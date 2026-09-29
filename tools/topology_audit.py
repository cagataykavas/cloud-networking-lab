from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_048_576
MAX_SERVICES = 128
MAX_NETWORKS = 32
MAX_ATTACHMENTS = 512
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
DANGEROUS_NETWORK_CAPABILITIES = frozenset({"NET_ADMIN", "NET_RAW", "SYS_ADMIN"})


class ArtifactError(ValueError):
    """The topology artifact is malformed or exceeds an audit budget."""


@dataclass(frozen=True, slots=True)
class TopologyPolicy:
    edge_network: str
    private_network: str
    gateway_service: str
    backend_services: tuple[str, ...]
    gateway_target_port: int = 80

    def __post_init__(self) -> None:
        names = (
            self.edge_network,
            self.private_network,
            self.gateway_service,
            *self.backend_services,
        )
        if any(not NAME_PATTERN.fullmatch(name) for name in names):
            raise ValueError("policy names must be bounded Compose identifiers")
        if self.edge_network == self.private_network:
            raise ValueError("edge and private networks must differ")
        if not self.backend_services:
            raise ValueError("at least one backend service is required")
        if len(set(self.backend_services)) != len(self.backend_services):
            raise ValueError("backend services must be unique")
        if self.gateway_service in self.backend_services:
            raise ValueError("gateway cannot also be a backend")
        if not 1 <= self.gateway_target_port <= 65_535:
            raise ValueError("gateway target port must be between 1 and 65535")


@dataclass(frozen=True, order=True, slots=True)
class Violation:
    code: str
    subject: str


@dataclass(frozen=True, slots=True)
class AuditReport:
    accepted: bool
    topology_sha256: str
    policy_sha256: str
    service_count: int
    network_count: int
    attachment_count: int
    violations: tuple[Violation, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "topology_sha256": self.topology_sha256,
            "policy_sha256": self.policy_sha256,
            "service_count": self.service_count,
            "network_count": self.network_count,
            "attachment_count": self.attachment_count,
            "violations": [asdict(item) for item in self.violations],
        }


def _reject_constant(value: str) -> None:
    raise ArtifactError(f"non-finite JSON number is not allowed: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError("duplicate JSON object key")
        result[key] = value
    return result


def load_compose_json(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_INPUT_BYTES:
        raise ArtifactError("Compose artifact exceeds the 1 MiB input budget")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactError("Compose artifact must be UTF-8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ArtifactError("Compose artifact is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ArtifactError("Compose artifact root must be an object")
    _assert_finite(document)
    return document


def _assert_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ArtifactError("Compose artifact contains a non-finite number")
    if isinstance(value, dict):
        for child in value.values():
            _assert_finite(child)
    elif isinstance(value, list):
        for child in value:
            _assert_finite(child)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{label} must be an object")
    return value


def _service_networks(service: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    raw = service.get("networks", {})
    if isinstance(raw, list):
        if not all(isinstance(item, str) for item in raw):
            raise ArtifactError(f"service {name} has invalid network attachments")
        return {item: {} for item in raw}
    if not isinstance(raw, dict):
        raise ArtifactError(f"service {name} networks must be an object or list")
    attachments: dict[str, dict[str, Any]] = {}
    for network_name, config in raw.items():
        if not isinstance(network_name, str):
            raise ArtifactError(f"service {name} has a non-string network name")
        if config is None:
            attachments[network_name] = {}
        elif isinstance(config, dict):
            attachments[network_name] = config
        else:
            raise ArtifactError(f"service {name} attachment {network_name} must be an object")
    return attachments


def _network_subnets(config: dict[str, Any], name: str) -> list[ipaddress._BaseNetwork]:
    ipam = _mapping(config.get("ipam", {}), f"network {name} ipam")
    raw_configs = ipam.get("config", [])
    if not isinstance(raw_configs, list):
        raise ArtifactError(f"network {name} ipam.config must be a list")
    subnets: list[ipaddress._BaseNetwork] = []
    for item in raw_configs:
        entry = _mapping(item, f"network {name} ipam entry")
        raw_subnet = entry.get("subnet")
        if not isinstance(raw_subnet, str):
            raise ArtifactError(f"network {name} subnet must be a string")
        try:
            subnets.append(ipaddress.ip_network(raw_subnet, strict=True))
        except ValueError as exc:
            raise ArtifactError(f"network {name} has an invalid canonical subnet") from exc
    return subnets


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def audit_topology(document: dict[str, Any], policy: TopologyPolicy) -> AuditReport:
    services = _mapping(document.get("services"), "services")
    networks = _mapping(document.get("networks"), "networks")
    if not 1 <= len(services) <= MAX_SERVICES:
        raise ArtifactError("service count is outside the audit budget")
    if not 1 <= len(networks) <= MAX_NETWORKS:
        raise ArtifactError("network count is outside the audit budget")
    if not all(
        isinstance(name, str) and isinstance(value, dict) for name, value in services.items()
    ):
        raise ArtifactError("service names must map to objects")
    if not all(
        isinstance(name, str) and isinstance(value, dict) for name, value in networks.items()
    ):
        raise ArtifactError("network names must map to objects")

    attachments = {
        service_name: _service_networks(service, service_name)
        for service_name, service in services.items()
    }
    attachment_count = sum(len(value) for value in attachments.values())
    if attachment_count > MAX_ATTACHMENTS:
        raise ArtifactError("network attachment count exceeds the audit budget")

    expected_services = {policy.gateway_service, *policy.backend_services}
    required_networks = {policy.edge_network, policy.private_network}
    violations: set[Violation] = set()

    for missing in sorted(expected_services - services.keys()):
        violations.add(Violation("missing_service", missing))
    for unmanaged in sorted(services.keys() - expected_services):
        violations.add(Violation("unmanaged_service", unmanaged))
    for missing in sorted(required_networks - networks.keys()):
        violations.add(Violation("missing_network", missing))

    for service_name, attached in attachments.items():
        for network_name in attached:
            if network_name not in networks:
                violations.add(
                    Violation("undefined_network_attachment", f"{service_name}:{network_name}")
                )

    if policy.gateway_service in attachments:
        actual = set(attachments[policy.gateway_service])
        for missing in sorted(required_networks - actual):
            violations.add(Violation("gateway_missing_network", missing))
        for extra in sorted(actual - required_networks):
            violations.add(Violation("gateway_unexpected_network", extra))

    for backend in policy.backend_services:
        if backend not in attachments:
            continue
        actual = set(attachments[backend])
        if policy.private_network not in actual:
            violations.add(Violation("backend_missing_private_network", backend))
        if policy.edge_network in actual:
            violations.add(Violation("backend_attached_to_edge", backend))
        for extra in sorted(actual - {policy.private_network}):
            violations.add(Violation("backend_unexpected_network", f"{backend}:{extra}"))

    for network_name, config in networks.items():
        if config.get("external") is True and network_name in required_networks:
            violations.add(Violation("audited_network_is_external", network_name))
        driver = config.get("driver", "bridge")
        if network_name in required_networks and driver != "bridge":
            violations.add(Violation("unsupported_network_driver", network_name))
        internal = config.get("internal", False)
        if not isinstance(internal, bool):
            raise ArtifactError(f"network {network_name} internal must be boolean")
        if network_name == policy.private_network and not internal:
            violations.add(Violation("private_network_not_internal", network_name))
        if network_name == policy.edge_network and internal:
            violations.add(Violation("edge_network_is_internal", network_name))

    subnet_map: dict[str, list[ipaddress._BaseNetwork]] = {}
    for network_name, config in networks.items():
        subnet_map[network_name] = _network_subnets(config, network_name)
        if network_name in required_networks and not subnet_map[network_name]:
            violations.add(Violation("network_missing_subnet", network_name))
    flat_subnets = [
        (name, subnet) for name, configured in subnet_map.items() for subnet in configured
    ]
    for index, (left_name, left) in enumerate(flat_subnets):
        for right_name, right in flat_subnets[index + 1 :]:
            if left.version == right.version and left.overlaps(right):
                subject = ":".join(sorted((left_name, right_name)))
                violations.add(Violation("overlapping_subnets", subject))

    assigned: dict[str, str] = {}
    for service_name, service_attachments in attachments.items():
        for network_name, config in service_attachments.items():
            for field in ("ipv4_address", "ipv6_address"):
                raw_address = config.get(field)
                if raw_address is None:
                    continue
                if not isinstance(raw_address, str):
                    raise ArtifactError(f"{service_name} {field} must be a string")
                try:
                    address = ipaddress.ip_address(raw_address)
                except ValueError as exc:
                    raise ArtifactError(f"{service_name} has an invalid static address") from exc
                key = f"{network_name}:{address}"
                if key in assigned:
                    violations.add(Violation("duplicate_static_address", network_name))
                assigned[key] = service_name
                candidates = subnet_map.get(network_name, [])
                if not any(address in subnet for subnet in candidates):
                    violations.add(
                        Violation("static_address_outside_subnet", f"{service_name}:{network_name}")
                    )

    for service_name, service in services.items():
        if service.get("network_mode") == "host":
            violations.add(Violation("host_network_mode", service_name))
        if service.get("privileged") is True:
            violations.add(Violation("privileged_service", service_name))
        capabilities = service.get("cap_add", [])
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) for item in capabilities
        ):
            raise ArtifactError(f"service {service_name} cap_add must be a string list")
        normalized_capabilities = {item.upper() for item in capabilities}
        for capability in sorted(
            DANGEROUS_NETWORK_CAPABILITIES.intersection(normalized_capabilities)
        ):
            violations.add(
                Violation("dangerous_network_capability", f"{service_name}:{capability}")
            )

        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise ArtifactError(f"service {service_name} ports must be a list")
        if ports and service_name != policy.gateway_service:
            violations.add(Violation("backend_publishes_host_port", service_name))
        for port in ports:
            if not isinstance(port, dict):
                raise ArtifactError("ports must use normalized Compose JSON objects")
            target = port.get("target")
            protocol = port.get("protocol", "tcp")
            mode = port.get("mode", "ingress")
            if service_name == policy.gateway_service and (
                target != policy.gateway_target_port or protocol != "tcp" or mode != "ingress"
            ):
                violations.add(Violation("unexpected_gateway_publication", service_name))

    gateway_ports = services.get(policy.gateway_service, {}).get("ports", [])
    if policy.gateway_service in services and not gateway_ports:
        violations.add(Violation("gateway_has_no_publication", policy.gateway_service))

    projection = {
        "services": {
            name: {
                "networks": attachments[name],
                "ports": services[name].get("ports", []),
                "network_mode": services[name].get("network_mode"),
                "privileged": services[name].get("privileged", False),
                "cap_add": services[name].get("cap_add", []),
            }
            for name in sorted(services)
        },
        "networks": {
            name: {
                "driver": networks[name].get("driver", "bridge"),
                "internal": networks[name].get("internal", False),
                "external": networks[name].get("external", False),
                "subnets": sorted(str(item) for item in subnet_map[name]),
            }
            for name in sorted(networks)
        },
    }
    policy_projection = {
        "edge_network": policy.edge_network,
        "private_network": policy.private_network,
        "gateway_service": policy.gateway_service,
        "backend_services": sorted(policy.backend_services),
        "gateway_target_port": policy.gateway_target_port,
    }
    ordered = tuple(sorted(violations))
    return AuditReport(
        accepted=not ordered,
        topology_sha256=_digest(projection),
        policy_sha256=_digest(policy_projection),
        service_count=len(services),
        network_count=len(networks),
        attachment_count=attachment_count,
        violations=ordered,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a normalized Docker Compose network topology"
    )
    parser.add_argument("input", nargs="?", default="-", help="Compose JSON path, or - for stdin")
    parser.add_argument("--edge-network", default="edge")
    parser.add_argument("--private-network", default="private_app")
    parser.add_argument("--gateway-service", default="proxy")
    parser.add_argument("--backend-service", action="append", required=True)
    parser.add_argument("--gateway-target-port", type=int, default=80)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = TopologyPolicy(
            edge_network=args.edge_network,
            private_network=args.private_network,
            gateway_service=args.gateway_service,
            backend_services=tuple(args.backend_service),
            gateway_target_port=args.gateway_target_port,
        )
        if args.input == "-":
            payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            path = Path(args.input)
            if path.stat().st_size > MAX_INPUT_BYTES:
                raise ArtifactError("Compose artifact exceeds the 1 MiB input budget")
            payload = path.read_bytes()
        report = audit_topology(load_compose_json(payload), policy)
    except (ArtifactError, OSError, ValueError) as exc:
        print(json.dumps({"accepted": False, "error": "malformed_artifact", "detail": str(exc)}))
        return 3
    print(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
