from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
SERVICE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
IMAGE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127}|@sha256:[0-9a-f]{64})$"
)
DEFAULT_PROBE_IMAGE = "python:3.12-alpine"


class ConfigurationError(ValueError):
    """The requested audit or normalized Compose topology is unsafe."""


class OperationalError(RuntimeError):
    """Docker could not produce trustworthy reachability evidence."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class ReachabilityPolicy:
    compose_file: str = "docker-compose.yml"
    project_name: str = "network-reachability-audit"
    proxy_service: str = "proxy"
    edge_network: str = "edge"
    private_network: str = "private_app"
    backend_services: tuple[str, ...] = ("backend_a", "backend_b")
    backend_port: int = 8000
    proxy_path: str = "/whoami"
    probe_image: str = DEFAULT_PROBE_IMAGE
    command_timeout_seconds: float = 120.0
    probe_timeout_seconds: float = 2.0

    def validate(self) -> None:
        if PROJECT_PATTERN.fullmatch(self.project_name) is None:
            raise ConfigurationError("project_name must be a bounded Docker Compose identifier")
        for name, value in (
            ("proxy_service", self.proxy_service),
            ("edge_network", self.edge_network),
            ("private_network", self.private_network),
        ):
            if SERVICE_PATTERN.fullmatch(value) is None:
                raise ConfigurationError(f"{name} must be a bounded Compose identifier")
        if not self.backend_services or len(self.backend_services) > 16:
            raise ConfigurationError("backend_services must contain between 1 and 16 entries")
        if len(set(self.backend_services)) != len(self.backend_services):
            raise ConfigurationError("backend_services must be unique")
        if any(SERVICE_PATTERN.fullmatch(item) is None for item in self.backend_services):
            raise ConfigurationError("backend service names must be bounded Compose identifiers")
        if not 1 <= self.backend_port <= 65535:
            raise ConfigurationError("backend_port must be between 1 and 65535")
        if not self.proxy_path.startswith("/") or len(self.proxy_path) > 256:
            raise ConfigurationError("proxy_path must be an absolute bounded path")
        if any(char in self.proxy_path for char in "\r\n?#"):
            raise ConfigurationError(
                "proxy_path must not contain control, query, or fragment syntax"
            )
        if not 0.1 <= self.probe_timeout_seconds <= 10.0:
            raise ConfigurationError("probe_timeout_seconds must be between 0.1 and 10")
        if not 10.0 <= self.command_timeout_seconds <= 600.0:
            raise ConfigurationError("command_timeout_seconds must be between 10 and 600")
        if len(self.probe_image) > 256 or IMAGE_PATTERN.fullmatch(self.probe_image) is None:
            raise ConfigurationError("probe_image must be a bounded tag or sha256 digest reference")


@dataclass(frozen=True, slots=True)
class Topology:
    edge_network_name: str
    backend_endpoints: tuple[tuple[str, str, str], ...]
    digest: str


@dataclass(frozen=True, slots=True)
class Observation:
    check: str
    subject_sha256: str
    passed: bool
    reason: str


def _reject_constant(value: str) -> None:
    raise ConfigurationError(f"non-finite JSON value is forbidden: {value}")


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(payload: str) -> Any:
    if len(payload.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ConfigurationError("normalized Compose JSON exceeds the byte budget")
    return json.loads(
        payload,
        object_pairs_hook=_reject_duplicate,
        parse_constant=_reject_constant,
    )


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{name} must be an object")
    return value


def _network_memberships(service: Mapping[str, Any]) -> Mapping[str, Any]:
    networks = service.get("networks", {})
    if isinstance(networks, list):
        return {name: {} for name in networks if isinstance(name, str)}
    return _mapping(networks, "service networks")


def topology_from_config(config: Any, policy: ReachabilityPolicy) -> Topology:
    root = _mapping(config, "Compose document")
    services = _mapping(root.get("services"), "services")
    networks = _mapping(root.get("networks"), "networks")
    required_services = {policy.proxy_service, *policy.backend_services}
    if not required_services.issubset(services):
        raise ConfigurationError("required proxy or backend service is absent")
    if policy.edge_network not in networks or policy.private_network not in networks:
        raise ConfigurationError("required edge or private network is absent")

    edge = _mapping(networks[policy.edge_network], "edge network")
    private = _mapping(networks[policy.private_network], "private network")
    if bool(edge.get("internal", False)):
        raise ConfigurationError("edge network must not be internal")
    if not bool(private.get("internal", False)):
        raise ConfigurationError("private network must be internal")

    proxy = _mapping(services[policy.proxy_service], "proxy service")
    proxy_networks = _network_memberships(proxy)
    if not {policy.edge_network, policy.private_network}.issubset(proxy_networks):
        raise ConfigurationError("proxy must join both edge and private networks")

    backend_endpoints: list[tuple[str, str, str]] = []
    topology_services: dict[str, Any] = {
        policy.proxy_service: {
            "networks": sorted(proxy_networks),
            "ports": proxy.get("ports", []),
        }
    }
    for name in policy.backend_services:
        service = _mapping(services[name], f"service {name}")
        memberships = _network_memberships(service)
        if set(memberships) != {policy.private_network}:
            raise ConfigurationError(f"backend {name} must join only the private network")
        if service.get("ports"):
            raise ConfigurationError(f"backend {name} must not publish host ports")
        private_membership = _mapping(memberships[policy.private_network], f"{name} network")
        address = private_membership.get("ipv4_address")
        if not isinstance(address, str) or not address:
            raise ConfigurationError(f"backend {name} requires a static private IPv4 address")
        environment = _mapping(service.get("environment", {}), f"{name} environment")
        instance_id = environment.get("INSTANCE_ID")
        if not isinstance(instance_id, str) or not instance_id:
            raise ConfigurationError(f"backend {name} requires a bounded INSTANCE_ID")
        if len(instance_id) > 128 or any(char in instance_id for char in "\r\n"):
            raise ConfigurationError(f"backend {name} has an invalid INSTANCE_ID")
        backend_endpoints.append((name, address, instance_id))
        topology_services[name] = {"networks": [policy.private_network], "ports": []}

    edge_name = edge.get("name")
    if not isinstance(edge_name, str) or not edge_name:
        raise ConfigurationError("normalized edge network requires a runtime name")
    digest_payload = {
        "services": topology_services,
        "networks": {
            policy.edge_network: {
                "driver": edge.get("driver"),
                "internal": bool(edge.get("internal", False)),
                "ipam": edge.get("ipam", {}),
            },
            policy.private_network: {
                "driver": private.get("driver"),
                "internal": bool(private.get("internal", False)),
                "ipam": private.get("ipam", {}),
            },
        },
    }
    return Topology(
        edge_network_name=edge_name,
        backend_endpoints=tuple(backend_endpoints),
        digest=canonical_digest(digest_payload),
    )


def run_command(command: Sequence[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperationalError(f"command failed to execute: {type(exc).__name__}") from exc
    stdout = completed.stdout
    stderr = completed.stderr
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES:
        raise OperationalError("command output exceeds the evidence budget")
    return CommandResult(completed.returncode, stdout, stderr)


def _compose_command(policy: ReachabilityPolicy, *arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        policy.project_name,
        "--file",
        policy.compose_file,
        *arguments,
    ]


def _probe_command(policy: ReachabilityPolicy, network: str, script: str, *args: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        network,
        "--read-only",
        "--user=65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=96m",
        "--cpus=0.50",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
        "--entrypoint=python",
        policy.probe_image,
        "-c",
        script,
        *args,
    ]


PROXY_SCRIPT = """
import json, sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=float(sys.argv[2])) as response:
        body = response.read(8193)
        if response.status != 200 or len(body) > 8192:
            raise ValueError("bad response")
        payload = json.loads(body)
        if payload.get("instance_id") not in set(sys.argv[3:]):
            raise ValueError("unexpected upstream")
except Exception:
    raise SystemExit(20)
""".strip()

DNS_ISOLATION_SCRIPT = """
import socket, sys
try:
    socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM)
except socket.gaierror:
    raise SystemExit(0)
except Exception:
    raise SystemExit(21)
raise SystemExit(20)
""".strip()

IP_ISOLATION_SCRIPT = """
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(float(sys.argv[3]))
try:
    result = sock.connect_ex((sys.argv[1], int(sys.argv[2])))
finally:
    sock.close()
raise SystemExit(20 if result == 0 else 0)
""".strip()


def _subject_digest(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}\0{value}".encode()).hexdigest()


def _observation(check: str, subject: str, result: CommandResult, failure: str) -> Observation:
    if result.returncode not in {0, 20}:
        raise OperationalError(f"probe returned unexpected exit code for {check}")
    return Observation(
        check=check,
        subject_sha256=_subject_digest(check, subject),
        passed=result.returncode == 0,
        reason="OK" if result.returncode == 0 else failure,
    )


def _write_atomic(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


Runner = Callable[[Sequence[str], float], CommandResult]


def audit_reachability(
    policy: ReachabilityPolicy,
    *,
    runner: Runner = run_command,
) -> dict[str, Any]:
    policy.validate()
    policy_digest = canonical_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "proxy_service": policy.proxy_service,
            "edge_network": policy.edge_network,
            "private_network": policy.private_network,
            "backend_services": sorted(policy.backend_services),
            "backend_port": policy.backend_port,
            "proxy_path": policy.proxy_path,
            "probe_image": policy.probe_image,
            "probe_timeout_seconds": policy.probe_timeout_seconds,
        }
    )
    config_result = runner(
        _compose_command(policy, "config", "--format", "json"),
        policy.command_timeout_seconds,
    )
    if config_result.returncode != 0:
        raise OperationalError("docker compose config failed")
    topology = topology_from_config(strict_json_loads(config_result.stdout), policy)

    pull = runner(["docker", "pull", policy.probe_image], policy.command_timeout_seconds)
    if pull.returncode != 0:
        raise OperationalError("probe image pull failed")

    observations: list[Observation] = []
    compose_attempted = False
    try:
        compose_attempted = True
        up = runner(
            _compose_command(
                policy,
                "--progress",
                "quiet",
                "up",
                "--detach",
                "--build",
                "--quiet-pull",
                "--wait",
                "--wait-timeout",
                "90",
            ),
            policy.command_timeout_seconds,
        )
        if up.returncode != 0:
            raise OperationalError("docker compose up failed")
        proxy_url = f"http://{policy.proxy_service}{policy.proxy_path}"
        proxy = runner(
            _probe_command(
                policy,
                topology.edge_network_name,
                PROXY_SCRIPT,
                proxy_url,
                str(policy.probe_timeout_seconds),
                *(instance_id for _, _, instance_id in topology.backend_endpoints),
            ),
            policy.probe_timeout_seconds + 10,
        )
        observations.append(
            _observation("proxy_path", policy.proxy_service, proxy, "PROXY_PATH_UNAVAILABLE")
        )

        for service, address, _ in topology.backend_endpoints:
            dns = runner(
                _probe_command(
                    policy,
                    topology.edge_network_name,
                    DNS_ISOLATION_SCRIPT,
                    service,
                    str(policy.backend_port),
                ),
                policy.probe_timeout_seconds + 10,
            )
            observations.append(
                _observation(
                    "backend_dns_isolation", service, dns, "BACKEND_DNS_REACHABLE_FROM_EDGE"
                )
            )
            direct = runner(
                _probe_command(
                    policy,
                    topology.edge_network_name,
                    IP_ISOLATION_SCRIPT,
                    address,
                    str(policy.backend_port),
                    str(policy.probe_timeout_seconds),
                ),
                policy.probe_timeout_seconds + 10,
            )
            observations.append(
                _observation(
                    "backend_ip_isolation", service, direct, "BACKEND_IP_REACHABLE_FROM_EDGE"
                )
            )
    finally:
        if compose_attempted:
            down = runner(
                _compose_command(
                    policy,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    "--timeout",
                    "5",
                ),
                policy.command_timeout_seconds,
            )
            if down.returncode != 0:
                raise OperationalError("docker compose cleanup failed")

    accepted = all(item.passed for item in observations)
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "accepted": accepted,
        "policy_sha256": policy_digest,
        "topology_sha256": topology.digest,
        "observations": [asdict(item) for item in observations],
    }
    return {**evidence, "evidence_sha256": canonical_digest(evidence)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove proxy reachability and direct-backend isolation from the edge network."
    )
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--project-name", default="network-reachability-audit")
    parser.add_argument("--output", type=Path, default=Path("artifacts/runtime-reachability.json"))
    parser.add_argument("--probe-image", default=DEFAULT_PROBE_IMAGE)
    parser.add_argument("--probe-timeout", type=float, default=2.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    policy = ReachabilityPolicy(
        compose_file=args.compose_file,
        project_name=args.project_name,
        probe_image=args.probe_image,
        probe_timeout_seconds=args.probe_timeout,
    )
    try:
        report = audit_reachability(policy)
    except (ConfigurationError, OperationalError) as exc:
        failure = {
            "schema_version": SCHEMA_VERSION,
            "accepted": False,
            "error_code": (
                "CONFIGURATION_ERROR"
                if isinstance(exc, ConfigurationError)
                else "OPERATIONAL_ERROR"
            ),
        }
        _write_atomic(args.output, failure)
        print(json.dumps(failure, sort_keys=True))
        return 3
    _write_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
