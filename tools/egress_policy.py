from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

IPAddress = IPv4Address | IPv6Address

_METADATA_ENDPOINTS = (
    ip_network("169.254.169.254/32"),
    ip_network("fd00:ec2::254/128"),
)


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    allowed_private_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    url: str
    hostname: str | None
    port: int | None
    resolved_addresses: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _host_matches(hostname: str, pattern: str) -> bool:
    normalized = pattern.rstrip(".").lower()
    if normalized.startswith("*."):
        suffix = normalized[1:]
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == normalized


def _is_metadata_endpoint(address: IPAddress) -> bool:
    return any(address in network for network in _METADATA_ENDPOINTS if address.version == network.version)


def _private_exception(address: IPAddress, cidrs: Sequence[str]) -> bool:
    for value in cidrs:
        network = ip_network(value, strict=False)
        if address.version == network.version and address in network:
            return True
    return False


def evaluate_destination(
    url: str,
    resolved_addresses: Sequence[str],
    policy: EgressPolicy,
) -> EgressDecision:
    """Evaluate a URL and its DNS answers before an outbound connection.

    Callers must connect to one of the already-validated addresses and repeat
    validation after every DNS refresh or redirect. This closes the gap where
    a hostname passes an allowlist but resolves to an internal or metadata IP.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname.rstrip(".").lower() if parsed.hostname else None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        port = None

    reasons: list[str] = []
    if parsed.scheme not in policy.allowed_schemes:
        reasons.append(f"scheme_not_allowed:{parsed.scheme or 'missing'}")
    if hostname is None:
        reasons.append("hostname_missing")
    if parsed.username is not None or parsed.password is not None:
        reasons.append("embedded_credentials_not_allowed")
    if port is None or port not in policy.allowed_ports:
        reasons.append(f"port_not_allowed:{port}")
    if hostname is not None and not any(
        _host_matches(hostname, pattern) for pattern in policy.allowed_hosts
    ):
        reasons.append(f"hostname_not_allowed:{hostname}")

    parsed_addresses: list[IPAddress] = []
    if hostname is not None:
        try:
            parsed_addresses.append(ip_address(hostname))
        except ValueError:
            pass

    for value in resolved_addresses:
        try:
            address = ip_address(value)
        except ValueError:
            reasons.append(f"invalid_dns_answer:{value}")
            continue
        if address not in parsed_addresses:
            parsed_addresses.append(address)

    if not parsed_addresses:
        reasons.append("no_validated_address")

    for address in parsed_addresses:
        rendered = str(address)
        if _is_metadata_endpoint(address):
            reasons.append(f"metadata_endpoint_blocked:{rendered}")
            continue
        if address.is_global:
            continue
        if _private_exception(address, policy.allowed_private_cidrs):
            continue
        reasons.append(f"non_global_address_blocked:{rendered}")

    return EgressDecision(
        allowed=not reasons,
        url=url,
        hostname=hostname,
        port=port,
        resolved_addresses=tuple(str(address) for address in parsed_addresses),
        reasons=tuple(reasons),
    )
