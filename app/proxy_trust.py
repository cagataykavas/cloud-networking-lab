"""Fail-closed client identity derivation behind trusted reverse proxies."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class ProxyEvidenceError(ValueError):
    """Raised when a trusted proxy supplies unusable identity evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TrustedProxyPolicy:
    """Explicit proxy networks and resource limits for one forwarded chain."""

    trusted_proxy_cidrs: tuple[str, ...] = ()
    max_forwarded_hops: int = 16
    max_header_bytes: int = 4096
    _networks: tuple[IPNetwork, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.trusted_proxy_cidrs, tuple):
            raise ValueError("trusted_proxy_cidrs must be an immutable tuple")
        if not _plain_int(self.max_forwarded_hops) or not 1 <= self.max_forwarded_hops <= 64:
            raise ValueError("max_forwarded_hops must be an integer between 1 and 64")
        if not _plain_int(self.max_header_bytes) or not 64 <= self.max_header_bytes <= 16384:
            raise ValueError("max_header_bytes must be an integer between 64 and 16384")
        if len(self.trusted_proxy_cidrs) > 64:
            raise ValueError("at most 64 trusted proxy CIDRs are allowed")

        networks: list[IPNetwork] = []
        for value in self.trusted_proxy_cidrs:
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError("trusted proxy CIDRs must be non-empty canonical strings")
            try:
                network = ip_network(value, strict=True)
            except ValueError as exc:
                raise ValueError("trusted proxy CIDR is invalid or non-canonical") from exc
            minimum_prefix = 8 if network.version == 4 else 32
            if network.prefixlen < minimum_prefix:
                raise ValueError("trusted proxy CIDR is dangerously broad")
            if network in networks:
                raise ValueError("trusted proxy CIDRs must be unique")
            networks.append(network)
        object.__setattr__(self, "_networks", tuple(networks))

    def trusts(self, address: IPAddress) -> bool:
        return any(
            address.version == network.version and address in network for network in self._networks
        )


@dataclass(frozen=True)
class ClientIdentity:
    client_ip: str
    peer_ip: str
    source: str
    status: str
    forwarded_hop_count: int
    trusted_proxy_hop_count: int


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _address(value: str, code: str) -> IPAddress:
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        raise ProxyEvidenceError(code)
    try:
        return ip_address(value)
    except ValueError as exc:
        raise ProxyEvidenceError(code) from exc


def resolve_client_identity(
    peer_ip: str | None,
    forwarded_for: str | None,
    policy: TrustedProxyPolicy,
) -> ClientIdentity:
    """Derive the nearest untrusted hop, never trusting a header from an untrusted peer."""

    if not isinstance(policy, TrustedProxyPolicy):
        raise TypeError("policy must be TrustedProxyPolicy")
    if peer_ip is None:
        raise ProxyEvidenceError("PEER_MISSING")
    peer = _address(peer_ip, "PEER_INVALID")

    if forwarded_for is None:
        if policy.trusts(peer):
            raise ProxyEvidenceError("FORWARDED_CHAIN_MISSING")
        return ClientIdentity(
            client_ip=str(peer),
            peer_ip=str(peer),
            source="direct",
            status="DIRECT_PEER",
            forwarded_hop_count=0,
            trusted_proxy_hop_count=0,
        )

    if not isinstance(forwarded_for, str):
        raise ProxyEvidenceError("FORWARDED_HEADER_INVALID")
    if len(forwarded_for.encode("utf-8")) > policy.max_header_bytes:
        raise ProxyEvidenceError("FORWARDED_HEADER_TOO_LARGE")

    if not policy.trusts(peer):
        return ClientIdentity(
            client_ip=str(peer),
            peer_ip=str(peer),
            source="direct",
            status="UNTRUSTED_PEER_IGNORED_FORWARDED",
            forwarded_hop_count=0,
            trusted_proxy_hop_count=0,
        )

    raw_hops = forwarded_for.split(",")
    if len(raw_hops) > policy.max_forwarded_hops:
        raise ProxyEvidenceError("FORWARDED_HOP_LIMIT_EXCEEDED")
    if any(not value.strip() for value in raw_hops):
        raise ProxyEvidenceError("FORWARDED_HOP_EMPTY")
    hops = tuple(_address(value.strip(), "FORWARDED_HOP_INVALID") for value in raw_hops)

    trusted_hops = 0
    for address in reversed((*hops, peer)):
        if policy.trusts(address):
            trusted_hops += 1
            continue
        return ClientIdentity(
            client_ip=str(address),
            peer_ip=str(peer),
            source="forwarded",
            status="TRUSTED_PROXY_CHAIN",
            forwarded_hop_count=len(hops),
            trusted_proxy_hop_count=trusted_hops,
        )
    raise ProxyEvidenceError("NO_UNTRUSTED_CLIENT_HOP")
