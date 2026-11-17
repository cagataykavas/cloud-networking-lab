from __future__ import annotations

import ipaddress
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
MAX_FORWARDED_HEADER_BYTES = 2_048
MAX_FORWARDED_HOPS = 32


@dataclass(frozen=True)
class ClientIdentity:
    client_ip: str | None
    source: str
    forwarded_header_accepted: bool
    error: str | None = None


def parse_trusted_proxy_cidrs(value: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated, explicit proxy allowlist."""

    networks: list[IPNetwork] = []
    for item in value.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=True))
        except ValueError as exc:
            raise ValueError(f"invalid trusted proxy CIDR: {candidate}") from exc
    return tuple(networks)


def resolve_client_identity(
    peer: str | None,
    forwarded_for: str | None,
    trusted_proxy_networks: tuple[IPNetwork, ...],
) -> ClientIdentity:
    """Resolve a client IP without trusting headers from an untrusted peer.

    Nginx appends the socket peer to X-Forwarded-For. Walking the header from
    right to left therefore discards only configured proxy hops and prevents a
    client-controlled value on the left from overriding the actual edge peer.
    """

    peer_ip = _parse_address(peer)
    if peer_ip is None:
        return ClientIdentity(None, "unavailable", False, "invalid peer address")
    if not _is_trusted(peer_ip, trusted_proxy_networks):
        return ClientIdentity(str(peer_ip), "peer", False)
    if forwarded_for is None:
        return ClientIdentity(
            str(peer_ip), "peer", False, "trusted proxy omitted X-Forwarded-For"
        )
    if len(forwarded_for.encode("utf-8")) > MAX_FORWARDED_HEADER_BYTES:
        return ClientIdentity(
            str(peer_ip), "peer", False, "X-Forwarded-For exceeds size limit"
        )

    parts = [part.strip() for part in forwarded_for.split(",")]
    if not parts or len(parts) > MAX_FORWARDED_HOPS:
        return ClientIdentity(
            str(peer_ip), "peer", False, "X-Forwarded-For hop count is invalid"
        )
    chain = [_parse_address(part) for part in parts]
    if any(address is None for address in chain):
        return ClientIdentity(
            str(peer_ip), "peer", False, "X-Forwarded-For contains an invalid address"
        )

    addresses = [address for address in chain if address is not None]
    for address in reversed(addresses):
        if not _is_trusted(address, trusted_proxy_networks):
            return ClientIdentity(str(address), "forwarded", True)
    return ClientIdentity(str(addresses[0]), "forwarded", True)


def _parse_address(value: str | None) -> IPAddress | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _is_trusted(address: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )
