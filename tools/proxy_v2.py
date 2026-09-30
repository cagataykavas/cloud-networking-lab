from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Sequence


SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
FIXED_HEADER_BYTES = 16

CMD_LOCAL = 0x00
CMD_PROXY = 0x01
FAM_INET_STREAM = 0x11
FAM_INET6_STREAM = 0x21

TLV_ALPN = 0x01
TLV_AUTHORITY = 0x02
TLV_CRC32C = 0x03
TLV_NOOP = 0x04
TLV_UNIQUE_ID = 0x05
TLV_SSL = 0x20
TLV_NETNS = 0x30

EXIT_ACCEPTED = 0
EXIT_REJECTED = 2
EXIT_MALFORMED = 3
MAX_POLICY_BYTES = 65536

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class ProxyV2Error(ValueError):
    """Base exception for a PROXY protocol v2 admission failure."""


class MalformedHeader(ProxyV2Error):
    """The supplied bytes cannot be interpreted safely as a v2 header."""


class PolicyRejected(ProxyV2Error):
    """A well-formed header violates the configured trust boundary."""


@dataclass(frozen=True)
class ProxyV2Policy:
    trusted_proxy_cidrs: tuple[Network, ...]
    destination_cidrs: tuple[Network, ...]
    destination_ports: tuple[int, ...]
    allowed_tlv_types: tuple[int, ...] = (TLV_CRC32C, TLV_NOOP, TLV_UNIQUE_ID)
    require_crc32c: bool = True
    max_header_bytes: int = 4096
    max_tlvs: int = 16
    max_unique_id_bytes: int = 128

    def __post_init__(self) -> None:
        if not self.trusted_proxy_cidrs:
            raise ValueError("at least one trusted proxy CIDR is required")
        if not self.destination_cidrs:
            raise ValueError("at least one destination CIDR is required")
        if not self.destination_ports:
            raise ValueError("at least one destination port is required")
        if len(self.trusted_proxy_cidrs) > 64 or len(self.destination_cidrs) > 64:
            raise ValueError("CIDR policy exceeds the 64-entry budget")
        if len(set(self.destination_ports)) != len(self.destination_ports):
            raise ValueError("destination ports must be unique")
        if any(port < 1 or port > 65535 for port in self.destination_ports):
            raise ValueError("destination ports must be between 1 and 65535")
        if tuple(sorted(self.destination_ports)) != self.destination_ports:
            raise ValueError("destination ports must be sorted")
        if len(set(self.allowed_tlv_types)) != len(self.allowed_tlv_types):
            raise ValueError("allowed TLV types must be unique")
        if tuple(sorted(self.allowed_tlv_types)) != self.allowed_tlv_types:
            raise ValueError("allowed TLV types must be sorted")
        if any(value < 0 or value > 255 for value in self.allowed_tlv_types):
            raise ValueError("TLV types must fit in one byte")
        if self.max_header_bytes < FIXED_HEADER_BYTES or self.max_header_bytes > 65551:
            raise ValueError("max header bytes must be between 16 and 65551")
        if self.max_tlvs < 0 or self.max_tlvs > 256:
            raise ValueError("max TLVs must be between 0 and 256")
        if self.max_unique_id_bytes < 1 or self.max_unique_id_bytes > 1024:
            raise ValueError("max unique ID bytes must be between 1 and 1024")
        for network in (*self.trusted_proxy_cidrs, *self.destination_cidrs):
            if network.prefixlen == 0:
                raise ValueError("all-address CIDRs are not valid trust boundaries")

    @classmethod
    def from_strings(
        cls,
        *,
        trusted_proxy_cidrs: tuple[str, ...],
        destination_cidrs: tuple[str, ...],
        destination_ports: tuple[int, ...],
        allowed_tlv_types: tuple[int, ...] = (TLV_CRC32C, TLV_NOOP, TLV_UNIQUE_ID),
        require_crc32c: bool = True,
        max_header_bytes: int = 4096,
        max_tlvs: int = 16,
        max_unique_id_bytes: int = 128,
    ) -> ProxyV2Policy:
        return cls(
            trusted_proxy_cidrs=tuple(
                ipaddress.ip_network(value, strict=True) for value in trusted_proxy_cidrs
            ),
            destination_cidrs=tuple(
                ipaddress.ip_network(value, strict=True) for value in destination_cidrs
            ),
            destination_ports=destination_ports,
            allowed_tlv_types=allowed_tlv_types,
            require_crc32c=require_crc32c,
            max_header_bytes=max_header_bytes,
            max_tlvs=max_tlvs,
            max_unique_id_bytes=max_unique_id_bytes,
        )

    @property
    def digest(self) -> str:
        document = {
            "allowed_tlv_types": list(self.allowed_tlv_types),
            "destination_cidrs": [str(value) for value in self.destination_cidrs],
            "destination_ports": list(self.destination_ports),
            "max_header_bytes": self.max_header_bytes,
            "max_tlvs": self.max_tlvs,
            "max_unique_id_bytes": self.max_unique_id_bytes,
            "require_crc32c": self.require_crc32c,
            "trusted_proxy_cidrs": [str(value) for value in self.trusted_proxy_cidrs],
        }
        return _sha256_json(document)


@dataclass(frozen=True)
class ProxyMetadata:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int


@dataclass(frozen=True)
class AdmissionEvidence:
    schema_version: int
    outcome: str
    reason: str
    header_sha256: str
    policy_sha256: str
    address_family: str | None
    tlv_types: tuple[str, ...]
    header_bytes: int
    evidence_sha256: str


@dataclass(frozen=True)
class AdmissionResult:
    evidence: AdmissionEvidence
    metadata: ProxyMetadata | None

    @property
    def accepted(self) -> bool:
        return self.evidence.outcome == "accepted"


@dataclass(frozen=True)
class _ParsedHeader:
    metadata: ProxyMetadata
    source: Address
    destination: Address
    address_family: str
    tlv_types: tuple[int, ...]


def _sha256_json(document: object) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def crc32c(data: bytes) -> int:
    """Return the Castagnoli CRC-32C used by PP2_TYPE_CRC32C."""
    checksum = 0xFFFFFFFF
    for byte in data:
        checksum ^= byte
        for _ in range(8):
            checksum = (checksum >> 1) ^ (0x82F63B78 if checksum & 1 else 0)
    return (~checksum) & 0xFFFFFFFF


def _canonical_address(value: str, *, field: str) -> Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PolicyRejected(f"invalid_{field}") from exc
    if str(address) != value:
        raise PolicyRejected(f"noncanonical_{field}")
    return address


def _contains(address: Address, networks: tuple[Network, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _parse_tlvs(
    header: bytes,
    *,
    offset: int,
    policy: ProxyV2Policy,
) -> tuple[int, ...]:
    tlv_types: list[int] = []
    crc_value_offset: int | None = None
    while offset < len(header):
        if len(tlv_types) >= policy.max_tlvs:
            raise PolicyRejected("tlv_count_exceeded")
        if len(header) - offset < 3:
            raise MalformedHeader("truncated_tlv_prefix")
        tlv_type = header[offset]
        tlv_length = struct.unpack_from("!H", header, offset + 1)[0]
        value_offset = offset + 3
        end = value_offset + tlv_length
        if end > len(header):
            raise MalformedHeader("truncated_tlv_value")
        if tlv_type not in policy.allowed_tlv_types:
            raise PolicyRejected("disallowed_tlv_type")
        if tlv_type in tlv_types and tlv_type != TLV_NOOP:
            raise PolicyRejected("duplicate_singleton_tlv")
        if tlv_type == TLV_CRC32C:
            if tlv_length != 4:
                raise MalformedHeader("invalid_crc32c_length")
            crc_value_offset = value_offset
        elif tlv_type == TLV_UNIQUE_ID and not (1 <= tlv_length <= policy.max_unique_id_bytes):
            raise PolicyRejected("unique_id_size_invalid")
        tlv_types.append(tlv_type)
        offset = end

    if policy.require_crc32c and crc_value_offset is None:
        raise PolicyRejected("crc32c_required")
    if crc_value_offset is not None:
        claimed = struct.unpack_from("!I", header, crc_value_offset)[0]
        zeroed = bytearray(header)
        zeroed[crc_value_offset : crc_value_offset + 4] = b"\x00" * 4
        if crc32c(bytes(zeroed)) != claimed:
            raise MalformedHeader("crc32c_mismatch")
    return tuple(tlv_types)


def _parse(header: bytes, policy: ProxyV2Policy) -> _ParsedHeader:
    if len(header) < FIXED_HEADER_BYTES:
        raise MalformedHeader("truncated_fixed_header")
    if len(header) > policy.max_header_bytes:
        raise PolicyRejected("header_size_exceeded")
    if header[:12] != SIGNATURE:
        raise MalformedHeader("invalid_signature")

    version_command = header[12]
    if version_command >> 4 != 2:
        raise MalformedHeader("unsupported_version")
    command = version_command & 0x0F
    if command != CMD_PROXY:
        raise PolicyRejected("proxy_command_required")

    declared_payload = struct.unpack_from("!H", header, 14)[0]
    if len(header) != FIXED_HEADER_BYTES + declared_payload:
        raise MalformedHeader("declared_length_mismatch")

    family_protocol = header[13]
    if family_protocol == FAM_INET_STREAM:
        address_bytes = 12
        address_family = "inet"
        if declared_payload < address_bytes:
            raise MalformedHeader("truncated_address_block")
        source = ipaddress.ip_address(header[16:20])
        destination = ipaddress.ip_address(header[20:24])
        source_port, destination_port = struct.unpack_from("!HH", header, 24)
    elif family_protocol == FAM_INET6_STREAM:
        address_bytes = 36
        address_family = "inet6"
        if declared_payload < address_bytes:
            raise MalformedHeader("truncated_address_block")
        source = ipaddress.ip_address(header[16:32])
        destination = ipaddress.ip_address(header[32:48])
        source_port, destination_port = struct.unpack_from("!HH", header, 48)
    else:
        raise PolicyRejected("tcp_inet_transport_required")

    if source.is_unspecified or source.is_multicast:
        raise PolicyRejected("invalid_source_scope")
    if destination.is_unspecified or destination.is_multicast:
        raise PolicyRejected("invalid_destination_scope")
    if source_port == 0:
        raise PolicyRejected("source_port_zero")
    if destination_port == 0:
        raise PolicyRejected("destination_port_zero")

    tlv_types = _parse_tlvs(
        header,
        offset=FIXED_HEADER_BYTES + address_bytes,
        policy=policy,
    )
    metadata = ProxyMetadata(
        source_address=str(source),
        source_port=source_port,
        destination_address=str(destination),
        destination_port=destination_port,
    )
    return _ParsedHeader(
        metadata=metadata,
        source=source,
        destination=destination,
        address_family=address_family,
        tlv_types=tlv_types,
    )


def _evidence(
    *,
    outcome: str,
    reason: str,
    header: bytes,
    policy: ProxyV2Policy,
    address_family: str | None = None,
    tlv_types: tuple[int, ...] = (),
) -> AdmissionEvidence:
    document = {
        "address_family": address_family,
        "header_bytes": len(header),
        "header_sha256": hashlib.sha256(header).hexdigest(),
        "outcome": outcome,
        "policy_sha256": policy.digest,
        "reason": reason,
        "schema_version": 1,
        "tlv_types": [f"0x{value:02x}" for value in tlv_types],
    }
    return AdmissionEvidence(
        **document,
        evidence_sha256=_sha256_json(document),
    )


def admit_proxy_v2(
    header: bytes,
    *,
    immediate_peer: str,
    policy: ProxyV2Policy,
) -> AdmissionResult:
    """Validate a complete v2 header before trusting its forwarded endpoints."""
    try:
        peer = _canonical_address(immediate_peer, field="peer")
        if not _contains(peer, policy.trusted_proxy_cidrs):
            raise PolicyRejected("untrusted_immediate_peer")
        parsed = _parse(header, policy)
        if not _contains(parsed.destination, policy.destination_cidrs):
            raise PolicyRejected("destination_cidr_denied")
        if parsed.metadata.destination_port not in policy.destination_ports:
            raise PolicyRejected("destination_port_denied")
    except MalformedHeader as exc:
        return AdmissionResult(
            evidence=_evidence(outcome="malformed", reason=str(exc), header=header, policy=policy),
            metadata=None,
        )
    except PolicyRejected as exc:
        return AdmissionResult(
            evidence=_evidence(outcome="rejected", reason=str(exc), header=header, policy=policy),
            metadata=None,
        )

    return AdmissionResult(
        evidence=_evidence(
            outcome="accepted",
            reason="accepted",
            header=header,
            policy=policy,
            address_family=parsed.address_family,
            tlv_types=parsed.tlv_types,
        ),
        metadata=parsed.metadata,
    )


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_proxy_v2_header(stream: BinaryIO, *, max_header_bytes: int) -> bytes:
    """Read exactly one bounded header, leaving application bytes unread."""
    fixed = _read_exact(stream, FIXED_HEADER_BYTES)
    if len(fixed) != FIXED_HEADER_BYTES:
        raise MalformedHeader("truncated_fixed_header")
    declared_payload = struct.unpack_from("!H", fixed, 14)[0]
    total = FIXED_HEADER_BYTES + declared_payload
    if total > max_header_bytes:
        raise PolicyRejected("header_size_exceeded")
    payload = _read_exact(stream, declared_payload)
    if len(payload) != declared_payload:
        raise MalformedHeader("truncated_declared_payload")
    return fixed + payload


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _load_policy(path: Path) -> ProxyV2Policy:
    encoded = path.read_bytes()
    if len(encoded) > MAX_POLICY_BYTES:
        raise ValueError("policy exceeds the 65536-byte budget")
    raw = json.loads(
        encoded.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(raw, dict):
        raise ValueError("policy must be a JSON object")
    expected = {
        "trusted_proxy_cidrs",
        "destination_cidrs",
        "destination_ports",
        "allowed_tlv_types",
        "require_crc32c",
        "max_header_bytes",
        "max_tlvs",
        "max_unique_id_bytes",
    }
    if set(raw) - expected:
        raise ValueError("policy contains unknown fields")
    return ProxyV2Policy.from_strings(
        trusted_proxy_cidrs=tuple(raw["trusted_proxy_cidrs"]),
        destination_cidrs=tuple(raw["destination_cidrs"]),
        destination_ports=tuple(raw["destination_ports"]),
        allowed_tlv_types=tuple(raw.get("allowed_tlv_types", (3, 4, 5))),
        require_crc32c=raw.get("require_crc32c", True),
        max_header_bytes=raw.get("max_header_bytes", 4096),
        max_tlvs=raw.get("max_tlvs", 16),
        max_unique_id_bytes=raw.get("max_unique_id_bytes", 128),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed PROXY protocol v2 admission audit.")
    parser.add_argument("header", type=Path, help="binary file containing exactly one header")
    parser.add_argument("--peer", required=True, help="canonical immediate socket peer IP")
    parser.add_argument("--policy", required=True, type=Path, help="JSON policy file")
    args = parser.parse_args(argv)
    try:
        policy = _load_policy(args.policy)
        with args.header.open("rb") as stream:
            header = read_proxy_v2_header(stream, max_header_bytes=policy.max_header_bytes)
            if stream.read(1):
                raise MalformedHeader("trailing_bytes_after_header")
        result = admit_proxy_v2(header, immediate_peer=args.peer, policy=policy)
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"outcome": "error", "reason": type(exc).__name__}))
        return EXIT_MALFORMED

    print(json.dumps(asdict(result.evidence), indent=2, sort_keys=True))
    if result.evidence.outcome == "accepted":
        return EXIT_ACCEPTED
    if result.evidence.outcome == "rejected":
        return EXIT_REJECTED
    return EXIT_MALFORMED


if __name__ == "__main__":
    raise SystemExit(main())
