from __future__ import annotations

import io
import ipaddress
import json
import math
import socket
import struct

import pytest

from tools.proxy_v2 import (
    FAM_INET6_STREAM,
    FAM_INET_STREAM,
    FIXED_HEADER_BYTES,
    SIGNATURE,
    TLV_CRC32C,
    TLV_NOOP,
    TLV_UNIQUE_ID,
    HeaderReadDeadlineExceeded,
    MalformedHeader,
    PolicyRejected,
    ProxyV2Policy,
    admit_proxy_v2,
    crc32c,
    main,
    read_proxy_v2_header,
    read_proxy_v2_socket,
)


class ChunkedReader(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 3) if size >= 0 else size)


class ScriptedSocket:
    def __init__(self, chunks: list[bytes], clock_state: list[float]) -> None:
        self.chunks = chunks
        self.clock_state = clock_state
        self.timeout: float | None = 7.0
        self.timeout_history: list[float | None] = []

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, value: float | None) -> None:
        self.timeout = value
        self.timeout_history.append(value)

    def recv(self, bufsize: int) -> bytes:
        self.clock_state[0] += 0.1
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        assert len(chunk) <= bufsize
        return chunk


class TimingOutSocket(ScriptedSocket):
    def recv(self, bufsize: int) -> bytes:
        raise TimeoutError


def policy(**overrides: object) -> ProxyV2Policy:
    values: dict[str, object] = {
        "trusted_proxy_cidrs": ("10.10.0.0/24", "2001:db8:10::/64"),
        "destination_cidrs": ("10.20.0.0/24", "2001:db8:20::/64"),
        "destination_ports": (443, 8443),
    }
    values.update(overrides)
    return ProxyV2Policy.from_strings(**values)  # type: ignore[arg-type]


def build_header(
    *,
    source: str = "198.51.100.7",
    destination: str = "10.20.0.8",
    source_port: int = 53000,
    destination_port: int = 443,
    command: int = 1,
    family_protocol: int | None = None,
    tlvs: tuple[tuple[int, bytes], ...] = ((TLV_UNIQUE_ID, b"request-17"),),
    include_crc: bool = True,
) -> bytes:
    source_ip = ipaddress.ip_address(source)
    destination_ip = ipaddress.ip_address(destination)
    if family_protocol is None:
        family_protocol = (
            FAM_INET_STREAM if source_ip.version == 4 else FAM_INET6_STREAM
        )
    address_block = (
        source_ip.packed
        + destination_ip.packed
        + struct.pack("!HH", source_port, destination_port)
    )
    encoded_tlvs = b"".join(
        struct.pack("!BH", tlv_type, len(value)) + value for tlv_type, value in tlvs
    )
    crc_value_offset = None
    if include_crc:
        crc_value_offset = (
            FIXED_HEADER_BYTES + len(address_block) + len(encoded_tlvs) + 3
        )
        encoded_tlvs += struct.pack("!BH", TLV_CRC32C, 4) + b"\x00" * 4
    payload = address_block + encoded_tlvs
    header = bytearray(
        SIGNATURE
        + bytes([(2 << 4) | command, family_protocol])
        + struct.pack("!H", len(payload))
        + payload
    )
    if crc_value_offset is not None:
        struct.pack_into("!I", header, crc_value_offset, crc32c(bytes(header)))
    return bytes(header)


def test_crc32c_known_vector() -> None:
    assert crc32c(b"123456789") == 0xE3069283


def test_accepts_ipv4_and_returns_endpoints_only_to_caller() -> None:
    result = admit_proxy_v2(
        build_header(), immediate_peer="10.10.0.12", policy=policy()
    )
    assert result.accepted
    assert result.metadata is not None
    assert result.metadata.source_address == "198.51.100.7"
    assert result.metadata.destination_address == "10.20.0.8"
    assert result.evidence.address_family == "inet"
    assert result.evidence.schema_version == 2
    assert result.evidence.unique_id_sha256 is not None
    serialized_evidence = str(result.evidence)
    assert "198.51.100.7" not in serialized_evidence
    assert "10.20.0.8" not in serialized_evidence
    assert b"request-17".decode() not in serialized_evidence


def test_accepts_ipv6() -> None:
    result = admit_proxy_v2(
        build_header(
            source="2001:db8:99::7",
            destination="2001:db8:20::8",
            destination_port=8443,
        ),
        immediate_peer="2001:db8:10::12",
        policy=policy(),
    )
    assert result.accepted
    assert result.evidence.address_family == "inet6"


def test_evidence_is_deterministic_and_header_bound() -> None:
    header = build_header()
    first = admit_proxy_v2(header, immediate_peer="10.10.0.12", policy=policy())
    second = admit_proxy_v2(header, immediate_peer="10.10.0.12", policy=policy())
    changed = admit_proxy_v2(
        build_header(source_port=53001),
        immediate_peer="10.10.0.12",
        policy=policy(),
    )
    assert first.evidence == second.evidence
    assert first.evidence.evidence_sha256 != changed.evidence.evidence_sha256


@pytest.mark.parametrize(
    ("peer", "reason"),
    [
        ("10.11.0.12", "untrusted_immediate_peer"),
        ("010.010.000.012", "invalid_peer"),
        ("2001:0db8:10::12", "noncanonical_peer"),
    ],
)
def test_rejects_untrusted_or_noncanonical_peer(peer: str, reason: str) -> None:
    result = admit_proxy_v2(build_header(), immediate_peer=peer, policy=policy())
    assert not result.accepted
    assert result.evidence.outcome == "rejected"
    assert result.evidence.reason == reason


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (build_header(command=0), "proxy_command_required"),
        (build_header(family_protocol=0x12), "tcp_inet_transport_required"),
        (build_header(destination="10.21.0.8"), "destination_cidr_denied"),
        (build_header(destination_port=9443), "destination_port_denied"),
        (build_header(source="0.0.0.0"), "invalid_source_scope"),
        (build_header(source_port=0), "source_port_zero"),
    ],
)
def test_rejects_policy_violations(header: bytes, reason: str) -> None:
    result = admit_proxy_v2(header, immediate_peer="10.10.0.12", policy=policy())
    assert result.evidence.outcome == "rejected"
    assert result.evidence.reason == reason
    assert result.metadata is None


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (b"short", "truncated_fixed_header"),
        (b"x" * 16, "invalid_signature"),
        (SIGNATURE + b"\x31\x11\x00\x00", "unsupported_version"),
        (SIGNATURE + b"\x21\x11\x00\x00", "truncated_address_block"),
        (build_header()[:-1], "declared_length_mismatch"),
    ],
)
def test_marks_structural_failures_malformed(header: bytes, reason: str) -> None:
    result = admit_proxy_v2(header, immediate_peer="10.10.0.12", policy=policy())
    assert result.evidence.outcome == "malformed"
    assert result.evidence.reason == reason


def test_detects_crc_tampering() -> None:
    header = bytearray(build_header())
    header[20] ^= 1
    result = admit_proxy_v2(bytes(header), immediate_peer="10.10.0.12", policy=policy())
    assert result.evidence.outcome == "malformed"
    assert result.evidence.reason == "crc32c_mismatch"


def test_requires_crc_when_configured() -> None:
    result = admit_proxy_v2(
        build_header(include_crc=False),
        immediate_peer="10.10.0.12",
        policy=policy(),
    )
    assert result.evidence.outcome == "rejected"
    assert result.evidence.reason == "crc32c_required"


def test_allows_crc_to_be_optional_explicitly() -> None:
    result = admit_proxy_v2(
        build_header(include_crc=False),
        immediate_peer="10.10.0.12",
        policy=policy(require_crc32c=False),
    )
    assert result.accepted


def test_rejects_unknown_and_duplicate_singleton_tlvs() -> None:
    unknown = admit_proxy_v2(
        build_header(tlvs=((0xEE, b"x"),)),
        immediate_peer="10.10.0.12",
        policy=policy(),
    )
    duplicate = admit_proxy_v2(
        build_header(tlvs=((TLV_UNIQUE_ID, b"a"), (TLV_UNIQUE_ID, b"b"))),
        immediate_peer="10.10.0.12",
        policy=policy(),
    )
    assert unknown.evidence.reason == "disallowed_tlv_type"
    assert duplicate.evidence.reason == "duplicate_singleton_tlv"


def test_bounds_tlv_count_and_unique_id() -> None:
    too_many = admit_proxy_v2(
        build_header(tlvs=((TLV_NOOP, b""), (TLV_NOOP, b""))),
        immediate_peer="10.10.0.12",
        policy=policy(max_tlvs=2),
    )
    oversized_id = admit_proxy_v2(
        build_header(tlvs=((TLV_UNIQUE_ID, b"12345"),)),
        immediate_peer="10.10.0.12",
        policy=policy(max_unique_id_bytes=4),
    )
    assert too_many.evidence.reason == "tlv_count_exceeded"
    assert oversized_id.evidence.reason == "unique_id_size_invalid"


def test_read_one_header_leaves_application_bytes_unread() -> None:
    header = build_header()
    stream = io.BytesIO(header + b"GET /health HTTP/1.1\r\n")
    assert read_proxy_v2_header(stream, max_header_bytes=4096) == header
    assert stream.read() == b"GET /health HTTP/1.1\r\n"


def test_reader_handles_partial_stream_reads() -> None:
    header = build_header()
    stream = ChunkedReader(header + b"payload")
    assert read_proxy_v2_header(stream, max_header_bytes=4096) == header
    assert stream.read() == b"payload"


def test_reader_rejects_truncation_and_oversize_before_payload_read() -> None:
    with pytest.raises(MalformedHeader, match="truncated_fixed_header"):
        read_proxy_v2_header(io.BytesIO(b"short"), max_header_bytes=4096)

    fixed = SIGNATURE + b"\x21\x11" + struct.pack("!H", 5000)
    with pytest.raises(PolicyRejected, match="header_size_exceeded"):
        read_proxy_v2_header(io.BytesIO(fixed), max_header_bytes=4096)


def test_reader_rejects_short_declared_payload() -> None:
    fixed = SIGNATURE + b"\x21\x11" + struct.pack("!H", 12)
    with pytest.raises(MalformedHeader, match="truncated_declared_payload"):
        read_proxy_v2_header(io.BytesIO(fixed + b"x"), max_header_bytes=4096)


def test_socket_reader_preserves_application_bytes_and_timeout() -> None:
    header = build_header()
    application = b"GET /health HTTP/1.1\r\n"
    sender, receiver = socket.socketpair()
    try:
        receiver.settimeout(1.25)
        sender.sendall(header + application)

        assert (
            read_proxy_v2_socket(
                receiver,
                max_header_bytes=4096,
                read_timeout_seconds=0.5,
            )
            == header
        )
        assert receiver.gettimeout() == 1.25
        assert receiver.recv(len(application)) == application
    finally:
        sender.close()
        receiver.close()


def test_socket_reader_uses_one_shrinking_monotonic_budget() -> None:
    header = build_header()
    clock_state = [10.0]
    connection = ScriptedSocket([header[:16], header[16:]], clock_state)

    assert (
        read_proxy_v2_socket(
            connection,
            max_header_bytes=4096,
            read_timeout_seconds=0.5,
            clock=lambda: clock_state[0],
        )
        == header
    )

    assert connection.timeout_history[:2] == pytest.approx([0.5, 0.4])
    assert connection.timeout_history[-1] == 7.0


def test_socket_reader_classifies_timeout_and_restores_prior_timeout() -> None:
    clock_state = [10.0]
    connection = TimingOutSocket([], clock_state)

    with pytest.raises(
        HeaderReadDeadlineExceeded, match="proxy_header_deadline_exceeded"
    ):
        read_proxy_v2_socket(
            connection,
            max_header_bytes=4096,
            read_timeout_seconds=0.25,
            clock=lambda: clock_state[0],
        )

    assert connection.timeout_history == [0.25, 7.0]


def test_socket_reader_deadline_spans_all_partial_reads() -> None:
    header = build_header()
    clock_state = [10.0]
    connection = ScriptedSocket(
        [header[:16], header[16:20], header[20:]],
        clock_state,
    )

    with pytest.raises(
        HeaderReadDeadlineExceeded, match="proxy_header_deadline_exceeded"
    ):
        read_proxy_v2_socket(
            connection,
            max_header_bytes=4096,
            read_timeout_seconds=0.15,
            clock=lambda: clock_state[0],
        )

    assert connection.timeout_history[:2] == pytest.approx([0.15, 0.05])
    assert connection.timeout_history[-1] == 7.0
    assert connection.chunks == [header[20:]]


def test_socket_reader_rejects_oversize_before_payload_recv() -> None:
    fixed = SIGNATURE + b"\x21\x11" + struct.pack("!H", 5000)
    clock_state = [10.0]
    connection = ScriptedSocket([fixed], clock_state)

    with pytest.raises(PolicyRejected, match="header_size_exceeded"):
        read_proxy_v2_socket(
            connection,
            max_header_bytes=4096,
            read_timeout_seconds=0.5,
            clock=lambda: clock_state[0],
        )

    assert connection.chunks == []
    assert connection.timeout_history[-1] == 7.0


@pytest.mark.parametrize("timeout", [True, 0, -1, math.nan, math.inf, 30.1])
def test_socket_reader_rejects_invalid_deadline(timeout: float) -> None:
    connection = ScriptedSocket([], [10.0])

    with pytest.raises(ValueError, match="read timeout"):
        read_proxy_v2_socket(
            connection,
            max_header_bytes=4096,
            read_timeout_seconds=timeout,
        )

    assert connection.timeout_history == []


def test_cli_exit_codes_and_privacy_reduced_output(tmp_path, capsys) -> None:
    header_path = tmp_path / "header.bin"
    policy_path = tmp_path / "policy.json"
    header_path.write_bytes(build_header())
    policy_path.write_text(
        json.dumps(
            {
                "trusted_proxy_cidrs": ["10.10.0.0/24"],
                "destination_cidrs": ["10.20.0.0/24"],
                "destination_ports": [443],
            }
        ),
        encoding="utf-8",
    )
    common = [str(header_path), "--policy", str(policy_path), "--peer"]

    assert main([*common, "10.10.0.12"]) == 0
    accepted_output = capsys.readouterr().out
    assert '"outcome": "accepted"' in accepted_output
    assert "198.51.100.7" not in accepted_output
    assert main([*common, "10.11.0.12"]) == 2
    assert '"outcome": "rejected"' in capsys.readouterr().out

    header_path.write_bytes(b"short")
    assert main([*common, "10.10.0.12"]) == 3
    assert '"outcome": "error"' in capsys.readouterr().out


@pytest.mark.parametrize(
    "invalid_policy",
    [
        '{"trusted_proxy_cidrs": [], "trusted_proxy_cidrs": []}',
        '{"trusted_proxy_cidrs": [], "max_tlvs": NaN}',
        "x" * 65537,
    ],
)
def test_cli_rejects_ambiguous_or_oversized_policy(
    invalid_policy: str, tmp_path, capsys
) -> None:
    header_path = tmp_path / "header.bin"
    policy_path = tmp_path / "policy.json"
    header_path.write_bytes(build_header())
    policy_path.write_text(invalid_policy, encoding="utf-8")
    assert (
        main(
            [
                str(header_path),
                "--peer",
                "10.10.0.12",
                "--policy",
                str(policy_path),
            ]
        )
        == 3
    )
    assert '"outcome": "error"' in capsys.readouterr().out


@pytest.mark.parametrize(
    "kwargs",
    [
        {"trusted_proxy_cidrs": ("0.0.0.0/0",)},
        {"destination_ports": (443, 443)},
        {"destination_ports": (8443, 443)},
        {"allowed_tlv_types": (5, 3)},
        {"max_header_bytes": 15},
        {"max_tlvs": 257},
    ],
)
def test_rejects_unsafe_or_nondeterministic_policy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        policy(**kwargs)
