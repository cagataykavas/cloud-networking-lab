from __future__ import annotations

import json
import socket
from dataclasses import replace

import pytest

from tools.proxy_v2_loopback import (
    MAX_RECEIPT_BYTES,
    _read_exact,
    build_loopback_receipt,
    parse_loopback_receipt,
    verify_loopback_receipt,
)


def receipt():
    return build_loopback_receipt(
        application_payload=b"application-frame\n",
        capacity_policy_sha256="1" * 64,
        proxy_policy_sha256="2" * 64,
        proxy_admission_evidence_sha256="3" * 64,
        connection_admission_evidence_sha256="4" * 64,
    )


def test_receipt_is_privacy_reduced_and_self_verifying() -> None:
    evidence = receipt()

    assert verify_loopback_receipt(evidence, expected_payload=b"application-frame\n")
    assert not verify_loopback_receipt(evidence, expected_payload=b"other")
    serialized = json.dumps(evidence.as_dict(), sort_keys=True)
    assert "source" not in serialized
    assert "destination" not in serialized
    assert "address" not in serialized


def test_receipt_tampering_and_invalid_digest_fail_closed() -> None:
    evidence = receipt()

    assert not verify_loopback_receipt(
        replace(evidence, application_bytes=evidence.application_bytes + 1)
    )
    assert not verify_loopback_receipt(
        replace(evidence, proxy_policy_sha256="not-a-digest")
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"[]",
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b"{" + b"x" * MAX_RECEIPT_BYTES + b"}",
    ],
)
def test_receipt_parser_rejects_ambiguous_or_unbounded_json(payload: bytes) -> None:
    with pytest.raises(ValueError):
        parse_loopback_receipt(payload)


def test_receipt_parser_requires_exact_schema() -> None:
    document = receipt().as_dict()
    document["unexpected"] = True

    with pytest.raises(ValueError, match="receipt_fields_invalid"):
        parse_loopback_receipt(json.dumps(document).encode("ascii"))


def test_bounded_frame_reader_restores_socket_timeout() -> None:
    sender, receiver = socket.socketpair()
    receiver.settimeout(3.0)
    try:
        sender.sendall(b"application-frame\ntrailing")

        assert _read_exact(receiver, len(b"application-frame\n"), 0.25) == (
            b"application-frame\n"
        )
        assert receiver.gettimeout() == 3.0
        assert receiver.recv(8) == b"trailing"
    finally:
        sender.close()
        receiver.close()


def test_bounded_frame_reader_rejects_truncation_and_restores_timeout() -> None:
    sender, receiver = socket.socketpair()
    receiver.settimeout(2.0)
    try:
        sender.sendall(b"short")
        sender.shutdown(socket.SHUT_WR)

        with pytest.raises(EOFError, match="application_frame_truncated"):
            _read_exact(receiver, 10, 0.25)
        assert receiver.gettimeout() == 2.0
    finally:
        sender.close()
        receiver.close()
