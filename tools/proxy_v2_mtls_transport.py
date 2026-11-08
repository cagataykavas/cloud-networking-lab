from __future__ import annotations

import hashlib
import hmac
import json
import socket
import ssl
import stat
import struct
import time
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

from tools.proxy_v2_loopback import LoopbackReceipt, parse_loopback_receipt
from tools.proxy_v2_receipt_ledger import (
    ENTRY_SCHEMA_VERSION,
    AppendRequest,
    LedgerCheckpoint,
    append_receipt,
    parse_append_request,
    parse_checkpoint,
)

TRANSPORT_SCHEMA_VERSION = 1
MAX_FRAME_BYTES = 32 * 1024
MAX_CERTIFICATE_PINS = 8
MAX_TIMEOUT_SECONDS = 30.0
_FRAME_HEADER = struct.Struct("!I")


class MTLSTransportError(ConnectionError):
    """Stable transport failure that does not expose TLS or socket internals."""


class AppendRejected(MTLSTransportError):
    """The authenticated collector rejected an otherwise valid transport request."""


@dataclass(frozen=True)
class CollectorResult:
    accepted: bool
    checkpoint: LedgerCheckpoint | None
    local_rejection_code: str | None


class _Deadline:
    def __init__(self, timeout_seconds: float) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("transport_timeout_invalid")
        self._expires_at = time.monotonic() + float(timeout_seconds)

    def apply(self, connection: socket.socket) -> None:
        remaining = self._expires_at - time.monotonic()
        if remaining <= 0:
            raise MTLSTransportError("transport_deadline_exceeded")
        connection.settimeout(remaining)


def _canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _strict_document(payload: bytes, *, label: str) -> dict[str, object]:
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise MTLSTransportError(f"{label}_size_invalid")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise MTLSTransportError(f"{label}_duplicate_field")
            document[key] = value
        return document

    try:
        document = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                MTLSTransportError(f"{label}_invalid")
            ),
        )
    except MTLSTransportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MTLSTransportError(f"{label}_invalid") from exc
    if not isinstance(document, dict) or not hmac.compare_digest(
        payload, _canonical(document)
    ):
        raise MTLSTransportError(f"{label}_invalid")
    return document


def _validate_private_key_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("tls_private_key_unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("tls_private_key_not_regular")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("tls_private_key_permissions_too_open")


def build_client_context(
    *, ca_file: Path, certificate_file: Path, private_key_file: Path
) -> ssl.SSLContext:
    _validate_private_key_file(private_key_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certfile=certificate_file, keyfile=private_key_file)
    return context


def build_server_context(
    *, ca_file: Path, certificate_file: Path, private_key_file: Path
) -> ssl.SSLContext:
    _validate_private_key_file(private_key_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certfile=certificate_file, keyfile=private_key_file)
    return context


def _validate_context(context: ssl.SSLContext, *, server_side: bool) -> None:
    if not isinstance(context, ssl.SSLContext):
        raise ValueError("tls_context_policy_invalid")
    expected_protocol = (
        ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
    )
    maximum_version = context.maximum_version
    if (
        context.protocol != expected_protocol
        or context.minimum_version < ssl.TLSVersion.TLSv1_3
        or (
            maximum_version != ssl.TLSVersion.MAXIMUM_SUPPORTED
            and maximum_version < ssl.TLSVersion.TLSv1_3
        )
        or context.verify_mode != ssl.CERT_REQUIRED
        or (not server_side and not context.check_hostname)
    ):
        raise ValueError("tls_context_policy_invalid")


def _normalize_pins(pins: Collection[str]) -> frozenset[str]:
    if isinstance(pins, (str, bytes)) or not 1 <= len(pins) <= MAX_CERTIFICATE_PINS:
        raise ValueError("certificate_pins_invalid")
    normalized: set[str] = set()
    for pin in pins:
        if (
            not isinstance(pin, str)
            or len(pin) != 64
            or any(character not in "0123456789abcdef" for character in pin)
        ):
            raise ValueError("certificate_pins_invalid")
        normalized.add(pin)
    if not normalized:
        raise ValueError("certificate_pins_invalid")
    return frozenset(normalized)


def _verify_peer_certificate(
    connection: ssl.SSLSocket, pins: Collection[str], *, peer: str
) -> str:
    trusted = _normalize_pins(pins)
    certificate = connection.getpeercert(binary_form=True)
    if not certificate:
        raise MTLSTransportError(f"{peer}_certificate_missing")
    fingerprint = hashlib.sha256(certificate).hexdigest()
    if not any(hmac.compare_digest(fingerprint, pin) for pin in trusted):
        raise MTLSTransportError(f"{peer}_certificate_pin_mismatch")
    return fingerprint


def _receive_exact(
    connection: socket.socket, byte_count: int, deadline: _Deadline
) -> bytes:
    chunks: list[bytes] = []
    remaining = byte_count
    while remaining:
        deadline.apply(connection)
        chunk = connection.recv(remaining)
        if not chunk:
            raise MTLSTransportError("transport_frame_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_frame(connection: socket.socket, deadline: _Deadline) -> bytes:
    header = _receive_exact(connection, _FRAME_HEADER.size, deadline)
    (frame_size,) = _FRAME_HEADER.unpack(header)
    if not 1 <= frame_size <= MAX_FRAME_BYTES:
        raise MTLSTransportError("transport_frame_size_invalid")
    return _receive_exact(connection, frame_size, deadline)


def _send_frame(connection: socket.socket, payload: bytes, deadline: _Deadline) -> None:
    if not 1 <= len(payload) <= MAX_FRAME_BYTES:
        raise MTLSTransportError("transport_frame_size_invalid")
    deadline.apply(connection)
    connection.sendall(_FRAME_HEADER.pack(len(payload)) + payload)


def _append_envelope(
    receipt: LoopbackReceipt, request: AppendRequest
) -> dict[str, object]:
    return {
        "receipt": receipt.as_dict(),
        "request": request.as_dict(),
        "schema_version": TRANSPORT_SCHEMA_VERSION,
    }


def _parse_append_envelope(payload: bytes) -> tuple[LoopbackReceipt, AppendRequest]:
    document = _strict_document(payload, label="append_envelope")
    schema_version = document.get("schema_version")
    if (
        set(document) != {"receipt", "request", "schema_version"}
        or isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != TRANSPORT_SCHEMA_VERSION
    ):
        raise MTLSTransportError("append_envelope_fields_invalid")
    try:
        receipt = parse_loopback_receipt(_canonical(document["receipt"]))
        request = parse_append_request(_canonical(document["request"]))
    except (TypeError, ValueError) as exc:
        raise MTLSTransportError("append_envelope_invalid") from exc
    return receipt, request


def _accepted_response(checkpoint: LedgerCheckpoint) -> bytes:
    return _canonical(
        {
            "checkpoint": checkpoint.as_dict(),
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "status": "accepted",
        }
    )


def _rejected_response() -> bytes:
    return _canonical(
        {
            "code": "append_rejected",
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "status": "rejected",
        }
    )


def _parse_response(payload: bytes) -> LedgerCheckpoint:
    document = _strict_document(payload, label="append_response")
    schema_version = document.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != TRANSPORT_SCHEMA_VERSION
    ):
        raise MTLSTransportError("append_response_fields_invalid")
    if document.get("status") == "rejected":
        if (
            set(document) != {"code", "schema_version", "status"}
            or document.get("code") != "append_rejected"
        ):
            raise MTLSTransportError("append_response_fields_invalid")
        raise AppendRejected("append_rejected")
    if document.get("status") != "accepted" or set(document) != {
        "checkpoint",
        "schema_version",
        "status",
    }:
        raise MTLSTransportError("append_response_fields_invalid")
    try:
        return parse_checkpoint(_canonical(document["checkpoint"]))
    except (TypeError, ValueError) as exc:
        raise MTLSTransportError("append_response_invalid") from exc


def _verify_checkpoint_binding(
    checkpoint: LedgerCheckpoint,
    receipt: LoopbackReceipt,
    request: AppendRequest,
) -> None:
    entry = {
        "previous_entry_sha256": request.expected_ledger_head_sha256,
        "receipt": receipt.as_dict(),
        "request_hmac_sha256": request.hmac_sha256,
        "request_nonce": request.nonce,
        "schema_version": ENTRY_SCHEMA_VERSION,
        "sequence": checkpoint.entry_count,
    }
    expected_head = hashlib.sha256(_canonical(entry)).hexdigest()
    if not hmac.compare_digest(checkpoint.ledger_head_sha256, expected_head):
        raise MTLSTransportError("append_response_checkpoint_mismatch")


def deliver_append_request(
    host: str,
    port: int,
    *,
    server_hostname: str,
    context: ssl.SSLContext,
    trusted_server_certificate_sha256: Collection[str],
    receipt: LoopbackReceipt,
    request: AppendRequest,
    timeout_seconds: float = 5.0,
) -> LedgerCheckpoint:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("transport_host_invalid")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("transport_port_invalid")
    if (
        not isinstance(server_hostname, str)
        or not server_hostname
        or len(server_hostname) > 253
    ):
        raise ValueError("server_hostname_invalid")
    pins = _normalize_pins(trusted_server_certificate_sha256)
    _validate_context(context, server_side=False)
    deadline = _Deadline(timeout_seconds)
    try:
        raw_connection = socket.create_connection(
            (host, port), timeout=float(timeout_seconds)
        )
        with raw_connection:
            deadline.apply(raw_connection)
            with context.wrap_socket(
                raw_connection,
                server_hostname=server_hostname,
                do_handshake_on_connect=False,
            ) as tls_connection:
                deadline.apply(tls_connection)
                tls_connection.do_handshake()
                _verify_peer_certificate(tls_connection, pins, peer="server")
                _send_frame(
                    tls_connection,
                    _canonical(_append_envelope(receipt, request)),
                    deadline,
                )
                checkpoint = _parse_response(_receive_frame(tls_connection, deadline))
                _verify_checkpoint_binding(checkpoint, receipt, request)
                return checkpoint
    except (AppendRejected, MTLSTransportError):
        raise
    except (TimeoutError, socket.timeout) as exc:
        raise MTLSTransportError("transport_deadline_exceeded") from exc
    except ssl.SSLError as exc:
        raise MTLSTransportError("tls_connection_failed") from exc
    except OSError as exc:
        raise MTLSTransportError("transport_connection_failed") from exc


def collect_one_append(
    listener: socket.socket,
    *,
    context: ssl.SSLContext,
    trusted_client_certificate_sha256: Collection[str],
    ledger_path: Path,
    request_key: bytes,
    checkpoint_key: bytes,
    expected_payload: bytes | None = None,
    timeout_seconds: float = 5.0,
) -> CollectorResult:
    pins = _normalize_pins(trusted_client_certificate_sha256)
    _validate_context(context, server_side=True)
    deadline = _Deadline(timeout_seconds)
    try:
        deadline.apply(listener)
        raw_connection, _ = listener.accept()
        with raw_connection:
            deadline.apply(raw_connection)
            with context.wrap_socket(
                raw_connection,
                server_side=True,
                do_handshake_on_connect=False,
            ) as tls_connection:
                deadline.apply(tls_connection)
                tls_connection.do_handshake()
                _verify_peer_certificate(tls_connection, pins, peer="client")
                receipt, request = _parse_append_envelope(
                    _receive_frame(tls_connection, deadline)
                )
                try:
                    checkpoint = append_receipt(
                        ledger_path,
                        receipt,
                        request,
                        request_key=request_key,
                        checkpoint_key=checkpoint_key,
                        expected_payload=expected_payload,
                    )
                except ValueError as exc:
                    _send_frame(tls_connection, _rejected_response(), deadline)
                    return CollectorResult(False, None, str(exc))
                _send_frame(tls_connection, _accepted_response(checkpoint), deadline)
                return CollectorResult(True, checkpoint, None)
    except MTLSTransportError:
        raise
    except (TimeoutError, socket.timeout) as exc:
        raise MTLSTransportError("transport_deadline_exceeded") from exc
    except ssl.SSLError as exc:
        raise MTLSTransportError("tls_connection_failed") from exc
    except OSError as exc:
        raise MTLSTransportError("transport_connection_failed") from exc
