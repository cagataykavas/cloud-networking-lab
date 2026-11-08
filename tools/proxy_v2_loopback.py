from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import signal
import socket
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from tools.connection_limiter import ConnectionLimitPolicy, ConnectionLimiter
from tools.listener_admission import admit_listener_connection
from tools.proxy_v2 import ProxyV2Policy


MAX_RECEIPT_BYTES = 4096
MAX_APPLICATION_BYTES = 4096
SCHEMA_VERSION = 1


def _sha256_json(document: object) -> str:
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True)
class LoopbackReceipt:
    schema_version: int
    outcome: str
    application_bytes: int
    application_sha256: str
    capacity_policy_sha256: str
    proxy_policy_sha256: str
    proxy_admission_evidence_sha256: str
    connection_admission_evidence_sha256: str
    evidence_sha256: str

    def as_dict(self) -> dict[str, int | str]:
        return asdict(self)


def build_loopback_receipt(
    *,
    application_payload: bytes,
    capacity_policy_sha256: str,
    proxy_policy_sha256: str,
    proxy_admission_evidence_sha256: str,
    connection_admission_evidence_sha256: str,
) -> LoopbackReceipt:
    document: dict[str, int | str] = {
        "application_bytes": len(application_payload),
        "application_sha256": hashlib.sha256(application_payload).hexdigest(),
        "capacity_policy_sha256": capacity_policy_sha256,
        "connection_admission_evidence_sha256": connection_admission_evidence_sha256,
        "outcome": "accepted",
        "proxy_admission_evidence_sha256": proxy_admission_evidence_sha256,
        "proxy_policy_sha256": proxy_policy_sha256,
        "schema_version": SCHEMA_VERSION,
    }
    return LoopbackReceipt(**document, evidence_sha256=_sha256_json(document))


def verify_loopback_receipt(
    receipt: LoopbackReceipt, *, expected_payload: bytes | None = None
) -> bool:
    document = receipt.as_dict()
    claimed = document.pop("evidence_sha256")
    if (
        receipt.schema_version != SCHEMA_VERSION
        or receipt.outcome != "accepted"
        or isinstance(receipt.application_bytes, bool)
        or not isinstance(receipt.application_bytes, int)
        or not 0 <= receipt.application_bytes <= MAX_APPLICATION_BYTES
        or not all(
            _is_sha256(value)
            for key, value in document.items()
            if key.endswith("sha256")
        )
        or not _is_sha256(claimed)
        or not hmac.compare_digest(str(claimed), _sha256_json(document))
    ):
        return False
    if expected_payload is None:
        return True
    return receipt.application_bytes == len(expected_payload) and hmac.compare_digest(
        receipt.application_sha256, hashlib.sha256(expected_payload).hexdigest()
    )


def parse_loopback_receipt(payload: bytes) -> LoopbackReceipt:
    if not payload or len(payload) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt_size_invalid")

    def reject_duplicate(
        key_value_pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in key_value_pairs:
            if key in result:
                raise ValueError("duplicate_receipt_key")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non_finite_receipt_value:{value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("receipt_json_invalid") from exc
    if not isinstance(document, dict):
        raise ValueError("receipt_not_object")
    expected_fields = set(LoopbackReceipt.__dataclass_fields__)
    if set(document) != expected_fields:
        raise ValueError("receipt_fields_invalid")
    try:
        return LoopbackReceipt(**document)
    except TypeError as exc:
        raise ValueError("receipt_fields_invalid") from exc


def _read_exact(connection: socket.socket, byte_count: int, timeout: float) -> bytes:
    if byte_count < 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("read_bounds_invalid")
    previous_timeout = connection.gettimeout()
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    remaining_bytes = byte_count
    try:
        while remaining_bytes:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise TimeoutError("application_frame_deadline_exceeded")
            connection.settimeout(remaining_time)
            chunk = connection.recv(remaining_bytes)
            if not chunk:
                raise EOFError("application_frame_truncated")
            chunks.append(chunk)
            remaining_bytes -= len(chunk)
        return b"".join(chunks)
    finally:
        connection.settimeout(previous_timeout)


def _serve_connection(
    connection: socket.socket,
    *,
    limiter: ConnectionLimiter,
    proxy_policy: ProxyV2Policy,
    expected_payload: bytes,
) -> None:
    peer = connection.getpeername()
    with admit_listener_connection(
        connection,
        immediate_peer=str(peer[0]),
        limiter=limiter,
        proxy_policy=proxy_policy,
        read_timeout_seconds=1.0,
    ) as admission:
        if not admission.accepted:
            print(json.dumps(admission.evidence.as_dict(), sort_keys=True), flush=True)
            return
        application_payload = _read_exact(connection, len(expected_payload), 1.0)
        if not hmac.compare_digest(application_payload, expected_payload):
            raise ValueError("application_frame_mismatch")
        proxy_evidence_sha256 = admission.evidence.proxy_evidence_sha256
        if proxy_evidence_sha256 is None:
            raise RuntimeError("accepted_admission_missing_proxy_evidence")
        receipt = build_loopback_receipt(
            application_payload=application_payload,
            capacity_policy_sha256=admission.evidence.capacity_policy_sha256,
            proxy_policy_sha256=admission.evidence.proxy_policy_sha256,
            proxy_admission_evidence_sha256=proxy_evidence_sha256,
            connection_admission_evidence_sha256=admission.evidence.evidence_sha256,
        )
        connection.sendall(
            json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")).encode(
                "ascii"
            )
            + b"\n"
        )


def serve(
    *,
    host: str,
    port: int,
    trusted_proxy_cidr: str,
    destination_cidr: str,
    destination_port: int,
    expected_payload: bytes,
) -> int:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=8))
    proxy_policy = ProxyV2Policy.from_strings(
        trusted_proxy_cidrs=(trusted_proxy_cidr,),
        destination_cidrs=(destination_cidr,),
        destination_ports=(destination_port,),
        require_crc32c=False,
    )
    stopping = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(16)
        listener.settimeout(0.25)
        while not stopping.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    _serve_connection(
                        connection,
                        limiter=limiter,
                        proxy_policy=proxy_policy,
                        expected_payload=expected_payload,
                    )
                except (EOFError, OSError, TimeoutError, ValueError) as exc:
                    print(
                        json.dumps(
                            {
                                "outcome": "rejected",
                                "reason": str(exc),
                                "schema_version": SCHEMA_VERSION,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
    return 0


def _probe_once(host: str, port: int, payload: bytes) -> LoopbackReceipt:
    with socket.create_connection((host, port), timeout=1.0) as connection:
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while b"\n" not in response:
            remaining = MAX_RECEIPT_BYTES + 1 - len(response)
            chunk = connection.recv(min(1024, remaining))
            if not chunk:
                raise EOFError("receipt_truncated")
            response.extend(chunk)
            if len(response) > MAX_RECEIPT_BYTES:
                raise ValueError("receipt_size_invalid")
        line, separator, trailing = bytes(response).partition(b"\n")
        if separator != b"\n" or trailing:
            raise ValueError("receipt_framing_invalid")
    receipt = parse_loopback_receipt(line)
    if not verify_loopback_receipt(receipt, expected_payload=payload):
        raise ValueError("receipt_verification_failed")
    return receipt


def probe(
    *, host: str, port: int, payload: bytes, attempts: int, retry_seconds: float
) -> LoopbackReceipt:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return _probe_once(host, port, payload)
        except (EOFError, OSError, TimeoutError, ValueError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(retry_seconds)
    raise RuntimeError(f"proxy_v2_loopback_failed:{last_error}") from last_error


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _hex_payload(value: str) -> bytes:
    try:
        payload = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be hexadecimal") from exc
    if not payload or len(payload) > MAX_APPLICATION_BYTES:
        raise argparse.ArgumentTypeError(
            f"must decode to 1..{MAX_APPLICATION_BYTES} bytes"
        )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Exercise the listener admission boundary through a real proxy"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=_positive_int, default=9000)
    serve_parser.add_argument("--trusted-proxy-cidr", required=True)
    serve_parser.add_argument("--destination-cidr", required=True)
    serve_parser.add_argument("--destination-port", type=_positive_int, required=True)
    serve_parser.add_argument(
        "--expected-payload-hex", type=_hex_payload, required=True
    )

    probe_parser = subparsers.add_parser("probe")
    probe_parser.add_argument("--host", required=True)
    probe_parser.add_argument("--port", type=_positive_int, required=True)
    probe_parser.add_argument("--payload-hex", type=_hex_payload, required=True)
    probe_parser.add_argument("--attempts", type=_positive_int, default=20)
    probe_parser.add_argument("--retry-seconds", type=float, default=0.25)

    verify_parser = subparsers.add_parser("verify-receipt")
    verify_parser.add_argument("receipt", type=Path)
    verify_parser.add_argument("--payload-hex", type=_hex_payload, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return serve(
            host=args.host,
            port=args.port,
            trusted_proxy_cidr=args.trusted_proxy_cidr,
            destination_cidr=args.destination_cidr,
            destination_port=args.destination_port,
            expected_payload=args.expected_payload_hex,
        )
    if args.command == "probe":
        if not math.isfinite(args.retry_seconds) or not 0 <= args.retry_seconds <= 5:
            raise SystemExit("retry-seconds must be finite and in [0, 5]")
        receipt = probe(
            host=args.host,
            port=args.port,
            payload=args.payload_hex,
            attempts=args.attempts,
            retry_seconds=args.retry_seconds,
        )
        print(json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0

    payload = args.receipt.read_bytes()
    if len(payload) > MAX_RECEIPT_BYTES + 1:
        raise SystemExit("receipt_size_invalid")
    receipt = parse_loopback_receipt(payload.rstrip(b"\n"))
    if not verify_loopback_receipt(receipt, expected_payload=args.payload_hex):
        raise SystemExit("receipt_verification_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
