from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from tools.proxy_v2_loopback import (
    MAX_RECEIPT_BYTES,
    LoopbackReceipt,
    parse_loopback_receipt,
    verify_loopback_receipt,
)

GENESIS_HEAD = "0" * 64
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_LEDGER_ENTRIES = 10_000
MAX_REQUEST_BYTES = 4096
MAX_CHECKPOINT_BYTES = 4096
MIN_HMAC_KEY_BYTES = 32
MAX_HMAC_KEY_BYTES = 64
REQUEST_SCHEMA_VERSION = 1
ENTRY_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1
_NONCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_key(key: bytes) -> None:
    if not MIN_HMAC_KEY_BYTES <= len(key) <= MAX_HMAC_KEY_BYTES:
        raise ValueError("hmac_key_size_invalid")


def _validate_distinct_keys(request_key: bytes, checkpoint_key: bytes) -> None:
    _validate_key(request_key)
    _validate_key(checkpoint_key)
    if hmac.compare_digest(request_key, checkpoint_key):
        raise ValueError("hmac_key_roles_not_distinct")


def _strict_json(
    payload: bytes, *, maximum_bytes: int, label: str
) -> dict[str, object]:
    if not payload or len(payload) > maximum_bytes:
        raise ValueError(f"{label}_size_invalid")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate_{label}_key")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non_finite_{label}_value:{value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_json_invalid") from exc
    if not isinstance(document, dict):
        raise TypeError(f"{label}_not_object")
    return document


@dataclass(frozen=True)
class AppendRequest:
    schema_version: int
    expected_ledger_head_sha256: str
    receipt_document_sha256: str
    nonce: str
    hmac_sha256: str

    def as_dict(self) -> dict[str, int | str]:
        return {
            "expected_ledger_head_sha256": self.expected_ledger_head_sha256,
            "hmac_sha256": self.hmac_sha256,
            "nonce": self.nonce,
            "receipt_document_sha256": self.receipt_document_sha256,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class LedgerCheckpoint:
    schema_version: int
    entry_count: int
    ledger_head_sha256: str
    ledger_sha256: str
    hmac_sha256: str

    def as_dict(self) -> dict[str, int | str]:
        return {
            "entry_count": self.entry_count,
            "hmac_sha256": self.hmac_sha256,
            "ledger_head_sha256": self.ledger_head_sha256,
            "ledger_sha256": self.ledger_sha256,
            "schema_version": self.schema_version,
        }


def _request_document(
    *, expected_head: str, receipt_document_sha256: str, nonce: str
) -> dict[str, int | str]:
    return {
        "expected_ledger_head_sha256": expected_head,
        "nonce": nonce,
        "receipt_document_sha256": receipt_document_sha256,
        "schema_version": REQUEST_SCHEMA_VERSION,
    }


def build_append_request(
    receipt: LoopbackReceipt,
    *,
    expected_head: str,
    nonce: str,
    request_key: bytes,
    expected_payload: bytes | None = None,
) -> AppendRequest:
    _validate_key(request_key)
    if not _is_sha256(expected_head):
        raise ValueError("expected_ledger_head_invalid")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("request_nonce_invalid")
    if not verify_loopback_receipt(receipt, expected_payload=expected_payload):
        raise ValueError("receipt_verification_failed")
    receipt_document_sha256 = _sha256(_canonical(receipt.as_dict()))
    document = _request_document(
        expected_head=expected_head,
        receipt_document_sha256=receipt_document_sha256,
        nonce=nonce,
    )
    return AppendRequest(
        **document,
        hmac_sha256=hmac.new(
            request_key, _canonical(document), hashlib.sha256
        ).hexdigest(),
    )


def parse_append_request(payload: bytes) -> AppendRequest:
    document = _strict_json(payload, maximum_bytes=MAX_REQUEST_BYTES, label="request")
    if set(document) != set(AppendRequest.__dataclass_fields__):
        raise ValueError("request_fields_invalid")
    try:
        request = AppendRequest(**document)
    except TypeError as exc:
        raise ValueError("request_fields_invalid") from exc
    if (
        isinstance(request.schema_version, bool)
        or not isinstance(request.schema_version, int)
        or request.schema_version != REQUEST_SCHEMA_VERSION
        or not _is_sha256(request.expected_ledger_head_sha256)
        or not _is_sha256(request.receipt_document_sha256)
        or not _is_sha256(request.hmac_sha256)
        or not isinstance(request.nonce, str)
        or _NONCE_RE.fullmatch(request.nonce) is None
    ):
        raise ValueError("request_fields_invalid")
    return request


def _verify_append_request(
    request: AppendRequest, receipt: LoopbackReceipt, *, request_key: bytes
) -> None:
    _validate_key(request_key)
    receipt_document_sha256 = _sha256(_canonical(receipt.as_dict()))
    if not hmac.compare_digest(
        request.receipt_document_sha256, receipt_document_sha256
    ):
        raise ValueError("request_receipt_mismatch")
    document = _request_document(
        expected_head=request.expected_ledger_head_sha256,
        receipt_document_sha256=request.receipt_document_sha256,
        nonce=request.nonce,
    )
    expected_hmac = hmac.new(
        request_key, _canonical(document), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(request.hmac_sha256, expected_hmac):
        raise ValueError("request_authentication_failed")


def _entry_document(
    *,
    sequence: int,
    previous_head: str,
    receipt: LoopbackReceipt,
    request: AppendRequest,
) -> dict[str, object]:
    return {
        "previous_entry_sha256": previous_head,
        "receipt": receipt.as_dict(),
        "request_hmac_sha256": request.hmac_sha256,
        "request_nonce": request.nonce,
        "schema_version": ENTRY_SCHEMA_VERSION,
        "sequence": sequence,
    }


def _checkpoint_document(
    *, entry_count: int, ledger_head: str, ledger_sha256: str
) -> dict[str, int | str]:
    return {
        "entry_count": entry_count,
        "ledger_head_sha256": ledger_head,
        "ledger_sha256": ledger_sha256,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
    }


def _build_checkpoint(
    *,
    ledger_payload: bytes,
    entry_count: int,
    ledger_head: str,
    checkpoint_key: bytes,
) -> LedgerCheckpoint:
    document = _checkpoint_document(
        entry_count=entry_count,
        ledger_head=ledger_head,
        ledger_sha256=_sha256(ledger_payload),
    )
    return LedgerCheckpoint(
        **document,
        hmac_sha256=hmac.new(
            checkpoint_key, _canonical(document), hashlib.sha256
        ).hexdigest(),
    )


def parse_checkpoint(payload: bytes) -> LedgerCheckpoint:
    document = _strict_json(
        payload, maximum_bytes=MAX_CHECKPOINT_BYTES, label="checkpoint"
    )
    if set(document) != set(LedgerCheckpoint.__dataclass_fields__):
        raise ValueError("checkpoint_fields_invalid")
    try:
        checkpoint = LedgerCheckpoint(**document)
    except TypeError as exc:
        raise ValueError("checkpoint_fields_invalid") from exc
    if (
        isinstance(checkpoint.schema_version, bool)
        or not isinstance(checkpoint.schema_version, int)
        or checkpoint.schema_version != CHECKPOINT_SCHEMA_VERSION
        or isinstance(checkpoint.entry_count, bool)
        or not isinstance(checkpoint.entry_count, int)
        or not 1 <= checkpoint.entry_count <= MAX_LEDGER_ENTRIES
        or not _is_sha256(checkpoint.ledger_head_sha256)
        or not _is_sha256(checkpoint.ledger_sha256)
        or not _is_sha256(checkpoint.hmac_sha256)
    ):
        raise ValueError("checkpoint_fields_invalid")
    return checkpoint


def _verify_checkpoint(
    checkpoint: LedgerCheckpoint,
    *,
    ledger_payload: bytes,
    entry_count: int,
    ledger_head: str,
    checkpoint_key: bytes,
) -> None:
    document = _checkpoint_document(
        entry_count=checkpoint.entry_count,
        ledger_head=checkpoint.ledger_head_sha256,
        ledger_sha256=checkpoint.ledger_sha256,
    )
    expected_hmac = hmac.new(
        checkpoint_key, _canonical(document), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(checkpoint.hmac_sha256, expected_hmac):
        raise ValueError("checkpoint_authentication_failed")
    if (
        checkpoint.entry_count != entry_count
        or not hmac.compare_digest(checkpoint.ledger_head_sha256, ledger_head)
        or not hmac.compare_digest(checkpoint.ledger_sha256, _sha256(ledger_payload))
    ):
        raise ValueError("checkpoint_ledger_mismatch")


def _receipt_from_document(document: object) -> LoopbackReceipt:
    return parse_loopback_receipt(_canonical(document))


def _verify_ledger_payload(
    payload: bytes, *, request_key: bytes
) -> tuple[int, str, set[str]]:
    _validate_key(request_key)
    if len(payload) > MAX_LEDGER_BYTES:
        raise ValueError("ledger_size_invalid")
    if not payload:
        return 0, GENESIS_HEAD, set()
    if not payload.endswith(b"\n"):
        raise ValueError("ledger_truncated")
    lines = payload.splitlines()
    if not 1 <= len(lines) <= MAX_LEDGER_ENTRIES:
        raise ValueError("ledger_entry_count_invalid")

    previous_head = GENESIS_HEAD
    nonces: set[str] = set()
    expected_fields = {
        "entry_sha256",
        "previous_entry_sha256",
        "receipt",
        "request_hmac_sha256",
        "request_nonce",
        "schema_version",
        "sequence",
    }
    for sequence, line in enumerate(lines, start=1):
        document = _strict_json(
            line, maximum_bytes=MAX_REQUEST_BYTES * 2, label="entry"
        )
        if set(document) != expected_fields:
            raise ValueError("ledger_entry_fields_invalid")
        claimed_entry_sha256 = document.pop("entry_sha256")
        schema_version = document.get("schema_version")
        claimed_sequence = document.get("sequence")
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != ENTRY_SCHEMA_VERSION
            or isinstance(claimed_sequence, bool)
            or not isinstance(claimed_sequence, int)
            or claimed_sequence != sequence
            or not hmac.compare_digest(
                str(document.get("previous_entry_sha256")), previous_head
            )
            or not _is_sha256(claimed_entry_sha256)
        ):
            raise ValueError("ledger_chain_invalid")
        nonce = document.get("request_nonce")
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise ValueError("ledger_request_invalid")
        if nonce in nonces:
            raise ValueError("duplicate_request_nonce")
        nonces.add(nonce)
        receipt = _receipt_from_document(document.get("receipt"))
        if not verify_loopback_receipt(receipt):
            raise ValueError("ledger_receipt_invalid")
        request = AppendRequest(
            schema_version=REQUEST_SCHEMA_VERSION,
            expected_ledger_head_sha256=previous_head,
            receipt_document_sha256=_sha256(_canonical(receipt.as_dict())),
            nonce=nonce,
            hmac_sha256=str(document.get("request_hmac_sha256")),
        )
        _verify_append_request(request, receipt, request_key=request_key)
        expected_entry_sha256 = _sha256(_canonical(document))
        if not hmac.compare_digest(str(claimed_entry_sha256), expected_entry_sha256):
            raise ValueError("ledger_entry_digest_invalid")
        complete_document = {**document, "entry_sha256": claimed_entry_sha256}
        if not hmac.compare_digest(line, _canonical(complete_document)):
            raise ValueError("ledger_entry_not_canonical")
        previous_head = str(claimed_entry_sha256)
    return len(lines), previous_head, nonces


def _open_ledger(path: Path, *, create: bool) -> int:
    if path.is_symlink():
        raise ValueError("ledger_symlink_forbidden")
    flags = os.O_RDWR
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileNotFoundError as exc:
        raise ValueError("ledger_missing") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError("ledger_not_regular_file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        os.close(descriptor)
        raise ValueError("ledger_permissions_too_open")
    return descriptor


def _read_descriptor(descriptor: int) -> bytes:
    size = os.fstat(descriptor).st_size
    if size > MAX_LEDGER_BYTES:
        raise ValueError("ledger_size_invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            raise ValueError("ledger_truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def append_receipt(
    ledger_path: Path,
    receipt: LoopbackReceipt,
    request: AppendRequest,
    *,
    request_key: bytes,
    checkpoint_key: bytes,
    expected_payload: bytes | None = None,
) -> LedgerCheckpoint:
    if not verify_loopback_receipt(receipt, expected_payload=expected_payload):
        raise ValueError("receipt_verification_failed")
    _validate_distinct_keys(request_key, checkpoint_key)
    _verify_append_request(request, receipt, request_key=request_key)
    descriptor = _open_ledger(ledger_path, create=True)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        existing_payload = _read_descriptor(descriptor)
        entry_count, current_head, nonces = _verify_ledger_payload(
            existing_payload, request_key=request_key
        )
        if not hmac.compare_digest(request.expected_ledger_head_sha256, current_head):
            raise ValueError("stale_ledger_head")
        if request.nonce in nonces:
            raise ValueError("duplicate_request_nonce")
        if entry_count >= MAX_LEDGER_ENTRIES:
            raise ValueError("ledger_entry_count_invalid")
        document = _entry_document(
            sequence=entry_count + 1,
            previous_head=current_head,
            receipt=receipt,
            request=request,
        )
        entry_sha256 = _sha256(_canonical(document))
        entry_payload = _canonical({**document, "entry_sha256": entry_sha256}) + b"\n"
        if len(existing_payload) + len(entry_payload) > MAX_LEDGER_BYTES:
            raise ValueError("ledger_size_invalid")
        os.lseek(descriptor, 0, os.SEEK_END)
        written = 0
        while written < len(entry_payload):
            byte_count = os.write(descriptor, entry_payload[written:])
            if byte_count <= 0:
                raise OSError("ledger_append_incomplete")
            written += byte_count
        os.fsync(descriptor)
        ledger_payload = existing_payload + entry_payload
        return _build_checkpoint(
            ledger_payload=ledger_payload,
            entry_count=entry_count + 1,
            ledger_head=entry_sha256,
            checkpoint_key=checkpoint_key,
        )
    finally:
        os.close(descriptor)


def verify_ledger(
    ledger_path: Path,
    checkpoint: LedgerCheckpoint,
    *,
    request_key: bytes,
    checkpoint_key: bytes,
    expected_head: str | None = None,
    minimum_entries: int = 1,
) -> None:
    if isinstance(minimum_entries, bool) or not isinstance(minimum_entries, int):
        raise TypeError("minimum_entries_invalid")
    if not 1 <= minimum_entries <= MAX_LEDGER_ENTRIES:
        raise ValueError("minimum_entries_invalid")
    if expected_head is not None and not _is_sha256(expected_head):
        raise ValueError("expected_ledger_head_invalid")
    _validate_distinct_keys(request_key, checkpoint_key)
    descriptor = _open_ledger(ledger_path, create=False)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        ledger_payload = _read_descriptor(descriptor)
        entry_count, ledger_head, _ = _verify_ledger_payload(
            ledger_payload, request_key=request_key
        )
    finally:
        os.close(descriptor)
    if entry_count < minimum_entries:
        raise ValueError("ledger_below_minimum_entries")
    if expected_head is not None and not hmac.compare_digest(
        expected_head, ledger_head
    ):
        raise ValueError("ledger_head_mismatch")
    _verify_checkpoint(
        checkpoint,
        ledger_payload=ledger_payload,
        entry_count=entry_count,
        ledger_head=ledger_head,
        checkpoint_key=checkpoint_key,
    )


def _read_private_key(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("hmac_key_symlink_forbidden")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("hmac_key_not_regular_file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("hmac_key_permissions_too_open")
        if metadata.st_size > MAX_HMAC_KEY_BYTES:
            raise ValueError("hmac_key_size_invalid")
        key = os.read(descriptor, MAX_HMAC_KEY_BYTES + 1)
    finally:
        os.close(descriptor)
    _validate_key(key)
    return key


def _read_bounded(path: Path, maximum_bytes: int, label: str) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{label}_symlink_forbidden")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label}_not_regular_file")
        if metadata.st_size > maximum_bytes:
            raise ValueError(f"{label}_size_invalid")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ValueError(f"{label}_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > maximum_bytes:
        raise ValueError(f"{label}_size_invalid")
    return payload


def _write_private_json(path: Path, document: object) -> None:
    if path.is_symlink():
        raise ValueError("output_symlink_forbidden")
    payload = _canonical(document) + b"\n"
    path.parent.mkdir(parents=False, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        temporary.write(payload)
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_path, path)


def _hex_payload(value: str) -> bytes:
    try:
        payload = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be hexadecimal") from exc
    if not payload:
        raise argparse.ArgumentTypeError("must not be empty")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate and retain PROXY v2 loopback receipts"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser("create-request")
    request_parser.add_argument("receipt", type=Path)
    request_parser.add_argument("output", type=Path)
    request_parser.add_argument("--request-key-file", required=True, type=Path)
    request_parser.add_argument("--expected-head", required=True)
    request_parser.add_argument("--nonce", required=True)
    request_parser.add_argument("--payload-hex", required=True, type=_hex_payload)

    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("receipt", type=Path)
    append_parser.add_argument("request", type=Path)
    append_parser.add_argument("ledger", type=Path)
    append_parser.add_argument("checkpoint", type=Path)
    append_parser.add_argument("--request-key-file", required=True, type=Path)
    append_parser.add_argument("--checkpoint-key-file", required=True, type=Path)
    append_parser.add_argument("--payload-hex", required=True, type=_hex_payload)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("ledger", type=Path)
    verify_parser.add_argument("checkpoint", type=Path)
    verify_parser.add_argument("--request-key-file", required=True, type=Path)
    verify_parser.add_argument("--checkpoint-key-file", required=True, type=Path)
    verify_parser.add_argument("--expected-head")
    verify_parser.add_argument("--minimum-entries", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    request_key = _read_private_key(args.request_key_file)
    if args.command == "create-request":
        receipt = parse_loopback_receipt(
            _read_bounded(args.receipt, MAX_RECEIPT_BYTES + 1, "receipt").rstrip(b"\n")
        )
        request = build_append_request(
            receipt,
            expected_head=args.expected_head,
            nonce=args.nonce,
            request_key=request_key,
            expected_payload=args.payload_hex,
        )
        _write_private_json(args.output, request.as_dict())
        return 0
    if args.command == "append":
        checkpoint_key = _read_private_key(args.checkpoint_key_file)
        receipt = parse_loopback_receipt(
            _read_bounded(args.receipt, MAX_RECEIPT_BYTES + 1, "receipt").rstrip(b"\n")
        )
        request = parse_append_request(
            _read_bounded(args.request, MAX_REQUEST_BYTES, "request").rstrip(b"\n")
        )
        checkpoint = append_receipt(
            args.ledger,
            receipt,
            request,
            request_key=request_key,
            checkpoint_key=checkpoint_key,
            expected_payload=args.payload_hex,
        )
        _write_private_json(args.checkpoint, checkpoint.as_dict())
        return 0

    checkpoint_key = _read_private_key(args.checkpoint_key_file)
    checkpoint = parse_checkpoint(
        _read_bounded(args.checkpoint, MAX_CHECKPOINT_BYTES, "checkpoint").rstrip(b"\n")
    )
    verify_ledger(
        args.ledger,
        checkpoint,
        request_key=request_key,
        checkpoint_key=checkpoint_key,
        expected_head=args.expected_head,
        minimum_entries=args.minimum_entries,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
