"""Fail-closed HTTP/1.x request-framing admission.

The parser intentionally accepts a narrow, unambiguous subset of HTTP/1.x.
It is designed for a reverse-proxy/backend conformance gate, not as a general
purpose HTTP server.  Rejected reports never copy request targets or header
values into evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

SCHEMA_VERSION: Final = "http1-framing-report/v1"
EXIT_ACCEPTED: Final = 0
EXIT_REJECTED: Final = 2
EXIT_ERROR: Final = 3

_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CANONICAL_LENGTH = re.compile(rb"^(?:0|[1-9][0-9]*)$")
_HTTP_VERSIONS = {b"HTTP/1.0", b"HTTP/1.1"}


@dataclass(frozen=True)
class FramingPolicy:
    """Resource and protocol limits for the strict request-head parser."""

    max_head_bytes: int = 65_536
    max_line_bytes: int = 8_192
    max_header_fields: int = 100
    max_body_bytes: int = 16 * 1024 * 1024
    require_host_http11: bool = True
    allowed_transfer_codings: tuple[str, ...] = ("chunked",)

    def __post_init__(self) -> None:
        if not isinstance(self.require_host_http11, bool):
            raise ValueError("require_host_http11 must be a boolean")
        for name in (
            "max_head_bytes",
            "max_line_bytes",
            "max_header_fields",
            "max_body_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        codings = self.allowed_transfer_codings
        if not isinstance(codings, tuple):
            raise ValueError("allowed_transfer_codings must be an immutable tuple")
        if not codings or codings[-1] != "chunked":
            raise ValueError("allowed_transfer_codings must end with 'chunked'")
        if len(set(codings)) != len(codings):
            raise ValueError("allowed_transfer_codings must not contain duplicates")
        if any(not coding.isascii() or not coding.islower() for coding in codings):
            raise ValueError("transfer codings must be lowercase ASCII tokens")
        if any(_TOKEN.fullmatch(coding.encode("ascii")) is None for coding in codings):
            raise ValueError("transfer codings must be valid HTTP tokens")


@dataclass(frozen=True)
class FramingReport:
    schema_version: str
    accepted: bool
    reason_codes: tuple[str, ...]
    framing: str
    content_length: int | None
    header_count: int
    request_digest: str
    policy_digest: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _policy_digest(policy: FramingPolicy) -> str:
    return _canonical_digest(asdict(policy))


def _request_digest(raw_head: bytes) -> str:
    return hashlib.sha256(raw_head).hexdigest()


def _report(
    raw_head: bytes,
    policy: FramingPolicy,
    *,
    reasons: set[str] | tuple[str, ...] = (),
    framing: str = "invalid",
    content_length: int | None = None,
    header_count: int = 0,
) -> FramingReport:
    reason_codes = tuple(sorted(reasons))
    return FramingReport(
        schema_version=SCHEMA_VERSION,
        accepted=not reason_codes,
        reason_codes=reason_codes,
        framing=framing if not reason_codes else "invalid",
        content_length=content_length if not reason_codes else None,
        header_count=header_count,
        request_digest=_request_digest(raw_head),
        policy_digest=_policy_digest(policy),
    )


def _has_invalid_line_endings(raw_head: bytes) -> bool:
    for index, byte in enumerate(raw_head):
        if byte == 0x0A and (index == 0 or raw_head[index - 1] != 0x0D):
            return True
        if byte == 0x0D and (index + 1 == len(raw_head) or raw_head[index + 1] != 0x0A):
            return True
    return False


def _valid_field_value(value: bytes) -> bool:
    return all(byte == 0x09 or byte >= 0x20 and byte != 0x7F for byte in value)


def _parse_connection_tokens(values: list[bytes]) -> tuple[set[bytes], bool]:
    tokens: set[bytes] = set()
    invalid = False
    for value in values:
        for part in value.split(b","):
            token = part.strip(b" \t").lower()
            if not token or _TOKEN.fullmatch(token) is None:
                invalid = True
            else:
                tokens.add(token)
    return tokens, invalid


def audit_request_head(raw_head: bytes, policy: FramingPolicy | None = None) -> FramingReport:
    """Audit one complete HTTP/1.x request head.

    ``raw_head`` must end immediately after the first CRLF CRLF delimiter.
    Body bytes are deliberately out of scope so callers cannot accidentally
    audit one byte sequence and forward another.
    """

    if not isinstance(raw_head, bytes):
        raise TypeError("raw_head must be bytes")
    policy = policy or FramingPolicy()

    if len(raw_head) > policy.max_head_bytes:
        return _report(raw_head, policy, reasons=("HEAD_TOO_LARGE",))
    if not raw_head:
        return _report(raw_head, policy, reasons=("EMPTY_HEAD",))
    if _has_invalid_line_endings(raw_head):
        return _report(raw_head, policy, reasons=("INVALID_LINE_ENDING",))
    delimiter = raw_head.find(b"\r\n\r\n")
    if delimiter < 0:
        return _report(raw_head, policy, reasons=("INCOMPLETE_HEAD",))
    if delimiter + 4 != len(raw_head):
        return _report(raw_head, policy, reasons=("TRAILING_BYTES",))

    lines = raw_head[:-4].split(b"\r\n")
    if not lines or not lines[0]:
        return _report(raw_head, policy, reasons=("INVALID_REQUEST_LINE",))
    if any(len(line) > policy.max_line_bytes for line in lines):
        return _report(raw_head, policy, reasons=("LINE_TOO_LARGE",))

    request_line = lines[0]
    if b"\t" in request_line or request_line.count(b" ") != 2:
        return _report(raw_head, policy, reasons=("INVALID_REQUEST_LINE",))
    method, target, version = request_line.split(b" ")
    if _TOKEN.fullmatch(method) is None:
        return _report(raw_head, policy, reasons=("INVALID_METHOD",))
    if not target or any(byte <= 0x20 or byte >= 0x7F for byte in target):
        return _report(raw_head, policy, reasons=("INVALID_TARGET",))
    if version not in _HTTP_VERSIONS:
        return _report(raw_head, policy, reasons=("UNSUPPORTED_HTTP_VERSION",))

    header_lines = lines[1:]
    if len(header_lines) > policy.max_header_fields:
        return _report(
            raw_head,
            policy,
            reasons=("TOO_MANY_HEADERS",),
            header_count=len(header_lines),
        )

    headers: dict[bytes, list[bytes]] = {}
    for line in header_lines:
        if not line:
            return _report(
                raw_head,
                policy,
                reasons=("EMPTY_HEADER_LINE",),
                header_count=len(header_lines),
            )
        if line.startswith((b" ", b"\t")):
            return _report(
                raw_head,
                policy,
                reasons=("OBS_FOLD",),
                header_count=len(header_lines),
            )
        if b":" not in line:
            return _report(
                raw_head,
                policy,
                reasons=("MISSING_HEADER_COLON",),
                header_count=len(header_lines),
            )
        name, value = line.split(b":", 1)
        if _TOKEN.fullmatch(name) is None:
            return _report(
                raw_head,
                policy,
                reasons=("INVALID_HEADER_NAME",),
                header_count=len(header_lines),
            )
        if not _valid_field_value(value):
            return _report(
                raw_head,
                policy,
                reasons=("INVALID_HEADER_VALUE",),
                header_count=len(header_lines),
            )
        headers.setdefault(name.lower(), []).append(value)

    reasons: set[str] = set()
    host_values = headers.get(b"host", [])
    if len(host_values) > 1:
        reasons.add("MULTIPLE_HOST")
    if version == b"HTTP/1.1" and policy.require_host_http11:
        if not host_values:
            reasons.add("MISSING_HOST")
        elif not host_values[0].strip(b" \t"):
            reasons.add("EMPTY_HOST")

    if b"proxy-connection" in headers:
        reasons.add("PROXY_CONNECTION_HEADER")

    connection_tokens, invalid_connection = _parse_connection_tokens(headers.get(b"connection", []))
    if invalid_connection:
        reasons.add("INVALID_CONNECTION_TOKEN")
    if connection_tokens & {b"content-length", b"transfer-encoding"}:
        reasons.add("CONNECTION_NOMINATES_FRAMING")

    length_values = headers.get(b"content-length", [])
    transfer_values = headers.get(b"transfer-encoding", [])
    content_length: int | None = None
    framing = "none"

    if len(length_values) > 1:
        reasons.add("MULTIPLE_CONTENT_LENGTH")
    if length_values:
        value = length_values[0]
        if value.startswith(b" "):
            value = value[1:]
        if b"," in value:
            reasons.add("CONTENT_LENGTH_LIST")
        elif value != value.strip(b" \t"):
            reasons.add("NON_CANONICAL_CONTENT_LENGTH")
        elif _CANONICAL_LENGTH.fullmatch(value) is None:
            reasons.add("INVALID_CONTENT_LENGTH")
        else:
            content_length = int(value)
            if content_length > policy.max_body_bytes:
                reasons.add("BODY_TOO_LARGE")
            framing = "fixed-length"

    if len(transfer_values) > 1:
        reasons.add("MULTIPLE_TRANSFER_ENCODING")
    if length_values and transfer_values:
        reasons.add("TRANSFER_ENCODING_WITH_CONTENT_LENGTH")
    if transfer_values:
        value = transfer_values[0]
        if value.startswith(b" "):
            value = value[1:]
        if value != value.strip(b" \t"):
            reasons.add("NON_CANONICAL_TRANSFER_ENCODING")
        parts = [part.strip(b" \t").lower() for part in value.split(b",")]
        if any(not part or _TOKEN.fullmatch(part) is None for part in parts):
            reasons.add("INVALID_TRANSFER_CODING")
        else:
            codings = tuple(part.decode("ascii") for part in parts)
            if codings.count("chunked") != 1:
                reasons.add("INVALID_CHUNKED_COUNT")
            elif codings[-1] != "chunked":
                reasons.add("CHUNKED_NOT_FINAL")
            if any(coding not in policy.allowed_transfer_codings for coding in codings):
                reasons.add("UNSUPPORTED_TRANSFER_CODING")
        if version == b"HTTP/1.0":
            reasons.add("TRANSFER_ENCODING_ON_HTTP_1_0")
        framing = "chunked"

    if b"trailer" in headers and framing != "chunked":
        reasons.add("TRAILER_WITHOUT_CHUNKED")
    if b"expect" in headers and framing == "none":
        if any(value.strip(b" \t").lower() == b"100-continue" for value in headers[b"expect"]):
            reasons.add("EXPECT_WITHOUT_BODY")

    return _report(
        raw_head,
        policy,
        reasons=reasons,
        framing=framing,
        content_length=content_length,
        header_count=len(header_lines),
    )


def _atomic_write_json(path: Path, report: FramingReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit an exact HTTP/1.x request head for framing ambiguity."
    )
    parser.add_argument("input", type=Path, help="binary request-head file")
    parser.add_argument("--output", type=Path, help="atomically written JSON report")
    args = parser.parse_args(argv)

    policy = FramingPolicy()
    try:
        raw_head = _read_bounded(args.input, policy.max_head_bytes)
        report = audit_request_head(raw_head, policy)
        if args.output:
            _atomic_write_json(args.output, report)
        else:
            json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
    except (OSError, ValueError) as exc:
        print(f"http1-framing: {type(exc).__name__}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ACCEPTED if report.accepted else EXIT_REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
