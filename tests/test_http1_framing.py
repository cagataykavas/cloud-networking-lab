from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.http1_framing import FramingPolicy, audit_request_head


def request(*headers: bytes, line: bytes = b"GET / HTTP/1.1") -> bytes:
    return b"\r\n".join((line, *headers, b"", b""))


def assert_rejected(raw: bytes, code: str) -> None:
    report = audit_request_head(raw)
    assert not report.accepted
    assert code in report.reason_codes
    assert report.framing == "invalid"
    assert report.content_length is None


def test_accepts_bodyless_http11_request() -> None:
    report = audit_request_head(request(b"Host: api.internal"))
    assert report.accepted
    assert report.framing == "none"
    assert report.header_count == 1


def test_accepts_canonical_content_length() -> None:
    report = audit_request_head(
        request(b"Host: api.internal", b"Content-Length: 42", line=b"POST /v1 HTTP/1.1")
    )
    assert report.accepted
    assert report.framing == "fixed-length"
    assert report.content_length == 42


def test_accepts_chunked_body() -> None:
    report = audit_request_head(request(b"Host: api.internal", b"Transfer-Encoding: chunked"))
    assert report.accepted
    assert report.framing == "chunked"


def test_accepts_allowed_composite_transfer_coding() -> None:
    policy = FramingPolicy(allowed_transfer_codings=("gzip", "chunked"))
    report = audit_request_head(
        request(b"Host: api.internal", b"Transfer-Encoding: gzip, chunked"), policy
    )
    assert report.accepted
    assert report.framing == "chunked"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "EMPTY_HEAD"),
        (b"GET / HTTP/1.1\nHost: x\n\n", "INVALID_LINE_ENDING"),
        (b"GET / HTTP/1.1\r\nHost: x\r\n", "INCOMPLETE_HEAD"),
        (request(b"Host: x") + b"body", "TRAILING_BYTES"),
        (request(b"Host: x", line=b"GET  / HTTP/1.1"), "INVALID_REQUEST_LINE"),
        (request(b"Host: x", line=b"G@T / HTTP/1.1"), "INVALID_METHOD"),
        (request(b"Host: x", line=b"GET /bad target HTTP/1.1"), "INVALID_REQUEST_LINE"),
        (request(b"Host: x", line=b"GET /caf\xe9 HTTP/1.1"), "INVALID_TARGET"),
        (request(b"Host: x", line=b"GET / HTTP/2"), "UNSUPPORTED_HTTP_VERSION"),
        (request(b" Host: x"), "OBS_FOLD"),
        (request(b"Host x"), "MISSING_HEADER_COLON"),
        (request(b"Host : x"), "INVALID_HEADER_NAME"),
        (request(b"Host: x\x00"), "INVALID_HEADER_VALUE"),
        (request(), "MISSING_HOST"),
        (request(b"Host:   "), "EMPTY_HOST"),
        (request(b"Host: one", b"Host: two"), "MULTIPLE_HOST"),
        (request(b"Host: x", b"Proxy-Connection: keep-alive"), "PROXY_CONNECTION_HEADER"),
        (
            request(b"Host: x", b"Connection: transfer-encoding"),
            "CONNECTION_NOMINATES_FRAMING",
        ),
        (request(b"Host: x", b"Connection: keep-alive,,close"), "INVALID_CONNECTION_TOKEN"),
        (
            request(b"Host: x", b"Content-Length:1", b"Content-Length:1"),
            "MULTIPLE_CONTENT_LENGTH",
        ),
        (request(b"Host: x", b"Content-Length:1, 1"), "CONTENT_LENGTH_LIST"),
        (request(b"Host: x", b"Content-Length:  1"), "NON_CANONICAL_CONTENT_LENGTH"),
        (request(b"Host: x", b"Content-Length:+1"), "INVALID_CONTENT_LENGTH"),
        (request(b"Host: x", b"Content-Length:01"), "INVALID_CONTENT_LENGTH"),
        (
            request(b"Host: x", b"Content-Length:1", b"Transfer-Encoding:chunked"),
            "TRANSFER_ENCODING_WITH_CONTENT_LENGTH",
        ),
        (
            request(
                b"Host: x",
                b"Transfer-Encoding:chunked",
                b"Transfer-Encoding:chunked",
            ),
            "MULTIPLE_TRANSFER_ENCODING",
        ),
        (request(b"Host: x", b"Transfer-Encoding:  chunked"), "NON_CANONICAL_TRANSFER_ENCODING"),
        (request(b"Host: x", b"Transfer-Encoding:gzip"), "INVALID_CHUNKED_COUNT"),
        (request(b"Host: x", b"Transfer-Encoding:chunked, gzip"), "CHUNKED_NOT_FINAL"),
        (request(b"Host: x", b"Transfer-Encoding:gzip, chunked"), "UNSUPPORTED_TRANSFER_CODING"),
        (
            request(
                b"Host: x",
                b"Transfer-Encoding:chunked",
                line=b"POST / HTTP/1.0",
            ),
            "TRANSFER_ENCODING_ON_HTTP_1_0",
        ),
        (request(b"Host: x", b"Trailer: digest"), "TRAILER_WITHOUT_CHUNKED"),
        (request(b"Host: x", b"Expect: 100-continue"), "EXPECT_WITHOUT_BODY"),
    ],
)
def test_rejects_ambiguous_or_malformed_heads(raw: bytes, code: str) -> None:
    assert_rejected(raw, code)


def test_rejects_head_byte_budget() -> None:
    raw = request(b"Host: " + b"a" * 100)
    assert_rejected_with_policy(raw, FramingPolicy(max_head_bytes=32), "HEAD_TOO_LARGE")


def test_rejects_line_and_header_count_budgets() -> None:
    long_line = request(b"Host: " + b"a" * 32)
    assert_rejected_with_policy(long_line, FramingPolicy(max_line_bytes=16), "LINE_TOO_LARGE")
    many = request(b"Host: x", b"X-One: 1", b"X-Two: 2")
    assert_rejected_with_policy(many, FramingPolicy(max_header_fields=2), "TOO_MANY_HEADERS")


def assert_rejected_with_policy(raw: bytes, policy: FramingPolicy, code: str) -> None:
    report = audit_request_head(raw, policy)
    assert not report.accepted
    assert code in report.reason_codes


def test_rejects_body_budget() -> None:
    raw = request(b"Host: x", b"Content-Length:11")
    assert_rejected_with_policy(raw, FramingPolicy(max_body_bytes=10), "BODY_TOO_LARGE")


def test_report_is_deterministic_and_does_not_echo_input() -> None:
    raw = request(b"Host: secret.internal", line=b"GET /customer/alice HTTP/1.1")
    first = audit_request_head(raw).to_dict()
    second = audit_request_head(raw).to_dict()
    assert first == second
    serialized = json.dumps(first)
    assert "secret.internal" not in serialized
    assert "customer" not in serialized
    assert len(first["request_digest"]) == 64
    assert len(first["policy_digest"]) == 64


def test_policy_changes_policy_digest() -> None:
    raw = request(b"Host: x")
    first = audit_request_head(raw)
    second = audit_request_head(raw, FramingPolicy(max_body_bytes=1_024))
    assert first.request_digest == second.request_digest
    assert first.policy_digest != second.policy_digest


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_head_bytes": 0},
        {"max_line_bytes": True},
        {"max_header_fields": -1},
        {"max_body_bytes": 0},
        {"require_host_http11": "yes"},
        {"allowed_transfer_codings": ["chunked"]},
        {"allowed_transfer_codings": ()},
        {"allowed_transfer_codings": ("chunked", "gzip")},
        {"allowed_transfer_codings": ("chunked", "chunked")},
        {"allowed_transfer_codings": ("Chunked",)},
    ],
)
def test_rejects_invalid_policy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        FramingPolicy(**kwargs)


def test_requires_bytes() -> None:
    with pytest.raises(TypeError):
        audit_request_head("GET / HTTP/1.1\r\n\r\n")  # type: ignore[arg-type]


def test_cli_exit_codes_and_atomic_report(tmp_path: Path) -> None:
    accepted = tmp_path / "accepted.http"
    accepted.write_bytes(request(b"Host: x"))
    report_path = tmp_path / "report.json"
    command = [
        sys.executable,
        "-m",
        "tools.http1_framing",
        str(accepted),
        "--output",
        str(report_path),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0
    assert json.loads(report_path.read_text())["accepted"] is True

    rejected = tmp_path / "rejected.http"
    rejected.write_bytes(request(b"Host: x", b"Content-Length:1, 1"))
    result = subprocess.run(
        [*command[:3], str(rejected), *command[4:]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert json.loads(report_path.read_text())["reason_codes"] == ["CONTENT_LENGTH_LIST"]


def test_cli_missing_input_is_operational_error(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tools.http1_framing", str(tmp_path / "missing")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3
    assert "FileNotFoundError" in result.stderr
    assert str(tmp_path) not in result.stderr
