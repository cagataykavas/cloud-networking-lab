import concurrent.futures
import io
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools import load_demo


class Response(io.BytesIO):
    status = 200


class StaticOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


def test_response_read_is_byte_bounded():
    class TrackingResponse(Response):
        requested = []

        def read(self, size=-1):
            self.requested.append(size)
            return super().read(size)

    response = TrackingResponse(b"x" * (load_demo.MAX_RESPONSE_BYTES + 2))
    with pytest.raises(ValueError, match="byte limit"):
        load_demo.request_once("http://127.0.0.1", 1, StaticOpener(response))
    assert response.requested == [load_demo.MAX_RESPONSE_BYTES + 1]
    assert response.closed


def test_response_exactly_at_byte_limit_is_accepted():
    body = json.dumps({"instance_id": "x" * 128}).encode()
    body += b" " * (load_demo.MAX_RESPONSE_BYTES - len(body))
    response = Response(body)
    backend, latency, status = load_demo.request_once(
        "http://127.0.0.1", 1, StaticOpener(response)
    )
    assert backend == "x" * 128
    assert latency >= 0
    assert status == 200
    assert response.closed


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"instance_id": None},
        {"instance_id": 12},
        {"instance_id": " "},
        {"instance_id": "x" * 129},
    ],
)
def test_invalid_backend_identity_is_not_counted_as_success(payload):
    response = Response(json.dumps(payload).encode())
    with pytest.raises(ValueError, match="instance_id"):
        load_demo.request_once("http://127.0.0.1", 1, StaticOpener(response))
    assert response.closed


def test_bounded_submission_window_and_exact_aggregate_metrics(monkeypatch):
    class Future:
        def __init__(self, executor, index):
            self.executor = executor
            self.index = index

        def result(self):
            self.executor.outstanding -= 1
            if self.index % 10 == 0:
                raise OSError("sensitive remote error text")
            return "backend-a", 10.0, 200

    class Executor:
        instance = None

        def __init__(self, max_workers):
            Executor.instance = self
            self.max_workers = max_workers
            self.submitted = 0
            self.outstanding = 0
            self.peak = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def submit(self, *_args):
            self.outstanding += 1
            self.peak = max(self.peak, self.outstanding)
            self.submitted += 1
            return Future(self, self.submitted)

    def complete_one(pending, return_when):
        assert return_when == concurrent.futures.FIRST_COMPLETED
        selected = min(pending, key=lambda item: item.index)
        return {selected}, pending - {selected}

    monkeypatch.setattr(load_demo.concurrent.futures, "ThreadPoolExecutor", Executor)
    monkeypatch.setattr(load_demo.concurrent.futures, "wait", complete_one)
    result = load_demo.run("http://127.0.0.1", 10_000, 8, 1)

    assert Executor.instance.submitted == 10_000
    assert Executor.instance.peak == 8
    assert Executor.instance.outstanding == 0
    assert result["requested"] == 10_000
    assert result["succeeded"] == 9_000
    assert result["failed"] == 1_000
    assert result["backend_distribution"] == {"backend-a": 9_000}
    assert result["sample_failures"] == ["OSError"] * 5
    assert result["latency_ms"] == {"mean": 10.0, "p50": 10.0, "p95": 10.0, "p99": 10.0}


@pytest.mark.parametrize(
    "changes",
    [
        {"requests": 0},
        {"requests": -1},
        {"requests": 100_001},
        {"requests": 1.5},
        {"requests": True},
        {"concurrency": 0},
        {"concurrency": 129},
        {"concurrency": True},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": 61},
        {"timeout": True},
    ],
)
def test_invalid_budgets_fail_before_any_request(monkeypatch, changes):
    def forbidden(*_args):
        pytest.fail("invalid budgets must not submit requests")

    monkeypatch.setattr(load_demo, "request_once", forbidden)
    values = {"requests": 1, "concurrency": 1, "timeout": 1}
    values.update(changes)
    with pytest.raises(ValueError):
        load_demo.run("http://127.0.0.1", **values)


def test_all_failed_requests_keep_exact_count_and_five_error_types(monkeypatch):
    def failed(*_args):
        raise RuntimeError("secret-bearing diagnostic must not be copied")

    monkeypatch.setattr(load_demo, "request_once", failed)
    result = load_demo.run("http://127.0.0.1", 30, 4, 1)
    assert result["succeeded"] == 0
    assert result["failed"] == 30
    assert result["backend_distribution"] == {}
    assert result["sample_failures"] == ["RuntimeError"] * 5
    assert all(value == 0 for value in result["latency_ms"].values())
    assert "secret-bearing" not in json.dumps(result)


def test_small_request_budget_works_with_larger_concurrency(monkeypatch):
    monkeypatch.setattr(load_demo, "request_once", lambda *_a: ("a", 3.0, 200))
    result = load_demo.run("http://127.0.0.1", 1, 128, 1)
    assert result["succeeded"] == 1
    assert result["failed"] == 0


def test_real_loopback_http_success_and_failure_accounting(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        lock = threading.Lock()

        def do_GET(self):
            with self.lock:
                Handler.calls += 1
                failed = Handler.calls % 4 == 0
            body = b"not-json" if failed else b'{"instance_id":"loopback"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        result = load_demo.run(
            f"http://127.0.0.1:{server.server_port}/whoami", 12, 3, 3
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert result["succeeded"] == 9
    assert result["failed"] == 3
    assert result["backend_distribution"] == {"loopback": 9}
    assert result["sample_failures"] == ["JSONDecodeError"] * 3


@pytest.mark.parametrize(
    "url,match",
    [
        ("http://localhost:8080/whoami", "IP literal"),
        ("ftp://127.0.0.1/file", "scheme"),
        ("http://user:secret@127.0.0.1/", "credentials"),
        ("http://127.0.0.1/#fragment", "fragment"),
        ("http://10.0.0.2/", "allowlist"),
        ("http://169.254.169.254/latest/meta-data", "not permitted"),
        ("http://0.0.0.0/", "not permitted"),
        ("http://224.0.0.1/", "not permitted"),
        ("http://127.0.0.1:99999/", "invalid port"),
        ("http://127.0.0.1/path with space", "whitespace"),
        ("http://127.0.0.1/" + "x" * 2048, "byte limit"),
    ],
)
def test_default_target_policy_fails_closed(url, match):
    with pytest.raises(ValueError, match=match):
        load_demo.TargetPolicy.from_cidrs().validate_url(url)


def test_invalid_target_fails_before_worker_pool(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid target must fail before creating workers")

    monkeypatch.setattr(load_demo.concurrent.futures, "ThreadPoolExecutor", forbidden)
    with pytest.raises(ValueError, match="IP literal"):
        load_demo.run("http://localhost:8080/whoami", 1, 1, 1)


def test_explicit_private_network_is_allowed_but_scope_is_exact():
    policy = load_demo.TargetPolicy.from_cidrs(("10.42.0.0/16", "2001:db8::/32"))
    policy.validate_url("http://10.42.3.9:8080/whoami")
    policy.validate_url("https://[2001:db8::4]/health")
    with pytest.raises(ValueError, match="allowlist"):
        policy.validate_url("http://10.43.0.1/")


@pytest.mark.parametrize(
    "cidrs,match",
    [
        (("10.0.0.1/8",), "canonical"),
        (("invalid",), "canonical"),
        (("169.254.0.0/16",), "link-local"),
        (("0.0.0.0/0",), "unspecified"),
        (("224.0.0.0/4",), "multicast"),
        (("127.0.0.1/32",) * 33, "at most"),
    ],
)
def test_allowlist_rejects_ambiguous_or_unsafe_networks(cidrs, match):
    with pytest.raises(ValueError, match=match):
        load_demo.TargetPolicy.from_cidrs(cidrs)


def test_opener_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    opener = load_demo.build_opener(load_demo.TargetPolicy.from_cidrs())
    proxy_handlers = [
        handler
        for handler in opener.handlers
        if isinstance(handler, load_demo.urllib.request.ProxyHandler)
    ]
    # Passing ProxyHandler({}) suppresses urllib's default environment-derived
    # handler; an empty handler has no protocol methods and is not retained.
    assert proxy_handlers == []
    assert os.environ["HTTP_PROXY"]


def test_redirect_handler_validates_every_hop_and_https_downgrade():
    policy = load_demo.TargetPolicy.from_cidrs()
    handler = load_demo.PolicyRedirectHandler(policy)
    request = load_demo.urllib.request.Request("http://127.0.0.1/start")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "http://127.0.0.2/next"
    )
    assert redirected.full_url == "http://127.0.0.2/next"
    with pytest.raises(ValueError, match="allowlist"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://10.0.0.1/")

    secure = load_demo.urllib.request.Request("https://127.0.0.1/start")
    with pytest.raises(load_demo.urllib.error.HTTPError, match="downgrade"):
        handler.redirect_request(secure, None, 302, "Found", {}, "http://127.0.0.1/")


def test_policy_uses_literal_address_without_dns_resolution(monkeypatch):
    def forbidden(*_args):
        pytest.fail("target validation must not perform DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    load_demo.TargetPolicy.from_cidrs().validate_url("http://127.0.0.1/whoami")
