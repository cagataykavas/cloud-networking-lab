import concurrent.futures
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools import load_demo


class Response(io.BytesIO):
    status = 200


def test_response_read_is_byte_bounded(monkeypatch):
    class TrackingResponse(Response):
        requested = []

        def read(self, size=-1):
            self.requested.append(size)
            return super().read(size)

    response = TrackingResponse(b"x" * (load_demo.MAX_RESPONSE_BYTES + 2))
    monkeypatch.setattr(
        load_demo.urllib.request, "urlopen", lambda *_a, **_kw: response
    )
    with pytest.raises(ValueError, match="byte limit"):
        load_demo.request_once("http://test.invalid", 1)
    assert response.requested == [load_demo.MAX_RESPONSE_BYTES + 1]
    assert response.closed


def test_response_exactly_at_byte_limit_is_accepted(monkeypatch):
    body = json.dumps({"instance_id": "x" * 128}).encode()
    body += b" " * (load_demo.MAX_RESPONSE_BYTES - len(body))
    response = Response(body)
    monkeypatch.setattr(
        load_demo.urllib.request, "urlopen", lambda *_a, **_kw: response
    )
    backend, latency, status = load_demo.request_once("http://test.invalid", 1)
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
def test_invalid_backend_identity_is_not_counted_as_success(monkeypatch, payload):
    response = Response(json.dumps(payload).encode())
    monkeypatch.setattr(
        load_demo.urllib.request, "urlopen", lambda *_a, **_kw: response
    )
    with pytest.raises(ValueError, match="instance_id"):
        load_demo.request_once("http://test.invalid", 1)
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
    result = load_demo.run("http://test.invalid", 10_000, 8, 1)

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
        load_demo.run("http://test.invalid", **values)


def test_all_failed_requests_keep_exact_count_and_five_error_types(monkeypatch):
    def failed(*_args):
        raise RuntimeError("secret-bearing diagnostic must not be copied")

    monkeypatch.setattr(load_demo, "request_once", failed)
    result = load_demo.run("http://test.invalid", 30, 4, 1)
    assert result["succeeded"] == 0
    assert result["failed"] == 30
    assert result["backend_distribution"] == {}
    assert result["sample_failures"] == ["RuntimeError"] * 5
    assert all(value == 0 for value in result["latency_ms"].values())
    assert "secret-bearing" not in json.dumps(result)


def test_small_request_budget_works_with_larger_concurrency(monkeypatch):
    monkeypatch.setattr(load_demo, "request_once", lambda *_a: ("a", 3.0, 200))
    result = load_demo.run("http://test.invalid", 1, 128, 1)
    assert result["succeeded"] == 1
    assert result["failed"] == 0


def test_real_loopback_http_success_and_failure_accounting():
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
