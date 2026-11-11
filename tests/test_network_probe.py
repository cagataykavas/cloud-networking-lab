from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools import network_probe


class ProbeHandler(BaseHTTPRequestHandler):
    final_requests = 0

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/final":
            type(self).final_requests += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, _format: str, *args: object) -> None:
        del args


@pytest.fixture
def local_server() -> Iterator[tuple[str, int]]:
    ProbeHandler.final_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_probe_blocks_non_global_targets_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = network_probe.ResolvedEndpoint(
        family=socket.AF_INET,
        address="127.0.0.1",
        sockaddr=("127.0.0.1", 8080),
    )
    monkeypatch.setattr(network_probe, "resolve", lambda _host, _port: (endpoint,))

    result = network_probe.probe("http://internal.example:8080/health")

    assert result.addresses == ("127.0.0.1",)
    assert result.selected_address is None
    assert result.error is not None and result.error.startswith("TargetPolicyError:")


def test_private_opt_in_pins_one_dns_answer(
    local_server: tuple[str, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    address, port = local_server
    lookups = 0

    def fake_getaddrinfo(
        host: str,
        requested_port: int,
        *,
        family: int,
        type: int,
        proto: int,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal lookups
        lookups += 1
        assert host == "probe.test"
        assert requested_port == port
        assert family == socket.AF_UNSPEC
        assert type == socket.SOCK_STREAM
        assert proto == socket.IPPROTO_TCP
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = network_probe.probe(
        f"http://probe.test:{port}/final", allow_private=True
    )

    assert result.error is None
    assert result.http_status == 200
    assert result.selected_address == "127.0.0.1"
    assert result.address_family == "IPv4"
    assert lookups == 1


def test_probe_reports_redirect_without_following_it(local_server: tuple[str, int]) -> None:
    address, port = local_server

    result = network_probe.probe(
        f"http://{address}:{port}/redirect", allow_private=True
    )

    assert result.error is None
    assert result.http_status == 302
    assert result.redirect_location == "/final"
    assert ProbeHandler.final_requests == 0


@pytest.mark.parametrize(
    "url, message",
    [
        ("http://user:secret@example.com", "credentials"),
        ("http://example.com/path#fragment", "fragment"),
        ("http://example.com:99999", "invalid port"),
        ("http://example.com/\nheader", "control characters"),
    ],
)
def test_probe_rejects_ambiguous_urls(url: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        network_probe.probe(url)


@pytest.mark.parametrize("timeout", [0.0, 30.01, float("inf"), float("nan")])
def test_probe_bounds_timeouts(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout must be between"):
        network_probe.probe("https://example.com", timeout=timeout)


def test_policy_filters_non_global_answers_when_global_address_exists() -> None:
    private = network_probe.ResolvedEndpoint(
        socket.AF_INET, "10.0.0.8", ("10.0.0.8", 80)
    )
    public = network_probe.ResolvedEndpoint(
        socket.AF_INET, "8.8.8.8", ("8.8.8.8", 80)
    )

    assert network_probe.permitted_endpoints(
        (private, public), allow_private=False
    ) == (public,)
