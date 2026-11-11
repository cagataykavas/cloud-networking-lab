from __future__ import annotations

import argparse
import http.client
import json
import math
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

MAX_URL_LENGTH = 2_048
MAX_RESPONSE_BYTES = 256
MIN_TIMEOUT_SECONDS = 0.05
MAX_TIMEOUT_SECONDS = 30.0


class TargetPolicyError(RuntimeError):
    """Raised when DNS returns no address permitted by the egress policy."""


@dataclass(frozen=True)
class ResolvedEndpoint:
    family: int
    address: str
    sockaddr: tuple[object, ...]

    @property
    def family_name(self) -> str:
        return "IPv6" if self.family == socket.AF_INET6 else "IPv4"


@dataclass(frozen=True)
class ProbeResult:
    host: str
    addresses: tuple[str, ...]
    port: int
    selected_address: str | None
    address_family: str | None
    tcp_connect_ms: float | None
    http_status: int | None
    total_http_ms: float | None
    redirect_location: str | None
    error: str | None


def validate_url(url: str) -> tuple[str, str, int, str]:
    if not url or len(url) > MAX_URL_LENGTH:
        raise ValueError(f"url must contain between 1 and {MAX_URL_LENGTH} characters")
    if any(ord(character) < 32 for character in url):
        raise ValueError("url must not contain control characters")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must use http:// or https:// and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("url must not contain credentials")
    if parsed.fragment:
        raise ValueError("url must not contain a fragment")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("url contains an invalid port") from exc

    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return parsed.scheme, parsed.hostname.encode("idna").decode("ascii"), port, request_target


def validate_timeout(timeout: float) -> None:
    if (
        not math.isfinite(timeout)
        or timeout < MIN_TIMEOUT_SECONDS
        or timeout > MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds"
        )


def resolve(host: str, port: int) -> tuple[ResolvedEndpoint, ...]:
    infos = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    endpoints: list[ResolvedEndpoint] = []
    seen: set[tuple[int, str]] = set()
    for family, _type, _proto, _canonname, sockaddr in infos:
        address = str(sockaddr[0])
        identity = (family, address)
        if family not in {socket.AF_INET, socket.AF_INET6} or identity in seen:
            continue
        seen.add(identity)
        endpoints.append(ResolvedEndpoint(family=family, address=address, sockaddr=sockaddr))
    if not endpoints:
        raise OSError("DNS returned no TCP-capable IPv4 or IPv6 addresses")
    return tuple(endpoints)


def permitted_endpoints(
    endpoints: tuple[ResolvedEndpoint, ...], *, allow_private: bool
) -> tuple[ResolvedEndpoint, ...]:
    if allow_private:
        return endpoints
    permitted = tuple(endpoint for endpoint in endpoints if ip_address(endpoint.address).is_global)
    if not permitted:
        raise TargetPolicyError(
            "DNS returned only non-global addresses; pass --allow-private only for a trusted lab target"
        )
    return permitted


def connect(
    endpoints: tuple[ResolvedEndpoint, ...], timeout: float
) -> tuple[ResolvedEndpoint, float]:
    deadline = time.monotonic() + timeout
    errors: list[str] = []
    for endpoint in endpoints:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        started = time.perf_counter()
        try:
            with socket.socket(endpoint.family, socket.SOCK_STREAM) as connection:
                connection.settimeout(remaining)
                connection.connect(endpoint.sockaddr)
            return endpoint, (time.perf_counter() - started) * 1_000
        except OSError as exc:
            errors.append(f"{endpoint.address}: {type(exc).__name__}")
    detail = ", ".join(errors) if errors else "deadline exhausted"
    raise OSError(f"unable to connect to an approved address ({detail})")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, endpoint: ResolvedEndpoint, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._endpoint = endpoint

    def connect(self) -> None:
        connection = socket.socket(self._endpoint.family, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self._endpoint.sockaddr)
        except BaseException:
            connection.close()
            raise
        self.sock = connection


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, endpoint: ResolvedEndpoint, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._endpoint = endpoint

    def connect(self) -> None:
        connection = socket.socket(self._endpoint.family, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self._endpoint.sockaddr)
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


def request(
    scheme: str,
    host: str,
    port: int,
    target: str,
    endpoint: ResolvedEndpoint,
    timeout: float,
) -> tuple[int, str | None, float]:
    connection_type = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    connection = connection_type(host, port, endpoint, timeout)
    started = time.perf_counter()
    try:
        connection.request(
            "GET",
            target,
            headers={"Accept": "application/json", "User-Agent": "cloud-networking-lab/2.0"},
        )
        response = connection.getresponse()
        response.read(MAX_RESPONSE_BYTES)
        return (
            response.status,
            response.getheader("Location") if 300 <= response.status < 400 else None,
            (time.perf_counter() - started) * 1_000,
        )
    finally:
        connection.close()


def probe(url: str, timeout: float = 2.0, *, allow_private: bool = False) -> ProbeResult:
    scheme, host, port, target = validate_url(url)
    validate_timeout(timeout)

    addresses: tuple[str, ...] = ()
    selected: ResolvedEndpoint | None = None
    tcp_ms = None
    http_status = None
    http_ms = None
    redirect_location = None
    error = None
    try:
        endpoints = resolve(host, port)
        addresses = tuple(endpoint.address for endpoint in endpoints)
        approved = permitted_endpoints(endpoints, allow_private=allow_private)
        selected, tcp_ms = connect(approved, timeout)
        http_status, redirect_location, http_ms = request(
            scheme, host, port, target, selected, timeout
        )
    except Exception as exc:  # diagnostic utility intentionally returns failures as data
        error = f"{type(exc).__name__}: {exc}"

    return ProbeResult(
        host=host,
        addresses=addresses,
        port=port,
        selected_address=selected.address if selected is not None else None,
        address_family=selected.family_name if selected is not None else None,
        tcp_connect_ms=round(tcp_ms, 3) if tcp_ms is not None else None,
        http_status=http_status,
        total_http_ms=round(http_ms, 3) if http_ms is not None else None,
        redirect_location=redirect_location,
        error=error,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve DNS once, enforce target policy, then probe the selected address."
    )
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private, loopback, link-local, reserved, or otherwise non-global addresses",
    )
    args = parser.parse_args()
    try:
        result = probe(args.url, args.timeout, allow_private=args.allow_private)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(asdict(result), indent=2))
    if result.error is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
