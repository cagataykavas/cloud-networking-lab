from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.request
from dataclasses import asdict, dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProbeResult:
    host: str
    addresses: tuple[str, ...]
    port: int
    tcp_connect_ms: float | None
    http_status: int | None
    total_http_ms: float | None
    error: str | None


def resolve(host: str) -> tuple[str, ...]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(item[4][0] for item in infos))


def probe(url: str, timeout: float = 2.0) -> ProbeResult:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must use http:// or https:// and include a hostname")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    addresses: tuple[str, ...] = ()
    tcp_ms = None
    http_status = None
    http_ms = None
    error = None
    try:
        addresses = resolve(host)
        started = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            tcp_ms = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        with urllib.request.urlopen(url, timeout=timeout) as response:
            response.read(256)
            http_status = response.status
        http_ms = (time.perf_counter() - started) * 1000
    except Exception as exc:  # diagnostic utility intentionally returns failures as data
        error = f"{type(exc).__name__}: {exc}"

    return ProbeResult(
        host=host,
        addresses=addresses,
        port=port,
        tcp_connect_ms=round(tcp_ms, 3) if tcp_ms is not None else None,
        http_status=http_status,
        total_http_ms=round(http_ms, 3) if http_ms is not None else None,
        error=error,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve DNS, open TCP and issue an HTTP request.")
    parser.add_argument("url", nargs="?", default="http://localhost:8080/whoami")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    print(json.dumps(asdict(probe(args.url, args.timeout)), indent=2))


if __name__ == "__main__":
    main()
