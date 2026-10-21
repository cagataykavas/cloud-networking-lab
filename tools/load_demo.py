from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import math
import re
import socket
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import BinaryIO

MAX_REQUESTS = 100_000
MAX_CONCURRENCY = 128
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ALLOWED_NETWORKS = 32
MAX_TARGET_URL_BYTES = 2048
MAX_RATE_PER_SECOND = 10_000.0
MAX_SCHEDULE_SECONDS = 600.0
DEFAULT_ALLOWED_CIDRS = ("127.0.0.0/8", "::1/128")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class DeadlineExceeded(TimeoutError):
    """Raised when one request exceeds its monotonic end-to-end deadline."""


@dataclass(frozen=True)
class TargetPolicy:
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    @classmethod
    def from_cidrs(cls, cidrs: tuple[str, ...] = ()) -> TargetPolicy:
        configured = cidrs or DEFAULT_ALLOWED_CIDRS
        if len(configured) > MAX_ALLOWED_NETWORKS:
            raise ValueError(
                f"at most {MAX_ALLOWED_NETWORKS} allowed networks are supported"
            )
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for value in configured:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid canonical allowlist CIDR: {value!r}"
                ) from error
            boundary_addresses = (network.network_address, network.broadcast_address)
            if any(
                address.is_multicast or address.is_unspecified or address.is_link_local
                for address in boundary_addresses
            ):
                raise ValueError(
                    "multicast, unspecified and link-local networks cannot be allowed"
                )
            networks.append(network)
        return cls(tuple(networks))

    def validate_url(self, url: str) -> None:
        if not isinstance(url, str) or not url:
            raise ValueError("target URL must be a non-empty string")
        if len(url.encode("utf-8")) > MAX_TARGET_URL_BYTES:
            raise ValueError(
                f"target URL exceeds the {MAX_TARGET_URL_BYTES}-byte limit"
            )
        if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
            raise ValueError(
                "target URL cannot contain whitespace or control characters"
            )
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise ValueError(
                "target URL contains an invalid port or address"
            ) from error
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("target URL scheme must be http or https")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target URL cannot contain credentials")
        if parsed.fragment:
            raise ValueError("target URL cannot contain a fragment")
        if parsed.hostname is None:
            raise ValueError("target URL requires an IP-literal host")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("target URL port is outside 1..65535")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError(
                "target URL host must be an IP literal to prevent DNS rebinding"
            ) from error
        if address.is_multicast or address.is_unspecified or address.is_link_local:
            raise ValueError("target address class is not permitted")
        if not any(address in network for network in self.allowed_networks):
            raise ValueError(
                "target address is outside the configured network allowlist"
            )


class PolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: TargetPolicy) -> None:
        self.policy = policy

    def redirect_request(
        self, req, fp: BinaryIO, code: int, msg: str, headers, newurl: str
    ):
        self.policy.validate_url(newurl)
        old_scheme = urllib.parse.urlsplit(req.full_url).scheme
        new_scheme = urllib.parse.urlsplit(newurl).scheme
        if old_scheme == "https" and new_scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code, "HTTPS downgrade redirect rejected", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(policy: TargetPolicy) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        PolicyRedirectHandler(policy),
    )


def request_once(
    url: str,
    timeout: float,
    opener: urllib.request.OpenerDirector | None = None,
    policy: TargetPolicy | None = None,
    request_id: str | None = None,
    scheduled_at: float | None = None,
    deadline_at: float | None = None,
) -> tuple[str, float, int]:
    policy = policy or TargetPolicy.from_cidrs()
    policy.validate_url(url)
    opener = opener or build_opener(policy)
    started = time.perf_counter() if scheduled_at is None else scheduled_at
    effective_timeout = timeout
    if deadline_at is not None:
        remaining = deadline_at - time.perf_counter()
        if remaining <= 0.0:
            raise DeadlineExceeded("request deadline elapsed before dispatch")
        effective_timeout = min(timeout, remaining)
    headers = {"User-Agent": "cloud-networking-lab/1.0"}
    if request_id is not None:
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError("request_id must be a bounded token without whitespace")
        headers["X-Loadgen-Request-ID"] = request_id
    request = urllib.request.Request(
        url,
        headers=headers,
    )
    try:
        with opener.open(request, timeout=effective_timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("response exceeds the load probe byte limit")
            payload = json.loads(body)
            status = response.status
    except TimeoutError as error:
        if deadline_at is not None:
            raise DeadlineExceeded(
                "request exceeded its end-to-end deadline"
            ) from error
        raise
    except urllib.error.URLError as error:
        if deadline_at is not None and isinstance(
            error.reason, (TimeoutError, socket.timeout)
        ):
            raise DeadlineExceeded(
                "request exceeded its end-to-end deadline"
            ) from error
        raise
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("instance_id"), str)
        or not 1 <= len(payload["instance_id"]) <= 128
        or not payload["instance_id"].strip()
    ):
        raise ValueError(
            "response requires a non-empty instance_id of at most 128 characters"
        )
    if deadline_at is not None and time.perf_counter() > deadline_at:
        raise DeadlineExceeded("request completed after its end-to-end deadline")
    latency_ms = (time.perf_counter() - started) * 1000
    return payload["instance_id"], latency_ms, status


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * quantile))))
    return ordered[index]


def run(
    url: str,
    requests: int,
    concurrency: int,
    timeout: float,
    allowed_cidrs: tuple[str, ...] = (),
    rate_per_second: float | None = None,
    deadline: float | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    if (
        isinstance(requests, bool)
        or not isinstance(requests, int)
        or not 1 <= requests <= MAX_REQUESTS
    ):
        raise ValueError(f"requests must be an integer between 1 and {MAX_REQUESTS}")
    if (
        isinstance(concurrency, bool)
        or not isinstance(concurrency, int)
        or not 1 <= concurrency <= MAX_CONCURRENCY
    ):
        raise ValueError(
            f"concurrency must be an integer between 1 and {MAX_CONCURRENCY}"
        )
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 60
    ):
        raise ValueError(
            "timeout must be finite and between 0 (exclusive) and 60 seconds"
        )
    if rate_per_second is not None and (
        isinstance(rate_per_second, bool)
        or not isinstance(rate_per_second, (int, float))
        or not math.isfinite(rate_per_second)
        or not 0 < rate_per_second <= MAX_RATE_PER_SECOND
    ):
        raise ValueError(
            f"rate_per_second must be finite and within (0, {MAX_RATE_PER_SECOND}]"
        )
    if (
        rate_per_second is not None
        and (requests - 1) / rate_per_second > MAX_SCHEDULE_SECONDS
    ):
        raise ValueError(
            f"arrival schedule cannot exceed {MAX_SCHEDULE_SECONDS} seconds"
        )
    effective_deadline = timeout if deadline is None else deadline
    if (
        isinstance(effective_deadline, bool)
        or not isinstance(effective_deadline, (int, float))
        or not math.isfinite(effective_deadline)
        or not 0 < effective_deadline <= 60
    ):
        raise ValueError("deadline must be finite and within (0, 60] seconds")
    effective_run_id = run_id or uuid.uuid4().hex[:16]
    if not isinstance(effective_run_id, str) or not RUN_ID_RE.fullmatch(
        effective_run_id
    ):
        raise ValueError("run_id must be a bounded token without whitespace")
    policy = TargetPolicy.from_cidrs(allowed_cidrs)
    policy.validate_url(url)
    opener = build_opener(policy)

    latencies: list[float] = []
    backends: Counter[str] = Counter()
    failures: list[str] = []
    failed = 0
    deadline_exceeded = 0
    client_saturated = 0
    schedule_lag_ms: list[float] = []
    started = time.perf_counter()
    workers = min(concurrency, requests)

    def request_identity(index: int) -> str:
        return f"{effective_run_id}-{index:06d}"

    def submit(pool, index: int, scheduled_at: float):
        return pool.submit(
            request_once,
            url,
            timeout,
            opener,
            policy,
            request_identity(index),
            scheduled_at,
            scheduled_at + effective_deadline,
        )

    def consume(completed) -> None:
        nonlocal failed, deadline_exceeded
        for future in completed:
            try:
                backend, latency, _status = future.result()
                backends[backend] += 1
                latencies.append(latency)
            except Exception as exc:
                failed += 1
                if isinstance(exc, DeadlineExceeded):
                    deadline_exceeded += 1
                if len(failures) < 5:
                    # Exception messages may contain URLs or remote body data.
                    failures.append(type(exc).__name__)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        if rate_per_second is None:
            pending = {submit(pool, index, started) for index in range(workers)}
            submitted = workers
            while pending:
                completed, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                consume(completed)
                while submitted < requests and len(pending) < workers:
                    scheduled_at = time.perf_counter()
                    pending.add(submit(pool, submitted, scheduled_at))
                    submitted += 1
        else:
            pending = set()
            for index in range(requests):
                scheduled_at = started + index / rate_per_second
                delay = scheduled_at - time.perf_counter()
                if delay > 0.0:
                    time.sleep(delay)
                arrived_at = time.perf_counter()
                schedule_lag_ms.append(max(0.0, arrived_at - scheduled_at) * 1000)
                completed = {future for future in pending if future.done()}
                pending.difference_update(completed)
                consume(completed)
                if len(pending) >= workers:
                    client_saturated += 1
                    failed += 1
                    if len(failures) < 5:
                        failures.append("ClientSaturated")
                    continue
                pending.add(submit(pool, index, scheduled_at))
            while pending:
                completed, pending = concurrent.futures.wait(
                    pending, return_when=concurrent.futures.FIRST_COMPLETED
                )
                consume(completed)
    elapsed = time.perf_counter() - started
    return {
        "requested": requests,
        "succeeded": len(latencies),
        "failed": failed,
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(len(latencies) / elapsed, 2) if elapsed else 0.0,
        "backend_distribution": dict(backends),
        "load_model": {
            "mode": "constant_rate" if rate_per_second is not None else "closed_loop",
            "run_id": effective_run_id,
            "target_rate_per_second": rate_per_second,
            "deadline_seconds": effective_deadline,
            "client_saturated": client_saturated,
            "deadline_exceeded": deadline_exceeded,
            "schedule_lag_ms": {
                "p50": round(percentile(schedule_lag_ms, 0.50), 3),
                "p95": round(percentile(schedule_lag_ms, 0.95), 3),
                "max": round(max(schedule_lag_ms), 3) if schedule_lag_ms else 0.0,
            },
        },
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3) if latencies else 0.0,
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
        "sample_failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate concurrent traffic through the reverse proxy."
    )
    parser.add_argument("--url", default="http://127.0.0.1:8080/whoami")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--rate",
        type=float,
        help="constant open-loop arrival rate in requests/second",
    )
    parser.add_argument(
        "--deadline",
        type=float,
        help="end-to-end request deadline in seconds; defaults to --timeout",
    )
    parser.add_argument(
        "--run-id",
        help="bounded correlation token; generated automatically when omitted",
    )
    parser.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="canonical target network; repeat to replace the loopback-only default",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            run(
                args.url,
                args.requests,
                args.concurrency,
                args.timeout,
                tuple(args.allow_cidr),
                args.rate,
                args.deadline,
                args.run_id,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
