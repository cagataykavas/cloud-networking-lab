from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import statistics
import time
import urllib.request
from collections import Counter

MAX_REQUESTS = 100_000
MAX_CONCURRENCY = 128
MAX_RESPONSE_BYTES = 64 * 1024


def request_once(url: str, timeout: float) -> tuple[str, float, int]:
    started = time.perf_counter()
    request = urllib.request.Request(
        url, headers={"User-Agent": "cloud-networking-lab/1.0"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeds the load probe byte limit")
        payload = json.loads(body)
        status = response.status
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("instance_id"), str)
        or not 1 <= len(payload["instance_id"]) <= 128
        or not payload["instance_id"].strip()
    ):
        raise ValueError(
            "response requires a non-empty instance_id of at most 128 characters"
        )
    latency_ms = (time.perf_counter() - started) * 1000
    return payload["instance_id"], latency_ms, status


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * quantile))))
    return ordered[index]


def run(url: str, requests: int, concurrency: int, timeout: float) -> dict[str, object]:
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

    latencies: list[float] = []
    backends: Counter[str] = Counter()
    failures: list[str] = []
    failed = 0
    started = time.perf_counter()
    workers = min(concurrency, requests)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {pool.submit(request_once, url, timeout) for _ in range(workers)}
        submitted = workers
        while pending:
            completed, pending = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in completed:
                try:
                    backend, latency, _status = future.result()
                    backends[backend] += 1
                    latencies.append(latency)
                except Exception as exc:
                    failed += 1
                    if len(failures) < 5:
                        # Exception messages may contain URLs or remote body data.
                        failures.append(type(exc).__name__)
            # Drop completed futures before refilling the bounded submission window.
            completed.clear()
            del future
            while submitted < requests and len(pending) < workers:
                pending.add(pool.submit(request_once, url, timeout))
                submitted += 1
    elapsed = time.perf_counter() - started
    return {
        "requested": requests,
        "succeeded": len(latencies),
        "failed": failed,
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(len(latencies) / elapsed, 2) if elapsed else 0.0,
        "backend_distribution": dict(backends),
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
    parser.add_argument("--url", default="http://localhost:8080/whoami")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    print(
        json.dumps(
            run(args.url, args.requests, args.concurrency, args.timeout), indent=2
        )
    )


if __name__ == "__main__":
    main()
