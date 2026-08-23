from __future__ import annotations

import argparse
import concurrent.futures
import json
import statistics
import time
import urllib.request
from collections import Counter


def request_once(url: str, timeout: float) -> tuple[str, float, int]:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": "cloud-networking-lab/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read())
        status = response.status
    latency_ms = (time.perf_counter() - started) * 1000
    return str(payload.get("instance_id", "unknown")), latency_ms, status


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * quantile))))
    return ordered[index]


def run(url: str, requests: int, concurrency: int, timeout: float) -> dict[str, object]:
    results: list[tuple[str, float, int]] = []
    failures: list[str] = []
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(request_once, url, timeout) for _ in range(requests)]
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                failures.append(f"{type(exc).__name__}: {exc}")
    elapsed = time.perf_counter() - started
    latencies = [item[1] for item in results]
    return {
        "requested": requests,
        "succeeded": len(results),
        "failed": len(failures),
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(len(results) / elapsed, 2) if elapsed else 0.0,
        "backend_distribution": dict(Counter(item[0] for item in results)),
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3) if latencies else 0.0,
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
        "sample_failures": failures[:5],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate concurrent traffic through the reverse proxy.")
    parser.add_argument("--url", default="http://localhost:8080/whoami")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    print(json.dumps(run(args.url, args.requests, args.concurrency, args.timeout), indent=2))


if __name__ == "__main__":
    main()
