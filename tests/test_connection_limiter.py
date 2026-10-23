from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tools.connection_limiter import (
    ConnectionCapacityExceeded,
    ConnectionLimitPolicy,
    ConnectionLimiter,
)


def test_context_manager_releases_capacity_after_success_and_exception() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))

    with limiter.acquire():
        assert limiter.snapshot().in_flight == 1
    assert limiter.snapshot().in_flight == 0

    with pytest.raises(RuntimeError, match="handler failed"):
        with limiter.acquire():
            raise RuntimeError("handler failed")
    assert limiter.snapshot().in_flight == 0


def test_saturated_limiter_fails_immediately_and_counts_rejection() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))

    with limiter.acquire():
        with pytest.raises(
            ConnectionCapacityExceeded, match="connection_capacity_exceeded"
        ):
            limiter.acquire()
        snapshot = limiter.snapshot()
        assert snapshot.in_flight == 1
        assert snapshot.admitted_total == 1
        assert snapshot.rejected_total == 1
        assert snapshot.high_watermark == 1


def test_parallel_admission_never_exceeds_budget() -> None:
    worker_count = 64
    capacity = 8
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=capacity))
    start = threading.Barrier(worker_count + 1)
    release = threading.Event()

    def attempt() -> bool:
        start.wait()
        try:
            with limiter.acquire():
                assert release.wait(timeout=5)
                return True
        except ConnectionCapacityExceeded:
            return False

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(attempt) for _ in range(worker_count)]
        start.wait()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            snapshot = limiter.snapshot()
            if snapshot.admitted_total + snapshot.rejected_total == worker_count:
                break
            time.sleep(0.001)
        else:
            pytest.fail("parallel admission decisions did not complete")
        release.set()
        accepted = [future.result(timeout=5) for future in futures]

    assert sum(accepted) == capacity
    snapshot = limiter.snapshot()
    assert snapshot.in_flight == 0
    assert snapshot.high_watermark == capacity
    assert snapshot.admitted_total == capacity
    assert snapshot.rejected_total == worker_count - capacity


def test_lease_release_is_idempotent_and_cannot_underflow() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=1))
    lease = limiter.acquire()

    assert lease.release() is True
    assert lease.release() is False
    assert lease.released is True
    assert limiter.snapshot().in_flight == 0


@pytest.mark.parametrize("value", [True, 0, -1, 65_537, 1.5, "8"])
def test_policy_rejects_unbounded_or_ambiguous_capacity(value: object) -> None:
    with pytest.raises(ValueError, match="max_in_flight"):
        ConnectionLimitPolicy(max_in_flight=value)  # type: ignore[arg-type]


def test_policy_digest_and_snapshot_are_deterministic_and_low_cardinality() -> None:
    first = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=4))
    second = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=4))

    with first.acquire():
        snapshot = first.snapshot()

    assert snapshot.policy_sha256 == second.policy.digest
    assert snapshot.as_dict() == {
        "max_in_flight": 4,
        "in_flight": 1,
        "available": 3,
        "admitted_total": 1,
        "rejected_total": 0,
        "high_watermark": 1,
        "policy_sha256": first.policy.digest,
    }
