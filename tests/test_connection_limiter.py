from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tools.connection_limiter import (
    ConnectionCapacityExceeded,
    ConnectionLimitPolicy,
    ConnectionLimiter,
    ListenerDraining,
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


def test_drain_rejects_new_leases_and_preserves_existing_ownership() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=2))
    lease = limiter.acquire()

    assert limiter.begin_drain() is True
    assert limiter.begin_drain() is False
    assert limiter.snapshot().lifecycle_state == "draining"
    with pytest.raises(ListenerDraining, match="listener_draining"):
        limiter.acquire()

    snapshot = limiter.snapshot()
    assert snapshot.in_flight == 1
    assert snapshot.rejected_total == 1
    assert snapshot.draining_rejected_total == 1
    assert limiter.wait_for_drain(0) is False

    assert lease.release()
    assert limiter.wait_for_drain(0) is True
    assert limiter.snapshot().lifecycle_state == "drained"


def test_wait_for_drain_unblocks_only_after_last_lease_releases() -> None:
    limiter = ConnectionLimiter(ConnectionLimitPolicy(max_in_flight=2))
    first = limiter.acquire()
    second = limiter.acquire()
    limiter.begin_drain()
    waiter_started = threading.Event()

    def wait_for_shutdown() -> bool:
        waiter_started.set()
        return limiter.wait_for_drain(1)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(wait_for_shutdown)
        assert waiter_started.wait(timeout=1)
        assert first.release()
        assert not future.done()
        assert second.release()
        assert future.result(timeout=1) is True


def test_wait_for_drain_requires_explicit_transition() -> None:
    limiter = ConnectionLimiter()
    with pytest.raises(RuntimeError, match="listener_drain_not_started"):
        limiter.wait_for_drain(0)


def test_drain_empty_listener_is_immediate_and_idempotent() -> None:
    limiter = ConnectionLimiter()

    assert limiter.drain(0) is True
    assert limiter.drain(0) is True
    assert limiter.snapshot().lifecycle_state == "drained"


@pytest.mark.parametrize("value", [True, -1, float("inf"), float("nan"), 3_601, "1"])
def test_drain_rejects_invalid_or_unbounded_timeouts(value: object) -> None:
    limiter = ConnectionLimiter()
    with pytest.raises(ValueError, match="timeout_seconds"):
        limiter.drain(value)  # type: ignore[arg-type]
    assert limiter.snapshot().lifecycle_state == "accepting"


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
        "draining_rejected_total": 0,
        "high_watermark": 1,
        "policy_sha256": first.policy.digest,
        "lifecycle_state": "accepting",
    }
