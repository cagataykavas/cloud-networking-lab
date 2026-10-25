from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tools.replay_guard import (
    ProxyHeaderReplay,
    ProxyReplayGuard,
    ReplayGuardCapacityExceeded,
    ReplayGuardPolicy,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Clock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_claim_rejects_replay_until_ttl_expires() -> None:
    clock = Clock()
    guard = ProxyReplayGuard(
        ReplayGuardPolicy(ttl_seconds=10, max_entries=2), clock=clock
    )
    key = digest("request-1")

    guard.claim(key)
    with pytest.raises(ProxyHeaderReplay, match="proxy_header_replay"):
        guard.claim(key)

    clock.now += 10
    guard.claim(key)
    snapshot = guard.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 2
    assert snapshot.replay_rejected_total == 1
    assert snapshot.expired_total == 1


def test_capacity_fails_closed_without_evicting_live_claims() -> None:
    guard = ProxyReplayGuard(ReplayGuardPolicy(ttl_seconds=30, max_entries=1))
    first = digest("request-1")
    second = digest("request-2")

    guard.claim(first)
    with pytest.raises(
        ReplayGuardCapacityExceeded, match="replay_guard_capacity_exceeded"
    ):
        guard.claim(second)
    with pytest.raises(ProxyHeaderReplay):
        guard.claim(first)

    snapshot = guard.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.capacity_rejected_total == 1
    assert snapshot.replay_rejected_total == 1


def test_parallel_duplicate_claim_has_exactly_one_winner() -> None:
    workers = 64
    guard = ProxyReplayGuard(ReplayGuardPolicy(ttl_seconds=30, max_entries=workers))
    key = digest("same-request")
    start = threading.Barrier(workers + 1)

    def claim() -> bool:
        start.wait()
        try:
            guard.claim(key)
            return True
        except ProxyHeaderReplay:
            return False

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(claim) for _ in range(workers)]
        start.wait()
        accepted = [future.result(timeout=5) for future in futures]

    assert sum(accepted) == 1
    snapshot = guard.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 1
    assert snapshot.replay_rejected_total == workers - 1


@pytest.mark.parametrize(
    "value",
    [True, 0, -1, float("inf"), float("nan"), 3_601, "30"],
)
def test_policy_rejects_invalid_ttl(value: object) -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        ReplayGuardPolicy(ttl_seconds=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 0, -1, 1_000_001, 1.5, "8"])
def test_policy_rejects_invalid_capacity(value: object) -> None:
    with pytest.raises(ValueError, match="max_entries"):
        ReplayGuardPolicy(max_entries=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["A" * 64, "0" * 63, "not-a-digest", 7])
def test_claim_rejects_noncanonical_digests(value: object) -> None:
    with pytest.raises(ValueError, match="unique_id_sha256"):
        ProxyReplayGuard().claim(value)  # type: ignore[arg-type]


def test_snapshot_is_low_cardinality_and_policy_bound() -> None:
    policy = ReplayGuardPolicy(ttl_seconds=30, max_entries=4)
    guard = ProxyReplayGuard(policy)
    guard.claim(digest("request-1"))

    assert guard.snapshot().as_dict() == {
        "active_entries": 1,
        "max_entries": 4,
        "claimed_total": 1,
        "replay_rejected_total": 0,
        "capacity_rejected_total": 0,
        "expired_total": 0,
        "policy_sha256": policy.digest,
        "clock_regression_rejected_total": 0,
    }
