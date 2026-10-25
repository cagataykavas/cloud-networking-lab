from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from tools.replay_guard import (
    ProxyHeaderReplay,
    ReplayGuardCapacityExceeded,
    ReplayGuardUnavailable,
)
from tools.sqlite_replay_guard import (
    ReplayGuardPolicyMismatch,
    SQLiteReplayGuard,
    SQLiteReplayGuardPolicy,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Clock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def claim_in_process(database_path: str, unique_id_sha256: str) -> str:
    guard = SQLiteReplayGuard(
        database_path,
        SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=64,
            namespace="listener-a",
            busy_timeout_seconds=5,
        ),
    )
    try:
        guard.claim(unique_id_sha256)
        return "accepted"
    except ProxyHeaderReplay:
        return "replayed"


def test_claim_persists_across_guard_instances(tmp_path: Path) -> None:
    database = tmp_path / "replay.db"
    policy = SQLiteReplayGuardPolicy(ttl_seconds=30, max_entries=8)
    first = SQLiteReplayGuard(database, policy)
    second = SQLiteReplayGuard(database, policy)

    first.claim(digest("request-1"))

    with pytest.raises(ProxyHeaderReplay, match="proxy_header_replay"):
        second.claim(digest("request-1"))
    assert second.snapshot().claimed_total == 1
    assert second.snapshot().replay_rejected_total == 1


def test_parallel_processes_allow_exactly_one_claim(tmp_path: Path) -> None:
    database = tmp_path / "shared.db"
    policy = SQLiteReplayGuardPolicy(
        ttl_seconds=30,
        max_entries=64,
        namespace="listener-a",
        busy_timeout_seconds=5,
    )
    SQLiteReplayGuard(database, policy)
    key = digest("same-request")

    with ProcessPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                claim_in_process,
                [str(database)] * 32,
                [key] * 32,
            )
        )

    assert outcomes.count("accepted") == 1
    assert outcomes.count("replayed") == 31
    snapshot = SQLiteReplayGuard(database, policy).snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 1
    assert snapshot.replay_rejected_total == 31


def test_ttl_expiry_is_shared_and_persisted(tmp_path: Path) -> None:
    database = tmp_path / "expiry.db"
    clock = Clock()
    policy = SQLiteReplayGuardPolicy(ttl_seconds=10, max_entries=2)
    first = SQLiteReplayGuard(database, policy, clock=clock)
    first.claim(digest("request-1"))

    clock.now += 10
    second = SQLiteReplayGuard(database, policy, clock=clock)
    second.claim(digest("request-1"))

    snapshot = first.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 2
    assert snapshot.expired_total == 1


def test_capacity_is_enforced_across_instances(tmp_path: Path) -> None:
    database = tmp_path / "capacity.db"
    policy = SQLiteReplayGuardPolicy(ttl_seconds=30, max_entries=1)
    first = SQLiteReplayGuard(database, policy)
    second = SQLiteReplayGuard(database, policy)
    first.claim(digest("request-1"))

    with pytest.raises(
        ReplayGuardCapacityExceeded, match="replay_guard_capacity_exceeded"
    ):
        second.claim(digest("request-2"))
    assert first.snapshot().capacity_rejected_total == 1


def test_namespaces_are_isolated(tmp_path: Path) -> None:
    database = tmp_path / "namespaces.db"
    key = digest("request-1")
    guard_a = SQLiteReplayGuard(
        database, SQLiteReplayGuardPolicy(namespace="listener-a")
    )
    guard_b = SQLiteReplayGuard(
        database, SQLiteReplayGuardPolicy(namespace="listener-b")
    )

    guard_a.claim(key)
    guard_b.claim(key)

    assert guard_a.snapshot().claimed_total == 1
    assert guard_b.snapshot().claimed_total == 1


def test_policy_change_for_existing_namespace_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "policy.db"
    SQLiteReplayGuard(
        database,
        SQLiteReplayGuardPolicy(ttl_seconds=30, namespace="listener-a"),
    )

    with pytest.raises(ReplayGuardPolicyMismatch, match="replay_guard_policy_mismatch"):
        SQLiteReplayGuard(
            database,
            SQLiteReplayGuardPolicy(ttl_seconds=60, namespace="listener-a"),
        )


def test_locked_store_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "locked.db"
    policy = SQLiteReplayGuardPolicy(busy_timeout_seconds=0.01)
    guard = SQLiteReplayGuard(database, policy)
    blocker = sqlite3.connect(database, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(ReplayGuardUnavailable, match="replay_guard_unavailable"):
            guard.claim(digest("request-1"))
    finally:
        blocker.rollback()
        blocker.close()


@pytest.mark.parametrize(
    "namespace",
    ["", "has space", "../escape", "a" * 65, "ümlaut"],
)
def test_policy_rejects_invalid_namespaces(namespace: str) -> None:
    with pytest.raises(ValueError, match="namespace"):
        SQLiteReplayGuardPolicy(namespace=namespace)


def test_policy_digest_binds_shared_backend_configuration() -> None:
    policy = SQLiteReplayGuardPolicy(
        ttl_seconds=30,
        max_entries=8,
        namespace="listener-a",
        busy_timeout_seconds=2,
    )

    assert (
        policy.digest
        == SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
            busy_timeout_seconds=2,
        ).digest
    )
    assert (
        policy.digest
        != SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-b",
            busy_timeout_seconds=2,
        ).digest
    )
