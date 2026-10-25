from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from tools.replay_guard import (
    ProxyHeaderReplay,
    ReplayGuardCapacityExceeded,
    ReplayGuardClockRegression,
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


def test_small_clock_regression_uses_persistent_watermark(tmp_path: Path) -> None:
    database = tmp_path / "small-regression.db"
    clock = Clock()
    guard = SQLiteReplayGuard(
        database,
        SQLiteReplayGuardPolicy(
            ttl_seconds=10,
            max_clock_regression_seconds=1,
        ),
        clock=clock,
    )
    guard.claim(digest("request-1"))

    clock.now -= 0.5
    guard.claim(digest("request-2"))
    with sqlite3.connect(database) as connection:
        expirations = connection.execute(
            "SELECT DISTINCT expires_at FROM replay_guard_claims"
        ).fetchall()

    assert expirations == [(1_010.0,)]
    clock.now = 1_010.0
    assert guard.snapshot().active_entries == 0


def test_large_clock_regression_rejects_without_claiming(tmp_path: Path) -> None:
    database = tmp_path / "large-regression.db"
    clock = Clock()
    guard = SQLiteReplayGuard(
        database,
        SQLiteReplayGuardPolicy(max_clock_regression_seconds=1),
        clock=clock,
    )
    guard.claim(digest("request-1"))

    clock.now -= 1.001
    with pytest.raises(
        ReplayGuardClockRegression, match="replay_guard_clock_regression"
    ):
        guard.claim(digest("request-2"))

    clock.now = 1_000.0
    snapshot = guard.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 1
    assert snapshot.clock_regression_rejected_total == 1


def test_clock_watermark_is_shared_across_instances(tmp_path: Path) -> None:
    database = tmp_path / "shared-clock.db"
    policy = SQLiteReplayGuardPolicy(max_clock_regression_seconds=0.25)
    first_clock = Clock(2_000.0)
    second_clock = Clock(1_999.0)
    first = SQLiteReplayGuard(database, policy, clock=first_clock)
    second = SQLiteReplayGuard(database, policy, clock=second_clock)
    first.claim(digest("request-1"))

    with pytest.raises(ReplayGuardClockRegression):
        second.claim(digest("request-2"))

    second_clock.now = 2_000.0
    assert second.snapshot().clock_regression_rejected_total == 1


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


def test_sqlite_v1_namespace_migrates_without_losing_claims(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    policy = SQLiteReplayGuardPolicy(
        ttl_seconds=30,
        max_entries=8,
        namespace="listener-a",
    )
    key = digest("request-1")
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE replay_guard_state (
                namespace TEXT PRIMARY KEY,
                policy_sha256 TEXT NOT NULL,
                active_entries INTEGER NOT NULL,
                claimed_total INTEGER NOT NULL,
                replay_rejected_total INTEGER NOT NULL,
                capacity_rejected_total INTEGER NOT NULL,
                expired_total INTEGER NOT NULL
            );
            CREATE TABLE replay_guard_claims (
                namespace TEXT NOT NULL,
                unique_id_sha256 TEXT NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (namespace, unique_id_sha256),
                FOREIGN KEY (namespace) REFERENCES replay_guard_state(namespace)
            ) WITHOUT ROWID;
            """
        )
        connection.execute(
            "INSERT INTO replay_guard_state VALUES (?, ?, 1, 1, 0, 0, 0)",
            (policy.namespace, policy.legacy_digest),
        )
        connection.execute(
            "INSERT INTO replay_guard_claims VALUES (?, ?, ?)",
            (policy.namespace, key, 1_030.0),
        )

    guard = SQLiteReplayGuard(database, policy, clock=Clock())

    with pytest.raises(ProxyHeaderReplay):
        guard.claim(key)
    assert guard.snapshot().active_entries == 1
    with sqlite3.connect(database) as connection:
        stored_policy, watermark, regressions = connection.execute(
            """
            SELECT policy_sha256, last_observed_at,
                   clock_regression_rejected_total
            FROM replay_guard_state WHERE namespace = ?
            """,
            (policy.namespace,),
        ).fetchone()
    assert stored_policy == policy.digest
    assert watermark == 1_000.0
    assert regressions == 0


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
        max_clock_regression_seconds=0.5,
    )

    assert (
        policy.digest
        == SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
            busy_timeout_seconds=2,
            max_clock_regression_seconds=0.5,
        ).digest
    )
    assert (
        policy.digest
        != SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-b",
            busy_timeout_seconds=2,
            max_clock_regression_seconds=0.5,
        ).digest
    )
    assert (
        policy.digest
        != SQLiteReplayGuardPolicy(
            ttl_seconds=30,
            max_entries=8,
            namespace="listener-a",
            busy_timeout_seconds=2,
            max_clock_regression_seconds=1,
        ).digest
    )


@pytest.mark.parametrize("value", [True, -1, 61, float("inf"), float("nan"), "1"])
def test_policy_rejects_invalid_clock_regression_tolerance(value: object) -> None:
    with pytest.raises(ValueError, match="max_clock_regression_seconds"):
        SQLiteReplayGuardPolicy(  # type: ignore[arg-type]
            max_clock_regression_seconds=value
        )
