from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tools.replay_guard import (
    MAX_REPLAY_ENTRIES,
    MAX_REPLAY_TTL_SECONDS,
    SHA256_RE,
    ProxyHeaderReplay,
    ReplayGuardCapacityExceeded,
    ReplayGuardSnapshot,
    ReplayGuardUnavailable,
)


NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ReplayGuardPolicyMismatch(RuntimeError):
    """A namespace is already bound to a different immutable policy."""

    code = "replay_guard_policy_mismatch"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True)
class SQLiteReplayGuardPolicy:
    ttl_seconds: float = 300.0
    max_entries: int = 65_536
    namespace: str = "default"
    busy_timeout_seconds: float = 1.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.ttl_seconds, bool)
            or not isinstance(self.ttl_seconds, (int, float))
            or not math.isfinite(self.ttl_seconds)
            or not 0 < self.ttl_seconds <= MAX_REPLAY_TTL_SECONDS
        ):
            raise ValueError(
                f"ttl_seconds must be finite and in (0, {MAX_REPLAY_TTL_SECONDS:g}]"
            )
        if (
            isinstance(self.max_entries, bool)
            or not isinstance(self.max_entries, int)
            or not 1 <= self.max_entries <= MAX_REPLAY_ENTRIES
        ):
            raise ValueError(
                f"max_entries must be an integer in [1, {MAX_REPLAY_ENTRIES}]"
            )
        if (
            not isinstance(self.namespace, str)
            or NAMESPACE_RE.fullmatch(self.namespace) is None
        ):
            raise ValueError(
                "namespace must be 1-64 ASCII letters, numbers, dots, underscores or hyphens"
            )
        if (
            isinstance(self.busy_timeout_seconds, bool)
            or not isinstance(self.busy_timeout_seconds, (int, float))
            or not math.isfinite(self.busy_timeout_seconds)
            or not 0 < self.busy_timeout_seconds <= 30
        ):
            raise ValueError("busy_timeout_seconds must be finite and in (0, 30]")

    @property
    def digest(self) -> str:
        document = {
            "backend": "sqlite-v1",
            "busy_timeout_seconds": float(self.busy_timeout_seconds),
            "max_entries": self.max_entries,
            "namespace": self.namespace,
            "ttl_seconds": float(self.ttl_seconds),
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class _Decision:
    error: RuntimeError | None = None


class SQLiteReplayGuard:
    """Process-safe, bounded TTL claims in a local SQLite database.

    Every operation opens its own connection and uses ``BEGIN IMMEDIATE`` so
    independent listener workers serialize claim decisions in the database.
    Store errors are normalized to a fail-closed exception.
    """

    def __init__(
        self,
        database_path: str | Path,
        policy: SQLiteReplayGuardPolicy | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy or SQLiteReplayGuardPolicy()
        self.database_path = Path(database_path)
        if str(database_path) == ":memory:":
            raise ValueError(":memory: cannot coordinate independent connections")
        if not self.database_path.parent.is_dir():
            raise ValueError("database parent directory must already exist")
        self._clock = clock
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=float(self.policy.busy_timeout_seconds),
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _now(self) -> float:
        now = self._clock()
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            raise RuntimeError("replay_guard_clock_invalid")
        return float(now)

    @staticmethod
    def _validate_digest(unique_id_sha256: str) -> None:
        if (
            not isinstance(unique_id_sha256, str)
            or SHA256_RE.fullmatch(unique_id_sha256) is None
        ):
            raise ValueError("unique_id_sha256 must be canonical lowercase SHA-256")

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS replay_guard_state (
                        namespace TEXT PRIMARY KEY,
                        policy_sha256 TEXT NOT NULL,
                        active_entries INTEGER NOT NULL CHECK (active_entries >= 0),
                        claimed_total INTEGER NOT NULL CHECK (claimed_total >= 0),
                        replay_rejected_total INTEGER NOT NULL CHECK (replay_rejected_total >= 0),
                        capacity_rejected_total INTEGER NOT NULL CHECK (capacity_rejected_total >= 0),
                        expired_total INTEGER NOT NULL CHECK (expired_total >= 0)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS replay_guard_claims (
                        namespace TEXT NOT NULL,
                        unique_id_sha256 TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        PRIMARY KEY (namespace, unique_id_sha256),
                        FOREIGN KEY (namespace) REFERENCES replay_guard_state(namespace)
                    ) WITHOUT ROWID
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS replay_guard_claim_expiry
                    ON replay_guard_claims (namespace, expires_at)
                    """
                )
                row = connection.execute(
                    "SELECT policy_sha256 FROM replay_guard_state WHERE namespace = ?",
                    (self.policy.namespace,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO replay_guard_state (
                            namespace, policy_sha256, active_entries, claimed_total,
                            replay_rejected_total, capacity_rejected_total, expired_total
                        ) VALUES (?, ?, 0, 0, 0, 0, 0)
                        """,
                        (self.policy.namespace, self.policy.digest),
                    )
                elif row[0] != self.policy.digest:
                    raise ReplayGuardPolicyMismatch
        except ReplayGuardPolicyMismatch:
            raise
        except sqlite3.Error as exc:
            raise ReplayGuardUnavailable from exc

    def _expire(self, connection: sqlite3.Connection, now: float) -> int:
        cursor = connection.execute(
            """
            DELETE FROM replay_guard_claims
            WHERE namespace = ? AND expires_at <= ?
            """,
            (self.policy.namespace, now),
        )
        expired = cursor.rowcount
        if expired:
            connection.execute(
                """
                UPDATE replay_guard_state
                SET active_entries = active_entries - ?, expired_total = expired_total + ?
                WHERE namespace = ?
                """,
                (expired, expired, self.policy.namespace),
            )
        return expired

    def claim(self, unique_id_sha256: str) -> None:
        """Claim one digest atomically across all workers using this namespace."""
        self._validate_digest(unique_id_sha256)
        decision = _Decision()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now = self._now()
                self._expire(connection, now)
                existing = connection.execute(
                    """
                    SELECT 1 FROM replay_guard_claims
                    WHERE namespace = ? AND unique_id_sha256 = ?
                    """,
                    (self.policy.namespace, unique_id_sha256),
                ).fetchone()
                if existing is not None:
                    connection.execute(
                        """
                        UPDATE replay_guard_state
                        SET replay_rejected_total = replay_rejected_total + 1
                        WHERE namespace = ?
                        """,
                        (self.policy.namespace,),
                    )
                    decision = _Decision(ProxyHeaderReplay())
                else:
                    active_entries = connection.execute(
                        """
                        SELECT active_entries FROM replay_guard_state
                        WHERE namespace = ?
                        """,
                        (self.policy.namespace,),
                    ).fetchone()
                    if active_entries is None:
                        raise sqlite3.DatabaseError("replay guard state missing")
                    if active_entries[0] >= self.policy.max_entries:
                        connection.execute(
                            """
                            UPDATE replay_guard_state
                            SET capacity_rejected_total = capacity_rejected_total + 1
                            WHERE namespace = ?
                            """,
                            (self.policy.namespace,),
                        )
                        decision = _Decision(ReplayGuardCapacityExceeded())
                    else:
                        connection.execute(
                            """
                            INSERT INTO replay_guard_claims (
                                namespace, unique_id_sha256, expires_at
                            ) VALUES (?, ?, ?)
                            """,
                            (
                                self.policy.namespace,
                                unique_id_sha256,
                                now + float(self.policy.ttl_seconds),
                            ),
                        )
                        connection.execute(
                            """
                            UPDATE replay_guard_state
                            SET active_entries = active_entries + 1,
                                claimed_total = claimed_total + 1
                            WHERE namespace = ?
                            """,
                            (self.policy.namespace,),
                        )
        except sqlite3.Error as exc:
            raise ReplayGuardUnavailable from exc
        if decision.error is not None:
            raise decision.error

    def snapshot(self) -> ReplayGuardSnapshot:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._expire(connection, self._now())
                row = connection.execute(
                    """
                    SELECT active_entries, claimed_total, replay_rejected_total,
                           capacity_rejected_total, expired_total
                    FROM replay_guard_state WHERE namespace = ?
                    """,
                    (self.policy.namespace,),
                ).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError("replay guard state missing")
                return ReplayGuardSnapshot(
                    active_entries=row[0],
                    max_entries=self.policy.max_entries,
                    claimed_total=row[1],
                    replay_rejected_total=row[2],
                    capacity_rejected_total=row[3],
                    expired_total=row[4],
                    policy_sha256=self.policy.digest,
                )
        except sqlite3.Error as exc:
            raise ReplayGuardUnavailable from exc
