"""Durable, hash-chained authority state for Redis promotion proofs."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.redis_promotion_proof import (
    IDENTIFIER_RE,
    SHA256_RE,
    RedisPromotionProof,
    RedisReplicationSnapshot,
    sign_promotion_proof,
)


SCHEMA_VERSION = 1


class PromotionAuthorityError(RuntimeError):
    """Base class for fail-closed authority errors."""


class PromotionAuthorityConflict(PromotionAuthorityError):
    """The caller supplied stale or non-monotonic authority state."""


class PromotionAuthorityCorrupt(PromotionAuthorityError):
    """The persisted authority chain failed integrity validation."""


class PromotionAuthorityUnavailable(PromotionAuthorityError):
    """The authority database could not complete a durable operation."""


@dataclass(frozen=True)
class PromotionAuthorityState:
    cluster_id: str
    revision: int
    authority_epoch: int
    candidate_id: str
    minimum_replication_offset: int
    replid_sha256: str
    observed_at: int
    previous_state_sha256: str | None
    state_sha256: str

    def payload(self) -> dict[str, str | int | None]:
        return {
            "authority_epoch": self.authority_epoch,
            "candidate_id": self.candidate_id,
            "cluster_id": self.cluster_id,
            "minimum_replication_offset": self.minimum_replication_offset,
            "observed_at": self.observed_at,
            "previous_state_sha256": self.previous_state_sha256,
            "replid_sha256": self.replid_sha256,
            "revision": self.revision,
            "schema_version": SCHEMA_VERSION,
        }


class SQLitePromotionAuthority:
    """Single-writer election ledger with explicit compare-and-swap tokens.

    Each revision is append-only and chained to the previous revision's digest.
    Callers must retain the returned ``state_sha256`` outside this database and
    supply it on the next mutation or proof issuance. That token detects stale
    writers and a database restored behind the caller's durable checkpoint.
    """

    def __init__(
        self,
        database_path: str | Path,
        cluster_id: str,
        *,
        busy_timeout_seconds: float = 1.0,
    ) -> None:
        self.database_path = Path(database_path)
        self.cluster_id = _identifier(cluster_id, "cluster_id")
        if str(database_path) == ":memory:":
            raise ValueError(":memory: is not durable authority storage")
        if self.database_path.is_symlink():
            raise ValueError("authority database path must not be a symlink")
        if not self.database_path.parent.is_dir():
            raise ValueError("authority database parent directory must already exist")
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not 0 < busy_timeout_seconds <= 30
        ):
            raise ValueError("busy_timeout_seconds must be in (0, 30]")
        self.busy_timeout_seconds = float(busy_timeout_seconds)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.busy_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS promotion_authority_revisions (
                        cluster_id TEXT NOT NULL,
                        revision INTEGER NOT NULL CHECK (revision > 0),
                        authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 0),
                        candidate_id TEXT NOT NULL,
                        minimum_replication_offset INTEGER NOT NULL
                            CHECK (minimum_replication_offset >= 0),
                        replid_sha256 TEXT NOT NULL,
                        observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
                        previous_state_sha256 TEXT,
                        state_sha256 TEXT NOT NULL,
                        PRIMARY KEY (cluster_id, revision),
                        UNIQUE (cluster_id, authority_epoch),
                        UNIQUE (cluster_id, state_sha256)
                    ) WITHOUT ROWID
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS promotion_authority_no_update
                    BEFORE UPDATE ON promotion_authority_revisions
                    BEGIN
                        SELECT RAISE(ABORT, 'promotion authority revisions are immutable');
                    END
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS promotion_authority_no_delete
                    BEFORE DELETE ON promotion_authority_revisions
                    BEGIN
                        SELECT RAISE(ABORT, 'promotion authority revisions are immutable');
                    END
                    """
                )
                self._validated_head(connection)
                connection.commit()
            os.chmod(self.database_path, 0o600)
        except PromotionAuthorityCorrupt:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PromotionAuthorityUnavailable(
                "promotion_authority_unavailable"
            ) from exc

    def snapshot(self) -> PromotionAuthorityState | None:
        try:
            with closing(self._connect()) as connection:
                return self._validated_head(connection)
        except PromotionAuthorityCorrupt:
            raise
        except sqlite3.Error as exc:
            raise PromotionAuthorityUnavailable(
                "promotion_authority_unavailable"
            ) from exc

    def advance(
        self,
        *,
        authority_epoch: int,
        candidate_id: str,
        minimum_replication_offset: int,
        snapshot: RedisReplicationSnapshot,
        observed_at: int,
        expected_state_sha256: str | None,
    ) -> PromotionAuthorityState:
        """Append one monotonic election decision under a CAS head token."""

        epoch = _nonnegative_integer(authority_epoch, "authority_epoch")
        candidate = _identifier(candidate_id, "candidate_id")
        offset = _nonnegative_integer(
            minimum_replication_offset, "minimum_replication_offset"
        )
        timestamp = _nonnegative_integer(observed_at, "observed_at")
        _optional_digest(expected_state_sha256, "expected_state_sha256")
        if snapshot.role != "master":
            raise ValueError("authority state requires an already promoted master")
        if snapshot.offset < offset:
            raise ValueError("candidate offset is below the authority minimum")

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = self._validated_head(connection)
                current_digest = current.state_sha256 if current else None
                if expected_state_sha256 != current_digest:
                    raise PromotionAuthorityConflict(
                        "promotion_authority_head_mismatch"
                    )
                if current is not None:
                    requested = (
                        epoch,
                        candidate,
                        offset,
                        snapshot.replid_sha256,
                        timestamp,
                    )
                    existing = (
                        current.authority_epoch,
                        current.candidate_id,
                        current.minimum_replication_offset,
                        current.replid_sha256,
                        current.observed_at,
                    )
                    if requested == existing:
                        connection.commit()
                        return current
                    if epoch <= current.authority_epoch:
                        raise PromotionAuthorityConflict(
                            "promotion_authority_epoch_not_monotonic"
                        )
                    if offset < current.minimum_replication_offset:
                        raise PromotionAuthorityConflict(
                            "promotion_authority_offset_regressed"
                        )
                    if timestamp < current.observed_at:
                        raise PromotionAuthorityConflict(
                            "promotion_authority_time_regressed"
                        )

                revision = 1 if current is None else current.revision + 1
                state = _build_state(
                    cluster_id=self.cluster_id,
                    revision=revision,
                    authority_epoch=epoch,
                    candidate_id=candidate,
                    minimum_replication_offset=offset,
                    replid_sha256=snapshot.replid_sha256,
                    observed_at=timestamp,
                    previous_state_sha256=current_digest,
                )
                connection.execute(
                    """
                    INSERT INTO promotion_authority_revisions (
                        cluster_id, revision, authority_epoch, candidate_id,
                        minimum_replication_offset, replid_sha256, observed_at,
                        previous_state_sha256, state_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        state.cluster_id,
                        state.revision,
                        state.authority_epoch,
                        state.candidate_id,
                        state.minimum_replication_offset,
                        state.replid_sha256,
                        state.observed_at,
                        state.previous_state_sha256,
                        state.state_sha256,
                    ),
                )
                connection.commit()
                return state
        except PromotionAuthorityError:
            raise
        except sqlite3.Error as exc:
            raise PromotionAuthorityUnavailable(
                "promotion_authority_unavailable"
            ) from exc

    def issue_proof(
        self,
        *,
        expected_state_sha256: str,
        candidate_id: str,
        snapshot: RedisReplicationSnapshot,
        issued_at: int,
        expires_at: int,
        key_id: str,
        secret: bytes,
    ) -> RedisPromotionProof:
        """Issue a proof only from the exact externally anchored authority head."""

        expected = _digest(expected_state_sha256, "expected_state_sha256")
        candidate = _identifier(candidate_id, "candidate_id")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN")
                current = self._validated_head(connection)
                if current is None or current.state_sha256 != expected:
                    raise PromotionAuthorityConflict(
                        "promotion_authority_head_mismatch"
                    )
                if current.candidate_id != candidate:
                    raise PromotionAuthorityConflict(
                        "promotion_authority_candidate_mismatch"
                    )
                if snapshot.role != "master":
                    raise PromotionAuthorityConflict(
                        "promotion_authority_candidate_not_master"
                    )
                if snapshot.replid_sha256 != current.replid_sha256:
                    raise PromotionAuthorityConflict(
                        "promotion_authority_replid_mismatch"
                    )
                if snapshot.offset < current.minimum_replication_offset:
                    raise PromotionAuthorityConflict(
                        "promotion_authority_offset_below_minimum"
                    )
                proof = sign_promotion_proof(
                    cluster_id=self.cluster_id,
                    candidate_id=candidate,
                    authority_epoch=current.authority_epoch,
                    minimum_replication_offset=current.minimum_replication_offset,
                    snapshot=snapshot,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    key_id=key_id,
                    secret=secret,
                )
                connection.commit()
                return proof
        except PromotionAuthorityError:
            raise
        except sqlite3.Error as exc:
            raise PromotionAuthorityUnavailable(
                "promotion_authority_unavailable"
            ) from exc

    def _validated_head(
        self, connection: sqlite3.Connection
    ) -> PromotionAuthorityState | None:
        rows = connection.execute(
            """
            SELECT * FROM promotion_authority_revisions
            WHERE cluster_id = ? ORDER BY revision
            """,
            (self.cluster_id,),
        ).fetchall()
        previous: PromotionAuthorityState | None = None
        for row in rows:
            state = _state_from_row(row)
            if state.revision != (1 if previous is None else previous.revision + 1):
                raise PromotionAuthorityCorrupt("promotion_authority_revision_gap")
            expected_previous = previous.state_sha256 if previous else None
            if state.previous_state_sha256 != expected_previous:
                raise PromotionAuthorityCorrupt("promotion_authority_chain_broken")
            if _state_digest(state.payload()) != state.state_sha256:
                raise PromotionAuthorityCorrupt("promotion_authority_digest_mismatch")
            if previous is not None and (
                state.authority_epoch <= previous.authority_epoch
                or state.minimum_replication_offset
                < previous.minimum_replication_offset
                or state.observed_at < previous.observed_at
            ):
                raise PromotionAuthorityCorrupt(
                    "promotion_authority_monotonicity_broken"
                )
            previous = state
        return previous


def _build_state(**values: Any) -> PromotionAuthorityState:
    unsigned = {"schema_version": SCHEMA_VERSION, **values}
    return PromotionAuthorityState(
        **values,
        state_sha256=_state_digest(unsigned),
    )


def _state_from_row(row: sqlite3.Row) -> PromotionAuthorityState:
    try:
        state = PromotionAuthorityState(
            cluster_id=_identifier(row["cluster_id"], "cluster_id"),
            revision=_positive_integer(row["revision"], "revision"),
            authority_epoch=_nonnegative_integer(
                row["authority_epoch"], "authority_epoch"
            ),
            candidate_id=_identifier(row["candidate_id"], "candidate_id"),
            minimum_replication_offset=_nonnegative_integer(
                row["minimum_replication_offset"],
                "minimum_replication_offset",
            ),
            replid_sha256=_digest(row["replid_sha256"], "replid_sha256"),
            observed_at=_nonnegative_integer(row["observed_at"], "observed_at"),
            previous_state_sha256=_optional_digest(
                row["previous_state_sha256"], "previous_state_sha256"
            ),
            state_sha256=_digest(row["state_sha256"], "state_sha256"),
        )
    except (TypeError, ValueError) as exc:
        raise PromotionAuthorityCorrupt("promotion_authority_invalid_row") from exc
    return state


def _state_digest(document: dict[str, Any]) -> str:
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable ASCII identifier")
    return value


def _nonnegative_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _positive_integer(value: Any, name: str) -> int:
    parsed = _nonnegative_integer(value, name)
    if parsed == 0:
        raise ValueError(f"{name} must be positive")
    return parsed


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: Any, name: str) -> str | None:
    return None if value is None else _digest(value, name)
