from __future__ import annotations

import hashlib
import json
import sqlite3
import shutil
from pathlib import Path

import pytest

from tools.redis_promotion_authority import (
    PromotionAuthorityConflict,
    PromotionAuthorityCorrupt,
    PromotionAuthorityUnavailable,
    SQLitePromotionAuthority,
)
from tools.redis_promotion_proof import (
    RedisPromotionPolicy,
    RedisReplicationSnapshot,
    verify_promotion_proof,
)


SECRET = b"promotion-authority-test-key-material"
REPLID = "a" * 40
NOW = 1_800_000_000


def snapshot(
    *, role: str = "master", replid: str = REPLID, offset: int = 120
) -> RedisReplicationSnapshot:
    return RedisReplicationSnapshot.from_info(
        {"role": role, "master_replid": replid, "master_repl_offset": offset}
    )


def authority(tmp_path: Path) -> SQLitePromotionAuthority:
    return SQLitePromotionAuthority(tmp_path / "authority.db", "edge-replay")


def advance(
    ledger: SQLitePromotionAuthority,
    *,
    epoch: int = 7,
    candidate: str = "redis-b",
    minimum_offset: int = 100,
    current: RedisReplicationSnapshot | None = None,
    observed_at: int = NOW,
    expected: str | None = None,
    source_sha256: str | None = None,
):
    return ledger.advance(
        authority_epoch=epoch,
        candidate_id=candidate,
        minimum_replication_offset=minimum_offset,
        snapshot=current or snapshot(),
        source_sha256=source_sha256,
        observed_at=observed_at,
        expected_state_sha256=expected,
    )


def test_persists_election_and_issues_verifiable_proof(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    state = advance(SQLitePromotionAuthority(database, "edge-replay"))
    restarted = SQLitePromotionAuthority(database, "edge-replay")

    proof = restarted.issue_proof(
        expected_state_sha256=state.state_sha256,
        candidate_id="redis-b",
        snapshot=snapshot(offset=125),
        issued_at=NOW,
        expires_at=NOW + 30,
        key_id="rotation-4",
        secret=SECRET,
    )
    authorization = verify_promotion_proof(
        proof,
        RedisPromotionPolicy(
            cluster_id="edge-replay",
            candidate_id="redis-b",
            minimum_authority_epoch=7,
            keyring={"rotation-4": SECRET},
        ),
        snapshot(offset=125),
        now=NOW,
    )

    assert restarted.snapshot() == state
    assert authorization.authority_epoch == 7
    assert authorization.minimum_replication_offset == 100


def test_key_rotation_overlap_and_retirement_are_explicit(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    state = advance(ledger)
    old_secret = b"old-promotion-authority-key-0001"
    new_secret = b"new-promotion-authority-key-0002"
    old_proof = ledger.issue_proof(
        expected_state_sha256=state.state_sha256,
        candidate_id="redis-b",
        snapshot=snapshot(),
        issued_at=NOW,
        expires_at=NOW + 30,
        key_id="rotation-4",
        secret=old_secret,
    )
    new_proof = ledger.issue_proof(
        expected_state_sha256=state.state_sha256,
        candidate_id="redis-b",
        snapshot=snapshot(),
        issued_at=NOW,
        expires_at=NOW + 30,
        key_id="rotation-5",
        secret=new_secret,
    )
    overlap = RedisPromotionPolicy(
        cluster_id="edge-replay",
        candidate_id="redis-b",
        minimum_authority_epoch=7,
        keyring={"rotation-4": old_secret, "rotation-5": new_secret},
    )

    assert verify_promotion_proof(old_proof, overlap, snapshot(), now=NOW)
    assert verify_promotion_proof(new_proof, overlap, snapshot(), now=NOW)
    retired = RedisPromotionPolicy(
        cluster_id="edge-replay",
        candidate_id="redis-b",
        minimum_authority_epoch=7,
        keyring={"rotation-5": new_secret},
    )
    with pytest.raises(RuntimeError, match="unknown_key"):
        verify_promotion_proof(old_proof, retired, snapshot(), now=NOW)


def test_appends_hash_chained_monotonic_revisions(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    first = advance(ledger)
    second = advance(
        ledger,
        epoch=8,
        candidate="redis-c",
        minimum_offset=120,
        current=snapshot(replid="b" * 40, offset=130),
        observed_at=NOW + 5,
        expected=first.state_sha256,
    )

    assert second.revision == 2
    assert second.previous_state_sha256 == first.state_sha256
    assert second.state_sha256 != first.state_sha256


def test_exact_advance_retry_is_idempotent(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    first = advance(ledger)

    retried = advance(ledger, expected=first.state_sha256)

    assert retried == first
    with sqlite3.connect(ledger.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM promotion_authority_revisions"
        ).fetchone() == (1,)


def test_source_commitment_is_hash_bound_and_idempotent(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    source = "b" * 64
    first = advance(ledger, source_sha256=source)

    retried = advance(
        ledger,
        expected=first.state_sha256,
        source_sha256=source,
    )

    assert retried == first
    assert first.schema_version == 2
    assert first.source_sha256 == source
    assert first.payload()["source_sha256"] == source


def test_version_two_chain_cannot_drop_source_commitment(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    first = advance(ledger, source_sha256="b" * 64)

    with pytest.raises(PromotionAuthorityConflict, match="source_required"):
        advance(
            ledger,
            epoch=8,
            observed_at=NOW + 1,
            expected=first.state_sha256,
        )


def test_stale_writer_cannot_append_or_issue_proof(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    first = advance(ledger)
    second = advance(
        ledger,
        epoch=8,
        minimum_offset=110,
        observed_at=NOW + 1,
        expected=first.state_sha256,
    )

    with pytest.raises(
        PromotionAuthorityConflict, match="promotion_authority_head_mismatch"
    ):
        advance(
            ledger,
            epoch=9,
            minimum_offset=120,
            observed_at=NOW + 2,
            expected=first.state_sha256,
        )
    with pytest.raises(PromotionAuthorityConflict, match="head_mismatch"):
        ledger.issue_proof(
            expected_state_sha256=first.state_sha256,
            candidate_id="redis-b",
            snapshot=snapshot(),
            issued_at=NOW,
            expires_at=NOW + 30,
            key_id="rotation-4",
            secret=SECRET,
        )
    assert ledger.snapshot() == second


def test_external_head_detects_database_restore_rollback(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    backup = tmp_path / "authority-backup.db"
    ledger = SQLitePromotionAuthority(database, "edge-replay")
    first = advance(ledger)
    shutil.copy2(database, backup)
    second = advance(
        ledger,
        epoch=8,
        minimum_offset=110,
        observed_at=NOW + 1,
        expected=first.state_sha256,
    )
    shutil.copy2(backup, database)
    restored = SQLitePromotionAuthority(database, "edge-replay")

    with pytest.raises(PromotionAuthorityConflict, match="head_mismatch"):
        restored.issue_proof(
            expected_state_sha256=second.state_sha256,
            candidate_id="redis-b",
            snapshot=snapshot(),
            issued_at=NOW,
            expires_at=NOW + 30,
            key_id="rotation-4",
            secret=SECRET,
        )
    assert restored.snapshot() == first


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"epoch": 7, "observed_at": NOW + 1}, "epoch_not_monotonic"),
        (
            {"epoch": 8, "minimum_offset": 99, "observed_at": NOW + 1},
            "offset_regressed",
        ),
        ({"epoch": 8, "observed_at": NOW - 1}, "time_regressed"),
    ],
)
def test_rejects_epoch_offset_and_time_rollback(
    tmp_path: Path, changes: dict[str, int], reason: str
) -> None:
    ledger = authority(tmp_path)
    first = advance(ledger)

    with pytest.raises(PromotionAuthorityConflict, match=reason):
        advance(ledger, expected=first.state_sha256, **changes)


@pytest.mark.parametrize(
    ("candidate", "current", "reason"),
    [
        ("redis-c", snapshot(), "candidate_mismatch"),
        ("redis-b", snapshot(role="slave"), "candidate_not_master"),
        ("redis-b", snapshot(replid="b" * 40), "replid_mismatch"),
        ("redis-b", snapshot(offset=99), "offset_below_minimum"),
    ],
)
def test_proof_issuance_requires_exact_election_state(
    tmp_path: Path,
    candidate: str,
    current: RedisReplicationSnapshot,
    reason: str,
) -> None:
    ledger = authority(tmp_path)
    state = advance(ledger)

    with pytest.raises(PromotionAuthorityConflict, match=reason):
        ledger.issue_proof(
            expected_state_sha256=state.state_sha256,
            candidate_id=candidate,
            snapshot=current,
            issued_at=NOW,
            expires_at=NOW + 30,
            key_id="rotation-4",
            secret=SECRET,
        )


def test_candidate_below_floor_never_enters_ledger(tmp_path: Path) -> None:
    ledger = authority(tmp_path)

    with pytest.raises(ValueError, match="below the authority minimum"):
        advance(ledger, minimum_offset=121, current=snapshot(offset=120))

    assert ledger.snapshot() is None


def test_database_is_private_and_revisions_are_immutable(tmp_path: Path) -> None:
    ledger = authority(tmp_path)
    advance(ledger)

    assert ledger.database_path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(ledger.database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE promotion_authority_revisions SET authority_epoch = 8"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM promotion_authority_revisions")


def test_reopen_detects_hash_chain_tampering(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    ledger = SQLitePromotionAuthority(database, "edge-replay")
    state = advance(ledger)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER promotion_authority_no_update")
        connection.execute(
            """
            UPDATE promotion_authority_revisions
            SET minimum_replication_offset = 99
            WHERE state_sha256 = ?
            """,
            (state.state_sha256,),
        )

    with pytest.raises(PromotionAuthorityCorrupt, match="digest_mismatch"):
        SQLitePromotionAuthority(database, "edge-replay")


def test_reopen_detects_source_commitment_tampering(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    ledger = SQLitePromotionAuthority(database, "edge-replay")
    state = advance(ledger, source_sha256="b" * 64)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER promotion_authority_no_update")
        connection.execute(
            """
            UPDATE promotion_authority_revisions
            SET source_sha256 = ?
            WHERE state_sha256 = ?
            """,
            ("c" * 64, state.state_sha256),
        )

    with pytest.raises(PromotionAuthorityCorrupt, match="digest_mismatch"):
        SQLitePromotionAuthority(database, "edge-replay")


def test_migrates_legacy_schema_before_binding_source(tmp_path: Path) -> None:
    database = tmp_path / "legacy-authority.db"
    legacy_payload = {
        "authority_epoch": 7,
        "candidate_id": "redis-b",
        "cluster_id": "edge-replay",
        "minimum_replication_offset": 100,
        "observed_at": NOW,
        "previous_state_sha256": None,
        "replid_sha256": snapshot().replid_sha256,
        "revision": 1,
        "schema_version": 1,
    }
    legacy_digest = hashlib.sha256(
        json.dumps(
            legacy_payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE promotion_authority_revisions (
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
            INSERT INTO promotion_authority_revisions (
                cluster_id, revision, authority_epoch, candidate_id,
                minimum_replication_offset, replid_sha256, observed_at,
                previous_state_sha256, state_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "edge-replay",
                1,
                7,
                "redis-b",
                100,
                snapshot().replid_sha256,
                NOW,
                None,
                legacy_digest,
            ),
        )

    ledger = SQLitePromotionAuthority(database, "edge-replay")
    legacy = ledger.snapshot()
    state = advance(
        ledger,
        epoch=8,
        minimum_offset=110,
        observed_at=NOW + 1,
        expected=legacy_digest,
        source_sha256="b" * 64,
    )

    assert legacy is not None
    assert legacy.schema_version == 1
    assert legacy.source_sha256 is None
    assert legacy.state_sha256 == legacy_digest
    assert state.schema_version == 2
    assert state.source_sha256 == "b" * 64
    assert state.previous_state_sha256 == legacy_digest
    with sqlite3.connect(database) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(promotion_authority_revisions)"
            )
        }
    assert {"schema_version", "source_sha256"}.issubset(columns)


def test_separate_clusters_share_database_without_state_leakage(tmp_path: Path) -> None:
    database = tmp_path / "authority.db"
    cluster_a = SQLitePromotionAuthority(database, "cluster-a")
    cluster_b = SQLitePromotionAuthority(database, "cluster-b")

    first_a = advance(cluster_a)
    first_b = advance(cluster_b, epoch=1, candidate="redis-c")

    assert cluster_a.snapshot() == first_a
    assert cluster_b.snapshot() == first_b


def test_rejects_memory_symlink_and_locked_database(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=":memory:"):
        SQLitePromotionAuthority(":memory:", "edge-replay")
    target = tmp_path / "target.db"
    target.touch()
    link = tmp_path / "link.db"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        SQLitePromotionAuthority(link, "edge-replay")

    ledger = SQLitePromotionAuthority(
        tmp_path / "locked.db", "edge-replay", busy_timeout_seconds=0.01
    )
    with sqlite3.connect(ledger.database_path, isolation_level=None) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(PromotionAuthorityUnavailable):
            advance(ledger)
