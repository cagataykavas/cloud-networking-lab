from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from tools.redis_promotion_proof import (
    PromotionProofRejected,
    RedisPromotionPolicy,
    RedisPromotionProof,
    RedisReplicationSnapshot,
    execute_after_promotion_proof,
    load_promotion_proof_json,
    sign_promotion_proof,
    verify_promotion_proof,
)


SECRET = b"promotion-proof-test-key-material"
NOW = 1_800_000_000


def snapshot(
    *, role: str = "master", replid: str = "a" * 40, offset: int = 120
) -> RedisReplicationSnapshot:
    return RedisReplicationSnapshot.from_info(
        {"role": role, "master_replid": replid, "master_repl_offset": offset}
    )


def policy(**changes: object) -> RedisPromotionPolicy:
    values: dict[str, object] = {
        "cluster_id": "edge-replay",
        "candidate_id": "redis-b",
        "minimum_authority_epoch": 7,
        "keyring": {"rotation-3": SECRET},
        "max_proof_lifetime_seconds": 60,
        "max_future_skew_seconds": 5,
    }
    values.update(changes)
    return RedisPromotionPolicy(**values)


def proof(
    *,
    observed: RedisReplicationSnapshot | None = None,
    minimum_offset: int = 100,
    authority_epoch: int = 7,
    issued_at: int = NOW - 10,
    expires_at: int = NOW + 20,
    cluster_id: str = "edge-replay",
    candidate_id: str = "redis-b",
    key_id: str = "rotation-3",
    secret: bytes = SECRET,
) -> RedisPromotionProof:
    return sign_promotion_proof(
        cluster_id=cluster_id,
        candidate_id=candidate_id,
        authority_epoch=authority_epoch,
        minimum_replication_offset=minimum_offset,
        snapshot=observed or snapshot(),
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=key_id,
        secret=secret,
    )


def rejected_reason(
    value: RedisPromotionProof,
    *,
    configured: RedisPromotionPolicy | None = None,
    current: RedisReplicationSnapshot | None = None,
    now: int = NOW,
) -> str:
    with pytest.raises(PromotionProofRejected) as captured:
        verify_promotion_proof(
            value,
            configured or policy(),
            current or snapshot(),
            now=now,
        )
    return captured.value.reason


def test_accepts_fresh_signed_candidate_at_or_above_minimum() -> None:
    authorization = verify_promotion_proof(
        proof(), policy(), snapshot(offset=125), now=NOW
    )

    assert authorization.authority_epoch == 7
    assert authorization.minimum_replication_offset == 100
    assert authorization.observed_replication_offset == 120
    assert authorization.current_replication_offset == 125
    assert len(authorization.proof_sha256) == 64


def test_executes_replay_operation_only_after_authorization() -> None:
    calls: list[str] = []

    authorization, result = execute_after_promotion_proof(
        proof(),
        policy(),
        snapshot(),
        now=NOW,
        operation=lambda: calls.append("claim") or "accepted",
    )

    assert result == "accepted"
    assert calls == ["claim"]
    assert authorization.proof_sha256 == proof().digest


def test_stale_candidate_never_invokes_replay_operation() -> None:
    calls: list[str] = []
    stale = snapshot(offset=90)

    with pytest.raises(
        PromotionProofRejected, match="replication_offset_below_minimum"
    ):
        execute_after_promotion_proof(
            proof(observed=stale, minimum_offset=100),
            policy(),
            stale,
            now=NOW,
            operation=lambda: calls.append("claim"),
        )

    assert calls == []


def test_rejects_invalid_signature_before_semantic_claims() -> None:
    tampered = replace(proof(minimum_offset=100), minimum_replication_offset=1)

    assert rejected_reason(tampered) == "invalid_signature"


def test_rejects_unknown_key() -> None:
    assert rejected_reason(proof(key_id="retired", secret=b"r" * 32)) == "unknown_key"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (proof(cluster_id="other-cluster"), "cluster_mismatch"),
        (proof(candidate_id="redis-c"), "candidate_mismatch"),
        (proof(authority_epoch=6), "authority_epoch_too_old"),
        (proof(expires_at=NOW - 1), "expired"),
        (proof(issued_at=NOW + 6, expires_at=NOW + 20), "issued_in_future"),
        (proof(issued_at=NOW - 100, expires_at=NOW + 1), "lifetime_too_long"),
    ],
)
def test_rejects_wrong_scope_epoch_or_freshness(
    value: RedisPromotionProof, expected: str
) -> None:
    assert rejected_reason(value) == expected


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (snapshot(role="slave"), "candidate_not_promoted"),
        (snapshot(replid="b" * 40), "replication_id_mismatch"),
        (snapshot(offset=119), "replication_offset_regressed"),
    ],
)
def test_rejects_current_candidate_state_drift(
    current: RedisReplicationSnapshot, expected: str
) -> None:
    assert rejected_reason(proof(), current=current) == expected


def test_proof_contains_only_replication_id_commitment() -> None:
    raw_replid = "sensitive-replication-id"
    value = proof(observed=snapshot(replid=raw_replid))

    assert raw_replid not in str(value.document())
    assert value.replid_sha256 == hashlib.sha256(raw_replid.encode("ascii")).hexdigest()


def test_rejects_unknown_proof_fields_and_boolean_offsets() -> None:
    document = {**proof().document(), "unexpected": "field"}

    with pytest.raises(ValueError, match="unexpected"):
        RedisPromotionProof.from_document(document)
    with pytest.raises(ValueError, match="non-negative integer"):
        replace(proof(), minimum_replication_offset=True)


def test_strict_json_loader_rejects_duplicate_fields() -> None:
    encoded = '{"schema_version":1,"schema_version":1}'

    with pytest.raises(ValueError, match="duplicate field"):
        load_promotion_proof_json(encoded)


def test_proof_expires_at_exact_cutoff() -> None:
    assert rejected_reason(proof(expires_at=NOW)) == "expired"


def test_policy_copies_keyring_and_rejects_short_keys() -> None:
    keys = {"rotation-3": SECRET}
    configured = policy(keyring=keys)
    keys["rotation-3"] = b"changed" * 5

    assert verify_promotion_proof(proof(), configured, snapshot(), now=NOW)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        policy(keyring={"short": b"not-long-enough"})
