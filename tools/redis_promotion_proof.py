"""Authenticated freshness proof for Redis replay-admission promotion."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeVar


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "cluster_id",
        "candidate_id",
        "authority_epoch",
        "minimum_replication_offset",
        "observed_replication_offset",
        "replid_sha256",
        "issued_at",
        "expires_at",
        "key_id",
        "signature",
    }
)
T = TypeVar("T")


class PromotionProofRejected(RuntimeError):
    """Fail-closed promotion proof decision with a stable, non-secret reason."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"redis_promotion_proof_rejected:{reason}")


@dataclass(frozen=True)
class RedisReplicationSnapshot:
    """Privacy-reduced Redis replication state observed on a candidate."""

    role: str
    replid_sha256: str
    offset: int

    @classmethod
    def from_info(cls, document: Mapping[str, Any]) -> RedisReplicationSnapshot:
        role = document.get("role")
        replid = document.get("master_replid")
        offset = document.get("master_repl_offset")
        if role not in {"master", "slave"}:
            raise ValueError("Redis INFO has an invalid replication role")
        if not isinstance(replid, str) or not replid or not replid.isascii():
            raise ValueError("Redis INFO has an invalid replication ID")
        parsed_offset = _nonnegative_integer(offset, "master_repl_offset")
        return cls(
            role=role,
            replid_sha256=hashlib.sha256(replid.encode("ascii")).hexdigest(),
            offset=parsed_offset,
        )

    def __post_init__(self) -> None:
        if self.role not in {"master", "slave"}:
            raise ValueError("role must be master or slave")
        if (
            not isinstance(self.replid_sha256, str)
            or SHA256_RE.fullmatch(self.replid_sha256) is None
        ):
            raise ValueError("replid_sha256 must be a lowercase SHA-256 digest")
        _nonnegative_integer(self.offset, "offset")


@dataclass(frozen=True)
class RedisPromotionPolicy:
    """Local trust boundary for one promoted replay-serving candidate."""

    cluster_id: str
    candidate_id: str
    minimum_authority_epoch: int
    keyring: Mapping[str, bytes]
    max_proof_lifetime_seconds: int = 60
    max_future_skew_seconds: int = 5

    def __post_init__(self) -> None:
        _identifier(self.cluster_id, "cluster_id")
        _identifier(self.candidate_id, "candidate_id")
        _nonnegative_integer(self.minimum_authority_epoch, "minimum_authority_epoch")
        if (
            isinstance(self.max_proof_lifetime_seconds, bool)
            or not isinstance(self.max_proof_lifetime_seconds, int)
            or not 1 <= self.max_proof_lifetime_seconds <= 300
        ):
            raise ValueError(
                "max_proof_lifetime_seconds must be an integer in [1, 300]"
            )
        if (
            isinstance(self.max_future_skew_seconds, bool)
            or not isinstance(self.max_future_skew_seconds, int)
            or not 0 <= self.max_future_skew_seconds <= 30
        ):
            raise ValueError("max_future_skew_seconds must be an integer in [0, 30]")
        if not isinstance(self.keyring, Mapping) or not self.keyring:
            raise ValueError("keyring must contain at least one verification key")
        copied: dict[str, bytes] = {}
        for key_id, secret in self.keyring.items():
            _identifier(key_id, "key_id")
            if not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError("promotion proof keys must contain at least 32 bytes")
            copied[key_id] = secret
        object.__setattr__(self, "keyring", MappingProxyType(copied))


@dataclass(frozen=True)
class RedisPromotionProof:
    schema_version: int
    cluster_id: str
    candidate_id: str
    authority_epoch: int
    minimum_replication_offset: int
    observed_replication_offset: int
    replid_sha256: str
    issued_at: int
    expires_at: int
    key_id: str
    signature: str

    @classmethod
    def from_document(cls, document: Any) -> RedisPromotionProof:
        if not isinstance(document, dict):
            raise ValueError("promotion proof must be a JSON object")
        if set(document) != PROOF_FIELDS:
            missing = sorted(PROOF_FIELDS.difference(document))
            unexpected = sorted(set(document).difference(PROOF_FIELDS))
            raise ValueError(
                f"promotion proof fields do not match schema; missing={missing}, "
                f"unexpected={unexpected}"
            )
        return cls(**document)

    def __post_init__(self) -> None:
        if self.schema_version != 1 or isinstance(self.schema_version, bool):
            raise ValueError("schema_version must be 1")
        _identifier(self.cluster_id, "cluster_id")
        _identifier(self.candidate_id, "candidate_id")
        _identifier(self.key_id, "key_id")
        _nonnegative_integer(self.authority_epoch, "authority_epoch")
        _nonnegative_integer(
            self.minimum_replication_offset, "minimum_replication_offset"
        )
        _nonnegative_integer(
            self.observed_replication_offset, "observed_replication_offset"
        )
        _nonnegative_integer(self.issued_at, "issued_at")
        _nonnegative_integer(self.expires_at, "expires_at")
        if (
            not isinstance(self.replid_sha256, str)
            or SHA256_RE.fullmatch(self.replid_sha256) is None
        ):
            raise ValueError("replid_sha256 must be a lowercase SHA-256 digest")
        if (
            not isinstance(self.signature, str)
            or SHA256_RE.fullmatch(self.signature) is None
        ):
            raise ValueError("signature must be a lowercase HMAC-SHA256 digest")

    def signed_payload(self) -> dict[str, str | int]:
        return {
            "authority_epoch": self.authority_epoch,
            "candidate_id": self.candidate_id,
            "cluster_id": self.cluster_id,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "minimum_replication_offset": self.minimum_replication_offset,
            "observed_replication_offset": self.observed_replication_offset,
            "replid_sha256": self.replid_sha256,
            "schema_version": self.schema_version,
        }

    def document(self) -> dict[str, str | int]:
        return {**self.signed_payload(), "signature": self.signature}

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.document())).hexdigest()


@dataclass(frozen=True)
class PromotionAuthorization:
    proof_sha256: str
    authority_epoch: int
    minimum_replication_offset: int
    observed_replication_offset: int
    current_replication_offset: int


def sign_promotion_proof(
    *,
    cluster_id: str,
    candidate_id: str,
    authority_epoch: int,
    minimum_replication_offset: int,
    snapshot: RedisReplicationSnapshot,
    issued_at: int,
    expires_at: int,
    key_id: str,
    secret: bytes,
) -> RedisPromotionProof:
    """Create a canonical HMAC proof without serializing the raw replication ID."""

    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("promotion proof secret must contain at least 32 bytes")
    unsigned = {
        "authority_epoch": authority_epoch,
        "candidate_id": candidate_id,
        "cluster_id": cluster_id,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "key_id": key_id,
        "minimum_replication_offset": minimum_replication_offset,
        "observed_replication_offset": snapshot.offset,
        "replid_sha256": snapshot.replid_sha256,
        "schema_version": 1,
    }
    signature = hmac.new(secret, _canonical(unsigned), hashlib.sha256).hexdigest()
    return RedisPromotionProof.from_document({**unsigned, "signature": signature})


def load_promotion_proof_json(text: str) -> RedisPromotionProof:
    """Parse proof JSON while rejecting duplicate object keys."""

    if not isinstance(text, str):
        raise TypeError("promotion proof JSON must be text")
    try:
        document = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("promotion proof is not valid JSON") from exc
    return RedisPromotionProof.from_document(document)


def verify_promotion_proof(
    proof: RedisPromotionProof,
    policy: RedisPromotionPolicy,
    current: RedisReplicationSnapshot,
    *,
    now: int,
) -> PromotionAuthorization:
    """Authorize replay traffic only for a fresh, sufficiently replicated candidate."""

    _nonnegative_integer(now, "now")
    secret = policy.keyring.get(proof.key_id)
    if secret is None:
        raise PromotionProofRejected("unknown_key")
    expected = hmac.new(
        secret, _canonical(proof.signed_payload()), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, proof.signature):
        raise PromotionProofRejected("invalid_signature")
    if proof.cluster_id != policy.cluster_id:
        raise PromotionProofRejected("cluster_mismatch")
    if proof.candidate_id != policy.candidate_id:
        raise PromotionProofRejected("candidate_mismatch")
    if proof.authority_epoch < policy.minimum_authority_epoch:
        raise PromotionProofRejected("authority_epoch_too_old")
    if proof.expires_at <= proof.issued_at:
        raise PromotionProofRejected("invalid_lifetime")
    if proof.expires_at - proof.issued_at > policy.max_proof_lifetime_seconds:
        raise PromotionProofRejected("lifetime_too_long")
    if proof.issued_at > now + policy.max_future_skew_seconds:
        raise PromotionProofRejected("issued_in_future")
    if proof.expires_at <= now:
        raise PromotionProofRejected("expired")
    if proof.observed_replication_offset < proof.minimum_replication_offset:
        raise PromotionProofRejected("replication_offset_below_minimum")
    if current.role != "master":
        raise PromotionProofRejected("candidate_not_promoted")
    if current.replid_sha256 != proof.replid_sha256:
        raise PromotionProofRejected("replication_id_mismatch")
    if current.offset < proof.observed_replication_offset:
        raise PromotionProofRejected("replication_offset_regressed")
    return PromotionAuthorization(
        proof_sha256=proof.digest,
        authority_epoch=proof.authority_epoch,
        minimum_replication_offset=proof.minimum_replication_offset,
        observed_replication_offset=proof.observed_replication_offset,
        current_replication_offset=current.offset,
    )


def execute_after_promotion_proof(
    proof: RedisPromotionProof,
    policy: RedisPromotionPolicy,
    current: RedisReplicationSnapshot,
    *,
    now: int,
    operation: Callable[[], T],
) -> tuple[PromotionAuthorization, T]:
    """Run a replay-serving operation only after promotion authorization succeeds."""

    authorization = verify_promotion_proof(proof, policy, current, now=now)
    return authorization, operation()


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"promotion proof contains duplicate field: {key}")
        document[key] = value
    return document


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable ASCII identifier")
    return value


def _nonnegative_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value
