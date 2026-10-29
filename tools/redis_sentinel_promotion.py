"""Fail-closed Redis Sentinel promotion observations for the authority ledger."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from tools.redis_promotion_authority import (
    PromotionAuthorityState,
    SQLitePromotionAuthority,
)
from tools.redis_promotion_proof import (
    IDENTIFIER_RE,
    RedisReplicationSnapshot,
)


RUN_ID_RE = re.compile(r"^[0-9a-f]{40}$")
UNSAFE_FLAGS = frozenset(
    {"s_down", "o_down", "disconnected", "failover_in_progress"}
)
REQUIRED_FIELDS = frozenset(
    {
        "name",
        "ip",
        "port",
        "runid",
        "flags",
        "last-ok-ping-reply",
        "info-refresh",
        "role-reported",
        "config-epoch",
        "num-other-sentinels",
        "quorum",
    }
)


class SentinelPromotionError(RuntimeError):
    """Base class for stable, fail-closed Sentinel adapter errors."""


class SentinelPromotionRejected(SentinelPromotionError):
    """Live Sentinel or candidate state does not satisfy promotion policy."""


class SentinelPromotionUnavailable(SentinelPromotionError):
    """A live Sentinel or candidate observation could not be completed."""


class SentinelClient(Protocol):
    def execute_command(self, *args: str) -> Any:
        """Execute one synchronous Redis command."""


class CandidateClient(Protocol):
    def info(self, section: str) -> Mapping[str, Any]:
        """Read one synchronous Redis INFO section."""


@dataclass(frozen=True)
class SentinelPromotionPolicy:
    """Expected Sentinel master and freshness boundary for one failover group."""

    master_name: str
    candidate_host: str
    candidate_port: int
    minimum_config_epoch: int = 1
    max_info_age_ms: int = 5_000
    max_ping_age_ms: int = 5_000

    def __post_init__(self) -> None:
        _identifier(self.master_name, "master_name")
        if (
            not isinstance(self.candidate_host, str)
            or not self.candidate_host
            or len(self.candidate_host) > 253
            or not self.candidate_host.isascii()
            or any(character.isspace() for character in self.candidate_host)
        ):
            raise ValueError("candidate_host must be a non-empty ASCII host")
        _bounded_integer(self.candidate_port, "candidate_port", 1, 65_535)
        _bounded_integer(
            self.minimum_config_epoch,
            "minimum_config_epoch",
            1,
            2**63 - 1,
        )
        _bounded_integer(self.max_info_age_ms, "max_info_age_ms", 0, 60_000)
        _bounded_integer(self.max_ping_age_ms, "max_ping_age_ms", 0, 60_000)


@dataclass(frozen=True)
class SentinelPromotionDecision:
    """Privacy-reduced, policy-validated input to the durable authority ledger."""

    candidate_id: str
    authority_epoch: int
    minimum_replication_offset: int
    snapshot: RedisReplicationSnapshot
    observed_at: int
    source_sha256: str

    def advance(
        self,
        authority: SQLitePromotionAuthority,
        *,
        expected_state_sha256: str | None,
    ) -> PromotionAuthorityState:
        """Append this observed election decision under the ledger CAS token."""

        return authority.advance(
            authority_epoch=self.authority_epoch,
            candidate_id=self.candidate_id,
            minimum_replication_offset=self.minimum_replication_offset,
            snapshot=self.snapshot,
            observed_at=self.observed_at,
            expected_state_sha256=expected_state_sha256,
        )


def observe_sentinel_promotion(
    sentinel: SentinelClient,
    candidate: CandidateClient,
    policy: SentinelPromotionPolicy,
    *,
    minimum_replication_offset: int,
    observed_at: int,
) -> SentinelPromotionDecision:
    """Query Sentinel and the promoted Redis candidate, then validate both."""

    try:
        master_reply = sentinel.execute_command(
            "SENTINEL", "MASTER", policy.master_name
        )
    except Exception as exc:
        raise SentinelPromotionUnavailable(
            "sentinel_master_observation_unavailable"
        ) from exc
    try:
        candidate_info = candidate.info("replication")
    except Exception as exc:
        raise SentinelPromotionUnavailable(
            "candidate_replication_observation_unavailable"
        ) from exc
    return derive_sentinel_promotion(
        master_reply,
        candidate_info,
        policy,
        minimum_replication_offset=minimum_replication_offset,
        observed_at=observed_at,
    )


def derive_sentinel_promotion(
    master_reply: Mapping[Any, Any] | Sequence[Any],
    candidate_info: Mapping[str, Any],
    policy: SentinelPromotionPolicy,
    *,
    minimum_replication_offset: int,
    observed_at: int,
) -> SentinelPromotionDecision:
    """Validate one Sentinel election view and candidate replication snapshot."""

    offset_floor = _bounded_integer(
        minimum_replication_offset,
        "minimum_replication_offset",
        0,
        2**63 - 1,
    )
    timestamp = _bounded_integer(observed_at, "observed_at", 0, 2**63 - 1)
    document = _sentinel_document(master_reply)
    missing = sorted(REQUIRED_FIELDS.difference(document))
    if missing:
        raise SentinelPromotionRejected(
            f"sentinel_master_missing_fields:{','.join(missing)}"
        )

    if document["name"] != policy.master_name:
        raise SentinelPromotionRejected("sentinel_master_name_mismatch")
    if (
        document["ip"] != policy.candidate_host
        or _reply_integer(document, "port", 1, 65_535)
        != policy.candidate_port
    ):
        raise SentinelPromotionRejected("sentinel_candidate_endpoint_mismatch")

    candidate_id = document["runid"]
    if RUN_ID_RE.fullmatch(candidate_id) is None:
        raise SentinelPromotionRejected("sentinel_candidate_runid_invalid")

    flags = frozenset(document["flags"].split(","))
    if "master" not in flags or "" in flags:
        raise SentinelPromotionRejected("sentinel_candidate_not_master")
    unsafe = sorted(flags.intersection(UNSAFE_FLAGS))
    if unsafe:
        raise SentinelPromotionRejected(
            f"sentinel_candidate_unsafe:{','.join(unsafe)}"
        )
    if document["role-reported"] != "master":
        raise SentinelPromotionRejected("sentinel_role_not_master")

    epoch = _reply_integer(document, "config-epoch", 0, 2**63 - 1)
    if epoch < policy.minimum_config_epoch:
        raise SentinelPromotionRejected("sentinel_config_epoch_too_old")
    info_age = _reply_integer(document, "info-refresh", 0, 2**63 - 1)
    if info_age > policy.max_info_age_ms:
        raise SentinelPromotionRejected("sentinel_info_stale")
    ping_age = _reply_integer(
        document, "last-ok-ping-reply", 0, 2**63 - 1
    )
    if ping_age > policy.max_ping_age_ms:
        raise SentinelPromotionRejected("sentinel_ping_stale")

    other_sentinels = _reply_integer(
        document, "num-other-sentinels", 0, 1_000_000
    )
    quorum = _reply_integer(document, "quorum", 1, 1_000_000)
    if other_sentinels + 1 < quorum:
        raise SentinelPromotionRejected("sentinel_quorum_unreachable")

    if not isinstance(candidate_info, Mapping):
        raise SentinelPromotionRejected("candidate_info_invalid")
    try:
        snapshot = RedisReplicationSnapshot.from_info(candidate_info)
    except (TypeError, ValueError) as exc:
        raise SentinelPromotionRejected("candidate_info_invalid") from exc
    if snapshot.role != "master":
        raise SentinelPromotionRejected("candidate_role_not_master")
    if snapshot.offset < offset_floor:
        raise SentinelPromotionRejected("candidate_offset_below_floor")

    source = {
        "candidate_id": candidate_id,
        "config_epoch": epoch,
        "endpoint_sha256": hashlib.sha256(
            f"{policy.candidate_host}:{policy.candidate_port}".encode("ascii")
        ).hexdigest(),
        "info_age_ms": info_age,
        "master_name": policy.master_name,
        "observed_at": timestamp,
        "ping_age_ms": ping_age,
        "quorum": quorum,
        "schema_version": 1,
        "sentinels_seen": other_sentinels + 1,
    }
    return SentinelPromotionDecision(
        candidate_id=candidate_id,
        authority_epoch=epoch,
        minimum_replication_offset=offset_floor,
        snapshot=snapshot,
        observed_at=timestamp,
        source_sha256=hashlib.sha256(_canonical(source)).hexdigest(),
    )


def _sentinel_document(
    reply: Mapping[Any, Any] | Sequence[Any],
) -> dict[str, str]:
    if isinstance(reply, Mapping):
        pairs = list(reply.items())
    elif isinstance(reply, Sequence) and not isinstance(
        reply, (str, bytes, bytearray)
    ):
        if len(reply) % 2:
            raise SentinelPromotionRejected("sentinel_master_reply_odd_length")
        pairs = list(zip(reply[::2], reply[1::2]))
    else:
        raise SentinelPromotionRejected("sentinel_master_reply_invalid")

    document: dict[str, str] = {}
    for raw_key, raw_value in pairs:
        key = _reply_text(raw_key)
        value = _reply_text(raw_value)
        if key in document:
            raise SentinelPromotionRejected(
                f"sentinel_master_duplicate_field:{key}"
            )
        document[key] = value
    return document


def _reply_text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SentinelPromotionRejected(
                "sentinel_master_reply_non_ascii"
            ) from exc
    if isinstance(value, str) and value.isascii():
        return value
    raise SentinelPromotionRejected("sentinel_master_reply_non_text")


def _reply_integer(
    document: Mapping[str, str],
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    value = document[field]
    if not value.isdigit():
        raise SentinelPromotionRejected(
            f"sentinel_master_invalid_integer:{field}"
        )
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise SentinelPromotionRejected(
            f"sentinel_master_integer_out_of_range:{field}"
        )
    return parsed


def _bounded_integer(
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable ASCII identifier")
    return value


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
