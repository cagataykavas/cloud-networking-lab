from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from redis.exceptions import RedisError

from tools.replay_guard import (
    MAX_REPLAY_ENTRIES,
    SHA256_RE,
    ProxyHeaderReplay,
    ReplayGuardCapacityExceeded,
    ReplayGuardIntegrityError,
    ReplayGuardPolicyMismatch,
    ReplayGuardSnapshot,
    ReplayGuardUnavailable,
)


NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_REPLAY_TTL_MILLISECONDS = 3_600_000


class RedisScript(Protocol):
    def __call__(
        self, *, keys: Sequence[str], args: Sequence[str | int]
    ) -> Sequence[bytes | str | int]: ...


class RedisClient(Protocol):
    def register_script(self, script: str) -> RedisScript: ...


@dataclass(frozen=True)
class RedisReplayGuardPolicy:
    ttl_milliseconds: int = 300_000
    max_entries: int = 65_536
    namespace: str = "default"
    key_prefix: str = "proxy-replay"
    ambiguous_retry_attempts: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.ttl_milliseconds, bool)
            or not isinstance(self.ttl_milliseconds, int)
            or not 1 <= self.ttl_milliseconds <= MAX_REPLAY_TTL_MILLISECONDS
        ):
            raise ValueError(
                "ttl_milliseconds must be an integer in "
                f"[1, {MAX_REPLAY_TTL_MILLISECONDS}]"
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
            isinstance(self.ambiguous_retry_attempts, bool)
            or not isinstance(self.ambiguous_retry_attempts, int)
            or self.ambiguous_retry_attempts not in (0, 1)
        ):
            raise ValueError("ambiguous_retry_attempts must be 0 or 1")
        for field_name, value in (
            ("namespace", self.namespace),
            ("key_prefix", self.key_prefix),
        ):
            if not isinstance(value, str) or NAMESPACE_RE.fullmatch(value) is None:
                raise ValueError(
                    f"{field_name} must be 1-64 ASCII letters, numbers, dots, "
                    "underscores or hyphens"
                )

    @property
    def digest(self) -> str:
        document = {
            "ambiguous_retry_attempts": self.ambiguous_retry_attempts,
            "backend": "redis-v2",
            "key_prefix": self.key_prefix,
            "max_entries": self.max_entries,
            "namespace": self.namespace,
            "ttl_milliseconds": self.ttl_milliseconds,
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        return hashlib.sha256(encoded).hexdigest()


_CLAIM_SCRIPT = r"""
local state_key = KEYS[1]
local claims_key = KEYS[2]
local expected_policy = ARGV[1]
local ttl_ms = tonumber(ARGV[2])
local max_entries = tonumber(ARGV[3])
local digest = ARGV[4]
local operation_token = ARGV[5]
local marker = 'policy:' .. expected_policy

if string.len(operation_token) ~= 64 or not string.match(operation_token, '^[0-9a-f]+$') then
    return {'integrity_error'}
end

local stored_policy = redis.call('HGET', state_key, 'policy_sha256')
if stored_policy and stored_policy ~= expected_policy then
    return {'policy_mismatch'}
end
if not stored_policy then
    if redis.call('EXISTS', claims_key) == 1 then
        return {'integrity_error'}
    end
    redis.call(
        'HSET', state_key,
        'policy_sha256', expected_policy,
        'claimed_total', 0,
        'replay_rejected_total', 0,
        'capacity_rejected_total', 0,
        'expired_total', 0
    )
    redis.call('ZADD', claims_key, 9007199254740991, marker)
elseif not redis.call('ZSCORE', claims_key, marker) then
    return {'integrity_error'}
end

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000) + math.floor(tonumber(server_time[2]) / 1000)
local expired_digests = redis.call('ZRANGEBYSCORE', claims_key, '-inf', now_ms)
local expired = #expired_digests
if expired > 0 then
    for _, expired_digest in ipairs(expired_digests) do
        redis.call('HDEL', state_key, 'claim:' .. expired_digest)
    end
    redis.call('ZREMRANGEBYSCORE', claims_key, '-inf', now_ms)
    redis.call('HINCRBY', state_key, 'expired_total', expired)
end
local stored_score = redis.call('ZSCORE', claims_key, digest)
local stored_token = redis.call('HGET', state_key, 'claim:' .. digest)
if stored_score then
    if not stored_token or string.len(stored_token) ~= 64 or not string.match(stored_token, '^[0-9a-f]+$') then
        return {'integrity_error'}
    end
    if stored_token == operation_token then
        return {'accepted_retry'}
    end
    redis.call('HINCRBY', state_key, 'replay_rejected_total', 1)
    return {'replayed'}
end
if stored_token then
    return {'integrity_error'}
end
local active = redis.call('ZCARD', claims_key) - 1
if active >= max_entries then
    redis.call('HINCRBY', state_key, 'capacity_rejected_total', 1)
    return {'capacity'}
end

redis.call('ZADD', claims_key, now_ms + ttl_ms, digest)
redis.call('HSET', state_key, 'claim:' .. digest, operation_token)
redis.call('HINCRBY', state_key, 'claimed_total', 1)
return {'accepted'}
"""


_SNAPSHOT_SCRIPT = r"""
local state_key = KEYS[1]
local claims_key = KEYS[2]
local expected_policy = ARGV[1]
local marker = 'policy:' .. expected_policy

local stored_policy = redis.call('HGET', state_key, 'policy_sha256')
if stored_policy and stored_policy ~= expected_policy then
    return {'policy_mismatch'}
end
if not stored_policy then
    if redis.call('EXISTS', claims_key) == 1 then
        return {'integrity_error'}
    end
    redis.call(
        'HSET', state_key,
        'policy_sha256', expected_policy,
        'claimed_total', 0,
        'replay_rejected_total', 0,
        'capacity_rejected_total', 0,
        'expired_total', 0
    )
    redis.call('ZADD', claims_key, 9007199254740991, marker)
elseif not redis.call('ZSCORE', claims_key, marker) then
    return {'integrity_error'}
end

local server_time = redis.call('TIME')
local now_ms = (tonumber(server_time[1]) * 1000) + math.floor(tonumber(server_time[2]) / 1000)
local expired_digests = redis.call('ZRANGEBYSCORE', claims_key, '-inf', now_ms)
local expired = #expired_digests
if expired > 0 then
    for _, expired_digest in ipairs(expired_digests) do
        redis.call('HDEL', state_key, 'claim:' .. expired_digest)
    end
    redis.call('ZREMRANGEBYSCORE', claims_key, '-inf', now_ms)
    redis.call('HINCRBY', state_key, 'expired_total', expired)
end
local counters = redis.call(
    'HMGET', state_key,
    'claimed_total',
    'replay_rejected_total',
    'capacity_rejected_total',
    'expired_total'
)
return {
    'snapshot',
    redis.call('ZCARD', claims_key) - 1,
    counters[1],
    counters[2],
    counters[3],
    counters[4]
}
"""


class RedisReplayGuard:
    """Fleet-wide replay claims serialized by one Redis primary.

    Both keys include the namespace as a Redis Cluster hash tag, so each Lua
    execution remains single-slot. Redis server time, rather than listener host
    clocks, is authoritative for expiry decisions.
    """

    def __init__(
        self,
        client: RedisClient,
        policy: RedisReplayGuardPolicy | None = None,
    ) -> None:
        self.policy = policy or RedisReplayGuardPolicy()
        slot = f"{{{self.policy.namespace}}}"
        self._keys = (
            f"{self.policy.key_prefix}:{slot}:state",
            f"{self.policy.key_prefix}:{slot}:claims",
        )
        self._claim_script = client.register_script(_CLAIM_SCRIPT)
        self._snapshot_script = client.register_script(_SNAPSHOT_SCRIPT)

    @property
    def keys(self) -> tuple[str, str]:
        """Return the two exact keys for provisioning and scoped cleanup."""
        return self._keys

    @staticmethod
    def _validate_digest(unique_id_sha256: str) -> None:
        if (
            not isinstance(unique_id_sha256, str)
            or SHA256_RE.fullmatch(unique_id_sha256) is None
        ):
            raise ValueError("unique_id_sha256 must be canonical lowercase SHA-256")

    @staticmethod
    def _code(response: Sequence[bytes | str | int]) -> str:
        if not isinstance(response, (list, tuple)) or not response:
            raise ReplayGuardUnavailable
        raw = response[0]
        if isinstance(raw, bytes):
            try:
                return raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ReplayGuardUnavailable from exc
        if not isinstance(raw, str):
            raise ReplayGuardUnavailable
        return raw

    def _execute(
        self,
        script: Callable[..., Sequence[bytes | str | int]],
        *args: str | int,
        redis_retries: int = 0,
    ) -> Sequence[bytes | str | int]:
        for attempt in range(redis_retries + 1):
            try:
                response = script(keys=self._keys, args=args)
                break
            except RedisError as exc:
                if attempt == redis_retries:
                    raise ReplayGuardUnavailable from exc
        if not isinstance(response, (list, tuple)):
            raise ReplayGuardUnavailable
        return response

    def claim(self, unique_id_sha256: str) -> None:
        self._validate_digest(unique_id_sha256)
        operation_token = secrets.token_hex(32)
        response = self._execute(
            self._claim_script,
            self.policy.digest,
            self.policy.ttl_milliseconds,
            self.policy.max_entries,
            unique_id_sha256,
            operation_token,
            redis_retries=self.policy.ambiguous_retry_attempts,
        )
        outcome = self._code(response)
        if outcome in ("accepted", "accepted_retry"):
            return
        if outcome == "replayed":
            raise ProxyHeaderReplay
        if outcome == "capacity":
            raise ReplayGuardCapacityExceeded
        if outcome == "policy_mismatch":
            raise ReplayGuardPolicyMismatch
        if outcome == "integrity_error":
            raise ReplayGuardIntegrityError
        raise ReplayGuardUnavailable

    def snapshot(self) -> ReplayGuardSnapshot:
        response = self._execute(self._snapshot_script, self.policy.digest)
        outcome = self._code(response)
        if outcome == "policy_mismatch":
            raise ReplayGuardPolicyMismatch
        if outcome == "integrity_error":
            raise ReplayGuardIntegrityError
        if outcome != "snapshot" or len(response) != 6:
            raise ReplayGuardUnavailable
        try:
            values = [int(value) for value in response[1:]]
        except (TypeError, ValueError) as exc:
            raise ReplayGuardUnavailable from exc
        return ReplayGuardSnapshot(
            active_entries=values[0],
            max_entries=self.policy.max_entries,
            claimed_total=values[1],
            replay_rejected_total=values[2],
            capacity_rejected_total=values[3],
            expired_total=values[4],
            policy_sha256=self.policy.digest,
        )
