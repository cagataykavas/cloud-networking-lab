from __future__ import annotations

import hashlib
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Iterator

import pytest
import redis
from redis.exceptions import RedisError

from tools.redis_replay_guard import RedisReplayGuard, RedisReplayGuardPolicy
from tools.replay_guard import (
    ProxyHeaderReplay,
    ReplayGuardCapacityExceeded,
    ReplayGuardIntegrityError,
    ReplayGuardPolicyMismatch,
    ReplayGuardUnavailable,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


@pytest.fixture
def redis_url() -> str:
    value = os.getenv("REDIS_URL")
    if value is None:
        pytest.skip("REDIS_URL is required for Redis integration tests")
    return value


@pytest.fixture
def guard(redis_url: str) -> Iterator[RedisReplayGuard]:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    client.ping()
    policy = RedisReplayGuardPolicy(
        ttl_milliseconds=30_000,
        max_entries=64,
        namespace=f"test-{uuid.uuid4().hex}",
    )
    replay_guard = RedisReplayGuard(client, policy)
    try:
        yield replay_guard
    finally:
        client.delete(*replay_guard.keys)
        client.close()


def test_claim_is_shared_across_independent_clients(
    redis_url: str, guard: RedisReplayGuard
) -> None:
    second_client = redis.Redis.from_url(redis_url, socket_timeout=1)
    second = RedisReplayGuard(second_client, guard.policy)
    key = digest("request-1")
    try:
        guard.claim(key)
        with pytest.raises(ProxyHeaderReplay, match="proxy_header_replay"):
            second.claim(key)

        snapshot = second.snapshot()
        assert snapshot.active_entries == 1
        assert snapshot.claimed_total == 1
        assert snapshot.replay_rejected_total == 1
        assert snapshot.policy_sha256 == guard.policy.digest
    finally:
        second_client.close()


def test_redis_server_time_expires_claims_and_restores_capacity(
    redis_url: str,
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    policy = RedisReplayGuardPolicy(
        ttl_milliseconds=50,
        max_entries=1,
        namespace=f"expiry-{uuid.uuid4().hex}",
    )
    replay_guard = RedisReplayGuard(client, policy)
    try:
        replay_guard.claim(digest("request-1"))
        with pytest.raises(
            ReplayGuardCapacityExceeded, match="replay_guard_capacity_exceeded"
        ):
            replay_guard.claim(digest("request-2"))

        time.sleep(0.1)
        replay_guard.claim(digest("request-2"))
        snapshot = replay_guard.snapshot()
        assert snapshot.active_entries == 1
        assert snapshot.claimed_total == 2
        assert snapshot.capacity_rejected_total == 1
        assert snapshot.expired_total == 1
    finally:
        client.delete(*replay_guard.keys)
        client.close()


def test_snapshot_removes_expired_operation_tokens(redis_url: str) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    policy = RedisReplayGuardPolicy(
        ttl_milliseconds=50,
        max_entries=8,
        namespace=f"snapshot-expiry-{uuid.uuid4().hex}",
    )
    replay_guard = RedisReplayGuard(client, policy)
    key = digest("request-1")
    try:
        replay_guard.claim(key)
        time.sleep(0.1)

        snapshot = replay_guard.snapshot()

        assert snapshot.active_entries == 0
        assert snapshot.expired_total == 1
        assert not client.hexists(replay_guard.keys[0], f"claim:{key}")
    finally:
        client.delete(*replay_guard.keys)
        client.close()


def test_parallel_clients_allow_exactly_one_claim(
    redis_url: str, guard: RedisReplayGuard
) -> None:
    key = digest("same-request")

    def claim_once(_: int) -> str:
        client = redis.Redis.from_url(redis_url, socket_timeout=1)
        worker = RedisReplayGuard(client, guard.policy)
        try:
            worker.claim(key)
            return "accepted"
        except ProxyHeaderReplay:
            return "replayed"
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(claim_once, range(32)))

    assert outcomes.count("accepted") == 1
    assert outcomes.count("replayed") == 31
    snapshot = guard.snapshot()
    assert snapshot.active_entries == 1
    assert snapshot.claimed_total == 1
    assert snapshot.replay_rejected_total == 31


class _CommitThenLoseReplyClient:
    def __init__(self, client: redis.Redis) -> None:
        self._client = client
        self.claim_attempt_args: list[tuple[object, ...]] = []

    def register_script(self, script: str):
        registered = self._client.register_script(script)
        if "local operation_token = ARGV[5]" not in script:
            return registered

        def execute(*, keys: object, args: object) -> object:
            arguments = tuple(args)  # type: ignore[arg-type]
            self.claim_attempt_args.append(arguments)
            response = registered(keys=keys, args=args)
            if len(self.claim_attempt_args) == 1:
                raise RedisError("simulated lost reply after commit")
            return response

        return execute


def test_lost_commit_reply_retries_once_with_the_same_operation_token(
    redis_url: str,
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    policy = RedisReplayGuardPolicy(
        ttl_milliseconds=30_000,
        max_entries=8,
        namespace=f"ambiguous-{uuid.uuid4().hex}",
    )
    ambiguous_client = _CommitThenLoseReplyClient(client)
    replay_guard = RedisReplayGuard(ambiguous_client, policy)
    key = digest("request-with-lost-reply")
    try:
        replay_guard.claim(key)

        assert len(ambiguous_client.claim_attempt_args) == 2
        assert (
            ambiguous_client.claim_attempt_args[0][-1]
            == ambiguous_client.claim_attempt_args[1][-1]
        )
        with pytest.raises(ProxyHeaderReplay, match="proxy_header_replay"):
            RedisReplayGuard(client, policy).claim(key)

        snapshot = replay_guard.snapshot()
        assert snapshot.active_entries == 1
        assert snapshot.claimed_total == 1
        assert snapshot.replay_rejected_total == 1
    finally:
        client.delete(*replay_guard.keys)
        client.close()


def test_namespace_policy_mismatch_fails_closed(
    redis_url: str, guard: RedisReplayGuard
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    conflicting = RedisReplayGuard(
        client,
        replace(guard.policy, max_entries=guard.policy.max_entries + 1),
    )
    try:
        guard.claim(digest("request-1"))
        with pytest.raises(
            ReplayGuardPolicyMismatch, match="replay_guard_policy_mismatch"
        ):
            conflicting.claim(digest("request-2"))
        with pytest.raises(ReplayGuardPolicyMismatch):
            conflicting.snapshot()
    finally:
        client.close()


@pytest.mark.parametrize("missing_key_index", [0, 1])
def test_partial_namespace_loss_fails_closed(
    redis_url: str, guard: RedisReplayGuard, missing_key_index: int
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    try:
        guard.claim(digest("request-1"))
        client.delete(guard.keys[missing_key_index])

        with pytest.raises(
            ReplayGuardIntegrityError, match="replay_guard_integrity_error"
        ):
            guard.claim(digest("request-2"))
    finally:
        client.close()


@pytest.mark.parametrize("stored_token", [None, "bad-token"])
def test_missing_or_malformed_claim_operation_token_fails_closed(
    redis_url: str, guard: RedisReplayGuard, stored_token: str | None
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    key = digest("request-1")
    try:
        guard.claim(key)
        if stored_token is None:
            client.hdel(guard.keys[0], f"claim:{key}")
        else:
            client.hset(guard.keys[0], f"claim:{key}", stored_token)

        with pytest.raises(
            ReplayGuardIntegrityError, match="replay_guard_integrity_error"
        ):
            guard.claim(key)
    finally:
        client.close()


def test_missing_claim_member_with_remaining_token_fails_closed(
    redis_url: str, guard: RedisReplayGuard
) -> None:
    client = redis.Redis.from_url(redis_url, socket_timeout=1)
    key = digest("request-1")
    try:
        guard.claim(key)
        client.zrem(guard.keys[1], key)

        with pytest.raises(
            ReplayGuardIntegrityError, match="replay_guard_integrity_error"
        ):
            guard.claim(key)
    finally:
        client.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ttl_milliseconds", True),
        ("ttl_milliseconds", 0),
        ("ttl_milliseconds", 3_600_001),
        ("max_entries", True),
        ("max_entries", 0),
        ("max_entries", 1_000_001),
        ("ambiguous_retry_attempts", True),
        ("ambiguous_retry_attempts", -1),
        ("ambiguous_retry_attempts", 2),
        ("namespace", "bad namespace"),
        ("namespace", "{slot}"),
        ("key_prefix", "../escape"),
        ("key_prefix", "a" * 65),
    ],
)
def test_policy_rejects_unbounded_or_unsafe_values(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        RedisReplayGuardPolicy(**{field: value})  # type: ignore[arg-type]


def test_policy_digest_binds_backend_namespace_and_limits() -> None:
    policy = RedisReplayGuardPolicy(
        ttl_milliseconds=30_000,
        max_entries=8,
        namespace="listener-a",
        key_prefix="service-a",
    )

    assert (
        policy.digest
        == RedisReplayGuardPolicy(
            ttl_milliseconds=30_000,
            max_entries=8,
            namespace="listener-a",
            key_prefix="service-a",
        ).digest
    )
    assert policy.digest != replace(policy, ttl_milliseconds=30_001).digest
    assert policy.digest != replace(policy, namespace="listener-b").digest
    assert policy.digest != replace(policy, key_prefix="service-b").digest
    assert policy.digest != replace(policy, ambiguous_retry_attempts=0).digest


def test_exact_keys_share_one_cluster_hash_slot() -> None:
    replay_guard = RedisReplayGuard(
        _StaticClient([b"accepted"]),
        RedisReplayGuardPolicy(namespace="listener-a", key_prefix="service-a"),
    )

    assert replay_guard.keys == (
        "service-a:{listener-a}:state",
        "service-a:{listener-a}:claims",
    )


class _StaticClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls = 0

    def register_script(self, script: str):
        def execute(*, keys: object, args: object) -> object:
            self.calls += 1
            return self.response

        return execute


class _UnavailableClient:
    def __init__(self) -> None:
        self.calls = 0

    def register_script(self, script: str):
        def execute(*, keys: object, args: object) -> object:
            self.calls += 1
            raise RedisError("sensitive upstream detail")

        return execute


@pytest.mark.parametrize("response", [None, [], [b"unknown"], [b"\xff"]])
def test_malformed_script_responses_fail_closed(response: object) -> None:
    client = _StaticClient(response)
    replay_guard = RedisReplayGuard(client)  # type: ignore[arg-type]

    with pytest.raises(ReplayGuardUnavailable, match="replay_guard_unavailable"):
        replay_guard.claim(digest("request-1"))

    assert client.calls == 1


def test_redis_errors_are_normalized_without_leaking_details() -> None:
    client = _UnavailableClient()
    replay_guard = RedisReplayGuard(client)  # type: ignore[arg-type]

    with pytest.raises(ReplayGuardUnavailable) as caught:
        replay_guard.claim(digest("request-1"))

    assert str(caught.value) == "replay_guard_unavailable"
    assert "sensitive" not in str(caught.value)
    assert client.calls == 2


def test_ambiguous_retry_can_be_disabled() -> None:
    client = _UnavailableClient()
    replay_guard = RedisReplayGuard(
        client,  # type: ignore[arg-type]
        RedisReplayGuardPolicy(ambiguous_retry_attempts=0),
    )

    with pytest.raises(ReplayGuardUnavailable, match="replay_guard_unavailable"):
        replay_guard.claim(digest("request-1"))

    assert client.calls == 1
