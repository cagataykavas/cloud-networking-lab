#!/usr/bin/env python3
"""Exercise a real three-Sentinel election before admitting replay traffic."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import redis
from redis.exceptions import RedisError

from tools.docker_egress_partition import DockerEgressPartition
from tools.redis_promotion_authority import (
    PromotionAuthorityConflict,
    SQLitePromotionAuthority,
)
from tools.redis_promotion_proof import (
    RedisPromotionPolicy,
    RedisReplicationSnapshot,
    execute_after_promotion_proof,
)
from tools.redis_replay_guard import RedisReplayGuard, RedisReplayGuardPolicy
from tools.redis_sentinel_promotion import (
    SentinelPromotionDecision,
    SentinelPromotionError,
    SentinelPromotionPolicy,
    observe_sentinel_consensus,
)


def validate_election_endpoints(
    primary_url: str,
    candidate_url: str,
    sentinel_urls: list[str],
) -> None:
    """Require five distinct, credential-free loopback endpoints."""

    if not isinstance(sentinel_urls, list) or len(sentinel_urls) != 3:
        raise ValueError("exactly three Sentinel URLs are required")
    values = [primary_url, candidate_url, *sentinel_urls]
    endpoints = [
        _loopback_endpoint(value, label)
        for label, value in zip(
            ("primary", "candidate", "sentinel-a", "sentinel-b", "sentinel-c"),
            values,
            strict=True,
        )
    ]
    if len(set(endpoints)) != len(endpoints):
        raise ValueError("election endpoints must be distinct")


def run_election_drill(
    primary_url: str,
    candidate_url: str,
    sentinel_urls: list[str],
    *,
    candidate_advertised_host: str,
    candidate_advertised_port: int,
    partition: DockerEgressPartition,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Partition one live primary, corroborate promotion, heal, and fence it."""

    validate_election_endpoints(primary_url, candidate_url, sentinel_urls)
    if not 5.0 <= timeout_seconds <= 60.0:
        raise ValueError("timeout_seconds must be in [5, 60]")
    policy = SentinelPromotionPolicy(
        master_name="replay-primary",
        candidate_host=candidate_advertised_host,
        candidate_port=candidate_advertised_port,
        minimum_config_epoch=1,
        max_info_age_ms=5_000,
        max_ping_age_ms=5_000,
    )
    connection_options = {
        "socket_connect_timeout": 1,
        "socket_timeout": 1,
    }
    primary = redis.Redis.from_url(primary_url, **connection_options)
    candidate = redis.Redis.from_url(candidate_url, **connection_options)
    sentinels = {
        f"sentinel-{label}": redis.Redis.from_url(url, **connection_options)
        for label, url in zip("abc", sentinel_urls, strict=True)
    }
    run_id = uuid.uuid4().hex
    marker_key = f"redis-sentinel-election:{run_id}:sync"
    split_brain_key = f"redis-sentinel-election:{run_id}:isolated-write"
    claim_sha256 = hashlib.sha256(f"{run_id}:claim".encode("ascii")).hexdigest()

    try:
        _wait_for(
            lambda: _is_synced_replica(primary, candidate),
            timeout_seconds,
            "candidate did not become a synchronized replica",
        )
        primary.set(marker_key, "ready", ex=120)
        if primary.wait(1, 1_000) < 1:
            raise RuntimeError("synchronization marker was not acknowledged")
        _wait_for(
            lambda: candidate.get(marker_key) == b"ready",
            timeout_seconds,
            "candidate did not observe the synchronization marker",
        )
        offset_floor = _integer_field(primary.info("replication"), "master_repl_offset")
        _wait_for(
            lambda: _replication_offset(candidate) >= offset_floor,
            timeout_seconds,
            "candidate did not reach the reviewed replication offset",
        )
        with tempfile.TemporaryDirectory() as directory:
            authority = SQLitePromotionAuthority(
                Path(directory) / "authority.db",
                "redis-sentinel-election",
            )
            former_primary_id = _redis_run_id(primary)
            former_snapshot = RedisReplicationSnapshot.from_info(
                primary.info("replication")
            )
            former_state = authority.advance(
                authority_epoch=0,
                candidate_id=former_primary_id,
                minimum_replication_offset=offset_floor,
                snapshot=former_snapshot,
                source_sha256=hashlib.sha256(
                    f"pre-partition:{former_primary_id}".encode("ascii")
                ).hexdigest(),
                observed_at=int(time.time()),
                expected_state_sha256=None,
            )

            partition.isolate()
            if not _is_reachable_master(primary):
                raise RuntimeError(
                    "one-way partition did not preserve former-primary client access"
                )

            decision = _wait_for_consensus(
                sentinels,
                candidate,
                policy,
                minimum_replication_offset=offset_floor,
                timeout_seconds=timeout_seconds,
            )
            if not _is_reachable_master(primary):
                raise RuntimeError("former primary was not alive behind the partition")
            primary.set(split_brain_key, "former-primary", ex=120)
            if candidate.get(split_brain_key) is not None:
                raise RuntimeError(
                    "isolated former-primary write reached the promoted candidate"
                )

            state = decision.advance(
                authority,
                expected_state_sha256=former_state.state_sha256,
            )
            secret = secrets.token_bytes(32)
            issued_at = int(time.time())
            proof = authority.issue_proof(
                expected_state_sha256=state.state_sha256,
                candidate_id=decision.candidate_id,
                snapshot=decision.snapshot,
                issued_at=issued_at,
                expires_at=issued_at + 30,
                key_id="drill-ephemeral",
                secret=secret,
            )
            current = RedisReplicationSnapshot.from_info(candidate.info("replication"))
            fenced_state, (authorization, _) = authority.execute_under_epoch_fence(
                expected_state_sha256=state.state_sha256,
                candidate_id=decision.candidate_id,
                operation=lambda: execute_after_promotion_proof(
                    proof,
                    RedisPromotionPolicy(
                        cluster_id="redis-sentinel-election",
                        candidate_id=decision.candidate_id,
                        minimum_authority_epoch=state.authority_epoch,
                        keyring={"drill-ephemeral": secret},
                    ),
                    current,
                    now=issued_at,
                    operation=lambda: RedisReplayGuard(
                        candidate,
                        RedisReplayGuardPolicy(
                            namespace=f"sentinel-election-{run_id}",
                            required_replica_acks=0,
                        ),
                    ).claim(claim_sha256),
                ),
            )
            if fenced_state != state:
                raise RuntimeError("epoch fence returned an unexpected authority head")

            partition.heal()
            _wait_for(
                lambda: _is_synced_replica(candidate, primary),
                timeout_seconds,
                "former primary did not rejoin the promoted candidate as a replica",
            )
            if candidate.get(split_brain_key) is not None:
                raise RuntimeError(
                    "isolated former-primary write survived topology healing"
                )

            stale_callback_entered = False

            def stale_write() -> None:
                nonlocal stale_callback_entered
                stale_callback_entered = True
                primary.set(f"{split_brain_key}:stale-callback", "entered", ex=120)

            try:
                authority.execute_under_epoch_fence(
                    expected_state_sha256=former_state.state_sha256,
                    candidate_id=former_state.candidate_id,
                    operation=stale_write,
                )
            except PromotionAuthorityConflict as exc:
                if str(exc) != "promotion_authority_head_mismatch":
                    raise
            else:
                raise RuntimeError("stale former-primary authority head was accepted")
            if stale_callback_entered:
                raise RuntimeError("stale former-primary write callback was entered")

        return {
            "boundary": {
                "authority_advanced_before_admission": True,
                "connectivity_restored_after_promotion": True,
                "external_epoch_fence_held_during_admission": True,
                "former_primary_alive_and_writable_during_partition": True,
                "former_primary_rejoined_as_replica": True,
                "one_way_egress_partition_applied": True,
                "stale_authority_head_rejected_after_heal": True,
                "three_sentinel_views_unanimous": True,
            },
            "observed": {
                "authority_epoch": state.authority_epoch,
                "authority_head_sha256": state.state_sha256,
                "candidate_id_sha256": hashlib.sha256(
                    decision.candidate_id.encode("ascii")
                ).hexdigest(),
                "former_primary_id_sha256": hashlib.sha256(
                    former_primary_id.encode("ascii")
                ).hexdigest(),
                "minimum_replication_offset": offset_floor,
                "observer_count": len(sentinels),
                "pre_failover_authority_head_sha256": former_state.state_sha256,
                "promotion_proof_sha256": authorization.proof_sha256,
                "replication_id_sha256": current.replid_sha256,
                "source_sha256": decision.source_sha256,
            },
            "run_id": run_id,
            "scenario": "three-sentinel-election-one-way-partition-and-heal",
            "schema_version": 2,
            "status": "pass",
        }
    finally:
        try:
            partition.heal()
        finally:
            primary.close()
            candidate.close()
            for sentinel in sentinels.values():
                sentinel.close()


def write_receipt(receipt: dict[str, Any], output: Path) -> None:
    """Atomically persist private, deterministic JSON evidence."""

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _loopback_endpoint(value: str, label: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    if parsed.scheme != "redis":
        raise ValueError(f"{label} URL must use redis://")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} URL must not contain credentials")
    if parsed.hostname is None or parsed.port is None:
        raise ValueError(f"{label} URL must include an explicit host and port")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError(f"{label} URL must use an explicit loopback IP") from exc
    if not address.is_loopback:
        raise ValueError(f"{label} URL must use an explicit loopback IP")
    if parsed.path not in {"", "/", "/0"} or parsed.query or parsed.fragment:
        raise ValueError(f"{label} URL must select only database zero")
    return str(address), parsed.port


def _wait_for_consensus(
    sentinels: dict[str, redis.Redis],
    candidate: redis.Redis,
    policy: SentinelPromotionPolicy,
    *,
    minimum_replication_offset: int,
    timeout_seconds: float,
) -> SentinelPromotionDecision:
    decision: SentinelPromotionDecision | None = None

    def observed() -> bool:
        nonlocal decision
        try:
            decision = observe_sentinel_consensus(
                sentinels,
                candidate,
                policy,
                minimum_replication_offset=minimum_replication_offset,
                observed_at=int(time.time()),
            )
        except (RedisError, SentinelPromotionError):
            return False
        return True

    _wait_for(
        observed,
        timeout_seconds,
        "Sentinel observers did not corroborate one safe promoted candidate",
    )
    if decision is None:
        raise RuntimeError("Sentinel consensus completed without a decision")
    return decision


def _is_synced_replica(primary: redis.Redis, candidate: redis.Redis) -> bool:
    try:
        primary_info = primary.info("replication")
        candidate_info = candidate.info("replication")
    except RedisError:
        return False
    return (
        primary_info.get("role") == "master"
        and int(primary_info.get("connected_slaves", 0)) >= 1
        and candidate_info.get("role") == "slave"
        and candidate_info.get("master_link_status") == "up"
        and int(candidate_info.get("master_sync_in_progress", 1)) == 0
    )


def _is_reachable_master(client: redis.Redis) -> bool:
    try:
        return client.ping() and client.info("replication").get("role") == "master"
    except RedisError:
        return False


def _redis_run_id(client: redis.Redis) -> str:
    try:
        value = client.info("server").get("run_id")
    except RedisError as exc:
        raise RuntimeError("former-primary identity is unavailable") from exc
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError("former-primary identity is invalid")
    return value


def _replication_offset(client: redis.Redis) -> int:
    try:
        info = client.info("replication")
    except RedisError:
        return -1
    field = (
        "master_repl_offset" if info.get("role") == "master" else "slave_repl_offset"
    )
    try:
        return int(info.get(field, -1))
    except (TypeError, ValueError):
        return -1


def _integer_field(document: dict[str, Any], name: str) -> int:
    value = document.get(name)
    if isinstance(value, bool):
        raise RuntimeError(f"Redis returned an invalid {name}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Redis returned an invalid {name}") from exc
    if parsed < 0:
        raise RuntimeError(f"Redis returned an invalid {name}")
    return parsed


def _can_ping(client: redis.Redis) -> bool:
    try:
        return bool(client.ping())
    except RedisError:
        return False


def _wait_for(
    predicate: Callable[[], bool],
    timeout_seconds: float,
    failure: str,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise RuntimeError(failure)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a destructive election drill against an isolated three-Sentinel topology."
    )
    parser.add_argument("--primary-url", required=True)
    parser.add_argument("--candidate-url", required=True)
    parser.add_argument("--sentinel-url", action="append", required=True)
    parser.add_argument("--candidate-advertised-host", required=True)
    parser.add_argument("--candidate-advertised-port", type=int, required=True)
    parser.add_argument("--partition-peer", action="append", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    started_at = datetime.now(UTC).isoformat()
    try:
        receipt = run_election_drill(
            args.primary_url,
            args.candidate_url,
            args.sentinel_url,
            candidate_advertised_host=args.candidate_advertised_host,
            candidate_advertised_port=args.candidate_advertised_port,
            partition=DockerEgressPartition(args.partition_peer),
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RedisError, RuntimeError, ValueError) as exc:
        receipt = {
            "error": str(exc),
            "schema_version": 2,
            "started_at": started_at,
            "status": "error",
        }
    else:
        receipt["completed_at"] = datetime.now(UTC).isoformat()
        receipt["started_at"] = started_at
    write_receipt(receipt, args.receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
