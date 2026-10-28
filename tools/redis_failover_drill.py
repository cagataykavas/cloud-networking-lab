#!/usr/bin/env python3
"""Reproduce the stale-replica promotion boundary on an isolated Redis pair."""

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

from tools.redis_promotion_proof import (
    PromotionProofRejected,
    RedisPromotionPolicy,
    RedisPromotionProof,
    RedisReplicationSnapshot,
    execute_after_promotion_proof,
    sign_promotion_proof,
)
from tools.redis_replay_guard import RedisReplayGuard, RedisReplayGuardPolicy
from tools.replay_guard import ReplayGuardUnavailable


def validate_drill_endpoints(primary_url: str, replica_url: str) -> None:
    """Refuse credentials, remote hosts and endpoint reuse before destructive calls."""

    endpoints: list[tuple[str, int]] = []
    for label, value in (("primary", primary_url), ("replica", replica_url)):
        parsed = urlsplit(value)
        if parsed.scheme != "redis":
            raise ValueError(f"{label} URL must use redis://")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(f"{label} URL must not contain credentials")
        if parsed.hostname is None or parsed.port is None:
            raise ValueError(
                f"{label} URL must include an explicit loopback host and port"
            )
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError(
                f"{label} URL must use an explicit loopback IP address"
            ) from exc
        if not address.is_loopback:
            raise ValueError(f"{label} URL must use an explicit loopback IP address")
        if parsed.query or parsed.fragment:
            raise ValueError(f"{label} URL must not contain query or fragment data")
        endpoints.append((str(address), parsed.port))
    if endpoints[0] == endpoints[1]:
        raise ValueError("primary and replica endpoints must be distinct")


def run_drill(
    primary_url: str,
    replica_url: str,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Detach a synced replica, stop the primary and exercise both admission policies."""

    validate_drill_endpoints(primary_url, replica_url)
    if not 1.0 <= timeout_seconds <= 60.0:
        raise ValueError("timeout_seconds must be in [1, 60]")

    primary = redis.Redis.from_url(
        primary_url,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    replica = redis.Redis.from_url(
        replica_url,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    run_id = uuid.uuid4().hex
    marker_key = f"redis-failover-drill:{run_id}:sync"
    ungated_key = _digest(f"{run_id}:ungated")
    gated_key = _digest(f"{run_id}:gated")
    proof_gated_key = _digest(f"{run_id}:proof-gated")
    ungated_policy = RedisReplayGuardPolicy(
        namespace=f"drill-{run_id}-ungated",
        required_replica_acks=0,
    )
    gated_policy = RedisReplayGuardPolicy(
        namespace=f"drill-{run_id}-gated",
        required_replica_acks=1,
        replica_ack_timeout_milliseconds=50,
    )

    try:
        _wait_for(
            lambda: _is_synced_replica(primary, replica),
            timeout_seconds,
            "replica did not reach a healthy synchronized state",
        )
        primary.set(marker_key, "ready", ex=60)
        acknowledged = primary.wait(1, 1_000)
        if acknowledged < 1:
            raise RuntimeError("initial synchronization marker was not acknowledged")
        _wait_for(
            lambda: replica.get(marker_key) == b"ready",
            timeout_seconds,
            "replica did not observe the synchronization marker",
        )
        replica_before = _integer_field(
            replica.info("replication"), "slave_repl_offset"
        )

        # Redirect to a closed loopback port. The node remains a replica with its
        # current dataset but can no longer receive primary writes.
        replica.execute_command("REPLICAOF", "127.0.0.1", "1")
        _wait_for(
            lambda: _is_disconnected_replica(replica),
            timeout_seconds,
            "replica did not enter the controlled disconnected state",
        )
        _wait_for(
            lambda: _has_no_replicas(primary),
            timeout_seconds,
            "primary still reported a connected replica after detachment",
        )

        RedisReplayGuard(primary, ungated_policy).claim(ungated_key)
        gated_primary = _expect_unavailable(
            lambda: RedisReplayGuard(primary, gated_policy).claim(gated_key)
        )
        primary_after = _integer_field(
            primary.info("replication"), "master_repl_offset"
        )
        if primary_after <= replica_before:
            raise RuntimeError(
                "primary replication offset did not advance after detached claims"
            )

        try:
            primary.execute_command("SHUTDOWN", "NOSAVE")
        except RedisError:
            # Redis normally closes the connection before returning a reply.
            pass
        _wait_for(
            lambda: not _can_ping(primary),
            timeout_seconds,
            "primary remained reachable after shutdown",
        )

        replica.execute_command("REPLICAOF", "NO", "ONE")
        _wait_for(
            lambda: replica.info("replication").get("role") == "master",
            timeout_seconds,
            "stale replica was not promoted",
        )
        promoted_snapshot = RedisReplicationSnapshot.from_info(
            replica.info("replication")
        )
        promoted_before = promoted_snapshot.offset

        authority_epoch = 1
        proof_secret = secrets.token_bytes(32)
        proof_issued_at = int(time.time())
        promotion_proof = sign_promotion_proof(
            cluster_id="redis-failover-drill",
            candidate_id="redis-fault-replica",
            authority_epoch=authority_epoch,
            minimum_replication_offset=primary_after,
            snapshot=promoted_snapshot,
            issued_at=proof_issued_at,
            expires_at=proof_issued_at + 30,
            key_id="drill-ephemeral",
            secret=proof_secret,
        )
        promotion_policy = RedisPromotionPolicy(
            cluster_id="redis-failover-drill",
            candidate_id="redis-fault-replica",
            minimum_authority_epoch=authority_epoch,
            keyring={"drill-ephemeral": proof_secret},
            max_proof_lifetime_seconds=30,
        )
        proof_gate_reason = _expect_promotion_denied(
            promotion_proof,
            promotion_policy,
            promoted_snapshot,
            now=proof_issued_at,
            operation=lambda: RedisReplayGuard(replica, ungated_policy).claim(
                proof_gated_key
            ),
        )
        if replica.hexists(
            RedisReplayGuard(replica, ungated_policy).keys[0],
            f"claim:{proof_gated_key}",
        ):
            raise RuntimeError(
                "proof-gated replay operation ran after promotion denial"
            )

        # The same digest is accepted again because the promoted node never saw
        # the primary-only claim. This is the documented asynchronous boundary.
        RedisReplayGuard(replica, ungated_policy).claim(ungated_key)
        gated_promoted = _expect_unavailable(
            lambda: RedisReplayGuard(replica, gated_policy).claim(gated_key)
        )
        return {
            "status": "pass",
            "schema_version": 2,
            "run_id": run_id,
            "scenario": "controlled-stale-replica-promotion",
            "observed": {
                "gated_primary": gated_primary,
                "gated_promoted_replica": gated_promoted,
                "primary_offset_after_detached_claims": primary_after,
                "promoted_offset_before_reclaims": promoted_before,
                "promotion_authority_epoch": authority_epoch,
                "promotion_proof_decision": "admission_denied",
                "promotion_proof_reason": proof_gate_reason,
                "promotion_proof_sha256": promotion_proof.digest,
                "required_minimum_replication_offset": primary_after,
                "replica_offset_before_disconnect": replica_before,
                "ungated_primary": "accepted",
                "ungated_promoted_replica": "accepted_again",
            },
            "boundary": {
                "replica_ack_gate_kept_admission_closed": True,
                "stale_promotion_reopened_ungated_claim": True,
                "stale_promotion_proof_denied_replay_traffic": True,
            },
        }
    finally:
        primary.close()
        replica.close()


def write_receipt(receipt: dict[str, Any], output: Path) -> None:
    """Atomically persist a private deterministic JSON receipt."""

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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _expect_unavailable(operation: Callable[[], None]) -> str:
    try:
        operation()
    except ReplayGuardUnavailable:
        return "admission_denied"
    raise RuntimeError("replica-gated claim unexpectedly admitted traffic")


def _expect_promotion_denied(
    proof: RedisPromotionProof,
    policy: RedisPromotionPolicy,
    snapshot: RedisReplicationSnapshot,
    *,
    now: int,
    operation: Callable[[], None],
) -> str:
    try:
        execute_after_promotion_proof(
            proof,
            policy,
            snapshot,
            now=now,
            operation=operation,
        )
    except PromotionProofRejected as exc:
        if exc.reason != "replication_offset_below_minimum":
            raise RuntimeError(
                f"promotion proof failed for unexpected reason: {exc.reason}"
            ) from exc
        return exc.reason
    raise RuntimeError("stale candidate unexpectedly satisfied the promotion proof")


def _is_synced_replica(primary: redis.Redis, replica: redis.Redis) -> bool:
    try:
        primary_info = primary.info("replication")
        replica_info = replica.info("replication")
    except RedisError:
        return False
    return (
        primary_info.get("role") == "master"
        and int(primary_info.get("connected_slaves", 0)) >= 1
        and replica_info.get("role") == "slave"
        and replica_info.get("master_link_status") == "up"
        and int(replica_info.get("master_sync_in_progress", 1)) == 0
    )


def _is_disconnected_replica(replica: redis.Redis) -> bool:
    try:
        info = replica.info("replication")
    except RedisError:
        return False
    return info.get("role") == "slave" and info.get("master_link_status") == "down"


def _has_no_replicas(primary: redis.Redis) -> bool:
    try:
        info = primary.info("replication")
    except RedisError:
        return False
    return info.get("role") == "master" and int(info.get("connected_slaves", -1)) == 0


def _integer_field(document: dict[str, Any], name: str) -> int:
    value = document.get(name)
    if isinstance(value, bool):
        raise RuntimeError(f"Redis returned an invalid {name}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Redis returned an invalid {name}") from exc


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
        description="Run a destructive stale-promotion drill against an isolated loopback Redis pair."
    )
    parser.add_argument("--primary-url", required=True)
    parser.add_argument("--replica-url", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    started_at = datetime.now(UTC).isoformat()
    try:
        receipt = run_drill(
            args.primary_url,
            args.replica_url,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RedisError, RuntimeError, ValueError) as exc:
        receipt = {
            "status": "error",
            "schema_version": 1,
            "started_at": started_at,
            "error": str(exc),
        }
    else:
        receipt["started_at"] = started_at
        receipt["completed_at"] = datetime.now(UTC).isoformat()
    write_receipt(receipt, args.receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
