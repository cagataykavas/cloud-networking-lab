from __future__ import annotations

import json
import re
import stat
import tempfile
from pathlib import Path

import pytest

from tools.redis_sentinel_election_drill import (
    validate_election_endpoints,
    write_receipt,
)


PRIMARY = "redis://127.0.0.1:16479/0"
CANDIDATE = "redis://127.0.0.1:16480/0"
SENTINELS = [
    "redis://127.0.0.1:26479/0",
    "redis://127.0.0.1:26480/0",
    "redis://127.0.0.1:26481/0",
]


def test_accepts_five_distinct_loopback_endpoints() -> None:
    validate_election_endpoints(PRIMARY, CANDIDATE, SENTINELS)


@pytest.mark.parametrize(
    ("primary", "candidate", "sentinels", "message"),
    [
        (PRIMARY, CANDIDATE, SENTINELS[:2], "exactly three"),
        (PRIMARY, CANDIDATE, [*SENTINELS[:2], PRIMARY], "distinct"),
        (
            PRIMARY,
            CANDIDATE,
            [*SENTINELS[:2], "redis://10.0.0.8:26481/0"],
            "loopback",
        ),
        (
            PRIMARY,
            "redis://user:secret@127.0.0.1:16480/0",
            SENTINELS,
            "credentials",
        ),
        (
            "rediss://127.0.0.1:16479/0",
            CANDIDATE,
            SENTINELS,
            "redis://",
        ),
        (
            PRIMARY,
            "redis://127.0.0.1:16480/4",
            SENTINELS,
            "database zero",
        ),
    ],
)
def test_rejects_unsafe_or_ambiguous_topologies(
    primary: str,
    candidate: str,
    sentinels: list[str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_election_endpoints(primary, candidate, sentinels)


def test_writes_private_receipt_without_raw_topology() -> None:
    receipt = {
        "observed": {"observer_count": 3, "source_sha256": "a" * 64},
        "schema_version": 1,
        "status": "pass",
    }
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "evidence" / "receipt.json"

        write_receipt(receipt, output)

        assert json.loads(output.read_text(encoding="utf-8")) == receipt
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert output.read_text(encoding="utf-8").endswith("\n")
        assert "127.0.0.1" not in output.read_text(encoding="utf-8")


def test_ci_runs_three_sentinel_election_and_archives_evidence() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "docker compose --profile redis-sentinel-election up" in workflow
    assert "python -m tools.redis_sentinel_election_drill" in workflow
    assert workflow.count("--sentinel-url redis://127.0.0.1:") == 3
    assert workflow.count("--partition-peer 172.30.0.") == 4
    assert "--reconnect-interface eth0" in workflow
    assert "--reconnect-delay-ms 200" in workflow
    assert "--reconnect-jitter-ms 20" in workflow
    assert "--reconnect-reorder-percent 25" in workflow
    assert "--reconnect-reorder-correlation-percent 50" in workflow
    assert "--loss-probe-percent 100" in workflow
    assert "--partial-loss-percent 20" in workflow
    assert "--partial-loss-seed 12648430" in workflow
    assert "--partial-loss-attempts 128" in workflow
    assert "steps.sentinel_election_drill.outcome == 'failure'" in workflow
    assert "logs --no-color --tail 200" in workflow
    assert "redis-sentinel-election down --volumes" in workflow
    uploader = re.findall(r"actions/upload-artifact@([0-9a-f]{40})", workflow)
    assert len(uploader) == 2
    assert len(set(uploader)) == 1


def test_drill_holds_external_epoch_fence_across_replay_admission() -> None:
    source = Path("tools/redis_sentinel_election_drill.py").read_text(encoding="utf-8")

    fence = source.index("authority.execute_under_epoch_fence(")
    proof = source.index("execute_after_promotion_proof(", fence)
    claim = source.index(").claim(claim_sha256)", proof)
    assert fence < proof < claim
    assert '"external_epoch_fence_held_during_admission": True' in source
    isolate = source.index("partition.isolate()")
    consensus = source.index("_wait_for_consensus(", isolate)
    baseline = source.index("baseline_latency = observe_round_trip_latency", consensus)
    impair = source.index("reconnect_impairment.apply()", baseline)
    heal = source.index("partition.heal()", consensus)
    rejoined = source.index("former primary did not rejoin under impaired reconnection")
    impaired = source.index("impaired_latency = observe_round_trip_latency", rejoined)
    traffic = source.index("reconnect_impairment.verify_traffic_observed()", rejoined)
    clear = source.index("reconnect_impairment.clear()", rejoined)
    recovery = source.index("recovery_latency = observe_round_trip_latency", clear)
    latency = source.index("latency_evidence = verify_latency_shift", recovery)
    drop_apply = source.index("drop_probe_impairment.apply()", latency)
    drop_attempts = source.index("range(DROP_PROBE_ATTEMPTS)", drop_apply)
    drop_evidence = source.index(
        "drop_probe_impairment.verify_traffic_observed(", drop_attempts
    )
    drop_clear = source.index("drop_probe_impairment.clear()", drop_evidence)
    drop_recovery = source.index("former primary did not recover", drop_clear)
    partial_apply = source.index("partial_loss_impairment.apply()", drop_recovery)
    partial_outcomes = source.index("partial_loss_outcomes = observe_probe_outcomes(")
    partial_traffic = source.index(
        "partial_loss_impairment.verify_traffic_observed(", partial_outcomes
    )
    partial_evidence = source.index(
        "partial_loss_evidence = verify_partial_loss_benchmark(", partial_traffic
    )
    partial_clear = source.index("partial_loss_impairment.clear()", partial_evidence)
    partial_recovery = source.index(
        "former primary did not recover after the partial-loss benchmark",
        partial_clear,
    )
    stale_fence = source.index("expected_state_sha256=former_state.state_sha256", heal)
    stale_callback = source.index("operation=stale_write", stale_fence)
    assert (
        isolate
        < consensus
        < baseline
        < impair
        < heal
        < rejoined
        < impaired
        < traffic
        < clear
        < recovery
        < latency
        < drop_apply
        < drop_attempts
        < drop_evidence
        < drop_clear
        < drop_recovery
        < partial_apply
        < partial_outcomes
        < partial_traffic
        < partial_evidence
        < partial_clear
        < partial_recovery
        < stale_fence
    )
    assert stale_fence < stale_callback
    assert '"reconnection_delay_and_reordering_applied": True' in source
    assert '"reconnection_impairment_removed": True' in source
    assert '"reconnection_latency_recovered": True' in source
    assert '"reconnection_latency_shift_observed": True' in source
    assert '"reconnection_latency": latency_evidence.as_dict()' in source
    assert '"reconnection_qdisc_pressure_counters_collected": True' in source
    assert '"reconnection_traffic_traversed_impairment": True' in source
    assert '"reconnection_traffic_bytes": reconnection_traffic.bytes' in source
    assert '"reconnection_traffic_drops": reconnection_traffic.drops' in source
    assert (
        '"reconnection_traffic_overlimits": reconnection_traffic.overlimits' in source
    )
    assert '"reconnection_traffic_packets": reconnection_traffic.packets' in source
    assert '"deterministic_packet_loss_applied": True' in source
    assert '"drop_probe_connectivity_recovered": True' in source
    assert '"drop_probe_impairment_removed": True' in source
    assert '"nonzero_drop_evidence_observed": True' in source
    assert '"drop_probe_attempts": DROP_PROBE_ATTEMPTS' in source
    assert '"drop_probe_traffic_attempted_packets": (' in source
    assert '"drop_probe_traffic_drops": drop_probe_traffic.drops' in source
    assert '"seeded_partial_loss_benchmarked": True' in source
    assert '"partial_loss_frequency_sanity_checked": True' in source
    assert '"partial_loss_benchmark": partial_loss_evidence.as_dict()' in source
    assert '"schema_version": 8' in source
    assert '"stale_authority_head_rejected_after_heal": True' in source


def test_compose_declares_three_independent_sentinel_processes() -> None:
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    sentinel = Path("ops/redis-sentinel/sentinel.conf").read_text(encoding="utf-8")

    assert compose.count('profiles: ["redis-sentinel-election"]') == 5
    assert "dockerfile: ops/redis-sentinel/partition.Dockerfile" in compose
    assert "- NET_ADMIN" in compose
    assert "- no-new-privileges:true" in compose
    assert compose.count("exec redis-sentinel /tmp/sentinel.conf") == 3
    assert "127.0.0.1:26479:26379" in compose
    assert "127.0.0.1:26480:26379" in compose
    assert "127.0.0.1:26481:26379" in compose
    assert "./ops/redis-sentinel:/template:ro" in compose
    assert "subnet: 172.30.0.0/24" in compose
    for address in (
        "172.30.0.10",
        "172.30.0.11",
        "172.30.0.21",
        "172.30.0.22",
        "172.30.0.23",
    ):
        assert compose.count(f"ipv4_address: {address}") == 1
    assert "--replica-announce-ip\n      - 172.30.0.11" in compose
    assert "sentinel monitor replay-primary 172.30.0.10 6379 2" in sentinel
    assert "resolve-hostnames" not in sentinel
    assert "announce-hostnames" not in sentinel


def test_partition_image_contains_only_required_fault_injection_tools() -> None:
    dockerfile = Path("ops/redis-sentinel/partition.Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerfile.startswith("FROM redis:8.2.10-alpine\n")
    assert dockerfile.count("RUN ") == 1
    assert "apk add --no-cache iproute2 iptables" in dockerfile
