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
    heal = source.index("partition.heal()", consensus)
    stale_fence = source.index("expected_state_sha256=former_state.state_sha256", heal)
    stale_callback = source.index("operation=stale_write", stale_fence)
    assert isolate < consensus < heal < stale_fence < stale_callback
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


def test_partition_image_contains_only_required_fault_injection_tool() -> None:
    dockerfile = Path("ops/redis-sentinel/partition.Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerfile.startswith("FROM redis:8.2.10-alpine\n")
    assert dockerfile.count("RUN ") == 1
    assert "apk add --no-cache iptables" in dockerfile
