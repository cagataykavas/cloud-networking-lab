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
    assert "steps.sentinel_election_drill.outcome == 'failure'" in workflow
    assert "logs --no-color --tail 200" in workflow
    assert "redis-sentinel-election down --volumes" in workflow
    uploader = re.findall(r"actions/upload-artifact@([0-9a-f]{40})", workflow)
    assert len(uploader) == 2
    assert len(set(uploader)) == 1


def test_compose_declares_three_independent_sentinel_processes() -> None:
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert compose.count('profiles: ["redis-sentinel-election"]') == 5
    assert compose.count("exec redis-sentinel /tmp/sentinel.conf") == 3
    assert "127.0.0.1:26479:26379" in compose
    assert "127.0.0.1:26480:26379" in compose
    assert "127.0.0.1:26481:26379" in compose
    assert "./ops/redis-sentinel:/template:ro" in compose
