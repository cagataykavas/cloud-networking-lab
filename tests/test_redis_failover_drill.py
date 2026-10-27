from __future__ import annotations

import json
import re
import stat
import tempfile
from pathlib import Path

import pytest

from tools.redis_failover_drill import validate_drill_endpoints, write_receipt


def test_accepts_distinct_loopback_endpoints() -> None:
    validate_drill_endpoints(
        "redis://127.0.0.1:16379/0",
        "redis://127.0.0.1:16380/0",
    )


@pytest.mark.parametrize(
    ("primary_url", "replica_url", "message"),
    [
        ("rediss://127.0.0.1:16379/0", "redis://127.0.0.1:16380/0", "redis://"),
        ("redis://10.0.0.2:16379/0", "redis://127.0.0.1:16380/0", "loopback"),
        ("redis://localhost:16379/0", "redis://127.0.0.1:16380/0", "loopback"),
        (
            "redis://user:secret@127.0.0.1:16379/0",
            "redis://127.0.0.1:16380/0",
            "credentials",
        ),
        ("redis://127.0.0.1/0", "redis://127.0.0.1:16380/0", "explicit"),
        ("redis://127.0.0.1:16379/0", "redis://127.0.0.1:16379/1", "distinct"),
    ],
)
def test_rejects_unsafe_or_ambiguous_endpoints(
    primary_url: str, replica_url: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_drill_endpoints(primary_url, replica_url)


def test_writes_private_deterministic_receipt() -> None:
    receipt = {"schema_version": 1, "status": "pass"}
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "nested" / "receipt.json"

        write_receipt(receipt, output)

        assert json.loads(output.read_text(encoding="utf-8")) == receipt
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert output.read_text(encoding="utf-8").endswith("\n")


def test_ci_runs_live_drill_and_pins_evidence_uploader() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "docker compose --profile redis-failover up" in workflow
    assert "python -m tools.redis_failover_drill" in workflow
    assert "steps.failover_drill.outcome == 'failure'" in workflow
    assert "retention-days: 14" in workflow
    uploader = re.search(r"actions/upload-artifact@([0-9a-f]{40})", workflow)
    assert uploader is not None
    assert "docker compose --profile redis-failover down --volumes" in workflow
