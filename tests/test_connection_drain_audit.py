from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest
from tools.connection_drain_audit import (
    MAX_ARTIFACT_BYTES,
    ArtifactError,
    DrainPolicy,
    audit_connection_drains,
    load_artifact_bytes,
    main,
    parse_artifact,
)

NOW = datetime(2026, 9, 26, 19, 0, tzinfo=UTC)


def valid_backend(backend_id: str = "backend-a", *, minute: int = 0) -> dict[str, object]:
    prefix = f"2026-09-26T18:{minute:02d}:"
    return {
        "backend_id": backend_id,
        "termination_notice_at": prefix + "00Z",
        "replacement_ready_at": prefix + "00Z",
        "readiness_withdrawn_at": prefix + "05Z",
        "endpoint_removed_at": prefix + "10Z",
        "terminated_at": prefix + "40Z",
        "samples": [
            {
                "observed_at": prefix + "00Z",
                "active_connections": 4,
                "new_connections": 2,
                "in_flight_requests": 3,
                "failed_requests": 0,
            },
            {
                "observed_at": prefix + "10Z",
                "active_connections": 3,
                "new_connections": 0,
                "in_flight_requests": 2,
                "failed_requests": 0,
            },
            {
                "observed_at": prefix + "20Z",
                "active_connections": 1,
                "new_connections": 0,
                "in_flight_requests": 1,
                "failed_requests": 0,
            },
            {
                "observed_at": prefix + "30Z",
                "active_connections": 0,
                "new_connections": 0,
                "in_flight_requests": 0,
                "failed_requests": 0,
            },
            {
                "observed_at": prefix + "40Z",
                "active_connections": 0,
                "new_connections": 0,
                "in_flight_requests": 0,
                "failed_requests": 0,
            },
        ],
    }


def valid_artifact() -> dict[str, object]:
    return {
        "schema_version": 1,
        "deployment_id": "payments-prod-20260926",
        "collected_at": "2026-09-26T18:01:00Z",
        "backends": [valid_backend()],
    }


def report_for(value: dict[str, object], policy: DrainPolicy | None = None):
    return audit_connection_drains(parse_artifact(value), policy, now=NOW)


def codes(value: dict[str, object], policy: DrainPolicy | None = None) -> set[str]:
    return {finding.code for finding in report_for(value, policy).findings}


def test_complete_connection_drain_is_accepted_without_raw_identifiers() -> None:
    report = report_for(valid_artifact())
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.accepted
    assert report.backend_count == 1
    assert report.sample_count == 5
    assert report.peak_concurrent_drains == 1
    assert "payments-prod" not in rendered
    assert "backend-a" not in rendered


def test_canonical_digest_is_independent_of_backend_order_and_utc_offset() -> None:
    first = valid_artifact()
    first["backends"] = [valid_backend("backend-a", minute=0), valid_backend("backend-b", minute=2)]
    first["collected_at"] = "2026-09-26T18:03:00Z"
    second = copy.deepcopy(first)
    second["backends"] = list(reversed(second["backends"]))  # type: ignore[arg-type]
    second["collected_at"] = "2026-09-26T21:03:00+03:00"

    left = report_for(first, DrainPolicy(max_concurrent_drains=2))
    right = report_for(second, DrainPolicy(max_concurrent_drains=2))

    assert left.accepted and right.accepted
    assert left.artifact_sha256 == right.artifact_sha256


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("replacement_ready_at", "2026-09-26T18:00:06Z", "REPLACEMENT_NOT_READY"),
        ("termination_notice_at", "2026-09-26T18:00:06Z", "READINESS_PRECEDES_TERMINATION_NOTICE"),
        ("endpoint_removed_at", "2026-09-26T18:00:04Z", "ENDPOINT_REMOVED_BEFORE_READINESS"),
        ("terminated_at", "2026-09-26T18:00:09Z", "TERMINATED_BEFORE_ENDPOINT_REMOVAL"),
    ],
)
def test_invalid_lifecycle_order_is_rejected(field: str, value: str, expected: str) -> None:
    artifact = valid_artifact()
    artifact["backends"][0][field] = value  # type: ignore[index]
    assert expected in codes(artifact)


def test_drain_window_and_endpoint_delay_budgets_are_enforced() -> None:
    short = valid_artifact()
    short["backends"][0]["terminated_at"] = "2026-09-26T18:00:25Z"  # type: ignore[index]
    slow_endpoint = valid_artifact()
    slow_endpoint["backends"][0]["endpoint_removed_at"] = "2026-09-26T18:00:36Z"  # type: ignore[index]

    assert "DRAIN_WINDOW_TOO_SHORT" in codes(short)
    assert "ENDPOINT_REMOVAL_TOO_SLOW" in codes(slow_endpoint)


def test_late_new_connection_is_rejected_after_propagation_grace() -> None:
    artifact = valid_artifact()
    artifact["backends"][0]["samples"][2]["new_connections"] = 1  # type: ignore[index]
    report = report_for(artifact)

    assert not report.accepted
    finding = next(item for item in report.findings if item.code == "LATE_NEW_CONNECTIONS")
    assert finding.sample_index == 2


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("active_connections", "ACTIVE_CONNECTIONS_AT_TERMINATION"),
        ("in_flight_requests", "IN_FLIGHT_REQUESTS_AT_TERMINATION"),
    ],
)
def test_terminal_work_must_reach_zero(field: str, expected: str) -> None:
    artifact = valid_artifact()
    artifact["backends"][0]["samples"][-1][field] = 1  # type: ignore[index]
    assert expected in codes(artifact)


def test_failed_request_budget_is_enforced() -> None:
    artifact = valid_artifact()
    artifact["backends"][0]["samples"][2]["failed_requests"] = 1  # type: ignore[index]
    assert codes(artifact) == {"FAILED_REQUEST_BUDGET_EXCEEDED"}
    assert report_for(artifact, DrainPolicy(max_failed_requests=1)).accepted


def test_sampling_must_be_ordered_and_cover_the_lifecycle() -> None:
    artifact = valid_artifact()
    samples = artifact["backends"][0]["samples"]  # type: ignore[index]
    samples[2]["observed_at"] = samples[1]["observed_at"]
    found = codes(artifact)
    assert "SAMPLES_NOT_STRICTLY_ORDERED" in found

    missing = valid_artifact()
    missing["backends"][0]["samples"] = missing["backends"][0]["samples"][1:]  # type: ignore[index]
    assert "PRE_DRAIN_SAMPLE_MISSING" in codes(missing)


def test_sample_gap_and_terminal_freshness_are_enforced() -> None:
    gap = valid_artifact()
    gap["backends"][0]["samples"] = [  # type: ignore[index]
        gap["backends"][0]["samples"][0],  # type: ignore[index]
        gap["backends"][0]["samples"][-1],  # type: ignore[index]
    ]
    assert "SAMPLE_GAP_EXCEEDED" in codes(gap)

    old_terminal = valid_artifact()
    old_terminal["backends"][0]["samples"] = old_terminal["backends"][0]["samples"][:-1]  # type: ignore[index]
    assert "TERMINAL_SAMPLE_TOO_OLD" in codes(
        old_terminal, DrainPolicy(max_terminal_sample_lag_seconds=5)
    )


def test_connection_counter_growth_requires_new_connection_evidence() -> None:
    artifact = valid_artifact()
    artifact["backends"][0]["samples"][2]["active_connections"] = 5  # type: ignore[index]
    assert "CONNECTION_COUNTER_INCONSISTENT" in codes(artifact)


def test_overlapping_backend_drains_obey_wave_budget() -> None:
    artifact = valid_artifact()
    artifact["backends"] = [valid_backend("backend-a"), valid_backend("backend-b")]
    report = report_for(artifact)

    assert report.peak_concurrent_drains == 2
    assert "CONCURRENT_DRAIN_LIMIT_EXCEEDED" in {item.code for item in report.findings}
    assert report_for(artifact, DrainPolicy(max_concurrent_drains=2)).accepted


def test_stale_and_future_artifacts_fail_closed() -> None:
    stale = valid_artifact()
    assert "ARTIFACT_STALE" in codes(stale, DrainPolicy(max_artifact_age_seconds=60))
    future = valid_artifact()
    future["collected_at"] = "2026-09-26T19:01:00Z"
    assert "COLLECTED_AT_IN_FUTURE" in codes(future)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"schema_version": 2}),
        lambda value: value.update({"deployment_id": ""}),
        lambda value: value.update({"collected_at": "2026-09-26T18:01:00"}),
        lambda value: value.update({"backends": []}),
    ],
)
def test_malformed_artifact_shape_is_rejected(mutation) -> None:
    artifact = valid_artifact()
    mutation(artifact)
    with pytest.raises(ArtifactError):
        parse_artifact(artifact)


def test_duplicate_backend_and_invalid_counts_are_rejected() -> None:
    duplicate = valid_artifact()
    duplicate["backends"] = [valid_backend(), valid_backend()]
    with pytest.raises(ArtifactError, match="unique"):
        parse_artifact(duplicate)
    invalid = valid_artifact()
    invalid["backends"][0]["samples"][0]["active_connections"] = True  # type: ignore[index]
    with pytest.raises(ArtifactError, match="integer"):
        parse_artifact(invalid)


def test_duplicate_json_nonfinite_and_size_budgets_are_rejected() -> None:
    with pytest.raises(ArtifactError, match="duplicate"):
        load_artifact_bytes(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ArtifactError, match="non-finite"):
        load_artifact_bytes(b'{"value":NaN}')
    with pytest.raises(ArtifactError, match="256 KiB"):
        load_artifact_bytes(b"x" * (MAX_ARTIFACT_BYTES + 1))


def test_backend_and_sample_resource_budgets_fail_closed() -> None:
    artifact = valid_artifact()
    artifact["backends"] = [valid_backend("a"), valid_backend("b")]
    assert "BACKEND_LIMIT_EXCEEDED" in codes(
        artifact, DrainPolicy(max_backends=1, max_concurrent_drains=2)
    )
    samples = valid_artifact()
    assert "SAMPLE_LIMIT_EXCEEDED" in codes(samples, DrainPolicy(max_samples_per_backend=4))


def test_finding_report_is_bounded_and_marks_truncation() -> None:
    artifact = valid_artifact()
    backends = []
    for index in range(100):
        backend = valid_backend(f"backend-{index}")
        backend["samples"][-1]["active_connections"] = 1  # type: ignore[index]
        backend["samples"][-1]["in_flight_requests"] = 1  # type: ignore[index]
        backends.append(backend)
    artifact["backends"] = backends

    report = report_for(artifact, DrainPolicy(max_concurrent_drains=100))

    assert not report.accepted
    assert len(report.findings) == 128
    assert report.findings_truncated


def test_policy_rejects_boolean_and_inverted_limits() -> None:
    with pytest.raises(ArtifactError, match="positive integer"):
        DrainPolicy(max_backends=True)
    with pytest.raises(ArtifactError, match="cover"):
        DrainPolicy(min_drain_seconds=60, max_drain_seconds=30)


def test_cli_uses_distinct_accept_reject_and_malformed_exit_codes(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(valid_artifact()))
    now = NOW.isoformat()
    assert main([str(path), "--now", now]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True

    rejected = valid_artifact()
    rejected["backends"][0]["samples"][-1]["active_connections"] = 1  # type: ignore[index]
    path.write_text(json.dumps(rejected))
    assert main([str(path), "--now", now]) == 2
    assert json.loads(capsys.readouterr().out)["accepted"] is False

    path.write_text("not-json")
    assert main([str(path), "--now", now]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "malformed"
