from __future__ import annotations

import json
from copy import deepcopy

import pytest

from tools.load_balance_gate import (
    LoadBalancePolicy,
    LoadEvidenceError,
    evaluate_load_balance,
    main,
    wilson_lower_bound,
)


@pytest.fixture
def policy() -> LoadBalancePolicy:
    return LoadBalancePolicy(expected_backends=("backend-a", "backend-b"))


@pytest.fixture
def healthy_evidence() -> dict:
    return {
        "requested": 100,
        "succeeded": 100,
        "failed": 0,
        "backend_distribution": {"backend-a": 52, "backend-b": 48},
        "latency_ms": {"p50": 18.0, "p95": 42.0, "p99": 70.0},
    }


def test_healthy_distribution_is_admitted_with_json_ready_evidence(policy, healthy_evidence):
    report = evaluate_load_balance(healthy_evidence, policy)

    assert report.accepted is True
    assert report.reasons == ()
    assert report.success_rate == 1.0
    assert report.success_rate_lower_bound > 0.95
    assert report.max_backend_share == 0.52
    assert report.to_dict()["backend_counts"] == {"backend-a": 52, "backend-b": 48}


def test_wilson_bound_reflects_sample_size():
    assert wilson_lower_bound(100, 100) > wilson_lower_bound(10, 10)
    with pytest.raises(ValueError, match="non-empty"):
        wilson_lower_bound(0, 0)


def test_sparse_evidence_fails_even_when_every_request_succeeds(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence.update(
        requested=10, succeeded=10, backend_distribution={"backend-a": 5, "backend-b": 5}
    )

    report = evaluate_load_balance(evidence, policy)

    assert "insufficient_request_evidence" in report.reasons
    assert "success_confidence_below_threshold" in report.reasons


def test_backend_loss_and_distribution_collapse_are_distinct(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence["backend_distribution"] = {"backend-a": 100}

    report = evaluate_load_balance(evidence, policy)

    assert report.missing_backends == ("backend-b",)
    assert "expected_backend_missing" in report.reasons
    assert "backend_share_exceeded" in report.reasons


def test_skewed_distribution_is_rejected_before_complete_backend_loss(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence["backend_distribution"] = {"backend-a": 71, "backend-b": 29}

    report = evaluate_load_balance(evidence, policy)

    assert report.missing_backends == ()
    assert report.max_backend_share == 0.71
    assert report.reasons == ("backend_share_exceeded",)


def test_success_confidence_and_tail_latency_are_gated(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence.update(succeeded=95, failed=5, backend_distribution={"backend-a": 48, "backend-b": 47})
    evidence["latency_ms"]["p95"] = 251.0

    report = evaluate_load_balance(evidence, policy)

    assert "success_confidence_below_threshold" in report.reasons
    assert "p95_latency_exceeded" in report.reasons


def test_unexpected_backend_policy_is_explicit(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence["backend_distribution"] = {"backend-a": 45, "backend-b": 45, "backend-c": 10}

    rejected = evaluate_load_balance(evidence, policy)
    admitted = evaluate_load_balance(
        evidence,
        LoadBalancePolicy(
            expected_backends=policy.expected_backends,
            allow_unexpected_backends=True,
        ),
    )

    assert rejected.unexpected_backends == ("backend-c",)
    assert "unexpected_backend_observed" in rejected.reasons
    assert admitted.accepted is True


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("requested", True, "requested"),
        ("failed", -1, "failed"),
        ("latency_ms", {"p95": float("nan")}, "finite"),
        ("backend_distribution", {"backend-a": 99}, "sum to succeeded"),
    ],
)
def test_malformed_evidence_fails_closed(policy, healthy_evidence, field, value, message):
    evidence = deepcopy(healthy_evidence)
    evidence[field] = value

    with pytest.raises(LoadEvidenceError, match=message):
        evaluate_load_balance(evidence, policy)


def test_inconsistent_result_counts_fail_closed(policy, healthy_evidence):
    evidence = deepcopy(healthy_evidence)
    evidence["failed"] = 1

    with pytest.raises(LoadEvidenceError, match=r"succeeded \+ failed"):
        evaluate_load_balance(evidence, policy)


def test_policy_validation_rejects_duplicate_backends_and_invalid_thresholds():
    with pytest.raises(ValueError, match="unique"):
        LoadBalancePolicy(expected_backends=("backend-a", "backend-a"))
    with pytest.raises(ValueError, match="between 0 and 1"):
        LoadBalancePolicy(expected_backends=("backend-a",), min_success_lower_bound=1.1)


def test_cli_distinguishes_policy_rejection_from_invalid_json(tmp_path, healthy_evidence, capsys):
    rejected = deepcopy(healthy_evidence)
    rejected["backend_distribution"] = {"backend-a": 100}
    rejected_path = tmp_path / "rejected.json"
    rejected_path.write_text(json.dumps(rejected), encoding="utf-8")
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{", encoding="utf-8")
    args = [str(rejected_path), "--backend", "backend-a", "--backend", "backend-b"]

    assert main(args) == 2
    assert '"expected_backend_missing"' in capsys.readouterr().out
    assert main([str(invalid_path), "--backend", "backend-a"]) == 3
    assert '"invalid_load_evidence"' in capsys.readouterr().out
