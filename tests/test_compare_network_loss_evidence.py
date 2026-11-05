from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from tools.compare_network_loss_evidence import load_evidence, main
from tools.docker_netem_impairment import (
    RUNTIME_FINGERPRINT_SCHEMA,
    NetemRuntimeFingerprint,
    QdiscTrafficDelta,
)
from tools.network_loss_evidence import (
    PARTIAL_LOSS_COMPARISON_SCHEMA,
    PartialLossBenchmarkEvidence,
    ProbeOutcomeSummary,
    compare_partial_loss_benchmarks,
    verify_partial_loss_benchmark,
)


def fingerprint(kernel: str = "a" * 64, tc: str = "b" * 64) -> NetemRuntimeFingerprint:
    payload = json.dumps(
        {
            "kernel_release_sha256": kernel,
            "schema_version": RUNTIME_FINGERPRINT_SCHEMA,
            "tc_version_sha256": tc,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return NetemRuntimeFingerprint(
        kernel_release_sha256=kernel,
        tc_version_sha256=tc,
        environment_sha256=hashlib.sha256(payload).hexdigest(),
    )


def benchmark(
    *,
    failures: int = 4,
    elapsed_ms: int = 700,
    runtime: NetemRuntimeFingerprint | None = None,
    seed: int = 12_648_430,
) -> PartialLossBenchmarkEvidence:
    return verify_partial_loss_benchmark(
        ProbeOutcomeSummary(
            attempts=128,
            successes=128 - failures,
            failures=failures,
            elapsed_ms=elapsed_ms,
        ),
        QdiscTrafficDelta(
            packets=800,
            bytes=72_000,
            drops=200,
            overlimits=0,
        ),
        configured_loss_percent=20,
        seed=seed,
        runtime_fingerprint=runtime or fingerprint(),
    )


def write_benchmark(path: Path, evidence: PartialLossBenchmarkEvidence) -> None:
    path.write_text(json.dumps(evidence.as_dict()), encoding="utf-8")


def test_reconstructs_exact_retained_benchmark_and_rejects_tampering() -> None:
    evidence = benchmark()
    assert PartialLossBenchmarkEvidence.from_dict(evidence.as_dict()) == evidence

    cases = []
    extended = {**evidence.as_dict(), "unreviewed": True}
    cases.append((extended, "fields"))
    changed_rate = {**evidence.as_dict(), "observed_drop_basis_points": 1_999}
    cases.append((changed_rate, "statistical"))
    changed_interval = {**evidence.as_dict(), "drop_interval_min_basis_points": 0}
    cases.append((changed_interval, "statistical"))
    changed_fingerprint = copy.deepcopy(evidence.as_dict())
    changed_fingerprint["runtime_fingerprint"]["environment_sha256"] = "f" * 64
    cases.append((changed_fingerprint, "commitment"))

    for document, message in cases:
        with pytest.raises(ValueError, match=message):
            PartialLossBenchmarkEvidence.from_dict(document)


def test_compares_compatible_benchmarks_with_privacy_reduced_commitments() -> None:
    baseline = benchmark(failures=4, elapsed_ms=700)
    candidate = benchmark(failures=5, elapsed_ms=770)

    comparison = compare_partial_loss_benchmarks(
        baseline,
        candidate,
        max_failure_rate_increase_basis_points=100,
        max_elapsed_increase_basis_points=1_000,
    )
    receipt = comparison.as_dict()

    assert comparison.accepted
    assert comparison.failure_rate_delta_basis_points == 78
    assert comparison.elapsed_change_basis_points == 1_000
    assert receipt["schema_version"] == PARTIAL_LOSS_COMPARISON_SCHEMA
    assert receipt["status"] == "pass"
    assert len(receipt["baseline_benchmark_sha256"]) == 64
    assert len(receipt["candidate_benchmark_sha256"]) == 64
    assert len(receipt["policy_sha256"]) == 64
    assert len(receipt["evidence_sha256"]) == 64

    serialized = json.dumps(receipt, sort_keys=True)
    assert baseline.runtime_fingerprint.kernel_release_sha256 not in serialized
    assert baseline.runtime_fingerprint.tc_version_sha256 not in serialized


def test_marks_regression_failed_without_discarding_comparison_evidence() -> None:
    comparison = compare_partial_loss_benchmarks(
        benchmark(failures=4, elapsed_ms=700),
        benchmark(failures=12, elapsed_ms=900),
        max_failure_rate_increase_basis_points=500,
        max_elapsed_increase_basis_points=2_000,
    )

    assert not comparison.accepted
    assert comparison.failure_rate_delta_basis_points == 625
    assert comparison.elapsed_change_basis_points == 2_857
    assert comparison.as_dict()["status"] == "fail"


def test_rejects_runtime_or_policy_substitution_before_comparison() -> None:
    baseline = benchmark()
    with pytest.raises(ValueError, match="runtime fingerprints"):
        compare_partial_loss_benchmarks(
            baseline,
            benchmark(runtime=fingerprint(kernel="c" * 64)),
        )
    with pytest.raises(ValueError, match="policies"):
        compare_partial_loss_benchmarks(baseline, benchmark(seed=12_648_431))


@pytest.mark.parametrize("threshold", [True, -1, 10_001, 1.5])
def test_rejects_invalid_regression_budgets(threshold: object) -> None:
    with pytest.raises(ValueError, match="integer"):
        compare_partial_loss_benchmarks(
            benchmark(),
            benchmark(),
            max_failure_rate_increase_basis_points=threshold,  # type: ignore[arg-type]
        )


def test_cli_writes_private_pass_and_fail_receipts(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    receipt = tmp_path / "comparison.json"
    write_benchmark(baseline, benchmark(failures=4, elapsed_ms=700))
    write_benchmark(candidate, benchmark(failures=5, elapsed_ms=770))

    arguments = [
        str(baseline),
        str(candidate),
        "--max-failure-rate-increase-basis-points",
        "100",
        "--max-elapsed-increase-basis-points",
        "1000",
        "--output",
        str(receipt),
    ]
    assert main(arguments) == 0
    assert json.loads(receipt.read_text(encoding="utf-8"))["status"] == "pass"
    assert os.stat(receipt).st_mode & 0o777 == 0o600

    arguments[3] = "0"
    assert main(arguments) == 3
    assert json.loads(receipt.read_text(encoding="utf-8"))["status"] == "fail"


def test_loader_rejects_duplicate_keys_symlinks_and_input_aliases(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"seed":1,"seed":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_evidence(duplicate)

    target = tmp_path / "target.json"
    write_benchmark(target, benchmark())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="without following links"):
        load_evidence(link)

    assert main([str(target), str(target)]) == 2
    assert main([str(target), str(tmp_path / "missing.json")]) == 2
