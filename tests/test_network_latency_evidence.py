from __future__ import annotations

from collections.abc import Iterable

import pytest

from tools.network_latency_evidence import (
    LatencyWindow,
    observe_round_trip_latency,
    verify_latency_shift,
)


class FakeClock:
    def __init__(self, durations_us: Iterable[int]) -> None:
        self._durations = iter(durations_us)
        self._now_ns = 1_000_000
        self._started = False

    def __call__(self) -> int:
        if not self._started:
            self._started = True
            return self._now_ns
        self._started = False
        self._now_ns += next(self._durations) * 1_000
        return self._now_ns


def window(median_us: int, p95_us: int | None = None) -> LatencyWindow:
    return LatencyWindow(
        sample_count=7,
        median_us=median_us,
        p95_us=p95_us if p95_us is not None else median_us,
    )


def test_observes_bounded_aggregate_window_and_discards_samples() -> None:
    calls = 0

    def probe() -> bool:
        nonlocal calls
        calls += 1
        return True

    observed = observe_round_trip_latency(
        probe,
        sample_count=7,
        clock_ns=FakeClock([100, 700, 300, 500, 200, 600, 400]),
    )

    assert observed == LatencyWindow(sample_count=7, median_us=400, p95_us=700)
    assert calls == 7
    assert not hasattr(observed, "samples")


def test_verifies_visible_delay_and_bounded_recovery() -> None:
    evidence = verify_latency_shift(
        window(1_000, 1_500),
        window(205_000, 225_000),
        window(3_000, 4_000),
        configured_delay_ms=200,
        configured_jitter_ms=20,
    )

    assert evidence.median_shift_us == 204_000
    assert evidence.minimum_expected_shift_us == 140_000
    assert evidence.recovery_delta_us == 2_000
    assert evidence.recovery_budget_us == 50_000
    receipt = evidence.as_dict()
    assert receipt["impaired"] == {
        "sample_count": 7,
        "median_us": 205_000,
        "p95_us": 225_000,
    }
    assert "samples" not in str(receipt)


def test_rejects_impairment_that_is_not_visible() -> None:
    with pytest.raises(RuntimeError, match="not visible"):
        verify_latency_shift(
            window(1_000),
            window(120_000),
            window(2_000),
            configured_delay_ms=200,
            configured_jitter_ms=20,
        )


def test_rejects_latency_that_does_not_recover() -> None:
    with pytest.raises(RuntimeError, match="did not recover"):
        verify_latency_shift(
            window(1_000),
            window(205_000),
            window(60_000),
            configured_delay_ms=200,
            configured_jitter_ms=20,
        )


@pytest.mark.parametrize("sample_count", [2, 4, 33])
def test_rejects_unbounded_or_even_sample_counts(sample_count: int) -> None:
    with pytest.raises(ValueError, match="sample_count"):
        observe_round_trip_latency(lambda: True, sample_count=sample_count)


def test_rejects_unacknowledged_or_out_of_bounds_probe() -> None:
    with pytest.raises(RuntimeError, match="did not acknowledge"):
        observe_round_trip_latency(
            lambda: False,
            sample_count=3,
            clock_ns=FakeClock([1, 1, 1]),
        )

    with pytest.raises(RuntimeError, match="outside"):
        observe_round_trip_latency(
            lambda: True,
            sample_count=3,
            max_sample_ms=10,
            clock_ns=FakeClock([11_000, 1, 1]),
        )


def test_rejects_mismatched_windows_or_invalid_policy() -> None:
    with pytest.raises(ValueError, match="same sample_count"):
        verify_latency_shift(
            window(1_000),
            LatencyWindow(sample_count=5, median_us=200_000, p95_us=200_000),
            window(2_000),
            configured_delay_ms=200,
            configured_jitter_ms=20,
        )
    with pytest.raises(ValueError, match="configured_jitter_ms"):
        verify_latency_shift(
            window(1_000),
            window(200_000),
            window(2_000),
            configured_delay_ms=200,
            configured_jitter_ms=201,
        )
