"""Bounded Docker/tc controller for impaired one-way reconnection traffic."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


SERVICE = "redis_election_primary"
HANDLE = "1:"
CommandRunner = Callable[[list[str], float], str]
MAX_COUNTER = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class QdiscTrafficDelta:
    """Bounded traffic and queue-pressure deltas from one verified qdisc."""

    packets: int
    bytes: int
    drops: int
    overlimits: int


def run_command(command: list[str], timeout_seconds: float) -> str:
    """Run one fixed-shape control command and return bounded stdout."""
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("docker executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("network impairment command timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\n", " ")[:300]
        raise RuntimeError(
            f"network impairment command failed: {detail or 'no error text'}"
        )
    return completed.stdout[:16_384]


@dataclass
class DockerNetemImpairment:
    """Apply one bounded, verified netem policy to former-primary egress."""

    interface: str = "eth0"
    delay_ms: int = 200
    jitter_ms: int = 20
    reorder_percent: int = 25
    reorder_correlation_percent: int = 50
    loss_percent: int = 0
    seed: int | None = None
    timeout_seconds: float = 10.0
    runner: CommandRunner = field(default=run_command, repr=False)
    _active: bool = field(default=False, init=False, repr=False)
    _baseline_counters: tuple[int, int, int, int] | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,14}", self.interface) is None:
            raise ValueError("network interface must be an explicit safe Linux name")
        if not 10 <= self.delay_ms <= 2_000:
            raise ValueError("network delay must be in [10, 2000] milliseconds")
        if not 0 <= self.jitter_ms <= min(self.delay_ms, 1_000):
            raise ValueError("network jitter must be in [0, min(delay, 1000)]")
        if not 0 <= self.reorder_percent <= 50:
            raise ValueError("packet reordering must be in [0, 50] percent")
        if not 0 <= self.reorder_correlation_percent <= 100:
            raise ValueError("reordering correlation must be in [0, 100] percent")
        if self.reorder_percent == 0 and self.reorder_correlation_percent != 0:
            raise ValueError("reordering correlation requires packet reordering")
        if not 0 <= self.loss_percent <= 100:
            raise ValueError("packet loss must be in [0, 100] percent")
        if self.seed is not None:
            if (
                isinstance(self.seed, bool)
                or not isinstance(self.seed, int)
                or not 1 <= self.seed <= MAX_COUNTER
            ):
                raise ValueError(
                    "netem seed must be an unsigned nonzero 64-bit integer"
                )
            if self.loss_percent == 0:
                raise ValueError("netem seed requires a packet-loss policy")
        if not 1.0 <= self.timeout_seconds <= 30.0:
            raise ValueError("network impairment timeout must be in [1, 30]")

    @property
    def active(self) -> bool:
        return self._active

    def apply(self) -> None:
        """Install one bounded root netem qdisc and verify its live policy."""
        if self.active:
            raise RuntimeError("reconnection impairment is already active")
        self.runner(self._tc("add", *self._policy_arguments()), self.timeout_seconds)
        self._active = True
        try:
            self._baseline_counters = self._verify_live_policy()
        except BaseException:
            self._clear(suppress_errors=True)
            raise

    def verify_traffic_observed(
        self, *, require_drops: bool = False, minimum_packets: int = 1
    ) -> QdiscTrafficDelta:
        """Fail closed unless traffic counters advanced under the live policy."""
        if (
            isinstance(minimum_packets, bool)
            or not isinstance(minimum_packets, int)
            or not 1 <= minimum_packets <= 1_000
        ):
            raise ValueError("minimum_packets must be an integer in [1, 1000]")
        if not self.active or self._baseline_counters is None:
            raise RuntimeError("reconnection impairment is not active")
        if require_drops and self.loss_percent == 0:
            raise RuntimeError("drop evidence requires a configured loss policy")
        current = self._verify_live_policy()
        baseline = self._baseline_counters
        if any(
            observed < initial
            for observed, initial in zip(current, baseline, strict=True)
        ):
            raise RuntimeError("reconnection impairment counters regressed")
        delta = QdiscTrafficDelta(
            packets=current[0] - baseline[0],
            bytes=current[1] - baseline[1],
            drops=current[2] - baseline[2],
            overlimits=current[3] - baseline[3],
        )
        if require_drops:
            if delta.drops < 1:
                raise RuntimeError(
                    "no packet drops were recorded under the loss policy"
                )
            if delta.packets + delta.drops < minimum_packets:
                raise RuntimeError("insufficient traffic traversed the loss policy")
        elif delta.packets < minimum_packets or delta.bytes < 1:
            raise RuntimeError("no reconnection traffic traversed the impairment")
        return delta

    def clear(self) -> None:
        """Remove the exact qdisc; a second clear is a safe no-op."""
        self._clear(suppress_errors=False)

    def _clear(self, *, suppress_errors: bool) -> None:
        if not self.active:
            return
        try:
            self.runner(self._tc("del", "root", "handle", HANDLE), self.timeout_seconds)
            self._active = False
            self._verify_absent()
            self._baseline_counters = None
        except BaseException as exc:
            if not suppress_errors:
                raise RuntimeError("reconnection impairment cleanup failed") from exc

    def _verify_live_policy(self) -> tuple[int, int, int, int]:
        document = self._qdisc_document()
        matches = [
            entry
            for entry in document
            if entry.get("kind") == "netem"
            and entry.get("handle") == HANDLE
            and entry.get("root") is True
        ]
        if len(matches) != 1:
            raise RuntimeError(
                "live reconnection impairment was not installed exactly once"
            )
        options = matches[0].get("options")
        if not isinstance(options, dict):
            raise RuntimeError("live reconnection impairment options are unavailable")
        delay = options.get("delay")
        reorder = options.get("reorder")
        if not isinstance(delay, dict):
            raise RuntimeError("live reconnection impairment options are incomplete")
        expected: list[tuple[object, float]] = [
            (delay.get("delay"), self.delay_ms / 1_000),
            (delay.get("jitter"), self.jitter_ms / 1_000),
        ]
        if self.reorder_percent:
            if not isinstance(reorder, dict):
                raise RuntimeError(
                    "live reconnection impairment options are incomplete"
                )
            expected.extend(
                (
                    (reorder.get("reorder"), self.reorder_percent / 100),
                    (
                        reorder.get("correlation"),
                        self.reorder_correlation_percent / 100,
                    ),
                )
            )
        elif reorder is not None:
            raise RuntimeError("live reconnection impairment does not match policy")
        loss = options.get("loss-random")
        if self.loss_percent:
            if not isinstance(loss, dict):
                raise RuntimeError(
                    "live reconnection impairment options are incomplete"
                )
            expected.extend(
                (
                    (loss.get("loss"), self.loss_percent / 100),
                    (loss.get("correlation"), 0.0),
                )
            )
        elif loss is not None:
            raise RuntimeError("live reconnection impairment does not match policy")
        observed_seed = options.get("seed")
        if self.seed is not None:
            if (
                isinstance(observed_seed, bool)
                or not isinstance(observed_seed, int)
                or observed_seed != self.seed
            ):
                raise RuntimeError("live reconnection impairment seed does not match")
        if (
            options.get("loss-state") is not None
            or options.get("loss-gemodel") is not None
        ):
            raise RuntimeError("live reconnection impairment does not match policy")
        if any(
            not isinstance(observed, (int, float))
            or abs(observed - required) > 0.000001
            for observed, required in expected
        ):
            raise RuntimeError("live reconnection impairment does not match policy")
        return self._traffic_counters(matches[0])

    @staticmethod
    def _traffic_counters(entry: dict[str, Any]) -> tuple[int, int, int, int]:
        values: list[int] = []
        for name in ("packets", "bytes", "drops", "overlimits"):
            value = entry.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= MAX_COUNTER
            ):
                raise RuntimeError(
                    f"live reconnection impairment {name} counter is invalid"
                )
            values.append(value)
        return values[0], values[1], values[2], values[3]

    def _verify_absent(self) -> None:
        if any(
            entry.get("kind") == "netem" and entry.get("handle") == HANDLE
            for entry in self._qdisc_document()
        ):
            self._active = True
            raise RuntimeError("reconnection impairment remained after cleanup")

    def _qdisc_document(self) -> list[dict[str, Any]]:
        raw = self.runner(self._show_command(), self.timeout_seconds)
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("tc returned malformed qdisc evidence") from exc
        if not isinstance(document, list) or len(document) > 16:
            raise RuntimeError("tc returned an invalid qdisc document")
        if not all(isinstance(item, dict) for item in document):
            raise RuntimeError("tc returned an invalid qdisc entry")
        return document

    def _policy_arguments(self) -> tuple[str, ...]:
        policy = (
            "root",
            "handle",
            HANDLE,
            "netem",
            "delay",
            f"{self.delay_ms}ms",
            f"{self.jitter_ms}ms",
        )
        if self.reorder_percent:
            policy += (
                "reorder",
                f"{self.reorder_percent}%",
                f"{self.reorder_correlation_percent}%",
            )
        if self.loss_percent:
            policy += ("loss", "random", f"{self.loss_percent}%")
        if self.seed is not None:
            policy += ("seed", str(self.seed))
        return policy

    def _tc(self, action: str, *arguments: str) -> list[str]:
        return [
            "docker",
            "compose",
            "exec",
            "-T",
            "--user",
            "0",
            SERVICE,
            "tc",
            "qdisc",
            action,
            "dev",
            self.interface,
            *arguments,
        ]

    def _show_command(self) -> list[str]:
        return [
            "docker",
            "compose",
            "exec",
            "-T",
            "--user",
            "0",
            SERVICE,
            "tc",
            "-statistics",
            "-json",
            "qdisc",
            "show",
            "dev",
            self.interface,
        ]
