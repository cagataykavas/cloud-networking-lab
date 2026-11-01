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
    """Delay and reorder former-primary egress while the topology heals."""

    interface: str = "eth0"
    delay_ms: int = 200
    jitter_ms: int = 20
    reorder_percent: int = 25
    reorder_correlation_percent: int = 50
    timeout_seconds: float = 10.0
    runner: CommandRunner = field(default=run_command, repr=False)
    _active: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,14}", self.interface) is None:
            raise ValueError("network interface must be an explicit safe Linux name")
        if not 10 <= self.delay_ms <= 2_000:
            raise ValueError("network delay must be in [10, 2000] milliseconds")
        if not 0 <= self.jitter_ms <= min(self.delay_ms, 1_000):
            raise ValueError("network jitter must be in [0, min(delay, 1000)]")
        if not 1 <= self.reorder_percent <= 50:
            raise ValueError("packet reordering must be in [1, 50] percent")
        if not 0 <= self.reorder_correlation_percent <= 100:
            raise ValueError("reordering correlation must be in [0, 100] percent")
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
            self._verify_live_policy()
        except BaseException:
            self._clear(suppress_errors=True)
            raise

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
        except BaseException as exc:
            if not suppress_errors:
                raise RuntimeError("reconnection impairment cleanup failed") from exc

    def _verify_live_policy(self) -> None:
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
        if not isinstance(delay, dict) or not isinstance(reorder, dict):
            raise RuntimeError("live reconnection impairment options are incomplete")
        expected = (
            (delay.get("delay"), self.delay_ms / 1_000),
            (delay.get("jitter"), self.jitter_ms / 1_000),
            (reorder.get("reorder"), self.reorder_percent / 100),
            (
                reorder.get("correlation"),
                self.reorder_correlation_percent / 100,
            ),
        )
        if any(
            not isinstance(observed, (int, float))
            or abs(observed - required) > 0.000001
            for observed, required in expected
        ):
            raise RuntimeError("live reconnection impairment does not match policy")

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
        except json.JSONDecodeError as exc:
            raise RuntimeError("tc returned malformed qdisc evidence") from exc
        if not isinstance(document, list) or len(document) > 16:
            raise RuntimeError("tc returned an invalid qdisc document")
        if not all(isinstance(item, dict) for item in document):
            raise RuntimeError("tc returned an invalid qdisc entry")
        return document

    def _policy_arguments(self) -> tuple[str, ...]:
        return (
            "root",
            "handle",
            HANDLE,
            "netem",
            "delay",
            f"{self.delay_ms}ms",
            f"{self.jitter_ms}ms",
            "reorder",
            f"{self.reorder_percent}%",
            f"{self.reorder_correlation_percent}%",
        )

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
            "-json",
            "qdisc",
            "show",
            "dev",
            self.interface,
        ]
