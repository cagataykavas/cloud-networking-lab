"""Bounded Docker/iptables controller for a disposable one-way lab partition."""

from __future__ import annotations

import ipaddress
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field


RULE_COMMENT = "cloud-networking-lab-one-way-partition"
SERVICE = "redis_election_primary"
CommandRunner = Callable[[list[str], float], None]


def run_command(command: list[str], timeout_seconds: float) -> None:
    """Run one fixed-shape control command without exposing its output."""
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
        raise RuntimeError("partition control command timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\n", " ")[:300]
        raise RuntimeError(
            f"partition control command failed: {detail or 'no error text'}"
        )


@dataclass
class DockerEgressPartition:
    """Drop only primary-to-peer traffic, preserving host-to-primary access."""

    peers: Sequence[str]
    timeout_seconds: float = 10.0
    runner: CommandRunner = field(default=run_command, repr=False)
    _installed: list[str] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if not 1 <= len(self.peers) <= 8:
            raise ValueError("partition requires between one and eight peers")
        normalized: list[str] = []
        for value in self.peers:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(
                    "partition peers must be explicit IP addresses"
                ) from exc
            if (
                address.version != 4
                or not address.is_private
                or address.is_loopback
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ValueError(
                    "partition peers must be private non-loopback IPv4 addresses"
                )
            normalized.append(str(address))
        if len(set(normalized)) != len(normalized):
            raise ValueError("partition peers must be distinct")
        if not 1.0 <= self.timeout_seconds <= 30.0:
            raise ValueError("partition timeout must be in [1, 30]")
        self.peers = tuple(normalized)

    @property
    def active(self) -> bool:
        return bool(self._installed)

    def isolate(self) -> None:
        """Install one OUTPUT drop rule per peer and verify every rule."""
        if self.active:
            raise RuntimeError("one-way partition is already active")
        try:
            for peer in self.peers:
                self.runner(
                    self._iptables("-I", peer, position="1"), self.timeout_seconds
                )
                self._installed.append(peer)
            for peer in self.peers:
                self.runner(self._iptables("-C", peer), self.timeout_seconds)
        except BaseException:
            self._remove_installed(suppress_errors=True)
            raise

    def heal(self) -> None:
        """Remove all installed rules; a second heal is a safe no-op."""
        self._remove_installed(suppress_errors=False)

    def _remove_installed(self, *, suppress_errors: bool) -> None:
        first_error: BaseException | None = None
        failed: list[str] = []
        for peer in reversed(self._installed):
            try:
                self.runner(self._iptables("-D", peer), self.timeout_seconds)
            except BaseException as exc:
                first_error = first_error or exc
                failed.append(peer)
        self._installed = list(reversed(failed))
        if first_error is not None and not suppress_errors:
            raise RuntimeError("one-way partition cleanup failed") from first_error

    @staticmethod
    def _iptables(action: str, peer: str, *, position: str | None = None) -> list[str]:
        command = [
            "docker",
            "compose",
            "exec",
            "-T",
            "--user",
            "0",
            SERVICE,
            "iptables",
            "-w",
            "5",
            action,
            "OUTPUT",
        ]
        if position is not None:
            command.append(position)
        return [
            *command,
            "-d",
            peer,
            "-m",
            "comment",
            "--comment",
            RULE_COMMENT,
            "-j",
            "DROP",
        ]
