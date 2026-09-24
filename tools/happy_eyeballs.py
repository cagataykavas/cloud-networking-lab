"""Bounded dual-stack TCP connection racing inspired by RFC 8305."""

from __future__ import annotations

import asyncio
import math
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any


@dataclass(frozen=True)
class DialPolicy:
    """Resource and timing limits for one connection race."""

    attempt_delay_seconds: float = 0.25
    deadline_seconds: float = 5.0
    first_family_count: int = 1
    max_candidates: int = 32

    def __post_init__(self) -> None:
        _finite_number("attempt_delay_seconds", self.attempt_delay_seconds)
        _finite_number("deadline_seconds", self.deadline_seconds)
        if not 0.01 <= self.attempt_delay_seconds <= 2.0:
            raise ValueError("attempt_delay_seconds must be between 0.01 and 2.0")
        if not 0 < self.deadline_seconds <= 300:
            raise ValueError("deadline_seconds must be positive and at most 300")
        if not _plain_int(self.first_family_count) or not 1 <= self.first_family_count <= 4:
            raise ValueError("first_family_count must be an integer between 1 and 4")
        if not _plain_int(self.max_candidates) or not 1 <= self.max_candidates <= 256:
            raise ValueError("max_candidates must be an integer between 1 and 256")


@dataclass(frozen=True)
class Candidate:
    address: str
    family: str

    @property
    def socket_family(self) -> socket.AddressFamily:
        return socket.AF_INET6 if self.family == "ipv6" else socket.AF_INET


@dataclass(frozen=True)
class AttemptEvidence:
    address: str
    family: str
    started_ms: float
    finished_ms: float
    outcome: str
    error_code: str | None


@dataclass(frozen=True)
class DialReport:
    host: str
    port: int
    outcome: str
    winner: str | None
    total_ms: float
    attempt_delay_ms: float
    deadline_ms: float
    ordered_candidates: tuple[Candidate, ...]
    attempts: tuple[AttemptEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DialSuccess:
    reader: Any
    writer: Any
    report: DialReport


class DialError(ConnectionError):
    """Raised when every candidate fails or the global deadline expires."""

    def __init__(self, report: DialReport) -> None:
        super().__init__(f"dual-stack dial failed: {report.outcome}")
        self.report = report


Connector = Callable[
    [Candidate, int, str | None, ssl.SSLContext | None], Awaitable[tuple[Any, Any]]
]
Clock = Callable[[], float]


@dataclass(frozen=True)
class _AttemptResult:
    index: int
    reader: Any
    writer: Any


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finite_number(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    if not math.isfinite(float(value)):
        raise ValueError(f"{name} must be a finite number")


def order_candidates(
    addresses: Sequence[str],
    *,
    first_family_count: int = 1,
    max_candidates: int = 32,
) -> tuple[Candidate, ...]:
    """Canonicalize, deduplicate and stably interleave IPv4/IPv6 addresses."""
    if isinstance(addresses, (str, bytes)) or not isinstance(addresses, Sequence):
        raise ValueError("addresses must be a sequence of IP address strings")
    if not _plain_int(first_family_count) or not 1 <= first_family_count <= 4:
        raise ValueError("first_family_count must be an integer between 1 and 4")
    if not _plain_int(max_candidates) or not 1 <= max_candidates <= 256:
        raise ValueError("max_candidates must be an integer between 1 and 256")
    if not addresses:
        raise ValueError("at least one address is required")
    if len(addresses) > max_candidates:
        raise ValueError("address count exceeds max_candidates")

    unique: list[IPv4Address | IPv6Address] = []
    seen: set[tuple[int, str]] = set()
    for raw in addresses:
        if not isinstance(raw, str) or not raw or raw.strip() != raw:
            raise ValueError("every address must be a normalized non-empty string")
        try:
            parsed = ip_address(raw)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {raw!r}") from exc
        canonical = str(parsed)
        key = (parsed.version, canonical)
        if key not in seen:
            seen.add(key)
            unique.append(parsed)

    if not unique:
        raise ValueError("at least one unique address is required")

    first_version = unique[0].version
    preferred = [item for item in unique if item.version == first_version]
    alternate = [item for item in unique if item.version != first_version]
    ordered: list[IPv4Address | IPv6Address] = []

    ordered.extend(preferred[:first_family_count])
    preferred_index = min(first_family_count, len(preferred))
    alternate_index = 0
    while preferred_index < len(preferred) or alternate_index < len(alternate):
        if alternate_index < len(alternate):
            ordered.append(alternate[alternate_index])
            alternate_index += 1
        if preferred_index < len(preferred):
            ordered.append(preferred[preferred_index])
            preferred_index += 1

    return tuple(Candidate(str(item), "ipv6" if item.version == 6 else "ipv4") for item in ordered)


async def _default_connector(
    candidate: Candidate,
    port: int,
    server_hostname: str | None,
    ssl_context: ssl.SSLContext | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(
        host=candidate.address,
        port=port,
        family=candidate.socket_family,
        ssl=ssl_context,
        server_hostname=server_hostname if ssl_context is not None else None,
    )


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "CONNECT_TIMEOUT"
    if isinstance(exc, OSError):
        return "CONNECT_OS_ERROR"
    return "CONNECTOR_ERROR"


def _close_writer(writer: Any) -> None:
    close = getattr(writer, "close", None)
    if callable(close):
        close()


async def open_happy_eyeballs_connection(
    host: str,
    port: int,
    addresses: Sequence[str],
    *,
    policy: DialPolicy = DialPolicy(),
    ssl_context: ssl.SSLContext | None = None,
    connector: Connector = _default_connector,
    clock: Clock = time.monotonic,
) -> DialSuccess:
    """Race ordered IP candidates and return the first established connection.

    DNS resolution is intentionally outside this function. The caller supplies a
    snapshot of A/AAAA answers, which makes address provenance and caching policy
    explicit and keeps the dialer's global deadline independent of resolver behavior.
    """
    if not isinstance(host, str) or not host or host.strip() != host:
        raise ValueError("host must be a normalized non-empty string")
    if not _plain_int(port) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if not isinstance(policy, DialPolicy):
        raise ValueError("policy must be a DialPolicy")

    candidates = order_candidates(
        addresses,
        first_family_count=policy.first_family_count,
        max_candidates=policy.max_candidates,
    )
    started = clock()
    deadline = started + policy.deadline_seconds
    evidence: dict[int, AttemptEvidence] = {}

    async def attempt(index: int, candidate: Candidate) -> _AttemptResult | None:
        delay = index * policy.attempt_delay_seconds
        if delay:
            await asyncio.sleep(delay)
        attempt_started = clock()
        remaining = deadline - attempt_started
        if remaining <= 0:
            return None
        try:
            async with asyncio.timeout(remaining):
                reader, writer = await connector(candidate, port, host, ssl_context)
            if not callable(getattr(writer, "close", None)):
                raise TypeError("connector writer must provide close()")
            finished = clock()
            evidence[index] = AttemptEvidence(
                candidate.address,
                candidate.family,
                round((attempt_started - started) * 1000, 3),
                round((finished - started) * 1000, 3),
                "connected",
                None,
            )
            return _AttemptResult(index, reader, writer)
        except asyncio.CancelledError:
            finished = clock()
            evidence[index] = AttemptEvidence(
                candidate.address,
                candidate.family,
                round((attempt_started - started) * 1000, 3),
                round((finished - started) * 1000, 3),
                "cancelled",
                None,
            )
            raise
        except Exception as exc:
            finished = clock()
            evidence[index] = AttemptEvidence(
                candidate.address,
                candidate.family,
                round((attempt_started - started) * 1000, 3),
                round((finished - started) * 1000, 3),
                "failed",
                _error_code(exc),
            )
            return None

    tasks = [
        asyncio.create_task(attempt(index, candidate), name=f"dial-{index}-{candidate.address}")
        for index, candidate in enumerate(candidates)
    ]
    winner: _AttemptResult | None = None
    timed_out = False
    try:
        remaining = max(0.0, deadline - clock())
        async with asyncio.timeout(remaining):
            for completed in asyncio.as_completed(tasks):
                result = await completed
                if result is not None:
                    winner = result
                    break
    except TimeoutError:
        timed_out = True
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, _AttemptResult) and (winner is None or result.index != winner.index):
            _close_writer(result.writer)
            item = evidence[result.index]
            evidence[result.index] = AttemptEvidence(
                item.address,
                item.family,
                item.started_ms,
                item.finished_ms,
                "superseded",
                None,
            )

    finished = clock()
    attempts = tuple(evidence[index] for index in sorted(evidence))
    report = DialReport(
        host=host,
        port=port,
        outcome="connected" if winner is not None else ("deadline" if timed_out else "exhausted"),
        winner=candidates[winner.index].address if winner is not None else None,
        total_ms=round((finished - started) * 1000, 3),
        attempt_delay_ms=round(policy.attempt_delay_seconds * 1000, 3),
        deadline_ms=round(policy.deadline_seconds * 1000, 3),
        ordered_candidates=candidates,
        attempts=attempts,
    )
    if winner is None:
        raise DialError(report)
    return DialSuccess(winner.reader, winner.writer, report)
