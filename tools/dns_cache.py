"""Bounded asynchronous DNS cache with single-flight refresh and stale fallback."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import math
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, NoReturn

QueryType = Literal["A", "AAAA"]
Source = Literal["resolver", "cache", "stale", "stale_backoff"]
Resolver = Callable[[str, QueryType], Awaitable["ResolverAnswer"]]
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NEGATIVE_CODES = frozenset({"NXDOMAIN", "NODATA"})


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _integer(name: str, value: object, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        _fail(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def _number(
    name: str,
    value: object,
    lower: float,
    upper: float,
    *,
    lower_inclusive: bool = True,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{name} must be numeric")
    result = float(value)
    lower_ok = result >= lower if lower_inclusive else result > lower
    if not math.isfinite(result) or not lower_ok or result > upper:
        opening = "[" if lower_inclusive else "("
        _fail(f"{name} must be finite and in {opening}{lower}, {upper}]")
    return result


def _error_code(value: object) -> str:
    if not isinstance(value, str) or _ERROR_CODE.fullmatch(value) is None:
        _fail("DNS error code must be a stable uppercase identifier")
    return value


def normalize_hostname(value: object) -> str:
    """Return a strict lower-case IDNA hostname without a trailing root dot."""
    if not isinstance(value, str) or not value or len(value) > 254:
        _fail("hostname must be a non-empty bounded string")
    if value != value.strip() or any(
        ord(character) < 33 or ord(character) == 127 for character in value
    ):
        _fail("hostname must not contain whitespace or control characters")
    candidate = value.removesuffix(".")
    if not candidate or candidate.endswith("."):
        _fail("hostname has an invalid root label")
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("hostname must be valid IDNA") from exc
    if len(normalized) > 253 or any(
        _LABEL.fullmatch(label) is None for label in normalized.split(".")
    ):
        _fail("hostname contains an invalid label")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return normalized
    _fail("IP literals do not require DNS resolution")


@dataclass(frozen=True)
class DNSCachePolicy:
    min_ttl_seconds: float = 1.0
    max_ttl_seconds: float = 300.0
    max_negative_ttl_seconds: float = 30.0
    transient_backoff_seconds: float = 1.0
    stale_if_error_seconds: float = 60.0
    refresh_timeout_seconds: float = 2.0
    max_entries: int = 1024
    max_inflight: int = 64
    max_addresses: int = 32

    def validate(self) -> None:
        minimum = _number("min_ttl_seconds", self.min_ttl_seconds, 0.001, 86_400.0)
        maximum = _number("max_ttl_seconds", self.max_ttl_seconds, 0.001, 86_400.0)
        if minimum > maximum:
            _fail("min_ttl_seconds must not exceed max_ttl_seconds")
        _number("max_negative_ttl_seconds", self.max_negative_ttl_seconds, 0.001, 86_400.0)
        _number("transient_backoff_seconds", self.transient_backoff_seconds, 0.001, 300.0)
        _number("stale_if_error_seconds", self.stale_if_error_seconds, 0.0, 86_400.0)
        _number("refresh_timeout_seconds", self.refresh_timeout_seconds, 0.001, 300.0)
        _integer("max_entries", self.max_entries, 1, 1_000_000)
        _integer("max_inflight", self.max_inflight, 1, 100_000)
        _integer("max_addresses", self.max_addresses, 1, 10_000)


@dataclass(frozen=True)
class ResolverAnswer:
    addresses: tuple[str, ...]
    ttl_seconds: float


class ResolverFailure(Exception):
    """Typed resolver failure without provider exception leakage."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool,
        negative_ttl_seconds: float | None = None,
    ) -> None:
        super().__init__(code)
        self.code = _error_code(code)
        self.retryable = retryable
        if not isinstance(retryable, bool):
            _fail("retryable must be a boolean")
        if retryable and negative_ttl_seconds is not None:
            _fail("retryable failures cannot declare a negative TTL")
        if not retryable and code not in _NEGATIVE_CODES:
            _fail("permanent resolver failures must be NXDOMAIN or NODATA")
        if not retryable and negative_ttl_seconds is None:
            _fail("permanent resolver failures require a negative TTL")
        self.negative_ttl_seconds = (
            None
            if negative_ttl_seconds is None
            else _number("negative_ttl_seconds", negative_ttl_seconds, 0.001, 86_400.0)
        )


class DNSLookupError(Exception):
    """Stable public lookup error."""

    def __init__(self, code: str, *, cached: bool, hostname_sha256: str, qtype: QueryType) -> None:
        super().__init__(code)
        self.code = _error_code(code)
        self.cached = cached
        self.hostname_sha256 = hostname_sha256
        self.qtype = qtype

    def evidence(self) -> dict[str, object]:
        return {
            "code": self.code,
            "cached": self.cached,
            "hostname_sha256": self.hostname_sha256,
            "qtype": self.qtype,
        }


@dataclass(frozen=True)
class DNSResult:
    addresses: tuple[str, ...]
    source: Source
    hostname_sha256: str
    qtype: QueryType
    ttl_seconds: float
    ttl_clamped: bool
    refresh_error_code: str | None = None

    def evidence(self) -> dict[str, object]:
        return {
            "source": self.source,
            "hostname_sha256": self.hostname_sha256,
            "qtype": self.qtype,
            "address_count": len(self.addresses),
            "address_sha256": [
                hashlib.sha256(item.encode("ascii")).hexdigest() for item in self.addresses
            ],
            "ttl_seconds": self.ttl_seconds,
            "ttl_clamped": self.ttl_clamped,
            "refresh_error_code": self.refresh_error_code,
        }


@dataclass
class _Entry:
    kind: Literal["positive", "negative", "transient"]
    addresses: tuple[str, ...]
    expires_at: float
    stale_until: float
    original_ttl: float
    ttl_clamped: bool
    error_code: str | None = None
    retry_after: float = 0.0


class AsyncDNSCache:
    """Concurrency-safe DNS result cache with bounded state and refresh work."""

    def __init__(
        self,
        resolver: Resolver,
        *,
        policy: DNSCachePolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(resolver) or not callable(clock):
            _fail("resolver and clock must be callable")
        self._resolver = resolver
        self._policy = policy or DNSCachePolicy()
        self._policy.validate()
        self._clock = clock
        self._cache: OrderedDict[tuple[str, QueryType], _Entry] = OrderedDict()
        self._inflight: dict[tuple[str, QueryType], asyncio.Task[DNSResult]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _identity(hostname: str) -> str:
        return hashlib.sha256(hostname.encode("ascii")).hexdigest()

    @staticmethod
    def _consume_background_exception(task: asyncio.Task[DNSResult]) -> None:
        if not task.cancelled():
            task.exception()

    @staticmethod
    def _qtype(value: object) -> QueryType:
        if value not in {"A", "AAAA"}:
            _fail("qtype must be A or AAAA")
        return value  # type: ignore[return-value]

    def _now(self) -> float:
        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            _fail("monotonic clock returned invalid evidence")
        return float(now)

    def _positive_result(
        self,
        hostname: str,
        qtype: QueryType,
        entry: _Entry,
        *,
        source: Source,
        now: float,
    ) -> DNSResult:
        remaining = max(0.0, entry.expires_at - now)
        return DNSResult(
            addresses=entry.addresses,
            source=source,
            hostname_sha256=self._identity(hostname),
            qtype=qtype,
            ttl_seconds=remaining,
            ttl_clamped=entry.ttl_clamped,
            refresh_error_code=entry.error_code if source.startswith("stale") else None,
        )

    def _prune_and_evict(self, now: float) -> None:
        expired = [
            key
            for key, entry in self._cache.items()
            if (entry.kind == "positive" and now > entry.stale_until)
            or (entry.kind != "positive" and now >= entry.expires_at)
        ]
        for key in expired:
            self._cache.pop(key, None)
        while len(self._cache) > self._policy.max_entries:
            self._cache.popitem(last=False)

    async def resolve(self, hostname: object, qtype: object) -> DNSResult:
        normalized = normalize_hostname(hostname)
        query_type = self._qtype(qtype)
        key = (normalized, query_type)
        now = self._now()

        async with self._lock:
            self._prune_and_evict(now)
            entry = self._cache.get(key)
            if entry is not None:
                self._cache.move_to_end(key)
                if entry.kind == "positive" and now < entry.expires_at:
                    return self._positive_result(
                        normalized, query_type, entry, source="cache", now=now
                    )
                if (
                    entry.kind == "positive"
                    and now < entry.stale_until
                    and entry.error_code is not None
                    and now < entry.retry_after
                ):
                    return self._positive_result(
                        normalized, query_type, entry, source="stale_backoff", now=now
                    )
                if entry.kind in {"negative", "transient"} and now < entry.expires_at:
                    raise DNSLookupError(
                        entry.error_code or "RESOLVER_ERROR",
                        cached=True,
                        hostname_sha256=self._identity(normalized),
                        qtype=query_type,
                    )

            task = self._inflight.get(key)
            if task is None:
                if len(self._inflight) >= self._policy.max_inflight:
                    raise DNSLookupError(
                        "INFLIGHT_LIMIT",
                        cached=False,
                        hostname_sha256=self._identity(normalized),
                        qtype=query_type,
                    )
                stale = entry if entry is not None and entry.kind == "positive" else None
                task = asyncio.create_task(self._run_refresh(key, normalized, query_type, stale))
                task.add_done_callback(self._consume_background_exception)
                self._inflight[key] = task

        return await asyncio.shield(task)

    async def _run_refresh(
        self,
        key: tuple[str, QueryType],
        hostname: str,
        qtype: QueryType,
        stale: _Entry | None,
    ) -> DNSResult:
        try:
            return await self._refresh(hostname, qtype, stale)
        finally:
            task = asyncio.current_task()
            async with self._lock:
                if self._inflight.get(key) is task:
                    self._inflight.pop(key, None)

    async def _refresh(
        self,
        hostname: str,
        qtype: QueryType,
        stale: _Entry | None,
    ) -> DNSResult:
        try:
            answer = await asyncio.wait_for(
                self._resolver(hostname, qtype), timeout=self._policy.refresh_timeout_seconds
            )
            entry = self._answer_entry(answer, qtype)
        except TimeoutError:
            return await self._transient_failure(hostname, qtype, stale, "TIMEOUT")
        except ResolverFailure as exc:
            if exc.retryable:
                return await self._transient_failure(hostname, qtype, stale, exc.code)
            await self._store_negative(hostname, qtype, exc)
            raise DNSLookupError(
                exc.code,
                cached=False,
                hostname_sha256=self._identity(hostname),
                qtype=qtype,
            ) from None
        except (ValueError, TypeError):
            return await self._transient_failure(hostname, qtype, stale, "INVALID_RESPONSE")
        except Exception:  # noqa: BLE001 - provider diagnostics must not cross the boundary
            return await self._transient_failure(hostname, qtype, stale, "RESOLVER_ERROR")

        now = self._now()
        key = (hostname, qtype)
        async with self._lock:
            entry.expires_at = now + entry.original_ttl
            entry.stale_until = entry.expires_at + self._policy.stale_if_error_seconds
            self._cache[key] = entry
            self._cache.move_to_end(key)
            self._prune_and_evict(now)
        return self._positive_result(hostname, qtype, entry, source="resolver", now=now)

    def _answer_entry(self, answer: object, qtype: QueryType) -> _Entry:
        if not isinstance(answer, ResolverAnswer):
            _fail("resolver must return ResolverAnswer")
        if not isinstance(answer.addresses, tuple) or not answer.addresses:
            _fail("resolver answer must contain addresses")
        if len(answer.addresses) > self._policy.max_addresses:
            _fail("resolver answer exceeds max_addresses")
        family = 4 if qtype == "A" else 6
        addresses: list[str] = []
        seen: set[str] = set()
        for raw in answer.addresses:
            if not isinstance(raw, str) or raw != raw.strip() or "%" in raw:
                _fail("resolver answer contains a malformed address")
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ValueError("resolver answer contains a malformed address") from exc
            if parsed.version != family:
                _fail("resolver answer address family does not match qtype")
            canonical = str(parsed)
            if canonical not in seen:
                seen.add(canonical)
                addresses.append(canonical)
        if not addresses:
            _fail("resolver answer contains no unique addresses")
        raw_ttl = _number("resolver ttl_seconds", answer.ttl_seconds, 0.0, 86_400.0)
        ttl = min(max(raw_ttl, self._policy.min_ttl_seconds), self._policy.max_ttl_seconds)
        return _Entry(
            kind="positive",
            addresses=tuple(addresses),
            expires_at=0.0,
            stale_until=0.0,
            original_ttl=ttl,
            ttl_clamped=ttl != raw_ttl,
        )

    async def _store_negative(
        self, hostname: str, qtype: QueryType, failure: ResolverFailure
    ) -> None:
        assert failure.negative_ttl_seconds is not None
        ttl = min(failure.negative_ttl_seconds, self._policy.max_negative_ttl_seconds)
        now = self._now()
        entry = _Entry(
            kind="negative",
            addresses=(),
            expires_at=now + ttl,
            stale_until=now + ttl,
            original_ttl=ttl,
            ttl_clamped=ttl != failure.negative_ttl_seconds,
            error_code=failure.code,
        )
        async with self._lock:
            self._cache[(hostname, qtype)] = entry
            self._cache.move_to_end((hostname, qtype))
            self._prune_and_evict(now)

    async def _transient_failure(
        self,
        hostname: str,
        qtype: QueryType,
        stale: _Entry | None,
        code: str,
    ) -> DNSResult:
        stable_code = _error_code(code)
        now = self._now()
        key = (hostname, qtype)
        if stale is not None and now < stale.stale_until:
            stale.error_code = stable_code
            stale.retry_after = min(stale.stale_until, now + self._policy.transient_backoff_seconds)
            async with self._lock:
                self._cache[key] = stale
                self._cache.move_to_end(key)
            return self._positive_result(hostname, qtype, stale, source="stale", now=now)

        entry = _Entry(
            kind="transient",
            addresses=(),
            expires_at=now + self._policy.transient_backoff_seconds,
            stale_until=now + self._policy.transient_backoff_seconds,
            original_ttl=self._policy.transient_backoff_seconds,
            ttl_clamped=False,
            error_code=stable_code,
        )
        async with self._lock:
            self._cache[key] = entry
            self._cache.move_to_end(key)
            self._prune_and_evict(now)
        raise DNSLookupError(
            stable_code,
            cached=False,
            hostname_sha256=self._identity(hostname),
            qtype=qtype,
        )

    async def snapshot(self) -> dict[str, int]:
        """Return bounded, content-free cache state for metrics or diagnostics."""
        now = self._now()
        async with self._lock:
            self._prune_and_evict(now)
            counts = {"positive": 0, "negative": 0, "transient": 0}
            for entry in self._cache.values():
                counts[entry.kind] += 1
            return {
                "entries": len(self._cache),
                "positive_entries": counts["positive"],
                "negative_entries": counts["negative"],
                "transient_entries": counts["transient"],
                "inflight": len(self._inflight),
                "max_entries": self._policy.max_entries,
                "max_inflight": self._policy.max_inflight,
            }
