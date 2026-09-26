from __future__ import annotations

import asyncio
import json
import math

import pytest
from tools.dns_cache import (
    AsyncDNSCache,
    DNSCachePolicy,
    DNSLookupError,
    ResolverAnswer,
    ResolverFailure,
    normalize_hostname,
)


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def run(coroutine):
    return asyncio.run(coroutine)


def test_positive_answer_is_canonicalized_cached_and_privacy_safe():
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        assert (hostname, qtype) == ("xn--bcher-kva.example", "A")
        return ResolverAnswer(("192.0.2.1", "192.0.2.1", "192.0.2.2"), 30)

    cache = AsyncDNSCache(resolver)
    first = run(cache.resolve("Bücher.Example.", "A"))
    second = run(cache.resolve("xn--bcher-kva.example", "A"))

    assert calls == 1
    assert first.source == "resolver"
    assert second.source == "cache"
    assert first.addresses == ("192.0.2.1", "192.0.2.2")
    encoded = json.dumps(first.evidence())
    assert "Bücher" not in encoded
    assert "192.0.2.1" not in encoded


def test_ttl_is_clamped_and_expiry_refreshes():
    clock = Clock()
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        return ResolverAnswer((f"192.0.2.{calls}",), 0.01)

    cache = AsyncDNSCache(
        resolver,
        policy=DNSCachePolicy(min_ttl_seconds=2, stale_if_error_seconds=0),
        clock=clock,
    )
    first = run(cache.resolve("api.example", "A"))
    clock.advance(1.9)
    cached = run(cache.resolve("api.example", "A"))
    clock.advance(0.1)
    refreshed = run(cache.resolve("api.example", "A"))

    assert first.ttl_clamped is True
    assert cached.addresses == ("192.0.2.1",)
    assert refreshed.addresses == ("192.0.2.2",)
    assert calls == 2


@pytest.mark.parametrize("code", ["NXDOMAIN", "NODATA"])
def test_negative_answers_are_cached_without_stale_positive_fallback(code):
    clock = Clock()
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ResolverAnswer(("2001:db8::1",), 1)
        raise ResolverFailure(code, retryable=False, negative_ttl_seconds=10)

    cache = AsyncDNSCache(resolver, clock=clock)
    run(cache.resolve("api.example", "AAAA"))
    clock.advance(1)
    with pytest.raises(DNSLookupError) as first:
        run(cache.resolve("api.example", "AAAA"))
    with pytest.raises(DNSLookupError) as second:
        run(cache.resolve("api.example", "AAAA"))

    assert first.value.code == code and first.value.cached is False
    assert second.value.code == code and second.value.cached is True
    assert calls == 2


def test_transient_failure_serves_bounded_stale_then_uses_backoff():
    clock = Clock()
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ResolverAnswer(("192.0.2.10",), 2)
        raise ResolverFailure("SERVFAIL", retryable=True)

    cache = AsyncDNSCache(
        resolver,
        policy=DNSCachePolicy(stale_if_error_seconds=10, transient_backoff_seconds=3),
        clock=clock,
    )
    run(cache.resolve("api.example", "A"))
    clock.advance(2)
    stale = run(cache.resolve("api.example", "A"))
    backed_off = run(cache.resolve("api.example", "A"))

    assert stale.source == "stale"
    assert stale.refresh_error_code == "SERVFAIL"
    assert backed_off.source == "stale_backoff"
    assert calls == 2


def test_stale_backoff_expiry_allows_recovery_refresh():
    clock = Clock()
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ResolverAnswer(("192.0.2.10",), 1)
        if calls == 2:
            raise ResolverFailure("SERVFAIL", retryable=True)
        return ResolverAnswer(("192.0.2.11",), 30)

    cache = AsyncDNSCache(
        resolver,
        policy=DNSCachePolicy(stale_if_error_seconds=10, transient_backoff_seconds=2),
        clock=clock,
    )
    run(cache.resolve("api.example", "A"))
    clock.advance(1)
    assert run(cache.resolve("api.example", "A")).source == "stale"
    clock.advance(2)
    recovered = run(cache.resolve("api.example", "A"))

    assert recovered.source == "resolver"
    assert recovered.addresses == ("192.0.2.11",)
    assert recovered.refresh_error_code is None
    assert calls == 3


def test_stale_window_expiry_returns_cached_transient_error():
    clock = Clock()
    calls = 0

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ResolverAnswer(("192.0.2.10",), 1)
        raise TimeoutError

    cache = AsyncDNSCache(
        resolver,
        policy=DNSCachePolicy(stale_if_error_seconds=1, transient_backoff_seconds=2),
        clock=clock,
    )
    run(cache.resolve("api.example", "A"))
    clock.advance(2.1)
    with pytest.raises(DNSLookupError) as first:
        run(cache.resolve("api.example", "A"))
    with pytest.raises(DNSLookupError) as second:
        run(cache.resolve("api.example", "A"))

    assert first.value.code == "TIMEOUT" and first.value.cached is False
    assert second.value.code == "TIMEOUT" and second.value.cached is True
    assert calls == 2


def test_concurrent_miss_is_single_flight():
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return ResolverAnswer(("192.0.2.20",), 30)

    async def scenario():
        cache = AsyncDNSCache(resolver)
        tasks = [asyncio.create_task(cache.resolve("api.example", "A")) for _ in range(50)]
        await started.wait()
        release.set()
        results = await asyncio.gather(*tasks)
        return cache, results

    cache, results = run(scenario())
    assert calls == 1
    assert {item.addresses for item in results} == {("192.0.2.20",)}
    assert run(cache.snapshot())["inflight"] == 0


def test_cancelling_one_waiter_does_not_cancel_shared_refresh():
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, qtype):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return ResolverAnswer(("192.0.2.30",), 30)

    async def scenario():
        cache = AsyncDNSCache(resolver)
        cancelled = asyncio.create_task(cache.resolve("api.example", "A"))
        survivor = asyncio.create_task(cache.resolve("api.example", "A"))
        await started.wait()
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release.set()
        return await survivor

    result = run(scenario())
    assert result.addresses == ("192.0.2.30",)
    assert calls == 1


def test_cancelled_only_waiter_does_not_leak_inflight_capacity():
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, qtype):
        started.set()
        await release.wait()
        return ResolverAnswer(("192.0.2.31",), 30)

    async def scenario():
        cache = AsyncDNSCache(resolver, policy=DNSCachePolicy(max_inflight=1))
        waiter = asyncio.create_task(cache.resolve("api.example", "A"))
        await started.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        for _ in range(10):
            if (await cache.snapshot())["inflight"] == 0:
                break
            await asyncio.sleep(0)
        return await cache.snapshot()

    assert run(scenario())["inflight"] == 0


def test_cancelled_only_waiter_does_not_leak_background_failure():
    started = asyncio.Event()
    release = asyncio.Event()
    loop_errors = []

    async def resolver(hostname, qtype):
        started.set()
        await release.wait()
        raise ResolverFailure("SERVFAIL", retryable=True)

    async def scenario():
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
        cache = AsyncDNSCache(resolver)
        waiter = asyncio.create_task(cache.resolve("api.example", "A"))
        await started.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        for _ in range(10):
            if (await cache.snapshot())["inflight"] == 0:
                break
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        return await cache.snapshot()

    assert run(scenario())["inflight"] == 0
    assert loop_errors == []


def test_distinct_key_inflight_budget_fails_fast():
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, qtype):
        started.set()
        await release.wait()
        return ResolverAnswer(("192.0.2.40",), 30)

    async def scenario():
        cache = AsyncDNSCache(resolver, policy=DNSCachePolicy(max_inflight=1))
        first = asyncio.create_task(cache.resolve("a.example", "A"))
        await started.wait()
        with pytest.raises(DNSLookupError) as raised:
            await cache.resolve("b.example", "A")
        release.set()
        await first
        return raised.value

    error = run(scenario())
    assert error.code == "INFLIGHT_LIMIT"
    assert error.cached is False


def test_lru_entry_budget_evicts_oldest_key():
    calls: list[str] = []

    async def resolver(hostname, qtype):
        calls.append(hostname)
        return ResolverAnswer(("192.0.2.50",), 30)

    cache = AsyncDNSCache(resolver, policy=DNSCachePolicy(max_entries=2))
    run(cache.resolve("a.example", "A"))
    run(cache.resolve("b.example", "A"))
    run(cache.resolve("a.example", "A"))
    run(cache.resolve("c.example", "A"))
    run(cache.resolve("b.example", "A"))

    assert calls == ["a.example", "b.example", "c.example", "b.example"]
    assert run(cache.snapshot())["entries"] == 2


@pytest.mark.parametrize(
    "hostname",
    ["", " api.example", "api..example", "-api.example", "api-.example", "127.0.0.1", "a.."],
)
def test_rejects_malformed_or_literal_hostname(hostname):
    with pytest.raises(ValueError):
        normalize_hostname(hostname)


@pytest.mark.parametrize("qtype", ["a", "TXT", "", None])
def test_rejects_unsupported_query_type(qtype):
    async def resolver(hostname, query_type):  # pragma: no cover
        raise AssertionError

    with pytest.raises(ValueError):
        run(AsyncDNSCache(resolver).resolve("api.example", qtype))


@pytest.mark.parametrize(
    ("qtype", "addresses"),
    [
        ("A", ("2001:db8::1",)),
        ("AAAA", ("192.0.2.1",)),
        ("A", ("bad",)),
        ("AAAA", ("fe80::1%eth0",)),
        ("A", ()),
        ("A", ["192.0.2.1"]),
    ],
)
def test_invalid_resolver_answer_fails_closed_and_is_briefly_cached(qtype, addresses):
    calls = 0

    async def resolver(hostname, query_type):
        nonlocal calls
        calls += 1
        return ResolverAnswer(addresses, 30)

    cache = AsyncDNSCache(resolver)
    with pytest.raises(DNSLookupError) as first:
        run(cache.resolve("api.example", qtype))
    with pytest.raises(DNSLookupError) as second:
        run(cache.resolve("api.example", qtype))

    assert first.value.code == "INVALID_RESPONSE" and first.value.cached is False
    assert second.value.code == "INVALID_RESPONSE" and second.value.cached is True
    assert calls == 1


def test_address_and_ttl_budgets_fail_closed():
    async def too_many(hostname, qtype):
        return ResolverAnswer(tuple(f"192.0.2.{index}" for index in range(1, 4)), 30)

    cache = AsyncDNSCache(too_many, policy=DNSCachePolicy(max_addresses=2))
    with pytest.raises(DNSLookupError, match="INVALID_RESPONSE"):
        run(cache.resolve("api.example", "A"))

    async def nonfinite(hostname, qtype):
        return ResolverAnswer(("192.0.2.1",), math.nan)

    with pytest.raises(DNSLookupError, match="INVALID_RESPONSE"):
        run(AsyncDNSCache(nonfinite).resolve("api.example", "A"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_ttl_seconds": True},
        {"min_ttl_seconds": 5, "max_ttl_seconds": 4},
        {"stale_if_error_seconds": -1},
        {"refresh_timeout_seconds": math.inf},
        {"max_entries": 0},
        {"max_inflight": "many"},
    ],
)
def test_invalid_policy_is_rejected(kwargs):
    async def resolver(hostname, qtype):  # pragma: no cover
        raise AssertionError

    with pytest.raises(ValueError):
        AsyncDNSCache(resolver, policy=DNSCachePolicy(**kwargs))


def test_unknown_resolver_exception_is_redacted():
    async def resolver(hostname, qtype):
        raise RuntimeError("secret provider diagnostic")

    cache = AsyncDNSCache(resolver)
    with pytest.raises(DNSLookupError) as raised:
        run(cache.resolve("api.example", "A"))

    assert raised.value.code == "RESOLVER_ERROR"
    assert "secret provider diagnostic" not in json.dumps(raised.value.evidence())


def test_snapshot_is_content_free_and_counts_entry_types():
    async def resolver(hostname, qtype):
        if hostname == "missing.example":
            raise ResolverFailure("NXDOMAIN", retryable=False, negative_ttl_seconds=30)
        return ResolverAnswer(("192.0.2.60",), 30)

    cache = AsyncDNSCache(resolver)
    run(cache.resolve("api.example", "A"))
    with pytest.raises(DNSLookupError):
        run(cache.resolve("missing.example", "A"))
    snapshot = run(cache.snapshot())

    assert snapshot == {
        "entries": 2,
        "positive_entries": 1,
        "negative_entries": 1,
        "transient_entries": 0,
        "inflight": 0,
        "max_entries": 1024,
        "max_inflight": 64,
    }
    assert "example" not in json.dumps(snapshot)
