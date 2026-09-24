import asyncio
import json
import math
import socket
from dataclasses import dataclass

import pytest

from tools.happy_eyeballs import (
    DialError,
    DialPolicy,
    open_happy_eyeballs_connection,
    order_candidates,
)


@dataclass
class FakeWriter:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


def run(coroutine):
    return asyncio.run(coroutine)


def test_interleaves_families_and_preserves_family_order() -> None:
    candidates = order_candidates(
        ["2001:db8::1", "2001:db8::2", "192.0.2.1", "192.0.2.2", "2001:0db8::1"]
    )

    assert [item.address for item in candidates] == [
        "2001:db8::1",
        "192.0.2.1",
        "2001:db8::2",
        "192.0.2.2",
    ]
    assert [item.family for item in candidates] == ["ipv6", "ipv4", "ipv6", "ipv4"]


def test_supports_bounded_first_family_preference() -> None:
    candidates = order_candidates(
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2"],
        first_family_count=2,
    )
    assert [item.address for item in candidates] == [
        "192.0.2.1",
        "192.0.2.2",
        "2001:db8::1",
        "192.0.2.3",
        "2001:db8::2",
    ]


@pytest.mark.parametrize(
    "addresses, kwargs",
    [
        ([], {}),
        (["not-an-ip"], {}),
        ([" 192.0.2.1"], {}),
        (["192.0.2.1", "192.0.2.2"], {"max_candidates": 1}),
        (["192.0.2.1"], {"first_family_count": 0}),
    ],
)
def test_rejects_malformed_or_over_budget_candidates(addresses, kwargs) -> None:
    with pytest.raises(ValueError):
        order_candidates(addresses, **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"attempt_delay_seconds": 0.009},
        {"attempt_delay_seconds": 2.001},
        {"attempt_delay_seconds": math.inf},
        {"deadline_seconds": 0},
        {"deadline_seconds": 300.001},
        {"deadline_seconds": math.nan},
        {"first_family_count": True},
        {"max_candidates": 0},
    ],
)
def test_policy_fails_closed_on_invalid_limits(kwargs) -> None:
    with pytest.raises(ValueError):
        DialPolicy(**kwargs)


def test_races_broken_ipv6_without_waiting_for_its_timeout() -> None:
    writers: list[FakeWriter] = []
    calls: list[str] = []

    async def connector(candidate, port, server_hostname, ssl_context):
        calls.append(candidate.address)
        if candidate.family == "ipv6":
            await asyncio.Event().wait()
        writer = FakeWriter()
        writers.append(writer)
        return object(), writer

    result = run(
        open_happy_eyeballs_connection(
            "service.example",
            443,
            ["2001:db8::10", "192.0.2.10"],
            policy=DialPolicy(attempt_delay_seconds=0.01, deadline_seconds=0.5),
            connector=connector,
        )
    )

    assert calls == ["2001:db8::10", "192.0.2.10"]
    assert result.report.winner == "192.0.2.10"
    assert [item.outcome for item in result.report.attempts] == ["cancelled", "connected"]
    assert writers[0].closed is False
    result.writer.close()


def test_fast_preferred_family_cancels_unstarted_attempts() -> None:
    calls: list[str] = []

    async def connector(candidate, port, server_hostname, ssl_context):
        calls.append(candidate.address)
        return object(), FakeWriter()

    result = run(
        open_happy_eyeballs_connection(
            "service.example",
            80,
            ["2001:db8::1", "192.0.2.1"],
            policy=DialPolicy(attempt_delay_seconds=0.05, deadline_seconds=0.5),
            connector=connector,
        )
    )

    assert calls == ["2001:db8::1"]
    assert len(result.report.attempts) == 1
    assert result.report.attempts[0].outcome == "connected"
    result.writer.close()


def test_closes_a_connection_that_loses_a_simultaneous_success_race() -> None:
    both_started = asyncio.Event()
    release = asyncio.Event()
    writers: dict[str, FakeWriter] = {}

    async def connector(candidate, port, server_hostname, ssl_context):
        writers[candidate.address] = FakeWriter()
        if len(writers) == 2:
            both_started.set()
        await release.wait()
        return object(), writers[candidate.address]

    async def scenario():
        task = asyncio.create_task(
            open_happy_eyeballs_connection(
                "service.example",
                443,
                ["2001:db8::1", "192.0.2.1"],
                policy=DialPolicy(attempt_delay_seconds=0.01, deadline_seconds=0.5),
                connector=connector,
            )
        )
        await asyncio.wait_for(both_started.wait(), timeout=0.2)
        release.set()
        return await task

    result = run(scenario())
    loser_addresses = set(writers) - {result.report.winner}

    assert len(loser_addresses) == 1
    assert writers[loser_addresses.pop()].closed is True
    assert sorted(item.outcome for item in result.report.attempts) == [
        "connected",
        "superseded",
    ]
    result.writer.close()


def test_exhausted_candidates_produce_stable_failure_evidence() -> None:
    async def connector(candidate, port, server_hostname, ssl_context):
        raise OSError("private diagnostic detail")

    with pytest.raises(DialError) as raised:
        run(
            open_happy_eyeballs_connection(
                "service.example",
                443,
                ["2001:db8::1", "192.0.2.1"],
                policy=DialPolicy(attempt_delay_seconds=0.01, deadline_seconds=0.5),
                connector=connector,
            )
        )

    report = raised.value.report
    assert report.outcome == "exhausted"
    assert report.winner is None
    assert [item.error_code for item in report.attempts] == [
        "CONNECT_OS_ERROR",
        "CONNECT_OS_ERROR",
    ]
    assert "private diagnostic detail" not in json.dumps(report.to_dict())


def test_global_deadline_cancels_all_started_attempts() -> None:
    async def connector(candidate, port, server_hostname, ssl_context):
        await asyncio.Event().wait()

    with pytest.raises(DialError) as raised:
        run(
            open_happy_eyeballs_connection(
                "service.example",
                443,
                ["2001:db8::1", "192.0.2.1"],
                policy=DialPolicy(attempt_delay_seconds=0.01, deadline_seconds=0.04),
                connector=connector,
            )
        )

    assert raised.value.report.outcome == "deadline"
    assert {item.outcome for item in raised.value.report.attempts} == {"failed", "cancelled"}
    failed = [item for item in raised.value.report.attempts if item.outcome == "failed"]
    assert [item.error_code for item in failed] == ["CONNECT_TIMEOUT"]


def test_connector_receives_original_hostname_for_tls_sni() -> None:
    observed = None

    async def connector(candidate, port, server_hostname, ssl_context):
        nonlocal observed
        observed = (candidate.address, port, server_hostname, ssl_context)
        return object(), FakeWriter()

    context = object()
    result = run(
        open_happy_eyeballs_connection(
            "api.example",
            443,
            ["192.0.2.44"],
            ssl_context=context,
            connector=connector,
        )
    )

    assert observed == ("192.0.2.44", 443, "api.example", context)
    result.writer.close()


def test_real_loopback_connection_uses_default_connector() -> None:
    async def scenario() -> None:
        accepted = asyncio.Event()

        async def handler(reader, writer):
            accepted.set()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0, family=socket.AF_INET)
        port = server.sockets[0].getsockname()[1]
        try:
            result = await open_happy_eyeballs_connection(
                "localhost",
                port,
                ["127.0.0.1"],
                policy=DialPolicy(deadline_seconds=1.0),
            )
            await asyncio.wait_for(accepted.wait(), timeout=1.0)
            assert result.report.outcome == "connected"
            assert result.report.winner == "127.0.0.1"
            result.writer.close()
            await result.writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    run(scenario())


def test_rejects_invalid_connection_contract_before_starting_tasks() -> None:
    with pytest.raises(ValueError):
        run(open_happy_eyeballs_connection(" host", 443, ["192.0.2.1"]))
    with pytest.raises(ValueError):
        run(open_happy_eyeballs_connection("host", 0, ["192.0.2.1"]))
    with pytest.raises(ValueError):
        run(open_happy_eyeballs_connection("host", 443, ["192.0.2.1"], policy="bad"))
