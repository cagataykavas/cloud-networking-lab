from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.redis_promotion_authority import SQLitePromotionAuthority
from tools.redis_sentinel_promotion import (
    SentinelPromotionPolicy,
    SentinelPromotionRejected,
    SentinelPromotionUnavailable,
    derive_sentinel_promotion,
    observe_sentinel_consensus,
    observe_sentinel_promotion,
)


RUN_ID = "a" * 40
REPL_ID = "b" * 40
NOW = 1_800_000_000


def sentinel_reply(**changes: str) -> list[bytes]:
    fields = {
        "name": "replay-primary",
        "ip": "10.0.0.12",
        "port": "6379",
        "runid": RUN_ID,
        "flags": "master",
        "last-ok-ping-reply": "17",
        "info-refresh": "23",
        "role-reported": "master",
        "config-epoch": "42",
        "num-other-sentinels": "2",
        "quorum": "2",
    }
    fields.update(changes)
    return [
        item.encode("ascii")
        for pair in fields.items()
        for item in pair
    ]


def candidate_info(
    *,
    role: str = "master",
    replid: str = REPL_ID,
    offset: int = 1_250,
) -> dict[str, str | int]:
    return {
        "role": role,
        "master_replid": replid,
        "master_repl_offset": offset,
    }


def policy(**changes: Any) -> SentinelPromotionPolicy:
    values = {
        "master_name": "replay-primary",
        "candidate_host": "10.0.0.12",
        "candidate_port": 6379,
        "minimum_config_epoch": 40,
        "max_info_age_ms": 1_000,
        "max_ping_age_ms": 1_000,
    }
    values.update(changes)
    return SentinelPromotionPolicy(**values)


class FakeSentinel:
    def __init__(
        self,
        reply: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.reply = sentinel_reply() if reply is None else reply
        self.error = error
        self.calls: list[tuple[str, ...]] = []

    def execute_command(self, *args: str) -> Any:
        self.calls.append(args)
        if self.error is not None:
            raise self.error
        return self.reply


class FakeCandidate:
    def __init__(
        self,
        document: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.document = candidate_info() if document is None else document
        self.error = error
        self.calls: list[str] = []

    def info(self, section: str) -> Any:
        self.calls.append(section)
        if self.error is not None:
            raise self.error
        return self.document


def derive(
    *,
    reply: Any = None,
    info: Any = None,
    selected_policy: SentinelPromotionPolicy | None = None,
    floor: int = 1_200,
):
    return derive_sentinel_promotion(
        sentinel_reply() if reply is None else reply,
        candidate_info() if info is None else info,
        selected_policy or policy(),
        minimum_replication_offset=floor,
        observed_at=NOW,
    )


def test_observes_live_clients_and_advances_authority(tmp_path: Path) -> None:
    sentinel = FakeSentinel()
    candidate = FakeCandidate()
    decision = observe_sentinel_promotion(
        sentinel,
        candidate,
        policy(),
        minimum_replication_offset=1_200,
        observed_at=NOW,
    )
    authority = SQLitePromotionAuthority(
        tmp_path / "authority.db",
        "edge-replay",
    )

    state = decision.advance(authority, expected_state_sha256=None)

    assert sentinel.calls == [
        ("SENTINEL", "MASTER", "replay-primary")
    ]
    assert candidate.calls == ["replication"]
    assert state.authority_epoch == 42
    assert state.candidate_id == RUN_ID
    assert state.minimum_replication_offset == 1_200
    assert state.replid_sha256 == decision.snapshot.replid_sha256
    assert state.schema_version == 2
    assert state.source_sha256 == decision.source_sha256


def test_source_commitment_is_bound_into_authority_head(tmp_path: Path) -> None:
    authority = SQLitePromotionAuthority(
        tmp_path / "authority.db",
        "edge-replay",
    )
    first_decision = derive()
    first = first_decision.advance(authority, expected_state_sha256=None)
    second_decision = derive(
        reply=sentinel_reply(**{"config-epoch": "43"}),
        info=candidate_info(offset=1_300),
        floor=1_250,
    )
    second = second_decision.advance(
        authority,
        expected_state_sha256=first.state_sha256,
    )

    assert first.source_sha256 == first_decision.source_sha256
    assert second.source_sha256 == second_decision.source_sha256
    assert second.previous_state_sha256 == first.state_sha256
    assert second.state_sha256 != first.state_sha256
    assert authority.snapshot() == second


def test_three_observers_bind_unanimous_view_into_authority(tmp_path: Path) -> None:
    candidate = FakeCandidate()
    observers = {
        "sentinel-c": FakeSentinel(sentinel_reply(**{"last-ok-ping-reply": "19"})),
        "sentinel-a": FakeSentinel(),
        "sentinel-b": FakeSentinel(sentinel_reply(**{"info-refresh": "29"})),
    }

    decision = observe_sentinel_consensus(
        observers,
        candidate,
        policy(),
        minimum_replication_offset=1_200,
        observed_at=NOW,
    )
    reordered = observe_sentinel_consensus(
        {
            observer_id: FakeSentinel(observers[observer_id].reply)
            for observer_id in reversed(observers)
        },
        FakeCandidate(),
        policy(),
        minimum_replication_offset=1_200,
        observed_at=NOW,
    )
    state = decision.advance(
        SQLitePromotionAuthority(tmp_path / "authority.db", "edge-replay"),
        expected_state_sha256=None,
    )

    assert candidate.calls == ["replication"]
    assert all(
        observer.calls == [("SENTINEL", "MASTER", "replay-primary")]
        for observer in observers.values()
    )
    assert decision.source_sha256 == reordered.source_sha256
    assert state.source_sha256 == decision.source_sha256
    assert "sentinel-a" not in repr(decision)


@pytest.mark.parametrize(
    "change",
    [
        {"config-epoch": "43"},
        {"runid": "c" * 40},
    ],
)
def test_consensus_rejects_dissenting_safe_view(change: dict[str, str]) -> None:
    observers = {
        "sentinel-a": FakeSentinel(),
        "sentinel-b": FakeSentinel(),
        "sentinel-c": FakeSentinel(sentinel_reply(**change)),
    }

    with pytest.raises(SentinelPromotionRejected, match="observers_disagree"):
        observe_sentinel_consensus(
            observers,
            FakeCandidate(),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )


def test_consensus_fails_closed_on_missing_or_reused_observer() -> None:
    shared = FakeSentinel()
    with pytest.raises(ValueError, match="between 3 and 9"):
        observe_sentinel_consensus(
            {"sentinel-a": shared, "sentinel-b": FakeSentinel()},
            FakeCandidate(),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )

    with pytest.raises(ValueError, match="distinct client instances"):
        observe_sentinel_consensus(
            {
                "sentinel-a": shared,
                "sentinel-b": shared,
                "sentinel-c": FakeSentinel(),
            },
            FakeCandidate(),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )


def test_consensus_normalizes_observer_transport_failures() -> None:
    observers = {
        "sentinel-a": FakeSentinel(),
        "sentinel-b": FakeSentinel(error=OSError("secret endpoint")),
        "sentinel-c": FakeSentinel(),
    }

    with pytest.raises(
        SentinelPromotionUnavailable,
        match="sentinel_consensus_observation_unavailable",
    ):
        observe_sentinel_consensus(
            observers,
            FakeCandidate(),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )


def test_accepts_mapping_reply_and_returns_stable_commitment() -> None:
    reply = {
        key.decode("ascii"): value.decode("ascii")
        for key, value in zip(
            sentinel_reply()[::2],
            sentinel_reply()[1::2],
        )
    }

    first = derive(reply=reply)
    second = derive(reply=reply)

    assert first == second
    assert len(first.source_sha256) == 64
    assert REPL_ID not in repr(first)


def test_commitment_changes_with_election_epoch() -> None:
    first = derive()
    second = derive(reply=sentinel_reply(**{"config-epoch": "43"}))

    assert first.source_sha256 != second.source_sha256


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"ip": "10.0.0.99"}, "endpoint_mismatch"),
        ({"port": "6380"}, "endpoint_mismatch"),
        ({"name": "other-primary"}, "name_mismatch"),
        ({"runid": "not-a-run-id"}, "runid_invalid"),
        ({"flags": "slave"}, "not_master"),
        ({"role-reported": "slave"}, "role_not_master"),
        ({"config-epoch": "39"}, "epoch_too_old"),
        ({"info-refresh": "1001"}, "info_stale"),
        ({"last-ok-ping-reply": "1001"}, "ping_stale"),
        ({"num-other-sentinels": "0", "quorum": "2"}, "quorum_unreachable"),
    ],
)
def test_rejects_untrusted_sentinel_state(
    changes: dict[str, str],
    reason: str,
) -> None:
    with pytest.raises(SentinelPromotionRejected, match=reason):
        derive(reply=sentinel_reply(**changes))


@pytest.mark.parametrize(
    "unsafe_flag",
    ["s_down", "o_down", "disconnected", "failover_in_progress"],
)
def test_rejects_unsafe_sentinel_flags(unsafe_flag: str) -> None:
    with pytest.raises(
        SentinelPromotionRejected,
        match=f"sentinel_candidate_unsafe:{unsafe_flag}",
    ):
        derive(reply=sentinel_reply(flags=f"master,{unsafe_flag}"))


def test_rejects_duplicate_odd_missing_and_non_ascii_fields() -> None:
    duplicate = sentinel_reply() + [b"name", b"replay-primary"]
    with pytest.raises(SentinelPromotionRejected, match="duplicate_field:name"):
        derive(reply=duplicate)

    with pytest.raises(SentinelPromotionRejected, match="odd_length"):
        derive(reply=sentinel_reply()[:-1])

    missing = sentinel_reply()[:-2]
    with pytest.raises(SentinelPromotionRejected, match="missing_fields"):
        derive(reply=missing)

    invalid = sentinel_reply()
    invalid[0] = b"\xff"
    with pytest.raises(SentinelPromotionRejected, match="non_ascii"):
        derive(reply=invalid)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"config-epoch": "-1"}, "invalid_integer:config-epoch"),
        ({"port": "0"}, "integer_out_of_range:port"),
        ({"quorum": "NaN"}, "invalid_integer:quorum"),
    ],
)
def test_rejects_malformed_sentinel_integers(
    changes: dict[str, str],
    reason: str,
) -> None:
    with pytest.raises(SentinelPromotionRejected, match=reason):
        derive(reply=sentinel_reply(**changes))


def test_rejects_non_master_candidate_and_offset_below_floor() -> None:
    with pytest.raises(SentinelPromotionRejected, match="candidate_role_not_master"):
        derive(info=candidate_info(role="slave"))

    with pytest.raises(
        SentinelPromotionRejected,
        match="candidate_offset_below_floor",
    ):
        derive(info=candidate_info(offset=1_199))


@pytest.mark.parametrize(
    "invalid_info",
    [
        None,
        [],
        {"role": "master"},
        {
            "role": "master",
            "master_replid": REPL_ID,
            "master_repl_offset": -1,
        },
    ],
)
def test_rejects_invalid_candidate_info(invalid_info: Any) -> None:
    value = object() if invalid_info is None else invalid_info
    with pytest.raises(SentinelPromotionRejected, match="candidate_info_invalid"):
        derive(info=value)


def test_wraps_live_observation_failures_without_diagnostics() -> None:
    with pytest.raises(
        SentinelPromotionUnavailable,
        match="sentinel_master_observation_unavailable",
    ):
        observe_sentinel_promotion(
            FakeSentinel(error=OSError("secret sentinel endpoint")),
            FakeCandidate(),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )

    with pytest.raises(
        SentinelPromotionUnavailable,
        match="candidate_replication_observation_unavailable",
    ):
        observe_sentinel_promotion(
            FakeSentinel(),
            FakeCandidate(error=OSError("secret candidate endpoint")),
            policy(),
            minimum_replication_offset=1_200,
            observed_at=NOW,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_host": "host with spaces"},
        {"candidate_port": 0},
        {"minimum_config_epoch": 0},
        {"max_info_age_ms": 60_001},
        {"max_ping_age_ms": -1},
    ],
)
def test_policy_rejects_unsafe_bounds(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        policy(**changes)
