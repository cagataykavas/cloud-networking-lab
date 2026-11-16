from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.path_mtu_audit import PolicyError, audit_path_mtu, main, parse_policy


def policy_payload() -> dict[str, object]:
    return {
        "ip_family": "dual_stack",
        "required_ip_mtu": 1400,
        "segments": [
            {
                "name": "vpc-underlay",
                "link_mtu": 1500,
                "encapsulation_overhead": 0,
                "pmtud_signals_allowed": True,
            },
            {
                "name": "wireguard-tunnel",
                "link_mtu": 1500,
                "encapsulation_overhead": 80,
                "pmtud_signals_allowed": True,
            },
        ],
    }


def test_audit_admits_budgeted_dual_stack_overlay() -> None:
    report = audit_path_mtu(parse_policy(policy_payload()))

    assert report.admitted is True
    assert report.effective_ip_mtu == 1420
    assert report.bottleneck_segments == ("wireguard-tunnel",)
    assert report.recommended_tcp_mss == {"ipv4": 1380, "ipv6": 1360}
    assert report.findings == ()


def test_audit_rejects_oversized_workload_mtu() -> None:
    payload = policy_payload()
    payload["required_ip_mtu"] = 1450

    report = audit_path_mtu(parse_policy(payload))

    assert report.admitted is False
    assert [finding.code for finding in report.findings] == [
        "required_mtu_exceeds_path_budget"
    ]
    assert report.findings[0].segment == "wireguard-tunnel"


def test_audit_rejects_blocked_pmtud_feedback() -> None:
    payload = policy_payload()
    segments = payload["segments"]
    assert isinstance(segments, list)
    segments[0]["pmtud_signals_allowed"] = False

    report = audit_path_mtu(parse_policy(payload))

    assert report.admitted is False
    assert report.findings[0].code == "pmtud_signal_blocked"
    assert report.findings[0].segment == "vpc-underlay"


def test_audit_reports_protocol_floor_and_shared_bottleneck() -> None:
    payload = policy_payload()
    payload["required_ip_mtu"] = 1280
    segments = payload["segments"]
    assert isinstance(segments, list)
    for segment in segments:
        segment["link_mtu"] = 1300
        segment["encapsulation_overhead"] = 40

    report = audit_path_mtu(parse_policy(payload))

    assert report.admitted is False
    assert report.effective_ip_mtu == 1260
    assert report.bottleneck_segments == ("vpc-underlay", "wireguard-tunnel")
    assert [finding.code for finding in report.findings] == [
        "protocol_floor_violation",
        "required_mtu_exceeds_path_budget",
    ]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload.update({"unexpected": True}), "unknown fields"),
        (
            lambda payload: payload.update({"required_ip_mtu": True}),
            "must be an integer",
        ),
        (lambda payload: payload.update({"segments": []}), "non-empty"),
    ],
)
def test_parse_policy_rejects_ambiguous_inputs(mutation, message: str) -> None:
    payload = policy_payload()
    mutation(payload)

    with pytest.raises(PolicyError, match=message):
        parse_policy(payload)


def test_cli_emits_machine_readable_report_and_nonzero_on_denial(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = policy_payload()
    payload["required_ip_mtu"] = 1450
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert main([str(path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["admitted"] is False
    assert output["effective_ip_mtu"] == 1420


def test_cli_rejects_duplicate_json_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        '{"ip_family":"ipv4","ip_family":"ipv6","required_ip_mtu":1280,"segments":[]}',
        encoding="utf-8",
    )

    assert main([str(path)]) == 1
    error = json.loads(capsys.readouterr().err)
    assert "duplicate JSON field" in error["error"]
