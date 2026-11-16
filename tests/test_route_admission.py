from dataclasses import replace

import pytest

from tools.route_admission import (
    OriginAuthorization,
    RouteAdmissionError,
    RouteAnnouncement,
    RoutePolicy,
    audit_route_announcements,
)


POLICY = RoutePolicy(local_asn=64512, max_as_path_length=8)
AUTHORIZATIONS = [
    OriginAuthorization("203.0.113.0/24", 64496, 25),
    OriginAuthorization("2001:db8:100::/48", 64497, 64),
]


def route(
    prefix: str = "203.0.113.0/24",
    origin: int = 64496,
    path: tuple[int, ...] = (64500, 64496),
) -> RouteAnnouncement:
    return RouteAnnouncement(prefix, origin, path)


def test_accepts_authorized_ipv4_and_ipv6_announcements() -> None:
    report = audit_route_announcements(
        [
            route(),
            route("2001:db8:100:1::/64", 64497, (64501, 64497, 64497)),
        ],
        AUTHORIZATIONS,
        POLICY,
    )

    assert report.accepted
    assert report.accepted_count == 2
    assert report.rejected_count == 0
    assert report.routes[0].matched_authorization == "203.0.113.0/24"
    assert report.routes[1].matched_authorization == "2001:db8:100::/48"


def test_report_and_digest_are_input_order_independent() -> None:
    announcements = [
        route("203.0.113.0/25"),
        route("203.0.113.0/25", path=(64502, 64496)),
        route("2001:db8:100:1::/64", 64497, (64501, 64497)),
    ]

    first = audit_route_announcements(announcements, AUTHORIZATIONS, POLICY)
    second = audit_route_announcements(
        reversed(announcements), reversed(AUTHORIZATIONS), POLICY
    )

    assert first == second
    assert len(first.evidence_sha256) == 64


@pytest.mark.parametrize(
    ("announcement", "finding"),
    [
        (route(origin=64498, path=(64500, 64498)), "unauthorized_origin"),
        (route("203.0.113.128/26"), "prefix_too_specific"),
        (route("198.51.100.0/24"), "unregistered_prefix"),
        (route(path=(64500, 64498)), "as_path_origin_mismatch"),
        (route(path=(64500, 64512, 64496)), "local_asn_loop"),
        (route(path=(1, 2, 3, 4, 5, 6, 7, 8, 64496)), "as_path_too_long"),
    ],
)
def test_rejects_route_policy_violations(
    announcement: RouteAnnouncement, finding: str
) -> None:
    report = audit_route_announcements([announcement], AUTHORIZATIONS, POLICY)

    assert not report.accepted
    assert finding in report.routes[0].findings
    assert report.rejected_count == 1


def test_default_route_requires_explicit_policy_and_authorization() -> None:
    authorization = OriginAuthorization("0.0.0.0/0", 64496, 0)
    announcement = route("0.0.0.0/0", 64496, (64496,))

    rejected = audit_route_announcements([announcement], [authorization], POLICY)
    accepted = audit_route_announcements(
        [announcement], [authorization], replace(POLICY, allow_default_route=True)
    )

    assert rejected.routes[0].findings == ("default_route_not_allowed",)
    assert accepted.accepted


def test_origin_prepending_is_not_mistaken_for_a_loop() -> None:
    report = audit_route_announcements(
        [route(path=(64500, 64496, 64496, 64496))], AUTHORIZATIONS, POLICY
    )

    assert report.accepted


@pytest.mark.parametrize(
    "prefix",
    ["203.0.113.1/24", "not-a-prefix", "2001:db8:100::1/48"],
)
def test_noncanonical_or_invalid_prefixes_fail_closed(prefix: str) -> None:
    with pytest.raises(RouteAdmissionError, match="canonical"):
        audit_route_announcements([route(prefix)], AUTHORIZATIONS, POLICY)


def test_duplicate_and_oversized_evidence_fail_closed() -> None:
    announcement = route()
    with pytest.raises(RouteAdmissionError, match="duplicate route"):
        audit_route_announcements([announcement, announcement], AUTHORIZATIONS, POLICY)

    with pytest.raises(RouteAdmissionError, match="record budget"):
        audit_route_announcements(
            [route(), route("203.0.113.0/25")],
            AUTHORIZATIONS,
            replace(POLICY, max_announcements=1),
        )


def test_empty_evidence_fails_closed() -> None:
    with pytest.raises(RouteAdmissionError, match="announcements must not be empty"):
        audit_route_announcements([], AUTHORIZATIONS, POLICY)

    with pytest.raises(RouteAdmissionError, match="authorizations must not be empty"):
        audit_route_announcements([route()], [], POLICY)


def test_authorization_contract_rejects_ambiguity_and_invalid_length() -> None:
    duplicate = [AUTHORIZATIONS[0], AUTHORIZATIONS[0]]
    with pytest.raises(RouteAdmissionError, match="duplicate prefix-origin"):
        audit_route_announcements([route()], duplicate, POLICY)

    invalid = [OriginAuthorization("203.0.113.0/24", 64496, 23)]
    with pytest.raises(RouteAdmissionError, match="outside the prefix family"):
        audit_route_announcements([route()], invalid, POLICY)


@pytest.mark.parametrize("asn", [0, 4_294_967_295, True, 1.5])
def test_invalid_asns_fail_closed(asn: object) -> None:
    with pytest.raises(RouteAdmissionError, match="ASN"):
        audit_route_announcements([route(origin=asn)], AUTHORIZATIONS, POLICY)
