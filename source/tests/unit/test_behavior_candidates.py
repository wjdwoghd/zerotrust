"""S2 synthetic scenarios; --noconftest prevents DB initialization/reseeding."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from core.behavior_candidates import SyntheticDetectionRules, generate_synthetic_candidates
from core.behavior_timeline import (
    SyntheticTimeline, TimelineSnapshot, TimelineGrant, TimelineLimits, TimelineError,
)


START = datetime(2026, 10, 22, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


def _rules(**changes):
    return SyntheticDetectionRules(**{
        "window": timedelta(minutes=10), "min_accesses": 3, "same_target": "resource_id",
        "cross_session": False, "normal_handling": "exclude_confirmed", **changes,
    })


def _event(row_id, minute, kind="ACCESS_DECISION", **changes):
    return {"table": "access_logs" if kind == "ACCESS_DECISION" else "audit_logs",
            "id": row_id, "event_type": kind, "actor_ref": "user:1",
            "occurred_at": START + timedelta(minutes=minute), "signal_quality": "synthetic",
            "resource_ref": "resource:1", "session_ref": "session:1", "action": "view",
            "outcome": "denied", "request_ref": f"access-evaluation:{row_id}", **changes}


def _records():
    return [_event(1, 0), _event(2, 1),
            _event(3, 2, "ADMIN_APPROVAL_REQUESTED", request_ref="resource-approval:1", outcome="pending"),
            _event(4, 3, outcome="allowed")]


def _run(records=None, *, rules=None, gaps=(), grant=None, **fixtures):
    records = _records() if records is None else records
    timeline = SyntheticTimeline(records, observed_at=END, missing_ranges=gaps)
    return generate_synthetic_candidates(
        timeline, rules=rules or _rules(), actor_ref="user:1", start=START, end=END,
        limits=TimelineLimits(timedelta(hours=2), 2),
        grant=grant or TimelineGrant(frozenset({"user:1"}),
                                    frozenset(f"{r['table']}:{r['id']}" for r in records)), **fixtures)


def _c2(results):
    return [r for r in results if r["type"] == "C2"]


def test_c2_candidates_are_deterministic_scoped_and_read_only():
    records = _records()
    before = deepcopy(records)
    result = _c2(_run(records))[0]
    assert result["status"] == "candidate"
    assert result["observed_facts"]["access_count"] == 3
    assert result["intent"] == "not_determined"
    assert result["observed_facts"]["causal_link"] == "not_established"
    assert set(result["evidence_refs"]) == {"access_logs:1", "access_logs:2", "access_logs:4", "audit_logs:3"}
    assert _run(records) == _run(list(reversed(records)))
    assert records == before


@pytest.mark.parametrize("minimum,status", [(2, "candidate"), (3, "candidate"), (4, "excluded")])
def test_minimum_boundary(minimum, status):
    assert _c2(_run(rules=_rules(min_accesses=minimum)))[0]["status"] == status


@pytest.mark.parametrize("seconds,status", [(179, "excluded"), (180, "candidate"), (181, "candidate")])
def test_sliding_period_boundary(seconds, status):
    assert _c2(_run(rules=_rules(window=timedelta(seconds=seconds))))[0]["status"] == status


@pytest.mark.parametrize("reason", ["approved_retry", "justified_bg", "emergency_cooperation"])
def test_confirmed_normal_controls_and_mark_only(reason):
    refs = ["access_logs:1", "access_logs:2", "audit_logs:3", "access_logs:4"]
    normal = [{"synthetic": True, "reason": reason, "evidence_refs": refs}]
    assert _c2(_run(normal_fixtures=normal))[0]["status"] == "excluded"
    result = _c2(_run(rules=_rules(normal_handling="mark_only"), normal_fixtures=normal))[0]
    assert result["status"] == "candidate"
    assert result["normal_exceptions"] == [reason]
    normal[0]["evidence_refs"] = refs[:1]
    assert _c2(_run(normal_fixtures=normal))[0]["status"] == "candidate"


@pytest.mark.parametrize("change", ["target", "actor", "session", "unknown_target", "ordering"])
def test_unrelated_or_unordered_sequences_are_not_joined(change):
    records = _records()
    if change == "ordering":
        records[2]["occurred_at"] = START - timedelta(minutes=1)
    else:
        field, value = {"target": ("resource_ref", "resource:2"), "actor": ("actor_ref", "user:2"),
                        "session": ("session_ref", "session:2"), "unknown_target": ("resource_ref", None)}[change]
        records[2][field] = value
    assert _c2(_run(records)) == []


def test_session_crossing_requires_explicit_experiment_choice():
    records = _records()
    records[2]["session_ref"] = "session:2"
    assert _c2(_run(records)) == []
    assert _c2(_run(records, rules=_rules(cross_session=True)))[0]["status"] == "candidate"


@pytest.mark.parametrize("change", ["duplicate", "missing_id", "missing_session", "gap"])
def test_uncertainty_never_becomes_candidate(change):
    records = _records()
    gaps = ()
    if change == "duplicate":
        records[1]["request_ref"] = records[0]["request_ref"]
    elif change == "missing_id":
        records[0]["request_ref"] = None
    elif change == "missing_session":
        for record in records:
            record["session_ref"] = None
    else:
        gaps = ({"start": START, "end": START + timedelta(minutes=1), "reason": "missing_source"},)
    assert _c2(_run(records, gaps=gaps))[0]["status"] == "insufficient_evidence"


def test_access_audit_duplicates_and_bg_usage_do_not_inflate_count():
    records = _records()
    records.append(_event(5, 0, table="audit_logs", request_ref="access-evaluation:1"))
    records.append(_event(6, 0, "BREAK_GLASS_USED", request_ref="access-evaluation:1"))
    result = _c2(_run(records))[0]
    assert result["observed_facts"]["access_count"] == 3
    assert "audit_logs:5" in result["evidence_refs"]
    assert "audit_logs:6" not in result["evidence_refs"]


def _purpose_fixture(**changes):
    return {"audit_logs:3": {"synthetic": True, "historical_scope_confirmed": True,
                             "allowed_resources": ["resource:1"], "allowed_actions": ["view"], **changes}}


@pytest.mark.parametrize("fixture,status", [
    ({}, "insufficient_evidence"),
    (_purpose_fixture(), "insufficient_evidence"),
    (_purpose_fixture(allowed_actions=["download"]), "candidate"),
    (_purpose_fixture(allowed_resources=["resource:2"]), "candidate"),
    (_purpose_fixture(historical_scope_confirmed=False), "insufficient_evidence"),
])
def test_c1_structured_scope_and_missing_semantic_evidence(fixture, status):
    records = _records()
    records[-1]["request_ref"] = "resource-approval:1"
    result = [r for r in _run(records, purpose_fixtures=fixture) if r["type"] == "C1"][0]
    assert result["status"] == status
    assert result["evidence_refs"] == ["access_logs:4", "audit_logs:3"]


def test_c1_bg_scope_and_normal_reason_with_purpose_drift():
    # A neutral work reason would not change structured download scope mismatch.
    records = [_event(3, 1, "BREAK_GLASS_ACTIVATED", activation_ref="bg:1", outcome="recorded"),
               _event(4, 2, activation_ref="bg:1", action="download", outcome="allowed")]
    result = _run(records, purpose_fixtures=_purpose_fixture())[0]
    assert result["type"] == "C1" and result["status"] == "candidate"
    records[-1]["activation_ref"] = None
    assert _run(records, purpose_fixtures=_purpose_fixture()) == []


def test_sparse_logs_do_not_create_a_repeated_sequence():
    assert _run([_event(1, 1, outcome="allowed")]) == []
    assert _run([]) == []


@pytest.mark.parametrize("kind", ["ADMIN_APPROVAL_REQUESTED", "CASE_ASSIGNMENT_REQUESTED", "BREAK_GLASS_ACTIVATED"])
def test_normal_purpose_scope_controls(kind):
    records = [_event(3, 1, kind, activation_ref="bg:1", request_ref="assignment:1"),
               _event(4, 2, activation_ref="bg:1", request_ref="assignment:1", outcome="allowed")]
    normal = [{"synthetic": True, "reason": "emergency_cooperation",
               "evidence_refs": ["audit_logs:3", "access_logs:4"]}]
    result = _run(records, purpose_fixtures=_purpose_fixture(), normal_fixtures=normal)[0]
    assert result["type"] == "C1" and result["status"] == "excluded"


@pytest.mark.parametrize("minute,expected", [(1, []), (11, ["candidate"]), (12, [])])
def test_c1_time_boundary_requires_strictly_later_usage(minute, expected):
    records = [_event(3, 1, "BREAK_GLASS_ACTIVATED", activation_ref="bg:1"),
               _event(4, minute, activation_ref="bg:1", action="download", outcome="allowed")]
    assert [r["status"] for r in _run(records, purpose_fixtures=_purpose_fixture())] == expected


def test_c1_gap_prevents_confirmed_mismatch_candidate():
    records = [_event(3, 1, "BREAK_GLASS_ACTIVATED", activation_ref="bg:1"),
               _event(4, 2, activation_ref="bg:1", action="download", outcome="allowed")]
    gaps = [{"start": START, "end": START + timedelta(minutes=3), "reason": "missing_source"}]
    assert _run(records, gaps=gaps, purpose_fixtures=_purpose_fixture())[0]["status"] == "insufficient_evidence"


def test_out_of_scope_fixture_and_real_projection_are_rejected():
    with pytest.raises(TimelineError, match="out-of-scope"):
        _run(normal_fixtures=[{"synthetic": True, "reason": "approved_retry", "evidence_refs": ["audit_logs:999"]}])
    with pytest.raises(TimelineError, match="out-of-scope"):
        _run(purpose_fixtures={"audit_logs:999": _purpose_fixture()["audit_logs:3"]})
    with pytest.raises(TimelineError, match="synthetic timeline"):
        generate_synthetic_candidates(TimelineSnapshot([], observed_at=END), rules=_rules())
    records = _records()
    records[0]["signal_quality"] = "server_recorded"
    with pytest.raises(TimelineError, match="synthetic"):
        _run(records)


def test_evidence_filtering_cannot_recover_hidden_request():
    grant = TimelineGrant(frozenset({"user:1"}), frozenset({"access_logs:1", "access_logs:2", "access_logs:4"}))
    assert _c2(_run(grant=grant)) == []


@pytest.mark.parametrize("changes", [
    {"window": timedelta(0)}, {"min_accesses": True}, {"min_accesses": 1},
    {"same_target": "case_id"}, {"cross_session": 1}, {"normal_handling": "ignore"},
])
def test_no_invalid_or_implicit_operating_rules(changes):
    with pytest.raises(TimelineError):
        _rules(**changes)
