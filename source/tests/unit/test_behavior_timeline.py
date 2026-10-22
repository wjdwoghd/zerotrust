"""S1 synthetic contract checks; run with --noconftest to avoid any DB setup."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from core.behavior_timeline import (
    SyntheticTimeline, TimelineAccessDenied, TimelineError, TimelineGrant, TimelineLimits,
)


START = datetime(2026, 10, 22, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
OBSERVED = END + timedelta(hours=1)
LIMITS = TimelineLimits(max_period=timedelta(days=1), max_page_size=20)


def _record(row_id=1, table="audit_logs", **changes):
    return {"table": table, "id": row_id, "event_type": "LOGIN_FAILED",
            "occurred_at": START, "actor_ref": "user:1", "signal_quality": "synthetic", **changes}


def _grant(records, actors=frozenset({"user:1"})):
    return TimelineGrant(actors, frozenset(f"{r['table']}:{r['id']}" for r in records))


def _scope(records, **changes):
    return {"actor_ref": "user:1", "start": START, "end": END,
            "grant": _grant(records), "limits": LIMITS, **changes}


def _query(records, **changes):
    return SyntheticTimeline(records, observed_at=OBSERVED).query(
        **_scope(records, **changes), page_size=20)


def _access(row_id=1, **changes):
    return _record(row_id, "access_logs", **{"event_type": "ACCESS_DECISION",
                   "resource_ref": "resource:20", "request_ref": "access-evaluation:abc",
                   "session_ref": "session:3", "action": "download", "outcome": "allowed", **changes})


def _audit(row_id=2, **changes):
    return _record(row_id, **{"event_type": "ACCESS_DECISION", "resource_ref": "resource:20",
                   "request_ref": "access-evaluation:abc", **changes})


def test_half_open_period_utc_kst_and_stable_equal_timestamp_order():
    records = [_record(3, occurred_at=END), _record(2),
               _record(1, occurred_at="2026-10-22T09:00:00+09:00"),
               _record(4, occurred_at=START - timedelta(microseconds=1))]
    page = _query(records)
    assert [e["event_key"] for e in page["events"]] == ["audit_logs:1", "audit_logs:2"]
    assert all(e["occurred_at"] == START.isoformat() for e in page["events"])
    assert page == _query(list(reversed(records)))


def test_verified_access_audit_pair_preserves_sources_and_bg_is_a_relation():
    records = [_audit(occurred_at=START + timedelta(seconds=1)), _access(),
               _record(3, event_type="BREAK_GLASS_USED", resource_ref="resource:20",
                       request_ref="access-evaluation:abc", activation_ref="bg:4")]
    page = _query(records)
    assert len(page["events"]) == 2
    access, bg = page["events"]
    assert access["evidence_refs"] == ["access_logs:1", "audit_logs:2"]
    assert access["sources"][1]["occurred_at"] == (START + timedelta(seconds=1)).isoformat()
    assert "session_ref_unavailable" not in access["unknown_reasons"]
    assert "action_unavailable" not in access["unknown_reasons"]
    assert "outcome_unavailable" not in access["unknown_reasons"]
    assert "download_completion_unrecorded" in access["unknown_reasons"]
    assert bg["relations"] == [{"type": "shares_access_evaluation", "event_key": access["event_key"]}]
    assert page == _query(list(reversed(records)))


@pytest.mark.parametrize("extra", [
    _access(3), _audit(4),
])
def test_non_unique_request_key_never_merges(extra):
    records = [_access(), _audit(), extra]
    events = _query(records)["events"]
    assert len(events) == 3
    assert all("ambiguous_evaluation_key" in e["unknown_reasons"] for e in events)


@pytest.mark.parametrize("field,value", [
    ("actor_ref", "user:2"), ("resource_ref", "resource:21"),
    ("request_ref", "http:abc"), ("request_ref", "resource-approval:abc"),
])
def test_same_user_time_or_unrelated_id_spaces_do_not_prove_one_action(field, value):
    audit = _audit(**{field: value})
    records = [_access(), audit]
    snapshot = SyntheticTimeline(records, observed_at=OBSERVED)
    events = snapshot.query(**_scope(records), page_size=20)["events"]
    assert events[0]["evidence_refs"] == ["access_logs:1"]
    assert all(len(e["evidence_refs"]) == 1 for e in events)


@pytest.mark.parametrize("changes", [
    {"session_ref": "session:other"}, {"activation_ref": "bg:other", "action": "view"},
    {"outcome": "denied"},
])
def test_conflicting_pair_is_preserved_without_fabricated_facts(changes):
    events = _query([_access(), _audit(**changes)])["events"]
    assert len(events) == 2
    assert all("conflicting_evaluation_records" in e["unknown_reasons"] for e in events)


def test_missing_counterpart_and_unverified_duplicate_are_distinct():
    events = _query([_access(), _record(2, event_type="ACCESS_DECISION")])["events"]
    assert "access_or_audit_counterpart_missing" in events[0]["unknown_reasons"]
    assert "possible_duplicate_unverified" in events[1]["unknown_reasons"]


def test_same_subject_different_cases_and_sessions_have_no_causal_link():
    records = [_record(1, case_ref="case:A", session_ref="session:1"),
               _record(2, case_ref="case:B", session_ref="session:2")]
    assert all(e["relations"] == [] for e in _query(records)["events"])


def test_pagination_never_loses_equal_timestamp_events_and_does_not_shrink_period():
    records = [_record(i) for i in range(1, 12)]
    snapshot = SyntheticTimeline(records, observed_at=OBSERVED)
    scope = _scope(records)
    cursor, keys = None, []
    while True:
        page = snapshot.query(**scope, page_size=3, cursor=cursor)
        keys.extend(e["event_key"] for e in page["events"])
        assert page["start"] == START.isoformat() and page["end"] == END.isoformat()
        assert page["truncated"] == (page["next_cursor"] is not None)
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(keys) == len(set(keys)) == 11
    assert keys == sorted(keys)


@pytest.mark.parametrize("change", ["actor", "period", "grant", "snapshot", "page_size"])
def test_cursor_cannot_cross_scope_or_snapshot(change):
    records = [_record(1), _record(2), _record(3)]
    snapshot = SyntheticTimeline(records, observed_at=OBSERVED)
    scope = _scope(records)
    cursor = snapshot.query(**scope, page_size=1)["next_cursor"]
    page_size = 1
    if change == "actor":
        scope.update(actor_ref="user:2", grant=_grant(records, frozenset({"user:1", "user:2"})))
    elif change == "period":
        scope["end"] = END + timedelta(minutes=1)
    elif change == "grant":
        scope["grant"] = _grant(records[:2])
    elif change == "snapshot":
        snapshot = SyntheticTimeline(records + [_record(4)], observed_at=OBSERVED)
    else:
        page_size = 2
    with pytest.raises(TimelineError, match="cursor"):
        snapshot.query(**scope, page_size=page_size, cursor=cursor)


@pytest.mark.parametrize("cursor", ["garbage", "W10=", "bnVsbA==", "e30=", "x" * 1025, 3])
def test_malformed_cursor_fails_explicitly(cursor):
    records = [_record()]
    with pytest.raises(TimelineError):
        SyntheticTimeline(records, observed_at=OBSERVED).query(**_scope(records), page_size=1, cursor=cursor)


@pytest.mark.parametrize("changes", [
    {"start": START.replace(tzinfo=None)}, {"end": START},
    {"end": START + timedelta(days=2)},
    {"limits": TimelineLimits(timedelta(0), 1)},
])
def test_period_and_injected_bounds_are_validated(changes):
    with pytest.raises(TimelineError):
        _query([_record()], **changes)


@pytest.mark.parametrize("changes", [{"page_size": 0}, {"page_size": 21},
                                        {"page_size": True}, {"order": "desc"}])
def test_page_size_and_sort_are_validated(changes):
    records = [_record()]
    with pytest.raises(TimelineError):
        SyntheticTimeline(records, observed_at=OBSERVED).query(
            **_scope(records), **{"page_size": 1, **changes})


def test_direct_evidence_checks_subject_period_and_every_merged_source():
    records = [_access(), _audit(), _record(3, actor_ref="user:2"),
               _record(4, occurred_at=END)]
    snapshot = SyntheticTimeline(records, observed_at=OBSERVED)
    scope = _scope(records)
    assert snapshot.evidence("audit_logs:2", **scope)["event"]["evidence_refs"] == ["access_logs:1", "audit_logs:2"]
    for denied in ("audit_logs:3", "audit_logs:4", "audit_logs:999", "sensitive_logs:1"):
        with pytest.raises(TimelineAccessDenied):
            snapshot.evidence(denied, **scope)
    limited = {**scope, "grant": _grant(records[1:])}
    assert snapshot.query(**limited, page_size=20)["events"] == []
    with pytest.raises(TimelineAccessDenied):
        snapshot.evidence("audit_logs:2", **limited)
    for grant in (None, TimelineGrant(frozenset(), frozenset())):
        with pytest.raises(TimelineAccessDenied):
            snapshot.query(**{**scope, "grant": grant}, page_size=1)


def test_relations_do_not_disclose_an_out_of_scope_evaluation():
    records = [_access(), _audit(), _record(3, event_type="BREAK_GLASS_USED",
               resource_ref="resource:20", request_ref="access-evaluation:abc")]
    page = _query(records, grant=_grant(records[2:]))
    event = page["events"][0]
    assert event["relations"] == []
    assert "related_evidence_outside_scope" in event["unknown_reasons"]


def test_current_state_is_observed_now_not_reconstructed_in_the_past():
    records = [_record(1, "approvals", event_type="CURRENT_STATE", occurred_at=START)]
    assert _query(records)["events"] == []
    snapshot = SyntheticTimeline(records, observed_at=END - timedelta(minutes=1))
    page = snapshot.query(**_scope(records), page_size=1)
    assert page["events"][0]["occurred_at"] == (END - timedelta(minutes=1)).isoformat()
    assert "current_state_only_not_historical" in page["events"][0]["unknown_reasons"]
    assert page["events"][0]["sources"][0]["occurred_at"] == START.isoformat()
    assert page["missing_ranges"] == [{"start": (END - timedelta(minutes=1)).isoformat(),
                                        "end": END.isoformat(),
                                        "reason": "snapshot_ends_before_range_end"}]


def test_coverage_gaps_are_clipped_and_empty_input_is_not_complete_history():
    snapshot = SyntheticTimeline([], observed_at=OBSERVED, missing_ranges=[
        {"start": START - timedelta(minutes=1), "end": END + timedelta(minutes=1)}])
    page = snapshot.query(**_scope([]), page_size=1)
    assert page["events"] == [] and page["truncated"] is False
    assert page["missing_ranges"] == [{"start": START.isoformat(), "end": END.isoformat(),
                                        "reason": "source_coverage_incomplete"}]
    assert "source_completeness_not_verified" in page["unknown_reasons"]


def test_all_flows_and_physical_log_names_are_represented_without_inferred_success():
    kinds = ["LOGIN_FAILED", "MFA_VERIFIED", "DEVICE_USED_UNREGISTERED", "ACCESS_DECISION",
             "DOWNLOAD_ATTEMPT", "ADMIN_APPROVAL_REQUESTED", "APPROVAL_GRANTED",
             "CASE_ASSIGNMENT_APPROVED", "BREAK_GLASS_ACTIVATED", "BREAK_GLASS_USED",
             "BREAK_GLASS_EXPIRED", "ACCESS_SCORE_CHANGED", "LOGIN_SUCCESS"]
    records = [_record(i + 1, "operation_logs" if i % 2 else "audit_logs", event_type=kind)
               for i, kind in enumerate(kinds)]
    events = _query(records)["events"]
    assert {e["event_type"] for e in events} == set(kinds)
    assert all(e["outcome"] == "unknown" and e["signal_quality"] == "synthetic" for e in events)
    assert "login_success_is_not_final_mfa" in next(
        e for e in events if e["event_type"] == "LOGIN_SUCCESS")["unknown_reasons"]


@pytest.mark.parametrize("changes", [
    {"table": "sensitive_logs"}, {"table": "operation"},
    {"signal_quality": "verified"}, {"signal_quality": None},
    {"table": []}, {"event_type": []}, {"action": []}, {"outcome": []},
    {"request_ref": "access-evaluation:"},
    {"event_type": "OTHER_APPROVAL_AI_REVIEW"}, {"id": True},
    {"actor_ref": None}, {"request_ref": "123"}, {"outcome": "transfer_success"},
    {"occurred_at": START.replace(tzinfo=None)}, {"occurred_at": OBSERVED + timedelta(seconds=1)},
])
def test_invalid_or_analysis_input_is_not_silently_accepted(changes):
    with pytest.raises(TimelineError):
        SyntheticTimeline([_record(**changes)], observed_at=OBSERVED)


def test_duplicate_source_id_is_not_silently_counted_twice():
    with pytest.raises(TimelineError, match="duplicate source"):
        SyntheticTimeline([_record(), _record()], observed_at=OBSERVED)


def test_reads_do_not_mutate_input_or_snapshot_or_return_raw_secrets():
    records = [_access(), _audit()]
    records[0].update(details={"secret": "synthetic-secret", "risk_score": 80},
                      approval_state="pending", session_state="active")
    before = deepcopy(records)
    snapshot = SyntheticTimeline(records, observed_at=OBSERVED)
    scope = _scope(records)
    first = snapshot.query(**scope, page_size=2)
    evidence = snapshot.evidence("audit_logs:2", **scope)
    assert "synthetic-secret" not in json.dumps([first, evidence])
    first["events"][0]["sources"].clear()
    evidence["event"]["evidence_refs"].clear()
    assert records == before
    assert snapshot.query(**scope, page_size=2) == SyntheticTimeline(before, observed_at=OBSERVED).query(**scope, page_size=2)
    records[0]["actor_ref"] = "changed-after-snapshot"
    assert snapshot.query(**scope, page_size=2)["events"][0]["actor_ref"] == "user:1"
