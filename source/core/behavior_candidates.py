"""S2 synthetic-only candidate experiments; no DB, model or access-policy hooks."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json

from core.behavior_timeline import SyntheticTimeline, TimelineError, _time


RULE_VERSION = "synthetic-candidates-v1"
_PURPOSE_EVENTS = frozenset({
    "ADMIN_APPROVAL_REQUESTED", "CASE_ASSIGNMENT_REQUESTED", "BREAK_GLASS_ACTIVATED",
})
_NORMAL_REASONS = frozenset({"approved_retry", "justified_bg", "emergency_cooperation"})


@dataclass(frozen=True)
class SyntheticDetectionRules:
    """Required experiment values, with no production defaults or activation flag."""

    window: timedelta
    min_accesses: int
    same_target: str
    cross_session: bool
    normal_handling: str

    def __post_init__(self):
        if (not isinstance(self.window, timedelta) or self.window <= timedelta(0)
                or type(self.min_accesses) is not int or self.min_accesses < 2
                or self.same_target != "resource_id" or type(self.cross_session) is not bool
                or self.normal_handling not in {"exclude_confirmed", "mark_only"}):
            raise TimelineError("invalid synthetic detection rules")


def generate_synthetic_candidates(timeline, *, rules, purpose_fixtures=None,
                                  normal_fixtures=(), **scope):
    """Analyze a scoped synthetic snapshot only, returning reproducible dispositions.

    Purpose fixtures are keyed by purpose event_key and contain synthetic=True,
    historical_scope_confirmed, allowed_resources and allowed_actions. They model
    structured historical scope, never interpret reason text. Normal fixtures
    contain synthetic=True, reason and evidence_refs covering a whole candidate.
    All supplied fixture anchors must resolve inside this query's evidence scope.
    Excluded and insufficient results remain visible for synthetic evaluation.
    """
    if type(timeline) is not SyntheticTimeline or not isinstance(rules, SyntheticDetectionRules):
        raise TimelineError("synthetic timeline and explicit rules required")
    events = []
    cursor = None
    while True:
        page = timeline.query(**scope, page_size=scope["limits"].max_page_size, cursor=cursor)
        events.extend(page["events"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    by_key = {e["event_key"]: e for e in events}
    available = {ref for e in events for ref in e["evidence_refs"]}
    purposes = {} if purpose_fixtures is None else purpose_fixtures
    if not isinstance(purposes, dict) or not isinstance(normal_fixtures, (list, tuple)):
        raise TimelineError("invalid synthetic fixtures")
    for key, fixture in purposes.items():
        if (key not in by_key or by_key[key]["event_type"] not in _PURPOSE_EVENTS
                or not isinstance(fixture, dict) or fixture.get("synthetic") is not True
                or type(fixture.get("historical_scope_confirmed")) is not bool
                or any(not isinstance(fixture.get(field), list)
                       or not all(isinstance(v, str) and v for v in fixture[field])
                       for field in ("allowed_resources", "allowed_actions"))):
            raise TimelineError("invalid or out-of-scope purpose fixture")
    for fixture in normal_fixtures:
        if not isinstance(fixture, dict):
            raise TimelineError("invalid synthetic normal fixture")
        refs = fixture.get("evidence_refs")
        if (fixture.get("synthetic") is not True or fixture.get("reason") not in _NORMAL_REASONS
                or not isinstance(refs, list) or not refs
                or not all(isinstance(ref, str) and ref in available for ref in refs)):
            raise TimelineError("invalid or out-of-scope normal fixture")

    config = {"window_seconds": rules.window.total_seconds(), "min_accesses": rules.min_accesses,
              "same_target": rules.same_target, "cross_session": rules.cross_session,
              "normal_handling": rules.normal_handling}
    results = []

    def emit(kind, members, status, facts, reasons):
        refs = sorted({ref for e in members for ref in e["evidence_refs"]})
        normal = sorted({f["reason"] for f in normal_fixtures
                         if set(refs) <= set(f["evidence_refs"])})
        if normal and rules.normal_handling == "exclude_confirmed":
            status = "excluded"
        identity = [RULE_VERSION, kind, page["snapshot_ref"], page["start"], page["end"],
                    config, refs, facts, status, normal, sorted(set(reasons))]
        results.append({
            "candidate_ref": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
            "type": kind, "status": status, "rule_version": RULE_VERSION,
            "analysis_scope": {k: page[k] for k in ("snapshot_ref", "actor_ref", "start", "end")},
            "experiment_rules": dict(config), "evidence_refs": refs, "observed_facts": facts,
            "unknown_reasons": sorted(set(reasons + page["unknown_reasons"])),
            "normal_exceptions": normal, "missing_ranges": page["missing_ranges"],
            "signal_quality": "synthetic", "intent": "not_determined",
        })

    def elapsed(first, last):
        return _time(last["occurred_at"]) - _time(first["occurred_at"])

    def session_matches(first, last):
        return rules.cross_session or (first["session_ref"] is not None
                                       and first["session_ref"] == last["session_ref"])

    # C1 uses explicit request/activation linkage, never a different case number.
    for purpose in events:
        if purpose["event_type"] not in _PURPOSE_EVENTS:
            continue
        link_field = "activation_ref" if purpose["event_type"] == "BREAK_GLASS_ACTIVATED" else "request_ref"
        for access in events:
            if access["event_type"] != "ACCESS_DECISION" or access["outcome"] != "allowed":
                continue
            if not timedelta(0) < elapsed(purpose, access) <= rules.window:
                continue
            if not purpose[link_field] or purpose[link_field] != access[link_field]:
                continue
            reasons = []
            fixture = purposes.get(purpose["event_key"])
            confirmed = (fixture is not None and fixture["historical_scope_confirmed"]
                         and access["resource_ref"] is not None and access["action"] is not None
                         and session_matches(purpose, access))
            mismatch = confirmed and (access["resource_ref"] not in fixture["allowed_resources"]
                                      or access["action"] not in fixture["allowed_actions"])
            if not confirmed:
                reasons.append("historical_purpose_scope_or_usage_unavailable")
            elif not mismatch:
                reasons.append("semantic_purpose_interpretation_unavailable")
            if page["missing_ranges"]:
                reasons.append("observation_has_missing_ranges")
            emit("C1", [purpose, access], "candidate" if mismatch and not reasons else "insufficient_evidence",
                 {"purpose_event": purpose["event_key"], "usage_event": access["event_key"],
                  "structured_scope_mismatch": bool(mismatch),
                  "historical_scope_confirmed": bool(confirmed),
                  "synthetic_allowed_resources": fixture["allowed_resources"][:] if confirmed else None,
                  "synthetic_allowed_actions": fixture["allowed_actions"][:] if confirmed else None}, reasons)

    # C2 counts distinct verified evaluation IDs, not polling or source row count.
    groups = defaultdict(list)
    for event in events:
        if event["resource_ref"]:
            groups[(event["resource_ref"], None if rules.cross_session else event["session_ref"])].append(event)
    for (target, session), members in sorted(groups.items(), key=lambda item: str(item[0])):
        accesses = [e for e in members if e["event_type"] == "ACCESS_DECISION"]
        for last in accesses:
            if last["outcome"] != "allowed":
                continue
            window = [e for e in members if timedelta(0) <= elapsed(e, last) <= rules.window]
            attempts = [e for e in window if e["event_type"] == "ACCESS_DECISION"
                        and e["outcome"] in {"denied", "allowed"}]
            requests = [e for e in window if e["event_type"] in _PURPOSE_EVENTS]
            denials = [e for e in attempts if e["outcome"] == "denied"]
            if not denials or not requests:
                continue
            ordered = [e for e in requests if any(elapsed(d, e) > timedelta(0) for d in denials)
                       and elapsed(e, last) > timedelta(0)]
            if not ordered:
                continue
            reasons = []
            ids = [e["request_ref"] for e in attempts]
            verified = (all(v and v.startswith("access-evaluation:") for v in ids)
                        and len(set(ids)) == len(ids)
                        and not any(set(e["unknown_reasons"]) & {
                            "ambiguous_evaluation_key", "conflicting_evaluation_records",
                            "possible_duplicate_unverified"} for e in attempts)
                        and (rules.cross_session or session is not None))
            if not verified:
                reasons.append("distinct_access_or_session_link_unverified")
            if page["missing_ranges"]:
                reasons.append("observation_has_missing_ranges")
            status = ("insufficient_evidence" if reasons else
                      "candidate" if len(attempts) >= rules.min_accesses else "excluded")
            if status == "excluded":
                reasons.append("below_injected_minimum")
            emit("C2", attempts + ordered, status,
                 {"resource_ref": target, "access_count": len(attempts),
                  "sequence": "denial_then_permission_request_then_allowed",
                  "causal_link": "not_established"}, reasons)
    return sorted(results, key=lambda r: (r["type"], r["evidence_refs"]))
