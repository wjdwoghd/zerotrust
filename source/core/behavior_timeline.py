"""Read-only timeline normalization; DB ownership is verified by its adapter.

SyntheticTimeline remains synthetic-only. TimelineSnapshot also accepts the fixed
server projection, never arbitrary raw rows, user grants or model instructions.
"""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json


CONTRACT_VERSION = "synthetic-timeline-v1"
_REFS = ("session_ref", "resource_ref", "case_ref", "request_ref", "activation_ref")
_AUDIT_EVENTS = frozenset("""
LOGIN_SUCCESS LOGIN_FAILED LOGIN_FAILURE MFA_FAILED MFA_VERIFIED
ADMIN_GATED_SESSION_STARTED DEVICE_NOT_REGISTERED DEVICE_USED_UNREGISTERED
IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED LOGIN_BLOCKED_LOCATION LOGIN_BLOCKED_LOCATION_NOT_ALLOWED LOCATION_ANOMALY_LOCKED
SESSION_STARTED SESSION_EXPIRED_IDLE SESSION_EXPIRED_ABSOLUTE
SESSION_EXPIRED_HIGH_SENSITIVITY SESSION_EXPIRED_PENDING_REAUTH SESSION_TERMINATED_BY_USER
CONCURRENT_SESSION_LOCKED CONCURRENT_SESSION_RESOLVED CONCURRENT_LOGIN_REJECTED
ACCESS_DECISION ACCESS_SCORE_CHANGED UNASSIGNED_CASE_CLICK DOWNLOAD_ATTEMPT
ADMIN_APPROVAL_REQUESTED APPROVAL_GRANTED APPROVAL_REJECTED
ADMIN_APPROVAL_GRANTED ADMIN_APPROVAL_REJECTED CASE_ASSIGNMENT_REQUESTED
CASE_ASSIGNMENT_OTP_REQUIRED CASE_ASSIGNMENT_OTP_VERIFIED CASE_ASSIGNMENT_OTP_FAILED
CASE_ASSIGNMENT_APPROVED CASE_ASSIGNMENT_REJECTED
BREAK_GLASS_ACTIVATED BREAK_GLASS_ACTIVATION_REFUSED BREAK_GLASS_USED
BREAK_GLASS_EXPIRED BREAK_GLASS_RELEASED BREAK_GLASS_REVOKED
BREAK_GLASS_REVIEWED_JUSTIFIED BREAK_GLASS_REVIEWED_UNJUSTIFIED
BREAK_GLASS_REVIEWED_PARTIAL
""".split())
_FIELDS = {
    "audit_logs": ("event_type", "user_id", "request_id", "created_at", "details"),
    "operation_logs": ("event_type", "user_id", "request_id", "created_at", "details"),
    "access_logs": ("user_id", "session_id", "resource_id", "reason_code", "action_type", "created_at"),
    "approvals": ("requester_id", "resource_id", "status", "requested_at"),
    "login_approval_requests": ("user_id", "status", "requested_at"),
    "case_assignment_requests": ("requester_id", "resource_id", "status", "requested_at"),
    "break_glass_activations": ("activator_id", "session_id", "resource_id", "status", "activated_at"),
    "sessions": ("user_id", "login_at"),
}


class TimelineError(ValueError):
    """Invalid synthetic input or query; messages never include supplied values."""


class TimelineAccessDenied(PermissionError):
    """Missing or insufficient injected scope, including direct evidence lookup."""


@dataclass(frozen=True)
class TimelineGrant:
    """Test-injected subject and evidence scope; no role gets implicit access."""

    actor_refs: frozenset[str]
    evidence_refs: frozenset[str]


@dataclass(frozen=True)
class TimelineLimits:
    """Explicit query bounds for synthetic tests, never detection thresholds."""

    max_period: timedelta
    max_page_size: int


def _time(value):
    try:
        result = datetime.fromisoformat(value) if isinstance(value, str) else value
        if not isinstance(result, datetime) or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise TimelineError("timezone-aware timestamp required") from None


def _iso(value):
    return _time(value).isoformat()


def _ref(value):
    if value is not None and (not isinstance(value, str) or not value or len(value) > 160):
        raise TimelineError("invalid reference")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _normalize(record, observed_at, signal_quality="synthetic"):
    if not isinstance(record, dict) or record.get("signal_quality") != signal_quality:
        raise TimelineError("explicitly synthetic projection required")
    table = record.get("table")
    if not isinstance(table, str) or table not in _FIELDS:
        raise TimelineError("unsupported source")
    row_id = record.get("id")
    if type(row_id) is not int or row_id < 1:
        raise TimelineError("positive synthetic source id required")
    kind = record.get("event_type")
    if not isinstance(kind, str):
        raise TimelineError("event type required")
    if table in {"audit_logs", "operation_logs"}:
        if kind not in _AUDIT_EVENTS:
            raise TimelineError("unsupported event; analysis events are excluded")
    elif kind != ("ACCESS_DECISION" if table == "access_logs" else "CURRENT_STATE"):
        raise TimelineError("unsupported source event")
    actor = _ref(record.get("actor_ref"))
    if actor is None:
        raise TimelineError("subject attribution required")
    occurred = _time(record.get("occurred_at"))
    if occurred > observed_at:
        raise TimelineError("event after snapshot")
    refs = {key: _ref(record.get(key)) for key in _REFS}
    request = refs["request_ref"]
    if request is not None and (not request.startswith(
        ("access-evaluation:", "http:", "resource-approval:", "login-approval:", "assignment:")
    ) or not request.split(":", 1)[1]):
        raise TimelineError("request namespace required")
    action = record.get("action")
    outcome = record.get("outcome")
    if action is not None and (not isinstance(action, str) or action not in {
        "view", "download", "copy", "print", "login", "review"
    }):
        raise TimelineError("invalid action")
    if outcome is not None and (not isinstance(outcome, str) or outcome not in {
        "attempted", "allowed", "denied", "recorded", "pending", "approved", "rejected", "unknown"
    }):
        raise TimelineError("invalid outcome; transfer completion is not recorded")
    reasons = [f"{key}_unavailable" for key, value in refs.items() if value is None]
    if action is None:
        reasons.append("action_unavailable")
    if outcome is None or outcome == "unknown":
        reasons.append("outcome_unavailable")
    source_time = occurred
    if kind == "CURRENT_STATE":
        # A current row is observed now, never treated as a historical transition.
        occurred = observed_at
        reasons.append("current_state_only_not_historical")
    if kind == "LOGIN_SUCCESS":
        reasons.append("login_success_is_not_final_mfa")
    if action == "download":
        reasons.append("download_completion_unrecorded")
    evidence = f"{table}:{row_id}"
    return {
        "event_key": evidence, "event_type": kind, "occurred_at": _iso(occurred),
        "observed_at": _iso(observed_at), "actor_ref": actor, **refs,
        "action": action, "outcome": outcome or "unknown",
        "evidence_refs": [evidence], "unknown_reasons": reasons,
        "signal_quality": signal_quality, "relations": [],
        "sources": [{"evidence_ref": evidence, "table": table, "id": row_id,
                     "occurred_at": _iso(source_time), "observed_at": _iso(observed_at),
                     "fields": list(_FIELDS[table])}],
    }


def _evaluation_key(event):
    request = event["request_ref"]
    if request and request.startswith("access-evaluation:") and event["resource_ref"]:
        return event["actor_ref"], event["resource_ref"], request
    return None


def _merge(events):
    groups = defaultdict(list)
    for event in events:
        key = _evaluation_key(event)
        if key and event["event_type"] in {"ACCESS_DECISION", "BREAK_GLASS_USED"}:
            groups[key].append(event)
    removed = set()
    for members in groups.values():
        access = [e for e in members if e["sources"][0]["table"] == "access_logs"]
        audit = [e for e in members if e["event_type"] == "ACCESS_DECISION"
                 and e["sources"][0]["table"] == "audit_logs"]
        if len(access) != 1 or len(audit) != 1:
            reason = "ambiguous_evaluation_key" if len(access) > 1 or len(audit) > 1 else "access_or_audit_counterpart_missing"
            for event in members:
                event["unknown_reasons"].append(reason)
            continue
        primary, secondary = access[0], audit[0]
        if any(primary[k] is not None and secondary[k] is not None and primary[k] != secondary[k]
               for k in (*_REFS, "action")) or (
            secondary["outcome"] != "unknown" and primary["outcome"] != "unknown"
            and primary["outcome"] != secondary["outcome"]
        ):
            for event in members:
                event["unknown_reasons"].append("conflicting_evaluation_records")
            continue
        primary["evidence_refs"].extend(secondary["evidence_refs"])
        primary["sources"].extend(secondary["sources"])
        for key in _REFS:
            primary[key] = primary[key] or secondary[key]
        primary["action"] = primary["action"] or secondary["action"]
        if primary["outcome"] == "unknown":
            primary["outcome"] = secondary["outcome"]
        primary["unknown_reasons"] = sorted(set(
            primary["unknown_reasons"] + secondary["unknown_reasons"]
        ) - {f"{k}_unavailable" for k in (*_REFS, "action", "outcome")
             if primary[k] is not None and primary[k] != "unknown"})
        removed.add(secondary["event_key"])
        for event in members:
            if event["event_type"] == "BREAK_GLASS_USED":
                event["relations"].append({"type": "shares_access_evaluation",
                                           "event_key": primary["event_key"]})
    for event in events:
        if event["event_type"] == "ACCESS_DECISION" and (
            not _evaluation_key(event) or event["sources"][0]["table"] == "operation_logs"
        ):
            event["unknown_reasons"].append("possible_duplicate_unverified")
    return [event for event in events if event["event_key"] not in removed]


class TimelineSnapshot:
    """Immutable projection snapshot, callable only with server-verified scope.

    Records use the POLICY S1 projection, not raw details/SQL. Returned values are
    copies. Reconstruct a snapshot to observe new inputs; cursors cannot cross it.
    """

    def __init__(self, records, *, observed_at, missing_ranges=(), signal_quality="server_recorded"):
        if signal_quality not in {"synthetic", "server_recorded"}:
            raise TimelineError("invalid signal quality")
        self._quality = signal_quality
        self._contract = CONTRACT_VERSION if signal_quality == "synthetic" else "behavior-timeline-v1"
        self._observed_at = _time(observed_at)
        self._events = [_normalize(record, self._observed_at, signal_quality) for record in records]
        keys = Counter(event["event_key"] for event in self._events)
        if any(count != 1 for count in keys.values()):
            raise TimelineError("duplicate source row")
        self._missing = []
        for gap in missing_ranges:
            start, end = _time(gap["start"]), _time(gap["end"])
            if start >= end or end > self._observed_at:
                raise TimelineError("invalid missing range")
            self._missing.append({"start": _iso(start), "end": _iso(end),
                                  "reason": "source_coverage_incomplete"})
        self._events = sorted(_merge(self._events), key=lambda e: (e["occurred_at"], e["event_key"]))
        self._snapshot = _digest([self._contract, self._events, self._missing, _iso(self._observed_at)])

    def _scope(self, *, actor_ref, start, end, grant, limits):
        if not isinstance(grant, TimelineGrant) or actor_ref not in grant.actor_refs:
            raise TimelineAccessDenied("timeline scope denied")
        if (not isinstance(limits, TimelineLimits) or type(limits.max_page_size) is not int
                or limits.max_page_size < 1 or not isinstance(limits.max_period, timedelta)
                or limits.max_period <= timedelta(0)):
            raise TimelineError("explicit positive query limits required")
        start, end = _time(start), _time(end)
        if start >= end or end - start > limits.max_period:
            raise TimelineError("invalid query period")
        events = [deepcopy(e) for e in self._events if e["actor_ref"] == actor_ref
                  and start <= _time(e["occurred_at"]) < end
                  and set(e["evidence_refs"]) <= grant.evidence_refs]
        # Relations never bypass evidence scope or point outside the returned scope.
        visible = {e["event_key"] for e in events}
        for event in events:
            relations = event["relations"]
            event["relations"] = [r for r in relations if r["event_key"] in visible]
            if len(relations) != len(event["relations"]):
                event["unknown_reasons"].append("related_evidence_outside_scope")
        return start, end, events

    def query(self, *, actor_ref, start, end, grant, limits, page_size, cursor=None, order="asc"):
        """Return a half-open scoped page with a snapshot-bound validated cursor.

        Only ascending ordering is supported. Missing coverage and pagination are
        separate from the requested observation period and any future detector.
        """
        start, end, events = self._scope(actor_ref=actor_ref, start=start, end=end, grant=grant, limits=limits)
        if order != "asc" or type(page_size) is not int or not 1 <= page_size <= limits.max_page_size:
            raise TimelineError("invalid page size or ordering")
        binding = _digest([self._snapshot, actor_ref, _iso(start), _iso(end),
                           sorted(grant.actor_refs), sorted(grant.evidence_refs), page_size, order])
        offset = 0
        if cursor is not None:
            try:
                if not isinstance(cursor, str) or len(cursor) > 1024:
                    raise ValueError
                data = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
                if (set(data) != {"binding", "after"} or data["binding"] != binding
                        or type(data["after"]) is not str):
                    raise ValueError
                offset = next(i + 1 for i, event in enumerate(events) if event["event_key"] == data["after"])
            except (ValueError, TypeError, KeyError, StopIteration, UnicodeError):
                raise TimelineError("invalid cursor or changed scope/snapshot") from None
        page = events[offset:offset + page_size]
        has_more = offset + len(page) < len(events)
        next_cursor = None
        if has_more:
            next_cursor = base64.urlsafe_b64encode(json.dumps(
                {"binding": binding, "after": page[-1]["event_key"]}, separators=(",", ":")
            ).encode()).decode()
        gaps = [gap for gap in self._missing if _time(gap["start"]) < end and _time(gap["end"]) > start]
        gaps = [{**gap, "start": _iso(max(start, _time(gap["start"]))),
                 "end": _iso(min(end, _time(gap["end"])))} for gap in gaps]
        if end > self._observed_at:
            gaps.append({"start": _iso(max(start, self._observed_at)), "end": _iso(end),
                         "reason": "snapshot_ends_before_range_end"})
        return {"contract_version": self._contract, "snapshot_ref": self._snapshot,
                "observed_at": _iso(self._observed_at), "actor_ref": actor_ref,
                "start": _iso(start), "end": _iso(end), "order": order,
                "events": page, "next_cursor": next_cursor, "truncated": has_more,
                "missing_ranges": deepcopy(gaps),
                "unknown_reasons": (["synthetic_input_only"] if self._quality == "synthetic" else
                                    ["environment_signals_not_independently_verified"]) +
                                   ["source_completeness_not_verified", "scope_filtered_not_full_history"]}

    def evidence(self, evidence_ref, *, actor_ref, start, end, grant, limits):
        """Resolve evidence through the same subject/period/evidence checks as pages.

        Unknown, excluded and other-subject references share the same denial.
        No raw log payload, secret or current-state reconstruction is returned.
        """
        _, _, events = self._scope(actor_ref=actor_ref, start=start, end=end, grant=grant, limits=limits)
        for event in events:
            if evidence_ref in event["evidence_refs"]:
                return {"snapshot_ref": self._snapshot, "event": event,
                        "source": next(s for s in event["sources"] if s["evidence_ref"] == evidence_ref)}
        raise TimelineAccessDenied("evidence scope denied")


class SyntheticTimeline(TimelineSnapshot):
    """Synthetic-only compatibility surface; never accepts a real DB projection."""

    def __init__(self, records, *, observed_at, missing_ranges=()):
        super().__init__(records, observed_at=observed_at, missing_ranges=missing_ranges,
                         signal_quality="synthetic")
