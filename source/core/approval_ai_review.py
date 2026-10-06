"""Transient, evidence-bound AI advice for a pending resource approval."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from integrations.openai_scenario_client import ModelOutputError

OPINIONS = {"request_more_information", "check_further", "no_issue_identified"}
MAX_ITEMS = 8


def _fact(fact, aliases):
    """Copy only a known scalar fact and replace its source with a call-local alias."""
    if not isinstance(fact, dict) or set(fact) != {"value", "source", "related_sources", "observed_at", "unknown_reason"}:
        raise ValueError("invalid server fact")
    value = fact["value"]
    if isinstance(value, dict):
        if set(value) != {"resource_flag", "grade_at_least_four"} or any(type(v) is not bool for v in value.values()):
            raise ValueError("invalid approval basis")
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("invalid fact value")
    if isinstance(value, str) and len(value) > 64:
        raise ValueError("fact string too long")
    reason = fact["unknown_reason"]
    if reason is not None and (not isinstance(reason, str) or len(reason) > 80):
        raise ValueError("invalid unknown reason")
    source = fact["source"]
    alias = None
    if source is not None:
        if not isinstance(source, dict) or set(source) != {"table", "id"} or source["table"] not in {"approvals", "resources", "users", "operation_logs", "access_logs"} or type(source["id"]) is not int:
            raise ValueError("invalid source")
        key = (source["table"], source["id"])
        alias = next((name for name, actual in aliases.items() if actual == key), None)
        if alias is None:
            alias = f"E{len(aliases) + 1}"
            aliases[alias] = key
    if fact["observed_at"] is not None and (not isinstance(fact["observed_at"], str) or len(fact["observed_at"]) > 40):
        raise ValueError("invalid observation time")
    return {"value": value, "evidence_ref": alias,
            "observed_at": fact["observed_at"], "unknown_reason": reason}


def build_model_input(facts):
    """Select only approved structured fields; never serialize the full facts object."""
    aliases = {}
    request = facts["request"]
    resource = facts["resource"]
    relation = facts["work_relation"]
    policy = facts["policy_facts"]
    fields = {
        "request": {key: _fact(request[key], aliases) for key in ("status", "requested_at", "reason_origin", "want_download")},
        "resource": {key: _fact(resource[key], aliases) for key in ("sensitivity_grade", "requires_approval", "approval_basis")},
        "work_relation": {key: _fact(relation[key], aliases) for key in ("assigned_case", "same_department", "job_relevance")},
        "policy_observations": {key: _fact(policy[key], aliases) for key in ("last_observed_risk_score", "last_observed_final_level", "score_base_level", "immediate_block", "policy_version", "current_evaluation")},
    }
    if fields["request"]["status"]["value"] != "pending":
        raise ValueError("request is not pending")
    prior = facts["past_decisions"]
    if set(prior) != {"records", "source", "comparison", "unknown_reason"} or prior["comparison"] != "unavailable" or len(prior["records"]) > 10:
        raise ValueError("invalid prior decisions")
    candidates = []
    for row in prior["records"]:
        if set(row) != {"approval_id", "status", "resolved_at", "source"} or row["status"] not in {"approved", "rejected"} or row["source"] != {"table": "approvals", "id": row["approval_id"]}:
            raise ValueError("invalid prior decision")
        alias = _fact({"value": row["status"], "source": row["source"], "related_sources": [], "observed_at": row["resolved_at"], "unknown_reason": None}, aliases)["evidence_ref"]
        candidates.append({"evidence_ref": alias, "status": row["status"], "resolved_at": row["resolved_at"]})
    fields["past_decisions"] = {"candidates": candidates, "comparison": "unavailable", "unknown_reason": prior["unknown_reason"]}
    fields["reason_text_available"] = False
    # JSON serialization also rejects unexpected non-scalar types before transmission.
    json.dumps(fields, allow_nan=False)
    return fields, aliases


def _refs(value, aliases):
    if not isinstance(value, list) or len(value) > MAX_ITEMS or any(not isinstance(ref, str) for ref in value) or len(value) != len(set(value)) or any(ref not in aliases for ref in value):
        raise ModelOutputError("invalid evidence_ref")
    return value


def validate_review(raw, aliases, candidates):
    """Validate the full model object and restore only this call's source IDs."""
    required = {"reason_summary", "missing_items", "contradictions", "similar_decisions", "review_opinion", "uncertainties", "evidence_refs"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ModelOutputError("invalid review fields")
    if raw["reason_summary"] != "분석 불가: 요청 사유 원문 미전송":
        raise ModelOutputError("reason text was not provided")
    if not isinstance(raw["review_opinion"], str) or raw["review_opinion"] not in OPINIONS:
        raise ModelOutputError("invalid review opinion")
    restored = {}
    for name in ("missing_items", "contradictions", "uncertainties"):
        items = raw[name]
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise ModelOutputError("invalid review items")
        cleaned = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {"text", "evidence_refs", "no_evidence_reason"}:
                raise ModelOutputError("invalid review item")
            message = item["text"]
            reason = item["no_evidence_reason"]
            if not isinstance(message, str) or not 1 <= len(message) <= 300 or (reason is not None and (not isinstance(reason, str) or not 1 <= len(reason) <= 160)):
                raise ModelOutputError("invalid review item length")
            if any(word in message.lower() for word in ("approved", "rejected", "approve(", "reject(")):
                raise ModelOutputError("executable decision text")
            refs = _refs(item["evidence_refs"], aliases)
            if not refs and reason is None:
                raise ModelOutputError("missing evidence reason")
            cleaned.append({"text": message, "evidence_ids": [{"table": aliases[ref][0], "id": aliases[ref][1]} for ref in refs], "no_evidence_reason": reason})
        restored[name] = cleaned
    if not isinstance(raw["similar_decisions"], list) or len(raw["similar_decisions"]) > MAX_ITEMS:
        raise ModelOutputError("invalid similar decisions")
    allowed_candidates = {item["evidence_ref"] for item in candidates}
    similar = []
    for ref in raw["similar_decisions"]:
        if not isinstance(ref, str) or ref not in allowed_candidates or ref in similar:
            raise ModelOutputError("invalid past decision reference")
        similar.append(ref)
    top_refs = _refs(raw["evidence_refs"], aliases)
    restored["similar_decisions"] = [{"table": aliases[ref][0], "id": aliases[ref][1]} for ref in similar]
    restored["evidence_ids"] = [{"table": aliases[ref][0], "id": aliases[ref][1]} for ref in top_refs]
    restored["reason_summary"] = raw["reason_summary"]
    restored["review_opinion"] = raw["review_opinion"]
    return restored


def review_response(facts, raw, aliases, candidates, model):
    """Keep server facts immutable and AI advice in a separate response branch."""
    reviewed = validate_review(raw, aliases, candidates)
    unknowns = []
    for group in ("request", "resource", "work_relation", "policy_facts"):
        for name, fact in facts[group].items():
            if fact["unknown_reason"]:
                unknowns.append({"field": f"{group}.{name}", "reason": fact["unknown_reason"]})
    if facts["past_decisions"]["unknown_reason"]:
        unknowns.append({"field": "past_decisions", "reason": facts["past_decisions"]["unknown_reason"]})
    return {"policy_facts": facts, "ai_review": {key: reviewed[key] for key in ("reason_summary", "missing_items", "contradictions", "similar_decisions", "review_opinion")},
            "uncertainties": {"server": unknowns, "ai": reviewed["uncertainties"]},
            "evidence_ids": reviewed["evidence_ids"], "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_status": "completed", "model": model}
