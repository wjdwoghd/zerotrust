"""Contract checks for a transient approval review. Final suite runs in phase 6."""
import pytest

from core.approval_ai_review import build_model_input, review_response
from tests.unit.test_approval_review_facts import _ReadDb
from core.approval_review_facts import load_approval_review_facts, ReviewFactsError
from integrations.openai_approval_review_client import generate_approval_review
from integrations.openai_review_transport import (MissingApiKeyError, ModelOutputError,
    ModelRefusalError, ModelTimeoutError)


def _input(db=None):
    facts = load_approval_review_facts(db or _ReadDb(), 10, 2)
    payload, aliases = build_model_input(facts)
    return facts, payload, aliases


def _review():
    return {"reason_summary": "분석 불가: 요청 사유 원문 미전송",
            "missing_items": [], "contradictions": [], "similar_decisions": [],
            "review_opinion": "check_further", "uncertainties": [], "evidence_refs": []}


def test_projection_excludes_identifiers_and_free_text_and_keeps_unknowns():
    db = _ReadDb(events=[], prior=[])
    db.row["reason"] = "SECRET CASE NUMBER"
    facts, payload, aliases = _input(db)
    serialized = str(payload)
    assert "SECRET CASE NUMBER" not in serialized
    assert "case_number" not in serialized
    assert "requester_id" not in serialized
    assert payload["request"]["want_download"]["unknown_reason"]
    assert payload["request"]["reason_origin"]["unknown_reason"]
    assert payload["past_decisions"]["comparison"] == "unavailable"
    assert all(ref.startswith("E") for ref in aliases)
    assert facts["request"]["status"]["value"] == "pending"


def test_output_is_nonbinding_and_server_facts_are_unchanged():
    facts, payload, aliases = _input()
    raw = _review()
    raw["evidence_refs"] = [payload["request"]["status"]["evidence_ref"]]
    result = review_response(facts, raw, aliases, [], "test-model")
    assert result["policy_facts"] == facts
    assert result["ai_review"]["review_opinion"] == "check_further"
    assert result["evidence_ids"] == [{"table": "approvals", "id": 10}]
    assert result["uncertainties"]["server"]


@pytest.mark.parametrize("change", [
    {"review_opinion": "approved"}, {"policy_facts": {}},
    {"evidence_refs": ["E999"]}, {"evidence_refs": ["E1", "E1"]},
    {"reason_summary": "This request seems sufficient"},
])
def test_untrusted_model_fields_are_rejected(change):
    _, payload, aliases = _input()
    raw = _review() | change
    with pytest.raises(ModelOutputError):
        review_response({}, raw, aliases, payload["past_decisions"]["candidates"], "test-model")


def test_other_call_reference_cannot_be_reused():
    _, payload, aliases = _input()
    raw = _review()
    raw["missing_items"] = [{"text": "check", "evidence_refs": ["E999"], "no_evidence_reason": None}]
    with pytest.raises(ModelOutputError):
        review_response({}, raw, aliases, payload["past_decisions"]["candidates"], "test-model")


def test_past_decision_must_be_server_candidate():
    from datetime import datetime, timezone
    now = datetime(2026, 10, 6, tzinfo=timezone.utc)
    db = _ReadDb(prior=[{"id": 3, "status": "rejected", "resolved_at": now,
                         "approver_id": 9, "download_allowed": False}])
    facts, payload, aliases = _input(db)
    candidate = payload["past_decisions"]["candidates"][0]["evidence_ref"]
    raw = _review()
    raw["similar_decisions"] = [candidate]
    assert review_response(facts, raw, aliases, payload["past_decisions"]["candidates"], "test-model")["ai_review"]["similar_decisions"] == [{"table": "approvals", "id": 3}]
    with pytest.raises(ModelOutputError):
        review_response(facts, raw, aliases, [], "test-model")


@pytest.mark.parametrize("status,reviewer", [("approved", 2), ("pending", 1)])
def test_ineligible_request_fails_before_projection(status, reviewer):
    with pytest.raises(ReviewFactsError):
        load_approval_review_facts(_ReadDb(status=status), 10, reviewer)


def test_fact_query_failure_prevents_ai_input():
    with pytest.raises(RuntimeError):
        _input(_ReadDb(fail_access=True))


def test_client_sends_only_projection_and_rejects_invalid_output():
    _, payload, _ = _input()
    requests = []

    def post(request, timeout):
        requests.append(__import__("json").loads(request.data))
        return {"status": "completed", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": __import__("json").dumps(_review())}]}]}

    raw = generate_approval_review(facts=payload, api_key="fake", model="fake-model", post_json=post)
    assert raw["review_opinion"] == "check_further"
    assert requests[0]["store"] is False
    assert "approval_id" not in requests[0]["input"]
    with pytest.raises(MissingApiKeyError):
        generate_approval_review(facts=payload, api_key="", model="fake-model", post_json=post)
    with pytest.raises(ModelOutputError):
        generate_approval_review(facts=payload, api_key="fake", model="fake-model",
            post_json=lambda *_: {"status": "completed", "output": [{"type": "message", "content": [
                {"type": "output_text", "text": "not-json"}]}]})
    with pytest.raises(ModelRefusalError):
        generate_approval_review(facts=payload, api_key="fake", model="fake-model",
            post_json=lambda *_: {"status": "completed", "output": [{"type": "message", "content": [
                {"type": "refusal"}]}]})
    with pytest.raises(ModelTimeoutError):
        generate_approval_review(facts=payload, api_key="fake", model="fake-model",
            post_json=lambda *_: (_ for _ in ()).throw(TimeoutError()))
