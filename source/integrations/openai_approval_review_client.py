"""Send only an allowlisted approval fact projection to Responses API."""
from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request

from integrations.openai_review_transport import (
    RESPONSES_URL, _default_post_json, _extract_output_text,
    MissingApiKeyError, ModelOutputError, ModelRefusalError, ModelTimeoutError,
    ReviewTransportError,
)


def _schema():
    item = {"type": "object", "properties": {
        "text": {"type": "string"}, "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "no_evidence_reason": {"type": ["string", "null"]}},
        "required": ["text", "evidence_refs", "no_evidence_reason"], "additionalProperties": False}
    properties = {
        "reason_summary": {"type": "string"},
        "missing_items": {"type": "array", "items": item},
        "contradictions": {"type": "array", "items": item},
        "similar_decisions": {"type": "array", "items": {"type": "string"}},
        "review_opinion": {"enum": ["request_more_information", "check_further", "no_issue_identified"]},
        "uncertainties": {"type": "array", "items": item},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
    }
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def generate_approval_review(*, facts, api_key, model, timeout=20.0, post_json=None):
    """Return raw structured advice; the caller must validate every field and reference."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise MissingApiKeyError("OPENAI_API_KEY is not configured")
    body = {"model": model, "store": False,
            "instructions": ("Offer nonbinding approval review advice from structured facts only. "
                             "No reason text was supplied: set reason_summary exactly to '분석 불가: 요청 사유 원문 미전송'. "
                             "Do not approve, reject, change access, infer current policy results, or invent evidence. "
                             "Similar decisions may reference only supplied past_decisions candidates."),
            "input": json.dumps(facts, ensure_ascii=False, allow_nan=False, separators=(",", ":")),
            "text": {"format": {"type": "json_schema", "name": "approval_review_advice",
                                "strict": True, "schema": _schema()}}}
    request = Request(RESPONSES_URL, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                      headers={"Authorization": f"Bearer {api_key.strip()}", "Content-Type": "application/json"}, method="POST")
    try:
        response = (post_json or _default_post_json)(request, timeout)
    except HTTPError as error:
        raise ReviewTransportError("OpenAI HTTP error") from error
    except (TimeoutError, socket.timeout) as error:
        raise ModelTimeoutError("OpenAI timed out") from error
    except URLError as error:
        raise ReviewTransportError("OpenAI network error") from error
    if not isinstance(response, dict):
        raise ModelOutputError("invalid OpenAI response")
    try:
        raw = json.loads(_extract_output_text(response))
    except json.JSONDecodeError as error:
        raise ModelOutputError("invalid JSON") from error
    return raw
