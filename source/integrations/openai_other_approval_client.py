"""Request nonbinding review advice from a minimal, type-specific projection."""
from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request

from integrations.openai_scenario_client import (
    RESPONSES_URL, _default_post_json, _extract_output_text,
    MissingApiKeyError, ModelOutputError, ModelTimeoutError,
    ScenarioGenerationError,
)


def generate_review(*, facts, api_key, model, timeout=20.0, post_json=None):
    """Send only the caller's allowlisted projection; return untrusted JSON."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise MissingApiKeyError("OPENAI_API_KEY is not configured")
    item = {"type": "object", "properties": {
        "text": {"type": "string"}, "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "no_evidence_reason": {"type": ["string", "null"]}},
        "required": ["text", "evidence_refs", "no_evidence_reason"], "additionalProperties": False}
    properties = {"review_opinion": {"enum": ["check_further", "request_more_information", "no_issue_identified"]},
                  "items": {"type": "array", "items": item},
                  "uncertainties": {"type": "array", "items": item},
                  "evidence_refs": {"type": "array", "items": {"type": "string"}}}
    schema = {"type": "object", "properties": properties, "required": list(properties),
              "additionalProperties": False}
    body = {"model": model, "store": False,
            "instructions": ("Give nonbinding administrative review advice from structured facts only. "
                             "Raw reasons, identities and case content are unavailable. "
                             "Do not approve, reject, infer missing facts or invent evidence. "
                             "Use only provided evidence aliases."),
            "input": json.dumps(facts, ensure_ascii=False, allow_nan=False, separators=(",", ":")),
            "text": {"format": {"type": "json_schema", "name": "other_approval_advice",
                                "strict": True, "schema": schema}}}
    request = Request(RESPONSES_URL, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                      headers={"Authorization": f"Bearer {api_key.strip()}",
                               "Content-Type": "application/json"}, method="POST")
    try:
        response = (post_json or _default_post_json)(request, timeout)
    except HTTPError as error:
        raise ScenarioGenerationError("OpenAI HTTP error") from error
    except (TimeoutError, socket.timeout) as error:
        raise ModelTimeoutError("OpenAI timed out") from error
    except URLError as error:
        raise ScenarioGenerationError("OpenAI network error") from error
    if not isinstance(response, dict):
        raise ModelOutputError("invalid OpenAI response")
    try:
        return json.loads(_extract_output_text(response))
    except json.JSONDecodeError as error:
        raise ModelOutputError("invalid JSON") from error
