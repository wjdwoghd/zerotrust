"""Provider failures expose only safe machine codes to review handlers."""

import io
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from integrations import openai_review_transport as transport


def _provider_error(status, code):
    body = json.dumps({"error": {"code": code, "message": "private provider detail"}})
    return HTTPError("https://api.openai.com/v1/responses", status, "failed", {},
                     io.BytesIO(body.encode()))


@pytest.mark.parametrize("status,provider_code,expected", [
    (429, "credit_balance_exhausted", ("ai_credits_exhausted", 503)),
    (429, "project_spend_limit_exceeded", ("ai_billing_limit", 503)),
    (429, "rate_limit_exceeded", ("ai_rate_limited", 503)),
    (401, "invalid_api_key", ("ai_auth_failed", 502)),
    (503, "server_is_overloaded", ("ai_provider_unavailable", 503)),
])
def test_http_error_classification_never_exposes_provider_body(monkeypatch, status, provider_code, expected):
    def fail(_request, timeout):
        raise _provider_error(status, provider_code)

    monkeypatch.setattr(transport, "urlopen", fail)
    with pytest.raises(transport.ReviewApiError) as raised:
        transport._default_post_json(Request("https://api.openai.com/v1/responses"), 1)

    assert raised.value.public_error == expected
    assert "private provider detail" not in str(raised.value)


def test_network_failure_is_distinct(monkeypatch):
    def fail(_request, timeout):
        raise URLError("private network detail")

    monkeypatch.setattr(transport, "urlopen", fail)
    with pytest.raises(transport.ReviewNetworkError) as raised:
        transport._default_post_json(Request("https://api.openai.com/v1/responses"), 1)
    assert "private network detail" not in str(raised.value)
