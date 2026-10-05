"""OpenAI Responses API로 합성 정책 시나리오 후보만 요청한다.

호출 본문에는 고정된 실험 목표, 요청 개수, 서버가 검증한 합성 허용값만
포함한다. 실제 식별자, 자료 본문, 감사 로그, 비밀값을 입력으로 받지 않는다.
"""

from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RESPONSES_URL = "https://api.openai.com/v1/responses"


class ScenarioGenerationError(RuntimeError):
    """시나리오 생성 호출이 명시적으로 실패했음을 나타낸다."""


class MissingApiKeyError(ScenarioGenerationError):
    """OpenAI API 키가 설정되지 않았음을 나타낸다."""


class ModelRefusalError(ScenarioGenerationError):
    """모델이 시나리오 생성을 거부했음을 나타낸다."""


class ModelTimeoutError(ScenarioGenerationError):
    """OpenAI 호출 제한 시간을 초과했음을 나타낸다."""


class ModelOutputError(ScenarioGenerationError):
    """응답 상태나 구조가 계약과 다름을 나타낸다."""


def _scenario_schema(count: int, allowed_values: dict) -> dict:
    """요청별 허용값과 정확한 개수를 강제하는 strict JSON Schema를 만든다."""
    properties = {
        name: {"type": "boolean"} if values == [False, True] else {"enum": values}
        for name, values in allowed_values.items()
    }
    scenario = {
        "type": "object",
        "properties": {
            "conditions": {
                "type": "object",
                "properties": properties,
                "required": list(allowed_values),
                "additionalProperties": False,
            },
            "explanation": {"type": "string"},
        },
        "required": ["conditions", "explanation"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "scenarios": {
                "type": "array", "items": scenario,
                "minItems": count, "maxItems": count,
            },
        },
        "required": ["scenarios"],
        "additionalProperties": False,
    }


def _default_post_json(request: Request, timeout: float) -> dict:
    """표준 라이브러리로 JSON 요청을 보내고 JSON 객체 응답을 반환한다."""
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
    except (TimeoutError, socket.timeout) as error:
        raise ModelTimeoutError("OpenAI scenario generation timed out") from error
    except HTTPError as error:
        raise ScenarioGenerationError(
            f"OpenAI scenario generation failed with HTTP {error.code}"
        ) from error
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            raise ModelTimeoutError("OpenAI scenario generation timed out") from error
        raise ScenarioGenerationError("OpenAI scenario generation request failed") from error
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise ModelOutputError("OpenAI response was not valid JSON") from error
    if not isinstance(decoded, dict):
        raise ModelOutputError("OpenAI response must be an object")
    return decoded


def _extract_output_text(response: dict) -> str:
    """완료 응답에서 텍스트를 추출하고 거부·미완료 상태를 구분한다."""
    if response.get("status") != "completed":
        raise ModelOutputError(
            f"OpenAI response did not complete: {response.get('status', 'missing')}"
        )
    texts = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            if content.get("type") == "refusal":
                raise ModelRefusalError("OpenAI model refused scenario generation")
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                texts.append(content["text"])
    if len(texts) != 1:
        raise ModelOutputError("OpenAI response must contain one structured output")
    return texts[0]


def generate_scenario_candidates(
    *, api_key: str, model: str, goal: str, count: int,
    allowed_values: dict, timeout: float = 20.0, post_json=None,
) -> list:
    """검증된 합성 허용값을 보내고 모델의 원시 시나리오 목록을 반환한다."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise MissingApiKeyError("OPENAI_API_KEY is not configured")
    request_input = {
        "experiment_goal": goal,
        "scenario_count": count,
        "allowed_values": allowed_values,
    }
    body = {
        "model": model,
        "store": False,
        "instructions": (
            "Generate synthetic policy-test scenarios only from the supplied allowed_values. "
            "The explanation may describe why the synthetic inputs test the experiment goal. "
            "Do not calculate or claim risk scores, access levels, approval, MFA, or Break-Glass outcomes."
        ),
        "input": json.dumps(request_input, ensure_ascii=False, separators=(",", ":")),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "synthetic_policy_scenarios",
                "strict": True,
                "schema": _scenario_schema(count, allowed_values),
            },
        },
    }
    request = Request(
        RESPONSES_URL,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        response = (post_json or _default_post_json)(request, timeout)
    except ModelTimeoutError:
        raise
    except (TimeoutError, socket.timeout) as error:
        raise ModelTimeoutError("OpenAI scenario generation timed out") from error
    if not isinstance(response, dict):
        raise ModelOutputError("OpenAI response must be an object")
    try:
        parsed = json.loads(_extract_output_text(response))
    except json.JSONDecodeError as error:
        raise ModelOutputError("OpenAI structured output was not valid JSON") from error
    if not isinstance(parsed, dict) or not isinstance(parsed.get("scenarios"), list):
        raise ModelOutputError("OpenAI structured output has an invalid shape")
    return parsed["scenarios"]
