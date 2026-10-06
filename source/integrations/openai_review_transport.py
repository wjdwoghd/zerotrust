"""승인 AI 참고 검토에서 공유하는 Responses API 응답 처리와 오류 유형."""

from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RESPONSES_URL = "https://api.openai.com/v1/responses"


class ReviewTransportError(RuntimeError):
    """승인 AI 참고 검토 서비스 호출이 명시적으로 실패했음을 나타낸다."""


class MissingApiKeyError(ReviewTransportError):
    """OpenAI API 키가 설정되지 않았음을 나타낸다."""


class ModelRefusalError(ReviewTransportError):
    """모델이 검토 의견 생성을 거부했음을 나타낸다."""


class ModelTimeoutError(ReviewTransportError):
    """OpenAI 호출 제한 시간을 초과했음을 나타낸다."""


class ModelOutputError(ReviewTransportError):
    """응답 상태나 구조가 계약과 다름을 나타낸다."""


def _default_post_json(request: Request, timeout: float) -> dict:
    """표준 라이브러리로 JSON 요청을 보내고 JSON 객체 응답을 반환한다."""
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
    except (TimeoutError, socket.timeout) as error:
        raise ModelTimeoutError("OpenAI review timed out") from error
    except HTTPError as error:
        raise ReviewTransportError(
            f"OpenAI review failed with HTTP {error.code}"
        ) from error
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            raise ModelTimeoutError("OpenAI review timed out") from error
        raise ReviewTransportError("OpenAI review request failed") from error
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
                raise ModelRefusalError("OpenAI model refused review generation")
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                texts.append(content["text"])
    if len(texts) != 1:
        raise ModelOutputError("OpenAI response must contain one structured output")
    return texts[0]
