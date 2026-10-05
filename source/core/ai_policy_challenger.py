"""AI가 제안한 합성 조건을 서버에서 검증하고 기존 정책으로 계산한다."""

from __future__ import annotations

from core.policy_simulator import simulate, validate_conditions
from integrations.openai_scenario_client import (
    ModelOutputError, generate_scenario_candidates,
)


MAX_SCENARIOS = 8
SUPPORTED_GOALS = {"boundary", "immediate_block"}
UNSUPPORTED_GOALS = {"approval_path"}
DEFAULT_ALLOWED_VALUES = {
    "sensitivity_grade": [1, 2, 3, 4, 5],
    "data_type": ["summary", "original", "evidence", "internal_memo"],
    "device_registered": [False, True],
    "location_allowed": [False, True],
    "is_assigned_case": [False, True],
    "same_department": [False, True],
    "hour": [0, 5, 6, 8, 9, 17, 18, 21, 22, 23],
    "job_relevance": [False, True],
    "bulk_query": [False, True],
    "download_attempt": [False, True],
    "impossible_travel": [False, True],
    "concurrent_session": [False, True],
    "device_mismatch": [False, True],
    "auth_failure": [False, True],
    "recent_access_count": [0, 4, 5, 9, 10, 25],
    "unassigned_click_count": [0, 1, 2, 3],
}


class UnsupportedExperimentGoalError(ValueError):
    """현 시뮬레이터가 실험 목표를 정확히 계산할 수 없음을 나타낸다."""


def _validated_allowed_values(overrides: dict | None) -> dict:
    """기본 합성 도메인을 요청의 허용 목록으로 안전하게 좁힌다."""
    if overrides is None:
        return {name: list(values) for name, values in DEFAULT_ALLOWED_VALUES.items()}
    if not isinstance(overrides, dict):
        raise ValueError("allowed_values must be an object")
    unknown = set(overrides) - set(DEFAULT_ALLOWED_VALUES)
    if unknown:
        raise ValueError(f"unsupported allowed_values fields: {sorted(unknown)}")
    result = {name: list(values) for name, values in DEFAULT_ALLOWED_VALUES.items()}
    for name, values in overrides.items():
        if not isinstance(values, list) or not values:
            raise ValueError(f"allowed_values.{name} must be a non-empty list")
        if len(values) != len({json_value(value) for value in values}):
            raise ValueError(f"allowed_values.{name} contains duplicates")
        domain = {json_value(value) for value in DEFAULT_ALLOWED_VALUES[name]}
        if any(json_value(value) not in domain for value in values):
            raise ValueError(f"allowed_values.{name} contains an unsupported value")
        result[name] = list(values)
    return result


def json_value(value) -> tuple:
    """bool과 int를 구별해 JSON 스칼라의 타입과 값을 비교한다."""
    return type(value).__name__, value


def run_challenge(
    *, goal: str, count: int, allowed_values: dict | None = None,
    api_key: str, model: str = "gpt-4o-mini", timeout: float = 20.0,
    post_json=None,
) -> dict:
    """AI 후보를 재검증하고 정책 결과와 AI 설명을 분리해 반환한다."""
    if goal in UNSUPPORTED_GOALS:
        raise UnsupportedExperimentGoalError(
            "approval_path requires MFA and approval state that the simulator does not evaluate"
        )
    if goal not in SUPPORTED_GOALS:
        raise ValueError("unsupported experiment goal")
    if type(count) is not int or not 1 <= count <= MAX_SCENARIOS:
        raise ValueError(f"count must be an integer from 1 to {MAX_SCENARIOS}")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number")
    allowed = _validated_allowed_values(allowed_values)
    candidates = generate_scenario_candidates(
        api_key=api_key, model=model, goal=goal, count=count,
        allowed_values=allowed, timeout=timeout, post_json=post_json,
    )
    if len(candidates) != count:
        raise ModelOutputError("OpenAI returned an unexpected scenario count")
    validated = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {"conditions", "explanation"}:
            raise ModelOutputError("scenario fields do not match the server contract")
        explanation = candidate["explanation"]
        if not isinstance(explanation, str) or not 1 <= len(explanation) <= 500:
            raise ModelOutputError("scenario explanation must contain 1 to 500 characters")
        try:
            conditions = validate_conditions(candidate["conditions"])
        except ValueError as error:
            raise ModelOutputError("scenario conditions failed server validation") from error
        for name, value in conditions.items():
            if json_value(value) not in {json_value(v) for v in allowed[name]}:
                raise ModelOutputError(f"scenario condition is outside allowed_values: {name}")
        validated.append((conditions, explanation))
    return {
        "experiment_goal": goal,
        "scenarios": [
            {
                "synthetic_conditions": conditions,
                "policy_engine_result": simulate(conditions),
                "ai_explanation": explanation,
            }
            for conditions, explanation in validated
        ],
        "support": {
            "ai_role": "synthetic scenario proposal and explanation only",
            "policy_authority": "server policy simulator",
            "unsupported_goals": sorted(UNSUPPORTED_GOALS),
            "persistent_storage": False,
        },
    }


def run_configured_challenge(
    *, goal: str, count: int, allowed_values: dict | None = None,
    post_json=None,
) -> dict:
    """서버 환경 설정을 사용해 합성 시나리오 도전을 실행한다."""
    import config

    return run_challenge(
        goal=goal, count=count, allowed_values=allowed_values,
        api_key=config.OPENAI_API_KEY,
        model=config.OPENAI_SCENARIO_MODEL,
        timeout=float(config.OPENAI_SCENARIO_TIMEOUT_SEC),
        post_json=post_json,
    )
