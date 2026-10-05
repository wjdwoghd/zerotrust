"""v2 AI 시나리오 생성과 서버 재검증 경계를 검증한다."""

import json

import pytest

from core import policy_thresholds as pt
from core.ai_policy_challenger import (
    DEFAULT_ALLOWED_VALUES, UnsupportedExperimentGoalError, run_challenge,
    run_configured_challenge,
)
from integrations.openai_scenario_client import (
    MissingApiKeyError, ModelOutputError, ModelRefusalError, ModelTimeoutError,
)


def _conditions(**changes):
    """전체 필드를 가진 유효한 합성 조건을 만든다."""
    values = {name: allowed[0] for name, allowed in DEFAULT_ALLOWED_VALUES.items()}
    values.update(changes)
    return values


def _response(scenarios):
    """Responses API의 완료된 구조화 출력 형태를 만든다."""
    return {
        "status": "completed",
        "output": [{
            "type": "message",
            "content": [{
                "type": "output_text",
                "text": json.dumps({"scenarios": scenarios}),
            }],
        }],
    }


@pytest.fixture
def policy_snapshot(monkeypatch):
    """정책 계산이 DB 없이 고정된 경계를 사용하게 한다."""
    monkeypatch.setattr(
        pt, "_load_from_db",
        lambda **_kwargs: ({
            "DECISION_BAND_L1_MAX": 25, "DECISION_BAND_L2_MAX": 50,
            "DECISION_BAND_L3_MAX": 75, "DECISION_BAND_L4_MAX": 90,
        }, {}),
    )


def test_normal_output_is_revalidated_and_policy_result_separated(policy_snapshot):
    """AI 설명과 서버 정책 결과가 별도 필드로 반환된다."""
    scenarios = [{"conditions": _conditions(), "explanation": "경계 입력 후보"}]
    result = run_challenge(
        goal="boundary", count=1, api_key="test-key",
        post_json=lambda _request, _timeout: _response(scenarios),
    )
    item = result["scenarios"][0]
    assert item["synthetic_conditions"] == scenarios[0]["conditions"]
    assert item["ai_explanation"] == "경계 입력 후보"
    assert item["policy_engine_result"]["score_level"] in range(1, 6)
    assert "score" not in scenarios[0]
    assert result["support"]["policy_authority"] == "server policy simulator"


@pytest.mark.parametrize("scenarios", [
    [{"conditions": _conditions(), "explanation": "ok", "score": 10}],
    [{"conditions": {**_conditions(), "unknown": True}, "explanation": "ok"}],
    [{"conditions": _conditions(), "explanation": ""}],
])
def test_malformed_output_is_rejected_before_simulation(policy_snapshot, scenarios):
    """추가 필드·알 수 없는 조건·빈 설명을 서버가 거부한다."""
    with pytest.raises(ModelOutputError):
        run_challenge(
            goal="boundary", count=1, api_key="test-key",
            post_json=lambda _request, _timeout: _response(scenarios),
        )


def test_out_of_range_output_is_rejected(policy_snapshot):
    """스키마를 우회한 범위 밖 값도 서버 허용 목록에서 거부한다."""
    scenarios = [{
        "conditions": _conditions(sensitivity_grade=6),
        "explanation": "범위 밖 입력",
    }]
    with pytest.raises(ModelOutputError, match="server validation"):
        run_challenge(
            goal="immediate_block", count=1, api_key="test-key",
            post_json=lambda _request, _timeout: _response(scenarios),
        )


def test_excess_scenario_count_is_rejected(policy_snapshot):
    """요청 개수보다 많은 모델 출력은 계산 전에 거부한다."""
    scenarios = [
        {"conditions": _conditions(), "explanation": "one"},
        {"conditions": _conditions(), "explanation": "two"},
    ]
    with pytest.raises(ModelOutputError, match="scenario count"):
        run_challenge(
            goal="boundary", count=1, api_key="test-key",
            post_json=lambda _request, _timeout: _response(scenarios),
        )


def test_model_refusal_is_explicit(policy_snapshot):
    """구조화 출력 대신 반환된 모델 거부를 별도 오류로 처리한다."""
    response = {
        "status": "completed",
        "output": [{"type": "message", "content": [
            {"type": "refusal", "refusal": "cannot comply"},
        ]}],
    }
    with pytest.raises(ModelRefusalError):
        run_challenge(
            goal="boundary", count=1, api_key="test-key",
            post_json=lambda _request, _timeout: response,
        )


def test_timeout_is_explicit(policy_snapshot):
    """전송 계층의 시간 초과를 정책 도전자 전용 오류로 변환한다."""
    def timeout(_request, _seconds):
        raise TimeoutError("slow")

    with pytest.raises(ModelTimeoutError):
        run_challenge(
            goal="boundary", count=1, api_key="test-key", post_json=timeout,
        )


def test_missing_key_fails_without_transport_call(policy_snapshot):
    """키 미설정은 외부 호출 전 명시적으로 실패한다."""
    called = False

    def transport(_request, _timeout):
        nonlocal called
        called = True
        return {}

    with pytest.raises(MissingApiKeyError):
        run_challenge(
            goal="boundary", count=1, api_key="", post_json=transport,
        )
    assert called is False


def test_configured_missing_key_does_not_affect_v1_app(monkeypatch, policy_snapshot):
    """키가 비어도 v1 앱은 구성되며 AI 기능 호출만 실패한다."""
    import config
    import server

    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "OPENAI_SCENARIO_TIMEOUT_SEC", "20")
    app = server.make_app()
    assert app is not None
    with pytest.raises(MissingApiKeyError):
        run_configured_challenge(
            goal="boundary", count=1,
            post_json=lambda _request, _timeout: pytest.fail("transport called"),
        )


def test_invalid_ai_timeout_is_deferred_until_ai_call(monkeypatch, policy_snapshot):
    """잘못된 AI 전용 timeout 설정은 v1 앱 구성을 막지 않는다."""
    import config
    import server

    monkeypatch.setattr(config, "OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(config, "OPENAI_SCENARIO_TIMEOUT_SEC", "invalid")
    assert server.make_app() is not None
    with pytest.raises(ValueError):
        run_configured_challenge(goal="boundary", count=1)


def test_only_fixed_synthetic_contract_is_transmitted(policy_snapshot):
    """본문에는 목표·개수·허용값만 있고 키나 실제 데이터 필드가 없다."""
    captured = {}
    secret = "secret-api-key-value"
    scenarios = [{"conditions": _conditions(), "explanation": "synthetic"}]

    def transport(request, timeout):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _response(scenarios)

    run_challenge(
        goal="boundary", count=1, api_key=secret, post_json=transport,
    )
    body = captured["body"]
    sent = json.loads(body["input"])
    assert set(sent) == {"experiment_goal", "scenario_count", "allowed_values"}
    assert secret not in json.dumps(body)
    assert not ({"user_id", "case_id", "resource_id", "body", "audit_log"} & set(sent))
    assert body["store"] is False
    assert body["text"]["format"]["strict"] is True


def test_allowed_values_can_only_narrow_server_domain(policy_snapshot):
    """요청 허용 목록은 서버 도메인 안에서만 좁힐 수 있다."""
    with pytest.raises(ValueError, match="unsupported value"):
        run_challenge(
            goal="boundary", count=1, api_key="test-key",
            allowed_values={"sensitivity_grade": [99]},
            post_json=lambda _request, _timeout: {},
        )


def test_approval_path_is_rejected_before_external_call(policy_snapshot):
    """승인 상태를 계산하지 못하는 목표는 모델에 보내지 않는다."""
    called = False

    def transport(_request, _timeout):
        nonlocal called
        called = True
        return {}

    with pytest.raises(UnsupportedExperimentGoalError, match="approval_path"):
        run_challenge(
            goal="approval_path", count=1, api_key="test-key", post_json=transport,
        )
    assert called is False
