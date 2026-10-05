"""합성 정책 계산과 실제 엔진의 순수 계산 경로를 비교한다."""

import pytest

from core import policy_thresholds as pt
from core.access_evaluator import _calculate_scoring
from core.decision_engine import determine_access_level
from core.policy_engine import check_immediate_block
from core.policy_simulator import simulate


BASE = {
    "sensitivity_grade": 1,
    "data_type": "summary",
    "device_registered": True,
    "location_allowed": True,
    "is_assigned_case": True,
    "same_department": False,
}


@pytest.fixture
def policy_snapshot(monkeypatch):
    """DB 없이 임계값 로더만 고정해 정책 엔진의 fallback을 비교한다."""
    def load(**_kwargs):
        return ({"DECISION_BAND_L1_MAX": 25, "DECISION_BAND_L2_MAX": 50,
                 "DECISION_BAND_L3_MAX": 75, "DECISION_BAND_L4_MAX": 90}, {})
    monkeypatch.setattr(pt, "_load_from_db", load)


def test_matches_access_scoring_and_decision(policy_snapshot):
    """허용 시나리오의 축과 기본 레벨이 실제 평가기의 계산과 같다."""
    conditions = {**BASE, "sensitivity_grade": 3, "is_assigned_case": False,
                  "same_department": True, "hour": 20, "recent_access_count": 6,
                  "unassigned_click_count": 2, "bulk_query": True}
    result = simulate(conditions)
    with pt.simulation_snapshot():
        actual = _calculate_scoring(
            user={"job_scope": []}, resource={"sensitivity_grade": 3,
                                               "data_type": "summary"},
            anomaly_result={"recent_access_count": 6,
                            "anomaly_types": ["BULK_QUERY"]},
            device_registered=True, location_allowed=True,
            is_assigned_case=False, same_department=True, job_relevance=False,
            pre_approved=False, unassigned_penalty_clicks=2,
            is_night=False, hour=20,
        )
        expected_level = determine_access_level(actual["total"]["total_risk_score"], 3)
    assert result["axes"]["object"] == actual["object_sensitivity"]
    assert result["axes"]["environment"] == actual["environment_risk"]
    assert result["axes"]["behavior"] == actual["behavior_risk"]
    assert result["axes"]["fitness"] == actual["work_fitness"]
    assert result["score_level"] == expected_level["level"]
    assert result["support"]["final_access_level"] is None


@pytest.mark.parametrize("boundary", [25, 50, 75, 90])
def test_each_side_of_decision_boundary(policy_snapshot, boundary, monkeypatch):
    """시뮬레이터가 정책 로더의 경계를 읽고 양쪽 레벨을 구분한다."""
    # 같은 합성 점수에서 경계만 앞뒤로 옮겨 본다. 점수 가중치는 건드리지 않는다.
    baseline = simulate(BASE)
    score = baseline["total"]["total_risk_score"]
    band_name = f"DECISION_BAND_L{[25, 50, 75, 90].index(boundary) + 1}_MAX"
    original_load = pt._load_from_db

    def load_at(value):
        values, overrides = original_load()
        values[band_name] = value
        # 앞선 경계가 이 점수보다 낮고 뒤의 경계가 높도록 정렬한다.
        index = [25, 50, 75, 90].index(boundary) + 1
        for n in range(1, 5):
            values[f"DECISION_BAND_L{n}_MAX"] = value + (n - index) * 10
        return values, overrides

    index = [25, 50, 75, 90].index(boundary) + 1
    for offset, expected in ((-0.1, index + 1), (0.1, index)):
        value = score + offset
        monkeypatch.setattr(pt, "_load_from_db", lambda value=value, **_kwargs: load_at(value))
        result = simulate(BASE)
        assert result["base_decision"]["thresholds_applied"][
            [25, 50, 75, 90].index(boundary)
        ][0] == value
        assert result["score_level"] == expected


@pytest.mark.parametrize("changes,rule", [
    ({"location_allowed": False}, "LOCATION_NOT_ALLOWED"),
    ({"impossible_travel": True}, "IMPOSSIBLE_TRAVEL"),
    ({"concurrent_session": True, "device_mismatch": True,
      "auth_failure": True}, "CONCURRENT_DEVICE_AUTH"),
    ({"sensitivity_grade": 4, "location_allowed": False,
      "device_registered": False, "download_attempt": True}, "HIGH_RISK_DOWNLOAD"),
])
def test_immediate_block_matches_policy(policy_snapshot, changes, rule):
    """즉시 차단의 우선순위를 기존 정책 함수와 비교한다."""
    c = {**BASE, **changes}
    result = simulate(c)
    assert result["immediate_block"]["rule"] == rule
    assert result["immediate_block"] == check_immediate_block(c)
    assert result["score_level"] == result["base_decision"]["level"]


@pytest.mark.parametrize("changes", [
    {"user_id": 1}, {"resource_id": 1}, {"body": "text"},
    {"pre_approved": True}, {"requires_approval": True},
    {"break_glass": True}, {"mfa_verified": True}, {1: "bad"},
    {"sensitivity_grade": True}, {"sensitivity_grade": 6},
    {"hour": 24}, {"recent_access_count": -1},
    {"device_registered": 1}, {"data_type": []},
])
def test_invalid_or_unsupported_input_rejected(policy_snapshot, changes):
    """실제 식별자·본문·상태와 잘못된 타입/범위는 계산 전에 거부한다."""
    with pytest.raises(ValueError):
        simulate({**BASE, **changes})


def test_read_failure_and_snapshot_provenance(policy_snapshot, monkeypatch):
    """DB 읽기 오류는 fallback 성공으로 숨기지 않고 스냅샷은 재현 가능하다."""
    first = simulate(BASE)
    second = simulate(BASE)
    assert first["policy_snapshot"] == second["policy_snapshot"]
    assert first["policy_snapshot"]["defaults_used"]
    monkeypatch.setattr(pt, "_load_from_db", lambda **_kwargs: (_ for _ in ()).throw(OSError("db down")))
    with pytest.raises(OSError, match="db down"):
        simulate(BASE)


def test_database_state_unchanged(db):
    """격리 DB에서 로그·세션·사용자 신뢰도·승인 행이 그대로인지 확인한다."""
    name = db.execute("SELECT current_database() AS name").fetchone()["name"]
    assert name.endswith("_test")
    tables = ("access_logs", "audit_logs", "operation_logs", "sensitive_logs",
              "sessions", "users", "approvals", "break_glass_activations",
              "trust_changes")

    def state():
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in tables
        }

    before = state()
    cache_before = dict(pt._CACHE)
    result = simulate(BASE)
    assert result["score_level"] in range(1, 6)
    assert not result["policy_snapshot"]["defaults_used"]
    assert state() == before
    assert pt._CACHE == cache_before
