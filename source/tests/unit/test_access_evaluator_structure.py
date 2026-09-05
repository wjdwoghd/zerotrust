"""접근 평가 오케스트레이션의 구조적 회귀 테스트."""

from core import access_evaluator


def test_calculate_scoring_calls_each_axis_once(monkeypatch):
    """한 접근 요청은 네 점수 축과 총점 계산을 각각 한 번만 수행한다."""
    calls = {
        "object": 0,
        "environment": 0,
        "behavior": 0,
        "fitness": 0,
        "total": 0,
    }

    def fake_axis(name, score):
        def calculate(*args, **kwargs):
            calls[name] += 1
            return {"score": score, "args": args, "kwargs": kwargs}

        return calculate

    def fake_total(*args):
        calls["total"] += 1
        return {"total_risk_score": sum(args)}

    monkeypatch.setattr(
        access_evaluator,
        "score_object_sensitivity",
        fake_axis("object", 10),
    )
    monkeypatch.setattr(
        access_evaluator,
        "score_environment_risk",
        fake_axis("environment", 20),
    )
    monkeypatch.setattr(
        access_evaluator,
        "score_behavior_risk",
        fake_axis("behavior", 30),
    )
    monkeypatch.setattr(
        access_evaluator,
        "score_work_fitness",
        fake_axis("fitness", -15),
    )
    monkeypatch.setattr(access_evaluator, "calculate_total_risk", fake_total)

    result = access_evaluator._calculate_scoring(
        user={"job_scope": ["traffic"]},
        resource={"sensitivity_grade": 2, "data_type": "original"},
        anomaly_result={"recent_access_count": 1, "anomaly_types": []},
        device_registered=True,
        location_allowed=True,
        is_assigned_case=True,
        same_department=True,
        job_relevance=True,
        pre_approved=False,
        unassigned_penalty_clicks=0,
        is_night=False,
        hour=14,
    )

    assert calls == {
        "object": 1,
        "environment": 1,
        "behavior": 1,
        "fitness": 1,
        "total": 1,
    }
    assert result["total"]["total_risk_score"] == 45
    assert result["behavior_risk"]["kwargs"]["download_attempt"] is False
    assert result["behavior_risk"]["kwargs"]["copy_attempt"] is False
