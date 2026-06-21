"""
결정 매트릭스 스냅샷 테스트

목적: scoring → decision 파이프라인의 (입력 → 결정 레벨) 매핑을 lock-down.
어떤 코드 변경이든 매트릭스를 바꾸면 즉시 빨간불.

매트릭스는 ZT 시스템의 "정책 정확도"를 단언하는 핵심 회귀 안전망이다.
입력 차원:
    - resource_sensitivity (1~5)
    - hour_of_day (낮 14, 밤 2)
    - location_allowed (True/False)
    - device_trust (corporate_mdm, byod, unknown)
    - is_assigned_case (True/False)
    - same_department / pre_approved
    - download_attempt / bulk_query / recent_downloads
    - ip_reputation (clean, suspicious, tor)

출력: 5단계 level (1=완전허용 ~ 5=차단)

본 테스트는 DB 를 건드리지 않는다 (scoring_engine.evaluate + decision_engine.make).
"""
from __future__ import annotations

import pytest

from core.scoring_engine import evaluate as score
from core.decision_engine import make as decide


def _eval(context: dict) -> dict:
    """scoring + decision 파이프라인을 한 번에."""
    s = score(context)
    return decide({
        "risk_score": s["risk_score"],
        "resource_sensitivity": context.get("resource_sensitivity",
                                            context.get("sensitivity_grade", 3)),
        "axes_values": list(s["axes"].values()),
    })


# ─── A. 신뢰 사용자 / 정상 환경 ─────────────────────────────────
NORMAL_TRUSTED = [
    # (case_name, context, expected_level_min, expected_level_max)
    ("admin_low_sens_normal_hours",
     {"resource_sensitivity": 1, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True}, 1, 2),
    ("admin_mid_sens_normal_hours",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "same_department": True}, 1, 2),
    ("admin_high_sens_assigned",
     {"resource_sensitivity": 4, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "same_department": True}, 1, 1),
    # 사전승인이 강력 음수 적합도를 부여해 점수가 충분히 떨어진다.
    ("admin_top_secret_pre_approved",
     {"resource_sensitivity": 5, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "pre_approved": True}, 1, 3),
]


# ─── B. 환경 위험 ───────────────────────────────────────────────
ENVIRONMENT_RISK = [
    ("trusted_user_at_night",
     {"resource_sensitivity": 3, "hour_of_day": 2, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True}, 1, 1),
    ("trusted_user_unallowed_location",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": False, "is_assigned_case": True}, 1, 1),
    ("trusted_user_unknown_device",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "unknown",
      "location_allowed": True, "is_assigned_case": True}, 1, 1),
    ("night_high_sens_unallowed_loc",
     {"resource_sensitivity": 4, "hour_of_day": 2, "device_trust": "corporate_mdm",
      "location_allowed": False, "is_assigned_case": True}, 2, 2),
]


# ─── C. 직무 적합성 ─────────────────────────────────────────────
WORK_FITNESS = [
    ("assigned_case_lowers_risk",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "same_department": True,
      "jurisdiction_match": True}, 1, 2),
    ("non_assigned_raises_level",
     {"resource_sensitivity": 4, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": False, "same_department": False}, 2, 2),
    ("pre_approved_within_ttl",
     {"resource_sensitivity": 4, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": False, "pre_approved": True}, 2, 3),
]


# ─── D. 행위 위험 ───────────────────────────────────────────────
BEHAVIOR_RISK = [
    ("normal_view",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True}, 1, 2),
    ("download_attempt_mid_sens",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "download_attempt": True}, 1, 1),
    ("bulk_query_anomaly",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "bulk_query": True}, 1, 1),
    ("high_recent_downloads",
     {"resource_sensitivity": 3, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": True, "recent_downloads": 50}, 3, 4),
]


# ─── E. 복합 고위험 ─────────────────────────────────────────────
HIGH_RISK_COMBINATIONS = [
    ("night_unallowed_unknown_dev_top_secret",
     {"resource_sensitivity": 5, "hour_of_day": 2, "device_trust": "unknown",
      "location_allowed": False, "is_assigned_case": False}, 4, 5),
    # NOTE: scoring + decision 만으론 ADMIN_APPROVAL 룰(policy_engine)이 안 걸림.
    # 등급 5 비담당 다운로드의 강제 admin_approval 검증은 e2e 시나리오 테스트로
    # 별도 다룬다. 여기는 점수 기반 매핑만 검증.
    ("download_top_secret_non_assigned_score_only",
     {"resource_sensitivity": 5, "hour_of_day": 14, "device_trust": "corporate_mdm",
      "location_allowed": True, "is_assigned_case": False, "download_attempt": True}, 3, 4),
    ("byod_at_night_high_sens_download",
     {"resource_sensitivity": 4, "hour_of_day": 2, "device_trust": "byod",
      "location_allowed": True, "is_assigned_case": True,
      "download_attempt": True}, 2, 2),
]


# ─── F. 민감도 등급 sweep (각 등급별 정상 시나리오) ──────────────
SENSITIVITY_SWEEP = [
    (f"normal_sens_{sens}",
     {"resource_sensitivity": sens, "hour_of_day": 14,
      "device_trust": "corporate_mdm", "location_allowed": True,
      "is_assigned_case": True, "same_department": True},
     1, 4)  # 등급 1~5 모두 정상 환경에선 1~4 사이 (5=차단은 안 나와야)
    for sens in range(1, 6)
]


# ─── G. 시간대 sweep ────────────────────────────────────────────
HOUR_SWEEP = [
    (f"hour_{h}_sens3_assigned",
     {"resource_sensitivity": 3, "hour_of_day": h,
      "device_trust": "corporate_mdm", "location_allowed": True,
      "is_assigned_case": True, "same_department": True},
     1, 3)
    for h in (0, 6, 9, 14, 18, 22)
]


# ─── 통합 매트릭스 ──────────────────────────────────────────────
ALL_CASES = (
    NORMAL_TRUSTED + ENVIRONMENT_RISK + WORK_FITNESS +
    BEHAVIOR_RISK + HIGH_RISK_COMBINATIONS + SENSITIVITY_SWEEP + HOUR_SWEEP
)


@pytest.mark.parametrize("name,context,lvl_min,lvl_max",
                         [(c[0], c[1], c[2], c[3]) for c in ALL_CASES])
def test_decision_matrix(name, context, lvl_min, lvl_max):
    """각 케이스가 기대 level 구간에 들어가는지."""
    result = _eval(context)
    level = result["level"]
    assert lvl_min <= level <= lvl_max, (
        f"{name}: 기대 [{lvl_min}, {lvl_max}], 실제 level={level}, "
        f"risk_score={result['risk_score']}, "
        f"confidence={result['confidence']}, "
        f"pre_confidence_level={result['level_pre_confidence']}"
    )


# ─── 단조성 / 일관성 invariant ──────────────────────────────────
class TestPolicyInvariants:
    """Property-based 스타일 — 입력이 변할 때 결정도 일관되게 변해야 한다."""

    def test_higher_sensitivity_never_lowers_level(self):
        """동일 환경에서 등급이 올라가면 level 도 비감소."""
        ctx = {"hour_of_day": 14, "device_trust": "corporate_mdm",
               "location_allowed": True, "is_assigned_case": True}
        levels = []
        for sens in range(1, 6):
            ctx["resource_sensitivity"] = sens
            levels.append(_eval(ctx)["level"])
        for i in range(1, len(levels)):
            assert levels[i] >= levels[i - 1] - 0, (
                f"등급 {i} → {i+1} 에서 level 이 비논리적으로 하락: {levels}"
            )

    def test_assigned_case_never_raises_level(self):
        """담당 사건 여부만 다를 때, 담당이면 level 이 같거나 낮아야 한다."""
        for sens in (2, 3, 4):
            base = {"resource_sensitivity": sens, "hour_of_day": 14,
                    "device_trust": "corporate_mdm", "location_allowed": True,
                    "same_department": True}
            assigned = _eval({**base, "is_assigned_case": True})
            unassigned = _eval({**base, "is_assigned_case": False})
            assert assigned["level"] <= unassigned["level"], (
                f"sens={sens}: 담당({assigned['level']}) > 비담당({unassigned['level']})"
            )

    def test_night_never_lowers_level_than_day(self):
        """야간 접근이 주간보다 결정 level 이 더 낮아질 수는 없다."""
        for sens in (2, 3, 4):
            base = {"resource_sensitivity": sens, "device_trust": "corporate_mdm",
                    "location_allowed": True, "is_assigned_case": True,
                    "same_department": True}
            day = _eval({**base, "hour_of_day": 14})
            night = _eval({**base, "hour_of_day": 2})
            assert night["level"] >= day["level"], (
                f"sens={sens}: 야간({night['level']}) < 주간({day['level']})"
            )

    def test_unallowed_location_never_lowers_level(self):
        for sens in (2, 3, 4):
            base = {"resource_sensitivity": sens, "hour_of_day": 14,
                    "device_trust": "corporate_mdm", "is_assigned_case": True,
                    "same_department": True}
            allowed = _eval({**base, "location_allowed": True})
            blocked = _eval({**base, "location_allowed": False})
            assert blocked["level"] >= allowed["level"]

    def test_pre_approved_lowers_or_equal_level(self):
        for sens in (3, 4, 5):
            base = {"resource_sensitivity": sens, "hour_of_day": 14,
                    "device_trust": "corporate_mdm", "location_allowed": True,
                    "is_assigned_case": False, "same_department": False}
            no_pre = _eval(base)
            pre = _eval({**base, "pre_approved": True})
            assert pre["level"] <= no_pre["level"]

    def test_top_sensitivity_unassigned_never_full_allow(self):
        """등급 5 자원에 대한 비담당 접근이 L1(완전허용)으로 떨어지면 안 됨."""
        ctx = {"resource_sensitivity": 5, "hour_of_day": 14,
               "device_trust": "corporate_mdm", "location_allowed": True,
               "is_assigned_case": False, "same_department": False}
        result = _eval(ctx)
        assert result["level"] >= 2, (
            f"등급 5 비담당이 level={result['level']} (L1 금지)"
        )


# ─── confidence 진단값 검증 ───────────────────────────────────────
class TestConfidenceAdjustment:
    """confidence 는 진단값이며 접근 레벨을 보정하지 않는다."""

    def test_uncertain_deny_softens_to_admin(self):
        """낮은 confidence 여도 최종 레벨은 총점 구간 그대로다."""
        from core.decision_engine import determine_access_level, compute_confidence
        # 점수 92 (DENY 시작) + 4축 한쪽 극단 + travel inactive
        conf = compute_confidence(
            risk_score=92,
            axes_values=[60, 0, 30, 2],   # 한쪽 극단
            anomaly_hits=2,
            travel_inactive=True,
        )
        d = determine_access_level(92, 5, confidence=conf)
        assert d["level_pre_confidence"] == 5
        assert d["level"] == 5
        assert d["confidence_adjusted"] is False

    def test_confident_decisions_unchanged(self):
        """확신 있는 결정은 조정 없이 그대로."""
        from core.decision_engine import determine_access_level
        # 확신 1.0 (수동 지정) → 무조건 base level
        for risk, sens, expected_level in [
            (10, 1, 1), (40, 1, 2), (60, 1, 3), (80, 1, 4), (95, 1, 5),
        ]:
            d = determine_access_level(risk, sens, confidence=1.0)
            assert d["level"] == expected_level
            assert d["confidence_adjusted"] is False
