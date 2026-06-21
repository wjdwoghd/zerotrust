"""
복합 결정 검증 — ZT 원칙 통합 테스트

기존 test_decision_matrix.py 와 보완 관계:
  - test_decision_matrix.py: scoring → decision 의 단순 매트릭스 매핑
  - 본 파일: 즉시차단 우선순위, BG 우회, 강제 분기, multiplier, anomaly+confidence
            결합 등 "여러 메커니즘이 동시 작용" 하는 영역

검증 framework:
  - ZT_원칙_매핑_framework.docx (방향 C)
  - 복합_시나리오_K1_K5.docx (방향 A 의 자동화 대응)

테스트 분류:
  - TestImmediateBlockPriority: 즉시차단 우선순위 (순수 함수)
  - TestForcedAdminApproval: 강제 ADMIN_APPROVAL 분기 (순수 함수)
  - TestCompositeScoreFlow: 4축 합산 + 음수 처리 (순수 함수)
  - TestAnomalyConfidenceCoupling: anomaly + confidence 진단값 (순수 함수)
  - TestPolicyOverrides: 부서별 multiplier (DB 필요)
  - TestBreakGlassOverride: BG 우회 (DB + e2e)
"""
from __future__ import annotations

import pytest

from core.policy_engine import (
    check_immediate_block,
    check_admin_approval_required,
)
from core.scoring_engine import evaluate as score
from core.decision_engine import (
    make as decide,
    compute_confidence,
    determine_access_level,
)


# ═════════════════════════════════════════════════════════════════
# A. 즉시차단 우선순위 — policy_engine 의 3 룰
# ═════════════════════════════════════════════════════════════════
class TestImmediateBlockPriority:
    """즉시차단 룰이 점수 결정보다 먼저 발동하는가."""

    def test_high_risk_download_blocks_with_4_conditions_and(self):
        """HIGH_RISK_DOWNLOAD: 4조건 모두 충족 시에만 차단."""
        # 4조건 모두 True
        ctx = {
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 5,
            "download_attempt": True,
        }
        result = check_immediate_block(ctx)
        assert result["blocked"] is True
        assert result["rule"] == "HIGH_RISK_DOWNLOAD"

    def test_high_risk_download_skips_when_any_condition_missing(self):
        """4조건 중 하나라도 빠지면 HIGH_RISK_DOWNLOAD 룰은 발동하지 않음 — AND 검증.

        정책 갱신(위치 이상 통일): 비허용 위치 단독으로도 차단 대상이지만,
        그 때 매칭되는 rule 은 HIGH_RISK_DOWNLOAD 가 아니라
        LOCATION_NOT_ALLOWED 다. 본 테스트는 룰 2 의 AND 분기가 별도로
        유효함을 확인한다 (rule != HIGH_RISK_DOWNLOAD).
        """
        # 미등록 단말 → 등록 단말로 변경 (1조건 빠짐)
        ctx = {
            "location_allowed": False,
            "device_registered": True,    # 변경
            "sensitivity_grade": 5,
            "download_attempt": True,
        }
        result = check_immediate_block(ctx)
        # 비허용 위치 단독 차단 룰(LOCATION_NOT_ALLOWED)이 잡지만,
        # HIGH_RISK_DOWNLOAD 가 잡으면 안 됨 (룰 2 AND 분기 보존).
        assert result["rule"] != "HIGH_RISK_DOWNLOAD"
        assert result["blocked"] is True
        assert result["rule"] == "LOCATION_NOT_ALLOWED"

        # 등급 3 으로 (sens<4)
        ctx2 = {
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 3,        # 변경
            "download_attempt": True,
        }
        result2 = check_immediate_block(ctx2)
        assert result2["rule"] != "HIGH_RISK_DOWNLOAD"
        assert result2["blocked"] is True
        assert result2["rule"] == "LOCATION_NOT_ALLOWED"

        # 다운로드 X
        ctx3 = {
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 5,
            "download_attempt": False,      # 변경
        }
        result3 = check_immediate_block(ctx3)
        assert result3["rule"] != "HIGH_RISK_DOWNLOAD"
        assert result3["blocked"] is True
        assert result3["rule"] == "LOCATION_NOT_ALLOWED"

    def test_impossible_travel_blocks_alone(self):
        """impossible_travel 단일 신호로 차단."""
        ctx = {"impossible_travel": True}
        result = check_immediate_block(ctx)
        assert result["blocked"] is True
        assert result["rule"] == "IMPOSSIBLE_TRAVEL"

    def test_location_not_allowed_blocks_alone(self):
        """비허용 위치 단일 신호로 차단 (정책 갱신 — 동시 로그인 대응 통일).

        시뮬 패널 등에서 위치를 허용 외 값으로 바꾼 그 순간 그 세션은
        신뢰 보류 상태가 되어야 한다. 룰 2 의 4중 AND 조건 없이도 차단되어야
        access_evaluator 가 pending_reauth 마킹을 트리거할 수 있다.
        """
        ctx = {"location_allowed": False}
        result = check_immediate_block(ctx)
        assert result["blocked"] is True
        assert result["rule"] == "LOCATION_NOT_ALLOWED"

    def test_location_allowed_default_true_does_not_block(self):
        """location_allowed 키가 없으면 (default True) 룰 4 가 발동하지 않음."""
        ctx = {}  # 모든 키 미설정
        result = check_immediate_block(ctx)
        assert result["blocked"] is False

    def test_high_risk_download_precedence_over_location_only(self):
        """4중 AND 조합은 룰 2 의 더 구체적인 매칭이 우선 — 매칭 우선순위 보존."""
        ctx = {
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 5,
            "download_attempt": True,
        }
        result = check_immediate_block(ctx)
        assert result["blocked"] is True
        # 더 구체적인 룰 2 가 잡혀야 한다 (룰 4 가 먼저 잡으면 분석 신호 손실)
        assert result["rule"] == "HIGH_RISK_DOWNLOAD"

    def test_concurrent_device_auth_requires_3_conditions(self):
        """CONCURRENT_DEVICE_AUTH: 3조건 (concurrent + mismatch + auth_fail) AND."""
        # 3조건 모두 True
        ctx = {
            "concurrent_session": True,
            "device_mismatch": True,
            "auth_failure": True,
        }
        result = check_immediate_block(ctx)
        assert result["blocked"] is True
        assert result["rule"] == "CONCURRENT_DEVICE_AUTH"

    def test_concurrent_device_auth_skips_when_one_missing(self):
        """3조건 중 하나라도 빠지면 차단 안 됨."""
        for missing_key in ("concurrent_session", "device_mismatch", "auth_failure"):
            ctx = {
                "concurrent_session": True,
                "device_mismatch": True,
                "auth_failure": True,
            }
            ctx[missing_key] = False
            result = check_immediate_block(ctx)
            assert result["blocked"] is False, (
                f"{missing_key}=False 인데 차단됨 — AND 분기 결함"
            )


# ═════════════════════════════════════════════════════════════════
# B. 강제 ADMIN_APPROVAL 분기 — 등급 4-5 비담당
# ═════════════════════════════════════════════════════════════════
class TestForcedAdminApproval:
    """등급 >= 4 + 비담당 + 비-부서 → 강제 admin_approval."""

    def test_grade5_non_assigned_non_dept_forces_approval(self):
        """등급 5 + 비담당 + 부서 외 → True."""
        ctx = {
            "sensitivity_grade": 5,
            "is_assigned_case": False,
            "same_department": False,
        }
        assert check_admin_approval_required(ctx) is True

    def test_grade4_non_assigned_non_dept_forces_approval(self):
        """등급 4 도 동일 분기 적용."""
        ctx = {
            "sensitivity_grade": 4,
            "is_assigned_case": False,
            "same_department": False,
        }
        assert check_admin_approval_required(ctx) is True

    def test_grade5_assigned_does_not_force(self):
        """담당 사건이면 강제 분기 미발동."""
        ctx = {
            "sensitivity_grade": 5,
            "is_assigned_case": True,
            "same_department": False,
        }
        assert check_admin_approval_required(ctx) is False

    def test_grade5_same_department_does_not_force(self):
        """같은 부서면 강제 분기 미발동."""
        ctx = {
            "sensitivity_grade": 5,
            "is_assigned_case": False,
            "same_department": True,
        }
        assert check_admin_approval_required(ctx) is False

    def test_grade3_does_not_force_even_if_unassigned(self):
        """등급 3 이하는 강제 분기 미발동."""
        ctx = {
            "sensitivity_grade": 3,
            "is_assigned_case": False,
            "same_department": False,
        }
        assert check_admin_approval_required(ctx) is False

    def test_requires_approval_flag_forces(self):
        """resource.requires_approval=True 자체로 강제."""
        ctx = {"requires_approval": True}
        assert check_admin_approval_required(ctx) is True


# ═════════════════════════════════════════════════════════════════
# C. 복합 점수 합산 — 4축 동시 작용
# ═════════════════════════════════════════════════════════════════
class TestCompositeScoreFlow:
    """4축이 동시에 작용할 때의 합산 정확성."""

    def test_trusted_path_all_fitness_discounts_accumulate(self):
        """K1: 모든 fitness 차감 누적 — 점수 분해 + 결정 결과 분리 단언.

        목적 분리 (시나리오 문서 K1 갱신과 정합):
          (a) 4가지 fitness 차감(-20 -10 -5 -10 = -45) 가 정확히 누적되는지
              → 점수 분해 (work_fitness, risk_score, level_pre_confidence) 검증
          (b) 최종 decision.level 이 4축 총점 구간 그대로 유지되는지 검증한다.
        """
        ctx = {
            "resource_sensitivity": 1,
            "hour_of_day": 14,
            "device_trust": "corporate_mdm",
            "location_allowed": True,
            "is_assigned_case": True,
            "same_department": True,
            "jurisdiction_match": True,
            "job_relevance": True,
        }
        s = score(ctx)

        # (a) 점수 분해 본질
        assert s["risk_score"] <= 25, (
            f"모든 차감 누적인데 risk_score={s['risk_score']} > 25 — fitness 결함"
        )
        # 4가지 fitness 항목 모두 매칭 → -45
        assert s["axes"]["fitness"] == -45, (
            f"4축 fitness 누적 결함: {s['axes']}"
        )

        d = decide({
            "risk_score": s["risk_score"],
            "resource_sensitivity": ctx["resource_sensitivity"],
            "axes_values": list(s["axes"].values()),
        })
        # 점수 자체는 L1 영역 (0 ≤ 25)
        assert d["level_pre_confidence"] == 1, (
            f"base level=1 기대, got {d['level_pre_confidence']} "
            f"— scoring/decision 매핑 결함"
        )

        # (b) 최종 결정 — 4축 총점 구간 그대로
        assert d["level"] == 1
        assert d["confidence_adjusted"] is False

    def test_night_time_adds_full_risk_and_level_matches_score_band(self):
        """심야 전환 시 환경축 +15가 그대로 반영되고 결정 레벨은 총점 구간과 일치."""
        normal_ctx = {
            "resource_sensitivity": 3,
            "data_type": "evidence",
            "hour_of_day": 14,
            "device_trust": "corporate_mdm",
            "location_allowed": True,
            "is_assigned_case": True,
            "same_department": True,
            "jurisdiction_match": True,
            "job_relevance": True,
            "job_scope": ["violent_crime"],
        }
        night_ctx = {**normal_ctx, "hour_of_day": 2}

        normal = score(normal_ctx)
        night = score(night_ctx)

        assert night["axes"]["environment"] - normal["axes"]["environment"] == 15
        assert night["risk_score"] - normal["risk_score"] == 15

        for scored in (normal, night):
            decision = decide({
                "risk_score": scored["risk_score"],
                "resource_sensitivity": normal_ctx["resource_sensitivity"],
                "confidence": 1.0,
            })
            assert decision["matched_band"]["level"] == decision["level"]
            assert decision["level_pre_confidence"] == decision["level"]
            assert decision["confidence_adjusted"] is False

    def test_anomaly_cascade_multi_penalty_score(self):
        """K3: 야간 + 미등록 + 비허용 + 다운로드 + 비담당 → 점수 폭증."""
        ctx = {
            "resource_sensitivity": 3,
            "hour_of_day": 2,
            "device_trust": "unknown",
            "location_allowed": False,
            "is_assigned_case": False,
            "same_department": False,
            "download_attempt": True,
        }
        s = score(ctx)
        # 환경 페널티 + 다운로드 가산 + sens 3 → 매우 높음
        assert s["risk_score"] >= 60, (
            f"다축 위험 누적인데 risk_score={s['risk_score']} < 60 — 합산 결함"
        )

    def test_composite_edge_assigned_in_risky_env(self):
        """K5: 담당 + 위험 환경 — 두 효과가 동시에 작용."""
        # detective_kim 같은 케이스 — 담당 + 야간 + 미등록 + 외부 + 다운로드
        ctx_risky_assigned = {
            "resource_sensitivity": 1,
            "hour_of_day": 2,
            "device_trust": "unknown",
            "location_allowed": False,
            "is_assigned_case": True,
            "same_department": True,
            "jurisdiction_match": True,
            "job_relevance": True,
            "download_attempt": True,
        }
        ctx_risky_unassigned = {**ctx_risky_assigned}
        ctx_risky_unassigned["is_assigned_case"] = False
        ctx_risky_unassigned["same_department"] = False
        ctx_risky_unassigned["jurisdiction_match"] = False
        ctx_risky_unassigned["job_relevance"] = False

        s_assigned = score(ctx_risky_assigned)
        s_unassigned = score(ctx_risky_unassigned)
        # 담당이 비담당보다 점수가 더 낮아야 한다 (차감 효과)
        assert s_assigned["risk_score"] <= s_unassigned["risk_score"], (
            f"담당({s_assigned['risk_score']}) > 비담당({s_unassigned['risk_score']}) "
            f"— fitness 차감 미작동"
        )


# ═════════════════════════════════════════════════════════════════
# D. Anomaly + Confidence 결합
# ═════════════════════════════════════════════════════════════════
class TestAnomalyConfidenceCoupling:
    """anomaly 신호가 confidence 산출에 영향을 주는가."""

    def test_anomaly_hits_lower_confidence(self):
        """anomaly hits 가 늘어날수록 confidence 가 낮아져야."""
        # 동일 risk_score / axes 에서 anomaly hits 만 변경
        base_args = {
            "risk_score": 50,
            "axes_values": [30, 10, 5, -5],
            "travel_inactive": False,
        }
        c0 = compute_confidence(anomaly_hits=0, **base_args)
        c1 = compute_confidence(anomaly_hits=1, **base_args)
        c2 = compute_confidence(anomaly_hits=2, **base_args)
        assert c0 >= c1 >= c2, (
            f"anomaly hits 증가 시 confidence 단조감소 안 함: {c0}, {c1}, {c2}"
        )

    def test_travel_inactive_lowers_confidence(self):
        """travel detection inactive 가 confidence 를 낮춤."""
        c_active = compute_confidence(
            risk_score=50, axes_values=[30, 10, 5, -5],
            anomaly_hits=0, travel_inactive=False,
        )
        c_inactive = compute_confidence(
            risk_score=50, axes_values=[30, 10, 5, -5],
            anomaly_hits=0, travel_inactive=True,
        )
        assert c_inactive <= c_active

    def test_boundary_proximity_lowers_confidence(self):
        """결정 경계에 가까울수록 confidence 가 낮음."""
        c_far = compute_confidence(
            risk_score=10,        # L1 중앙
            axes_values=[5, 5, 0, 0],
            anomaly_hits=0, travel_inactive=False,
        )
        c_near = compute_confidence(
            risk_score=49,        # L2/L3 경계 (50) 직전
            axes_values=[20, 15, 5, 5],
            anomaly_hits=0, travel_inactive=False,
        )
        # 경계 거리가 짧을수록 confidence 가 낮아져야
        assert c_near <= c_far, (
            f"경계 근접({c_near}) 이 멀리({c_far}) 보다 confidence 가 더 높음 — "
            f"_band_distance_score 결함"
        )

    def test_low_confidence_does_not_change_decision_level(self):
        """경계 근접 + anomaly + travel inactive 여도 레벨은 총점 구간 그대로."""
        # 점수 92 (DENY 시작) + 4축 분산 + anomaly + travel inactive
        conf = compute_confidence(
            risk_score=92,
            axes_values=[60, 0, 30, 2],
            anomaly_hits=2,
            travel_inactive=True,
        )
        d = determine_access_level(92, sensitivity_grade=5, confidence=conf)
        assert d["level"] == 5
        assert d["confidence_adjusted"] is False


# ═════════════════════════════════════════════════════════════════
# E. policy_overrides — 부서별 multiplier (DB 필요)
# ═════════════════════════════════════════════════════════════════
class TestPolicyOverrides:
    """016 마이그레이션의 multiplier 가 점수 산출에 반영되는가.

    실제 DB 연결 + 016 시드 적용 상태 가정.
    """

    @pytest.mark.skipif(
        not pytest.importorskip("psycopg2", reason="DB 미가용"),
        reason="DB 의존 테스트",
    )
    def test_violent_crime_night_multiplier(self, db):
        """job_scope=violent_crime 사용자도 야간 페널티는 기본 +15 그대로 적용."""
        # 시드 시점 상수
        EXPECTED_BASE_NIGHT = 15
        EXPECTED_MULTIPLIER = 1.0
        EXPECTED_VC_NIGHT = EXPECTED_BASE_NIGHT * EXPECTED_MULTIPLIER  # 15.0

        # 실제 시드 값 확인
        row = db.execute("""
            SELECT multiplier FROM policy_overrides
             WHERE job_category='violent_crime'
               AND threshold_name='ENV_NIGHT_TIME'
        """).fetchone()
        assert row is not None, "policy_overrides 에 violent_crime/ENV_NIGHT_TIME 시드 없음"
        assert float(row["multiplier"]) == EXPECTED_MULTIPLIER, (
            f"multiplier 시드 = {row['multiplier']}, expected {EXPECTED_MULTIPLIER}"
        )

        # ENV_NIGHT_TIME 시드값 확인
        row2 = db.execute(
            "SELECT value FROM policy_thresholds WHERE name='ENV_NIGHT_TIME'"
        ).fetchone()
        assert row2 is not None
        assert float(row2["value"]) == EXPECTED_BASE_NIGHT

        scored = score({
            "resource_sensitivity": 1,
            "hour_of_day": 2,
            "device_trust": "corporate_mdm",
            "location_allowed": True,
            "job_scope": ["violent_crime"],
        })
        assert scored["axes"]["environment"] == EXPECTED_VC_NIGHT


# ═════════════════════════════════════════════════════════════════
# F. Break-Glass 우회 (DB + e2e)
# ═════════════════════════════════════════════════════════════════
class TestBreakGlassOverride:
    """BG 활성 상태에서 즉시차단 룰까지 우회되는가.

    실제 라이브 서버 + admin_lee 토큰 + BG 활성 상태 필요.
    e2e 검증이라 시뮬 한계가 있음. 핵심 흐름만 단위 검증.
    """

    def test_immediate_block_returns_blocked_for_high_risk_download(self):
        """전제: 4조건 모두 충족 시 즉시차단이 본래 발동."""
        ctx = {
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 5,
            "download_attempt": True,
        }
        result = check_immediate_block(ctx)
        # BG 가 우회하기 전 baseline — 차단이 정상 발동해야
        assert result["blocked"] is True, (
            "전제 미달: 즉시차단 룰 자체가 작동 안 함 — BG 우회 검증 무의미"
        )


# ═════════════════════════════════════════════════════════════════
# G. 통합 invariants — 정책 일관성 (보강)
# ═════════════════════════════════════════════════════════════════
class TestPolicyCompositeInvariants:
    """test_decision_matrix.py 의 TestPolicyInvariants 보강."""

    def test_immediate_block_dominates_low_risk_score(self):
        """위험 점수가 낮아도 즉시차단 룰이 발동하면 차단."""
        # 점수 자체는 매우 낮은 컨텍스트
        low_risk_ctx = {
            "resource_sensitivity": 5,
            "hour_of_day": 14,
            "device_trust": "corporate_mdm",
            "location_allowed": True,
            "is_assigned_case": True,
            "same_department": True,
        }
        s = score(low_risk_ctx)
        # 점수만으로는 낮은 결정
        d = decide({
            "risk_score": s["risk_score"],
            "resource_sensitivity": 5,
            "axes_values": list(s["axes"].values()),
        })
        # 별도로 즉시차단이 트리거되면 그것이 우선
        block_ctx = {
            **low_risk_ctx,
            "location_allowed": False,
            "device_registered": False,
            "sensitivity_grade": 5,
            "download_attempt": True,
        }
        block_result = check_immediate_block(block_ctx)
        # 두 분기는 분리돼 있으나, access_evaluator 가 즉시차단을 먼저 검사
        # 본 테스트는 두 분기가 모두 의도대로 작동함을 단언
        assert block_result["blocked"] is True
        # 점수 흐름은 별도로 (감산이 강함)
        assert d["level"] <= 3

    def test_grade5_unassigned_never_l1(self):
        """등급 5 + 비담당 → 절대 L1 으로 떨어지지 않음 (강제 분기)."""
        # check_admin_approval_required 가 True 면 강제 ADMIN_APPROVAL
        force = check_admin_approval_required({
            "sensitivity_grade": 5,
            "is_assigned_case": False,
            "same_department": False,
        })
        assert force is True

    def test_pre_approval_flag_lowers_risk(self):
        """사전 승인 플래그가 점수를 낮춘다."""
        base_ctx = {
            "resource_sensitivity": 4,
            "hour_of_day": 14,
            "device_trust": "corporate_mdm",
            "location_allowed": True,
            "is_assigned_case": False,
            "same_department": False,
        }
        s_no_pre = score(base_ctx)
        s_pre = score({**base_ctx, "pre_approved": True})
        assert s_pre["risk_score"] <= s_no_pre["risk_score"], (
            f"사전승인({s_pre['risk_score']}) > 미승인({s_no_pre['risk_score']}) "
            f"— FIT_PRE_APPROVED 미적용"
        )
