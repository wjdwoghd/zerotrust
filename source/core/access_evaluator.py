"""
접근 평가 통합 모듈
모든 엔진과 서비스를 오케스트레이션하여 최종 접근 결정을 도출
"""
import json
import logging
import time
import uuid
from config import PRE_APPROVAL_TTL_SEC, REAUTH_TTL_SEC

# ITEM 12: 진단 출력은 stderr 직접 print 대신 표준 logging 으로.
_log = logging.getLogger(__name__)
from database import get_db, row_to_dict
from core.scoring_engine import (
    score_object_sensitivity, score_environment_risk,
    score_behavior_risk, score_work_fitness, calculate_total_risk
)
from core.policy_engine import check_immediate_block, check_force_reauth, check_admin_approval_required
from core.decision_engine import (
    determine_access_level, get_external_response,
    get_action_permissions,
)
from core.masking_engine import apply_masking
from core.anomaly_service import detect_anomalies
from core import travel_service
from core.audit_events import AuditEvent, audit_log
from core import break_glass as _bg


def evaluate_access(user_id: int, resource_id: int, session_id: int = None,
                    device_id: str = "registered-001", ip_address: str = "192.168.1.1",
                    location: str = "본청", action_type: str = "view",
                    is_night: bool = False,
                    hour: int | None = None,
                    record_access: bool = True,
                    mutate_state: bool = True,
                    include_resource_body: bool = True) -> dict:
    """
    접근 요청 종합 평가 → 최종 결정 반환

    Returns: {
        "request_id": str,
        "decision": {...},
        "scoring": {...},
        "policy_check": {...},
        "anomaly_check": {...},
        "resource": {...},  (마스킹 적용된 리소스)
        "external_message": str,
    }
    """
    request_id = str(uuid.uuid4())[:8]
    db = get_db()

    # ── 사용자/리소스 조회 ──
    user_row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    resource_row = db.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()

    if not user_row or not resource_row:
        decision = {"level": 5, "label": "차단", "label_en": "BLOCKED", "risk_score": 999}
        _finalize_decision(decision)
        db.close()
        return {
            "request_id": request_id,
            "error": "사용자 또는 리소스를 찾을 수 없습니다",
            "decision": decision,
        }

    user = row_to_dict(user_row)
    resource = row_to_dict(resource_row)

    # ── 세션 정보 ──
    session = None
    session_device = device_id
    if session_id:
        session_row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if session_row:
            session = row_to_dict(session_row)
            session_device = session.get("device_id", device_id)

    # ── 컨텍스트 구성 ──
    registered_devices = user.get("registered_devices", [])
    allowed_locations = user.get("allowed_locations", [])
    assigned_cases = user.get("assigned_cases", [])

    device_registered = device_id in registered_devices
    location_allowed = location in allowed_locations
    is_assigned_case = resource_id in assigned_cases or resource.get("case_number") in [str(c) for c in assigned_cases]
    same_department = user.get("department") == resource.get("department")

    # 보고서 §7-3 Table 21: 직무 연관성(-20).
    # users.job_scope 와 resources.job_tags 의 교집합이 비어있지 않으면 인정.
    user_job_scope = user.get("job_scope") or []
    resource_job_tags = resource.get("job_tags") or []
    if not isinstance(user_job_scope, (list, set, tuple)):
        user_job_scope = []
    if not isinstance(resource_job_tags, (list, set, tuple)):
        resource_job_tags = []
    job_relevance = bool(set(user_job_scope) & set(resource_job_tags))
    unassigned_clicks = _count_unassigned_case_clicks(db, user_id, session_id)
    # 첫 비담당 사건 클릭은 UI 경고만 남긴다. 두 번째 클릭부터 회당 +10.
    unassigned_penalty_clicks = max(0, int(unassigned_clicks) - 1)

    # ── 사전 승인 여부 확인 (관리자 승인 후 PRE_APPROVAL_TTL_SEC 이내 유효) ──
    # Option Y: 관리자 승인에 download_allowed 플래그가 실려 있으면
    #           해당 TTL 동안 level 1 (다운로드 허용) 로 승격.
    #
    # ITEM 1 — TTL 판정을 SQL 측으로 이전. 기존 파이썬 strptime 경로는
    # psycopg2 가 datetime 객체를 반환하면 TypeError → except 로 fail-open
    # (pre_approved=True) 되는 결함이 있었다 (감사 결함 #1). resolved_at 은
    # TIMESTAMPTZ 라 PG 측에서 직접 비교하는 것이 정확·안전.
    pre_approved = False
    approved_download = False
    approval_row = db.execute("""
        SELECT id, resolved_at, download_allowed FROM approvals
        WHERE requester_id=? AND resource_id=? AND status='approved'
          AND resolved_at IS NOT NULL
          AND resolved_at > (CURRENT_TIMESTAMP - INTERVAL '1 second' * ?)
        ORDER BY resolved_at DESC LIMIT 1
    """, (user_id, resource_id, PRE_APPROVAL_TTL_SEC)).fetchone()
    if approval_row:
        pre_approved = True
        # PostgreSQL 은 BOOLEAN — bool() 로 진위 평가
        approved_download = bool(approval_row["download_allowed"])

    # ── 1단계: 이상행동 탐지 ──
    anomaly_result = detect_anomalies(
        user_id=user_id,
        session_id=session_id or 0,
        action_type=action_type,
        device_id=device_id,
        session_device=session_device
    )

    # ── 2단계: 규칙 기반 즉시 차단 선검사 ──
    # L4-2: impossible_travel 하드코딩 제거. 세션 이력 기반 동적 계산.
    impossible_travel_flag = False
    travel_reason = None
    if session is not None:
        impossible_travel_flag, travel_reason = travel_service.evaluate(
            last_location=session.get("last_location"),
            last_location_time=session.get("last_location_time"),
            current_location=location,
        )
        if (travel_reason or "").startswith("inactive:"):
            # 비활성 사유는 1회 경고 이벤트로 기록 (L5-2)
            if mutate_state:
                audit_log(
                    db=db,
                    event=AuditEvent.TRAVEL_DETECTION_INACTIVE,
                    user_id=user_id,
                    request_id=request_id,
                    details={"reason": travel_reason},
                    severity=1,
                    layer="operation",
                )
            impossible_travel_flag = False

    policy_context = {
        "concurrent_session": anomaly_result.get("concurrent_session", False),
        "device_mismatch": anomaly_result.get("device_mismatch", False),
        "auth_failure": user.get("failed_login_count", 0) > 0,
        "location_allowed": location_allowed,
        "device_registered": device_registered,
        "sensitivity_grade": resource.get("sensitivity_grade", 1),
        "download_attempt": action_type == "download",
        "impossible_travel": impossible_travel_flag,
        "is_assigned_case": is_assigned_case,
        "same_department": same_department,
        "device_changed": device_id != session_device if session else False,
        "location_changed": (
            bool(session) and session.get("last_location")
            and session.get("last_location") != location
        ),
        "requires_approval": resource.get("requires_approval", False),
    }

    # ── 3단계: 4축 점수 산출 ──
    # 즉시차단 예외가 걸리더라도 총 위험점수 자체는 4축 계산값으로 남긴다.
    obj_result = score_object_sensitivity(
        resource["sensitivity_grade"], resource.get("data_type", "summary")
    )
    user_categories = user.get("job_scope") if isinstance(user.get("job_scope"), list) else None

    is_relaxed = False
    if hour is not None:
        is_night = (hour >= 22 or hour < 6)
        if not is_night:
            is_relaxed = (6 <= hour < 9) or (18 <= hour < 22)

    env_result = score_environment_risk(
        device_registered, location_allowed, is_night,
        relaxed_time=is_relaxed,
        user_categories=user_categories,
    )
    beh_result = score_behavior_risk(
        access_count_5min=anomaly_result.get("recent_access_count", 0),
        download_attempt=False,
        copy_attempt=False,
        bulk_query=("BULK_QUERY" in anomaly_result.get("anomaly_types", [])),
        unauthorized_access=not is_assigned_case,
        high_sensitivity_unassigned=(not is_assigned_case and int(resource.get("sensitivity_grade", 1)) >= 4),
        unassigned_click_count=unassigned_penalty_clicks,
    )
    fit_result = score_work_fitness(
        is_assigned_case=is_assigned_case,
        same_department=same_department,
        jurisdiction_match=same_department,
        pre_approved=pre_approved,
        job_relevance=job_relevance,
    )
    total_result = calculate_total_risk(
        obj_result["score"], env_result["score"],
        beh_result["score"], fit_result["score"]
    )
    scoring = {
        "object_sensitivity": obj_result,
        "environment_risk": env_result,
        "behavior_risk": beh_result,
        "work_fitness": fit_result,
        "total": total_result,
    }

    block_result = check_immediate_block(policy_context)
    if block_result["blocked"]:
        score_decision = determine_access_level(
            total_result["total_risk_score"],
            resource["sensitivity_grade"],
            confidence=1.0,
        )
        # ── Break-Glass 우회 기회 (Phase 2-fix) ──
        # 이전에는 immediate_block 에 걸리면 그대로 차단하고 return 해서,
        # 아래 §5.5 의 BG 검사(decision["level"] >= 4 분기)가 실행되지 않았다.
        # 그 결과 BG 를 정당하게 발동한 사용자도 device_mismatch /
        # location_not_allowed / downloading_high_sens 같은 즉시차단 규칙에
        # 걸리면 파일 다운로드가 막히는 버그가 있었다.
        # BG 의 설계 목적은 "정책 차단을 포함한 긴급 접근 허용" 이므로,
        # level 5(차단) 단계에서도 반드시 BG 검사를 수행한다.
        active_bg = _probe_active_bg(
            db, user_id, resource_id, resource["sensitivity_grade"],
            request_id, where="immediate_block",
        )

        if active_bg is not None:
            if mutate_state:
                _bg.consume(
                    db=db,
                    activation_id=int(active_bg["id"]),
                    resource_id=resource_id,
                    user_id=user_id,
                    request_id=request_id,
                )
            decision = {
                "level": 1,
                "label": "전체 허용 (Break-Glass)",
                "label_en": "FULL_ACCESS_BREAK_GLASS",
                "external_message": (
                    "Break-Glass 경로로 열람·다운로드가 허용됩니다. "
                    "모든 행동이 감사되며 사후 리뷰 대상입니다."
                ),
                "risk_score": total_result["total_risk_score"],
                "score_level": score_decision["level"],
                "score_label": score_decision["label"],
                "sensitivity_grade": resource["sensitivity_grade"],
                "reason": (
                    "긴급 접근(Break-Glass) 으로 정책 차단을 우회하여 "
                    "열람·다운로드를 허용합니다. 사후 검토 대상입니다."
                ),
                "override": {
                    "type": "BREAK_GLASS",
                    "rule": block_result.get("rule"),
                    "reason": "긴급 접근 승인으로 즉시차단을 우회",
                },
                "break_glass": {
                    "activation_id": int(active_bg["id"]),
                    "scope": active_bg["scope"],
                    "expires_at": str(active_bg.get("expires_at") or ""),
                    "overrode_rule": block_result.get("rule"),
                },
            }
            _finalize_decision(decision, scoring)
            if record_access:
                _log_access(db, request_id, user, resource, session_id, decision,
                             obj_result["score"], env_result["score"],
                             beh_result["score"], fit_result["score"],
                             device_id, ip_address, location, action_type,
                             decision["reason"])
            masked_resource = apply_masking(resource, 1, user.get("name", ""))
            db.close()
            return _build_response(request_id, decision, scoring, block_result,
                                   anomaly_result, masked_resource,
                                   include_resource_body=include_resource_body)

        # BG 없음 → 기존대로 즉시차단.
        # ── 동시 로그인 대응과 통일: 위치 룰(IMPOSSIBLE_TRAVEL /
        # LOCATION_NOT_ALLOWED)에 의한 차단이고 살아있는 세션이 있으면,
        # 그 세션을 pending_reauth=TRUE 로 마킹한다. 이렇게 하면
        # base_handler.require_auth() 가 후속 요청에서 401
        # concurrent_session_detected 로 끊어, 동시 로그인 케이스와
        # 같은 OTP 재인증 모달을 띄운다.
        if mutate_state:
            _lock_session_for_location_anomaly(
                db=db,
                session_id=session_id,
                user_id=user_id,
                rule=block_result.get("rule"),
                reason=block_result.get("reason"),
                request_id=request_id,
                attempted_location=location,
                attempted_device_id=device_id,
            )
        decision = {
            "level": 5,
            "label": "즉시 차단",
            "label_en": "IMMEDIATE_BLOCK",
            "external_message": "접근이 제한되었습니다.",
            "risk_score": total_result["total_risk_score"],
            "score_level": score_decision["level"],
            "score_label": score_decision["label"],
            "sensitivity_grade": resource["sensitivity_grade"],
            "reason": block_result["reason"],
            "rule": block_result["rule"],
            "override": {
                "type": "IMMEDIATE_BLOCK",
                "rule": block_result["rule"],
                "reason": block_result["reason"],
                "score_level": score_decision["level"],
                "score_label": score_decision["label"],
            },
        }
        _finalize_decision(decision, scoring)
        if record_access:
            _log_access(db, request_id, user, resource, session_id, decision,
                         obj_result["score"], env_result["score"],
                         beh_result["score"], fit_result["score"],
                         device_id, ip_address, location, action_type,
                         block_result["reason"])
        masked_resource = apply_masking(resource, 5, user.get("name", ""))
        db.close()
        return _build_response(request_id, decision, scoring, block_result,
                               anomaly_result, masked_resource,
                               include_resource_body=include_resource_body)

    # ── 3단계: 4축 점수 산출 ──
    obj_result = score_object_sensitivity(
        resource["sensitivity_grade"], resource.get("data_type", "summary")
    )
    # 016: 사용자 job_scope 를 user_categories 로 전달해 부서별 multiplier 적용
    user_categories = user.get("job_scope") if isinstance(user.get("job_scope"), list) else None

    # 시간대 분류 — hour 가 명시되면 우선 사용 (시뮬 패널 X-Sim-Hour 헤더
    # 또는 호출자가 직접 지정). 그 외에는 is_night 만 받던 구버전 호환.
    #   심야: 22~06    → ENV_NIGHT_TIME (+15)
    #   추가 근무: 06~09 / 18~22 → ENV_RELAXED_TIME (+5)
    #   근무: 09~18    → 가산 0
    is_relaxed = False
    if hour is not None:
        is_night = (hour >= 22 or hour < 6)
        if not is_night:
            is_relaxed = (6 <= hour < 9) or (18 <= hour < 22)

    env_result = score_environment_risk(
        device_registered, location_allowed, is_night,
        relaxed_time=is_relaxed,
        user_categories=user_categories,
    )
    beh_result = score_behavior_risk(
        access_count_5min=anomaly_result.get("recent_access_count", 0),
        # 현재 요청의 download/copy 클릭은 그 자체로 감사·이상행동 로그에는
        # 남지만, 권한 결정 점수에는 "이전까지 누적된 상태" 만 반영한다.
        # 그렇지 않으면 L1 로 표시된 문서가 다운로드 요청 순간 자체 가산점
        # 때문에 L2 로 뒤집혀 점수-레벨-행동권한이 자기모순을 일으킨다.
        download_attempt=False,
        copy_attempt=False,
        bulk_query=("BULK_QUERY" in anomaly_result.get("anomaly_types", [])),
        unauthorized_access=not is_assigned_case,
        high_sensitivity_unassigned=(not is_assigned_case and int(resource.get("sensitivity_grade", 1)) >= 4),
        unassigned_click_count=unassigned_penalty_clicks,
    )
    # 보고서 §7-3 Table 21: 직무 연관성(-20)은 위에서 계산한 job_relevance
    # (users.job_scope ∩ resources.job_tags) 값을 그대로 전달한다.
    fit_result = score_work_fitness(
        is_assigned_case=is_assigned_case,
        same_department=same_department,
        jurisdiction_match=same_department,
        pre_approved=pre_approved,
        job_relevance=job_relevance,
    )

    total_result = calculate_total_risk(
        obj_result["score"], env_result["score"],
        beh_result["score"], fit_result["score"]
    )

    scoring = {
        "object_sensitivity": obj_result,
        "environment_risk": env_result,
        "behavior_risk": beh_result,
        "work_fitness": fit_result,
        "total": total_result,
    }

    # ── 4단계: 강제 재인증 검사 ──
    reauth_result = check_force_reauth(policy_context)
    admin_required = check_admin_approval_required(policy_context)

    # 이미 최근에 재인증을 완료한 세션이면 force_reauth 요구를 충족한
    # 것으로 간주한다. (reauth_at 이 REAUTH_TTL_SEC 이내여야 한다.)
    # /api/auth/reauth 성공 시 sessions.reauth_at = now() 로 갱신된다.
    reauth_satisfied = False
    if session is not None and session.get("reauth_at"):
        try:
            import datetime as _dt
            ra = session["reauth_at"]
            if isinstance(ra, str):
                # 문자열 timestamp 입력은 포맷을 유연하게 파싱한다.
                try:
                    ra_dt = _dt.datetime.strptime(ra, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # 소수점 초 또는 tz offset 포함 등
                    ra_dt = _dt.datetime.fromisoformat(ra.replace("Z", "+00:00"))
                    if ra_dt.tzinfo is not None:
                        ra_dt = ra_dt.astimezone(_dt.timezone.utc).replace(tzinfo=None)
            else:
                # psycopg2 TIMESTAMPTZ → tz-aware datetime
                if getattr(ra, "tzinfo", None) is not None:
                    ra_dt = ra.astimezone(_dt.timezone.utc).replace(tzinfo=None)
                else:
                    ra_dt = ra
            elapsed_ra = (_dt.datetime.utcnow() - ra_dt).total_seconds()
            reauth_satisfied = 0 <= elapsed_ra < REAUTH_TTL_SEC
        except Exception:
            reauth_satisfied = False

    # ── 5단계: 최종 결정 ──
    # 정상 경로의 접근 레벨은 4축 총 위험점수 구간만으로 결정한다.
    decision = determine_access_level(
        total_result["total_risk_score"],
        resource["sensitivity_grade"],
        confidence=1.0,
    )
    decision["score_level"] = decision["level"]
    decision["score_label"] = decision["label"]

    # 강제 재인증이 필요한 경우 레벨 상향 — 단, 최근 재인증 세션은 예외.
    if reauth_result["reauth_required"] and decision["level"] < 3:
        if reauth_satisfied:
            # 재인증이 최근에 완료된 세션. force_reauth 요구를 충족한 것으로 간주.
            decision["reason"] = (
                (decision.get("reason") or "")
                + f" [재인증 유효: reauth_at 기준 {REAUTH_TTL_SEC}s 이내]"
            ).strip()
        else:
            decision["level"] = 3
            decision["label"] = "추가 인증 후 허용"
            decision["label_en"] = "REAUTH_REQUIRED"
            decision["external_message"] = "추가 인증이 필요합니다."
            decision["reason"] = reauth_result["reason"]
            decision["override"] = {
                "type": "REAUTH_REQUIRED",
                "reason": reauth_result["reason"],
                "score_level": decision.get("score_level"),
                "score_label": decision.get("score_label"),
            }

    # ── L3(REAUTH_REQUIRED) → L1 해제 ──
    # decision.level 이 3 인 상태에서 세션의 reauth_at 이 REAUTH_TTL_SEC
    # 이내라면 열람·다운로드를 풀어준다(level=1). OTP 로 토큰 기기 점유를
    # 증명한 사용자는 해당 창(TTL) 동안 L3 자원을 완전히 열 수 있어야 한다는
    # 스펙 의도에 맞춘 것. 이전에는 reauth_at 이 있어도 score-based L3 가
    # 그대로 남아 "재인증했는데 여전히 안 열린다" 는 UX 버그가 있었다.
    #
    # 이 승격은 admin_required 블록보다 앞에 위치한다 — admin_required=True
    # 인 자원(requires_approval=1 또는 sens>=4 비담당)은 다음 블록에서
    # 다시 L4 로 잠긴다. 즉 admin 게이트는 OTP 로 열리지 않는다(정상).
    if decision["level"] == 3 and reauth_satisfied:
        decision["level"] = 1
        decision["label"] = "전체 허용 (재인증 완료)"
        decision["label_en"] = "FULL_ACCESS_REAUTH"
        decision["external_message"] = (
            "재인증 완료 — 열람 및 다운로드가 허용됩니다."
        )
        decision["reason"] = (
            (decision.get("reason") or "")
            + f" [재인증 완료로 L3→L1 해제: reauth_at TTL {REAUTH_TTL_SEC}s 이내]"
        ).strip()
        decision["override"] = {
            "type": "REAUTH_COMPLETED",
            "reason": "재인증 완료로 해당 세션에서 접근 허용",
            "score_level": decision.get("score_level"),
            "score_label": decision.get("score_label"),
        }

    # 관리자 승인이 필요하지만, 이미 승인된 경우
    #  - download_allowed=true  → 전체 허용(level 1, 다운로드 가능)
    #  - download_allowed=false → 열람 전용(level 2, 기본값)
    if pre_approved and admin_required:
        if approved_download:
            decision["level"] = 1
            decision["label"] = "전체 허용 (사전 승인·다운로드 허용)"
            decision["label_en"] = "FULL_ACCESS_APPROVED"
            decision["external_message"] = (
                "관리자 승인 완료 — 열람 및 다운로드가 허용됩니다."
            )
            decision["reason"] = (
                "관리자 사전 승인에 의한 접근 허용 (다운로드 허용 플래그)"
            )
            decision["override"] = {
                "type": "ADMIN_APPROVAL_GRANTED",
                "download_allowed": True,
                "reason": "관리자 승인으로 다운로드 포함 허용",
                "score_level": decision.get("score_level"),
                "score_label": decision.get("score_label"),
            }
        else:
            decision["level"] = 2
            decision["label"] = "열람 전용 (사전 승인)"
            decision["label_en"] = "VIEW_ONLY_APPROVED"
            decision["external_message"] = "관리자 승인 완료 — 열람만 허용됩니다."
            decision["reason"] = "관리자 사전 승인에 의한 접근 허용 (열람 전용)"
            decision["override"] = {
                "type": "ADMIN_APPROVAL_GRANTED",
                "download_allowed": False,
                "reason": "관리자 승인으로 열람 전용 허용",
                "score_level": decision.get("score_level"),
                "score_label": decision.get("score_label"),
            }
    elif admin_required and decision["level"] < 4:
        decision["level"] = 4
        decision["label"] = "관리자 승인 후 허용"
        decision["label_en"] = "ADMIN_APPROVAL"
        decision["external_message"] = "관리자 승인이 필요합니다."
        decision["override"] = {
            "type": "ADMIN_APPROVAL_REQUIRED",
            "reason": "자원 정책상 관리자 승인 필요",
            "score_level": decision.get("score_level"),
            "score_label": decision.get("score_label"),
        }

    # 승인 대기 레코드는 접근 평가 시 자동 생성하지 않는다.
    # 사용자가 명시적으로 POST /api/resources/<id>/request-approval 를
    # 호출할 때만 approvals 행이 생성된다 (관리자 승인 워크플로 의도 명확화).
    # 기존 자동 생성(_create_approval_request)은 의도치 않게 대기 목록이
    # 폭증하는 UX 문제가 있어 제거되었다.

    # ── 5.5단계: Break-Glass 우회 판정 (Phase 2) ──
    # 자격 있는 발동자가 사전에 발동한 BG 가 이 (user, resource) 조합에
    # 적용되면, 차단/승인대기 레벨을 "전체 허용(level 1)" 으로 덮어쓴다.
    # BG 의 목적은 긴급 자가발동 접근 — 열람뿐만 아니라 증거물 반출
    # (다운로드) 까지 허용해야 실효성이 있다. 대신 모든 행동이
    # BREAK_GLASS_USED 로 감사되며 사후 관리자 리뷰에서 unjustified
    # 판정 시 trust 페널티를 받는다.
    if decision["level"] >= 4:
        active_bg = _probe_active_bg(
            db, user_id, resource_id, resource["sensitivity_grade"],
            request_id, where="post_scoring",
        )
        if active_bg is not None:
            if mutate_state:
                _bg.consume(
                    db=db,
                    activation_id=int(active_bg["id"]),
                    resource_id=resource_id,
                    user_id=user_id,
                    request_id=request_id,
                )
            decision = {
                "level": 1,
                "label": "전체 허용 (Break-Glass)",
                "label_en": "FULL_ACCESS_BREAK_GLASS",
                "external_message": "Break-Glass 경로로 열람·다운로드가 허용됩니다. "
                                    "모든 행동이 감사되며 사후 리뷰 대상입니다.",
                "risk_score": decision.get("risk_score", 0),
                "score_level": decision.get("score_level"),
                "score_label": decision.get("score_label"),
                "sensitivity_grade": resource["sensitivity_grade"],
                "reason": (
                    "긴급 접근(Break-Glass) 활성 — 열람·다운로드를 "
                    "허용합니다. 사후 검토 대상입니다."
                ),
                "override": {
                    "type": "BREAK_GLASS",
                    "reason": "긴급 접근 승인으로 접근 허용",
                    "score_level": decision.get("score_level"),
                    "score_label": decision.get("score_label"),
                },
                "break_glass": {
                    "activation_id": int(active_bg["id"]),
                    "scope": active_bg["scope"],
                    "expires_at": str(active_bg.get("expires_at") or ""),
                },
            }

    # ── 6단계: 마스킹 적용 ──
    _finalize_decision(decision, scoring)
    masked_resource = apply_masking(resource, decision["level"], user.get("name", ""))

    # ── 7단계: 로그 기록 ──
    reason = decision.get("reason", block_result.get("reason", ""))
    if not reason:
        reason = f"위험점수 {decision.get('risk_score', total_result['total_risk_score'])} / 등급 {resource['sensitivity_grade']}"

    if record_access:
        _log_access(db, request_id, user, resource, session_id, decision,
                    obj_result["score"], env_result["score"],
                    beh_result["score"], fit_result["score"],
                    device_id, ip_address, location, action_type, reason)

    # 세션 최대 민감도 갱신 + 위치 이력 갱신
    if mutate_state and session_id and decision["level"] <= 4:
        db.execute(
            "UPDATE sessions "
            "SET max_sensitivity_accessed=GREATEST(max_sensitivity_accessed, ?), "
            "    last_activity=CURRENT_TIMESTAMP, "
            "    last_location=?, "
            "    last_location_time=CURRENT_TIMESTAMP "
            "WHERE id=?",
            (resource["sensitivity_grade"], location, session_id)
        )
        db.commit()

    db.close()

    return _build_response(request_id, decision, scoring, block_result,
                           anomaly_result, masked_resource,
                           include_resource_body=include_resource_body)


def _count_unassigned_case_clicks(db, user_id: int, session_id: int | None) -> int:
    """현재 세션의 비담당 사건 클릭 이벤트 수."""
    params = [AuditEvent.UNASSIGNED_CASE_CLICK.value, int(user_id)]
    session_clause = ""
    if session_id:
        session_clause = " AND COALESCE(details->>'session_id', '')=?"
        params.append(str(session_id))
    row = db.execute(
        "SELECT COUNT(*) AS c FROM audit_logs "
        "WHERE event_type=? AND user_id=?" + session_clause,
        tuple(params),
    ).fetchone()
    return int(row["c"] if row else 0)


def _build_response(request_id, decision, scoring, policy_check,
                    anomaly_check, masked_resource, *,
                    include_resource_body=True):
    _finalize_decision(decision, scoring)
    if not include_resource_body:
        masked_resource = _resource_state_only(masked_resource)
    return {
        "request_id": request_id,
        "decision": decision,
        "scoring": scoring,
        "policy_check": policy_check,
        "anomaly_check": anomaly_check,
        "resource": masked_resource,
        "external_message": get_external_response(decision["level"]),
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
    }


def _decision_anomaly_hits(anomaly_result: dict) -> int:
    """권한 결정 confidence 에 반영할 누적/환경성 이상 신호 개수.

    현재 요청의 DOWNLOAD_ATTEMPT/COPY_ATTEMPT 는 감사 이벤트로 남기되,
    그 클릭 하나가 자신의 허용 권한을 즉시 뒤집지 않도록 confidence
    산정에서는 제외한다. 고빈도·대량조회·단말/세션 이상 같은 누적 신호는
    계속 동적으로 반영된다.
    """
    action_only = {"DOWNLOAD_ATTEMPT", "COPY_ATTEMPT"}
    return len([
        t for t in (anomaly_result or {}).get("anomaly_types", [])
        if t not in action_only
    ])


def _finalize_decision(decision: dict, scoring: dict | None = None) -> None:
    """4축 총점은 그대로 두고, 적용 레벨의 행동 권한만 붙인다."""
    if not decision:
        return

    if scoring and scoring.get("total") is not None:
        score_source = scoring["total"].get(
            "total_risk_score",
            decision.get("risk_score", 0),
        )
    else:
        score_source = decision.get("risk_score", 0)

    try:
        display_score = max(0.0, min(100.0, float(score_source)))
    except (TypeError, ValueError):
        display_score = 0.0

    display_score = round(display_score, 1)
    decision["risk_score"] = display_score
    decision["display_risk_score"] = display_score
    decision["raw_risk_score"] = display_score
    decision.setdefault("score_level", decision.get("level", 5))
    decision.setdefault("score_label", decision.get("label", "차단"))

    permissions = get_action_permissions(decision.get("level", 5))
    decision["action_permissions"] = permissions
    decision.update(permissions)

    if scoring and scoring.get("total") is not None:
        total = scoring["total"]
        total["total_risk_score"] = display_score
        total["score_level"] = int(decision.get("score_level", decision.get("level", 5)) or 5)
        total["decision_level"] = int(decision.get("level", 5) or 5)
        total["action_permissions"] = dict(permissions)


def _resource_state_only(resource: dict) -> dict:
    """실시간 상태 폴링용: 본문/설명 없이 권한 상태만 반환."""
    keep = {
        "id", "case_number", "title", "sensitivity_grade", "data_type",
        "department", "requires_approval", "masking_level", "masking_name",
        "masking_description", "watermark", "can_view", "can_download", "can_copy",
        "can_print",
    }
    return {k: v for k, v in (resource or {}).items() if k in keep}


def _log_access(db, request_id, user, resource, session_id, decision,
                obj_score, env_score, beh_score, fit_score,
                device_id, ip_address, location, action_type, reason):
    logged_score = decision.get("display_risk_score", decision.get("risk_score", 0))
    db.execute("""
        INSERT INTO access_logs
        (session_id, user_id, resource_id, risk_score, trust_score,
         object_sensitivity_score, environment_risk_score,
         behavior_risk_score, work_fitness_score,
         decision_level, decision_label, reason_code, reason_detail,
         device_id, ip_address, location, action_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        session_id, user["id"], resource["id"],
        logged_score, user.get("trust_score", 80),
        obj_score, env_score, beh_score, fit_score,
        decision["level"], decision["label"],
        request_id, reason,
        device_id, ip_address, location, action_type
    ))

    # 감사 로그
    db.execute("""
        INSERT INTO audit_logs (request_id, layer, event_type, details, user_id)
        VALUES (?, 'audit', 'ACCESS_DECISION', ?, ?)
    """, (
        request_id,
        json.dumps({
            "decision_level": decision["level"],
            "decision_label": decision["label"],
            "risk_score": logged_score,
            "raw_risk_score": decision.get("raw_risk_score", logged_score),
            "action_permissions": decision.get("action_permissions", {}),
            "resource_id": resource["id"],
            "reason": reason,
        }, ensure_ascii=False),
        user["id"]
    ))
    db.commit()


def _lock_session_for_location_anomaly(*, db, session_id, user_id, rule,
                                       reason, request_id,
                                       attempted_location, attempted_device_id):
    """
    위치 룰(IMPOSSIBLE_TRAVEL / LOCATION_NOT_ALLOWED)에 의한 차단이면
    동시 로그인 정책과 같은 처리를 적용한다:
      - sessions.pending_reauth = TRUE, pending_reauth_at = now()
      - audit_logs 에 CONCURRENT_SESSION_LOCKED 동격 이벤트 1건 +
        LOCATION_ANOMALY_LOCKED 1건 (구분 유지를 위해 분리 기록)

    이 함수는 다음 조건 모두에 해당할 때만 실제 갱신을 수행한다:
      - rule 이 위치 관련(IMPOSSIBLE_TRAVEL / LOCATION_NOT_ALLOWED 또는
        HIGH_RISK_DOWNLOAD — 이 역시 비허용 위치 기반)
      - session_id 가 0/None 이 아님
      - 해당 세션이 여전히 활성 (좀비/만료된 세션은 무시)

    실패는 silently 통과한다 (즉시차단 응답 자체는 막지 않기 위함).
    """
    LOCATION_RULES = ("IMPOSSIBLE_TRAVEL", "LOCATION_NOT_ALLOWED",
                      "HIGH_RISK_DOWNLOAD")
    if rule not in LOCATION_RULES:
        return
    if not session_id:
        return
    try:
        # 활성 세션에 한해서만 마킹 — 좀비 세션은 그대로 둔다
        row = db.execute(
            "SELECT id, is_active FROM sessions WHERE id=?",
            (session_id,)
        ).fetchone()
        if not row:
            return
        is_active = row["is_active"] if isinstance(row, dict) or hasattr(row, "keys") else row[1]
        if not is_active:
            return

        db.execute(
            "UPDATE sessions "
            "SET pending_reauth=TRUE, pending_reauth_at=now() "
            "WHERE id=? AND is_active",
            (session_id,)
        )
        # 1) 동시 로그인 정책과 같은 이벤트로 후속 401 흐름의 단서 통일
        db.execute(
            "INSERT INTO audit_logs (request_id, layer, event_type, details, user_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, "audit", "CONCURRENT_SESSION_LOCKED",
             json.dumps({
                 "locked_session_ids": [int(session_id)],
                 "reason": "location_anomaly",
                 "rule": rule,
                 "rule_reason": reason,
                 "attempted_location": attempted_location,
                 "attempted_device_id": attempted_device_id,
             }, ensure_ascii=False),
             user_id)
        )
        # 2) 위치 이상 구분용 별도 이벤트 (감사·분석 편의)
        db.execute(
            "INSERT INTO audit_logs (request_id, layer, event_type, details, user_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (request_id, "operation", "LOCATION_ANOMALY_LOCKED",
             json.dumps({
                 "session_id": int(session_id),
                 "rule": rule,
                 "reason": reason,
                 "attempted_location": attempted_location,
             }, ensure_ascii=False),
             user_id)
        )
        db.commit()
        _log.info(
            "Session %s locked by location anomaly (rule=%s, loc=%s)",
            session_id, rule, attempted_location,
        )
    except Exception as e:
        _log.exception(
            "Failed to lock session for location anomaly "
            "(session_id=%s rule=%s err=%s:%s)",
            session_id, rule, type(e).__name__, e,
        )


def _probe_active_bg(db, user_id, resource_id, resource_grade,
                     request_id, where):
    """
    BG 조회 래퍼 — 예외를 삼키되 stderr 에 '왜 실패/매칭 실패했는지' 힌트를 남긴다.

    디버깅 중인 상황에서만 쓰는 얇은 래퍼. 정상 흐름에는 영향이 없고,
    미스/예외 시 서버 콘솔에 한 줄씩 찍혀 재현 1회로 원인 구분이 가능해진다.

    참고 (`req=…` / `actor=…` / `res=…` / `grade=…` / `at=…` 은 공통 필드):
      - "BG probe HIT  …"   : find_active_for_resource 가 매칭된 BG 반환.
      - "BG probe MISS …"   : 활성 BG 가 0건이거나 있지만 이 자원엔 안 맞음.
      - "BG probe ERROR …"  : DB 예외. 테이블 없음/컬럼 타입 이상 등.
    """
    try:
        actives = _bg.get_active_for_user(db, user_id)
        result = _bg.find_active_for_resource(
            db, user_id, resource_id, resource_grade
        )
        if result is None:
            _log.debug(
                "BG probe MISS at=%s req=%s actor=%s res=%s grade=%s actives=%s",
                where, request_id, user_id, resource_id, resource_grade,
                len(actives) if actives is not None else "NA",
            )
            return None
        _log.debug(
            "BG probe HIT at=%s req=%s actor=%s res=%s grade=%s bg_id=%s",
            where, request_id, user_id, resource_id, resource_grade,
            result.get("id") if isinstance(result, dict) else result,
        )
        return result
    except Exception as e:
        _log.exception(
            "BG probe ERROR at=%s req=%s actor=%s res=%s grade=%s err=%s:%s",
            where, request_id, user_id, resource_id, resource_grade,
            type(e).__name__, e,
        )
        return None
