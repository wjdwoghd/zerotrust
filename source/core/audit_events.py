"""
감사 이벤트 상수 카탈로그 (L5-2)

모든 감사 이벤트는 본 모듈의 AuditEvent enum 상수를 사용한다.
emit 지점과 상수명이 분기되지 않도록 pytest (OPM-L5-04) 에서 정합성 검사.

추가 계약:
  - `severity` 1(정보) ~ 5(치명)
  - `layer`    "operation" | "audit" | "sensitive"

각 이벤트의 `details` JSON 스키마는 하기 _SCHEMAS 에 필수 필드 목록으로 정의.
"""
from __future__ import annotations

import enum
import json
import logging
from typing import Any, Dict, Optional


class AuditEvent(str, enum.Enum):
    # 접근 결정
    ACCESS_DECISION           = "ACCESS_DECISION"
    ACCESS_SCORE_CHANGED      = "ACCESS_SCORE_CHANGED"
    UNASSIGNED_CASE_CLICK     = "UNASSIGNED_CASE_CLICK"
    IMMEDIATE_BLOCK           = "IMMEDIATE_BLOCK"
    FORCE_REAUTH              = "FORCE_REAUTH"
    ADMIN_APPROVAL_REQUESTED  = "ADMIN_APPROVAL_REQUESTED"
    ADMIN_APPROVAL_GRANTED    = "ADMIN_APPROVAL_GRANTED"
    BREAK_GLASS_GRANTED       = "BREAK_GLASS_GRANTED"

    # Break-Glass (Phase 2 / 진짜 긴급 자가발동)
    BREAK_GLASS_ACTIVATED             = "BREAK_GLASS_ACTIVATED"
    BREAK_GLASS_ACTIVATION_REFUSED    = "BREAK_GLASS_ACTIVATION_REFUSED"
    BREAK_GLASS_USED                  = "BREAK_GLASS_USED"
    BREAK_GLASS_EXPIRED               = "BREAK_GLASS_EXPIRED"
    BREAK_GLASS_REVOKED               = "BREAK_GLASS_REVOKED"
    BREAK_GLASS_RELEASED              = "BREAK_GLASS_RELEASED"
    BREAK_GLASS_REVIEWED_JUSTIFIED    = "BREAK_GLASS_REVIEWED_JUSTIFIED"
    BREAK_GLASS_REVIEWED_UNJUSTIFIED  = "BREAK_GLASS_REVIEWED_UNJUSTIFIED"
    BREAK_GLASS_REVIEWED_PARTIAL      = "BREAK_GLASS_REVIEWED_PARTIAL"

    # 세션 라이프사이클
    SESSION_STARTED                   = "SESSION_STARTED"
    SESSION_EXPIRED_IDLE              = "SESSION_EXPIRED_IDLE"
    SESSION_EXPIRED_HIGH_SENSITIVITY  = "SESSION_EXPIRED_HIGH_SENSITIVITY"
    SESSION_EXPIRED_ABSOLUTE          = "SESSION_EXPIRED_ABSOLUTE"
    SESSION_TERMINATED_BY_USER        = "SESSION_TERMINATED_BY_USER"
    # 동시 접속 정책
    CONCURRENT_SESSION_LOCKED         = "CONCURRENT_SESSION_LOCKED"
    CONCURRENT_SESSION_RESOLVED       = "CONCURRENT_SESSION_RESOLVED"
    CONCURRENT_LOGIN_REJECTED         = "CONCURRENT_LOGIN_REJECTED"
    SESSION_EXPIRED_PENDING_REAUTH    = "SESSION_EXPIRED_PENDING_REAUTH"

    # 인증
    LOGIN_SUCCESS     = "LOGIN_SUCCESS"
    LOGIN_FAILURE     = "LOGIN_FAILURE"
    ACCOUNT_LOCKED    = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED  = "ACCOUNT_UNLOCKED"
    # 계정 활성/비활성 (관리자 수동 — failed_login 자동 잠금과는 별개)
    ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED"
    ACCOUNT_ACTIVATED   = "ACCOUNT_ACTIVATED"
    # 관리자 콘솔에서 신규 계정 프로비저닝 (§20, role='user' 고정)
    USER_CREATED        = "USER_CREATED"
    MFA_SUCCESS       = "MFA_SUCCESS"
    MFA_FAILURE       = "MFA_FAILURE"

    # 비밀/키 관리
    SECRET_ROTATED    = "SECRET_ROTATED"

    # 이상행동
    ANOMALY_DETECTED  = "ANOMALY_DETECTED"

    # 사후 소명
    POLICY_OVERRIDE_REQUESTED = "POLICY_OVERRIDE_REQUESTED"
    POLICY_OVERRIDE_GRANTED   = "POLICY_OVERRIDE_GRANTED"

    # Impossible-travel 탐지가 비활성으로 빠진 경우 1회 경고
    # (위치 좌표가 등록되지 않은 위치쌍, 시간 파싱 실패, 직전 위치 부재 등)
    TRAVEL_DETECTION_INACTIVE = "TRAVEL_DETECTION_INACTIVE"

    # 이중감독 위반 시도 (self-approval / self-review 차단)
    SELF_ACTION_BLOCKED       = "SELF_ACTION_BLOCKED"


# 이벤트별 details 필수 필드
_SCHEMAS: Dict[AuditEvent, tuple] = {
    AuditEvent.ACCESS_DECISION:         ("decision_level", "decision_label", "resource_id"),
    AuditEvent.ACCESS_SCORE_CHANGED:    ("resource_id", "new_score", "new_level"),
    AuditEvent.UNASSIGNED_CASE_CLICK:   ("resource_id", "session_id", "click_index"),
    AuditEvent.IMMEDIATE_BLOCK:         ("rule", "reason", "resource_id"),
    AuditEvent.FORCE_REAUTH:            ("reason",),
    AuditEvent.ADMIN_APPROVAL_REQUESTED:("resource_id",),
    AuditEvent.ADMIN_APPROVAL_GRANTED:  ("approval_id", "approver_id"),
    AuditEvent.BREAK_GLASS_GRANTED:     ("approval_id", "approver_id"),
    AuditEvent.SESSION_STARTED:         ("session_id",),
    AuditEvent.SESSION_EXPIRED_IDLE:    ("session_id", "reason"),
    AuditEvent.SESSION_EXPIRED_HIGH_SENSITIVITY:("session_id", "reason"),
    AuditEvent.SESSION_EXPIRED_ABSOLUTE:("session_id", "reason"),
    AuditEvent.SESSION_TERMINATED_BY_USER:("session_id",),
    AuditEvent.CONCURRENT_SESSION_LOCKED:  ("locked_session_ids",),
    AuditEvent.CONCURRENT_SESSION_RESOLVED:("winning_session_id",),
    AuditEvent.CONCURRENT_LOGIN_REJECTED:  ("existing_live_session_ids", "reason"),
    AuditEvent.SESSION_EXPIRED_PENDING_REAUTH:("session_id", "reason"),
    AuditEvent.LOGIN_SUCCESS:           ("username",),
    AuditEvent.LOGIN_FAILURE:           ("username", "reason"),
    AuditEvent.ACCOUNT_LOCKED:          ("username", "failed_count"),
    AuditEvent.ACCOUNT_UNLOCKED:        ("username", "admin_id"),
    AuditEvent.ACCOUNT_DEACTIVATED:     ("target_user_id", "admin_id"),
    AuditEvent.ACCOUNT_ACTIVATED:       ("target_user_id", "admin_id"),
    AuditEvent.USER_CREATED:            ("target_user_id", "admin_id", "username", "role"),
    AuditEvent.MFA_SUCCESS:             ("username",),
    AuditEvent.MFA_FAILURE:             ("username", "reason"),
    AuditEvent.SECRET_ROTATED:          ("key_name",),
    AuditEvent.ANOMALY_DETECTED:        ("anomaly_types",),
    AuditEvent.POLICY_OVERRIDE_REQUESTED:("kind",),
    AuditEvent.POLICY_OVERRIDE_GRANTED: ("override_id", "approver_id"),
    AuditEvent.TRAVEL_DETECTION_INACTIVE:("reason",),

    # Break-Glass (Phase 2)
    AuditEvent.BREAK_GLASS_ACTIVATED:           ("activation_id", "scope", "justification"),
    AuditEvent.BREAK_GLASS_ACTIVATION_REFUSED:  ("reason",),
    AuditEvent.BREAK_GLASS_USED:                ("activation_id", "resource_id"),
    AuditEvent.BREAK_GLASS_EXPIRED:             ("activation_id",),
    AuditEvent.BREAK_GLASS_REVOKED:             ("activation_id", "revoker_id"),
    AuditEvent.BREAK_GLASS_RELEASED:            ("activation_id",),
    AuditEvent.BREAK_GLASS_REVIEWED_JUSTIFIED:  ("activation_id", "reviewer_id"),
    AuditEvent.BREAK_GLASS_REVIEWED_UNJUSTIFIED:("activation_id", "reviewer_id"),
    AuditEvent.BREAK_GLASS_REVIEWED_PARTIAL:    ("activation_id", "reviewer_id"),

    # 이중감독 위반 차단 기록
    #   action: "approval_grant" | "approval_reject"
    #         | "login_approval_grant" | "login_approval_reject"
    #         | "bg_review" | "bg_revoke"
    #   target_id: 대상 객체 PK (approval_id / login_request_id / activation_id)
    #   actor_id : 시도한 admin (== 원래 actor 이기 때문에 차단됨)
    AuditEvent.SELF_ACTION_BLOCKED:             ("action", "target_id", "actor_id"),
}


def required_fields(event: AuditEvent) -> tuple:
    return _SCHEMAS.get(event, ())


# ── 구조화 JSON 로거 (L5-1) ─────────────────────────────────────
_logger = logging.getLogger("zerotrust.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def _emit_json_log(record: Dict[str, Any]) -> None:
    try:
        _logger.info(json.dumps(record, ensure_ascii=False, default=str))
    except Exception:
        # 로깅 실패는 앱 흐름을 막지 않는다.
        pass


def audit_log(db,
              event: AuditEvent,
              user_id: Optional[int] = None,
              request_id: Optional[str] = None,
              details: Optional[Dict[str, Any]] = None,
              severity: int = 3,
              layer: str = "audit") -> None:
    """
    감사 이벤트를 DB + stdout JSON 로그 양쪽에 기록한다.

    - layer ∈ {"operation", "audit", "sensitive"}
    - sensitive 계층은 payload_hash 저장 경로에서 별도 호출.
    """
    details = details or {}

    # 1) DB (가능하면)
    try:
        if layer == "operation":
            db.execute(
                "INSERT INTO operation_logs (request_id, event_type, severity, details, user_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    request_id,
                    event.value,
                    severity,
                    json.dumps(details, ensure_ascii=False),
                    user_id,
                )
            )
        else:
            db.execute(
                "INSERT INTO audit_logs (request_id, layer, event_type, severity, details, user_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    layer,
                    event.value,
                    severity,
                    json.dumps(details, ensure_ascii=False),
                    user_id,
                )
            )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    # 2) stdout 구조화 로그
    import datetime
    _emit_json_log({
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "request_id": request_id,
        "actor_id": user_id,
        "event_type": event.value,
        "severity": severity,
        "layer": layer,
        "details": details,
    })
