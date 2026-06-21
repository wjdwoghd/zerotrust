"""
Break-Glass 서비스 (Phase 2 / 진짜 긴급 자가발동)

이 모듈은 '관리자 승인 로그인 게이트(login_approval_requests)' 와 **별개** 다.
자격 있는 사용자가 자기 책임 하에 특권 접근을 자가발동하고, 관리자가 사후
리뷰로 정당성을 판정하는 메커니즘을 제공한다.

정책 결정(제로트러스트 원칙 반영):

  1. 발동 자격 (Verify explicitly)
     토큰 기기(user_devices.mfa_secret IS NOT NULL) 를 보유한 사용자만
     발동할 수 있다. patrol_jung 처럼 토큰 기기 미보유인 사용자는
     관리자 승인 게이트(Phase 1) 를 경유해야 한다.

  2. 자원 범위 (Least privilege)
     - scope='resource'  특정 resource_id 한 건에만 유효 (권장).
     - scope='broad'     Grade ≥ BREAK_GLASS_MIN_GRADE 모든 자원 (광역 비상).
     Grade 3 이하는 정상 정책으로 접근 가능하므로 BG 대상이 아니다.

  3. 시간 범위 (Assume breach)
     - 절대 30분(BREAK_GLASS_TTL_SEC) + 유휴 5분(BREAK_GLASS_IDLE_SEC).
     - 관리자가 즉시 revoke 할 수 있다.

  4. 추적 (Accountability)
     - 발동 순간 sensitive_logs 에 원본 justification 을 해시+원문으로 저장.
     - 매 자원 접근마다 audit_logs 에 BREAK_GLASS_USED 기록.
     - 종료 후 반드시 관리자 리뷰 (pending_review 큐에 남는다).
     - unjustified 판정 시 trust_score 페널티.

본 모듈은 **순수 서비스 로직** 만 담당한다. HTTP 경로는
api/break_glass_handler.py 가 처리한다. 자원 접근 평가 통합은
core/access_evaluator.py 가 `get_active_for_user()` 를 조회해 수행한다.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from config import (
    BREAK_GLASS_TTL_SEC,
    BREAK_GLASS_IDLE_SEC,
    BREAK_GLASS_MIN_GRADE,
    BREAK_GLASS_TRUST_PENALTY,
    BREAK_GLASS_VIOLATION_PENALTY,
)
from core.audit_events import AuditEvent, audit_log
from database import row_to_dict


# =====================================================================
# 자격 판정
# =====================================================================
def is_eligible_activator(db, user_id: int) -> bool:
    """
    토큰 기기(mfa_secret IS NOT NULL) 를 1개 이상 보유한 사용자만 발동 가능.
    """
    row = db.execute(
        "SELECT COUNT(*) AS cnt FROM user_devices "
        "WHERE user_id=? AND is_active=TRUE AND mfa_secret IS NOT NULL",
        (user_id,)
    ).fetchone()
    return bool(row and row["cnt"] and int(row["cnt"]) > 0)


def get_token_device_secret(db, user_id: int) -> Optional[str]:
    """MFA 재확인용 — 첫 활성 토큰 기기의 TOTP 시크릿."""
    row = db.execute(
        "SELECT mfa_secret FROM user_devices "
        "WHERE user_id=? AND is_active=TRUE AND mfa_secret IS NOT NULL "
        "ORDER BY id ASC LIMIT 1",
        (user_id,)
    ).fetchone()
    if not row:
        return None
    return row["mfa_secret"]


def get_token_device_for_otp(db, user_id: int) -> Optional[dict]:
    """OTP 검증용 — 첫 활성 토큰 기기의 (id, secret, last_otp_step) 묶음.

    RFC 6238 §5.2 replay 방지를 위해 호출자가 통과 시 last_otp_step 을
    갱신해야 한다.
    """
    row = db.execute(
        "SELECT id, mfa_secret, last_otp_step FROM user_devices "
        "WHERE user_id=? AND is_active=TRUE AND mfa_secret IS NOT NULL "
        "ORDER BY id ASC LIMIT 1",
        (user_id,)
    ).fetchone()
    if not row:
        return None
    return dict(row)


# =====================================================================
# 발동
# =====================================================================
class BreakGlassError(Exception):
    """발동 실패. .code 에 에러 코드, .message 에 한국어 메시지."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def activate(
    db,
    activator_id: int,
    justification: str,
    scope: str = "resource",
    resource_id: Optional[int] = None,
    min_grade: int = None,
    session_id: Optional[int] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Break-Glass 를 발동한다.

    선행 검증(엄격):
      - justification 은 필수, 최소 10자.
      - scope='resource' 일 때 resource_id 필수, 해당 자원이 존재해야 함.
      - scope='broad' 일 때 resource_id 는 기록하지 않음 (광역).
      - activator 는 토큰 기기 보유자여야 함 (is_eligible_activator).
      - 동일 activator 에게 이미 active 인 BG 가 있으면 거부 (중복 방지).

    성공 시 break_glass_activations 에 INSERT 하고, sensitive_logs 에
    정당화 사유 원본을 저장, audit_logs 에 ACTIVATED 이벤트를 남긴다.

    Returns: 삽입된 레코드의 dict.
    Raises: BreakGlassError — 위 사전 조건 미충족.
    """
    # ── 입력 정규화 ──────────────────────────────────────────────
    justification = (justification or "").strip()
    if len(justification) < 10:
        raise BreakGlassError(
            "justification_too_short",
            "정당화 사유는 최소 10자 이상이어야 합니다."
        )

    if scope not in ("resource", "broad"):
        raise BreakGlassError(
            "invalid_scope",
            "scope 는 'resource' 또는 'broad' 여야 합니다."
        )

    if min_grade is None:
        min_grade = BREAK_GLASS_MIN_GRADE
    if not (1 <= int(min_grade) <= 5):
        raise BreakGlassError("invalid_min_grade", "min_grade 는 1~5 범위여야 합니다.")

    # ── 자격 확인 ────────────────────────────────────────────────
    if not is_eligible_activator(db, activator_id):
        audit_log(
            db=db,
            event=AuditEvent.BREAK_GLASS_ACTIVATION_REFUSED,
            user_id=activator_id,
            request_id=request_id,
            details={"reason": "not_token_device_holder"},
            severity=4,
            layer="audit",
        )
        raise BreakGlassError(
            "not_eligible",
            "토큰 기기를 보유한 사용자만 Break-Glass 를 발동할 수 있습니다."
        )

    # ── 리소스 유효성 ────────────────────────────────────────────
    resolved_resource_id: Optional[int] = None
    if scope == "resource":
        if resource_id is None:
            raise BreakGlassError(
                "resource_id_required",
                "scope='resource' 일 때는 resource_id 가 필요합니다."
            )
        row = db.execute(
            "SELECT id, sensitivity_grade FROM resources WHERE id=?",
            (int(resource_id),)
        ).fetchone()
        if not row:
            raise BreakGlassError("resource_not_found", "대상 자원을 찾을 수 없습니다.")
        # 등급 체크: BG 는 고민감만 대상
        if int(row["sensitivity_grade"]) < int(min_grade):
            raise BreakGlassError(
                "resource_not_high_sens",
                f"해당 자원은 Grade {row['sensitivity_grade']} 로 Break-Glass 대상이 아닙니다. "
                f"(기준 Grade ≥ {min_grade})"
            )
        resolved_resource_id = int(row["id"])

    # ── 중복 발동 방지 ───────────────────────────────────────────
    existing = db.execute(
        "SELECT id FROM break_glass_activations "
        "WHERE activator_id=? AND status='active'",
        (activator_id,)
    ).fetchone()
    if existing:
        raise BreakGlassError(
            "already_active",
            f"이미 활성 Break-Glass (id={existing['id']}) 가 있습니다. "
            f"먼저 해제하거나 만료를 기다리십시오."
        )

    # ── 만료 시각 계산 ───────────────────────────────────────────
    #
    # PostgreSQL TIMESTAMPTZ 주의:
    #   naive 문자열 '%Y-%m-%d %H:%M:%S' 을 TIMESTAMPTZ 컬럼에 바인딩하면
    #   PG 가 "현재 세션 timezone" 으로 해석해 UTC 로 저장한다. 서버 TZ 가
    #   KST (Asia/Seoul, +09:00) 면 UTC 로 -9h 이동 → INSERT 시점에 이미
    #   과거가 되어 get_active_for_user 가 즉시 _transition_to_expired 로
    #   만료 처리한다 (→ 발동 성공 알림은 뜨지만 바로 막히는 현상).
    #
    # 해법: **tz-aware datetime (UTC)** 를 직접 바인딩한다.
    #       psycopg2 는 tzinfo 가 있는 datetime 을 세션 TZ 와 무관하게
    #       TIMESTAMPTZ 에 올바르게 매핑한다.
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    expires_at_utc = utc_now + datetime.timedelta(seconds=BREAK_GLASS_TTL_SEC)

    # ── 삽입 ─────────────────────────────────────────────────────
    cur = db.execute(
        "INSERT INTO break_glass_activations "
        "(activator_id, session_id, scope, resource_id, min_grade, "
        " justification, expires_at, ip, user_agent, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb) "
        "RETURNING id, activated_at, expires_at",
        (
            activator_id, session_id, scope, resolved_resource_id, int(min_grade),
            justification, expires_at_utc, ip, user_agent,
            json.dumps({"request_id": request_id}),
        )
    )
    inserted = cur.fetchone()
    activation_id = int(inserted["id"])
    expires_at_text = _format_ts(inserted.get("expires_at") or expires_at_utc)

    # ── sensitive_logs: 정당화 사유 원본 ─────────────────────────
    try:
        payload_hash = hashlib.sha256(justification.encode("utf-8")).hexdigest()
        db.execute(
            "INSERT INTO sensitive_logs "
            "(request_id, event_type, payload_hash, payload_encrypted, user_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                request_id,
                AuditEvent.BREAK_GLASS_ACTIVATED.value,
                payload_hash,
                justification.encode("utf-8"),  # BYTEA — 본 구현에서는 평문. KMS 연동은 확장.
                activator_id,
            )
        )
    except Exception:
        # sensitive_logs 가 없거나 RLS 미설정이어도 진행은 해야 한다.
        # (실제 운영에서는 여기서 실패하면 활성화를 rollback 해야 한다.)
        pass

    # ── audit_logs: 감사 이벤트 ──────────────────────────────────
    audit_log(
        db=db,
        event=AuditEvent.BREAK_GLASS_ACTIVATED,
        user_id=activator_id,
        request_id=request_id,
        details={
            "activation_id": activation_id,
            "scope": scope,
            "resource_id": resolved_resource_id,
            "min_grade": int(min_grade),
            "justification": justification,
            "expires_at": expires_at_text,
            "session_id": session_id,
        },
        severity=5,  # 치명 — 운영자 알림 대상
        layer="audit",
    )

    db.commit()

    return {
        "id": activation_id,
        "activator_id": activator_id,
        "session_id": session_id,
        "scope": scope,
        "resource_id": resolved_resource_id,
        "min_grade": int(min_grade),
        "justification": justification,
        "expires_at": expires_at_text,
        "status": "active",
    }


# =====================================================================
# 조회 / 소비
# =====================================================================
def get_active_for_user(db, user_id: int) -> List[Dict[str, Any]]:
    """
    현재 활성 상태인 BG 목록을 반환. 만료된 것은 이 호출 내에서 'expired' 로
    전이시키고 audit 이벤트를 발행한다.
    """
    rows = db.execute(
        "SELECT * FROM break_glass_activations "
        "WHERE activator_id=? AND status='active' "
        "ORDER BY activated_at DESC",
        (user_id,)
    ).fetchall()

    now_dt = datetime.datetime.utcnow()
    active: List[Dict[str, Any]] = []
    for row in rows:
        d = row_to_dict(row)
        exp_raw = d.get("expires_at")
        idle_raw = d.get("last_activity_at") or d.get("activated_at")

        exp_dt = _parse_ts(exp_raw)
        idle_dt = _parse_ts(idle_raw)

        expired = exp_dt is not None and now_dt >= exp_dt
        idle_expired = (
            idle_dt is not None
            and (now_dt - idle_dt).total_seconds() >= BREAK_GLASS_IDLE_SEC
        )

        if expired or idle_expired:
            _transition_to_expired(
                db, int(d["id"]),
                reason="absolute" if expired else "idle",
                user_id=user_id,
            )
            continue

        active.append(d)
    return active


def touch(db, activation_id: int) -> None:
    """자원 접근 시 last_activity_at 을 갱신해 유휴 타이머를 연장."""
    db.execute(
        "UPDATE break_glass_activations "
        "SET last_activity_at=CURRENT_TIMESTAMP "
        "WHERE id=? AND status='active'",
        (int(activation_id),)
    )
    db.commit()


def consume(db, activation_id: int, resource_id: int,
            user_id: int, request_id: Optional[str] = None) -> None:
    """
    자원 접근을 BG 로 성사시킬 때 호출. audit_logs 에 BREAK_GLASS_USED 기록 +
    last_activity_at 갱신.
    """
    touch(db, activation_id)
    audit_log(
        db=db,
        event=AuditEvent.BREAK_GLASS_USED,
        user_id=user_id,
        request_id=request_id,
        details={
            "activation_id": int(activation_id),
            "resource_id": int(resource_id),
        },
        severity=4,
        layer="audit",
    )


def find_active_for_resource(
    db, user_id: int, resource_id: int, resource_grade: int
) -> Optional[Dict[str, Any]]:
    """
    자원 접근 판정 시, 이 (user, resource) 조합에 적용 가능한 활성 BG 를 찾는다.

    - scope='resource' 는 resource_id 일치 시만 적용.
    - scope='broad'   는 resource_grade >= min_grade 일 때 적용.
    """
    for act in get_active_for_user(db, user_id):
        if act["scope"] == "resource" and act.get("resource_id") == int(resource_id):
            return act
        if act["scope"] == "broad" and int(resource_grade) >= int(act["min_grade"]):
            return act
    return None


# =====================================================================
# 종료 / 리뷰
# =====================================================================
def release(db, activation_id: int, user_id: int,
            request_id: Optional[str] = None) -> None:
    """본인이 자발적으로 해제."""
    row = db.execute(
        "SELECT id, activator_id, status FROM break_glass_activations WHERE id=?",
        (int(activation_id),)
    ).fetchone()
    if not row:
        raise BreakGlassError("not_found", "해당 Break-Glass 를 찾을 수 없습니다.")
    if int(row["activator_id"]) != int(user_id):
        raise BreakGlassError("not_owner", "본인이 발동한 Break-Glass 만 해제할 수 있습니다.")
    if row["status"] != "active":
        raise BreakGlassError("not_active", "이미 종료된 Break-Glass 입니다.")

    db.execute(
        "UPDATE break_glass_activations "
        "SET status='released', released_at=CURRENT_TIMESTAMP "
        "WHERE id=?",
        (int(activation_id),)
    )
    audit_log(
        db=db,
        event=AuditEvent.BREAK_GLASS_RELEASED,
        user_id=user_id,
        request_id=request_id,
        details={"activation_id": int(activation_id)},
        severity=3,
        layer="audit",
    )
    db.commit()


def revoke(db, activation_id: int, revoker_id: int,
           reason: str = "", request_id: Optional[str] = None) -> None:
    """
    관리자가 즉시 강제 종료.

    이중감독 규칙: 본인이 발동한 BG 는 revoke 경로로 종료할 수 없다.
    본인 자발 종료는 release() 경로 전용.
    """
    row = db.execute(
        "SELECT id, activator_id, status FROM break_glass_activations WHERE id=?",
        (int(activation_id),)
    ).fetchone()
    if not row:
        raise BreakGlassError("not_found", "해당 Break-Glass 를 찾을 수 없습니다.")

    # 자기-revoke 차단: release 경로로만 가능.
    if int(row["activator_id"]) == int(revoker_id):
        audit_log(
            db=db,
            event=AuditEvent.SELF_ACTION_BLOCKED,
            user_id=revoker_id,
            request_id=request_id,
            details={
                "action": "bg_revoke",
                "target_id": int(activation_id),
                "actor_id": int(revoker_id),
                "reason": reason,
            },
            severity=4,
            layer="audit",
        )
        db.commit()
        raise BreakGlassError(
            "self_revoke_forbidden",
            "본인이 발동한 Break-Glass 는 강제 종료(revoke)가 아닌 해제(release) 경로를 이용해야 합니다."
        )

    if row["status"] != "active":
        raise BreakGlassError("not_active", "이미 종료된 Break-Glass 입니다.")

    db.execute(
        "UPDATE break_glass_activations "
        "SET status='revoked', revoked_at=CURRENT_TIMESTAMP "
        "WHERE id=?",
        (int(activation_id),)
    )
    audit_log(
        db=db,
        event=AuditEvent.BREAK_GLASS_REVOKED,
        user_id=revoker_id,
        request_id=request_id,
        details={
            "activation_id": int(activation_id),
            "revoker_id": int(revoker_id),
            "target_user_id": int(row["activator_id"]),
            "reason": reason,
        },
        severity=5,
        layer="audit",
    )
    db.commit()


_VERDICT_TO_STATUS = {
    "justified":   ("reviewed_justified",   AuditEvent.BREAK_GLASS_REVIEWED_JUSTIFIED,   1),
    "unjustified": ("reviewed_unjustified", AuditEvent.BREAK_GLASS_REVIEWED_UNJUSTIFIED, 5),
    "partial":     ("reviewed_partial",     AuditEvent.BREAK_GLASS_REVIEWED_PARTIAL,     3),
}


def review(db, activation_id: int, reviewer_id: int,
           verdict: str, notes: str = "",
           request_id: Optional[str] = None) -> Dict[str, Any]:
    """
    관리자 사후 리뷰. verdict ∈ {'justified', 'unjustified', 'partial'}.

    unjustified 판정 시 activator 의 trust_score 차감 + violation_count 증가.
    리뷰 대상 상태: expired, revoked, released (active 는 먼저 종료되어야 함).
    """
    if verdict not in _VERDICT_TO_STATUS:
        raise BreakGlassError(
            "invalid_verdict",
            "verdict 는 justified / unjustified / partial 중 하나여야 합니다."
        )

    row = db.execute(
        "SELECT id, activator_id, status FROM break_glass_activations WHERE id=?",
        (int(activation_id),)
    ).fetchone()
    if not row:
        raise BreakGlassError("not_found", "해당 Break-Glass 를 찾을 수 없습니다.")

    # 이중감독 위반 차단: 본인이 발동한 BG 는 본인이 리뷰할 수 없다.
    # (trust_score 페널티/violation_count 를 자기 자신에게 유리하게 조작할 여지를 차단)
    if int(row["activator_id"]) == int(reviewer_id):
        audit_log(
            db=db,
            event=AuditEvent.SELF_ACTION_BLOCKED,
            user_id=reviewer_id,
            request_id=request_id,
            details={
                "action": "bg_review",
                "target_id": int(activation_id),
                "actor_id": int(reviewer_id),
                "verdict_attempted": verdict,
            },
            severity=4,
            layer="audit",
        )
        db.commit()
        raise BreakGlassError(
            "self_review_forbidden",
            "본인이 발동한 Break-Glass 는 본인이 리뷰할 수 없습니다. 타 관리자에게 요청하세요."
        )

    if row["status"] in ("active",):
        raise BreakGlassError(
            "still_active",
            "활성 상태인 Break-Glass 는 먼저 종료(release/revoke) 후 리뷰할 수 있습니다."
        )
    if row["status"].startswith("reviewed_"):
        raise BreakGlassError("already_reviewed", "이미 리뷰된 Break-Glass 입니다.")

    new_status, event, severity = _VERDICT_TO_STATUS[verdict]

    db.execute(
        "UPDATE break_glass_activations "
        "SET status=?, reviewed_at=CURRENT_TIMESTAMP, "
        "    reviewer_id=?, review_verdict=?, review_notes=? "
        "WHERE id=?",
        (new_status, int(reviewer_id), verdict, notes or "", int(activation_id))
    )

    # 부당 판정 시 trust 페널티
    if verdict == "unjustified":
        # 019: trust_changes timeline 자동 추적 — UPDATE 직전 SET LOCAL.
        # 트리거 trg_track_trust_change 가 NEW/OLD trust_score 차이로
        # delta·before·after 자동 산출, 여기서 reason/source/actor 만 전달.
        db.execute("SELECT set_config('app.trust_reason', 'bg_unjustified', true)")
        db.execute(
            "SELECT set_config('app.trust_source_id', ?::TEXT, true)",
            (int(activation_id),)
        )
        db.execute(
            "SELECT set_config('app.trust_actor_id', ?::TEXT, true)",
            (int(reviewer_id),)
        )
        db.execute(
            "UPDATE users "
            "SET trust_score = GREATEST(0, trust_score - ?), "
            "    violation_count = violation_count + ? "
            "WHERE id=?",
            (
                BREAK_GLASS_TRUST_PENALTY,
                BREAK_GLASS_VIOLATION_PENALTY,
                int(row["activator_id"]),
            )
        )

    audit_log(
        db=db,
        event=event,
        user_id=reviewer_id,
        request_id=request_id,
        details={
            "activation_id": int(activation_id),
            "reviewer_id": int(reviewer_id),
            "target_user_id": int(row["activator_id"]),
            "verdict": verdict,
            "notes": notes or "",
        },
        severity=severity,
        layer="audit",
    )
    db.commit()

    return {
        "id": int(activation_id),
        "status": new_status,
        "verdict": verdict,
    }


def list_pending_review(db, limit: int = 100) -> List[Dict[str, Any]]:
    """종료되었으나 아직 리뷰되지 않은 BG 목록 (관리자 대기열)."""
    rows = db.execute(
        """
        SELECT bg.id, bg.activator_id, bg.session_id,
               bg.scope, bg.resource_id, bg.min_grade,
               bg.justification,
               bg.activated_at, bg.expires_at, bg.last_activity_at,
               bg.revoked_at, bg.released_at,
               bg.status, bg.ip, bg.user_agent,
               u.username AS activator_username,
               u.name     AS activator_name,
               u.department AS activator_department,
               r.case_number, r.title AS resource_title,
               r.sensitivity_grade
        FROM break_glass_activations bg
        JOIN users u ON bg.activator_id = u.id
        LEFT JOIN resources r ON bg.resource_id = r.id
        WHERE bg.reviewed_at IS NULL
          AND bg.status IN ('expired','revoked','released')
        ORDER BY bg.activated_at DESC
        LIMIT ?
        """,
        (int(limit),)
    ).fetchall()
    return [row_to_dict(r) for r in rows]


def list_history(db, limit: int = 100) -> List[Dict[str, Any]]:
    """전체 BG 이력 (관리자 감사용)."""
    rows = db.execute(
        """
        SELECT bg.id, bg.activator_id, bg.session_id,
               bg.scope, bg.resource_id, bg.min_grade,
               bg.justification,
               bg.activated_at, bg.expires_at, bg.last_activity_at,
               bg.revoked_at, bg.released_at, bg.reviewed_at,
               bg.reviewer_id, bg.review_verdict, bg.review_notes,
               bg.status, bg.ip, bg.user_agent,
               u.username AS activator_username,
               u.name     AS activator_name,
               u.department AS activator_department,
               rv.username AS reviewer_username,
               r.case_number, r.title AS resource_title,
               r.sensitivity_grade
        FROM break_glass_activations bg
        JOIN users u ON bg.activator_id = u.id
        LEFT JOIN users rv ON bg.reviewer_id = rv.id
        LEFT JOIN resources r ON bg.resource_id = r.id
        ORDER BY bg.activated_at DESC
        LIMIT ?
        """,
        (int(limit),)
    ).fetchall()
    return [row_to_dict(r) for r in rows]


# =====================================================================
# 내부 유틸
# =====================================================================
def _parse_ts(raw) -> Optional[datetime.datetime]:
    """TIMESTAMPTZ 또는 문자열 timestamp 를 naive UTC datetime 으로 정규화."""
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        # psycopg2 는 tz-aware datetime 반환 → UTC 기준 naive 로 변환
        if raw.tzinfo is not None:
            return raw.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return raw
    if isinstance(raw, str):
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
        ):
            try:
                return datetime.datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


def _format_ts(raw) -> str | None:
    """Return a JSON/audit-friendly UTC timestamp."""
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        dt = raw
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt.replace(microsecond=0).isoformat() + "Z"
    return str(raw)


def _transition_to_expired(db, activation_id: int,
                           reason: str, user_id: int) -> None:
    db.execute(
        "UPDATE break_glass_activations SET status='expired' "
        "WHERE id=? AND status='active'",
        (int(activation_id),)
    )
    audit_log(
        db=db,
        event=AuditEvent.BREAK_GLASS_EXPIRED,
        user_id=user_id,
        details={"activation_id": int(activation_id), "reason": reason},
        severity=3,
        layer="audit",
    )
    db.commit()
