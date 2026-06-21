"""
세션 유휴 만료 / 절대 만료 가드 (L3-3)

규칙:
  - 일반 세션: last_activity 로부터 SESSION_IDLE_TIMEOUT_SEC 초 경과 시 만료.
  - 고민감 세션: max_sensitivity_accessed >= 4 이면 SESSION_HIGH_SENS_TIMEOUT_SEC 로 단축.
  - 절대 만료: login_at + SESSION_ABSOLUTE_TIMEOUT_SEC 초 초과 시 즉시 만료.

반환:
  - SessionCheckResult(ok, reason, event_type)
     ok=False 이면 caller 는 401 응답 + 이벤트 로그를 남겨야 한다.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Optional

from config import (
    SESSION_IDLE_TIMEOUT_SEC,
    SESSION_HIGH_SENS_TIMEOUT_SEC,
    SESSION_ABSOLUTE_TIMEOUT_SEC,
    SESSION_PENDING_REAUTH_TIMEOUT_SEC,
)

@dataclass
class SessionCheckResult:
    ok: bool
    reason: Optional[str] = None
    event_type: Optional[str] = None  # audit_events 카탈로그 상수


# 시간 파싱 유틸: DB timestamp 및 ISO 문자열 모두 수용
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def _parse_ts(value) -> Optional[datetime.datetime]:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        # naive → UTC 로 간주
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value
    if not isinstance(value, str):
        return None
    s = value.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def check_session(session: dict,
                  now: Optional[datetime.datetime] = None) -> SessionCheckResult:
    """
    단일 세션 레코드에 대해 유휴/절대 만료를 판정한다.

    session dict 필드 (세션 테이블 행):
      - last_activity (timestamp)
      - login_at (timestamp)
      - absolute_expires_at (timestamp, optional)
      - max_sensitivity_accessed (int)
      - is_active (bool/int)
    """
    if not session:
        return SessionCheckResult(ok=False, reason="session_missing",
                                  event_type="SESSION_EXPIRED_IDLE")

    now = now or _now_utc()

    # is_active 키가 명시된 경우에만 비활성 체크. 테스트·순수 판정 호출에서는
    # 이 키를 생략할 수 있으므로 기본은 활성으로 간주한다.
    if "is_active" in session and not session.get("is_active"):
        return SessionCheckResult(ok=False, reason="session_inactive",
                                  event_type="SESSION_EXPIRED_IDLE")

    # 0) 동시 접속 정책: pending_reauth 가 시한 초과면 세션 자체를 만료 처리.
    #    (pending_reauth=TRUE 자체는 base_handler.require_auth 에서 401
    #     concurrent_session_detected 로 먼저 차단되므로 여기까지 오지 않음.
    #     다만 시한 초과만은 별도 만료 사유로 남겨 감사 가능하게 한다.)
    if session.get("pending_reauth"):
        pending_at = _parse_ts(session.get("pending_reauth_at"))
        if pending_at is not None:
            elapsed = (now - pending_at).total_seconds()
            if elapsed >= SESSION_PENDING_REAUTH_TIMEOUT_SEC:
                return SessionCheckResult(
                    ok=False,
                    reason=f"pending_reauth_{int(elapsed)}s",
                    event_type="SESSION_EXPIRED_PENDING_REAUTH",
                )

    # 1) 절대 만료
    abs_expires = _parse_ts(session.get("absolute_expires_at"))
    login_at = _parse_ts(session.get("login_at"))
    if abs_expires is not None:
        if now >= abs_expires:
            return SessionCheckResult(ok=False, reason="absolute_expired",
                                      event_type="SESSION_EXPIRED_ABSOLUTE")
    elif login_at is not None:
        if (now - login_at).total_seconds() >= SESSION_ABSOLUTE_TIMEOUT_SEC:
            return SessionCheckResult(ok=False, reason="absolute_expired",
                                      event_type="SESSION_EXPIRED_ABSOLUTE")

    # 2) 고민감 잠금 만료 (sensitive_unlocked_at 으로부터 5분)
    sens_unlocked = _parse_ts(session.get("sensitive_unlocked_at"))
    if sens_unlocked is not None:
        sens_elapsed = (now - sens_unlocked).total_seconds()
        if sens_elapsed >= SESSION_HIGH_SENS_TIMEOUT_SEC:
            return SessionCheckResult(
                ok=False,
                reason=f"high_sens_{int(sens_elapsed)}s",
                event_type="SESSION_EXPIRED_HIGH_SENSITIVITY",
            )

    # 3) 유휴 만료 (max_sensitivity_accessed 로 고민감 단축 분기 유지)
    last_activity = _parse_ts(session.get("last_activity"))
    if last_activity is None:
        return SessionCheckResult(ok=False, reason="missing_last_activity",
                                  event_type="SESSION_EXPIRED_IDLE")

    max_sens = int(session.get("max_sensitivity_accessed", 0) or 0)
    idle_limit = (
        SESSION_HIGH_SENS_TIMEOUT_SEC
        if max_sens >= 4
        else SESSION_IDLE_TIMEOUT_SEC
    )

    idle_elapsed = (now - last_activity).total_seconds()
    if idle_elapsed >= idle_limit:
        event = (
            "SESSION_EXPIRED_HIGH_SENSITIVITY"
            if max_sens >= 4
            else "SESSION_EXPIRED_IDLE"
        )
        return SessionCheckResult(ok=False, reason=f"idle_{int(idle_elapsed)}s",
                                  event_type=event)

    return SessionCheckResult(ok=True)


def deactivate_session(db, session_id: int, reason: str) -> None:
    """세션을 비활성화한다. 호출자가 이벤트 로그를 별도로 남겨야 한다."""
    db.execute(
        "UPDATE sessions SET is_active=FALSE WHERE id=?",
        (session_id,)
    )
    db.commit()


def touch_session(db, session_id: int, sensitivity_grade: int = 0) -> None:
    """세션 활동 시간 갱신 + max_sensitivity_accessed 누적.

    PostgreSQL 의 GREATEST 로 기존 최대 민감도와 새 민감도를 비교한다.
    """
    db.execute(
        "UPDATE sessions "
        "SET last_activity = CURRENT_TIMESTAMP, "
        "    max_sensitivity_accessed = GREATEST(max_sensitivity_accessed, ?) "
        "WHERE id=?",
        (int(sensitivity_grade), session_id)
    )
    db.commit()
