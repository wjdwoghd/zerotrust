"""
JWT 토큰 발급/검증 (L3-2)

- 서명 키는 config → secrets_loader 가 검증한 값을 사용.
- iss / aud 클레임 추가.
- SECRET_KEY 회전 시 기존 토큰 무효화 (서명 검증 실패로 자연 거부)
  + 회전 감지용 이벤트는 호출 계층에서 SECRET_ROTATED 로 emit.
"""
from __future__ import annotations

import time
from typing import Optional

import jwt

from config import (
    SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRY_HOURS,
    JWT_ISSUER, JWT_AUDIENCE,
)


# pyjwt 는 aud 검증을 옵션으로 사용. 검증 실패 시 InvalidAudienceError 반환.
_DECODE_OPTIONS = {"verify_aud": True}


def create_token(user_id: int, username: str, role: str,
                 mfa_verified: bool = False,
                 session_id: Optional[int] = None,
                 device_id: Optional[str] = None,
                 expiry_hours: Optional[int] = None,
                 admin_gated: bool = False,
                 approval_request_id: Optional[int] = None) -> str:
    now = int(time.time())
    hours = expiry_hours if expiry_hours is not None else JWT_EXPIRY_HOURS
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + hours * 3600,
        "user_id": user_id,
        "username": username,
        "role": role,
        "mfa_verified": bool(mfa_verified),
    }
    if session_id is not None:
        payload["session_id"] = session_id
    if device_id is not None:
        # Zero Trust: 1차 토큰에 기기를 박아 MFA 단계의 기기 바꿔치기 차단.
        payload["device_id"] = device_id
    # 관리자 승인 게이트 경로: MFA 단계에서 단축 세션을 개설하기 위해 토큰에 표식.
    # (과거 명칭 "bg" 는 의미 충돌로 008 에서 "ag"(admin-gated) 로 개명.)
    if admin_gated:
        payload["ag"] = True
    if approval_request_id is not None:
        payload["ag_request_id"] = int(approval_request_id)
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str, verify_aud: Optional[bool] = None) -> Optional[dict]:
    """
    verify_aud:
      - None (기본) → 기존 동작: 실패 시 None 반환
      - True        → aud 불일치를 예외로 전파 (테스트·엄격검증용)
      - False       → aud 검증 자체를 비활성
    """
    if not token:
        return None
    # 테스트에서 config.JWT_AUDIENCE 를 monkeypatch 할 수 있도록 호출 시점 재조회.
    import config as _cfg
    _aud = getattr(_cfg, "JWT_AUDIENCE", JWT_AUDIENCE)
    _iss = getattr(_cfg, "JWT_ISSUER", JWT_ISSUER)
    _key = getattr(_cfg, "SECRET_KEY", SECRET_KEY)

    if verify_aud is False:
        opts = {"verify_aud": False}
    else:
        opts = {"verify_aud": True}

    try:
        return jwt.decode(
            token, _key,
            algorithms=[JWT_ALGORITHM],
            audience=_aud,
            issuer=_iss,
            options=opts,
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidAudienceError:
        if verify_aud is True:
            raise
        return None
    except jwt.InvalidTokenError:
        # InvalidIssuerError, InvalidSignatureError 등 포함
        return None


# ─── §5-3 OPM-L3-02 호환 adapter ──────────────────────────────────
def issue_token(user_id: int, role: str,
                session_id: Optional[object] = None,
                username: Optional[str] = None,
                **kwargs) -> str:
    """
    스펙(§5-3) 호환 어댑터.
    username 없이 (user_id, role, session_id) 만으로 토큰을 발급한다.
    """
    uname = username if username is not None else f"user_{user_id}"
    return create_token(
        user_id=user_id,
        username=uname,
        role=role,
        session_id=session_id,
        **kwargs,
    )


def decode_token_verbose(token: str) -> dict:
    """
    세부 실패 사유가 필요한 경로(감사 로그)용.
    반환: {"ok": bool, "payload": dict|None, "error": str|None}
    """
    if not token:
        return {"ok": False, "payload": None, "error": "empty_token"}
    try:
        payload = jwt.decode(
            token, SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options=_DECODE_OPTIONS,
        )
        return {"ok": True, "payload": payload, "error": None}
    except jwt.ExpiredSignatureError:
        return {"ok": False, "payload": None, "error": "expired"}
    except jwt.InvalidSignatureError:
        return {"ok": False, "payload": None, "error": "invalid_signature"}
    except jwt.InvalidAudienceError:
        return {"ok": False, "payload": None, "error": "invalid_audience"}
    except jwt.InvalidIssuerError:
        return {"ok": False, "payload": None, "error": "invalid_issuer"}
    except jwt.InvalidTokenError as e:
        return {"ok": False, "payload": None, "error": f"invalid:{type(e).__name__}"}
