"""
MFA / TOTP 서비스 (L3-1)

운영 환경에서는 항상 실제 HMAC-SHA1 기반 TOTP 검증만 사용한다.
pyotp 가 설치되어 있으면 `pyotp.TOTP.verify(otp, valid_window=TOTP_VALID_WINDOW)`
를 우선 사용하고, 없으면 자작 HMAC 구현으로 폴백한다.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from config import TOTP_VALID_WINDOW


try:
    import pyotp
    _HAS_PYOTP = True
except ImportError:
    pyotp = None  # type: ignore
    _HAS_PYOTP = False


# ─── 시크릿 생성 ──────────────────────────────────────────────────
def generate_secret() -> str:
    """RFC 4648 base32, 160-bit 시크릿."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")


# ─── HMAC-SHA1 TOTP (pyotp 폴백) ─────────────────────────────────
def _dynamic_truncation(hmac_result: bytes) -> int:
    offset = hmac_result[-1] & 0x0F
    code = struct.unpack(">I", hmac_result[offset:offset + 4])[0]
    return (code & 0x7FFFFFFF) % 1000000


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    return str(_dynamic_truncation(digest)).zfill(6)


def generate_totp(secret: str, time_step: int = 30) -> str:
    """현재 시간 기반 TOTP 생성."""
    if _HAS_PYOTP:
        return pyotp.TOTP(secret).now()
    counter = int(time.time()) // time_step
    return _hotp(secret, counter)


# ─── 검증 ─────────────────────────────────────────────────────────
def verify_totp(secret: str, otp: str, time_step: int = 30,
                window: int | None = None) -> bool:
    """
    TOTP 검증 (하위호환 — bool 반환).

    replay 방지를 적용하려면 verify_totp_consume() 를 사용하라.
    """
    ok, _ = verify_totp_consume(secret, otp, time_step=time_step, window=window)
    return ok


def verify_totp_consume(secret: str, otp: str, *,
                        last_used_step: int | None = None,
                        time_step: int = 30,
                        window: int | None = None) -> tuple[bool, int | None]:
    """
    TOTP 검증 + 통과한 step 번호 반환 (RFC 6238 §5.2 replay 방지).

    Parameters
    ----------
    secret :
        base32 사용자 시크릿.
    otp :
        클라이언트 입력 6자리 코드.
    last_used_step :
        이 (사용자, 토큰 기기) 가 마지막으로 통과시킨 step 번호.
        주어지면 그보다 작거나 같은 step 의 코드는 거부 — 같은 OTP
        재사용 차단. None 이면 (마이그레이션 직후 등) 모든 윈도우 내
        step 을 허용 (첫 사용).
    time_step, window :
        기존 시그니처 동등.

    Returns
    -------
    (ok, used_step)
        ok=True 이면 used_step 가 통과한 정확한 step 번호. 호출자는 이
        값을 user_devices.last_otp_step 에 갱신해야 다음 검증부터
        replay 가 차단된다.
        ok=False 이면 used_step=None.
    """
    if not (isinstance(otp, str) and otp.isdigit() and len(otp) == 6):
        return False, None

    if window is None:
        window = TOTP_VALID_WINDOW

    current = int(time.time()) // time_step

    # 정확한 step 번호를 알아내려면 자작 HMAC 경로로 직접 비교한다.
    # pyotp.verify() 는 step 번호를 노출 안 함 → 자작 경로 사용.
    for offset in range(-window, window + 1):
        s = current + offset
        if last_used_step is not None and s <= last_used_step:
            continue
        if hmac.compare_digest(_hotp(secret, s), otp):
            return True, s
    return False, None


# ─── §5-3 OPM-L3-01 호환 adapter ──────────────────────────────────
def verify_otp(user_id: int, otp: str) -> bool:
    """
    스펙(§5-3 OPM-L3-01) 호환 어댑터.
    명시적 secret 없이 호출되었으므로 항상 거부한다.
    실제 OTP 검증은 반드시 `verify_totp(secret, otp)` 경로로 수행한다.
    (auth_handler 가 user_devices.mfa_secret 을 조회해 이 경로로 호출함.)
    """
    return False


def provisioning_uri(secret: str, username: str, issuer: str = "ZeroTrustCapstone") -> str:
    """authenticator 앱 등록용 otpauth:// URI. QR 코드 생성 보조."""
    if _HAS_PYOTP:
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30")
