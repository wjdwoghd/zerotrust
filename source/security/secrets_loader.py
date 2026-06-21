"""
비밀 검증기 (L1-2)

역할:
  - 런타임 기동 시점에 필수 비밀값의 "안전성"을 검증한다.
  - 검증 실패 시 SecretValidationError 를 던져 프로세스 기동을 차단한다.

검증 규칙:
  1) SECRET_KEY 가 하드코딩 기본값이면 거부
  2) SECRET_KEY 길이 하한 (32바이트)
  3) DATABASE_URL 이 postgresql:// 가 아니면 거부
  4) JWT_ALGORITHM 이 허용 목록 내인지

호출 시점:
  server.make_app() 의 최초 진입.
"""
from __future__ import annotations

import os
from typing import Dict, Any

import config


# 소스에 남아있던 하드코딩 기본값 (운영에서 사용 금지)
_DEFAULT_SECRET_KEY_BLOCKLIST = {
    "zerotrust-capstone-secret-key-2026",
    "change-me",
    "secret",
    "",
}

# SECRET_KEY 엔트로피 하한: 32바이트.
_SECRET_KEY_MIN_LEN = 32

_ALLOWED_JWT_ALGORITHMS = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}


class SecretValidationError(RuntimeError):
    """기동 중단 사유를 담는 커스텀 예외."""


def _is_weak_secret(secret_key: str) -> bool:
    if secret_key in _DEFAULT_SECRET_KEY_BLOCKLIST:
        return True
    if len(secret_key) < _SECRET_KEY_MIN_LEN:
        return True
    return False


def _scheme(url: str) -> str:
    if not url:
        return ""
    return url.split(":", 1)[0].lower()


def validate_secrets(raw_config: Any = None) -> Dict[str, Any]:
    """
    현재 설정값을 검증하고, 해석된 보안 파라미터를 dict 로 반환한다.

    Raises
    ------
    SecretValidationError :
        검증 실패 시. 호출자는 이 예외를 잡지 말고 프로세스 종료로
        이어지게 해야 한다 (fail-safe).
    """
    if raw_config is not None:
        secret_key = getattr(raw_config, "SECRET_KEY", "")
        jwt_alg = getattr(raw_config, "JWT_ALGORITHM", "HS256")
        database_url = getattr(raw_config, "DATABASE_URL", "")
    else:
        # 호출 시점의 실제 설정을 환경변수에서 직접 재조회.
        secret_key = os.getenv("SECRET_KEY", "")
        jwt_alg = os.getenv("JWT_ALGORITHM", "HS256")
        database_url = os.getenv("DATABASE_URL", "")

    errors = []

    # 규칙 1 & 2: SECRET_KEY
    if _is_weak_secret(secret_key):
        if secret_key in _DEFAULT_SECRET_KEY_BLOCKLIST:
            errors.append(
                "SECRET_KEY is a known default/blocklisted value; "
                "set a strong SECRET_KEY environment variable before starting."
            )
        else:
            errors.append(
                f"SECRET_KEY length {len(secret_key)} is below the minimum "
                f"{_SECRET_KEY_MIN_LEN} required."
            )

    # 규칙 3: DATABASE_URL 스킴 — PostgreSQL 만 허용
    db_scheme = _scheme(database_url)
    if db_scheme not in ("postgresql", "postgres"):
        errors.append(
            f"DATABASE_URL scheme {db_scheme!r} is not allowed; "
            f"only postgresql:// is supported."
        )

    # 규칙 4: JWT_ALGORITHM
    if jwt_alg not in _ALLOWED_JWT_ALGORITHMS:
        errors.append(
            f"JWT_ALGORITHM={jwt_alg!r} is not in the allow list "
            f"{sorted(_ALLOWED_JWT_ALGORITHMS)}."
        )

    if errors:
        detail = "\n  - ".join(errors)
        raise SecretValidationError(
            "Secret/config validation failed — refusing to start.\n  - " + detail
        )

    # 해석된 값 반환
    if raw_config is not None:
        jwt_expiry_hours = int(getattr(raw_config, "JWT_EXPIRY_HOURS", 1))
        jwt_issuer = getattr(raw_config, "JWT_ISSUER", "zerotrust-capstone")
        jwt_audience = getattr(raw_config, "JWT_AUDIENCE", "zerotrust-clients")
    else:
        try:
            jwt_expiry_hours = int(os.getenv("JWT_EXPIRY_HOURS", "1"))
        except ValueError:
            jwt_expiry_hours = 1
        jwt_issuer = os.getenv("JWT_ISSUER", "zerotrust-capstone")
        jwt_audience = os.getenv("JWT_AUDIENCE", "zerotrust-clients")

    return {
        "secret_key": secret_key,
        "secret_key_is_default": secret_key in _DEFAULT_SECRET_KEY_BLOCKLIST,
        "jwt_algorithm": jwt_alg,
        "jwt_expiry_hours": jwt_expiry_hours,
        "jwt_issuer": jwt_issuer,
        "jwt_audience": jwt_audience,
        "database_url": database_url,
        "database_scheme": db_scheme,
    }


def load_and_validate() -> Dict[str, Any]:
    """편의 헬퍼. 실패 시 RuntimeError 가 그대로 전파되어 기동이 중단된다."""
    return validate_secrets()


def explicit_get(name: str, default: str = "") -> str:
    """환경변수에서 이름만 알고 있는 임의 비밀을 안전하게 꺼낸다."""
    return os.getenv(name, default)
