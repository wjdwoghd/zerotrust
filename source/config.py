"""
시스템 설정 (운영 모드 단일)

본 시스템은 운영 모드만 지원한다. 데이터베이스는 PostgreSQL 만 허용하며,
스키마는 `migrations/` 디렉터리의 SQL 파일을 `scripts/run_migrations.py` 로
적용한다. 비밀 검증(약한 SECRET_KEY 거부, 비-PG URL 거부 등)은
`security/secrets_loader.py` 에서 수행한다.
"""
import os
import sys

# ── .env 자동 로드 (python-dotenv 가 설치된 경우에만) ────────────
# config.py 최상단에서 수행해 이후 os.getenv() 호출이 .env 값을 볼 수 있게 한다.
# python-dotenv 미설치 / .env 미존재 환경에서는 조용히 통과한다.
try:
    from dotenv import load_dotenv as _load_dotenv
    from pathlib import Path as _Path
    _ENV_FILE = _Path(__file__).resolve().parent / ".env"
    if _ENV_FILE.exists():
        _load_dotenv(_ENV_FILE, override=False)
except ImportError:
    pass


# ── JWT ────────────────────────────────────────────────────────
# 기본값은 의도적으로 약한 값 → 기동 시 secrets_loader 가 거부한다.
SECRET_KEY = os.getenv("SECRET_KEY", "zerotrust-capstone-secret-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "1"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "zerotrust-capstone")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "zerotrust-clients")


# ── DB ─────────────────────────────────────────────────────────
# 운영은 PostgreSQL 고정. secrets_loader 가 비-PG URL 을 거부한다.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ztuser:changeme@localhost:5432/zerotrust",
)


# ── TOTP ───────────────────────────────────────────────────────
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "ZeroTrustCapstone")
TOTP_VALID_WINDOW = int(os.getenv("TOTP_VALID_WINDOW", "1"))  # ±30s * window


# ── 세션 만료 (L3-3) ───────────────────────────────────────────
SESSION_IDLE_TIMEOUT_SEC = int(os.getenv("SESSION_IDLE_TIMEOUT_SEC", "900"))       # 15m
SESSION_HIGH_SENS_TIMEOUT_SEC = int(os.getenv("SESSION_HIGH_SENS_TIMEOUT_SEC", "300"))  # 5m
SESSION_ABSOLUTE_TIMEOUT_SEC = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_SEC", "28800"))  # 8h


# ── 계정 잠금 ──────────────────────────────────────────────────
ACCOUNT_MAX_FAILED_LOGIN = int(os.getenv("ACCOUNT_MAX_FAILED_LOGIN", "5"))


# ── 사전 승인 유효 시간 (운영 30m) ─────────────────────────────
PRE_APPROVAL_TTL_SEC = int(os.getenv("PRE_APPROVAL_TTL_SEC", "1800"))   # 30m


# ── Level 3 재인증 유효 시간 ─────────────────────────────────
# 사용자가 재인증(추가 OTP 검증) 에 성공한 뒤, 이 시간 동안은
# policy_engine.check_force_reauth() 가 요구하는 재인증 조건을 통과한 것으로
# 간주한다. 짧게 유지해 재인증의 의미를 살린다.
REAUTH_TTL_SEC = int(os.getenv("REAUTH_TTL_SEC", "300"))  # 5m


# ── 동시 접속 정책: pending_reauth 자동 만료 시한 ─────────────
# 두 번째 로그인이 탐지되면 양쪽 세션 모두 pending_reauth=TRUE 로 잠기고,
# 어느 쪽이든 MFA 재인증에 먼저 성공해야 통과된다. 이 시간 안에 아무도
# 재인증을 완료하지 않으면 session_guard 가 세션을 만료 처리한다.
SESSION_PENDING_REAUTH_TIMEOUT_SEC = int(
    os.getenv("SESSION_PENDING_REAUTH_TIMEOUT_SEC", "300")
)  # 5m


# ── 관리자 승인 로그인 게이트 (006 + 008 마이그레이션 연동) ───
# 사용자의 trust_score 가 임계값보다 낮거나 violation_count 가 임계값
# 이상이면 "의심 계정" 으로 분류되고, 로그인은 관리자의 명시적 승인
# (login_approval_requests) 이 있는 경우에만 허용된다.
SUSPICIOUS_TRUST_THRESHOLD = float(os.getenv("SUSPICIOUS_TRUST_THRESHOLD", "50"))
SUSPICIOUS_VIOLATION_THRESHOLD = int(os.getenv("SUSPICIOUS_VIOLATION_THRESHOLD", "3"))

# 관리자 로그인 승인 1건의 유효기간 (승인 후 이 시간 내에 로그인해야 함).
ADMIN_APPROVAL_TTL_SEC = int(os.getenv("ADMIN_APPROVAL_TTL_SEC", "1800"))  # 30m

# 관리자 승인으로 개설된 세션에 적용되는 단축 만료. 일반 세션(15m / 8h)
# 보다 훨씬 짧게 둔다.
ADMIN_GATED_SESSION_IDLE_SEC = int(os.getenv("ADMIN_GATED_SESSION_IDLE_SEC", "300"))       # 5m
ADMIN_GATED_SESSION_ABSOLUTE_SEC = int(os.getenv("ADMIN_GATED_SESSION_ABSOLUTE_SEC", "1800"))  # 30m


# ── Break-Glass (긴급 자가발동) ───────────────────────────────
# 자격 있는 사용자가 자기 책임 하에 고민감 자원 접근을 긴급 자가발동한다.
# 사후 관리자 리뷰로 정당성을 판정한다. (NIST SP 800-207 §7 "emergency
# access" 컨셉, ISO 27001 9.4 의 privileged access 예외 조항과 정합.)
BREAK_GLASS_TTL_SEC = int(os.getenv("BREAK_GLASS_TTL_SEC", "1800"))       # 30m
BREAK_GLASS_IDLE_SEC = int(os.getenv("BREAK_GLASS_IDLE_SEC", "300"))      # 5m
# 이 등급 이상의 자원만 BG 로 우회 가능. Grade 3 이하는 정상 정책으로 충분.
BREAK_GLASS_MIN_GRADE = int(os.getenv("BREAK_GLASS_MIN_GRADE", "4"))
# unjustified 리뷰 시 trust_score 차감량
BREAK_GLASS_TRUST_PENALTY = int(os.getenv("BREAK_GLASS_TRUST_PENALTY", "30"))
# unjustified 리뷰 시 violation_count 증가량
BREAK_GLASS_VIOLATION_PENALTY = int(os.getenv("BREAK_GLASS_VIOLATION_PENALTY", "1"))


# ── CORS ───────────────────────────────────────────────────────
# 빈 문자열(default) 이면 Same-origin SPA 로 가정 — 응답에 Access-Control-Allow-*
# 헤더 자체를 추가하지 않아 브라우저가 cross-origin 응답을 거부.
# 외부 origin 을 허용해야 하면 ALLOWED_ORIGIN 에 정확한 출처를 지정 (예:
# "https://admin.example.gov"). 절대 "null" 또는 "*" 을 쓰지 말 것 —
# "null" 은 sandboxed iframe / file:// 매칭으로 알려진 우회 경로,
# "*" 은 자격증명을 동반한 요청에서 오용될 위험이 있다.
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "")


# ── 서버 ───────────────────────────────────────────────────────
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
TORNADO_DEBUG = False  # 운영 환경 — 디버그 트레이스 비공개
