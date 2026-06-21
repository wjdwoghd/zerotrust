"""
Tornado 핸들러 베이스 클래스 (L3-3, L5-1, L6-1/L6-2 반영)

주요 변경점:
  - require_auth 가 core.session_guard.check_session 을 호출해 유휴/절대 만료 판정.
  - write_error 오버라이드로 스택트레이스 노출 금지 + request_id 포함.
  - 기본 보안 헤더를 set_default_headers 에 추가.
  - X-Request-ID 는 매 요청 생성·응답 헤더에 포함.
"""
from __future__ import annotations

import datetime
import json
import uuid
from urllib.parse import unquote

import tornado.web

from config import ALLOWED_ORIGIN
from database import get_db
from security.jwt_handler import decode_token
from core.session_guard import check_session


import math as _math


def _json_fallback(obj):
    """
    json.dumps(default=...) 폴백.
    datetime/Decimal/기타 → str,  float('inf')/nan → None.
    (allow_nan=False 와 함께 쓰면, 실수로 들어온 Infinity 도 null 로 완만히
    직렬화되어 프론트 파싱 실패를 막는다.)
    """
    if isinstance(obj, float) and (_math.isinf(obj) or _math.isnan(obj)):
        return None
    return str(obj)


class BaseHandler(tornado.web.RequestHandler):

    # ── 요청 전처리 ────────────────────────────────────────────
    def prepare(self):
        # X-Request-ID: 요청 식별자. 클라이언트가 제공하면 존중, 없으면 생성.
        rid = self.request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        self.request_id = rid
        self.set_header("X-Request-ID", rid)

    @staticmethod
    def _apply_security_headers(handler):
        """L6-1 + ITEM 10: 표준 보안 헤더를 임의 RequestHandler 에 부여.

        BaseHandler 외에 server.py 의 MainHandler/Healthz/Readyz 도 호출해
        SPA 진입점·헬스체크 응답에 CSP/X-Frame-Options/HSTS 가 빠지지 않도록.
        """
        handler.set_header("X-Content-Type-Options", "nosniff")
        handler.set_header("Referrer-Policy", "no-referrer")
        handler.set_header("X-Frame-Options", "DENY")
        # HSTS: HTTPS 전제 (리버스 프록시 가정)
        handler.set_header("Strict-Transport-Security",
                           "max-age=31536000; includeSubDomains")
        # CSP: SPA + CDN 허용 정책 (정확한 허용 도메인 서술)
        handler.set_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' data:;"
        )

    def set_default_headers(self):
        # CORS — 운영은 same-origin SPA 가정. ALLOWED_ORIGIN 이 비어 있으면
        # Access-Control-Allow-* 헤더 자체를 응답에 추가하지 않는다 → 브라우저가
        # cross-origin 응답을 거부하므로 사실상의 차단.
        #
        # ITEM 2 (감사 #2): 기존에는 "null" 을 박았으나 이는 sandboxed iframe /
        # file:// 매칭으로 cross-origin 우회 경로가 알려져 있어, 의도(차단)와
        # 효과가 정반대였다. 외부 origin 을 신뢰해야 한다면 ALLOWED_ORIGIN
        # 환경변수에 정확한 출처를 지정한다.
        if ALLOWED_ORIGIN:
            self.set_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.set_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-Device-Id, X-Location, "
                "X-IP-Address, X-Request-ID"
            )
            self.set_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS"
            )
        self.set_header("Content-Type", "application/json")

        BaseHandler._apply_security_headers(self)

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.finish()

    # ── JSON 유틸 ───────────────────────────────────────────────
    def get_json_body(self):
        try:
            return json.loads(self.request.body)
        except (json.JSONDecodeError, TypeError):
            return {}

    def write_json(self, data, status=200):
        self.set_status(status)
        # allow_nan=False: Infinity/NaN 를 JSON 리터럴로 내보내면 브라우저
        # JSON.parse 가 SyntaxError 로 거부해 무응답처럼 보이는 사고가 난다.
        # RFC 8259 기준 유효 JSON 만 내보내고, 직렬화 불가 값이 있으면
        # default=_json_fallback 이 문자열로 변환 (datetime, Decimal 등 포함).
        self.write(json.dumps(
            data,
            ensure_ascii=False,
            allow_nan=False,
            default=_json_fallback,
        ))

    def write_error_json(self, message, status=400, code: str | None = None):
        self.set_status(status)
        body = {"error": message, "request_id": getattr(self, "request_id", "-")}
        if code:
            body["code"] = code
        self.write(json.dumps(body, ensure_ascii=False))

    # ── L6-2: 에러 응답 세정 ───────────────────────────────────
    def write_error(self, status_code: int, **kwargs):
        """Tornado 기본 write_error 오버라이드 — 스택트레이스 숨김."""
        self.set_header("Content-Type", "application/json")
        body = {
            "error": self._reason or "server_error",
            "request_id": getattr(self, "request_id", "-"),
            "status": status_code,
        }
        # 운영 모드 — 스택트레이스 비공개. (트러블슈팅은 audit_logs / stderr 로.)
        self.finish(json.dumps(body, ensure_ascii=False))

    # ── 인증 ────────────────────────────────────────────────────
    def get_current_user_from_token(self):
        auth = self.request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        payload = decode_token(token)
        if not payload:
            return None
        return payload

    def require_auth(self):
        """인증 + 세션 유효성 + 유휴/절대 만료 판정."""
        user = self.get_current_user_from_token()
        if not user:
            self._respond_token_expired("token_invalid")
            return None
        if not user.get("mfa_verified"):
            self.write_error_json("MFA 인증이 필요합니다", 401, code="mfa_required")
            return None

        session_id = user.get("session_id")
        if session_id:
            db = get_db()
            try:
                session_row = db.execute(
                    "SELECT id, user_id, is_active, login_at, last_activity, "
                    "absolute_expires_at, max_sensitivity_accessed, "
                    "pending_reauth, pending_reauth_at "
                    "FROM sessions WHERE id=?",
                    (session_id,)
                ).fetchone()

                # ITEM 8 (감사 #8): check_session() 을 먼저 호출해야
                # core/session_guard.py:98-111 의 SESSION_EXPIRED_PENDING_REAUTH
                # 만료 분기에 도달할 수 있다. 기존 코드는 pending_reauth=TRUE
                # 면 즉시 401 로 끊어서 시한 초과 만료가 영원히 잡히지 않았다.
                result = check_session(session_row)
                if not result.ok:
                    # 세션을 즉시 비활성화 (이미 비활성일 수도 있음)
                    if session_row:
                        db.execute(
                            "UPDATE sessions SET is_active=FALSE WHERE id=?",
                            (session_id,)
                        )
                        db.commit()
                    # 감사 이벤트 기록 (L5-2). pending_reauth 시한 초과면
                    # SESSION_EXPIRED_PENDING_REAUTH 가 result.event_type 로 옴.
                    self._emit_session_expired_audit(db, user, session_id, result)
                    self._respond_token_expired(result.event_type or "session_expired")
                    return None

                # 만료가 아닌 정상 세션이지만 pending_reauth=TRUE → MFA 재인증
                # 전까지 보호된 엔드포인트 차단. reauth 자체는 예외.
                if session_row and session_row["pending_reauth"]:
                    path = self.request.path or ""
                    if not path.endswith("/api/auth/reauth"):
                        self.set_header("WWW-Authenticate",
                                        'Bearer error="reauth_required"')
                        self.write_error_json(
                            "동시 접속이 감지되어 재인증이 필요합니다.",
                            401, code="concurrent_session_detected"
                        )
                        return None

                # 사용자 잠금/비활성 확인
                user_row = db.execute(
                    "SELECT is_active, is_locked FROM users WHERE id=?",
                    (user["user_id"],)
                ).fetchone()
                if (not user_row or not user_row["is_active"]
                        or user_row["is_locked"]):
                    self.write_error_json(
                        "계정이 잠기거나 비활성화되었습니다.",
                        403, code="account_locked"
                    )
                    return None
            finally:
                db.close()

        return user

    @staticmethod
    def is_admin_role(user) -> bool:
        """관리자 등급 여부 — deputy_admin 도 admin 과 동등 취급.

        ITEM 6: 일부 핸들러가 ('admin', 'superadmin') 만 비교해 deputy_admin
        을 일반 사용자로 다루던 일관성 결함을 한 곳에서 정의.
        """
        if user is None:
            return False
        return user.get("role") in ("admin", "superadmin", "deputy_admin")

    def require_admin(self):
        """관리자 패널/승인 엔드포인트 공통 가드.

        deputy_admin 은 '관리자 순환 문제' 해소용 — admin_lee 가 본인이 신청한
        승인요청이나 본인이 발동한 Break-Glass 를 스스로 처리할 수 없는 상황에서
        ADMIN_APPROVAL_APPROVE / BG_REVIEW 등을 대신 처리한다. admin 과 동등한
        권한을 부여하되, 자기-승인/자기-리뷰 차단은 user_id 비교로 이미 막혀 있다.
        """
        user = self.require_auth()
        if not user:
            return None
        if not self.is_admin_role(user):
            self.write_error_json("관리자 권한이 필요합니다", 403, code="forbidden")
            return None
        return user

    # ── 클라이언트 컨텍스트 ──────────────────────────────────────
    def get_device_id(self):
        raw = self.request.headers.get("X-Device-Id", "unknown-device")
        return unquote(raw)

    def get_location(self):
        raw = self.request.headers.get("X-Location", "%EB%B3%B8%EC%B2%AD")
        return unquote(raw)

    def get_simulated_hour(self):
        """시뮬 패널에서 지정한 시간대 (X-Sim-Hour 헤더, 0-23) 반환.

        시연 시뮬레이션 전용 — 클라이언트가 야간 시간대 등을 직접 지정해
        환경 위험 평가 변동을 검증할 수 있게 한다. 헤더가 없거나 범위 밖이면
        None 반환 → 호출자가 서버 OS 시각으로 fallback.

        보안 메모: 이 헤더는 시뮬 의도이므로 운영 환경에선 클라이언트 위조
        가능성이 있다. 현재는 발표 시연용 단순화 — admin 권한 / 환경변수
        가드는 별도 ITEM 후보.
        """
        raw = self.request.headers.get("X-Sim-Hour")
        if raw is None or raw == "":
            return None
        try:
            h = int(raw)
        except (TypeError, ValueError):
            return None
        if not (0 <= h <= 23):
            return None
        return h

    def get_ip_address(self):
        return self.request.headers.get(
            "X-IP-Address",
            self.request.remote_ip or "127.0.0.1"
        )

    # ── 내부 헬퍼 ───────────────────────────────────────────────
    def _respond_token_expired(self, code: str) -> None:
        self.set_header("WWW-Authenticate", 'Bearer error="token_expired"')
        self.write_error_json("세션이 만료되었습니다. 다시 로그인하세요.",
                              401, code=code)

    def _emit_session_expired_audit(self, db, user: dict, session_id: int, result):
        """세션 만료 감사 이벤트를 audit_logs 에 기록."""
        try:
            db.execute(
                "INSERT INTO audit_logs (request_id, layer, event_type, details, user_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    getattr(self, "request_id", "-"),
                    "audit",
                    result.event_type or "SESSION_EXPIRED_IDLE",
                    json.dumps({
                        "session_id": session_id,
                        "reason": result.reason,
                        "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
                    }, ensure_ascii=False),
                    user.get("user_id"),
                )
            )
            db.commit()
        except Exception:
            # 감사 실패가 원 요청 흐름을 중단시켜서는 안 됨. rollback 만 수행.
            try:
                db.rollback()
            except Exception:
                pass
