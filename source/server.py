"""
동적 제로트러스트 접근제어 시스템 — 메인 서버 (운영 모드 전용)

기동 흐름:
  1. secrets_loader.load_and_validate() — 약한 SECRET_KEY / 비-PG URL 거부
  2. 이전 프로세스가 남긴 라이브 세션 일괄 비활성화
  3. /healthz, /readyz, /api/metrics 운영 엔드포인트 등록
  4. SIGTERM 수신 시 IOLoop 에 drain 콜백을 걸어 정상 종료

스키마는 `migrations/` 디렉터리의 SQL 을 `scripts/run_migrations.py` 가
적용한다. 본 서버는 DDL 을 직접 실행하지 않는다.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time

import tornado.ioloop
import tornado.web

sys.path.insert(0, os.path.dirname(__file__))

from config import SERVER_PORT, TORNADO_DEBUG
from security.secrets_loader import load_and_validate, SecretValidationError
from database import get_db
from core import metrics
from core.audit_events import AuditEvent, audit_log

from api.auth_handler import (
    LoginHandler, MFAVerifyHandler, LogoutHandler, MeHandler,
    TOTPCodeHandler, MFADeviceOtpHandler, ReauthHandler,
    DeviceHintHandler, HeartbeatHandler,
)
from api.resource_handler import (
    CaseListHandler, CaseDetailHandler, CaseAccessStatusHandler,
    CaseRestrictedClickHandler, CaseDownloadHandler, CaseFileHandler,
    CaseApprovalRequestHandler, CaseAssignmentRequestHandler, MyCaseAssignmentRequestsHandler, CaseAssignmentOtpVerifyHandler,
)
from api.admin_handler import (
    PendingApprovalsHandler, ApproveHandler, RejectHandler,
    CaseAssignmentPendingHandler, CaseAssignmentRequireOtpHandler,
    CaseAssignmentApproveHandler, CaseAssignmentRejectHandler,
    UserListHandler, UnlockUserHandler,
    DeactivateUserHandler, ActivateUserHandler, DeleteUserHandler, CreateUserHandler,
    UpdateAllowedLocationsHandler,
    AdminApprovalPendingHandler, AdminApprovalHistoryHandler,
    AdminApprovalApproveHandler, AdminApprovalRejectHandler,
    AdminApprovalStatusHandler,
)
from api.audit_handler import (
    AuditLogHandler, AccessLogHandler, DashboardStatsHandler,
    AccessDecisionReviewHandler,
)
from api.device_handler import (
    DeviceListHandler, DeviceItemHandler, DeviceTotpHandler,
    DeviceOtpRequestsHandler,
)
from api.break_glass_handler import (
    BreakGlassActivateHandler, BreakGlassMyActiveHandler, BreakGlassReleaseHandler,
    AdminBreakGlassPendingHandler, AdminBreakGlassHistoryHandler,
    AdminBreakGlassReviewHandler, AdminBreakGlassRevokeHandler,
)
from api.base_handler import BaseHandler


STATIC_PATH = os.path.join(os.path.dirname(__file__), "static")


class MainHandler(tornado.web.RequestHandler):
    """SPA 진입점 - index.html 서빙"""
    def set_default_headers(self):
        # ITEM 10: BaseHandler 비-상속 핸들러도 CSP/X-Frame-Options/HSTS 적용.
        BaseHandler._apply_security_headers(self)

    def get(self, *args):
        self.set_header("Content-Type", "text/html")
        self.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.set_header("Pragma", "no-cache")
        self.set_header("Expires", "0")
        with open(os.path.join(STATIC_PATH, "index.html"), "r", encoding="utf-8") as f:
            self.write(f.read())


# ─── 운영 경화: 헬스체크 & 메트릭 ────────────────────────────────
class HealthzHandler(tornado.web.RequestHandler):
    """L6-3: 프로세스 생존 여부 (빠른 응답)."""
    def set_default_headers(self):
        # ITEM 10: 보안 헤더.
        BaseHandler._apply_security_headers(self)

    def get(self):
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "ok"}))


class ReadyzHandler(tornado.web.RequestHandler):
    """L6-3: DB 핑 + 설정 로드 여부."""
    def set_default_headers(self):
        # ITEM 10: 보안 헤더.
        BaseHandler._apply_security_headers(self)

    def get(self):
        self.set_header("Content-Type", "application/json")
        try:
            db = get_db()
            db.execute("SELECT 1").fetchone()
            db.close()
            self.set_status(200)
            self.write(json.dumps({"status": "ready", "db": "up"}))
        except Exception as e:
            self.set_status(503)
            self.write(json.dumps({
                "status": "not_ready",
                "error": type(e).__name__,
            }))


class MetricsHandler(BaseHandler):
    """L5-5: 운영 메트릭. 관리자 토큰 필수."""
    def get(self):
        user = self.require_admin()
        if not user:
            return
        self.write_json(metrics.snapshot())


# ─── 세션 초기화 ──────────────────────────────────────────────────
def _invalidate_live_sessions(reason: str) -> int:
    """
    sessions 테이블의 모든 is_active=TRUE 행을 비활성화한다.

    호출 시점:
      - 서버 기동 직후 (이전 종료/크래시/킬-9 흔적 청소)
      - SIGINT/SIGTERM 수신 시 (정상 종료 시 현재 라이브 세션 모두 내림)

    이유:
      프로세스가 죽으면 클라이언트 측 토큰은 물리적으로 남아있더라도
      서버 입장에선 "내가 만든 적 없는 세션"이므로 신뢰 기반 세션이라
      할 수 없다. 기동/종료 시 일괄 청소가 Zero-Trust 관점에서도 안전하고,
      운영 UX 관점에서도 올바르다.

    반환: 영향 받은 행 수 (best-effort; 실패 시 0).
    """
    try:
        db = get_db()
        cnt_row = db.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE is_active"
        ).fetchone()
        killed = int(cnt_row["c"]) if cnt_row else 0

        if killed:
            db.execute(
                "UPDATE sessions SET is_active=FALSE WHERE is_active=TRUE"
            )
            db.execute(
                "INSERT INTO operation_logs (event_type, details, user_id) "
                "VALUES (?, ?, ?)",
                (
                    "SESSIONS_INVALIDATED_ON_RESTART",
                    json.dumps({"reason": reason, "count": killed},
                               ensure_ascii=False),
                    None,
                )
            )
        db.commit()
        db.close()
        return killed
    except Exception as e:
        # 청소 실패해도 기동/종료 자체는 막지 않는다.
        print(f"[server] session cleanup failed ({reason}): {e}",
              file=sys.stderr)
        try:
            db.rollback()
            db.close()
        except Exception:
            pass
        return 0


# ─── 종료 핸들러 ──────────────────────────────────────────────────
_shutting_down = False


def _graceful_shutdown(signum, frame):  # noqa: ARG001
    """L6-4: SIGTERM/SIGINT 처리."""
    global _shutting_down
    if _shutting_down:
        return
    _shutting_down = True
    print(f"[server] received signal={signum} — initiating graceful shutdown.",
          file=sys.stderr)

    killed = _invalidate_live_sessions("graceful_shutdown")
    if killed:
        print(f"[server] invalidated {killed} live session(s) on shutdown.",
              file=sys.stderr)

    io_loop = tornado.ioloop.IOLoop.current()

    def _stop():
        io_loop.stop()

    # 진행 중 요청의 drain 시간을 최대 5초로 제한
    deadline = time.time() + 5
    io_loop.add_callback_from_signal(
        lambda: io_loop.add_timeout(deadline, _stop)
    )


# ─── 앱 생성 ──────────────────────────────────────────────────────
def make_app() -> tornado.web.Application:
    # 1) 비밀 검증 — 약한 SECRET_KEY / 비-PG URL 이면 여기서 중단
    try:
        load_and_validate()
    except SecretValidationError as e:
        print(f"[server] REFUSING TO START: {e}", file=sys.stderr)
        raise

    # 2) 이전 프로세스가 남긴 라이브 세션 정리.
    #    SIGKILL/크래시/전원차단 같은 비정상 종료 경로에선 _graceful_shutdown
    #    훅이 돌지 않으므로, 기동 시 한 번 더 청소해야 안전하다. 세션의 신뢰는
    #    프로세스 수명과 1:1 — 프로세스가 재시작됐다는 건 그 세션이 "내가 발급한
    #    세션"이라는 보증이 깨졌다는 뜻이므로 일괄 내려도 무방.
    killed = _invalidate_live_sessions("server_startup")
    if killed:
        print(f"[server] invalidated {killed} stale live session(s) on startup.",
              file=sys.stderr)

    app = tornado.web.Application([
        # Auth API
        (r"/api/auth/login", LoginHandler),
        (r"/api/auth/mfa/verify", MFAVerifyHandler),
        (r"/api/auth/mfa/otp", MFADeviceOtpHandler),
        (r"/api/auth/reauth", ReauthHandler),
        (r"/api/auth/logout", LogoutHandler),
        (r"/api/auth/heartbeat", HeartbeatHandler),
        (r"/api/auth/me", MeHandler),
        (r"/api/auth/device-hint", DeviceHintHandler),
        (r"/api/auth/totp-code", TOTPCodeHandler),  # deprecated (410)

        # Resource API
        (r"/api/resources/cases", CaseListHandler),
        (r"/api/resources/cases/(\d+)/status", CaseAccessStatusHandler),
        (r"/api/resources/cases/(\d+)/restricted-click", CaseRestrictedClickHandler),
        (r"/api/resources/cases/(\d+)", CaseDetailHandler),
        (r"/api/resources/cases/(\d+)/download", CaseDownloadHandler),
        (r"/api/resources/cases/(\d+)/file", CaseFileHandler),
        (r"/api/resources/cases/(\d+)/request-approval", CaseApprovalRequestHandler),
        (r"/api/resources/cases/(\d+)/assignment-request", CaseAssignmentRequestHandler),
        (r"/api/resources/case-assignment-requests/my", MyCaseAssignmentRequestsHandler),
        (r"/api/resources/case-assignment-requests/(\d+)/verify-otp", CaseAssignmentOtpVerifyHandler),

        # Admin API
        (r"/api/admin/approvals/pending", PendingApprovalsHandler),
        (r"/api/admin/approvals/(\d+)/approve", ApproveHandler),
        (r"/api/admin/approvals/(\d+)/reject", RejectHandler),
        (r"/api/admin/case-assignment-requests/pending", CaseAssignmentPendingHandler),
        (r"/api/admin/case-assignment-requests/(\d+)/require-otp", CaseAssignmentRequireOtpHandler),
        (r"/api/admin/case-assignment-requests/(\d+)/approve", CaseAssignmentApproveHandler),
        (r"/api/admin/case-assignment-requests/(\d+)/reject", CaseAssignmentRejectHandler),
        (r"/api/admin/users", UserListHandler),            # GET: 목록 / POST: 신규 생성 (§20)
        (r"/api/admin/users/create", CreateUserHandler),   # POST 전용 별칭 — GET/POST 충돌 회피
        (r"/api/admin/users/(\d+)/unlock", UnlockUserHandler),
        (r"/api/admin/users/(\d+)/deactivate", DeactivateUserHandler),
        (r"/api/admin/users/(\d+)/activate", ActivateUserHandler),
        # 허용 위치(allowed_locations) 갱신 — 이중감독 권한 분리.
        # admin↔user/deputy_admin, deputy_admin↔admin/superadmin.
        (r"/api/admin/users/(\d+)/allowed_locations", UpdateAllowedLocationsHandler),
        # §20 (개정) 계정 하드 삭제 — DELETE 메서드. soft delete(비활성)와 분리 운용.
        (r"/api/admin/users/(\d+)", DeleteUserHandler),

        # 관리자 로그인 승인 게이트 (의심 계정 / 토큰 기기 미보유)
        (r"/api/admin/login-approvals/pending", AdminApprovalPendingHandler),
        (r"/api/admin/login-approvals/history", AdminApprovalHistoryHandler),
        (r"/api/admin/login-approvals/(\d+)/approve", AdminApprovalApproveHandler),
        (r"/api/admin/login-approvals/(\d+)/reject", AdminApprovalRejectHandler),
        # 인증 미필 로그인 화면이 승인 상태를 폴링할 때 사용
        (r"/api/auth/login-approval/status", AdminApprovalStatusHandler),

        # Audit API
        (r"/api/audit/logs", AuditLogHandler),
        (r"/api/audit/access-logs", AccessLogHandler),
        (r"/api/audit/dashboard", DashboardStatsHandler),
        # 017: 결정 사후 라벨링 (FP/FN 신고 → trust 자동 조정)
        (r"/api/admin/access-logs/(\d+)/review", AccessDecisionReviewHandler),

        # Device API (가상 기기 등록 / 기기별 TOTP)
        (r"/api/devices", DeviceListHandler),
        (r"/api/devices/(\d+)", DeviceItemHandler),
        (r"/api/devices/(\d+)/totp", DeviceTotpHandler),

        # Token Device App — 별도 실행되는 Tkinter 토큰 기기 앱이
        # 3초 주기로 폴링. API key 인증.
        (r"/api/device/otp-requests", DeviceOtpRequestsHandler),

        # ─── Break-Glass (긴급 자가발동) ───
        # 사용자 엔드포인트 — 토큰 기기 보유자 전용(핸들러 내부에서 검증).
        (r"/api/break-glass/activate", BreakGlassActivateHandler),
        (r"/api/break-glass/my-active", BreakGlassMyActiveHandler),
        (r"/api/break-glass/(\d+)/release", BreakGlassReleaseHandler),
        # 관리자 엔드포인트 — 리뷰·회수
        (r"/api/admin/break-glass/pending", AdminBreakGlassPendingHandler),
        (r"/api/admin/break-glass/history", AdminBreakGlassHistoryHandler),
        (r"/api/admin/break-glass/(\d+)/review", AdminBreakGlassReviewHandler),
        (r"/api/admin/break-glass/(\d+)/revoke", AdminBreakGlassRevokeHandler),

        # Operations (L5-5, L6-3)
        (r"/healthz", HealthzHandler),
        (r"/readyz", ReadyzHandler),
        (r"/api/metrics", MetricsHandler),

        # Static files
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": STATIC_PATH}),

        # SPA fallback
        (r"/(.*)", MainHandler),
    ], debug=TORNADO_DEBUG)

    # 시작 이벤트 감사 로그
    try:
        db = get_db()
        audit_log(
            db,
            AuditEvent.SESSION_STARTED,
            details={"kind": "server_start"},
            severity=1,
            layer="operation",
        )
        db.close()
    except Exception:
        pass

    return app


def _banner():
    print("=" * 60)
    print("  제로트러스트 접근제어 시스템 서버 시작 - 운영 모드")
    print(f"  http://localhost:{SERVER_PORT}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        app = make_app()
    except SecretValidationError:
        sys.exit(2)
    app.listen(SERVER_PORT)

    # SIGTERM / SIGINT — graceful_shutdown 콜백 등록
    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _graceful_shutdown)
        except (ValueError, OSError):
            # Windows 등에서 일부 시그널이 등록 불가할 때 — 무시
            pass

    _banner()
    tornado.ioloop.IOLoop.current().start()
