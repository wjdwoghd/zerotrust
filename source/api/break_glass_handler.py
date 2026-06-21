"""
Break-Glass REST API (Phase 2 / 진짜 긴급 자가발동)

엔드포인트:
  POST /api/break-glass/activate            — 발동 (MFA 재확인 필수)
  GET  /api/break-glass/my-active           — 내 활성 BG 조회
  POST /api/break-glass/<id>/release        — 본인 자발 해제
  GET  /api/admin/break-glass/pending       — (관리자) 리뷰 대기열
  GET  /api/admin/break-glass/history       — (관리자) 전체 이력
  POST /api/admin/break-glass/<id>/review   — (관리자) 사후 리뷰
  POST /api/admin/break-glass/<id>/revoke   — (관리자) 즉시 강제 종료
"""
from __future__ import annotations

from api.base_handler import BaseHandler
from database import get_db
from core import break_glass as bg
from core.break_glass import BreakGlassError
from core.audit_events import AuditEvent, audit_log
from security.mfa_service import verify_totp, verify_totp_consume


# =====================================================================
# 사용자 엔드포인트
# =====================================================================
class BreakGlassActivateHandler(BaseHandler):
    """POST /api/break-glass/activate

    Body: {
      justification: str,       # 최소 10자
      scope: 'resource'|'broad',
      resource_id: int,          # scope='resource' 일 때 필수
      min_grade: int,            # scope='broad' 일 때 선택(기본 4)
      mfa_code: str,             # TOTP 6자리 — 토큰 기기 시크릿으로 재확인
    }
    """
    def post(self):
        user = self.require_auth()
        if not user:
            return

        body = self.get_json_body()
        justification = (body.get("justification") or "").strip()
        scope = (body.get("scope") or "resource").strip()
        resource_id = body.get("resource_id")
        min_grade = body.get("min_grade")
        mfa_code = (body.get("mfa_code") or body.get("otp_code") or "").strip()

        db = get_db()
        try:
            # ── MFA 재확인 (replay 방지 — RFC 6238 §5.2) ─────────
            tdev = bg.get_token_device_for_otp(db, user["user_id"])
            if not tdev:
                audit_log(
                    db=db,
                    event=AuditEvent.BREAK_GLASS_ACTIVATION_REFUSED,
                    user_id=user["user_id"],
                    request_id=getattr(self, "request_id", None),
                    details={"reason": "no_token_device"},
                    severity=4,
                    layer="audit",
                )
                return self.write_error_json(
                    "토큰 기기를 보유한 사용자만 Break-Glass 를 사용할 수 있습니다.",
                    403, code="not_eligible"
                )

            ok, used_step = verify_totp_consume(
                tdev["mfa_secret"], mfa_code,
                last_used_step=tdev.get("last_otp_step"),
            )
            if not ok:
                audit_log(
                    db=db,
                    event=AuditEvent.BREAK_GLASS_ACTIVATION_REFUSED,
                    user_id=user["user_id"],
                    request_id=getattr(self, "request_id", None),
                    details={
                        "reason": (
                            "mfa_replay_or_invalid"
                            if tdev.get("last_otp_step") is not None
                            else "mfa_invalid"
                        ),
                    },
                    severity=4,
                    layer="audit",
                )
                return self.write_error_json(
                    "MFA 재확인에 실패했습니다. 토큰 기기의 6자리 코드를 확인하세요.",
                    401, code="mfa_invalid"
                )

            # 통과한 step 마킹 — 같은/이전 step 의 코드 재사용 차단
            db.execute(
                "UPDATE user_devices SET last_otp_step=? WHERE id=?",
                (used_step, tdev["id"])
            )
            db.commit()

            # ── 발동 ─────────────────────────────────────────────
            try:
                record = bg.activate(
                    db=db,
                    activator_id=user["user_id"],
                    justification=justification,
                    scope=scope,
                    resource_id=int(resource_id) if resource_id else None,
                    min_grade=int(min_grade) if min_grade else None,
                    session_id=user.get("session_id"),
                    ip=self.get_ip_address(),
                    user_agent=self.request.headers.get("User-Agent", ""),
                    request_id=getattr(self, "request_id", None),
                )
            except BreakGlassError as e:
                status = 409 if e.code == "already_active" else 400
                if e.code in ("not_eligible",):
                    status = 403
                return self.write_error_json(e.message, status, code=e.code)

            self.write_json({
                "message": "Break-Glass 발동 완료",
                "activation": record,
            })
        finally:
            db.close()


class BreakGlassMyActiveHandler(BaseHandler):
    """GET /api/break-glass/my-active — 내 활성 BG 목록."""
    def get(self):
        user = self.require_auth()
        if not user:
            return

        db = get_db()
        try:
            active = bg.get_active_for_user(db, user["user_id"])
            self.write_json({"activations": active, "total": len(active)})
        finally:
            db.close()


class BreakGlassReleaseHandler(BaseHandler):
    """POST /api/break-glass/<id>/release — 본인 자발 해제."""
    def post(self, activation_id):
        user = self.require_auth()
        if not user:
            return

        db = get_db()
        try:
            try:
                bg.release(
                    db=db,
                    activation_id=int(activation_id),
                    user_id=user["user_id"],
                    request_id=getattr(self, "request_id", None),
                )
            except BreakGlassError as e:
                status_map = {
                    "not_found":   404,
                    "not_owner":   403,
                    "not_active":  409,
                }
                return self.write_error_json(
                    e.message,
                    status_map.get(e.code, 400),
                    code=e.code,
                )
            self.write_json({
                "message": "Break-Glass 해제 완료",
                "activation_id": int(activation_id),
            })
        finally:
            db.close()


# =====================================================================
# 관리자 엔드포인트
# =====================================================================
class AdminBreakGlassPendingHandler(BaseHandler):
    """GET /api/admin/break-glass/pending — 리뷰 대기열."""
    def get(self):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        try:
            items = bg.list_pending_review(db)
            self.write_json({"activations": items, "total": len(items)})
        finally:
            db.close()


class AdminBreakGlassHistoryHandler(BaseHandler):
    """GET /api/admin/break-glass/history — 전체 이력."""
    def get(self):
        admin = self.require_admin()
        if not admin:
            return

        limit = int(self.get_argument("limit", "100"))
        db = get_db()
        try:
            items = bg.list_history(db, limit=limit)
            self.write_json({"activations": items, "total": len(items)})
        finally:
            db.close()


class AdminBreakGlassReviewHandler(BaseHandler):
    """POST /api/admin/break-glass/<id>/review

    Body: {
      verdict: 'justified' | 'unjustified' | 'partial',
      notes: str,
    }
    """
    def post(self, activation_id):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body()
        verdict = (body.get("verdict") or "").strip()
        notes = (body.get("notes") or "").strip()

        db = get_db()
        try:
            try:
                result = bg.review(
                    db=db,
                    activation_id=int(activation_id),
                    reviewer_id=admin["user_id"],
                    verdict=verdict,
                    notes=notes,
                    request_id=getattr(self, "request_id", None),
                )
            except BreakGlassError as e:
                status_map = {
                    "not_found":              404,
                    "still_active":           409,
                    "already_reviewed":       409,
                    "invalid_verdict":        400,
                    "self_review_forbidden":  403,
                }
                return self.write_error_json(
                    e.message,
                    status_map.get(e.code, 400),
                    code=e.code,
                )
            self.write_json({"message": "리뷰 완료", **result})
        finally:
            db.close()


class AdminBreakGlassRevokeHandler(BaseHandler):
    """POST /api/admin/break-glass/<id>/revoke — 즉시 강제 종료."""
    def post(self, activation_id):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body()
        reason = (body.get("reason") or "").strip()

        db = get_db()
        try:
            try:
                bg.revoke(
                    db=db,
                    activation_id=int(activation_id),
                    revoker_id=admin["user_id"],
                    reason=reason,
                    request_id=getattr(self, "request_id", None),
                )
            except BreakGlassError as e:
                status_map = {
                    "not_found":              404,
                    "not_active":             409,
                    "self_revoke_forbidden":  403,
                }
                return self.write_error_json(
                    e.message,
                    status_map.get(e.code, 400),
                    code=e.code,
                )
            self.write_json({
                "message": "Break-Glass 강제 종료 완료",
                "activation_id": int(activation_id),
            })
        finally:
            db.close()
