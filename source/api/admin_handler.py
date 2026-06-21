"""관리자 API 핸들러"""
import datetime
import json
import re
import time
from api.base_handler import BaseHandler
from database import get_db, row_to_dict, rows_to_list
from config import ADMIN_APPROVAL_TTL_SEC
from core.audit_events import AuditEvent, audit_log
from core.case_assignment_rules import assignment_compatibility
from security.password_handler import hash_password
from security.mfa_service import generate_secret


# ─── 이중감독 위반(자기-승인/자기-리뷰) 차단 공통 헬퍼 ───────────────
# 호출 측에서 검사된 결과를 감사 로그로 남기는 책임만 진다.
# 실제 비교는 각 핸들러가 수행 (각자 requester_id/target_user_id 필드가 다르므로).
def _log_self_action_blocked(db, admin_id: int, action: str,
                              target_id: int, request_id=None,
                              extra: dict = None) -> None:
    details = {
        "action": action,
        "target_id": int(target_id),
        "actor_id": int(admin_id),
    }
    if extra:
        details.update(extra)
    audit_log(
        db=db,
        event=AuditEvent.SELF_ACTION_BLOCKED,
        user_id=admin_id,
        request_id=request_id,
        details=details,
        severity=4,
        layer="audit",
    )
    db.commit()


class PendingApprovalsHandler(BaseHandler):
    """GET /api/admin/approvals/pending"""
    def get(self):
        user = self.require_admin()
        if not user:
            return

        db = get_db()
        rows = db.execute("""
            SELECT a.*, u.name as requester_name, u.department as requester_dept,
                   r.title as resource_title, r.sensitivity_grade, r.case_number
            FROM approvals a
            JOIN users u ON a.requester_id = u.id
            JOIN resources r ON a.resource_id = r.id
            WHERE a.status = 'pending'
            ORDER BY a.requested_at DESC
        """).fetchall()
        db.close()

        approvals = rows_to_list(rows)
        self.write_json({"approvals": approvals, "total": len(approvals)})


class ApproveHandler(BaseHandler):
    """POST /api/admin/approvals/<id>/approve

    Body(Option Y):
      { "download_allowed": bool }   # 생략 시 false — 열람 전용으로 승인
    """
    def post(self, approval_id):
        user = self.require_admin()
        if not user:
            return

        body = self.get_json_body() or {}
        # bool 캐스팅: 문자열 "true"/"false" 도 허용
        raw = body.get("download_allowed", False)
        if isinstance(raw, str):
            download_allowed = raw.strip().lower() in ("true", "1", "yes", "y")
        else:
            download_allowed = bool(raw)

        db = get_db()
        approval = db.execute("SELECT * FROM approvals WHERE id=?",
                              (int(approval_id),)).fetchone()
        if not approval:
            db.close()
            return self.write_error_json("승인 요청을 찾을 수 없습니다", 404)

        if approval["status"] != "pending":
            db.close()
            return self.write_error_json("이미 처리된 요청입니다")

        # 이중감독 위반 차단: 요청자가 본인인 경우 승인 불가.
        if int(approval["requester_id"]) == int(user["user_id"]):
            _log_self_action_blocked(
                db,
                admin_id=user["user_id"],
                action="approval_grant",
                target_id=int(approval_id),
                request_id=getattr(self, "request_id", None),
                extra={"resource_id": approval.get("resource_id")
                                      if isinstance(approval, dict)
                                      else approval["resource_id"]},
            )
            db.close()
            return self.write_error_json(
                "본인이 신청한 승인 요청은 본인이 승인할 수 없습니다.",
                403, code="self_approval_forbidden"
            )

        # ITEM 4 (감사 #4): 조건부 UPDATE — status='pending' 일 때만 처리.
        # 두 admin 동시 호출 race 에서 한쪽만 통과시키고, 다른 쪽은 0 행
        # 영향 → RETURNING None → 409 already_resolved 응답.
        # 위 SELECT+자기-승인 검사는 race 가 아닌 명백한 사후 호출용으로 유지.
        result = db.execute("""
            UPDATE approvals
               SET status='approved', approver_id=?,
                   download_allowed=?, resolved_at=CURRENT_TIMESTAMP
             WHERE id=? AND status='pending'
            RETURNING id, requester_id, resource_id
        """, (user["user_id"], download_allowed, int(approval_id))).fetchone()

        if not result:
            db.rollback()
            db.close()
            return self.write_error_json(
                "이미 처리된 요청입니다",
                409, code="already_resolved",
            )

        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
            ("audit", "APPROVAL_GRANTED",
             json.dumps({"approval_id": int(approval_id),
                         "requester_id": result["requester_id"],
                         "resource_id": result["resource_id"],
                         "download_allowed": download_allowed}, ensure_ascii=False),
             user["user_id"])
        )
        db.commit()
        db.close()

        self.write_json({
            "message": "승인 완료",
            "approval_id": int(approval_id),
            "download_allowed": download_allowed,
        })


class RejectHandler(BaseHandler):
    """POST /api/admin/approvals/<id>/reject"""
    def post(self, approval_id):
        user = self.require_admin()
        if not user:
            return

        body = self.get_json_body()
        reason = body.get("reason", "")

        db = get_db()
        approval = db.execute("SELECT * FROM approvals WHERE id=?",
                              (int(approval_id),)).fetchone()
        if not approval:
            db.close()
            return self.write_error_json("승인 요청을 찾을 수 없습니다", 404)

        if approval["status"] != "pending":
            db.close()
            return self.write_error_json("이미 처리된 요청입니다")

        # 이중감독 위반 차단: 본인이 신청한 요청은 본인이 반려도 불가.
        # (본인이 요청을 "스스로 철회" 하려면 별도 경로 — 현재는 존재하지 않으므로
        #  403 로 명시적으로 막고 기록한다.)
        if int(approval["requester_id"]) == int(user["user_id"]):
            _log_self_action_blocked(
                db,
                admin_id=user["user_id"],
                action="approval_reject",
                target_id=int(approval_id),
                request_id=getattr(self, "request_id", None),
                extra={"resource_id": approval.get("resource_id")
                                      if isinstance(approval, dict)
                                      else approval["resource_id"]},
            )
            db.close()
            return self.write_error_json(
                "본인이 신청한 승인 요청은 본인이 반려할 수 없습니다.",
                403, code="self_approval_forbidden"
            )

        # ITEM 4: 조건부 UPDATE + RETURNING — race 시 한쪽만 통과.
        result = db.execute("""
            UPDATE approvals
               SET status='rejected', approver_id=?,
                   resolved_at=CURRENT_TIMESTAMP
             WHERE id=? AND status='pending'
            RETURNING id, requester_id, resource_id
        """, (user["user_id"], int(approval_id))).fetchone()

        if not result:
            db.rollback()
            db.close()
            return self.write_error_json(
                "이미 처리된 요청입니다",
                409, code="already_resolved",
            )

        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
            ("audit", "APPROVAL_REJECTED",
             json.dumps({"approval_id": int(approval_id), "reason": reason}, ensure_ascii=False),
             user["user_id"])
        )
        db.commit()
        db.close()

        self.write_json({"message": "반려 완료", "approval_id": int(approval_id)})


class UserListHandler(BaseHandler):
    """GET /api/admin/users"""
    def get(self):
        user = self.require_admin()
        if not user:
            return

        db = get_db()
        rows = db.execute(
            "SELECT id, username, name, department, rank, role, "
            "       trust_score, violation_count, is_active, is_locked, "
            "       failed_login_count, allowed_locations, created_at "
            "FROM users ORDER BY id"
        ).fetchall()
        db.close()

        users = rows_to_list(rows)
        self.write_json({"users": users, "total": len(users)})


class UnlockUserHandler(BaseHandler):
    """POST /api/admin/users/<id>/unlock"""
    def post(self, user_id):
        admin = self.require_admin()
        if not admin:
            return

        # ITEM 13: 자기-unlock 차단. 본인이 자기 계정을 푸는 흐름은 admin
        # 등급이라도 이중감독 위반. self-approval / self-review 차단과 동일
        # 패턴으로 SELF_ACTION_BLOCKED 감사 + 403.
        target_id = int(user_id)
        if target_id == int(admin["user_id"]):
            db = get_db()
            try:
                _log_self_action_blocked(
                    db,
                    admin_id=admin["user_id"],
                    action="user_unlock",
                    target_id=target_id,
                    request_id=getattr(self, "request_id", None),
                )
            finally:
                db.close()
            return self.write_error_json(
                "본인의 계정 잠금은 본인이 해제할 수 없습니다.",
                403, code="self_action_blocked"
            )

        db = get_db()
        db.execute("UPDATE users SET is_locked=FALSE, failed_login_count=0 WHERE id=?",
                   (target_id,))
        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
            ("audit", "USER_UNLOCKED",
             json.dumps({"unlocked_user_id": target_id}, ensure_ascii=False),
             admin["user_id"])
        )
        db.commit()
        db.close()

        self.write_json({"message": "계정 잠금 해제 완료"})


# =====================================================================
# 계정 활성 / 비활성 (#19)
#   - is_active=FALSE  → require_auth 에서 403 account_locked.
#   - is_active=FALSE 시 해당 유저의 모든 활성 세션도 비활성화해서 즉시 축출.
#   - 안전장치:
#       (a) 자기 자신 비활성화 금지 — 본인이 시스템에서 잠기는 사고 방지.
#       (b) 마지막 남은 활성 admin 비활성화 금지 — 관리 불가 상태 방지.
#   - 감사 이벤트: ACCOUNT_DEACTIVATED / ACCOUNT_ACTIVATED.
# =====================================================================
class DeactivateUserHandler(BaseHandler):
    """POST /api/admin/users/<id>/deactivate"""
    def post(self, user_id):
        admin = self.require_admin()
        if not admin:
            return

        target_id = int(user_id)

        # (a) 자기 자신 비활성화 금지
        if target_id == admin["user_id"]:
            return self.write_error_json(
                "본인 계정은 비활성화할 수 없습니다.",
                400, code="self_deactivation_forbidden"
            )

        db = get_db()
        try:
            target = db.execute(
                "SELECT id, username, role, is_active FROM users WHERE id=?",
                (target_id,)
            ).fetchone()
            if not target:
                return self.write_error_json("대상 계정을 찾을 수 없습니다.",
                                             404, code="user_not_found")
            if not target["is_active"]:
                # 이미 비활성 — idempotent 응답.
                return self.write_json({
                    "message": "이미 비활성 상태입니다.",
                    "user_id": target_id,
                    "is_active": False,
                })

            # (b) 마지막 활성 admin 보호
            # deputy_admin 은 admin 풀에 포함해 계산 — 순환 해소용 보조 관리자이므로
            # 이들도 '관리자 역할 수행자' 로 간주한다. admin·deputy_admin 합산이
            # 1명 이하로 떨어지면 계정 생명주기 조작이 불가능해지므로 보호한다.
            if target["role"] in ("admin", "superadmin", "deputy_admin"):
                active_admin_count_row = db.execute(
                    "SELECT COUNT(*) AS c FROM users "
                    "WHERE role IN ('admin','superadmin','deputy_admin') "
                    "  AND is_active=TRUE AND is_locked=FALSE"
                ).fetchone()
                active_admin_count = int(active_admin_count_row["c"] or 0)
                if active_admin_count <= 1:
                    return self.write_error_json(
                        "마지막으로 남은 활성 관리자 계정은 비활성화할 수 없습니다.",
                        400, code="last_active_admin"
                    )

            # 비활성화 + 진행 중 세션 축출
            db.execute("UPDATE users SET is_active=FALSE WHERE id=?", (target_id,))
            db.execute("UPDATE sessions SET is_active=FALSE "
                       "WHERE user_id=? AND is_active=TRUE",
                       (target_id,))

            # 감사 로그 (layer=audit, severity=4 — 계정 생명주기 변경은 중요)
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, severity, details, user_id) "
                "VALUES (?,?,?,?,?)",
                ("audit", "ACCOUNT_DEACTIVATED", 4,
                 json.dumps({
                     "target_user_id": target_id,
                     "target_username": target["username"],
                     "admin_id": admin["user_id"],
                 }, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
        finally:
            db.close()

        self.write_json({
            "message": "계정을 비활성화했습니다.",
            "user_id": target_id,
            "is_active": False,
        })


class ActivateUserHandler(BaseHandler):
    """POST /api/admin/users/<id>/activate"""
    def post(self, user_id):
        admin = self.require_admin()
        if not admin:
            return

        target_id = int(user_id)

        db = get_db()
        try:
            target = db.execute(
                "SELECT id, username, is_active FROM users WHERE id=?",
                (target_id,)
            ).fetchone()
            if not target:
                return self.write_error_json("대상 계정을 찾을 수 없습니다.",
                                             404, code="user_not_found")
            if target["is_active"]:
                return self.write_json({
                    "message": "이미 활성 상태입니다.",
                    "user_id": target_id,
                    "is_active": True,
                })

            db.execute("UPDATE users SET is_active=TRUE WHERE id=?", (target_id,))
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, severity, details, user_id) "
                "VALUES (?,?,?,?,?)",
                ("audit", "ACCOUNT_ACTIVATED", 3,
                 json.dumps({
                     "target_user_id": target_id,
                     "target_username": target["username"],
                     "admin_id": admin["user_id"],
                 }, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
        finally:
            db.close()

        self.write_json({
            "message": "계정을 활성화했습니다.",
            "user_id": target_id,
            "is_active": True,
        })


# =====================================================================
# §20 (개정) — 계정 하드 삭제 (DELETE /api/admin/users/<id>)
# 결정 메모:
#   사용자 요청에 따라 soft delete(is_active=FALSE)에서 hard DELETE 로
#   전환한다. FK 관계로 인해 단순 DELETE FROM users 만 호출하면 PG 가
#   외래키 위반을 던지므로, 종속 테이블을 지정 순서로 선삭제한다.
#
#   삭제 대상 (운영·행위 데이터):
#     - sessions, otp_requests, login_approval_requests, user_devices
#     - access_logs, approvals(requester_id), policy_override_requests
#     - break_glass_activations(activator_id) — RESTRICT FK 라 강제 삭제
#       함께 reviewer_id/session_id 는 FK 가 SET NULL 이므로 자동 처리됨
#
#   보존 대상 (감사 추적성):
#     - audit_logs, sensitive_logs, operation_logs (FK 없음 — user_id 가
#       NULL 아닌 값으로 남지만 사용자명은 details JSON 에 보존되어 있어
#       사후 추적 가능)
#
#   보호 장치는 deactivate 와 동일:
#     (a) 본인 계정 삭제 금지
#     (b) 마지막 활성 admin/deputy_admin 삭제 금지
# =====================================================================
class DeleteUserHandler(BaseHandler):
    """DELETE /api/admin/users/<id>"""
    def delete(self, user_id):
        admin = self.require_admin()
        if not admin:
            return

        target_id = int(user_id)

        # (a) 자기 자신 삭제 금지
        if target_id == admin["user_id"]:
            return self.write_error_json(
                "본인 계정은 삭제할 수 없습니다.",
                400, code="self_deletion_forbidden"
            )

        db = get_db()
        try:
            target = db.execute(
                "SELECT id, username, role FROM users WHERE id=?",
                (target_id,)
            ).fetchone()
            if not target:
                return self.write_error_json("대상 계정을 찾을 수 없습니다.",
                                             404, code="user_not_found")

            # (b) 마지막 활성 admin/deputy_admin 보호 (deactivate 와 동일 정책)
            if target["role"] in ("admin", "superadmin", "deputy_admin"):
                active_admin_count_row = db.execute(
                    "SELECT COUNT(*) AS c FROM users "
                    "WHERE role IN ('admin','superadmin','deputy_admin') "
                    "  AND is_active=TRUE AND is_locked=FALSE"
                ).fetchone()
                if int(active_admin_count_row["c"] or 0) <= 1:
                    return self.write_error_json(
                        "마지막으로 남은 활성 관리자 계정은 삭제할 수 없습니다.",
                        400, code="last_active_admin"
                    )

            # 감사 로그 — DELETE 직전에 기록 (target 정보가 아직 살아있을 때)
            #   audit_logs 는 FK 가 없으므로 user_id=admin 으로 남기고,
            #   target 정보는 details JSON 에 보존한다.
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, severity, details, user_id) "
                "VALUES (?,?,?,?,?)",
                ("audit", "ACCOUNT_DELETED", 4,
                 json.dumps({
                     "target_user_id": target_id,
                     "target_username": target["username"],
                     "target_role": target["role"],
                     "admin_id": admin["user_id"],
                     "delete_kind": "hard",
                 }, ensure_ascii=False),
                 admin["user_id"])
            )

            # ── 종속 테이블 선삭제 (PG FK 위반 방지) ──
            # 순서 주의: 자식 → 부모. CASCADE 가 걸린 테이블도 명시 삭제한다.
            db.execute("DELETE FROM otp_requests WHERE user_id=?", (target_id,))
            db.execute("DELETE FROM login_approval_requests WHERE user_id=?",
                       (target_id,))
            db.execute("DELETE FROM user_devices WHERE user_id=?", (target_id,))
            db.execute("DELETE FROM sessions WHERE user_id=?", (target_id,))
            db.execute("DELETE FROM access_logs WHERE user_id=?", (target_id,))
            db.execute("DELETE FROM approvals WHERE requester_id=?",
                       (target_id,))
            db.execute("DELETE FROM policy_override_requests WHERE user_id=?",
                       (target_id,))
            # break_glass_activations: activator_id ON DELETE RESTRICT
            #   → 강제 삭제. reviewer_id/session_id 는 FK SET NULL.
            db.execute("DELETE FROM break_glass_activations WHERE activator_id=?",
                       (target_id,))

            # 마지막으로 users 행 삭제
            db.execute("DELETE FROM users WHERE id=?", (target_id,))
            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            return self.write_error_json(
                f"계정 삭제 실패: {type(e).__name__}: {e}",
                500, code="delete_failed")
        finally:
            db.close()

        # 토큰 기기가 사라졌으니 런처도 정리 (best-effort).
        try:
            from scripts.regenerate_launchers import regenerate as _regen
            _regen()
        except Exception:
            pass

        self.write_json({
            "message": "계정을 완전히 삭제했습니다.",
            "user_id": target_id,
            "deleted": True,
        })


# ─── 신규 사용자 계정 프로비저닝 (§20) ───────────────────────────
# 설계 메모:
#   - role 은 'user' 로 강제 고정. admin 생성은 bootstrap_admin.py 경로 유지
#     → UI 를 통한 권한 상승 표면 제거.
#   - mfa_secret 은 서버 내부에서 generate_secret() 로 자동 생성, 응답에
#     노출하지 않는다. 첫 로그인 시 사용자가 별도 기기 등록(TOTP) 플로우로
#     자신의 authenticator 에 엔롤하게 된다(device_handler 의 기기 등록
#     경로가 mfa_secret 을 재발급하므로 여기서 심은 값은 사실상 placeholder).
#   - registered_devices 는 빈 배열. Zero-Trust 기기 화이트리스트 검증을
#     통과하려면 첫 로그인 전에 기기 등록 API 로 채워야 한다.
#   - allowed_locations 은 최소 1개 필수. 위치 없으면 로그인 위치 검증 실패.

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]{2,31}$")


class CreateUserHandler(BaseHandler):
    """POST /api/admin/users

    Body:
      {
        "username":          "3~32자, 영문/숫자/._- 로 시작",
        "password":          "평문 11자 이상",
        "name":              "표시 이름",
        "department":        "소속 부서",
        "rank":              "계급",
        "allowed_locations": ["본청", ...],   # 최소 1개
        "job_scope":         ["traffic", ...]  # optional, default []
      }
    """
    def post(self):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body() or {}
        username  = (body.get("username") or "").strip()
        password  = body.get("password") or ""
        name      = (body.get("name") or "").strip()
        department= (body.get("department") or "").strip()
        rank      = (body.get("rank") or "").strip()
        locations = body.get("allowed_locations") or []
        job_scope = body.get("job_scope") or []

        # ── 입력 검증 (DB 열기 전) ──
        if not _USERNAME_RE.match(username):
            return self.write_error_json(
                "사용자명은 3-32자, 영문/숫자/._- 만 허용합니다.",
                400, code="invalid_username")
        if len(password) < 11:
            return self.write_error_json(
                "비밀번호는 최소 11자 이상이어야 합니다.",
                400, code="password_too_short")
        if not name:
            return self.write_error_json(
                "이름은 필수입니다.", 400, code="missing_name")
        if not department:
            return self.write_error_json(
                "소속 부서는 필수입니다.", 400, code="missing_department")
        if not rank:
            return self.write_error_json(
                "계급은 필수입니다.", 400, code="missing_rank")
        if not isinstance(locations, list):
            return self.write_error_json(
                "allowed_locations 는 배열이어야 합니다.",
                400, code="invalid_allowed_locations")
        locations = [str(x).strip() for x in locations if str(x).strip()]
        if not locations:
            return self.write_error_json(
                "허용 근무지를 최소 1개 입력해야 합니다.",
                400, code="missing_allowed_locations")
        if not isinstance(job_scope, list):
            return self.write_error_json(
                "job_scope 는 배열이어야 합니다.",
                400, code="invalid_job_scope")
        job_scope = [str(x).strip() for x in job_scope if str(x).strip()]

        db = get_db()
        try:
            dup = db.execute(
                "SELECT id FROM users WHERE username=?",
                (username,)
            ).fetchone()
            if dup:
                return self.write_error_json(
                    "이미 사용 중인 사용자명입니다.",
                    409, code="username_taken")

            pw_hash    = hash_password(password)
            mfa_secret = generate_secret()

            # ── 신규 계정 프로비저닝 패턴 ───────────────────────
            # 버그 수정 전: users 행만 INSERT 하고 user_devices 는 비움 →
            #   로그인 시 "등록되지 않은 업무 기기" 로 즉시 차단되어
            #   프런트에는 '로그인 실패' 만 노출되는 상황.
            # 수정 후:
            #   1) work 기기 1개를 `registered-new-{id}` 패턴으로 자동 발급해
            #      user_devices 에 넣고 users.registered_devices JSON 도 동기화.
            #   2) 토큰 기기는 발급하지 않는다. OTP 토큰 등록 전까지는
            #      LoginHandler 가 "토큰 기기 미등록" 사유로 관리자 로그인
            #      승인 게이트(login_approval_requests)를 건다.
            #   3) 담당 사건은 빈 배열로 시작한다. 부서가 같더라도 자동
            #      상속하지 않고, 담당 사건 등록 요청/승인 규칙을 통과해야 한다.
            #   4) trust_score 는 정상 기준값으로 시작한다. OTP 등록 후에는
            #      "신규 계정이라서" 관리자 승인이 계속 요구되지 않아야 한다.
            #   5) 응답에 device_id 를 포함해 관리자가 신규 사용자에게
            #      전달할 수 있도록 한다.
            initial_trust_score = 70.0
            row = db.execute(
                """
                INSERT INTO users
                    (username, password_hash, name, department, rank, role,
                     registered_devices, allowed_locations, assigned_cases,
                     job_scope, mfa_secret, trust_score, violation_count,
                     is_active, is_locked, failed_login_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,TRUE,FALSE,0)
                RETURNING id
                """,
                (username, pw_hash, name, department, rank, "user",
                 json.dumps([]),  # registered_devices 는 아래에서 UPDATE
                 json.dumps(locations, ensure_ascii=False),
                 json.dumps([]),
                 json.dumps(job_scope, ensure_ascii=False),
                 mfa_secret, initial_trust_score, 0)
            ).fetchone()
            new_id = row["id"] if isinstance(row, dict) else row[0]

            # work 기기 자동 발급 — patrol_jung 등 기존 시드와 같은 device_type='work'
            work_device_id = f"registered-new-{int(new_id):03d}"
            db.execute(
                "INSERT INTO user_devices "
                "(user_id, device_id, device_name, device_type, "
                " mfa_secret, api_key, is_active) "
                "VALUES (?,?,?,?,?,?,?)",
                (int(new_id), work_device_id, f"{username} 업무 PC",
                 "work", None, None, True)
            )
            # users.registered_devices JSON 동기화 (감사 목적으로만 사용)
            db.execute(
                "UPDATE users SET registered_devices=? WHERE id=?",
                (json.dumps([work_device_id], ensure_ascii=False), int(new_id))
            )

            # 감사 로그 — severity=3 (일반 관리행위)
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, severity, details, user_id) "
                "VALUES (?,?,?,?,?)",
                ("audit", "USER_CREATED", 3,
                 json.dumps({
                    "target_user_id": new_id,
                    "admin_id": admin["user_id"],
                    "username": username,
                    "role": "user",
                    "department": department,
                    "rank": rank,
                    "work_device_id": work_device_id,
                    "login_path": "admin_approval_gate",
                    "initial_trust_score": initial_trust_score,
                 }, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            return self.write_error_json(
                f"계정 생성 실패: {type(e).__name__}",
                500, code="create_failed")
        finally:
            db.close()

        # 응답은 목록 테이블에 바로 꽂아 쓸 수 있는 최소 필드만.
        # mfa_secret 은 반환하지 않는다 (§20 결정사항).
        # work_device_id 는 관리자가 신규 사용자에게 알려줘야 하므로 반환한다.
        self.write_json({
            "message": (
                f"계정을 생성했습니다. device_id={work_device_id} · 첫 로그인은 "
                f"OTP 토큰 등록 전까지 관리자 승인 게이트를 경유합니다."
            ),
            "user": {
                "id": new_id,
                "username": username,
                "name": name,
                "department": department,
                "rank": rank,
                "role": "user",
                "is_active": 1,
                "is_locked": 0,
                "trust_score": initial_trust_score,
                "violation_count": 0,
                "assigned_cases": [],
                "has_token_device": False,
            },
            "work_device_id": work_device_id,
            "login_path": "admin_approval_gate",
            "login_gate_reason": "token_device_missing",
        })


# =====================================================================
# 관리자 로그인 승인 게이트 (의심 계정 + 토큰 기기 미보유 계정) — 006/008 연동
# 과거 명칭 "Break-Glass" 는 008 리네임으로 폐기.
# =====================================================================
class AdminApprovalPendingHandler(BaseHandler):
    """GET /api/admin/login-approvals/pending

    의심 계정 판정으로 자동 생성된 로그인 승인 대기 요청 목록.
    """
    def get(self):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        rows = db.execute("""
            SELECT r.id, r.user_id, r.justification, r.status,
                   r.requested_at, r.resolved_at, r.expires_at,
                   u.username, u.name, u.department, u.rank,
                   u.trust_score, u.violation_count
            FROM login_approval_requests r
            JOIN users u ON r.user_id = u.id
            WHERE r.status = 'pending'
            ORDER BY r.requested_at ASC
        """).fetchall()
        db.close()

        items = rows_to_list(rows)
        self.write_json({"requests": items, "total": len(items)})


class AdminApprovalHistoryHandler(BaseHandler):
    """GET /api/admin/login-approvals/history

    최근 처리된(approved/rejected/used/expired) 요청 목록. 감사·대시보드용.
    """
    def get(self):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        rows = db.execute("""
            SELECT r.id, r.user_id, r.status, r.justification,
                   r.requested_at, r.resolved_at, r.expires_at,
                   r.approver_id, r.used_session_id,
                   u.username, u.name, u.department,
                   u.trust_score, u.violation_count,
                   ap.username AS approver_username
            FROM login_approval_requests r
            JOIN users u ON r.user_id = u.id
            LEFT JOIN users ap ON r.approver_id = ap.id
            WHERE r.status IN ('approved','rejected','used','expired')
            ORDER BY COALESCE(r.resolved_at, r.requested_at) DESC
            LIMIT 50
        """).fetchall()
        db.close()

        items = rows_to_list(rows)
        self.write_json({"requests": items, "total": len(items)})


class AdminApprovalApproveHandler(BaseHandler):
    """POST /api/admin/login-approvals/<id>/approve

    이중감독 규칙:
      - 요청자(target_user_id) == 승인자(admin) 인 경우를 '자기-승인' 으로 간주.
      - 활성 admin 이 2명 이상이면 **차단** (self_approval_forbidden, 403).
      - 활성 admin 이 1명뿐이면 **허용** 하되 감사 로그 details 에 self_approval=True
        로 명시한다(부트스트랩/운영 데드락 방지용 예외, 추적 가능성 유지).
    """
    def post(self, req_id):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        row = db.execute(
            "SELECT id, user_id, status FROM login_approval_requests WHERE id=?",
            (int(req_id),)
        ).fetchone()
        if not row:
            db.close()
            return self.write_error_json("요청을 찾을 수 없습니다", 404)
        if row["status"] != "pending":
            db.close()
            return self.write_error_json("이미 처리된 요청입니다", 409,
                                          code="already_resolved")

        # 자기-승인 여부 판정
        # deputy_admin 을 포함해 "활성 관리자" 수를 센다. 이렇게 하면 admin_lee
        # 혼자 있는 상태에서도 부관리자가 한 명이라도 있으면 self-approval 가
        # 금지되고, admin_lee 의 자기-승인 요청은 부관리자에게 넘어간다
        # (= 관리자 순환 해소).
        is_self_approval = int(row["user_id"]) == int(admin["user_id"])
        active_admin_count = None
        if is_self_approval:
            active_admin_count = int((db.execute(
                "SELECT COUNT(*) AS c FROM users "
                "WHERE role IN ('admin','superadmin','deputy_admin') "
                "  AND is_active=TRUE AND is_locked=FALSE"
            ).fetchone() or {"c": 0})["c"])
            if active_admin_count >= 2:
                _log_self_action_blocked(
                    db,
                    admin_id=admin["user_id"],
                    action="login_approval_grant",
                    target_id=int(req_id),
                    request_id=getattr(self, "request_id", None),
                    extra={"active_admin_count": active_admin_count},
                )
                db.close()
                return self.write_error_json(
                    "본인의 로그인 승인 요청은 본인이 승인할 수 없습니다. "
                    "타 관리자에게 요청하세요.",
                    403, code="self_approval_forbidden"
                )

        # ITEM 7 (감사 #7): tz-aware UTC datetime 을 직접 바인딩.
        # core/break_glass.py:191-206 패턴 이식 — naive strftime 문자열은
        # PG 세션 TZ 에 따라 9시간 어긋날 수 있다.
        expires_dt = datetime.datetime.now(datetime.timezone.utc) + \
                     datetime.timedelta(seconds=ADMIN_APPROVAL_TTL_SEC)
        expires_iso = expires_dt.isoformat()  # 응답/감사 로그용 직렬 표기

        db.execute(
            "UPDATE login_approval_requests "
            "SET status='approved', approver_id=?, "
            "    resolved_at=CURRENT_TIMESTAMP, expires_at=? "
            "WHERE id=?",
            (admin["user_id"], expires_dt, int(req_id))
        )
        _details = {
            "request_id": int(req_id),
            "target_user_id": row["user_id"],
            "ttl_seconds": ADMIN_APPROVAL_TTL_SEC,
            "expires_at": expires_iso,
        }
        if is_self_approval:
            # 1인 admin 예외가 발동한 경우 추적 가능성 확보.
            _details["self_approval"] = True
            _details["active_admin_count"] = active_admin_count
        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) "
            "VALUES (?,?,?,?)",
            ("audit", "ADMIN_APPROVAL_GRANTED",
             json.dumps(_details, ensure_ascii=False),
             admin["user_id"])
        )
        db.commit()
        db.close()

        self.write_json({
            "message": "관리자 로그인 승인 완료",
            "request_id": int(req_id),
            "expires_at": expires_iso,
            "ttl_seconds": ADMIN_APPROVAL_TTL_SEC,
            "self_approval": bool(is_self_approval),
        })


class AdminApprovalRejectHandler(BaseHandler):
    """POST /api/admin/login-approvals/<id>/reject

    이중감독 규칙:
      - 요청자 == 승인자(admin) 인 경우를 '자기-반려' 로 간주.
      - 활성 admin 이 2명 이상이면 차단(self_approval_forbidden, 403).
      - 1명뿐이면 허용하되 감사 로그에 self_approval=True 로 명시.
    """
    def post(self, req_id):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body() or {}
        reason = (body.get("reason") or "").strip()

        db = get_db()
        row = db.execute(
            "SELECT id, user_id, status FROM login_approval_requests WHERE id=?",
            (int(req_id),)
        ).fetchone()
        if not row:
            db.close()
            return self.write_error_json("요청을 찾을 수 없습니다", 404)
        if row["status"] != "pending":
            db.close()
            return self.write_error_json("이미 처리된 요청입니다", 409,
                                          code="already_resolved")

        is_self_approval = int(row["user_id"]) == int(admin["user_id"])
        active_admin_count = None
        if is_self_approval:
            active_admin_count = int((db.execute(
                "SELECT COUNT(*) AS c FROM users "
                "WHERE role IN ('admin','superadmin','deputy_admin') "
                "  AND is_active=TRUE AND is_locked=FALSE"
            ).fetchone() or {"c": 0})["c"])
            if active_admin_count >= 2:
                _log_self_action_blocked(
                    db,
                    admin_id=admin["user_id"],
                    action="login_approval_reject",
                    target_id=int(req_id),
                    request_id=getattr(self, "request_id", None),
                    extra={"active_admin_count": active_admin_count},
                )
                db.close()
                return self.write_error_json(
                    "본인의 로그인 승인 요청은 본인이 반려할 수 없습니다. "
                    "타 관리자에게 요청하세요.",
                    403, code="self_approval_forbidden"
                )

        db.execute(
            "UPDATE login_approval_requests "
            "SET status='rejected', approver_id=?, "
            "    resolved_at=CURRENT_TIMESTAMP "
            "WHERE id=?",
            (admin["user_id"], int(req_id))
        )
        _details = {
            "request_id": int(req_id),
            "target_user_id": row["user_id"],
            "reason": reason,
        }
        if is_self_approval:
            _details["self_approval"] = True
            _details["active_admin_count"] = active_admin_count
        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) "
            "VALUES (?,?,?,?)",
            ("audit", "ADMIN_APPROVAL_REJECTED",
             json.dumps(_details, ensure_ascii=False),
             admin["user_id"])
        )
        db.commit()
        db.close()

        self.write_json({
            "message": "관리자 로그인 승인 반려 완료",
            "request_id": int(req_id),
            "self_approval": bool(is_self_approval),
        })


class AdminApprovalStatusHandler(BaseHandler):
    """GET /api/auth/login-approval/status?username=<username>

    인증 전 사용자가 자신의 관리자 승인 요청 진행 상태를 폴링하기 위한 엔드포인트.
    반환:
      - state: 'pending' | 'approved' | 'rejected' | 'used' | 'expired' | 'none'
      - expires_at: 승인 만료 시각(승인된 경우)
      - request_id: 요청 PK(있을 때)
    """
    def get(self):
        username = (self.get_argument("username", default="") or "").strip()
        if not username:
            return self.write_error_json("username 이 필요합니다", 400,
                                         code="username_required")

        db = get_db()
        u = db.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone()
        if not u:
            db.close()
            # 존재 여부를 외부로 노출하지 않기 위해 'none' 으로 응답.
            return self.write_json({"state": "none"})

        row = db.execute(
            "SELECT id, status, expires_at, resolved_at "
            "FROM login_approval_requests "
            "WHERE user_id=? "
            "ORDER BY id DESC LIMIT 1",
            (int(u["id"]),)
        ).fetchone()
        db.close()

        if not row:
            return self.write_json({"state": "none"})

        status = (row["status"] or "").lower()
        if status not in ("pending", "approved", "rejected", "used", "expired"):
            status = "none"
        self.write_json({
            "state": status,
            "request_id": int(row["id"]),
            "expires_at": row["expires_at"],
            "resolved_at": row["resolved_at"],
        })


# =====================================================================
# 허용 위치 갱신 (이중감독 권한 분리)
#
# 운영 시나리오:
#   본인 관할서(allowed_locations) 외 위치에서 정당하게 로그인해야 할 때
#   (출장·임시 지원 등), 관리자가 사전에 해당 사용자의 허용 위치 목록을
#   조정해 둔다. LoginHandler 의 allowed_locations 게이트와 짝을 이룬다.
#
# 권한 매트릭스 (이중감독 — admin↔deputy_admin 상호 견제):
#   대상 role        │ 수정 가능 주체
#   ─────────────────┼───────────────────────
#   user             │ admin / superadmin
#   deputy_admin     │ admin / superadmin
#   admin            │ deputy_admin
#   superadmin       │ deputy_admin
#
# 추가 안전장치:
#   - 자기 자신 수정 금지 (SELF_ACTION_BLOCKED audit + 403)
#   - allowed_locations 비어 있는 입력 금지 (로그인 자체 불가 방지)
# =====================================================================
class UpdateAllowedLocationsHandler(BaseHandler):
    """PUT /api/admin/users/<id>/allowed_locations

    Body: {"allowed_locations": ["본청", "강남서", ...]}  # 최소 1개

    응답:
      200 {"message", "user_id", "allowed_locations"}
      400 invalid_allowed_locations / missing_allowed_locations
      403 self_action_blocked / role_permission_denied
      404 user_not_found
    """
    def put(self, user_id):
        actor = self.require_admin()  # admin / superadmin / deputy_admin
        if not actor:
            return

        target_id = int(user_id)
        body = self.get_json_body() or {}
        locations = body.get("allowed_locations")

        # 입력 검증 (DB 열기 전)
        if not isinstance(locations, list):
            return self.write_error_json(
                "allowed_locations 는 배열이어야 합니다.",
                400, code="invalid_allowed_locations")
        locations = [str(x).strip() for x in locations if str(x).strip()]
        if not locations:
            return self.write_error_json(
                "허용 근무지를 최소 1개 입력해야 합니다.",
                400, code="missing_allowed_locations")

        # 자기 자신 수정 금지
        if target_id == int(actor["user_id"]):
            db = get_db()
            try:
                _log_self_action_blocked(
                    db,
                    admin_id=actor["user_id"],
                    action="allowed_locations_update",
                    target_id=target_id,
                    request_id=getattr(self, "request_id", None),
                )
            finally:
                db.close()
            return self.write_error_json(
                "본인의 허용 위치는 본인이 변경할 수 없습니다.",
                403, code="self_action_blocked"
            )

        db = get_db()
        try:
            target = db.execute(
                "SELECT id, username, role FROM users WHERE id=?",
                (target_id,)
            ).fetchone()
            if not target:
                return self.write_error_json(
                    "대상 계정을 찾을 수 없습니다.",
                    404, code="user_not_found")

            actor_role = actor.get("role")
            target_role = target["role"]
            ADMIN_LIKE  = ("admin", "superadmin")
            DEPUTY_LIKE = ("deputy_admin",)
            USER_LIKE   = ("user",)

            if target_role in USER_LIKE or target_role in DEPUTY_LIKE:
                permitted = actor_role in ADMIN_LIKE
            elif target_role in ADMIN_LIKE:
                permitted = actor_role in DEPUTY_LIKE
            else:
                permitted = False

            if not permitted:
                # 거절도 audit 으로 남김 (사후 추적)
                db.execute(
                    "INSERT INTO audit_logs "
                    "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                    ("audit", "ALLOWED_LOCATIONS_UPDATE_DENIED",
                     json.dumps({
                         "actor_role": actor_role,
                         "target_user_id": target_id,
                         "target_role": target_role,
                         "reason": "role_permission_denied",
                     }, ensure_ascii=False),
                     actor["user_id"])
                )
                db.commit()
                return self.write_error_json(
                    f"권한이 부족합니다 (actor={actor_role}, target={target_role}).",
                    403, code="role_permission_denied"
                )

            # 이전 값을 함께 기록해 변경 추적 가능
            before_row = db.execute(
                "SELECT allowed_locations FROM users WHERE id=?",
                (target_id,)
            ).fetchone()
            before = before_row["allowed_locations"] if before_row else None

            db.execute(
                "UPDATE users SET allowed_locations=? WHERE id=?",
                (json.dumps(locations, ensure_ascii=False), target_id)
            )
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("audit", "ALLOWED_LOCATIONS_UPDATED",
                 json.dumps({
                     "target_user_id": target_id,
                     "target_username": target["username"],
                     "target_role": target_role,
                     "actor_role": actor_role,
                     "before": before,
                     "after": locations,
                 }, ensure_ascii=False),
                 actor["user_id"])
            )
            db.commit()
        finally:
            db.close()

        self.write_json({
            "message": "허용 위치 갱신 완료",
            "user_id": target_id,
            "allowed_locations": locations,
        })



# =====================================================================
# 담당 사건 등록 요청 승인 플로우
#   - 사용자 요청 → 관리자 검토
#   - 관리자가 OTP 인증 요구 가능 → 요청자 OTP 인증
#   - 관리자/부관리자 최종 승인 시 users.assigned_cases 에 사건 ID 추가
#   - 관리자가 요청한 경우 reviewer_role='deputy_admin' 으로 배정되어 부관리자가 처리
# =====================================================================
class CaseAssignmentPendingHandler(BaseHandler):
    """GET /api/admin/case-assignment-requests/pending"""
    def get(self):
        admin = self.require_admin()
        if not admin:
            return

        role = admin.get("role")
        db = get_db()
        try:
            where = "r.status IN ('pending_admin','otp_required','otp_verified')"
            params = []
            # 일반 admin 은 일반 사용자 요청을, deputy_admin 은 관리자/부관리자 요청을 우선 처리.
            # superadmin 은 전체 조회.
            if role == "deputy_admin":
                where += " AND r.reviewer_role='deputy_admin'"
            elif role == "admin":
                where += " AND r.reviewer_role='admin'"
            rows = db.execute(
                "SELECT r.*, "
                "       u.username AS requester_username, u.name AS requester_name, u.department AS requester_dept, u.role AS requester_role, "
                "       res.case_number, res.title AS resource_title, res.sensitivity_grade, res.department AS resource_department "
                "FROM case_assignment_requests r "
                "JOIN users u ON r.requester_id=u.id "
                "JOIN resources res ON r.resource_id=res.id "
                f"WHERE {where} "
                "ORDER BY r.requested_at DESC",
                tuple(params)
            ).fetchall()
            self.write_json({"requests": rows, "total": len(rows)})
        finally:
            db.close()


class CaseAssignmentRequireOtpHandler(BaseHandler):
    """POST /api/admin/case-assignment-requests/<id>/require-otp"""
    def post(self, request_id):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        try:
            req = db.execute("SELECT * FROM case_assignment_requests WHERE id=?", (int(request_id),)).fetchone()
            if not req:
                return self.write_error_json("담당 사건 등록 요청을 찾을 수 없습니다.", 404, code="request_not_found")
            if int(req["requester_id"]) == int(admin["user_id"]):
                return self.write_error_json("본인이 요청한 담당 사건 등록은 본인이 처리할 수 없습니다.", 403, code="self_approval_forbidden")
            if req["status"] not in ("pending_admin", "otp_required"):
                return self.write_error_json("OTP 요구가 가능한 상태가 아닙니다.", 400, code="invalid_status")

            row = db.execute(
                "UPDATE case_assignment_requests "
                "SET status='otp_required', otp_required_by=?, otp_required_at=CURRENT_TIMESTAMP "
                "WHERE id=? RETURNING *",
                (admin["user_id"], int(request_id))
            ).fetchone()
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("audit", "CASE_ASSIGNMENT_OTP_REQUIRED",
                 json.dumps({"assignment_request_id": int(request_id)}, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
            self.write_json({"message": "요청자 OTP 인증을 요구했습니다.", "assignment_request": row})
        finally:
            db.close()


class CaseAssignmentApproveHandler(BaseHandler):
    """POST /api/admin/case-assignment-requests/<id>/approve"""
    def post(self, request_id):
        admin = self.require_admin()
        if not admin:
            return

        db = get_db()
        try:
            req = db.execute("SELECT * FROM case_assignment_requests WHERE id=?", (int(request_id),)).fetchone()
            if not req:
                return self.write_error_json("담당 사건 등록 요청을 찾을 수 없습니다.", 404, code="request_not_found")
            if int(req["requester_id"]) == int(admin["user_id"]):
                return self.write_error_json("본인이 요청한 담당 사건 등록은 본인이 승인할 수 없습니다.", 403, code="self_approval_forbidden")
            if req["status"] not in ("pending_admin", "otp_verified"):
                return self.write_error_json("승인 가능한 상태가 아닙니다. OTP 요구 중이면 요청자의 인증 완료 후 승인하세요.", 400, code="invalid_status")

            requester = db.execute(
                "SELECT id, department, assigned_cases, job_scope FROM users WHERE id=?",
                (req["requester_id"],)
            ).fetchone()
            resource = db.execute(
                "SELECT id, department, job_tags FROM resources WHERE id=?",
                (req["resource_id"],)
            ).fetchone()
            if not requester or not resource:
                return self.write_error_json("요청자 또는 사건을 찾을 수 없습니다.", 404, code="assignment_target_not_found")

            compatible, message = assignment_compatibility(requester, resource)
            if not compatible:
                return self.write_error_json(message, 403, code="assignment_scope_mismatch")

            assigned = requester.get("assigned_cases") or []
            if isinstance(assigned, str):
                try:
                    assigned = json.loads(assigned)
                except Exception:
                    assigned = []
            assigned = list(assigned or [])
            rid = int(req["resource_id"])
            if rid not in [int(v) for v in assigned if str(v).isdigit()]:
                assigned.append(rid)

            db.execute(
                "UPDATE users SET assigned_cases=? WHERE id=?",
                (json.dumps(assigned), req["requester_id"])
            )
            row = db.execute(
                "UPDATE case_assignment_requests "
                "SET status='approved', final_approved_by=?, final_approved_at=CURRENT_TIMESTAMP "
                "WHERE id=? RETURNING *",
                (admin["user_id"], int(request_id))
            ).fetchone()
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("audit", "CASE_ASSIGNMENT_APPROVED",
                 json.dumps({"assignment_request_id": int(request_id), "requester_id": req["requester_id"], "resource_id": rid}, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
            self.write_json({"message": "담당 사건 등록이 승인되었습니다.", "assignment_request": row})
        finally:
            db.close()


class CaseAssignmentRejectHandler(BaseHandler):
    """POST /api/admin/case-assignment-requests/<id>/reject"""
    def post(self, request_id):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body() or {}
        reason = str(body.get("reason") or "").strip()
        db = get_db()
        try:
            req = db.execute("SELECT * FROM case_assignment_requests WHERE id=?", (int(request_id),)).fetchone()
            if not req:
                return self.write_error_json("담당 사건 등록 요청을 찾을 수 없습니다.", 404, code="request_not_found")
            if int(req["requester_id"]) == int(admin["user_id"]):
                return self.write_error_json("본인이 요청한 담당 사건 등록은 본인이 반려할 수 없습니다.", 403, code="self_approval_forbidden")

            row = db.execute(
                "UPDATE case_assignment_requests "
                "SET status='rejected', final_approved_by=?, final_approved_at=CURRENT_TIMESTAMP, rejection_reason=? "
                "WHERE id=? RETURNING *",
                (admin["user_id"], reason, int(request_id))
            ).fetchone()
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("audit", "CASE_ASSIGNMENT_REJECTED",
                 json.dumps({"assignment_request_id": int(request_id), "reason": reason}, ensure_ascii=False),
                 admin["user_id"])
            )
            db.commit()
            self.write_json({"message": "담당 사건 등록 요청을 반려했습니다.", "assignment_request": row})
        finally:
            db.close()
