"""감사 로그 API 핸들러"""
import json
from api.base_handler import BaseHandler
from database import get_db, rows_to_list
from core.audit_events import AuditEvent, audit_log


class AuditLogHandler(BaseHandler):
    """GET /api/audit/logs"""
    def get(self):
        user = self.require_admin()
        if not user:
            return

        # ITEM 11: 음수/0/과대 limit 방어 — 1..1000 으로 클램프.
        limit = max(1, min(int(self.get_argument("limit", "50")), 1000))
        event_type = self.get_argument("event_type", None)
        layer = self.get_argument("layer", None)

        db = get_db()
        query = "SELECT a.*, u.name as user_name FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id"
        params = []
        conditions = []

        if event_type:
            conditions.append("a.event_type=?")
            params.append(event_type)
        if layer:
            conditions.append("a.layer=?")
            params.append(layer)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, params).fetchall()
        db.close()

        logs = []
        for row in rows:
            d = dict(row)
            if d.get("details"):
                try:
                    d["details"] = json.loads(d["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            logs.append(d)

        self.write_json({"logs": logs, "total": len(logs)})


class AccessLogHandler(BaseHandler):
    """GET /api/audit/access-logs"""
    def get(self):
        user = self.require_auth()
        if not user:
            return

        # ITEM 11: limit 클램프 (위 AuditLogHandler 와 동일).
        limit = max(1, min(int(self.get_argument("limit", "50")), 1000))
        user_filter = self.get_argument("user_id", None)

        db = get_db()
        query = """
            SELECT al.*, u.name as user_name, u.department,
                   r.title as resource_title, r.sensitivity_grade, r.case_number
            FROM access_logs al
            JOIN users u ON al.user_id = u.id
            JOIN resources r ON al.resource_id = r.id
        """
        params = []

        # 일반 사용자는 본인 기록만 (deputy_admin 도 관리자 등급 — ITEM 6)
        if not BaseHandler.is_admin_role(user):
            query += " WHERE al.user_id=?"
            params.append(user["user_id"])
        elif user_filter:
            query += " WHERE al.user_id=?"
            params.append(int(user_filter))

        query += " ORDER BY al.created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, params).fetchall()
        db.close()

        logs = [dict(r) for r in rows]
        self.write_json({"logs": logs, "total": len(logs)})


class DashboardStatsHandler(BaseHandler):
    """GET /api/audit/dashboard - 대시보드 통계 (일반 사용자: 본인 통계, 관리자: 전체 통계)"""
    def get(self):
        user = self.require_auth()
        if not user:
            return
        # deputy_admin 도 관리자 등급으로 일관 처리 (ITEM 6)
        is_admin = BaseHandler.is_admin_role(user)

        db = get_db()
        uid = user["user_id"]

        # 관리자: 전체 통계, 일반 사용자: 본인 통계
        if is_admin:
            total_access = db.execute("SELECT COUNT(*) as cnt FROM access_logs").fetchone()["cnt"]
            blocked = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE decision_level=5").fetchone()["cnt"]
            reauth = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE decision_level=3").fetchone()["cnt"]
            approved = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE decision_level<=2").fetchone()["cnt"]
            pending = db.execute("SELECT COUNT(*) as cnt FROM approvals WHERE status='pending'").fetchone()["cnt"]
            active_sessions = db.execute("SELECT COUNT(*) as cnt FROM sessions WHERE is_active").fetchone()["cnt"]
            locked_users = db.execute("SELECT COUNT(*) as cnt FROM users WHERE is_locked").fetchone()["cnt"]
        else:
            total_access = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE user_id=?", (uid,)).fetchone()["cnt"]
            blocked = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE user_id=? AND decision_level=5", (uid,)).fetchone()["cnt"]
            reauth = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE user_id=? AND decision_level=3", (uid,)).fetchone()["cnt"]
            approved = db.execute("SELECT COUNT(*) as cnt FROM access_logs WHERE user_id=? AND decision_level<=2", (uid,)).fetchone()["cnt"]
            pending = db.execute("SELECT COUNT(*) as cnt FROM approvals WHERE requester_id=? AND status='pending'", (uid,)).fetchone()["cnt"]
            active_sessions = db.execute("SELECT COUNT(*) as cnt FROM sessions WHERE user_id=? AND is_active", (uid,)).fetchone()["cnt"]
            locked_users = 0

        # 등급별 접근 통계
        if is_admin:
            grade_stats = db.execute("""
                SELECT r.sensitivity_grade, COUNT(*) as cnt,
                       SUM(CASE WHEN al.decision_level<=2 THEN 1 ELSE 0 END) as allowed,
                       SUM(CASE WHEN al.decision_level=5 THEN 1 ELSE 0 END) as blocked
                FROM access_logs al
                JOIN resources r ON al.resource_id = r.id
                GROUP BY r.sensitivity_grade
                ORDER BY r.sensitivity_grade
            """).fetchall()
        else:
            grade_stats = db.execute("""
                SELECT r.sensitivity_grade, COUNT(*) as cnt,
                       SUM(CASE WHEN al.decision_level<=2 THEN 1 ELSE 0 END) as allowed,
                       SUM(CASE WHEN al.decision_level=5 THEN 1 ELSE 0 END) as blocked
                FROM access_logs al
                JOIN resources r ON al.resource_id = r.id
                WHERE al.user_id=?
                GROUP BY r.sensitivity_grade
                ORDER BY r.sensitivity_grade
            """, (uid,)).fetchall()

        # 최근 접근 결정 분포
        # (PostgreSQL 은 SELECT 에 나온 비집계 컬럼이 모두 GROUP BY 에 있어야 함 → decision_label 포함)
        if is_admin:
            decision_dist = db.execute("""
                SELECT decision_level, decision_label, COUNT(*) as cnt
                FROM access_logs
                GROUP BY decision_level, decision_label
                ORDER BY decision_level
            """).fetchall()
        else:
            decision_dist = db.execute("""
                SELECT decision_level, decision_label, COUNT(*) as cnt
                FROM access_logs WHERE user_id=?
                GROUP BY decision_level, decision_label
                ORDER BY decision_level
            """, (uid,)).fetchall()

        db.close()

        self.write_json({
            "total_access_requests": total_access,
            "blocked_count": blocked,
            "reauth_count": reauth,
            "approved_count": approved,
            "pending_approvals": pending,
            "active_sessions": active_sessions,
            "locked_users": locked_users,
            "grade_stats": [dict(r) for r in grade_stats],
            "decision_distribution": [dict(r) for r in decision_dist],
        })


# ─── 017: 결정 사후 라벨링 (FP/FN 신고) ──────────────────────────
class AccessDecisionReviewHandler(BaseHandler):
    """POST /api/admin/access-logs/{access_log_id}/review

    관리자가 특정 access_logs 결정을 사후 라벨링한다.
    label ∈ {false_positive, false_negative, justified}.

    트리거(017 마이그레이션) 가 INSERT 후 사용자 trust_score / violation_count
    를 자동 조정한다 (FP +5 / FN -10 +1 / justified 변동 없음).
    """

    def post(self, access_log_id):
        admin = self.require_admin()
        if not admin:
            return

        body = self.get_json_body()
        label = (body.get("label") or "").strip()
        notes = body.get("notes") or ""

        if label not in ("false_positive", "false_negative", "justified"):
            return self.write_error_json(
                "label 은 false_positive / false_negative / justified 중 하나",
                400, code="invalid_label",
            )

        try:
            log_id = int(access_log_id)
        except ValueError:
            return self.write_error_json(
                "올바르지 않은 access_log_id", 400)

        db = get_db()
        try:
            # access_logs 행 조회 — 대상 user_id 확보 + 자기-라벨 차단
            log_row = db.execute(
                "SELECT id, user_id FROM access_logs WHERE id=?", (log_id,)
            ).fetchone()
            if not log_row:
                return self.write_error_json(
                    "access_log 를 찾을 수 없습니다", 404)
            target_user_id = log_row["user_id"]

            # 자기-라벨 차단: 본인 결정을 본인이 라벨하는 것 금지
            if target_user_id == admin["user_id"]:
                audit_log(
                    db,
                    AuditEvent.SELF_ACTION_BLOCKED,
                    user_id=admin["user_id"],
                    request_id=getattr(self, "request_id", "-"),
                    details={
                        "action": "access_log_review",
                        "target_id": log_id,
                        "actor_id": admin["user_id"],
                    },
                    severity=3, layer="audit",
                )
                return self.write_error_json(
                    "본인이 한 결정을 본인이 라벨할 수 없습니다", 403,
                    code="self_action_blocked",
                )

            # INSERT — 트리거가 trust 자동 조정
            db.execute(
                "INSERT INTO access_decision_reviews "
                "(access_log_id, reviewer_id, target_user_id, label, notes) "
                "VALUES (?, ?, ?, ?, ?)",
                (log_id, admin["user_id"], target_user_id, label, notes),
            )
            db.commit()

            # 갱신된 사용자 trust 조회 (응답에 포함)
            user_row = db.execute(
                "SELECT trust_score, violation_count FROM users WHERE id=?",
                (target_user_id,),
            ).fetchone()

            # operation_logs 기록
            audit_log(
                db,
                AuditEvent.POLICY_OVERRIDE_REQUESTED,
                user_id=admin["user_id"],
                request_id=getattr(self, "request_id", "-"),
                details={
                    "kind": "access_decision_review",
                    "access_log_id": log_id,
                    "target_user_id": target_user_id,
                    "label": label,
                },
                severity=2, layer="operation",
            )
        finally:
            db.close()

        self.write_json({
            "status": "ok",
            "access_log_id": log_id,
            "target_user_id": target_user_id,
            "label": label,
            "trust_after": float(user_row["trust_score"]) if user_row else None,
            "violation_after": int(user_row["violation_count"]) if user_row else None,
        })
