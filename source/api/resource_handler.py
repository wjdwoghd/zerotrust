"""리소스(사건 문서) API 핸들러"""
import json
import time
from api.base_handler import BaseHandler
from database import get_db, row_to_dict, rows_to_list
from core.access_evaluator import evaluate_access
from core.audit_events import AuditEvent, audit_log
from core.case_assignment_rules import assignment_compatibility, assignment_guidance
from security.mfa_service import verify_totp_consume


class CaseListHandler(BaseHandler):
    """GET /api/resources/cases - 사건 목록 조회"""
    def get(self):
        user = self.require_auth()
        if not user:
            return

        db = get_db()

        # 사건 목록은 제로트러스트 시연 폭을 위해 넓게 제공하되,
        # 목록 단계에서는 상세 설명(description) 같은 민감 본문성 정보는 내려주지 않는다.
        # 실제 상세 내용은 /api/resources/cases/<id> 에서 매 요청 접근평가 후 마스킹되어 반환된다.
        # 목록 화면에서 담당 사건은 업무 편의상 기본 정보를 보여주고,
        # 비담당 사건은 카드 자체는 노출하되(탐색/반복 접근 탐지 가능),
        # 민감 메타데이터는 브라우저로도 최소한만 내려주도록 제한한다.
        # 등급 필터를 서버 쿼리에 직접 반영하면 비담당/마스킹 사건도
        # 응답 개수로 등급을 역추론할 수 있다. 목록은 항상 전체를 내려주고,
        # 비담당 사건의 민감 등급은 클라이언트로도 보내지 않는다.
        rows = db.execute(
            "SELECT id, case_number, title, description, sensitivity_grade, "
            "       data_type, department, requires_approval, created_at "
            "FROM resources ORDER BY sensitivity_grade, id"
        ).fetchall()

        # require_auth()가 돌려주는 JWT payload에는 assigned_cases가 없을 수 있다.
        # 따라서 목록 마스킹 판단은 항상 DB의 최신 users.assigned_cases를 기준으로 한다.
        user_row = db.execute(
            "SELECT assigned_cases FROM users WHERE id=?",
            (user["user_id"],)
        ).fetchone()
        assigned_cases = (user_row or {}).get("assigned_cases") or []
        if isinstance(assigned_cases, str):
            try:
                assigned_cases = json.loads(assigned_cases)
            except Exception:
                assigned_cases = []

        assigned_case_strs = {str(v) for v in assigned_cases}
        assigned_case_ids = set()
        for v in assigned_cases:
            try:
                assigned_case_ids.add(int(v))
            except Exception:
                pass

        cases = []
        for row in rows:
            r = row_to_dict(row)
            is_assigned_case = (
                r["id"] in assigned_case_ids
                or str(r.get("case_number")) in assigned_case_strs
            )

            cases.append({
                "id": r["id"],
                "case_number": r["case_number"] if is_assigned_case else "비공개",
                "title": r["title"],
                "description": (r.get("description") or "") if is_assigned_case else "상세 내용은 접근 평가 후 표시됩니다.",
                "sensitivity_grade": r["sensitivity_grade"] if is_assigned_case else None,
                "sensitivity_grade_masked": not is_assigned_case,
                "data_type": r["data_type"] if is_assigned_case else "비공개",
                "department": r["department"] if is_assigned_case else "비공개",
                "requires_approval": bool(r.get("requires_approval")),
                "is_assigned_case": bool(is_assigned_case),
            })

        db.close()
        self.write_json({"cases": cases, "total": len(cases)})


class CaseDetailHandler(BaseHandler):
    """GET /api/resources/cases/<id> - 사건 상세 조회 (접근 평가 포함)"""
    def get(self, case_id):
        user = self.require_auth()
        if not user:
            return

        device_id = self.get_device_id()
        location = self.get_location()
        ip_address = self.get_ip_address()

        # 현재 시간 기반 심야 판단
        # 시뮬 패널의 X-Sim-Hour 헤더가 있으면 그 값을 우선, 없으면 서버 OS 시각.
        sim_hour = self.get_simulated_hour()
        hour = sim_hour if sim_hour is not None else time.localtime().tm_hour
        is_night = hour >= 22 or hour < 6

        # JWT 토큰에 포함된 세션 ID 사용 (다중 세션 시 정확한 세션 참조)
        session_id = user.get("session_id")

        # 접근 평가 실행
        result = evaluate_access(
            user_id=user["user_id"],
            resource_id=int(case_id),
            session_id=session_id,
            device_id=device_id,
            ip_address=ip_address,
            location=location,
            action_type="view",
            is_night=is_night,
            hour=hour,
        )

        self.write_json(result)


class CaseAccessStatusHandler(BaseHandler):
    """GET /api/resources/cases/<id>/status - 실시간 접근 점수/레벨 조회.

    상세 GET 과 달리 access_logs 를 새로 만들지 않는다. 화면 자동 갱신이
    자체적으로 행동 위험도를 끌어올리지 않게 하기 위한 읽기 전용 평가다.
    사용자 응답에는 사유 문자열을 싣지 않고, 변화 내역은 관리자용 감사
    로그(ACCESS_SCORE_CHANGED)에만 남긴다.
    """
    def get(self, case_id):
        user = self.require_auth()
        if not user:
            return

        device_id = self.get_device_id()
        location = self.get_location()
        ip_address = self.get_ip_address()
        sim_hour = self.get_simulated_hour()
        hour = sim_hour if sim_hour is not None else time.localtime().tm_hour
        is_night = hour >= 22 or hour < 6
        session_id = user.get("session_id")

        result = evaluate_access(
            user_id=user["user_id"],
            resource_id=int(case_id),
            session_id=session_id,
            device_id=device_id,
            ip_address=ip_address,
            location=location,
            action_type="view",
            is_night=is_night,
            hour=hour,
            record_access=False,
            mutate_state=False,
            include_resource_body=False,
        )

        _log_score_change_if_needed(
            user_id=user["user_id"],
            session_id=session_id,
            resource_id=int(case_id),
            result=result,
            request_id=getattr(self, "request_id", None),
        )
        self.write_json(_sanitize_status_response(result))


class CaseRestrictedClickHandler(BaseHandler):
    """POST /api/resources/cases/<id>/restricted-click - 비담당 사건 클릭 기록."""
    def post(self, case_id):
        user = self.require_auth()
        if not user:
            return

        try:
            rid = int(case_id)
        except (TypeError, ValueError):
            return self.write_error_json(
                "리소스 ID 가 올바르지 않습니다.", 400, code="invalid_resource_id"
            )

        session_id = user.get("session_id")
        db = get_db()
        try:
            res = db.execute(
                "SELECT id, case_number, title FROM resources WHERE id=?",
                (rid,),
            ).fetchone()
            if not res:
                return self.write_error_json("리소스를 찾을 수 없습니다", 404)

            user_row = db.execute(
                "SELECT assigned_cases FROM users WHERE id=?",
                (user["user_id"],),
            ).fetchone()
            assigned = (user_row or {}).get("assigned_cases") or []
            if isinstance(assigned, str):
                try:
                    assigned = json.loads(assigned)
                except Exception:
                    assigned = []
            assigned_strs = {str(v) for v in assigned}
            assigned_ids = set()
            for v in assigned:
                try:
                    assigned_ids.add(int(v))
                except Exception:
                    pass

            is_assigned = rid in assigned_ids or str(res["case_number"]) in assigned_strs
            if is_assigned:
                return self.write_json({
                    "recorded": False,
                    "is_assigned_case": True,
                    "click_index": 0,
                    "behavior_penalty": 0,
                })

            before = db.execute(
                "SELECT COUNT(*) AS c FROM audit_logs "
                "WHERE event_type=? AND user_id=? "
                "  AND COALESCE(details->>'session_id', '')=?",
                (AuditEvent.UNASSIGNED_CASE_CLICK.value, user["user_id"], str(session_id or "")),
            ).fetchone()
            click_index = int(before["c"] if before else 0) + 1
            penalty_clicks = max(0, click_index - 1)
            behavior_penalty = penalty_clicks * 10

            audit_log(
                db=db,
                event=AuditEvent.UNASSIGNED_CASE_CLICK,
                user_id=user["user_id"],
                request_id=getattr(self, "request_id", None),
                details={
                    "resource_id": rid,
                    "case_number": res["case_number"],
                    "session_id": session_id,
                    "click_index": click_index,
                    "penalty_clicks": penalty_clicks,
                    "behavior_penalty": behavior_penalty,
                    "device_id": self.get_device_id(),
                    "location": self.get_location(),
                },
                severity=2 if penalty_clicks else 1,
                layer="audit",
            )
        finally:
            try:
                db.close()
            except Exception:
                pass

        self.write_json({
            "recorded": True,
            "is_assigned_case": False,
            "click_index": click_index,
            "penalty_clicks": penalty_clicks,
            "behavior_penalty": behavior_penalty,
            "message": (
                "비담당 사건 최초 클릭 경고만 기록되었습니다."
                if penalty_clicks == 0
                else f"비담당 사건 반복 클릭으로 행동위험도 +{behavior_penalty}가 적용됩니다."
            ),
        })


def _sanitize_status_response(result: dict) -> dict:
    """사용자 실시간 폴링 응답에서 내부 사유/상세 문자열 제거."""
    decision = dict(result.get("decision") or {})
    display_score = decision.get("display_risk_score", decision.get("risk_score", 0))
    decision = {
        "level": decision.get("level"),
        "label": decision.get("label"),
        "label_en": decision.get("label_en"),
        "risk_score": display_score,
        "display_risk_score": display_score,
        "raw_risk_score": (result.get("decision") or {}).get("raw_risk_score"),
        "score_level": decision.get("score_level", decision.get("level")),
        "score_label": decision.get("score_label", decision.get("label")),
        "override": decision.get("override"),
        "sensitivity_grade": decision.get("sensitivity_grade"),
        "action_permissions": decision.get("action_permissions") or {},
        "can_view": decision.get("can_view"),
        "can_download": decision.get("can_download"),
        "can_copy": decision.get("can_copy"),
        "can_print": decision.get("can_print"),
    }
    if (result.get("decision") or {}).get("break_glass"):
        decision["break_glass"] = (result.get("decision") or {}).get("break_glass")

    scoring = result.get("scoring") or {}
    total = scoring.get("total") or {}
    safe_scoring = {
        "object_sensitivity": {
            "score": (scoring.get("object_sensitivity") or {}).get("score", 0)
        },
        "environment_risk": {
            "score": (scoring.get("environment_risk") or {}).get("score", 0)
        },
        "behavior_risk": {
            "score": (scoring.get("behavior_risk") or {}).get("score", 0)
        },
        "work_fitness": {
            "score": (scoring.get("work_fitness") or {}).get("score", 0)
        },
        "total": {
            "total_risk_score": display_score,
            "score_level": total.get("score_level", decision.get("score_level")),
            "decision_level": decision.get("level"),
            "action_permissions": decision.get("action_permissions") or {},
        },
    }

    return {
        "request_id": result.get("request_id"),
        "decision": decision,
        "scoring": safe_scoring,
        "resource": result.get("resource") or {},
        "timestamp": result.get("timestamp"),
    }


def _log_score_change_if_needed(*, user_id: int, session_id, resource_id: int,
                                result: dict, request_id):
    decision = result.get("decision") or {}
    scoring = result.get("scoring") or {}
    if not decision or not scoring:
        return

    new_score = float(decision.get("display_risk_score",
                                   decision.get("risk_score", 0)) or 0)
    new_level = int(decision.get("level", 5) or 5)
    score_level = int(decision.get("score_level", new_level) or new_level)
    override = decision.get("override")
    session_key = str(session_id or "")

    db = get_db()
    try:
        row = db.execute("""
            SELECT details
            FROM audit_logs
            WHERE event_type=?
              AND user_id=?
              AND details->>'resource_id'=?
              AND COALESCE(details->>'session_id', '')=?
            ORDER BY created_at DESC
            LIMIT 1
        """, (
            AuditEvent.ACCESS_SCORE_CHANGED.value,
            user_id,
            str(resource_id),
            session_key,
        )).fetchone()

        previous = {}
        if row and row.get("details"):
            previous = row["details"]
            if isinstance(previous, str):
                try:
                    previous = json.loads(previous)
                except Exception:
                    previous = {}

        prev_score = previous.get("new_score")
        prev_level = previous.get("new_level")
        prev_score_level = previous.get("score_level")
        prev_override = previous.get("override")
        changed = (
            prev_score is None or
            abs(float(prev_score) - new_score) >= 0.05 or
            int(prev_level or 0) != new_level or
            int(prev_score_level or 0) != score_level or
            prev_override != override
        )
        if not changed:
            return

        axes = {
            "object": (scoring.get("object_sensitivity") or {}).get("score", 0),
            "environment": (scoring.get("environment_risk") or {}).get("score", 0),
            "behavior": (scoring.get("behavior_risk") or {}).get("score", 0),
            "fitness": (scoring.get("work_fitness") or {}).get("score", 0),
        }
        policy_check = result.get("policy_check") or {}
        anomaly_check = result.get("anomaly_check") or {}
        audit_log(
            db=db,
            event=AuditEvent.ACCESS_SCORE_CHANGED,
            user_id=user_id,
            request_id=request_id,
            details={
                "resource_id": resource_id,
                "session_id": session_id,
                "previous_score": prev_score,
                "new_score": new_score,
                "previous_level": prev_level,
                "new_level": new_level,
                "score_level": score_level,
                "override": override,
                "decision_label": decision.get("label"),
                "axes": axes,
                "policy_rule": policy_check.get("rule"),
                "policy_reason": policy_check.get("reason"),
                "anomaly_types": anomaly_check.get("anomaly_types", []),
                "decision_reason": decision.get("reason"),
            },
            severity=2,
            layer="audit",
        )
    finally:
        try:
            db.close()
        except Exception:
            pass


class CaseDownloadHandler(BaseHandler):
    """POST /api/resources/cases/<id>/download - 다운로드 요청 (접근 평가)"""
    def post(self, case_id):
        user = self.require_auth()
        if not user:
            return

        device_id = self.get_device_id()
        location = self.get_location()

        # 시뮬 패널의 X-Sim-Hour 헤더가 있으면 그 값을 우선, 없으면 서버 OS 시각.
        sim_hour = self.get_simulated_hour()
        hour = sim_hour if sim_hour is not None else time.localtime().tm_hour
        is_night = hour >= 22 or hour < 6

        # JWT 토큰에 포함된 세션 ID 사용
        session_id = user.get("session_id")

        result = evaluate_access(
            user_id=user["user_id"],
            resource_id=int(case_id),
            session_id=session_id,
            device_id=device_id,
            ip_address=self.get_ip_address(),
            location=location,
            action_type="download",
            is_night=is_night,
            hour=hour,
        )

        self.write_json(result)


class CaseFileHandler(BaseHandler):
    """
    GET /api/resources/cases/<id>/file

    실제 문서 파일 다운로드. 접근 평가를 action_type='download' 로
    수행해 결정이 다운로드를 허용할 때만 원본 파일 본문을 attachment
    로 서빙한다. 허용되지 않으면 403.

    허용 조건: decision.resource.can_download == True
      - Level 1 (FULL_ACCESS) 또는 BG 경로(level=1, FULL_ACCESS_BREAK_GLASS)
      - 관리자 승인 download_allowed=true 로 level 1 승격된 경우

    Level 2 (VIEW_ONLY) 이하는 masking_engine 에서 can_download=False 로
    셋팅되어 여기서 403 이 된다.
    """
    def get(self, case_id):
        user = self.require_auth()
        if not user:
            return

        device_id = self.get_device_id()
        location = self.get_location()

        # 시뮬 패널의 X-Sim-Hour 헤더가 있으면 그 값을 우선, 없으면 서버 OS 시각.
        sim_hour = self.get_simulated_hour()
        hour = sim_hour if sim_hour is not None else time.localtime().tm_hour
        is_night = hour >= 22 or hour < 6
        session_id = user.get("session_id")

        result = evaluate_access(
            user_id=user["user_id"],
            resource_id=int(case_id),
            session_id=session_id,
            device_id=device_id,
            ip_address=self.get_ip_address(),
            location=location,
            action_type="download",
            is_night=is_night,
            hour=hour,
        )

        resource_block = result.get("resource") or {}
        if not resource_block.get("can_download"):
            decision = result.get("decision") or {}
            return self.write_json({
                "error": (
                    decision.get("external_message")
                    or "이 문서는 현재 다운로드가 허용되지 않습니다."
                ),
                "code": "download_not_allowed",
                "request_id": result.get("request_id"),
                "decision": decision,
                "scoring": result.get("scoring"),
                "resource": resource_block,
                "timestamp": result.get("timestamp"),
            }, status=403)

        # 원본(마스킹 미적용) 본문을 재조회해 첨부로 내려준다.
        # can_download=True 는 level=1 에서만 True → 원본 서빙이 안전.
        db = get_db()
        try:
            row = db.execute(
                "SELECT case_number, title, content FROM resources WHERE id=?",
                (int(case_id),)
            ).fetchone()
        finally:
            db.close()

        if not row:
            return self.write_error_json("리소스를 찾을 수 없습니다", 404)

        content = (row["content"] or "").encode("utf-8")
        case_number = row["case_number"] or f"case-{case_id}"
        # 안전한 파일명 — ASCII 로 치환 + UTF-8 버전을 RFC 5987 로 덧붙여준다.
        import urllib.parse as _up
        safe_ascii = "".join(
            ch if ord(ch) < 128 and ch not in '"\\' else "_"
            for ch in f"{case_number}.txt"
        ) or "document.txt"
        utf8_name = _up.quote(f"{case_number}.txt", safe="")

        # CSP/보안 기본 헤더는 유지. Content-Type 만 text/plain 으로 교체.
        self.clear_header("Content-Type")
        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{utf8_name}'
        )
        self.set_header("Cache-Control", "no-store")
        self.set_header("Content-Length", str(len(content)))
        self.write(content)


class CaseAssignmentRequestHandler(BaseHandler):
    """POST /api/resources/cases/<id>/assignment-request - 담당 사건 등록 요청"""
    def post(self, case_id):
        user = self.require_auth()
        if not user:
            return

        try:
            rid = int(case_id)
        except (TypeError, ValueError):
            return self.write_error_json("리소스 ID가 올바르지 않습니다.", 400, code="invalid_resource_id")

        body = self.get_json_body() or {}
        reason = str(body.get("reason") or "비담당 사건 목록에서 담당 사건 등록 요청").strip()
        if len(reason) > 500:
            reason = reason[:500]

        db = get_db()
        try:
            resource = db.execute(
                "SELECT id, case_number, title, sensitivity_grade, department, job_tags FROM resources WHERE id=?",
                (rid,)
            ).fetchone()
            if not resource:
                return self.write_error_json("사건을 찾을 수 없습니다.", 404, code="resource_not_found")

            requester = db.execute(
                "SELECT id, username, role, department, assigned_cases, job_scope FROM users WHERE id=?",
                (user["user_id"],)
            ).fetchone()
            if not requester:
                return self.write_error_json("사용자를 찾을 수 없습니다.", 404, code="user_not_found")

            compatible, message = assignment_compatibility(requester, resource)
            if not compatible:
                return self.write_json({
                    "error": message,
                    "code": "assignment_scope_mismatch",
                    "request_id": getattr(self, "request_id", "-"),
                    "assignment_scope": assignment_guidance(requester, resource),
                }, status=403)

            assigned = requester.get("assigned_cases") or []
            assigned_ids = set()
            assigned_strs = set()
            if isinstance(assigned, str):
                try:
                    assigned = json.loads(assigned)
                except Exception:
                    assigned = []
            for v in assigned or []:
                assigned_strs.add(str(v))
                try:
                    assigned_ids.add(int(v))
                except Exception:
                    pass

            if rid in assigned_ids or str(resource.get("case_number")) in assigned_strs:
                return self.write_json({
                    "message": "이미 담당 사건으로 등록되어 있습니다.",
                    "already_assigned": True,
                    "resource_id": rid,
                })

            # 일반 사용자의 요청은 관리자에게, 관리자/부관리자의 요청은 자기승인 방지를 위해 부관리자에게 배정한다.
            requester_role = requester.get("role")
            reviewer_role = "deputy_admin" if requester_role in ("admin", "superadmin", "deputy_admin") else "admin"

            existing = db.execute(
                "SELECT * FROM case_assignment_requests "
                "WHERE requester_id=? AND resource_id=? AND status IN ('pending_admin','otp_required','otp_verified') "
                "ORDER BY id DESC LIMIT 1",
                (user["user_id"], rid)
            ).fetchone()
            if existing:
                return self.write_json({
                    "message": "이미 처리 대기 중인 담당 사건 등록 요청이 있습니다.",
                    "assignment_request": existing,
                    "existing": True,
                })

            row = db.execute(
                "INSERT INTO case_assignment_requests "
                "(requester_id, resource_id, reviewer_role, status, reason) "
                "VALUES (?, ?, ?, 'pending_admin', ?) "
                "RETURNING id, requester_id, resource_id, reviewer_role, status, reason, requested_at",
                (user["user_id"], rid, reviewer_role, reason)
            ).fetchone()

            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("audit", "CASE_ASSIGNMENT_REQUESTED",
                 json.dumps({
                     "assignment_request_id": row["id"],
                     "resource_id": rid,
                     "case_number": resource.get("case_number"),
                     "reviewer_role": reviewer_role,
                     "requester_role": requester_role,
                     "reason": reason,
                 }, ensure_ascii=False),
                 user["user_id"])
            )
            db.commit()
            self.write_json({
                "message": "담당 사건 등록 요청을 보냈습니다.",
                "assignment_request": row,
            }, status=201)
        finally:
            db.close()


class MyCaseAssignmentRequestsHandler(BaseHandler):
    """GET /api/resources/case-assignment-requests/my - 내 담당 사건 등록 요청 상태 조회"""
    def get(self):
        user = self.require_auth()
        if not user:
            return

        db = get_db()
        try:
            rows = db.execute(
                "SELECT r.*, "
                "       res.case_number, res.title AS resource_title, "
                "       res.sensitivity_grade, res.department AS resource_department, "
                "       reviewer.username AS otp_required_by_username, reviewer.name AS otp_required_by_name "
                "FROM case_assignment_requests r "
                "JOIN resources res ON r.resource_id=res.id "
                "LEFT JOIN users reviewer ON r.otp_required_by=reviewer.id "
                "WHERE r.requester_id=? "
                "  AND r.status IN ('pending_admin','otp_required','otp_verified') "
                "ORDER BY r.requested_at DESC",
                (user["user_id"],)
            ).fetchall()
            self.write_json({"requests": rows, "total": len(rows)})
        finally:
            db.close()


class CaseAssignmentOtpVerifyHandler(BaseHandler):
    """POST /api/resources/case-assignment-requests/<id>/verify-otp - 요청자 OTP 인증"""
    def post(self, request_id):
        user = self.require_auth()
        if not user:
            return

        body = self.get_json_body() or {}
        otp_code = str(body.get("otp") or "").strip()

        db = get_db()
        try:
            req = db.execute(
                "SELECT * FROM case_assignment_requests WHERE id=?",
                (int(request_id),)
            ).fetchone()
            if not req:
                return self.write_error_json("담당 사건 등록 요청을 찾을 수 없습니다.", 404, code="request_not_found")
            if int(req["requester_id"]) != int(user["user_id"]):
                return self.write_error_json("본인의 요청만 OTP 인증할 수 있습니다.", 403, code="forbidden")
            if req["status"] != "otp_required":
                return self.write_error_json("현재 OTP 인증이 필요한 상태가 아닙니다.", 400, code="otp_not_required")

            token_row = db.execute(
                "SELECT id, mfa_secret, last_otp_step FROM user_devices "
                "WHERE user_id=? AND device_type='totp_token' AND is_active "
                "ORDER BY id LIMIT 1",
                (user["user_id"],)
            ).fetchone()
            if not token_row or not token_row.get("mfa_secret"):
                return self.write_error_json("이 계정에 등록된 토큰 기기가 없습니다.", 403, code="token_device_missing")

            ok, used_step = verify_totp_consume(
                token_row["mfa_secret"], otp_code,
                last_used_step=token_row.get("last_otp_step")
            )
            if not ok:
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                    ("security", "CASE_ASSIGNMENT_OTP_FAILED",
                     json.dumps({"assignment_request_id": int(request_id)}, ensure_ascii=False),
                     user["user_id"])
                )
                db.commit()
                return self.write_error_json("OTP 코드가 올바르지 않거나 이미 사용되었습니다.", 401, code="otp_invalid_or_reused")

            db.execute("UPDATE user_devices SET last_otp_step=? WHERE id=?", (used_step, token_row["id"]))
            row = db.execute(
                "UPDATE case_assignment_requests "
                "SET status='otp_verified', otp_verified_at=CURRENT_TIMESTAMP "
                "WHERE id=? "
                "RETURNING *",
                (int(request_id),)
            ).fetchone()
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("security", "CASE_ASSIGNMENT_OTP_VERIFIED",
                 json.dumps({"assignment_request_id": int(request_id)}, ensure_ascii=False),
                 user["user_id"])
            )
            db.commit()
            self.write_json({"message": "OTP 인증이 완료되었습니다. 관리자 최종 승인을 기다려 주세요.", "assignment_request": row})
        finally:
            db.close()


class CaseApprovalRequestHandler(BaseHandler):
    """
    POST /api/resources/cases/<id>/request-approval

    사용자가 "관리자 승인이 필요하다" 고 판정된 자원에 대해
    **명시적으로** 승인 요청을 보낼 때만 approvals 행을 생성한다.

    이전에는 evaluate_access() 가 decision.level >= 4 인 모든 경우에
    자동으로 INSERT 했는데, 이 때문에 사용자가 단순히 자원을 열어보기만
    해도 pending 요청이 쌓이는 문제가 있었다. 이제는 자원 상세에서
    "승인 요청 보내기" 버튼을 눌러야만 이 엔드포인트가 호출되고,
    그제야 관리자 승인 대기열에 들어간다.

    요청 본문 (모두 optional):
      { "reason": "자유 서술 사유", "want_download": true|false }

    응답:
      201 created  : 신규 승인 요청 생성
      200 ok       : 이미 pending 요청이 있어 동일 approval 을 반환 (idempotent)
      400/404      : 에러
    """
    def post(self, case_id):
        user = self.require_auth()
        if not user:
            return

        try:
            rid = int(case_id)
        except (TypeError, ValueError):
            return self.write_error_json(
                "리소스 ID 가 올바르지 않습니다.", 400, code="invalid_resource_id"
            )

        # 요청 본문 파싱 (비어도 허용)
        try:
            body = json.loads(self.request.body or b"{}")
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        reason = str(body.get("reason") or "").strip()
        # 사유는 선택이지만, 최대 길이만 제한 (감사 로그 페이로드 방어)
        if len(reason) > 500:
            reason = reason[:500]
        want_download = bool(body.get("want_download", False))

        db = get_db()
        try:
            # 1) 리소스 존재·승인 필요 여부 확인
            res = db.execute(
                "SELECT id, case_number, requires_approval, sensitivity_grade "
                "FROM resources WHERE id=?", (rid,)
            ).fetchone()
            if not res:
                return self.write_error_json(
                    "리소스를 찾을 수 없습니다.", 404, code="resource_not_found"
                )

            # requires_approval 플래그가 없고 sens<4 이면 승인 게이트 없음.
            needs_gate = bool(res["requires_approval"]) or int(
                res["sensitivity_grade"] or 0) >= 4
            if not needs_gate:
                return self.write_error_json(
                    "이 자원은 관리자 승인이 필요한 자원이 아닙니다.",
                    400, code="approval_not_required"
                )

            # 2) 중복 pending 요청이 있으면 그대로 반환 (idempotent)
            existing = db.execute(
                "SELECT id FROM approvals "
                "WHERE requester_id=? AND resource_id=? AND status='pending' "
                "ORDER BY id DESC LIMIT 1",
                (user["user_id"], rid)
            ).fetchone()
            if existing:
                eid = int(existing["id"])
                self.set_status(200)
                return self.write_json({
                    "approval_id": eid,
                    "status": "pending",
                    "existing": True,
                    "message": "이미 대기 중인 승인 요청이 있습니다.",
                })

            # 3) 신규 생성
            final_reason = reason or "사용자 명시 요청 - 고민감 자료 접근"
            db.execute(
                "INSERT INTO approvals "
                "(requester_id, resource_id, reason, status) VALUES (?,?,?,?)",
                (user["user_id"], rid, final_reason, "pending")
            )
            # 방금 INSERT 한 id 를 재조회한다.
            new_row = db.execute(
                "SELECT id FROM approvals "
                "WHERE requester_id=? AND resource_id=? AND status='pending' "
                "ORDER BY id DESC LIMIT 1",
                (user["user_id"], rid)
            ).fetchone()
            new_id = int(new_row["id"]) if new_row else None

            # 감사 로그 (L5)
            audit_log(
                db=db,
                event=AuditEvent.ADMIN_APPROVAL_REQUESTED,
                user_id=user["user_id"],
                request_id=getattr(self, "request_id", None),
                details={
                    "resource_id": rid,
                    "case_number": res["case_number"],
                    "approval_id": new_id,
                    "reason": final_reason,
                    "want_download": want_download,
                    "origin": "user_explicit",
                },
                severity=2,
                layer="operation",
            )
            db.commit()
        finally:
            try:
                db.close()
            except Exception:
                pass

        self.set_status(201)
        self.write_json({
            "approval_id": new_id,
            "status": "pending",
            "existing": False,
            "message": "승인 요청이 접수되었습니다. 관리자 검토를 기다려주세요.",
        })
