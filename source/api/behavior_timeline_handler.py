"""Authenticated S1 reads; D4 is checked from current DB state, not JWT roles."""
from api.base_handler import BaseHandler
from core.behavior_timeline import TimelineAccessDenied, TimelineError
from core.behavior_timeline_db import load_timeline, TimelineSessionDenied, TimelineSourceLimit
from database import get_db


class BehaviorTimelineHandler(BaseHandler):
    """GET /api/admin/behavior-timeline/{user_id}[ /evidence/{source}:{id} ]."""

    def get(self, subject_id, evidence_ref=None):
        self.set_header("Cache-Control", "no-store")
        # Unlike require_auth's expiration cleanup, this route must remain read
        # only. The service uses the same pure session guard and rejects expired
        # or locked sessions without touching them or recording behavior.
        identity = self.get_current_user_from_token()
        if not identity or not identity.get("mfa_verified") or not identity.get("session_id"):
            return self.write_error_json("유효한 MFA 세션이 필요합니다.", 401, code="timeline_session_denied")
        permitted = {"start", "end", "page_size", "cursor"}
        if set(self.request.query_arguments) - permitted or any(
            len(values) != 1 for values in self.request.query_arguments.values()
        ):
            return self.write_error_json("조회 조건이 올바르지 않습니다.", 400, code="timeline_query_invalid")
        db = None
        try:
            page_size = int(self.get_argument("page_size", "50"))
            start, end = self.get_argument("start", ""), self.get_argument("end", "")
            cursor = self.get_argument("cursor", None)
            if evidence_ref is not None and cursor is not None:
                raise TimelineError("evidence cursor unsupported")
            db = get_db()
            result = load_timeline(db, reviewer_id=identity.get("user_id"),
                session_id=identity["session_id"], subject_id=int(subject_id), start=start,
                end=end, page_size=page_size, cursor=cursor, evidence_ref=evidence_ref)
            self.write_json(result)
        except TimelineSessionDenied:
            self.write_error_json("유효한 MFA 세션이 필요합니다.", 401, code="timeline_session_denied")
        except TimelineAccessDenied:
            self.write_error_json("조회 권한이 없습니다.", 403, code="timeline_scope_denied")
        except (TimelineError, ValueError):
            self.write_error_json("조회 조건 또는 커서가 유효하지 않습니다.", 400, code="timeline_query_invalid")
        except TimelineSourceLimit:
            self.write_error_json("조회 한도를 넘어 근거 범위를 확인할 수 없습니다.", 503, code="timeline_source_limit")
        finally:
            if db is not None:
                db.close()
