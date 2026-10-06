"""Administrator-only descriptive approval effect measurements."""
from datetime import datetime

from tornado.web import MissingArgumentError

from api.base_handler import BaseHandler
from core.approval_effect import measure
from database import get_db


class ApprovalEffectHandler(BaseHandler):
    """GET /api/admin/approval-effects?start=<ISO8601>&end=<ISO8601>."""

    def get(self):
        if not self.require_admin():
            return
        try:
            start = datetime.fromisoformat(self.get_query_argument("start"))
            end = datetime.fromisoformat(self.get_query_argument("end"))
            if start.tzinfo is None or end.tzinfo is None or start >= end:
                raise ValueError("period_invalid")
        except (ValueError, TypeError, MissingArgumentError):
            return self.write_error_json("period_invalid", 400, code="period_invalid")
        db = get_db()
        try:
            self.write_json(measure(db, start, end))
        finally:
            db.close()
