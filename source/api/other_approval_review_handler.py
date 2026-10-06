"""Administrator-only, read-only review and emergency audit candidates."""
from __future__ import annotations

import asyncio

from api.base_handler import BaseHandler
from core.approval_review_facts import ReviewFactsError
from core.other_approval_review import load_review_facts, build_model_input, review_response
from core.audit_events import AuditEvent, audit_log
from database import get_db
from integrations.openai_other_approval_client import generate_review
from integrations.openai_review_transport import (
    MissingApiKeyError, ModelRefusalError, ModelTimeoutError, ModelOutputError,
    ReviewTransportError,
)


class OtherApprovalFactsHandler(BaseHandler):
    """GET /api/admin/reviews/{type}/{id}/facts."""

    def get(self, review_type, target_id):
        reviewer = self.require_admin()
        if not reviewer:
            return
        db = get_db()
        try:
            self.write_json(load_review_facts(db, review_type, int(target_id),
                int(reviewer["user_id"]), reviewer["role"]))
        except ReviewFactsError as error:
            self.write_error_json(error.code, error.status, code=error.code)
        finally:
            db.close()


class OtherApprovalAiHandler(BaseHandler):
    """POST /api/admin/reviews/{type}/{id}/ai-review; writes audit only."""

    async def post(self, review_type, target_id):
        reviewer = self.require_admin()
        if not reviewer:
            return
        import config
        target_id = int(target_id)
        model = config.OPENAI_REVIEW_MODEL
        error_code = None
        result = None
        db = get_db()
        try:
            facts = load_review_facts(db, review_type, target_id,
                                      int(reviewer["user_id"]), reviewer["role"])
            payload, aliases = build_model_input(facts)
        except ReviewFactsError as error:
            error_code, status = error.code, error.status
        except (ValueError, KeyError, TypeError):
            error_code, status = "review_input_invalid", 409
        except Exception:
            error_code, status = "review_facts_unavailable", 503
        finally:
            db.close()
        if not error_code:
            try:
                raw = await asyncio.to_thread(generate_review, facts=payload,
                    api_key=config.OPENAI_API_KEY, model=model,
                    timeout=float(config.OPENAI_REVIEW_TIMEOUT_SEC))
                result = review_response(facts, raw, aliases, model)
            except MissingApiKeyError:
                error_code, status = "key_not_configured", 503
            except ModelRefusalError:
                error_code, status = "model_refusal", 502
            except ModelTimeoutError:
                error_code, status = "model_timeout", 504
            except ModelOutputError as error:
                error_code = "evidence_ref_invalid" if "evidence" in str(error) else "model_schema_invalid"
                status = 502
            except (ReviewTransportError, OSError):
                error_code, status = "openai_error", 502
            except (ValueError, TypeError, KeyError):
                error_code, status = "model_schema_invalid", 502
        audit_db = get_db()
        try:
            audit_log(audit_db, AuditEvent.OTHER_APPROVAL_AI_REVIEW,
                user_id=reviewer["user_id"], request_id=self.request_id,
                details={"review_type": review_type, "target_id": target_id,
                         "reviewer_id": reviewer["user_id"],
                         "status": "failed" if error_code else "succeeded",
                         "error_code": error_code, "model": model}, severity=2)
        finally:
            audit_db.close()
        if error_code:
            self.write_error_json(error_code, status, code=error_code)
        else:
            self.write_json(result)


class EmergencyAuditCandidatesHandler(BaseHandler):
    """GET concrete Break-Glass use events as review candidates, with no threshold."""

    def get(self):
        reviewer = self.require_admin()
        if not reviewer:
            return
        db = get_db()
        try:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = db.execute(
                "SELECT a.id, a.created_at, a.details->>'activation_id' AS activation_id "
                "FROM audit_logs a WHERE a.event_type='BREAK_GLASS_USED' "
                "AND EXISTS (SELECT 1 FROM break_glass_activations b "
                "WHERE b.id::text=a.details->>'activation_id' AND b.activator_id=a.user_id) "
                "ORDER BY a.id DESC LIMIT 100"
            ).fetchall()
            self.write_json({"candidates": [{"kind": "emergency_access", "audit_id": r["id"],
                "observed_at": r["created_at"].isoformat(),
                "activation_id": int(r["activation_id"])} for r in rows],
                "truncated_at": 100 if len(rows) == 100 else None})
        finally:
            db.close()


class RepeatedUnassignedCandidatesHandler(BaseHandler):
    """GET verified pairs of nonassigned clicks within an existing session."""

    def get(self):
        reviewer = self.require_admin()
        if not reviewer:
            return
        db = get_db()
        try:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            rows = db.execute(
                "SELECT later.id, later.created_at, prior.id AS prior_id "
                "FROM audit_logs later JOIN LATERAL ("
                "SELECT p.id FROM audit_logs p WHERE p.event_type='UNASSIGNED_CASE_CLICK' "
                "AND p.user_id=later.user_id AND p.id<later.id "
                "AND COALESCE(p.details->>'session_id','')=later.details->>'session_id' "
                "ORDER BY p.id DESC LIMIT 1) prior ON TRUE "
                "WHERE later.event_type='UNASSIGNED_CASE_CLICK' "
                "AND later.user_id IS NOT NULL "
                "AND COALESCE(later.details->>'session_id','')<>'' "
                "ORDER BY later.id DESC LIMIT 100"
            ).fetchall()
            self.write_json({"candidates": [{"kind": "repeated_unassigned_click",
                "audit_ids": [r["prior_id"], r["id"]],
                "observed_at": r["created_at"].isoformat()} for r in rows],
                "truncated_at": 100 if len(rows) == 100 else None})
        finally:
            db.close()
