"""Authenticated administrator endpoint for transient synthetic policy experiments."""

import asyncio
import json

from tornado.escape import json_decode

from api.base_handler import BaseHandler
from core.ai_policy_challenger import (
    UnsupportedExperimentGoalError, _validated_allowed_values,
    run_configured_challenge,
)
from core.audit_events import AuditEvent, audit_log
from database import get_db
from integrations.openai_scenario_client import (
    MissingApiKeyError, ModelOutputError, ModelRefusalError,
    ModelTimeoutError, ScenarioGenerationError,
)


ERRORS = {
    "invalid_request": (400, "요청 형식 또는 허용값이 올바르지 않습니다."),
    "unsupported_goal": (400, "이 목표는 현재 시뮬레이터에서 지원하지 않습니다."),
    "key_not_configured": (503, "AI 실험 서비스 키가 설정되지 않았습니다."),
    "model_refusal": (502, "모델이 합성 시나리오 생성을 거부했습니다."),
    "model_timeout": (504, "AI 실험 서비스 응답 시간이 초과되었습니다."),
    "model_output_invalid": (502, "AI 출력 형식이 올바르지 않습니다."),
    "model_output_out_of_range": (502, "AI 출력이 허용 범위를 벗어났습니다."),
    "openai_error": (502, "AI 실험 서비스 호출에 실패했습니다."),
}


def validate_request(body):
    """Accept only a fixed goal, bounded count and narrowed synthetic domains."""
    if not isinstance(body, dict) or set(body) - {"goal", "count", "allowed_values"}:
        raise ValueError("invalid fields")
    goal = body.get("goal")
    if goal == "approval_path":
        raise UnsupportedExperimentGoalError("approval_path")
    if goal not in ("boundary", "immediate_block"):
        raise ValueError("invalid goal")
    count = body.get("count")
    if type(count) is not int or not 1 <= count <= 8:
        raise ValueError("invalid count")
    allowed = body.get("allowed_values")
    _validated_allowed_values(allowed)
    return goal, count, allowed


class PolicyLabChallengeHandler(BaseHandler):
    """Run a one-time synthetic challenge; never accepts real resource identifiers."""

    async def post(self):
        actor = self.require_admin()
        if actor is None:
            return

        goal = None
        count = None
        error_code = None
        result = None
        try:
            body = json_decode(self.request.body)
            # Only safe, fixed values enter the audit trail even for rejected requests.
            if isinstance(body, dict):
                if body.get("goal") in ("boundary", "immediate_block", "approval_path"):
                    goal = body["goal"]
                if type(body.get("count")) is int and 1 <= body["count"] <= 8:
                    count = body["count"]
            goal, count, allowed = validate_request(body)
            result = await asyncio.to_thread(
                run_configured_challenge,
                goal=goal, count=count, allowed_values=allowed,
            )
        except UnsupportedExperimentGoalError:
            error_code = "unsupported_goal"
        except (ValueError, TypeError, json.JSONDecodeError):
            error_code = "invalid_request"
        except MissingApiKeyError:
            error_code = "key_not_configured"
        except ModelRefusalError:
            error_code = "model_refusal"
        except ModelTimeoutError:
            error_code = "model_timeout"
        except ModelOutputError as error:
            error_code = (
                "model_output_out_of_range"
                if "outside allowed_values" in str(error) or "server validation" in str(error)
                else "model_output_invalid"
            )
        except ScenarioGenerationError:
            error_code = "openai_error"
        except Exception:
            error_code = "openai_error"

        db = get_db()
        try:
            audit_log(
                db, AuditEvent.POLICY_LAB_CHALLENGE,
                user_id=actor["user_id"], request_id=self.request_id,
                details={"goal": goal, "count": count,
                         "status": "failed" if error_code else "succeeded",
                         "error_code": error_code},
                severity=2,
            )
        finally:
            db.close()
        if error_code:
            status, message = ERRORS[error_code]
            self.write_error_json(message, status, code=error_code)
        else:
            self.write_json(result)
