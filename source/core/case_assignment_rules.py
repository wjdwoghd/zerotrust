from __future__ import annotations

import json
from typing import Any


JOB_TAG_LABELS = {
    "violent_crime": "강력범죄",
    "drug": "마약",
    "organized_crime": "조직범죄",
    "cyber": "사이버",
    "forensic": "포렌식",
    "traffic": "교통",
    "national_security": "안보",
    "patrol": "생활안전/순찰",
    "infosec": "정보보안",
    "audit": "감사",
}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _clean_set(value: Any) -> set[str]:
    return {str(v).strip() for v in _as_list(value) if str(v).strip()}


def _tag_payload(tag: str) -> dict:
    return {"value": tag, "label": JOB_TAG_LABELS.get(tag, tag)}


def assignment_compatibility(user: dict, resource: dict) -> tuple[bool, str | None]:
    """Return whether a user can own a resource as an assigned case."""
    user_department = str(user.get("department") or "").strip()
    resource_department = str(resource.get("department") or "").strip()
    if not user_department or not resource_department:
        return False, "사용자 또는 사건의 담당 부서 정보가 없어 담당 사건으로 등록할 수 없습니다."
    if user_department != resource_department:
        return False, "담당 사건은 사용자 소속 부서와 사건 담당 부서가 일치해야 등록할 수 있습니다."

    user_scope = _clean_set(user.get("job_scope"))
    resource_tags = _clean_set(resource.get("job_tags"))
    if resource_tags and not (user_scope & resource_tags):
        return False, "사용자 직무 범위와 사건 직무 태그가 일치하지 않아 담당 사건으로 등록할 수 없습니다."

    return True, None


def assignment_guidance(user: dict, resource: dict) -> dict:
    """Return safe, user-facing guidance for failed assignment compatibility."""
    user_scope = sorted(_clean_set(user.get("job_scope")))
    resource_tags = sorted(_clean_set(resource.get("job_tags")))
    missing_tags = sorted(set(resource_tags) - set(user_scope))
    matching_tags = sorted(set(resource_tags) & set(user_scope))
    user_department = str(user.get("department") or "").strip()
    resource_department = str(resource.get("department") or "").strip()

    guidance = None
    if user_department and resource_department and user_department != resource_department:
        guidance = (
            f"사용자 소속 부서를 사건 담당 부서({resource_department})와 일치시키거나, "
            "해당 부서 소속 계정으로 담당 사건 등록을 요청해야 합니다."
        )
    elif resource_tags and not matching_tags:
        required = ", ".join(
            f"{JOB_TAG_LABELS.get(tag, tag)}({tag})" for tag in resource_tags
        )
        guidance = (
            "관리자가 계정을 만들 때 직무 카테고리에서 "
            f"{required} 중 하나 이상을 선택해야 이 사건을 담당 사건으로 등록할 수 있습니다."
        )

    return {
        "user_department": user_department,
        "resource_department": resource_department,
        "user_job_scope": [_tag_payload(tag) for tag in user_scope],
        "resource_job_tags": [_tag_payload(tag) for tag in resource_tags],
        "missing_job_scope": [_tag_payload(tag) for tag in missing_tags],
        "matching_job_scope": [_tag_payload(tag) for tag in matching_tags],
        "guidance": guidance,
    }
