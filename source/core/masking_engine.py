"""
마스킹 엔진
접근 결정 레벨에 따른 정보 마스킹 수준 결정 및 적용
"""
import re

from core.decision_engine import get_action_permissions


MASKING_LEVELS = {
    1: {"name": "없음", "description": "전체 정보 열람 가능"},
    2: {"name": "워터마크", "description": "열람 가능, 다운로드/복사 차단, 워터마크 표시"},
    3: {"name": "부분 마스킹", "description": "이름/사건번호 부분 가림"},
    4: {"name": "요약만 표시", "description": "상세 내용 숨김, 요약 정보만 표시"},
    5: {"name": "완전 차단", "description": "내용 접근 불가"},
}


def get_masking_level(decision_level: int) -> dict:
    return MASKING_LEVELS.get(decision_level, MASKING_LEVELS[5])


def mask_name(name: str) -> str:
    """이름 마스킹: 김OO"""
    if not name or len(name) < 2:
        return "O" * max(len(name), 1)
    return name[0] + "O" * (len(name) - 1)


def mask_case_number(case_number: str) -> str:
    """사건번호 마스킹: 2026-XXXX-0001 → 2026-XXXX-****"""
    if not case_number or len(case_number) < 4:
        return "****"
    return case_number[:-4] + "****"


def mask_id_number(id_number: str) -> str:
    """주민번호 마스킹: 900101-1234567 → 900101-*******"""
    if '-' in id_number:
        front, back = id_number.split('-', 1)
        return front + '-' + '*' * len(back)
    if len(id_number) > 6:
        return id_number[:6] + '*' * (len(id_number) - 6)
    return '*' * len(id_number)


def mask_phone(phone: str) -> str:
    """전화번호 마스킹: 010-1234-5678 → 010-****-5678"""
    cleaned = re.sub(r'[^0-9]', '', phone)
    if len(cleaned) >= 10:
        return cleaned[:3] + '-****-' + cleaned[-4:]
    return '****'


def mask_content(content: str, level: int) -> str:
    """본문 마스킹 적용"""
    if level == 1:
        return content
    elif level == 2:
        return content  # 워터마크는 프론트에서 처리
    elif level == 3:
        # 부분 마스킹: 이름 패턴, 전화번호 패턴
        masked = re.sub(r'[가-힣]{2,4}(?=\s*(씨|님|경찰관|형사|수사관))',
                        lambda m: mask_name(m.group()), content)
        masked = re.sub(r'01[016789]-?\d{3,4}-?\d{4}',
                        lambda m: mask_phone(m.group()), masked)
        masked = re.sub(r'\d{6}-\d{7}',
                        lambda m: mask_id_number(m.group()), masked)
        return masked
    elif level == 4:
        # 요약만 표시
        lines = content.split('\n')
        if len(lines) > 3:
            return '\n'.join(lines[:3]) + '\n\n[상세 내용은 권한 승인 후 열람 가능합니다]'
        return content[:200] + '\n\n[상세 내용은 권한 승인 후 열람 가능합니다]'
    else:
        return "[접근 권한이 없습니다. 관리자에게 문의하세요.]"


def apply_masking(resource: dict, decision_level: int, user_name: str = "") -> dict:
    """리소스에 마스킹 적용하여 반환"""
    masking = get_masking_level(decision_level)
    result = dict(resource)

    result["masking_level"] = decision_level
    result["masking_name"] = masking["name"]
    result["masking_description"] = masking["description"]
    result["watermark"] = user_name if decision_level == 2 else None
    # 행동 권한은 decision_engine 의 레벨별 매트릭스와 단일화한다.
    permissions = get_action_permissions(decision_level)
    result.update(permissions)

    if decision_level >= 5:
        result["content"] = "[접근이 차단되었습니다]"
        result["description"] = "[접근이 차단되었습니다]"
        return result

    if "content" in result and result["content"]:
        result["content"] = mask_content(result["content"], decision_level)

    if decision_level >= 3:
        if "case_number" in result:
            result["case_number"] = mask_case_number(result.get("case_number", ""))

    return result


# ─── §5-3 MK-01~06 호환 adapter ──────────────────────────────────
def _mask_account(account: str) -> str:
    """계좌번호 마스킹: 110-123-456789 → 110-123-******"""
    parts = account.split("-")
    if len(parts) >= 2:
        last = parts[-1]
        parts[-1] = "*" * len(last)
        return "-".join(parts)
    if len(account) > 4:
        return account[:-4] + "****"
    return "****"


def mask_text(text: str) -> str:
    """
    스펙(§5-3 MK) 호환 어댑터.

    패턴 기반으로 민감 정보(주민번호·전화번호·계좌번호)를 마스킹한다.
    일반 평문은 그대로 통과한다.
    """
    if not text:
        return text

    # 1) 주민등록번호 — 6자리 + 7자리
    text = re.sub(
        r"\d{6}-\d{7}",
        lambda m: mask_id_number(m.group()),
        text,
    )
    # 2) 휴대전화 — 01X-XXXX-XXXX
    text = re.sub(
        r"01[016789]-?\d{3,4}-?\d{4}",
        lambda m: mask_phone(m.group()),
        text,
    )
    # 3) 계좌번호 — 3자리 이상-3자리 이상-6자리 이상
    text = re.sub(
        r"\d{3,}-\d{3,}-\d{6,}",
        lambda m: _mask_account(m.group()),
        text,
    )
    return text
