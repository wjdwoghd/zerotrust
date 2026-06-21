"""
정책 엔진
규칙 기반 즉시 차단 조건 및 강제 재인증 조건 평가
"""


def check_immediate_block(context: dict) -> dict:
    """
    즉시 차단 규칙 검사
    context keys:
      - concurrent_session, device_mismatch,
        auth_failure, location_allowed, device_registered,
        sensitivity_grade, download_attempt, impossible_travel
    Returns: {"blocked": bool, "rule": str, "reason": str}

    매칭 우선순위 (위에서 아래로):
      1) CONCURRENT_DEVICE_AUTH   — 동시접속 + 단말불일치 + 인증실패 AND
      2) HIGH_RISK_DOWNLOAD       — 비허용위치 + 미등록단말 + sens≥4 + 다운로드 AND
      3) IMPOSSIBLE_TRAVEL        — 물리적 이동 불가 단일 신호
      4) LOCATION_NOT_ALLOWED     — 비허용 위치 단일 신호 (정책 갱신)

    참고: 룰 2 가 룰 4 보다 위에 위치하므로, 비허용 위치 + 미등록단말 +
    sens≥4 + 다운로드 조합은 더 구체적인 HIGH_RISK_DOWNLOAD 로 매칭된다.
    그 외의 비허용 위치 케이스는 룰 4 로 단일 차단된다. 동시 로그인
    정책과의 통합(세션 pending_reauth 마킹)은 access_evaluator 측에서
    rule 이 IMPOSSIBLE_TRAVEL / LOCATION_NOT_ALLOWED 일 때 수행한다.
    """
    # 규칙 1: 동시접속 + 단말 불일치 + 인증 실패
    if (context.get("concurrent_session") and
            context.get("device_mismatch") and
            context.get("auth_failure")):
        return {
            "blocked": True,
            "rule": "CONCURRENT_DEVICE_AUTH",
            "reason": "동시접속 + 단말 불일치 + 인증 실패 - 즉시 차단"
        }

    # 규칙 2: 비허용 위치 + 미등록 단말 + 4등급 이상 + 다운로드
    # (룰 4 보다 더 구체적인 조합 — 먼저 매칭되어야 한다)
    if (not context.get("location_allowed", True) and
            not context.get("device_registered", True) and
            context.get("sensitivity_grade", 1) >= 4 and
            context.get("download_attempt")):
        return {
            "blocked": True,
            "rule": "HIGH_RISK_DOWNLOAD",
            "reason": "비허용위치 + 미등록단말 + 고민감자료 다운로드 - 즉시 차단"
        }

    # 규칙 3: 비현실적 위치 전환
    if context.get("impossible_travel"):
        return {
            "blocked": True,
            "rule": "IMPOSSIBLE_TRAVEL",
            "reason": "비현실적 위치 전환 감지 - 세션 잠금"
        }

    # 규칙 4: 비허용 위치 단일 신호 (정책 갱신 — 동시 로그인 대응과 통일)
    # 시뮬 패널 등에서 위치를 비허용 값으로 변경한 순간 그 세션은
    # 신뢰 보류 상태가 되어야 한다는 정책. access_evaluator 가 이 rule
    # 매칭을 받아 sessions.pending_reauth=TRUE 를 세운다.
    if not context.get("location_allowed", True):
        return {
            "blocked": True,
            "rule": "LOCATION_NOT_ALLOWED",
            "reason": "허용되지 않은 위치 접근 - 세션 잠금"
        }

    return {"blocked": False, "rule": None, "reason": None}


def check_force_reauth(context: dict) -> dict:
    """
    강제 재인증 필요 조건 검사
    Returns: {"reauth_required": bool, "reason": str}
    """
    # 단말 변경 감지
    if context.get("device_changed"):
        return {
            "reauth_required": True,
            "reason": "세션 중 단말 변경 감지 - 재인증 필요"
        }

    # 고민감(4-5등급) + 비담당 사건
    if (context.get("sensitivity_grade", 1) >= 4 and
            not context.get("is_assigned_case")):
        return {
            "reauth_required": True,
            "reason": "고민감 자료 비담당 접근 - 재인증 또는 관리자 승인 필요"
        }

    # 위치 변경
    if context.get("location_changed"):
        return {
            "reauth_required": True,
            "reason": "접속 위치 변경 감지 - 재인증 필요"
        }

    return {"reauth_required": False, "reason": None}


def check_admin_approval_required(context: dict) -> bool:
    """관리자 승인 필요 여부"""
    # 4-5등급 + 비담당 사건
    if (context.get("sensitivity_grade", 1) >= 4 and
            not context.get("is_assigned_case") and
            not context.get("same_department")):
        return True

    # 리소스 자체가 승인 필요로 설정
    if context.get("requires_approval"):
        return True

    return False


# ─── §5-3 PO-01~10 호환 adapter ──────────────────────────────────
def check(context: dict) -> dict:
    """
    스펙(§5-3 PO) 호환 어댑터.

    context keys (모두 optional):
      - resource_sensitivity (or sensitivity_grade): int (1~5)
      - user_role: "admin"|"user"|...
      - hour_of_day: int (0~23)  # 업무시간 = 06~22
      + 기존 check_immediate_block / check_force_reauth 가 쓰는 키들

    Returns: {"ok": bool, "rule": str|None, "reason": str|None}
    """
    sens = int(context.get("resource_sensitivity",
                           context.get("sensitivity_grade", 3)))
    role = str(context.get("user_role", "user")).lower()

    # 규칙 A: 민감도 5 — admin 만 접근 가능
    if sens >= 5 and role != "admin":
        return {
            "ok": False,
            "rule": "sensitivity_5_admin_only",
            "reason": "최고 민감도 자원은 관리자만 접근 가능합니다.",
        }

    # 규칙 B: 업무시간 (06:00~22:00) 외 접근 — 민감도 4 이상이면 차단
    hour = context.get("hour_of_day")
    if hour is not None:
        h = int(hour)
        if (h < 6 or h >= 22) and sens >= 4:
            return {
                "ok": False,
                "rule": "business_hours",
                "reason": f"업무시간 외({h}시) 고민감 자원 접근 제한",
            }

    # 규칙 C: 기존 즉시차단 규칙 재사용
    blk = check_immediate_block({
        "concurrent_session": context.get("concurrent_session"),
        "device_mismatch": context.get("device_mismatch"),
        "auth_failure": context.get("auth_failure"),
        "location_allowed": context.get("location_allowed", True),
        "device_registered": context.get("device_registered", True),
        "sensitivity_grade": sens,
        "download_attempt": context.get("download_attempt"),
        "impossible_travel": context.get("impossible_travel"),
    })
    if blk.get("blocked"):
        return {"ok": False, "rule": blk["rule"], "reason": blk["reason"]}

    return {"ok": True, "rule": None, "reason": None}
