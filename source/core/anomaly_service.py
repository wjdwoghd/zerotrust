"""
이상행동 탐지 서비스
세션 내 누적형 행위 분석
"""
from database import get_db


# 탐지 기준 상수
RATE_LIMIT_WINDOW = 300    # 5분
RATE_LIMIT_THRESHOLD = 5   # 5분 내 5회: 주의 단계
HIGH_RISK_RATE_LIMIT_THRESHOLD = 10  # 5분 내 10회: 위험 단계
BULK_QUERY_THRESHOLD = 20  # 대량 조회 기준


def get_recent_access_count(user_id: int, window_seconds: int = RATE_LIMIT_WINDOW) -> int:
    """최근 N초 내 접근 횟수 조회.

    ITEM 9 (감사 #9): 기존엔 time.localtime(time.time()-N) 으로 만든 naive
    로컬 TZ 문자열을 PG TIMESTAMPTZ 와 비교 → KST 서버 + UTC PG 세션이면
    cutoff 가 9h 미래로 해석돼 카운트가 항상 0. 시간 계산을 SQL 측으로
    옮겨 TZ 함정을 제거한다.
    """
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM access_logs "
        "WHERE user_id=? "
        "  AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 second' * ?",
        (user_id, int(window_seconds))
    ).fetchone()
    db.close()
    return row["cnt"] if row else 0


def get_session_access_count(session_id: int) -> int:
    """현재 세션 내 총 접근 횟수"""
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM access_logs WHERE session_id=?",
        (session_id,)
    ).fetchone()
    db.close()
    return row["cnt"] if row else 0


def check_concurrent_sessions(user_id: int, current_session_id: int) -> bool:
    """동시 접속 여부 확인"""
    db = get_db()
    rows = db.execute(
        "SELECT id FROM sessions WHERE user_id=? AND is_active AND id!=?",
        (user_id, current_session_id)
    ).fetchall()
    db.close()
    return len(rows) > 0


def detect_anomalies(user_id: int, session_id: int, action_type: str = "view",
                     device_id: str = None, session_device: str = None) -> dict:
    """
    종합 이상행동 탐지
    Returns: {
        "anomaly_detected": bool,
        "anomaly_types": [...],
        "risk_addition": float,
        "details": str
    }
    """
    anomalies = []
    risk_addition = 0

    # 1. 고빈도 접근
    # 제로트러스트 시연과 실제 운영을 모두 고려해 2단계로 탐지한다.
    # - 5분 내 5회 이상: 산발적/탐색성 접근으로 주의(+10)
    # - 5분 내 10회 이상: 명확한 고빈도 접근으로 위험(+20)
    recent_count = get_recent_access_count(user_id)
    if recent_count >= HIGH_RISK_RATE_LIMIT_THRESHOLD:
        anomalies.append({
            "type": "HIGH_FREQUENCY_CRITICAL",
            "detail": f"5분 내 {recent_count}회 접근(위험)",
            "score": 20
        })
        risk_addition += 20
    elif recent_count >= RATE_LIMIT_THRESHOLD:
        anomalies.append({
            "type": "HIGH_FREQUENCY",
            "detail": f"5분 내 {recent_count}회 접근(주의)",
            "score": 10
        })
        risk_addition += 10

    # 2. 대량 조회
    session_count = get_session_access_count(session_id) if session_id else 0
    if session_count >= BULK_QUERY_THRESHOLD:
        anomalies.append({
            "type": "BULK_QUERY",
            "detail": f"세션 내 {session_count}건 조회",
            "score": 20
        })
        risk_addition += 20

    # 3. 다운로드/복사 시도
    if action_type == "download":
        anomalies.append({
            "type": "DOWNLOAD_ATTEMPT",
            "detail": "다운로드 시도",
            "score": 10
        })
        risk_addition += 10
    elif action_type == "copy":
        anomalies.append({
            "type": "COPY_ATTEMPT",
            "detail": "복사 시도",
            "score": 10
        })
        risk_addition += 10

    # 4. 단말 불일치
    device_mismatch = False
    if device_id and session_device and device_id != session_device:
        device_mismatch = True
        anomalies.append({
            "type": "DEVICE_MISMATCH",
            "detail": f"세션 단말({session_device}) != 현재 단말({device_id})",
            "score": 20
        })
        risk_addition += 20

    # 5. 동시접속
    concurrent = check_concurrent_sessions(user_id, session_id) if session_id else False
    if concurrent:
        anomalies.append({
            "type": "CONCURRENT_SESSION",
            "detail": "다중 세션 감지",
            "score": 15
        })
        risk_addition += 15

    return {
        "anomaly_detected": len(anomalies) > 0,
        "anomaly_types": [a["type"] for a in anomalies],
        "anomalies": anomalies,
        "risk_addition": risk_addition,
        "concurrent_session": concurrent,
        "device_mismatch": device_mismatch,
        "details": "; ".join(a["detail"] for a in anomalies) if anomalies else "이상 없음",
        # ── 점수와 분리된 원시 카운트/플래그 (scoring_engine 전용) ──
        "recent_access_count": recent_count,
        "session_access_count": session_count,
        "download_attempt": action_type == "download",
        "copy_attempt": action_type == "copy",
    }


# ─── §5-3 AN-03~04 호환 adapter ──────────────────────────────────
def detect_concurrent_device(sessions: list) -> bool:
    """
    동시 디바이스 감지 (순수 함수, DB 미접근).

    sessions: [{"device_id": str, "active": bool}, ...]
    서로 다른 device_id 가 2개 이상 active 이면 True.
    """
    if not sessions:
        return False
    active_devices = {
        s.get("device_id")
        for s in sessions
        if s.get("active") and s.get("device_id") is not None
    }
    return len(active_devices) >= 2


def detect_high_risk_download(
    recent_downloads: int,
    time_window_min: int = 10,
    threshold: int = 20,
) -> bool:
    """
    고위험 대량 다운로드 감지 (순수 함수).

    시간 창(time_window_min) 내 다운로드 횟수가 threshold 이상이면 True.
    time_window_min 은 현재 단순 검증용 파라미터로만 사용된다.
    """
    if threshold <= 0:
        return False
    return int(recent_downloads) >= int(threshold)
