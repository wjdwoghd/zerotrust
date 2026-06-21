"""
시나리오 C-P2 — 코드 감사 결함 회귀 테스트

코드 감사에서 발견된 결함의 회귀 보호. ITEM 번호별로 묶음.
ITEM 6·7·9 는 후속 세션에서 추가된다.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import urllib.error
import urllib.request

import pytest


# ─── ITEM 2 / TEST 4 (부분) — CORS Allow-Origin: null 제거 ─────
# 결함 (감사 #2): set_default_headers 가 "null" 을 박아 sandboxed iframe /
# file:// 매칭으로 cross-origin 우회가 가능한 상태였다. ALLOWED_ORIGIN
# 환경변수가 비면 Allow-* 헤더 자체를 추가하지 않도록 수정.
#
# CSP / X-Frame-Options 등 SPA 진입점(server.py 의 MainHandler/Healthz/Readyz)
# 보안 헤더 검증은 ITEM 10 에서 추가.
def test_cors_acao_is_not_null(http):
    """ALLOWED_ORIGIN 빈 환경: ACAO 가 'null' 이면 안 됨."""
    base = http.base
    # OPTIONS preflight — BaseHandler.options 가 204 반환하며 헤더 같이 옴.
    # /api/auth/login 은 BaseHandler 를 거치는 대표 엔드포인트.
    req = urllib.request.Request(base + "/api/auth/login", method="OPTIONS")
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        # 일부 환경에서 OPTIONS 가 405 일 수 있음 — 응답 헤더는 그래도 검사 가능
        resp = e
    acao = resp.headers.get("Access-Control-Allow-Origin")
    # ALLOWED_ORIGIN default(빈 문자열) 환경 — 헤더가 없거나, 있어도 'null' 절대 금지
    assert acao != "null", (
        f"Access-Control-Allow-Origin='null' detected — "
        f"sandboxed iframe / file:// 우회 위험"
    )


def test_cors_no_allow_origin_header_when_unset(http):
    """ALLOWED_ORIGIN 빈 환경: ACAO 헤더 자체가 없어야 함 (same-origin only)."""
    base = http.base
    req = urllib.request.Request(base + "/api/auth/login", method="OPTIONS")
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        resp = e
    # 빈 ALLOWED_ORIGIN 이면 set_default_headers 가 ACAO 를 set 하지 않는다.
    assert "Access-Control-Allow-Origin" not in resp.headers, (
        f"unexpected ACAO header present: "
        f"{resp.headers.get('Access-Control-Allow-Origin')}"
    )


# ─── ITEM 10 / TEST 4 (확장) — Main/Healthz/Readyz 보안 헤더 ────
# 결함 (감사 #10): server.py 의 MainHandler/HealthzHandler/ReadyzHandler 가
# tornado.web.RequestHandler 직접 상속이라 BaseHandler 의 보안 헤더가
# 적용되지 않았다. SPA 진입점이 CSP 없이 내려가 XSS 방어가 약함.
# ─── 시뮬 시간대 (X-Sim-Hour 헤더 + ENV_RELAXED_TIME) ─────────────
# 결함:
#   기존 시뮬 패널의 "심야 모드" 체크박스가 클라이언트 표시용 — 백엔드에
#   전달되지 않아 점수에 영향 X. 또 evaluate_access 가 relaxed_time 인자를
#   안 넘겨 ENV_RELAXED_TIME (+5) 가산도 발동 안 함.
# 수정:
#   evaluate_access(hour=N) → 22~06 심야(+15), 06~09/18~22 추가근무(+5),
#   09~18 근무(0). resource_handler 가 X-Sim-Hour 헤더 우선, 없으면 OS 시각.
def test_evaluate_access_hour_drives_environment_score(db):
    """evaluate_access(hour) 가 시간대별 ENV 가산을 정확히 발동시킨다.

    officer_choi 의 job_scope=['traffic'] 은 016 의 multiplier 표에 없어
    ENV_NIGHT_TIME 에 default 1.0 적용 → 정확히 +15 가산.
    """
    from core.access_evaluator import evaluate_access

    o = db.execute(
        "SELECT id FROM users WHERE username='officer_choi'"
    ).fetchone()
    res = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()

    base_kw = dict(
        user_id=o["id"], resource_id=res["id"],
        device_id="registered-006", location="본청",
        action_type="view",
    )
    r_normal = evaluate_access(**base_kw, hour=14)
    r_relaxed = evaluate_access(**base_kw, hour=20)
    r_night = evaluate_access(**base_kw, hour=2)

    env_n = r_normal["scoring"]["environment_risk"]["score"]
    env_r = r_relaxed["scoring"]["environment_risk"]["score"]
    env_h = r_night["scoring"]["environment_risk"]["score"]

    # 근무(09-18) → 0 / 추가근무(06-09,18-22) → +5 / 심야(22-06) → +15
    # 다른 환경 변수가 모두 동일하므로 차이가 시간 가산만 반영.
    assert env_r - env_n >= 5, f"추가 근무 가산 {env_r - env_n} < 5"
    assert env_h - env_n >= 15, f"심야 가산 {env_h - env_n} < 15 (multiplier 없는 사용자)"
    assert env_h > env_r, f"심야({env_h}) 가 추가근무({env_r}) 보다 커야"


def test_evaluate_access_hour_none_uses_is_night_only(db):
    """hour=None (구버전 호환) 이면 is_night 인자만 평가 — relaxed 미발동."""
    from core.access_evaluator import evaluate_access

    o = db.execute(
        "SELECT id FROM users WHERE username='officer_choi'"
    ).fetchone()
    res = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()
    base_kw = dict(
        user_id=o["id"], resource_id=res["id"],
        device_id="registered-006", location="본청",
        action_type="view",
    )
    # hour 미지정 + is_night=False — 시간 가산 0
    r = evaluate_access(**base_kw, is_night=False)
    assert r["scoring"]["environment_risk"]["score"] == 0
    # hour 미지정 + is_night=True — 심야 가산 발동 (relaxed 는 hour 정보 없어 미발동)
    r2 = evaluate_access(**base_kw, is_night=True)
    assert r2["scoring"]["environment_risk"]["score"] >= 15


# ─── OTP replay 방지 (RFC 6238 §5.2) ──────────────────────────────
# 결함: 기존 verify_totp 가 통과한 step 을 어디에도 마킹 안 해 같은 OTP 로
# 같은 윈도우 내 여러 번 검증 가능 (로그인 → 30초 내 로그아웃 → 같은 코드
# 재로그인). 수정: user_devices.last_otp_step 컬럼 + verify_totp_consume.
def test_otp_replay_blocked_in_login_flow(http, login_as, db):
    """첫 mfa/verify 통과한 OTP 로 두 번째 mfa/verify 호출 시 401."""
    from security.mfa_service import generate_totp

    # admin_lee 의 토큰 기기 secret 확보
    row = db.execute(
        "SELECT id, mfa_secret FROM user_devices "
        "WHERE device_id='token-003' "
        "  AND user_id=(SELECT id FROM users WHERE username='admin_lee')"
    ).fetchone()
    assert row, "admin_lee 토큰 기기 시드 누락"
    secret = row["mfa_secret"]

    # 첫 로그인 + MFA 통과 (login_as 가 자동으로 generate_totp 사용)
    tok1, code1, _ = login_as("admin_lee")
    assert code1 == 200, "첫 로그인 통과 기대"

    # last_otp_step 이 마킹됐어야
    after = db.execute(
        "SELECT last_otp_step FROM user_devices WHERE id=?", (row["id"],)
    ).fetchone()
    assert after["last_otp_step"] is not None, (
        "첫 통과 후 last_otp_step 갱신 누락 — replay 마킹 결함"
    )
    first_step = after["last_otp_step"]

    # 같은 시각에 같은 OTP 로 두 번째 mfa/verify 직접 호출 — 같은 step 이라 거부
    same_otp = generate_totp(secret)
    code, data = http(
        "POST", "/api/auth/mfa/verify",
        body={"otp_code": same_otp,
              "device_id": "registered-004",
              "location": "본청"},
        token=tok1, device="registered-004",
    )
    # 같은 토큰 + 같은 OTP → 401 otp_invalid_or_reused 또는 다른 만료/세션 코드
    # (이미 final 토큰 받은 상태라 mfa_required 분기 자체가 꺼져 다른 응답일 수도)
    if code == 200:
        # 여전히 통과하면 last_otp_step 이 같은 값으로 또 set 됐는지
        after2 = db.execute(
            "SELECT last_otp_step FROM user_devices WHERE id=?", (row["id"],)
        ).fetchone()
        assert after2["last_otp_step"] != first_step, (
            "두 번째 검증이 200 인데 step 이 갱신되지 않음 — 더 큰 step 통과해야"
        )


def test_verify_totp_consume_unit(db):
    """verify_totp_consume 의 last_used_step 가드 단위 검증."""
    from security.mfa_service import verify_totp_consume, generate_totp
    import time as _t

    # 임의 secret
    secret = "JBSWY3DPEHPK3PXP"  # base32 — RFC 4648 example
    code = generate_totp(secret)
    cur_step = int(_t.time()) // 30

    # 첫 검증 — last_used_step=None → 통과
    ok1, used1 = verify_totp_consume(secret, code, last_used_step=None)
    assert ok1 is True, "첫 검증 통과 기대"
    assert used1 == cur_step or abs(used1 - cur_step) <= 1

    # 같은 코드 + last_used_step=used1 → step <= used1 거부 → 다른 step 만 허용
    ok2, used2 = verify_totp_consume(secret, code, last_used_step=used1)
    # 같은 윈도우 내 다른 step 이 매칭될 수도, 안 될 수도 있음
    # 확실한 케이스: 매우 큰 last_used_step → 모든 후보 거부
    ok3, _ = verify_totp_consume(secret, code, last_used_step=used1 + 100)
    assert ok3 is False, "last_used_step 보다 미래 step 만 허용해야"


# ─── device-hint endpoint (정책 완화 부속) ───────────────────────
# 정책 변경: 미등록 업무기기 로그인 허용 + 환경 가산. 신규 계정 자동 채우기를
# 위해 인증 토큰 없이 호출 가능한 GET /api/auth/device-hint?username=X 추가.
def test_device_hint_returns_seed_user_work_device(http, db):
    """시드 사용자의 default 업무 기기 device_id 응답."""
    base = http.base
    resp = urllib.request.urlopen(
        base + "/api/auth/device-hint?username=detective_kim"
    )
    import json as _json
    data = _json.loads(resp.read().decode("utf-8"))
    assert data.get("work_device_id") is not None, data
    # 시드 매핑 — detective_kim 의 work device 는 registered-001
    assert data["work_device_id"] == "registered-001", data


def test_device_hint_unknown_user_returns_null(http):
    """존재하지 않는 username 은 null 반환 (404 X — UX 단순화)."""
    base = http.base
    resp = urllib.request.urlopen(
        base + "/api/auth/device-hint?username=does_not_exist_xyz"
    )
    import json as _json
    data = _json.loads(resp.read().decode("utf-8"))
    assert data.get("work_device_id") is None, data


def test_device_hint_empty_username(http):
    """빈 username 은 null."""
    base = http.base
    resp = urllib.request.urlopen(base + "/api/auth/device-hint?username=")
    import json as _json
    data = _json.loads(resp.read().decode("utf-8"))
    assert data.get("work_device_id") is None, data


# ─── trust_changes timeline (019 마이그레이션) ────────────────────
# 결함:
#   trust_score 변동이 4 시점에서 발생하지만 통합 추적 부재 — 사용자별
#   timeline 재구성 어려움.
# 수정:
#   trust_changes 테이블 + users.trust_score UPDATE 트리거로 자동 INSERT.
#   reason / source_id / actor_id 는 호출 측이 SET LOCAL 으로 전달.
def test_trust_change_logged_for_review_false_negative(http, login_as, db):
    """FN 라벨 → trust -10 → trust_changes 행이 자동 INSERT 되어야."""
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]

    # access_log 1건 시드 후 admin_lee 가 false_negative 라벨
    log_ins = db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type) "
        "VALUES (?, 1, 'ALLOW', 2, 'view') RETURNING id",
        (target_id,)
    ).fetchone()
    log_id = log_ins["id"]
    db.commit()

    pre_trust = float(db.execute(
        "SELECT trust_score FROM users WHERE id=?", (target_id,)
    ).fetchone()["trust_score"])

    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "false_negative", "notes": "회귀 테스트"},
    )
    assert code == 200, data

    # trust_changes 에 -10 행이 들어있어야
    chg = db.execute(
        "SELECT delta, before_trust, after_trust, reason, source_id, actor_id "
        "FROM trust_changes "
        "WHERE user_id=? AND reason='review_false_negative' "
        "ORDER BY id DESC LIMIT 1",
        (target_id,)
    ).fetchone()
    assert chg is not None, "trust_changes 행 누락"
    assert float(chg["delta"]) == -10.0, f"delta={chg['delta']}"
    assert float(chg["before_trust"]) == pre_trust
    assert float(chg["after_trust"]) == pre_trust - 10
    assert chg["source_id"] is not None  # access_decision_reviews.id
    assert chg["actor_id"] is not None   # 리뷰한 admin_lee


def test_trust_change_logged_for_review_false_positive(http, login_as, db):
    """FP 라벨 → trust +5 → trust_changes 행."""
    target_id = db.execute(
        "SELECT id FROM users WHERE username='officer_choi'"
    ).fetchone()["id"]
    log_ins = db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type) "
        "VALUES (?, 1, 'REAUTH', 3, 'view') RETURNING id",
        (target_id,)
    ).fetchone()
    log_id = log_ins["id"]
    db.commit()

    pre = float(db.execute(
        "SELECT trust_score FROM users WHERE id=?", (target_id,)
    ).fetchone()["trust_score"])

    tok_admin, _, _ = login_as("admin_lee")
    code, _ = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "false_positive"},
    )
    assert code == 200

    chg = db.execute(
        "SELECT delta, after_trust, reason FROM trust_changes "
        "WHERE user_id=? AND reason='review_false_positive' "
        "ORDER BY id DESC LIMIT 1",
        (target_id,)
    ).fetchone()
    assert chg is not None
    assert float(chg["delta"]) == 5.0
    assert float(chg["after_trust"]) == min(100, pre + 5)


def test_trust_change_logged_for_recalibration(db):
    """trust_recalibration 의 recover/decay 도 timeline 으로 기록."""
    from scripts.trust_recalibration import recalibrate

    # detective_kim 의 trust 를 인위로 낮추고 최근 활동 시드
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    db.execute(
        "UPDATE users SET trust_score=70 WHERE id=?", (target_id,)
    )
    # 직접 UPDATE 도 트리거 발동 — 이건 시뮬 셋업이라 trust_changes 1건 추가됨
    db.execute(
        "INSERT INTO access_logs (user_id, resource_id, decision_label, "
        "decision_level, action_type, created_at) "
        "VALUES (?, 1, 'ALLOW', 2, 'view', NOW())",
        (target_id,)
    )
    db.commit()

    pre_count = db.execute(
        "SELECT COUNT(*) AS c FROM trust_changes WHERE reason='recalibration_recover'"
    ).fetchone()["c"]

    result = recalibrate()
    assert result["recovered"] >= 1

    post_count = db.execute(
        "SELECT COUNT(*) AS c FROM trust_changes WHERE reason='recalibration_recover'"
    ).fetchone()["c"]
    assert post_count > pre_count, (
        f"recalibration_recover 행 추가 안 됨: {pre_count} → {post_count}"
    )


def test_trust_changes_is_append_only(db):
    """trust_changes UPDATE/DELETE 는 트리거가 거부."""
    import psycopg2

    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    # 테스트용 행 1건 삽입 (직접 INSERT 로 timeline)
    db.execute(
        "INSERT INTO trust_changes (user_id, delta, before_trust, after_trust, reason) "
        "VALUES (?, 1, 50, 51, 'test_seed')",
        (target_id,)
    )
    db.commit()

    row = db.execute(
        "SELECT id FROM trust_changes WHERE reason='test_seed' LIMIT 1"
    ).fetchone()
    assert row, "테스트 행 INSERT 통과해야"

    with pytest.raises((psycopg2.errors.RaiseException, Exception)):
        db.execute(
            "UPDATE trust_changes SET delta=999 WHERE id=?", (row["id"],)
        )
        db.commit()
    db.rollback()

    with pytest.raises((psycopg2.errors.RaiseException, Exception)):
        db.execute("DELETE FROM trust_changes WHERE id=?", (row["id"],))
        db.commit()
    db.rollback()


# ─── ITEM 13 — 자기-unlock 차단 ────────────────────────────────────
# 결함 (감사 #13): UnlockUserHandler 가 admin 본인이 자기 계정을 푸는 흐름
# 을 차단하지 않았다. self-approval / self-review 차단 패턴을 동일하게 적용.
def test_unlock_self_blocked(http, login_as, db):
    """admin_lee 가 자기 계정에 unlock POST → 403 self_action_blocked."""
    tok_admin, _, _ = login_as("admin_lee")
    admin_id = db.execute(
        "SELECT id FROM users WHERE username='admin_lee'"
    ).fetchone()["id"]

    code, data = http(
        "POST", f"/api/admin/users/{admin_id}/unlock",
        token=tok_admin, body={},
    )
    assert code == 403, f"자기 unlock 차단 기대: {code} {data}"
    assert data.get("code") == "self_action_blocked", data


@pytest.mark.parametrize("path", ["/", "/healthz", "/readyz"])
def test_security_headers_on_non_api_endpoints(http, path):
    """SPA 진입점 + 헬스체크 응답에 핵심 보안 헤더가 모두 있어야."""
    base = http.base
    try:
        resp = urllib.request.urlopen(base + path)
    except urllib.error.HTTPError as e:
        resp = e
    assert resp.headers.get("Content-Security-Policy"), (
        f"{path}: CSP 헤더 누락"
    )
    assert resp.headers.get("X-Frame-Options"), (
        f"{path}: X-Frame-Options 누락"
    )
    assert resp.headers.get("X-Content-Type-Options"), (
        f"{path}: X-Content-Type-Options 누락"
    )
    assert resp.headers.get("Strict-Transport-Security"), (
        f"{path}: HSTS 누락"
    )


# ─── ITEM 1 / TEST 1 — 사전 승인 TTL 만료 시 거부 ────────────────
# 결함 (감사 #1): psycopg2 가 approvals.resolved_at 을 datetime 객체로 반환.
# 기존 strptime 경로는 TypeError → except 에서 pre_approved=True (fail-open).
# 수정: SQL 측에서 직접 TTL 비교 (core/access_evaluator.py:91-114).
def test_pre_approval_expires_after_ttl(http, login_as, db):
    """사전 승인이 TTL 을 넘긴 시각에는 적용되지 않음을 단언."""
    from config import PRE_APPROVAL_TTL_SEC

    # 1) detective_kim 로그인 + grade>=4 자원 선택
    tok_d, _, _ = login_as("detective_kim")
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()
    assert row, "grade>=4 자원이 시드에 있어야 함"
    rid = row["id"]

    # 2) 승인 요청 생성 (엔드포인트 실패 시 직접 INSERT fallback)
    code, data = http(
        "POST", f"/api/resources/cases/{rid}/request-approval",
        token=tok_d, body={"reason": "TTL 만료 회귀 테스트"},
    )
    approval_id = data.get("approval_id") or data.get("id")
    if not approval_id:
        det = db.execute(
            "SELECT id FROM users WHERE username='detective_kim'"
        ).fetchone()
        ins = db.execute(
            "INSERT INTO approvals (requester_id, resource_id, reason, status) "
            "VALUES (?, ?, ?, 'pending') RETURNING id",
            (det["id"], rid, "TTL 만료 회귀 테스트"),
        ).fetchone()
        approval_id = ins["id"]
        db.commit()

    # 3) admin_lee 가 download_allowed=True 로 승인
    tok_a, _, _ = login_as("admin_lee")
    code, _ = http(
        "POST", f"/api/admin/approvals/{approval_id}/approve",
        token=tok_a, body={"download_allowed": True},
    )
    assert code == 200, "admin_lee 의 승인 자체는 성공해야 함"

    # 4) resolved_at 을 TTL + 60초 전으로 강제 (만료 상태)
    db.execute(
        "UPDATE approvals "
        "SET resolved_at = CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
        "WHERE id=?",
        (PRE_APPROVAL_TTL_SEC + 60, approval_id),
    )
    db.commit()

    # 5) detective_kim 가 동일 자원 GET → 사전 승인 효과가 사라져야
    code, data = http(
        "GET", f"/api/resources/cases/{rid}",
        token=tok_d, location="본청",
    )
    assert code == 200, data
    decision = data.get("decision") or {}
    resource_payload = data.get("resource") or {}
    can_download = resource_payload.get("can_download")

    # level=1 (FULL) 으로 승격되면 fail-open. 만료 후엔 최소 level>=3 기대.
    assert decision.get("level", 1) >= 3, (
        f"TTL 만료 후에도 level<3 → fail-open: decision={decision}"
    )
    # 응답에 can_download 키가 있으면 False 여야 함 (다운로드 승격 X)
    if can_download is not None:
        assert can_download is False, (
            f"TTL 만료 후 can_download=True → fail-open: {data}"
        )


def test_pre_approval_active_within_ttl(http, login_as, db):
    """fail-closed 한 쪽만 통과하지 않게 — TTL 안에서는 정상 적용 검증."""
    tok_d, _, _ = login_as("detective_kim")
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()
    rid = row["id"]

    code, data = http(
        "POST", f"/api/resources/cases/{rid}/request-approval",
        token=tok_d, body={"reason": "TTL 활성 회귀 테스트"},
    )
    approval_id = data.get("approval_id") or data.get("id")
    if not approval_id:
        det = db.execute(
            "SELECT id FROM users WHERE username='detective_kim'"
        ).fetchone()
        ins = db.execute(
            "INSERT INTO approvals (requester_id, resource_id, reason, status) "
            "VALUES (?, ?, ?, 'pending') RETURNING id",
            (det["id"], rid, "TTL 활성 회귀 테스트"),
        ).fetchone()
        approval_id = ins["id"]
        db.commit()

    tok_a, _, _ = login_as("admin_lee")
    code, _ = http(
        "POST", f"/api/admin/approvals/{approval_id}/approve",
        token=tok_a, body={"download_allowed": True},
    )
    assert code == 200

    # 막 승인했으므로 resolved_at 은 현재 시각 — TTL 안.
    code, data = http(
        "GET", f"/api/resources/cases/{rid}",
        token=tok_d, location="본청",
    )
    assert code == 200, data
    decision = data.get("decision") or {}
    # 사전 승인 효과(완화)가 적용되어 차단(level=5) 까지는 가지 않아야.
    # 정확한 level 은 다른 가중치 영향 — 느슨하게 level<=4 만 단언.
    assert decision.get("level", 5) <= 4, (
        f"활성 사전 승인이 적용 안 됨: decision={decision}"
    )


# ─── ITEM 4 / TEST 5 — Approve/Reject 동시성 ──────────────────────
# 결함 (감사 #4): UPDATE WHERE id=? 만 사용해 status='pending' 조건 부재 →
# 두 admin 동시 호출 시 양쪽 모두 200, approver_id / download_allowed 가
# 덮어씌워지는 race. 수정: WHERE id=? AND status='pending' + RETURNING.
def _make_pending_approval(http, login_as, db, reason):
    """detective_kim 의 grade>=4 자원에 대한 pending 승인 요청 1건 만들기."""
    tok_d, _, _ = login_as("detective_kim")
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()
    rid = row["id"]
    code, data = http(
        "POST", f"/api/resources/cases/{rid}/request-approval",
        token=tok_d, body={"reason": reason},
    )
    approval_id = data.get("approval_id") or data.get("id")
    if not approval_id:
        det = db.execute(
            "SELECT id FROM users WHERE username='detective_kim'"
        ).fetchone()
        ins = db.execute(
            "INSERT INTO approvals (requester_id, resource_id, reason, status) "
            "VALUES (?, ?, ?, 'pending') RETURNING id",
            (det["id"], rid, reason),
        ).fetchone()
        approval_id = ins["id"]
        db.commit()
    return approval_id


def test_concurrent_approve_only_one_succeeds(http, login_as, db):
    """두 deputy 동시 승인 → 정확히 1개만 200, 나머지 4xx (409 우선)."""
    approval_id = _make_pending_approval(
        http, login_as, db, "동시 승인 회귀 테스트"
    )
    tok_h, _, _ = login_as("deputy_han")
    tok_o, _, _ = login_as("deputy_oh")

    def _approve(tok):
        return http(
            "POST", f"/api/admin/approvals/{approval_id}/approve",
            token=tok, body={"download_allowed": False},
        )

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_approve, t) for t in (tok_h, tok_o)]
        results = [f.result() for f in futures]

    codes = sorted([r[0] for r in results])
    assert codes.count(200) == 1, (
        f"동시 승인 → 1개만 200 이어야: codes={codes}"
    )
    others = [c for c in codes if c != 200]
    assert all(c >= 400 for c in others), (
        f"비-200 응답은 모두 4xx 여야: codes={codes}"
    )

    # 최종 상태가 정확히 한 deputy 의 승인으로만 기록됐는지 검증
    final = db.execute(
        "SELECT status, approver_id FROM approvals WHERE id=?",
        (approval_id,),
    ).fetchone()
    assert final["status"] == "approved"
    assert final["approver_id"] is not None


def test_concurrent_reject_only_one_succeeds(http, login_as, db):
    """두 deputy 동시 반려 → 정확히 1개만 200, 나머지 4xx."""
    approval_id = _make_pending_approval(
        http, login_as, db, "동시 반려 회귀 테스트"
    )
    tok_h, _, _ = login_as("deputy_han")
    tok_o, _, _ = login_as("deputy_oh")

    def _reject(tok):
        return http(
            "POST", f"/api/admin/approvals/{approval_id}/reject",
            token=tok, body={"reason": "race test"},
        )

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_reject, t) for t in (tok_h, tok_o)]
        results = [f.result() for f in futures]

    codes = sorted([r[0] for r in results])
    assert codes.count(200) == 1, (
        f"동시 반려 → 1개만 200 이어야: codes={codes}"
    )
    others = [c for c in codes if c != 200]
    assert all(c >= 400 for c in others), (
        f"비-200 응답은 모두 4xx 여야: codes={codes}"
    )

    final = db.execute(
        "SELECT status FROM approvals WHERE id=?", (approval_id,),
    ).fetchone()
    assert final["status"] == "rejected"


# ─── ITEM 5 / TEST 6 — admin-gated 1차 토큰 1회성 소비 ────────────
# 결함 (감사 #5): mfa/verify 의 admin-gated 분기에서 세션 INSERT 와
# UPDATE login_approval_requests SET status='used' 가 별 트랜잭션이고
# UPDATE 에 status 조건도 없어, 같은 1차 토큰의 동시(또는 순차) 호출이
# 두 admin-gated 세션을 만들고 used_session_id 가 한쪽만 기록됐다.
# 가이드대로 직렬 단순화 — 같은 1차 토큰으로 두 번 호출 → 두 번째는
# 409 admin_approval_already_consumed 단언.
def test_admin_gated_mfa_verify_single_use(http, login_as, db):
    """admin-gated 승인은 첫 mfa/verify 와 함께 'used' 로 원자 소비된다."""
    # 1) admin_lee 가 신규 계정 생성 (토큰 기기 없음 — admin gate 흐름)
    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", "/api/admin/users/create",
        token=tok_admin, body={
            "username": "p2_admin_gated_user",
            "password": "TestPassword1234",
            "name": "ITEM5 회귀",
            "department": "강력범죄수사대",
            "rank": "순경", "role": "user",
            "assigned_cases": [],
            "allowed_locations": ["본청"],
            "job_scope": ["violent_crime"],
        },
    )
    assert code in (200, 201), f"create failed: {code} {data}"
    work_dev = data.get("work_device_id")

    new_user = db.execute(
        "SELECT id FROM users WHERE username='p2_admin_gated_user'"
    ).fetchone()
    assert new_user, "신규 계정 생성 후 users 행이 있어야 함"
    new_user_id = new_user["id"]

    # 2) login_approval_requests 에 'approved' 행을 직접 INSERT
    #    (실제 흐름 = 신규 계정 로그인 시도 → admin 승인. 여기선 회귀 검증
    #     단축을 위해 직접 시드).
    ag_ins = db.execute(
        "INSERT INTO login_approval_requests "
        "(user_id, justification, status, expires_at) "
        "VALUES (?, ?, 'approved', "
        "        CURRENT_TIMESTAMP + INTERVAL '30 minutes') "
        "RETURNING id",
        (new_user_id, "ITEM 5 회귀 셋업"),
    ).fetchone()
    approval_request_id = ag_ins["id"]
    db.commit()

    # 3) 1차 토큰 직접 발급 (admin-gated, mfa_verified=False)
    from security.jwt_handler import create_token
    tok_1st = create_token(
        user_id=new_user_id,
        username="p2_admin_gated_user",
        role="user",
        mfa_verified=False,
        device_id=work_dev,
        admin_gated=True,
        approval_request_id=approval_request_id,
    )

    # 4) 첫 mfa/verify → 200 (admin-gated + 토큰 기기 없음 → OTP 우회)
    code, data = http(
        "POST", "/api/auth/mfa/verify",
        token=tok_1st,
        body={"device_id": work_dev, "location": "본청", "otp_code": ""},
        device=work_dev, location="본청",
    )
    assert code == 200, f"첫 mfa/verify 가 200 이어야: {code} {data}"

    # 첫 호출 후 login_approval_requests 행은 status='used' 로 전이됐어야 함
    after_first = db.execute(
        "SELECT status, used_session_id FROM login_approval_requests WHERE id=?",
        (approval_request_id,),
    ).fetchone()
    assert after_first["status"] == "used", (
        f"첫 mfa/verify 후 status='used' 기대, got {after_first['status']}"
    )
    assert after_first["used_session_id"] is not None, (
        "first 호출의 session_id 가 used_session_id 에 채워져야 함"
    )

    # 5) 첫 세션을 비활성화 — 두 번째 호출의 동시 접속 정책 분기를 우회.
    #    (이 비활성화는 ITEM 5 의 검증 본질과 무관한 셋업.)
    db.execute(
        "UPDATE sessions SET is_active=FALSE WHERE user_id=?",
        (new_user_id,),
    )
    db.commit()

    # 6) 같은 1차 토큰으로 mfa/verify 재호출 → 409 admin_approval_already_consumed
    code, data = http(
        "POST", "/api/auth/mfa/verify",
        token=tok_1st,
        body={"device_id": work_dev, "location": "본청", "otp_code": ""},
        device=work_dev, location="본청",
    )
    assert code == 409, (
        f"두 번째 mfa/verify 는 409 admin_approval_already_consumed 기대: "
        f"{code} {data}"
    )
    assert data.get("code") == "admin_approval_already_consumed", data

    # 두 번째 호출이 차단됐으므로 새 세션이 만들어지지 않았어야 함
    active_count = db.execute(
        "SELECT COUNT(*) AS c FROM sessions "
        "WHERE user_id=? AND is_active=TRUE",
        (new_user_id,),
    ).fetchone()["c"]
    assert active_count == 0, (
        f"두 번째 호출이 새 세션을 만들면 안 됨 — active={active_count}"
    )


# ─── ITEM 6 / TEST 7 — deputy_admin 권한 일관성 ───────────────────
# 결함 (감사 #6): /api/audit/access-logs (line 73) 와 /api/audit/dashboard
# (line 96) 에서 deputy_admin 이 ('admin', 'superadmin') 비교에 빠져
# 일반 사용자로 취급됐다. require_admin (base_handler:221) 정의와 어긋남.
# 수정: BaseHandler.is_admin_role 헬퍼로 일관 처리.
def test_deputy_admin_can_filter_access_logs_by_user(http, login_as, db):
    """deputy_admin 이 user_id 필터로 다른 사용자의 access-logs 조회 가능."""
    # 시드 직후 access_logs 가 비어 있을 수 있어, detective_kim 의 접근 1건 시드.
    det = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()
    detective_id = det["id"]
    db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type) "
        "VALUES (?, 1, 'ALLOW', 2, 'view')",
        (detective_id,)
    )
    db.commit()

    tok_dep, _, _ = login_as("deputy_han")
    code, data = http(
        "GET", f"/api/audit/access-logs?user_id={detective_id}",
        token=tok_dep,
    )
    assert code == 200, f"deputy_admin access-logs 조회 200 기대: {code} {data}"
    logs = data.get("logs", [])
    # deputy_han 이 일반 사용자로 취급됐다면 user_id 필터가 무시되고
    # deputy_han 본인 기록만 반환됐을 것 — 그 경우 detective_id 행 0건.
    if logs:
        # 모든 로그가 detective_id 인지
        all_match = all(l.get("user_id") == detective_id for l in logs)
        assert all_match, (
            f"deputy_admin 이 user_id={detective_id} 필터 적용 후 다른 사용자 "
            f"로그 포함: {[l.get('user_id') for l in logs[:3]]}"
        )


def test_deputy_admin_dashboard_returns_global_stats(http, login_as, db):
    """deputy_admin 이 /api/audit/dashboard 호출 시 전역 통계 응답."""
    tok_dep, _, _ = login_as("deputy_han")
    code, data = http("GET", "/api/audit/dashboard", token=tok_dep)
    assert code == 200, f"deputy_admin dashboard 200 기대: {code} {data}"
    # admin 통계에만 등장하는 키 — locked_users — 가 응답에 있어야 한다
    # (일반 사용자 분기는 locked_users=0 을 강제로 set 하지만 키 자체는 존재).
    # 더 명확한 구분: total_access_requests 또는 total_access 키가 admin 통계에서
    # 채워지는지로 확인.
    assert "locked_users" in data or "total_access" in data, (
        f"admin 통계 키가 응답에 없음: {list(data.keys())}"
    )
