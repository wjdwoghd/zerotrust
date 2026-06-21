"""
시나리오 A — Smoke / Happy Path

정상 사용 흐름 10가지. ZT 시스템이 평소 사용에 방해되지 않는지 확인.
시스템이 차단/지연 없이 자연스럽게 동작하는 baseline.

사용 픽스처:
  - http       : 라이브 서버 + HTTP 호출 헬퍼
  - login_as   : 시드 사용자 로그인 + MFA 까지 토큰 발급
  - db         : PG 직접 연결 (검증용)
"""
from __future__ import annotations

import json

import pytest


# ─── 1. 시드 사용자 7명 모두 로그인 + MFA ────────────────────────
class TestSmokeLogin:
    """모든 시드 사용자가 정상 로그인할 수 있다."""

    @pytest.mark.parametrize("username", [
        "detective_kim",
        "investigator_park",
        "admin_lee",
        "officer_choi",
        "deputy_han",
        "deputy_oh",
    ])
    def test_seeded_user_can_login(self, login_as, username):
        tok, code, data = login_as(username)
        assert code == 200, f"{username} 로그인 실패: {data}"
        assert tok is not None
        assert data["user"]["username"] == username

    def test_patrol_jung_blocked_by_admin_gate(self, http, login_as):
        """patrol_jung(trust=40) 은 의심 계정 → 관리자 승인 게이트로 차단."""
        # patrol_jung 은 토큰 기기가 없어 login_as 의 MFA 단계에서 막히거나,
        # 관리자 승인 게이트로 즉시 차단된다.
        tok, code, data = login_as("patrol_jung", device_id="registered-007")
        # admin_approval_required 또는 has_token_device=False 응답 기대
        if tok is not None:
            # 토큰은 받았어도 실제 사용 시 admin_gated 라 보호 엔드포인트 차단
            code, _ = http("GET", "/api/auth/me", token=tok)
            assert code in (401, 403), \
                "patrol_jung 가 일반 인증으로 me 까지 통과하면 안 됨"
        else:
            # 로그인 자체에서 막힌 경우 — admin_approval_required 등
            assert code in (200, 403), data


# ─── 2. 자원 조회 정상 흐름 ─────────────────────────────────────
class TestSmokeResourceAccess:
    """담당 사건 정상 조회 — 차단 없이 돌아가는지."""

    def test_detective_lists_assigned_cases(self, http, login_as):
        """detective_kim 가 사건 목록을 보되 비담당 사건 등급은 노출되지 않는다."""
        tok, _, _ = login_as("detective_kim")
        code, data = http("GET", "/api/resources/cases", token=tok)
        assert code == 200, data
        assert "cases" in data or isinstance(data, list)
        cases = data.get("cases") if isinstance(data, dict) else data
        assert cases

        restricted_cases = [
            case for case in cases
            if case.get("is_assigned_case") is False
        ]
        assert restricted_cases, "비담당 사건도 담당 등록 요청을 위해 목록에 보여야 함"
        for case in restricted_cases:
            assert case.get("title")
            assert case.get("title") != "비공개 사건"
            assert case.get("sensitivity_grade") is None
            assert case.get("sensitivity_grade_masked") is True

    def test_admin_views_low_sens_resource(self, http, db, login_as):
        """관리자가 등급 1~2 자원 조회 — 마찰 없이."""
        tok, _, _ = login_as("admin_lee")
        # 등급 1 자원의 id 조회
        row = db.execute(
            "SELECT id FROM resources WHERE sensitivity_grade=1 LIMIT 1"
        ).fetchone()
        assert row, "등급 1 자원이 시드에 있어야 함"
        rid = row["id"]
        code, data = http("GET", f"/api/resources/cases/{rid}", token=tok,
                          location="본청")
        assert code == 200, data

    def test_access_status_realtime_preview_no_access_log_spam(self, http, db, login_as):
        """실시간 점수 폴링은 접근 로그를 만들지 않고 변화만 감사 로그로 남김."""
        tok, _, _ = login_as("detective_kim")
        user_id = db.execute(
            "SELECT id FROM users WHERE username='detective_kim'"
        ).fetchone()["id"]
        rid = db.execute(
            "SELECT id FROM resources WHERE case_number='2026-ADM-0001'"
        ).fetchone()["id"]

        before_access = db.execute(
            "SELECT COUNT(*) AS c FROM access_logs WHERE user_id=?",
            (user_id,),
        ).fetchone()["c"]
        before_events = db.execute(
            "SELECT COUNT(*) AS c FROM audit_logs "
            "WHERE event_type='ACCESS_SCORE_CHANGED' AND user_id=?",
            (user_id,),
        ).fetchone()["c"]

        code, data = http(
            "GET", f"/api/resources/cases/{rid}/status",
            token=tok, device="registered-001", location="본청",
        )
        assert code == 200, data
        assert "policy_check" not in data
        assert "anomaly_check" not in data
        assert "details" not in (data.get("scoring", {}).get("environment_risk") or {})
        assert "raw_total_risk_score" not in data["scoring"]["total"]
        assert data["decision"]["display_risk_score"] == data["decision"]["risk_score"]

        after_access = db.execute(
            "SELECT COUNT(*) AS c FROM access_logs WHERE user_id=?",
            (user_id,),
        ).fetchone()["c"]
        after_events = db.execute(
            "SELECT COUNT(*) AS c FROM audit_logs "
            "WHERE event_type='ACCESS_SCORE_CHANGED' AND user_id=?",
            (user_id,),
        ).fetchone()["c"]
        assert after_access == before_access
        assert after_events == before_events + 1

        code, data = http(
            "GET", f"/api/resources/cases/{rid}/status",
            token=tok, device="registered-001", location="본청",
        )
        assert code == 200, data
        final_events = db.execute(
            "SELECT COUNT(*) AS c FROM audit_logs "
            "WHERE event_type='ACCESS_SCORE_CHANGED' AND user_id=?",
            (user_id,),
        ).fetchone()["c"]
        assert final_events == after_events

    def test_repeated_unassigned_case_clicks_raise_behavior_risk(self, http, db, login_as):
        """비담당 사건 첫 클릭은 경고만, 이후 클릭은 회당 행동위험도 +10."""
        tok, _, _ = login_as("detective_kim")
        assigned_id = db.execute(
            "SELECT id FROM resources WHERE case_number='2026-VCT-0300'",
        ).fetchone()["id"]
        unassigned_id = db.execute(
            "SELECT id FROM resources WHERE case_number='2026-ADM-0001'",
        ).fetchone()["id"]

        code, baseline = http(
            "GET", f"/api/resources/cases/{assigned_id}/status",
            token=tok, device="registered-001", location="본청",
        )
        assert code == 200, baseline
        base_behavior = baseline["scoring"]["behavior_risk"]["score"]

        code, first = http(
            "POST", f"/api/resources/cases/{unassigned_id}/restricted-click",
            token=tok, device="registered-001", location="본청", body={},
        )
        assert code == 200, first
        assert first["click_index"] == 1
        assert first["behavior_penalty"] == 0

        code, second = http(
            "POST", f"/api/resources/cases/{unassigned_id}/restricted-click",
            token=tok, device="registered-001", location="본청", body={},
        )
        assert code == 200, second
        assert second["click_index"] == 2
        assert second["behavior_penalty"] == 10

        code, after = http(
            "GET", f"/api/resources/cases/{assigned_id}/status",
            token=tok, device="registered-001", location="본청",
        )
        assert code == 200, after
        assert after["scoring"]["behavior_risk"]["score"] == base_behavior + 10

        code, third = http(
            "POST", f"/api/resources/cases/{unassigned_id}/restricted-click",
            token=tok, device="registered-001", location="본청", body={},
        )
        assert code == 200, third
        assert third["click_index"] == 3
        assert third["behavior_penalty"] == 20

        code, after_third = http(
            "GET", f"/api/resources/cases/{assigned_id}/status",
            token=tok, device="registered-001", location="본청",
        )
        assert code == 200, after_third
        assert after_third["scoring"]["behavior_risk"]["score"] == base_behavior + 20

    def test_seed_assigned_cases_match_department_and_job_scope(self, db):
        """시드 담당 사건은 부서/직무 모순 없이 모든 문서를 커버한다."""
        users = db.execute(
            "SELECT username, department, assigned_cases, job_scope FROM users"
        ).fetchall()
        resources = db.execute(
            "SELECT id, case_number, department, job_tags FROM resources"
        ).fetchall()
        resources_by_id = {int(r["id"]): r for r in resources}
        covered_resource_ids = set()

        def as_list(value):
            if value is None:
                return []
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                    return parsed if isinstance(parsed, list) else []
                except Exception:
                    return []
            return list(value) if isinstance(value, (tuple, set)) else []

        for user in users:
            user_scope = {str(v) for v in as_list(user.get("job_scope"))}
            for raw_resource_id in as_list(user.get("assigned_cases")):
                resource_id = int(raw_resource_id)
                resource = resources_by_id[resource_id]
                resource_tags = {str(v) for v in as_list(resource.get("job_tags"))}
                covered_resource_ids.add(resource_id)
                assert user["department"] == resource["department"], {
                    "username": user["username"],
                    "resource_id": resource_id,
                    "case_number": resource["case_number"],
                }
                assert not resource_tags or (user_scope & resource_tags), {
                    "username": user["username"],
                    "resource_id": resource_id,
                    "case_number": resource["case_number"],
                }

        assert covered_resource_ids == set(resources_by_id)

    def test_cross_department_case_assignment_request_refused(self, http, login_as, db):
        """사건명은 보이더라도 다른 부서 사건은 담당 등록할 수 없다."""
        tok, _, _ = login_as("detective_kim")
        row = db.execute(
            "SELECT id FROM resources WHERE case_number='2026-ADM-0001'"
        ).fetchone()
        code, data = http(
            "POST",
            f"/api/resources/cases/{row['id']}/assignment-request",
            token=tok,
            body={"reason": "부서 불일치 담당 등록 회귀 테스트"},
        )
        assert code == 403, data
        assert data.get("code") == "assignment_scope_mismatch"


# ─── 3. 세션 정상 종료 흐름 ──────────────────────────────────────
class TestSmokeSession:
    """로그아웃 후 토큰 무효화."""

    def test_logout_invalidates_session(self, http, login_as):
        tok, _, _ = login_as("admin_lee")
        # 로그아웃
        code, _ = http("POST", "/api/auth/logout", token=tok, body={})
        assert code in (200, 204)
        # 같은 토큰으로 보호 엔드포인트 → 차단
        code, _ = http("GET", "/api/auth/me", token=tok)
        assert code == 401, "로그아웃 후에도 토큰이 유효하면 안 됨"


# ─── 4. 관리자 승인 흐름 (정상 결재) ────────────────────────────
class TestSmokeAdminApproval:
    """관리자 승인 요청 → 부관리자 승인 → 다운로드 가능."""

    def test_admin_approval_pending_endpoint(self, http, login_as):
        """관리자가 pending 승인 목록을 조회할 수 있다."""
        tok, _, _ = login_as("admin_lee")
        code, data = http("GET", "/api/admin/approvals/pending", token=tok)
        assert code == 200, data
        # pending 이 없을 수도 있음 — 빈 리스트라도 200 이 정상
        assert isinstance(data.get("approvals"), list) or isinstance(data, list)

    def test_deputy_can_act_as_admin(self, http, login_as):
        """deputy_admin 도 admin 엔드포인트 접근 가능 (이중감독 우회 방지)."""
        tok, _, _ = login_as("deputy_han")
        code, data = http("GET", "/api/admin/approvals/pending", token=tok)
        assert code == 200, data


# ─── 5. 헬스 / 운영 엔드포인트 ──────────────────────────────────
class TestSmokeOps:
    def test_healthz_no_auth(self, http):
        code, data = http("GET", "/healthz")
        assert code == 200
        assert data["status"] == "ok"

    def test_readyz_db_up(self, http):
        code, data = http("GET", "/readyz")
        assert code == 200
        assert data["db"] == "up"

    def test_metrics_requires_admin(self, http, login_as):
        """/api/metrics 은 admin 전용."""
        # 일반 유저
        tok_user, _, _ = login_as("detective_kim")
        code, _ = http("GET", "/api/metrics", token=tok_user)
        assert code == 403, "일반 유저는 metrics 차단"

        # admin
        tok_admin, _, _ = login_as("admin_lee")
        code, data = http("GET", "/api/metrics", token=tok_admin)
        assert code == 200, data
