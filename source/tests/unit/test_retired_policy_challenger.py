"""6단계 정리 후 라우트 경계와 승인 검토 경로를 보호한다."""

import server


def test_retired_route_is_absent_and_approval_routes_remain(monkeypatch):
    """서버 앱에서 합성 실험만 빠지고 승인 검토·효과 조회가 유지된다."""
    monkeypatch.setattr(server, "load_and_validate", lambda: None)
    monkeypatch.setattr(server, "_invalidate_live_sessions", lambda _reason: 0)
    monkeypatch.setattr(server, "get_db", lambda: (_ for _ in ()).throw(OSError("no DB")))
    app = server.make_app()
    patterns = {rule.matcher.regex.pattern for rule in app.wildcard_router.rules
                if hasattr(rule.matcher, "regex")}
    assert not any("policy-lab" in pattern for pattern in patterns)
    for route in (
        "approval-effects", "approvals/(\\d+)/ai-review",
        "reviews/(login|assignment|break_glass)/(\\d+)/ai-review",
        "approvals/(\\d+)/approve", "login-approvals/(\\d+)/approve",
        "case-assignment-requests/(\\d+)/approve",
        "break-glass/(\\d+)/review", "break-glass/activate",
        "resources/cases/(\\d+)", "audit/logs",
    ):
        assert any(route in pattern for pattern in patterns)
