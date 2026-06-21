from __future__ import annotations

import time


def test_stale_browser_presence_allows_relogin(http, login_as, db):
    tok1, code1, data1 = login_as("admin_lee", ip="10.0.0.1")
    assert code1 == 200, data1

    row = db.execute(
        "SELECT id FROM sessions "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "  AND is_active "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    old_session_id = int(row["id"])

    code_hb, data_hb = http("POST", "/api/auth/heartbeat", token=tok1)
    assert code_hb == 200, data_hb

    from core import client_presence

    with client_presence._LOCK:
        client_presence._SEEN[old_session_id] = (
            time.monotonic() - client_presence.STALE_SECONDS - 1
        )

    # Avoid TOTP replay blocking the second MFA verification in a fast test run.
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee')"
    )
    db.commit()

    tok2, code2, data2 = login_as("admin_lee", ip="10.0.0.2")
    assert code2 == 200, data2
    assert tok2

    old_row = db.execute(
        "SELECT is_active FROM sessions WHERE id=?",
        (old_session_id,)
    ).fetchone()
    assert old_row["is_active"] is False

    audit_row = db.execute(
        "SELECT details FROM audit_logs "
        "WHERE event_type='ZOMBIE_SESSION_CLEANED' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert audit_row
    assert "presence_stale_session_ids" in audit_row["details"]
