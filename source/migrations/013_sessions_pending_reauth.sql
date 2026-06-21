-- =====================================================================
-- 013_sessions_pending_reauth.sql
--
-- 동시 접속 정책 (L3-x):
--   동일 user_id 로 두 번째 활성 세션이 만들어지면 **양쪽 세션 모두**
--   pending_reauth=TRUE 로 잠근다. 해당 세션은 base_handler.require_auth
--   에서 401 concurrent_session_detected 를 반환하며, /api/auth/reauth
--   로 MFA 재인증에 성공한 세션만 해제된다. 먼저 해제된 쪽이 이기고
--   나머지 세션은 is_active=FALSE 로 강제 종료된다 (자동 종료 정책).
--   pending_reauth_at 이후 SESSION_PENDING_REAUTH_TIMEOUT_SEC (=5분)
--   초과 시 session_guard 가 자동으로 해당 세션을 만료 처리한다.
-- =====================================================================

BEGIN;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS pending_reauth    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pending_reauth_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sessions_pending_reauth
    ON sessions(pending_reauth) WHERE pending_reauth;

COMMIT;
