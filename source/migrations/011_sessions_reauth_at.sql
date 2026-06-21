-- =====================================================================
-- 011_sessions_reauth_at.sql
--
-- Level 3 (REAUTH_REQUIRED) 재인증 기능을 위한 세션 컬럼 추가.
-- /api/auth/reauth 에서 OTP 재검증 성공 시 sessions.reauth_at 을 now()
-- 로 갱신한다. access_evaluator 는 reauth_at 이 최근 REAUTH_TTL_SEC
-- 이내면 policy_engine.check_force_reauth() 요구를 충족한 것으로 간주한다.
-- =====================================================================

BEGIN;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS reauth_at TIMESTAMPTZ;

COMMIT;
