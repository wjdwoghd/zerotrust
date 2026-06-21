-- =====================================================================
-- 003_sessions_timeout_cols.sql  (L3-3)
-- sessions 테이블에 유휴·절대 만료 및 impossible_travel 계산에 필요한
-- 컬럼을 추가한다.
-- =====================================================================

BEGIN;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS idle_timeout_seconds       INTEGER NOT NULL DEFAULT 900,
    ADD COLUMN IF NOT EXISTS absolute_expires_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS high_sensitivity_locked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_location              TEXT,
    ADD COLUMN IF NOT EXISTS last_location_time         TIMESTAMPTZ;

-- 절대 만료 기본값: login_at + 8h (기존 행에 대해 일괄 설정)
UPDATE sessions
   SET absolute_expires_at = login_at + INTERVAL '8 hours'
 WHERE absolute_expires_at IS NULL;

COMMIT;
