-- =====================================================================
-- 004_users_password_policy.sql  (L3-4)
-- 비밀번호 변경 이력/정책 추적용 컬럼 추가 + Break-Glass 플래그 +
-- 사후 소명(policy_override_requests) 테이블.
--
-- 주의: password_changed_at 컬럼은 기존 배포본에 따라 이미 존재할 수 있음
-- (확인 필요) → IF NOT EXISTS 로 방어.
-- =====================================================================

BEGIN;

-- 1) 비밀번호 정책
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS password_history    JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 2) Break-Glass 플래그
ALTER TABLE approvals
    ADD COLUMN IF NOT EXISTS is_break_glass BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_approvals_break_glass
    ON approvals(is_break_glass)
    WHERE is_break_glass;

-- 3) 사후 소명 / 화이트리스트 (L4-4 — DDL 만)
CREATE TABLE IF NOT EXISTS policy_override_requests (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_id    BIGINT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    context_hash   TEXT NOT NULL,
    justification  TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    approver_id    BIGINT REFERENCES users(id),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_override_ctx
    ON policy_override_requests(context_hash, status, expires_at);

COMMIT;
