-- =====================================================================
-- 006_login_break_glass.sql  (L3-5 / 의심 계정 Break-Glass)
--
-- 목적:
--   1) 의심 계정(trust_score < 50 OR violation_count >= 3) 은 로그인 시점에
--      기본 차단된다. 관리자가 명시적으로 "Break-Glass 승인" 을 해야만
--      단일 로그인 기회가 열린다.
--   2) Break-Glass 로 개설된 세션은 유휴 5분 / 절대 30분으로 단축되며,
--      sessions.is_break_glass = TRUE 로 마킹되어 감사·모니터링에서 구분
--      가능하다.
--
-- 이 파일이 추가하는 객체:
--   - login_break_glass_requests  (로그인 단위 정책 예외 요청 큐)
--   - sessions.is_break_glass     (세션이 break-glass 경로로 개설됐는지)
--
-- 실행 순서: 001 -> 002 -> 003 -> 004 -> 005 -> 006
-- =====================================================================

BEGIN;

-- 1) 로그인 단위 Break-Glass 요청 테이블
--
--    policy_override_requests 는 resource_id NOT NULL 이라 로그인 컨텍스트에
--    쓸 수 없다. 로그인은 자원에 귀속되지 않는 행위이므로 별도 테이블을
--    둔다.
--
--    status 전이:
--      pending   -- 로그인 시도로 자동 생성
--      approved  -- 관리자가 승인. expires_at 까지 유효.
--      rejected  -- 관리자가 거부.
--      used      -- 이 승인으로 세션이 실제 개설됨 (재사용 방지).
--      expired   -- expires_at 경과 (조회 시 판정. 별도 스케줄러 없음).
CREATE TABLE IF NOT EXISTS login_break_glass_requests (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    justification  TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    approver_id    BIGINT REFERENCES users(id),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    used_session_id BIGINT REFERENCES sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_lbg_user_status
    ON login_break_glass_requests(user_id, status);

CREATE INDEX IF NOT EXISTS idx_lbg_pending
    ON login_break_glass_requests(status, requested_at)
    WHERE status = 'pending';

-- 2) sessions 테이블에 break-glass 세션 마킹
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS is_break_glass BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_sessions_break_glass
    ON sessions(is_break_glass)
    WHERE is_break_glass;

COMMIT;
