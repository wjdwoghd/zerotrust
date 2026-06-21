-- =====================================================================
-- 008_rename_admin_approval.sql  (L3-5 rename)
--
-- 006 에서 "Break-Glass" 라는 이름으로 도입됐던 기능은 실제로는
-- 업계 표준 Break-Glass(긴급 상황 시 자가발동 특권 접근) 와 용도가
-- 다르다. 현재 구현은 "토큰 기기 미보유 일반 계정의 관리자 승인 후
-- 로그인" = 사전 관리자 승인 게이트에 가깝다.
--
-- 진짜 Break-Glass 구현(Phase 2) 과 의미론적 충돌을 막기 위해
-- 이 파일에서 테이블/컬럼명을 "admin_approval" 계열로 개명한다.
--
-- 변경:
--   login_break_glass_requests        → login_approval_requests
--   sessions.is_break_glass           → sessions.is_admin_gated
--   인덱스 idx_lbg_user_status        → idx_lar_user_status
--   인덱스 idx_lbg_pending            → idx_lar_pending
--   인덱스 idx_sessions_break_glass   → idx_sessions_admin_gated
--
-- 006 와 대응되는 스키마 개명만 수행. DB 데이터/정책은 변경 없음.
-- approvals.is_break_glass (004) 는 본 개명 범위에서 제외 —
-- Phase 2 진짜 Break-Glass 에서 재사용할 수 있다.
-- =====================================================================

BEGIN;

-- 1) 테이블 개명
ALTER TABLE IF EXISTS login_break_glass_requests
    RENAME TO login_approval_requests;

-- 2) sessions 컬럼 개명
ALTER TABLE sessions
    RENAME COLUMN is_break_glass TO is_admin_gated;

-- 3) 인덱스 개명 (IF EXISTS: 신규 배포에서 없을 수도 있으므로 방어)
ALTER INDEX IF EXISTS idx_lbg_user_status RENAME TO idx_lar_user_status;
ALTER INDEX IF EXISTS idx_lbg_pending     RENAME TO idx_lar_pending;
ALTER INDEX IF EXISTS idx_sessions_break_glass
    RENAME TO idx_sessions_admin_gated;

COMMIT;
