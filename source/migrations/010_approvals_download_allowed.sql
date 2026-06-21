-- =====================================================================
-- 010_approvals_download_allowed.sql  (Option Y — 승인 차등화)
--
-- 관리자 승인 완료 시 기본 동작은 "열람 전용(level 2)" 이다.
-- 그러나 일부 업무 시나리오에서는 다운로드까지 허용해야 하는 경우가
-- 있다 (예: 김형사가 조직 범죄 수사 자료의 사본을 보관해야 할 때).
--
-- 본 마이그레이션은 approvals 테이블에 download_allowed 플래그를 추가하여,
-- 관리자가 승인 시점에 "다운로드 허용 여부" 를 선택할 수 있게 한다.
--
-- 정책 매트릭스:
--   approval.status='approved' + download_allowed=false  → level 2 (열람 전용)
--   approval.status='approved' + download_allowed=true   → level 1 (다운로드 가능)
--
-- 이 값은 access_evaluator.py 의 pre_approved 분기에서 읽는다.
-- 기본값은 false — 즉 명시적 허용이 없으면 기존처럼 열람만 허용.
-- =====================================================================

BEGIN;

ALTER TABLE approvals
    ADD COLUMN IF NOT EXISTS download_allowed BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
