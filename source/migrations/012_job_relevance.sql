-- =====================================================================
-- 012_job_relevance.sql
--
-- 보고서 §7-3 Table 21 의 "직무 연관성(-20)" 항목을 활성화하기 위한
-- 스키마 확장.
--
--   users.job_scope    — 사용자가 다루는 직무 카테고리 태그 (JSONB 배열)
--   resources.job_tags — 자료가 속한 직무 카테고리 태그 (JSONB 배열)
--
-- access_evaluator 는 user.job_scope ∩ resource.job_tags 가 비어있지
-- 않으면 score_work_fitness(job_relevance=True) 로 -20 점 차감한다.
-- =====================================================================

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS job_scope JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS job_tags JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 검색 용도 GIN 인덱스 (옵션 — JSONB 배열 contains 연산 가속)
CREATE INDEX IF NOT EXISTS idx_users_job_scope ON users USING GIN (job_scope);
CREATE INDEX IF NOT EXISTS idx_resources_job_tags ON resources USING GIN (job_tags);

COMMIT;
