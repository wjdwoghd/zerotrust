-- 022: 업무 적합도 기준 완화
-- - 사전 승인(FIT_PRE_APPROVED=-15)은 유지한다.
-- - 담당/부서/관할/직무 연관성 감산만 재조정한다.

-- ====== UP ======
BEGIN;

INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('FIT_ASSIGNED_CASE',   -20, 'fitness', '담당 사건'),
    ('FIT_SAME_DEPARTMENT', -10, 'fitness', '부서 일치'),
    ('FIT_JURISDICTION',     -5, 'fitness', '관할 일치'),
    ('FIT_JOB_RELEVANCE',   -10, 'fitness', '직무 연관성')
ON CONFLICT (name) DO UPDATE SET
    value = EXCLUDED.value,
    category = EXCLUDED.category,
    description = EXCLUDED.description;

COMMIT;

-- ====== DOWN ======
BEGIN;

INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('FIT_ASSIGNED_CASE',   -30, 'fitness', '담당 사건'),
    ('FIT_SAME_DEPARTMENT', -15, 'fitness', '부서 일치'),
    ('FIT_JURISDICTION',    -10, 'fitness', '관할 일치'),
    ('FIT_JOB_RELEVANCE',   -20, 'fitness', '직무 연관성 (높음)')
ON CONFLICT (name) DO UPDATE SET
    value = EXCLUDED.value,
    category = EXCLUDED.category,
    description = EXCLUDED.description;

COMMIT;
