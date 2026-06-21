-- 023_night_time_full_risk.sql
-- 심야 시간대 위험도는 직무 구분 없이 ENV_NIGHT_TIME 기본값(+15)을 그대로 적용한다.

-- ====== UP ======
BEGIN;

INSERT INTO policy_overrides (job_category, threshold_name, multiplier, reason) VALUES
    ('violent_crime',     'ENV_NIGHT_TIME', 1.0, '심야 위험도는 직무 구분 없이 기본 +15 적용'),
    ('organized_crime',   'ENV_NIGHT_TIME', 1.0, '심야 위험도는 직무 구분 없이 기본 +15 적용'),
    ('national_security', 'ENV_NIGHT_TIME', 1.0, '심야 위험도는 직무 구분 없이 기본 +15 적용')
ON CONFLICT (job_category, threshold_name) DO UPDATE SET
    multiplier = EXCLUDED.multiplier,
    reason = EXCLUDED.reason,
    updated_at = now();

COMMIT;

-- ====== DOWN ======
BEGIN;

INSERT INTO policy_overrides (job_category, threshold_name, multiplier, reason) VALUES
    ('violent_crime',     'ENV_NIGHT_TIME', 0.5, '강력범죄 — 야간 활동이 정상 패턴'),
    ('organized_crime',   'ENV_NIGHT_TIME', 0.5, '조직범죄 — 야간 활동이 정상 패턴'),
    ('national_security', 'ENV_NIGHT_TIME', 0.7, '국가안보 — 비상 대응 시간대 광범')
ON CONFLICT (job_category, threshold_name) DO UPDATE SET
    multiplier = EXCLUDED.multiplier,
    reason = EXCLUDED.reason,
    updated_at = now();

COMMIT;
