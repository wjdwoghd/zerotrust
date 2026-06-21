-- 016_policy_overrides.sql
--
-- 직무 카테고리별 임계값 multiplier — 부서별 정책 차등.
--
-- 배경:
--   015 의 policy_thresholds 는 글로벌 default 다. 그러나 부서별로 정상
--   행동 패턴이 다르므로 (강력범죄수사대: 야간 빈번, 사이버수사대: 단말
--   이동 빈번 등) 글로벌 임계값 하나로 모든 사용자를 평가하면 오탐이 늘어
--   진다. 사용자 job_scope 의 카테고리에 매칭되는 multiplier 가 있으면
--   해당 임계값에 곱해 적용한다.
--
-- 동작:
--   - scoring 시 user.job_scope (배열) 의 각 카테고리에 대해 매칭되는
--     override 가 있으면 가장 작은 multiplier 적용 (보수적 — 가장 관대한
--     쪽이 아닌 첫 매칭). 추후 정책으로 확장 가능.
--   - 매칭 없으면 base 임계값 그대로.
--
-- 시드 정책:
--   보고서에 부서별 차등의 명시적 표가 없어, 시범 시드는 "예시" 다.
--   운영자가 운영 데이터로 보정 후 갱신하는 흐름이 전제.

-- ====== UP ======
BEGIN;

CREATE TABLE IF NOT EXISTS policy_overrides (
    id              SERIAL PRIMARY KEY,
    job_category    TEXT NOT NULL,
    threshold_name  TEXT NOT NULL,
    multiplier      NUMERIC NOT NULL DEFAULT 1.0,
    reason          TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT uq_policy_overrides UNIQUE (job_category, threshold_name)
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_category
    ON policy_overrides(job_category);

-- ── 시범 시드 (예시 — 보고서 명시 없음. 운영 데이터로 보정 필요) ──
INSERT INTO policy_overrides (job_category, threshold_name, multiplier, reason) VALUES
    -- 강력범죄수사대: 야간 출동·심야 조사 빈번
    ('violent_crime',     'ENV_NIGHT_TIME',     0.5, '강력범죄 — 야간 활동이 정상 패턴'),
    ('organized_crime',   'ENV_NIGHT_TIME',     0.5, '조직범죄 — 야간 활동이 정상 패턴'),

    -- 사이버수사대 / 포렌식: 분석실 이동·외부 단말 빈번
    ('cyber',             'ENV_DEVICE_CHANGED', 0.5, '사이버수사 — 분석실 단말 이동이 정상'),
    ('forensic',          'ENV_DEVICE_CHANGED', 0.5, '포렌식 — 분석 단말 이동이 정상'),

    -- 국가안보: 비상 대응 빈번
    ('national_security', 'ENV_NIGHT_TIME',     0.7, '국가안보 — 비상 대응 시간대 광범'),

    -- 정보보안과 / 감사팀 / 일반 직무는 글로벌 default 그대로 (override 없음)
    -- 즉 violent_crime 카테고리가 job_scope 에 있는 사용자만 야간 페널티 절반.

    -- 직무 외 카테고리도 시연 가능하도록 한 줄 추가:
    ('audit',             'ENV_LONG_UNUSED_DEVICE', 1.5,
        '감사팀 — 장기 미사용 단말 의심도 더 엄격')
ON CONFLICT (job_category, threshold_name) DO NOTHING;

COMMIT;

-- ====== DOWN ======
-- 016 적용 전 상태로 되돌린다. multiplier 가 사라지면 모든 사용자에게
-- 글로벌 default 임계값이 적용된다 (부서별 차등 사라짐).
BEGIN;
DROP INDEX IF EXISTS idx_policy_overrides_category;
DROP TABLE IF EXISTS policy_overrides;
COMMIT;
