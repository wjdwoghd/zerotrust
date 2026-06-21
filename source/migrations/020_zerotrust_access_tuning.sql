-- 020: 제로트러스트 시연/운영 보완
-- - 비담당 사건 단일 접근은 실수 가능성을 고려해 소폭 가산
-- - 고등급 비담당 사건은 추가 가산
-- - 5분 내 다수 접근 기준을 5회(주의), 10회(위험)로 단계화

INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('BEH_UNAUTHORIZED_ACCESS', 10, 'behavior', '비담당 사건 접근 1회: 실수 가능성을 고려한 소폭 가산'),
    ('BEH_HIGH_SENS_UNASSIGNED',    5, 'behavior', '4~5등급 비담당 사건 접근 추가 가산'),
    ('BEH_HIGH_FREQ_ACCESS_CRITICAL', 20, 'behavior', '5분 내 10회 이상 고빈도 접근 위험')
ON CONFLICT (name) DO UPDATE SET
    value = EXCLUDED.value,
    category = EXCLUDED.category,
    description = EXCLUDED.description;

UPDATE policy_thresholds
SET value = 10,
    description = '5분 내 5회 이상 고빈도 접근 주의'
WHERE name = 'BEH_HIGH_FREQ_ACCESS';
