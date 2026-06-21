-- 015_policy_thresholds.sql
--
-- 점수·결정 임계값을 DB 테이블로 외부화한다.
--
-- 배경:
--   core/scoring_engine.py 와 core/decision_engine.py 의 모든 가중치는 보고서
--   §7-3 Table 21 의 설계 추정치다. 운영 데이터로 ROC 보정 시 코드 배포 없이
--   조정 가능해야 하므로 DB 테이블로 외부화한다.
--
-- 동작:
--   - 첫 적용 시 시드 INSERT 로 보고서 §7-3 기본값 입력.
--   - 운영자가 값 변경 후 재실행해도 ON CONFLICT DO NOTHING 으로 보존.
--   - 코드는 core/policy_thresholds.py 모듈을 통해 5분 TTL 캐시로 조회.
--
-- 주의:
--   - 시드 페르소나(detective_kim trust=85 등)가 시연 시나리오의 전제이므로
--     기본값은 보고서 §7-3 그대로 보존.
--   - 결정 경계(BAND_L*) 변경은 결정 매트릭스 스냅샷 테스트를 깨므로 신중.

-- ====== UP ======
BEGIN;

CREATE TABLE IF NOT EXISTS policy_thresholds (
    name        TEXT PRIMARY KEY,
    value       NUMERIC NOT NULL,
    category    TEXT NOT NULL,
    description TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  INTEGER       -- 변경한 admin user_id (FK 안 걸음 - 014 교훈)
);

CREATE INDEX IF NOT EXISTS idx_policy_thresholds_category
    ON policy_thresholds(category);

-- ── 객체 민감도 (보고서 §7-3 Table 21) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('OBJECT_SENS_GRADE_1',          10, 'object', '등급 1 자원 객체 점수'),
    ('OBJECT_SENS_GRADE_2',          20, 'object', '등급 2 자원 객체 점수'),
    ('OBJECT_SENS_GRADE_3',          30, 'object', '등급 3 자원 객체 점수'),
    ('OBJECT_SENS_GRADE_4',          40, 'object', '등급 4 자원 객체 점수'),
    ('OBJECT_SENS_GRADE_5',          50, 'object', '등급 5 자원 객체 점수'),
    ('OBJECT_DATA_TYPE_SUMMARY',      5, 'object', '사건 요약 보너스'),
    ('OBJECT_DATA_TYPE_ORIGINAL',    10, 'object', '일반 원문 보너스'),
    ('OBJECT_DATA_TYPE_EVIDENCE',    15, 'object', '증거자료 보너스'),
    ('OBJECT_DATA_TYPE_INTERNAL_MEMO', 20, 'object', '내부 메모·민감 첨부 보너스')
ON CONFLICT (name) DO NOTHING;

-- ── 환경 위험 (보고서 §7-3) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('ENV_RELAXED_TIME',          5, 'environment', '완화구간 (근무시간 인접)'),
    ('ENV_NIGHT_TIME',           15, 'environment', '심야 22:00~06:00'),
    ('ENV_UNREGISTERED_DEVICE',  20, 'environment', '미등록 단말'),
    ('ENV_LONG_UNUSED_DEVICE',   10, 'environment', '장기 미사용 등록 단말'),
    ('ENV_EXCEPTION_LOCATION',   10, 'environment', '예외 허용 위치 (출장 등)'),
    ('ENV_DISALLOWED_LOCATION',  20, 'environment', '비허용 위치'),
    ('ENV_DEVICE_CHANGED',       10, 'environment', '세션 중 단말 변경'),
    ('ENV_IMPOSSIBLE_TRAVEL',    15, 'environment', '비현실적 위치 전환 (점수 가산. 즉시차단은 별도 처리)')
ON CONFLICT (name) DO NOTHING;

-- ── 행위 위험 (보고서 §7-3) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('BEH_HIGH_FREQ_ACCESS',  15, 'behavior', '5분 내 10회 이상 고빈도 접근'),
    ('BEH_DOWNLOAD_SENSITIVE',20, 'behavior', '민감 자료 다운로드 시도'),
    ('BEH_COPY_ATTEMPT',      20, 'behavior', '복사 시도'),
    ('BEH_BULK_QUERY',        20, 'behavior', '20건 이상 대량 조회'),
    ('BEH_AUTH_FAIL_REPEAT',  15, 'behavior', '인증 실패 누적')
ON CONFLICT (name) DO NOTHING;

-- ── 업무 적합도 (음수, 보고서 §7-3) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('FIT_ASSIGNED_CASE',     -30, 'fitness', '담당 사건'),
    ('FIT_SAME_DEPARTMENT',   -15, 'fitness', '부서 일치'),
    ('FIT_JURISDICTION',      -10, 'fitness', '관할 일치'),
    ('FIT_JOB_RELEVANCE',     -20, 'fitness', '직무 연관성 (높음)'),
    ('FIT_PRE_APPROVED',      -15, 'fitness', '사전 승인')
ON CONFLICT (name) DO NOTHING;

-- ── IP 평판 (scoring_engine.evaluate 어댑터) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('IP_REP_CLEAN',       0, 'ip_reputation', '정상 IP'),
    ('IP_REP_SUSPICIOUS', 10, 'ip_reputation', '의심 IP'),
    ('IP_REP_TOR',        25, 'ip_reputation', 'Tor 출구 노드'),
    ('IP_REP_UNKNOWN',     5, 'ip_reputation', '미상 IP')
ON CONFLICT (name) DO NOTHING;

-- ── 결정 경계 (decision_engine._UNIFIED_BANDS) ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('DECISION_BAND_L1_MAX', 25, 'decision_band', 'L1 (완전 허용) 최대 점수'),
    ('DECISION_BAND_L2_MAX', 50, 'decision_band', 'L2 (조회만) 최대 점수'),
    ('DECISION_BAND_L3_MAX', 75, 'decision_band', 'L3 (재인증) 최대 점수'),
    ('DECISION_BAND_L4_MAX', 90, 'decision_band', 'L4 (관리자 승인) 최대 점수')
ON CONFLICT (name) DO NOTHING;

-- ── Confidence-aware 결정 임계값 ──
INSERT INTO policy_thresholds (name, value, category, description) VALUES
    ('CONFIDENCE_THRESHOLD', 0.85, 'confidence', '확신도 한 단계 조정 임계 (이 미만이면 검증 방향 이동)')
ON CONFLICT (name) DO NOTHING;

COMMIT;

-- ====== DOWN ======
-- 015 가 적용되기 전 상태로 되돌린다. 코드는 policy_thresholds 조회 실패 시
-- 보고서 §7-3 default fallback 으로 동작하므로 down 후에도 정책 결정 자체는
-- 가능하다 (단, 외부 보정한 값은 함께 사라짐).
BEGIN;
DROP INDEX IF EXISTS idx_policy_thresholds_category;
DROP TABLE IF EXISTS policy_thresholds;
COMMIT;
