-- 017_access_decision_reviews.sql
--
-- 관리자 사후 라벨링 + 사용자 trust_score 자동 조정.
--
-- 배경:
--   결정 정확도 (오탐/미탐) 보정에는 사후 라벨이 필요하다. 관리자가
--   access_logs 의 한 결정을 검토해 "false_positive" / "false_negative" /
--   "justified" 중 하나로 표시하면, 트리거가 즉시 사용자 trust_score 와
--   violation_count 를 양방향 조정한다.
--
-- 효과:
--   - false_positive (정당했는데 차단/검증) → trust +5 회복
--   - false_negative (의심스러웠는데 통과)  → trust -10, violation +1
--   - justified (정상 결정)                  → 변동 없음
--
-- 학습 루프:
--   라벨 누적 → 향후 운영 데이터로 ROC 보정 → 015 의 policy_thresholds 갱신.

-- ====== UP ======
BEGIN;

CREATE TABLE IF NOT EXISTS access_decision_reviews (
    id              BIGSERIAL PRIMARY KEY,
    access_log_id   BIGINT NOT NULL,
    reviewer_id     INTEGER,
    target_user_id  INTEGER,
    label           TEXT NOT NULL CHECK (
        label IN ('false_positive', 'false_negative', 'justified')
    ),
    notes           TEXT,
    reviewed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_adr_target_user
    ON access_decision_reviews(target_user_id);
CREATE INDEX IF NOT EXISTS idx_adr_label
    ON access_decision_reviews(label);
CREATE INDEX IF NOT EXISTS idx_adr_access_log
    ON access_decision_reviews(access_log_id);

-- ── 트리거: 라벨 INSERT 시 trust 자동 조정 ───────────────────────
CREATE OR REPLACE FUNCTION adjust_trust_on_review() RETURNS trigger AS $$
DECLARE
    delta_trust    INTEGER := 0;
    delta_violation INTEGER := 0;
BEGIN
    IF NEW.target_user_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.label = 'false_positive' THEN
        delta_trust := 5;
    ELSIF NEW.label = 'false_negative' THEN
        delta_trust := -10;
        delta_violation := 1;
    END IF;

    IF delta_trust <> 0 OR delta_violation <> 0 THEN
        UPDATE users
           SET trust_score = LEAST(100, GREATEST(0, trust_score + delta_trust)),
               violation_count = violation_count + delta_violation
         WHERE id = NEW.target_user_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_review_adjust_trust ON access_decision_reviews;
CREATE TRIGGER trg_review_adjust_trust
    AFTER INSERT ON access_decision_reviews
    FOR EACH ROW EXECUTE FUNCTION adjust_trust_on_review();

COMMIT;

-- ====== DOWN ======
-- 017 적용 전 상태로 되돌린다. 라벨 학습 루프가 사라지므로 trust 자동 조정
-- 안 됨. /api/admin/access-logs/{id}/review 엔드포인트는 여전히 코드에
-- 남지만 호출 시 access_decision_reviews 테이블 부재로 500 발생 — down 은
-- 코드 롤백과 함께 진행해야 안전.
BEGIN;
DROP TRIGGER IF EXISTS trg_review_adjust_trust ON access_decision_reviews;
DROP FUNCTION IF EXISTS adjust_trust_on_review();
DROP INDEX IF EXISTS idx_adr_target_user;
DROP INDEX IF EXISTS idx_adr_label;
DROP INDEX IF EXISTS idx_adr_access_log;
DROP TABLE IF EXISTS access_decision_reviews;
COMMIT;
