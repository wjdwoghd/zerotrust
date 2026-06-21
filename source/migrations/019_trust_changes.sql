-- ====== UP ======
-- 019_trust_changes.sql
--
-- trust_score 변동 timeline 추적 (옵션 A + C — 새 테이블 + PG 트리거).
--
-- 결함 (이전):
--   trust_score 변동이 4 시점에서 발생하지만 통합 추적 부재.
--     · FP/FN 라벨 (017 트리거가 silent UPDATE)
--     · BG unjustified 사후심사 (audit_log 발생하나 변량 정보 없음)
--     · trust_recalibration (집계만, 사용자별 X)
--   "왜 admin_lee 의 trust_score 가 95 → 65 인가?" 사후 추론 어려움.
--
-- 본 마이그레이션:
--   1) trust_changes 테이블 — 모든 변동의 timeline
--   2) users.trust_score UPDATE 트리거로 자동 INSERT (before/after/delta 자동)
--   3) reason / source_id / actor_id 는 호출 측이 SET LOCAL 으로 전달.
--      값이 없으면 NULL — fallback 으로 timeline 자체는 항상 보존.
--   4) trust_changes 도 append-only (audit_logs 패턴) — 변조 차단.
--   5) 017 의 adjust_trust_on_review() 함수를 OR REPLACE — 라벨링이
--      트리거할 trust UPDATE 직전에 SET LOCAL 으로 컨텍스트 전달.

CREATE TABLE IF NOT EXISTS trust_changes (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delta           NUMERIC(6, 2) NOT NULL,
    before_trust    NUMERIC(6, 2) NOT NULL,
    after_trust     NUMERIC(6, 2) NOT NULL,
    reason          TEXT,
    source_id       BIGINT,
    actor_id        BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trust_changes_user_time
    ON trust_changes(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trust_changes_reason
    ON trust_changes(reason);

COMMENT ON TABLE trust_changes IS
    'trust_score 변동 timeline. users.trust_score UPDATE 시 자동 INSERT.';
COMMENT ON COLUMN trust_changes.reason IS
    'review_false_positive / review_false_negative / bg_unjustified / '
    'recalibration_recover / recalibration_decay / 그 외(NULL)';

-- ── UPDATE 자동 감지 트리거 ───────────────────────────────────────
CREATE OR REPLACE FUNCTION track_trust_change() RETURNS trigger AS $$
DECLARE
    delta_val   NUMERIC;
    reason_val  TEXT;
    source_val  BIGINT;
    actor_val   BIGINT;
BEGIN
    -- trust_score 가 NULL 이거나 변하지 않으면 timeline INSERT 없음.
    IF NEW.trust_score IS NULL OR OLD.trust_score IS NULL OR
       NEW.trust_score = OLD.trust_score THEN
        RETURN NEW;
    END IF;
    delta_val := NEW.trust_score - OLD.trust_score;

    -- 호출 측에서 SET LOCAL 으로 전달한 컨텍스트.
    -- current_setting(name, true) 는 missing setting 시 빈 문자열 반환.
    BEGIN
        reason_val := NULLIF(current_setting('app.trust_reason', true), '');
    EXCEPTION WHEN OTHERS THEN reason_val := NULL;
    END;
    BEGIN
        source_val := NULLIF(current_setting('app.trust_source_id', true), '')::BIGINT;
    EXCEPTION WHEN OTHERS THEN source_val := NULL;
    END;
    BEGIN
        actor_val := NULLIF(current_setting('app.trust_actor_id', true), '')::BIGINT;
    EXCEPTION WHEN OTHERS THEN actor_val := NULL;
    END;

    INSERT INTO trust_changes(
        user_id, delta, before_trust, after_trust,
        reason, source_id, actor_id
    ) VALUES (
        NEW.id, delta_val, OLD.trust_score, NEW.trust_score,
        reason_val, source_val, actor_val
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_track_trust_change ON users;
CREATE TRIGGER trg_track_trust_change
    AFTER UPDATE OF trust_score ON users
    FOR EACH ROW EXECUTE FUNCTION track_trust_change();

-- ── append-only (audit_logs 패턴) ────────────────────────────────
CREATE OR REPLACE FUNCTION trust_changes_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'trust_changes is append-only';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_trust_changes_no_update ON trust_changes;
CREATE TRIGGER trg_trust_changes_no_update
    BEFORE UPDATE OR DELETE ON trust_changes
    FOR EACH ROW EXECUTE FUNCTION trust_changes_immutable();

-- ── 017 의 라벨링 트리거 함수 OR REPLACE ─────────────────────────
-- 사후심사 라벨 INSERT → trust UPDATE 직전 SET LOCAL 으로 컨텍스트 전달.
-- 그러면 trg_track_trust_change 가 reason/source_id/actor_id 를 자동 수집.
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
        -- 019: trust_changes 컨텍스트 전달 (트리거 체인 — 017 → users UPDATE → 019 → trust_changes INSERT)
        PERFORM set_config('app.trust_reason', 'review_' || NEW.label, true);
        PERFORM set_config('app.trust_source_id', NEW.id::TEXT, true);
        IF NEW.reviewer_id IS NOT NULL THEN
            PERFORM set_config('app.trust_actor_id', NEW.reviewer_id::TEXT, true);
        END IF;

        UPDATE users
           SET trust_score = LEAST(100, GREATEST(0, trust_score + delta_trust)),
               violation_count = violation_count + delta_violation
         WHERE id = NEW.target_user_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ====== DOWN ======
-- 017 의 함수는 019 가 OR REPLACE 로 덮어썼지만, down 시점엔 017 정의로
-- 자동 복귀하지 않는다. trust_changes 의존성을 모두 제거한 뒤 마이그레이션
-- 적용 이력에서 019 만 빠진다 → 017 재실행 (down→up 라운드트립) 시 원래
-- 함수가 다시 OR REPLACE 됨. 즉 코드 롤백과 함께 진행해야 안전.

DROP TRIGGER IF EXISTS trg_track_trust_change ON users;
DROP TRIGGER IF EXISTS trg_trust_changes_no_update ON trust_changes;
DROP FUNCTION IF EXISTS track_trust_change();
DROP FUNCTION IF EXISTS trust_changes_immutable();
DROP INDEX IF EXISTS idx_trust_changes_reason;
DROP INDEX IF EXISTS idx_trust_changes_user_time;
DROP TABLE IF EXISTS trust_changes;
