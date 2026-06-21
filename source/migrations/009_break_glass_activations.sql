-- =====================================================================
-- 009_break_glass_activations.sql  (Phase 2 / 진짜 Break-Glass)
--
-- 배경:
--   006/008 에서 구현한 "관리자 승인 로그인 게이트" 는 엄밀히 업계표준
--   Break-Glass 가 아니라 '승인 기반 로그인' 이다. 여기서는 진짜 Break-Glass
--   — 즉 자격 있는 사용자가 '긴급 상황에서 자기 책임 하에' 특권 접근을
--   자가발동하고 관리자 사후 리뷰로 정당성이 판정되는 메커니즘 — 을 추가한다.
--
-- 제로트러스트 원칙 반영:
--   - Least privilege: 발동자는 토큰 기기 보유자로 제한 (정책은 앱 단).
--                     scope = 'resource' (단일 자원) 또는 'broad' (Grade ≥ min_grade).
--   - Verify explicitly: 발동 시 MFA 재확인 필수 (정책은 앱 단).
--   - Assume breach: 짧은 TTL(절대 30m / 유휴 5m). 관리자 사후 의무 리뷰.
--   - Accountability: sensitive_logs 에 원본(사유) 기록, review_verdict 필수.
--
-- 이 파일이 추가하는 객체:
--   - break_glass_activations   (긴급 자가발동 레코드)
--   - idx_bg_activator_active   (활성 조회 성능)
--   - idx_bg_pending_review     (리뷰 대기 큐)
--   - idx_bg_activated          (시간순 감사 조회)
--
-- 실행 순서: 001 -> ... -> 008 -> 009
-- =====================================================================

BEGIN;

-- 1) Break-Glass 자가발동 레코드
--
-- status 전이:
--   active               — 발동 직후. expires_at 까지 유효.
--   expired              — expires_at 경과. 리뷰 대기.
--   revoked              — 관리자가 즉시 취소. 리뷰 대기.
--   released             — 본인이 자발 해제. 리뷰 대기.
--   reviewed_justified   — 관리자 사후 리뷰: 정당한 긴급 상황.
--   reviewed_unjustified — 관리자 사후 리뷰: 부당 발동. trust_score penalty.
--   reviewed_partial     — 관리자 사후 리뷰: 일부 정당.
--
-- scope:
--   resource  — resource_id 단일 자원에만 허용 (권장, least privilege)
--   broad     — min_grade 이상 모든 자원에 허용 (긴급 광역 상황)
CREATE TABLE IF NOT EXISTS break_glass_activations (
    id                BIGSERIAL PRIMARY KEY,
    activator_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id        BIGINT REFERENCES sessions(id) ON DELETE SET NULL,

    scope             TEXT NOT NULL CHECK (scope IN ('resource','broad')),
    resource_id       BIGINT REFERENCES resources(id) ON DELETE SET NULL,
    min_grade         INTEGER NOT NULL DEFAULT 4
                      CHECK (min_grade BETWEEN 1 AND 5),

    justification     TEXT NOT NULL,

    activated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    last_activity_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    revoked_at        TIMESTAMPTZ,
    released_at       TIMESTAMPTZ,

    reviewed_at       TIMESTAMPTZ,
    reviewer_id       BIGINT REFERENCES users(id) ON DELETE SET NULL,
    review_verdict    TEXT CHECK (review_verdict IN ('justified','unjustified','partial')),
    review_notes      TEXT,

    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN (
                          'active','expired','revoked','released',
                          'reviewed_justified','reviewed_unjustified','reviewed_partial'
                      )),

    ip                INET,
    user_agent        TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- scope='resource' 일 때는 resource_id 필수
    CONSTRAINT chk_resource_scope CHECK (
        (scope = 'broad')
        OR (scope = 'resource' AND resource_id IS NOT NULL)
    )
);

-- 활성 조회는 매 자원 접근마다 일어나므로 빠른 부분 인덱스
CREATE INDEX IF NOT EXISTS idx_bg_activator_active
    ON break_glass_activations(activator_id, status)
    WHERE status = 'active';

-- 리뷰 대기: 종료되었으나 아직 판정 미완
CREATE INDEX IF NOT EXISTS idx_bg_pending_review
    ON break_glass_activations(activated_at DESC)
    WHERE reviewed_at IS NULL
      AND status IN ('expired','revoked','released');

-- 시간순 감사 조회
CREATE INDEX IF NOT EXISTS idx_bg_activated
    ON break_glass_activations(activated_at DESC);

-- 시간축 조합(대시보드 필터)
CREATE INDEX IF NOT EXISTS idx_bg_status_time
    ON break_glass_activations(status, activated_at DESC);

COMMIT;
