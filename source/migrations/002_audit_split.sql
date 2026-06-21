-- =====================================================================
-- 002_audit_split.sql  (L2-2, L5)
-- audit_logs 를 3계층으로 분리하고 Row-Level Security (L2-3) DDL을 적용한다.
--
-- 계층:
--   operation_logs   — 앱 트레이스 (TTL 30일, 대량성 OK)
--   audit_logs       — 접근 결정·정책 발동 기록 (수정 금지 대상)
--   sensitive_logs   — 원본 민감값 (해시 전 원문). RLS 필수.
-- =====================================================================

BEGIN;

-- 1) operation_logs : 고빈도 트레이스
CREATE TABLE IF NOT EXISTS operation_logs (
    id           BIGSERIAL PRIMARY KEY,
    request_id   TEXT,
    event_type   TEXT NOT NULL,
    severity     INTEGER NOT NULL DEFAULT 1,
    details      JSONB,
    user_id      BIGINT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_operation_logs_time ON operation_logs(created_at DESC);

-- 2) 기존 audit_logs 는 "audit" 계층의 소스로 재사용한다.
--    수정 금지 강제: append-only 트리거.
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only (trigger audit_logs_immutable)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs;
CREATE TRIGGER trg_audit_logs_no_update
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();

-- 3) sensitive_logs : 원문 민감값 보관. RLS ON.
CREATE TABLE IF NOT EXISTS sensitive_logs (
    id                   BIGSERIAL PRIMARY KEY,
    request_id           TEXT,
    event_type           TEXT NOT NULL,
    payload_hash         TEXT NOT NULL,
    payload_encrypted    BYTEA,
    user_id              BIGINT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS 활성화 + 정책.
--   실 운영에서는 `sec_audit_reader` 롤이 CONNECT 가능해야 하며,
--   일반 앱 롤(`ztapp`)은 INSERT 만 허용한다.
ALTER TABLE sensitive_logs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    -- 감사 전용 롤이 없으면 생성 (존재 시 무시)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sec_audit_reader') THEN
        CREATE ROLE sec_audit_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ztapp') THEN
        CREATE ROLE ztapp NOLOGIN;
    END IF;
END$$;

DROP POLICY IF EXISTS sensitive_logs_read ON sensitive_logs;
CREATE POLICY sensitive_logs_read ON sensitive_logs
    FOR SELECT
    TO sec_audit_reader
    USING (TRUE);

DROP POLICY IF EXISTS sensitive_logs_insert ON sensitive_logs;
CREATE POLICY sensitive_logs_insert ON sensitive_logs
    FOR INSERT
    TO ztapp
    WITH CHECK (TRUE);

-- 4) users 테이블 방어심도 RLS — "자기 자신 또는 관리자만 조회"
--    앱 단 인가와 중복되지만 정책 우회 시 방어.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_self_or_admin ON users;
CREATE POLICY users_self_or_admin ON users
    FOR SELECT
    TO ztapp
    USING (
        current_setting('app.current_user_id', TRUE)::BIGINT = id
        OR current_setting('app.current_role', TRUE) = 'admin'
    );

COMMIT;
