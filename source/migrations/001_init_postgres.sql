-- =====================================================================
-- 001_init_postgres.sql  (L2-2)
-- 기존 6개 테이블을 PostgreSQL 타입·제약으로 재정의한다.
--   INTEGER PRIMARY KEY AUTOINCREMENT → BIGSERIAL PRIMARY KEY
--   TIMESTAMP DEFAULT CURRENT_TIMESTAMP → TIMESTAMPTZ DEFAULT now()
--   JSON 컬럼 → JSONB
-- 실행 순서: 001 → 002 → 003 → 004
-- =====================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id                   BIGSERIAL PRIMARY KEY,
    username             TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    name                 TEXT NOT NULL,
    department           TEXT NOT NULL,
    rank                 TEXT NOT NULL,
    role                 TEXT NOT NULL DEFAULT 'user',
    registered_devices   JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_locations    JSONB NOT NULL DEFAULT '[]'::jsonb,
    assigned_cases       JSONB NOT NULL DEFAULT '[]'::jsonb,
    mfa_secret           TEXT,
    trust_score          NUMERIC(5,2) NOT NULL DEFAULT 80.00,
    violation_count      INTEGER NOT NULL DEFAULT 0,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    is_locked            BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_department ON users(department);

CREATE TABLE IF NOT EXISTS resources (
    id                   BIGSERIAL PRIMARY KEY,
    case_number          TEXT NOT NULL,
    title                TEXT NOT NULL,
    description          TEXT,
    content              TEXT,
    sensitivity_grade    INTEGER NOT NULL CHECK (sensitivity_grade BETWEEN 1 AND 5),
    data_type            TEXT NOT NULL DEFAULT 'summary',
    department           TEXT,
    requires_approval    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_resources_case ON resources(case_number);
CREATE INDEX IF NOT EXISTS idx_resources_grade ON resources(sensitivity_grade);

CREATE TABLE IF NOT EXISTS sessions (
    id                        BIGSERIAL PRIMARY KEY,
    user_id                   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token                     TEXT UNIQUE NOT NULL,
    device_id                 TEXT,
    ip_address                INET,
    location                  TEXT,
    login_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity             TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at                TIMESTAMPTZ,
    is_active                 BOOLEAN NOT NULL DEFAULT TRUE,
    max_sensitivity_accessed  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS access_logs (
    id                          BIGSERIAL PRIMARY KEY,
    session_id                  BIGINT REFERENCES sessions(id) ON DELETE SET NULL,
    user_id                     BIGINT NOT NULL REFERENCES users(id),
    resource_id                 BIGINT NOT NULL REFERENCES resources(id),
    risk_score                  NUMERIC(6,2),
    trust_score                 NUMERIC(6,2),
    object_sensitivity_score    NUMERIC(6,2) DEFAULT 0,
    environment_risk_score      NUMERIC(6,2) DEFAULT 0,
    behavior_risk_score         NUMERIC(6,2) DEFAULT 0,
    work_fitness_score          NUMERIC(6,2) DEFAULT 0,
    decision_level              INTEGER,
    decision_label              TEXT,
    reason_code                 TEXT,
    reason_detail               TEXT,
    device_id                   TEXT,
    ip_address                  INET,
    location                    TEXT,
    action_type                 TEXT NOT NULL DEFAULT 'view',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_access_logs_user_time ON access_logs(user_id, created_at DESC);

-- 임시 단일 audit_logs — 002 에서 3계층으로 분리한다.
CREATE TABLE IF NOT EXISTS audit_logs (
    id           BIGSERIAL PRIMARY KEY,
    request_id   TEXT,
    layer        TEXT DEFAULT 'audit',
    event_type   TEXT NOT NULL,
    severity     INTEGER NOT NULL DEFAULT 3,
    details      JSONB,
    user_id      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON audit_logs(event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
    id             BIGSERIAL PRIMARY KEY,
    requester_id   BIGINT NOT NULL REFERENCES users(id),
    resource_id    BIGINT NOT NULL REFERENCES resources(id),
    reason         TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    approver_id    BIGINT REFERENCES users(id),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

COMMIT;
