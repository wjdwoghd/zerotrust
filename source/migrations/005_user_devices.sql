-- =====================================================================
-- 005_user_devices.sql  (가상 기기 등록 / 기기별 TOTP)
--
-- 목적:
--   - 사용자 1명이 여러 기기(가상 기기 포함)를 등록할 수 있도록 한다.
--   - 각 기기는 고유한 mfa_secret 을 가져 기기별 TOTP 검증이 가능하다.
--   - 기존 users.mfa_secret 은 하위 호환(fallback)으로 유지한다.
--
-- 실행 순서: 001 -> 002 -> 003 -> 004 -> 005
-- =====================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS user_devices (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    device_name    TEXT NOT NULL DEFAULT '가상 기기',
    device_type    TEXT NOT NULL DEFAULT 'virtual',  -- virtual | mobile | desktop
    mfa_secret     TEXT NOT NULL,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ,
    UNIQUE (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user
    ON user_devices(user_id)
    WHERE is_active;

CREATE INDEX IF NOT EXISTS idx_user_devices_device
    ON user_devices(device_id);

COMMIT;
