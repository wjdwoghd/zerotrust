-- =====================================================================
-- 007_otp_token_devices.sql
--   업무용 기기와 토큰(OTP 수신)용 기기를 DB 레이어에서 분리한다.
--
-- 배경:
--   005 이전까지는 user_devices.device_type 에 {virtual, mobile, desktop} 가
--   들어갔고, 업무에 쓰는 기기의 device_id 가 그대로 user_devices 에 MFA
--   시크릿과 함께 들어가 있어 "제2 요소가 같은 기기" 에 머물렀다.
--
-- 이 마이그레이션은:
--   1) mfa_secret 을 NULL 허용으로 풀어 업무 전용 기기(mfa_secret 없음) 를
--      user_devices 안에 공존시킬 수 있게 한다.
--   2) api_key 컬럼을 추가한다. 별도로 돌아가는 "가상 기기 실행 프로그램"
--      (Tkinter 앱) 이 서버에 인증할 때 사용한다. NULL 허용 + UNIQUE.
--   3) otp_requests 테이블을 신설한다. 로그인 모달의 "OTP 전송" 이벤트를
--      토큰 기기 앱이 폴링으로 가져갈 수 있도록 보관하는 짧은 수명 큐다.
--
-- 실행 순서: 001 -> 002 -> 003 -> 004 -> 005 -> 006 -> 007
-- =====================================================================

BEGIN;

-- (1) mfa_secret 을 NULL 허용으로 변경 (업무 전용 기기 도입을 위함)
ALTER TABLE user_devices
    ALTER COLUMN mfa_secret DROP NOT NULL;

-- (2) api_key 컬럼 (토큰 앱 인증용)
ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS api_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_api_key
    ON user_devices(api_key)
    WHERE api_key IS NOT NULL;

-- (3) otp_requests — 로그인 모달 → 토큰 기기 앱 간 이벤트 큐
CREATE TABLE IF NOT EXISTS otp_requests (
    id                BIGSERIAL PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_device_pk   BIGINT NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    work_device_id    TEXT,
    ip_address        TEXT,
    location          TEXT,
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at       TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '2 minutes')
);

CREATE INDEX IF NOT EXISTS idx_otp_requests_pending
    ON otp_requests(token_device_pk, requested_at DESC)
    WHERE consumed_at IS NULL;

COMMIT;
