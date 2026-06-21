-- ====== UP ======
-- 018_user_devices_last_otp_step.sql
--
-- TOTP 재사용(replay) 방지 — RFC 6238 §5.2 권고 이행.
--
-- 문제:
--   기존 verify_totp 는 ±window 안의 어떤 step 이든 매칭되면 통과시키고
--   통과한 step 을 어디에도 저장하지 않았다. 결과적으로 같은 OTP 코드로
--   같은 윈도우 내 무한 재검증이 가능 (예: 로그인 → 30초 내 로그아웃 →
--   같은 코드로 재로그인).
--
-- 해법:
--   user_devices.last_otp_step (BIGINT, NULL 허용) — 마지막 통과 TOTP step
--   번호. 다음 verify 호출 시 last_otp_step 보다 작거나 같은 step 의 코드는
--   거부한다. 통과 후 step 번호를 갱신.
--
-- 호환성:
--   NULL 인 행 (기존 데이터) 은 "아직 사용 흔적 없음" 으로 취급 — 첫 검증부터
--   step 마킹이 시작된다. 마이그레이션 자체는 멱등 + 비파괴.

ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS last_otp_step BIGINT;

COMMENT ON COLUMN user_devices.last_otp_step IS
    'TOTP replay 방지: 마지막 통과된 step (Unix epoch / 30s). '
    'NULL=사용 흔적 없음. verify_totp 가 (step <= last_otp_step) 인 코드를 거부.';

-- ====== DOWN ======
ALTER TABLE user_devices
    DROP COLUMN IF EXISTS last_otp_step;
