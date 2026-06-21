-- ====================================================================
-- ZeroTrust Capstone — Wipe Usage Traces (Keep .env + seed data)
--
-- 순서가 중요: TRUNCATE 로 의존 테이블을 먼저 비워야 DELETE FROM users 가
-- FK 충돌 없이 통과한다.
-- ====================================================================
\set ON_ERROR_STOP on

BEGIN;

-- 1) 모든 운영 로그·세션·요청 먼저 비움 (FK 의존 해소)
TRUNCATE TABLE
  audit_logs,
  sensitive_logs,
  operation_logs,
  access_logs,
  sessions,
  otp_requests,
  login_approval_requests,
  approvals,
  break_glass_activations,
  policy_override_requests
RESTART IDENTITY CASCADE;

-- 2) 시드 외 사용자의 모든 기기 정리 (사용자 삭제 전)
DELETE FROM user_devices
 WHERE user_id IN (
   SELECT id FROM users WHERE username NOT IN (
     'admin_lee','deputy_han','deputy_oh','detective_kim',
     'investigator_park','officer_choi','patrol_jung'
   )
 );

-- 3) 시드 외 사용자 모두 삭제 (FK 가 모두 정리된 상태라 안전)
DELETE FROM users
 WHERE username NOT IN (
   'admin_lee','deputy_han','deputy_oh','detective_kim',
   'investigator_park','officer_choi','patrol_jung'
 );

-- 4) 시드 사용자에 추가로 등록된 기기 정리
--    시드 device_id 패턴: registered-001~009 (work) + token-001~006 (totp_token)
DELETE FROM user_devices
 WHERE NOT (device_id LIKE 'registered-0%' OR device_id LIKE 'token-0%');

-- 5) 시드 사용자의 운영 상태 컬럼 복원
UPDATE users SET
  is_active = TRUE,
  is_locked = FALSE,
  failed_login_count = 0,
  trust_score = CASE username
    WHEN 'admin_lee'         THEN 95.0
    WHEN 'deputy_han'        THEN 90.0
    WHEN 'deputy_oh'         THEN 90.0
    WHEN 'detective_kim'     THEN 85.0
    WHEN 'investigator_park' THEN 78.0
    WHEN 'officer_choi'      THEN 70.0
    WHEN 'patrol_jung'       THEN 40.0
  END,
  violation_count = CASE username
    WHEN 'patrol_jung' THEN 5
    ELSE 0
  END
WHERE username IN (
  'admin_lee','deputy_han','deputy_oh','detective_kim',
  'investigator_park','officer_choi','patrol_jung'
);

COMMIT;

-- 검증 — 기대값:
--   users=7, devices=13, resources=15, sessions=0, audit_logs=0, approvals=0
SELECT
  (SELECT COUNT(*) FROM users)        AS users,
  (SELECT COUNT(*) FROM user_devices) AS devices,
  (SELECT COUNT(*) FROM resources)    AS resources,
  (SELECT COUNT(*) FROM sessions)     AS sessions,
  (SELECT COUNT(*) FROM audit_logs)   AS audit_logs,
  (SELECT COUNT(*) FROM approvals)    AS approvals;
