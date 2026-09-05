# 운영모드 전환 보고서

본 보고서는 프롬프트 §8 (REPORT.md 구조) 순서대로 기술한다.
모든 "확인됨"은 스펙의 정책·라인 조회 기준이며, 실제 runtime 검증 결과가 아닐 수 있음을 명시한다.

---

## §8-1. 운영 전제

| 항목 | 현재 시스템 |
|---|---|
| DB | **PostgreSQL 고정** |
| DATABASE_URL | `postgresql://` 또는 `postgres://` 스킴만 허용 |
| SECRET_KEY 약한값 | 기동 거부 |
| 실행 경로 | `scripts\run.bat` (마이그레이션 + wipe/reseed + 서버 기동) |
| 테스트 경로 | `scripts\run.bat test` (`zerotrust_test` DB 격리) |
| MFA | 토큰 기기 기반 TOTP 검증 |
| Tornado debug | `TORNADO_DEBUG` 설정값 기준 |
| PRE_APPROVAL_TTL | `config.PRE_APPROVAL_TTL_SEC` |
| 관리자 로그인 승인 | `ADMIN_APPROVAL_TTL_SEC` 기준 TTL |

관련 파일: `config.py`, `security/secrets_loader.py`, `api/response_formatter.py`

---

## §8-2. 비밀 관리 / 기동 거부 흐름

1. `server.py`의 `make_app()` 최초 진입에서 `security.secrets_loader.load_and_validate()` 호출.
2. 실패 시 `SecretValidationError` 를 raise → `server.py`가 잡아 **exit code 2** 로 종료.
3. 기동 거부 조건:
   - `SECRET_KEY` ∈ 블로킹 리스트 (`"zerotrust-capstone-secret-key-2026"`, `"change-me"`, 공백)
   - `SECRET_KEY` 길이 32 미만
   - `DATABASE_URL` 스킴이 `postgresql` 또는 `postgres` 가 아님
   - `JWT_ALGORITHM` 이 허용 목록 외 (`HS256/HS384/HS512/RS*`)

확인 테스트: `tests/unit/test_opm_secrets.py`, `tests/e2e/test_e2e_production_refuse_start.py`

---

## §8-3. 데이터 계층

- `database.py` 에 `_ConnectionWrapper`/`_CursorWrapper` 추가.
  - 호출부의 `?` placeholder 를 psycopg2용 `%s` 로 변환.
  - `_translate_placeholders()` 가 문자열 리터럴을 존중하며 치환.
- 마이그레이션 러너 `scripts/run_migrations.py` 추가.
  - `schema_migrations(version, applied_at)` 테이블에 적용 이력 기록.
- 마이그레이션 파일(migrations/) — 001 ~ 021:
  1. `001_init_postgres.sql` — 베이스 스키마, BIGSERIAL / TIMESTAMPTZ / JSONB / INET
  2. `002_audit_split.sql` — operation_logs / audit_logs(append-only 트리거) / sensitive_logs / RLS 정책
  3. `003_sessions_timeout_cols.sql` — idle / absolute / high-sensitivity 컬럼
  4. `004_users_password_policy.sql` — 비밀번호 이력·변경일, approvals.is_break_glass(Phase 2 예약), policy_override_requests
  5. `005_user_devices.sql` — 다중 기기 등록(`user_devices`) 테이블 + work/totp_token/virtual 구분
  6. `006_login_break_glass.sql` — 로그인 승인 게이트 원본 테이블 (008 에서 `login_approval_requests` 로 개명)
  7. `007_otp_token_devices.sql` — totp_token 기기에 `mfa_secret` / `api_key` 컬럼 추가
  8. `008_rename_admin_approval.sql` — 006 의 "break-glass" 명칭을 `login_approval_requests` / `sessions.is_admin_gated` 로 개명
  9. `009_break_glass_activations.sql` — Phase 2 BG 발동 이력(`break_glass_activations`) + 사후심사 컬럼
  10. `010_approvals_download_allowed.sql` — `approvals.download_allowed` 추가 (열람-only / 다운로드 허용 분리)
  11. `011_sessions_reauth_at.sql` — L3 재인증 성공 시각(`sessions.reauth_at`) — 재인증 만료 추적
  12. `012_job_relevance.sql` — `users.job_scope` JSONB — 직무 연관성(-20) 판정용 카테고리 배열
  13. `013_sessions_pending_reauth.sql` — 동시 로그인 감지 시 `sessions.pending_reauth` + `pending_reauth_at` 잠금 컬럼
  14. `014_audit_logs_drop_user_fk.sql` — 감사 로그 보존을 위한 사용자 FK 완화
  15. `015_policy_thresholds.sql` — 정책 임계값 외부화
  16. `016_policy_overrides.sql` — 사전 승인/정책 override 이력
  17. `017_access_decision_reviews.sql` — 접근 결정 리뷰 이력
  18. `018_user_devices_last_otp_step.sql` — TOTP replay 방지용 step 저장
  19. `019_trust_changes.sql` — trust_score 변경 이력
  20. `020_zerotrust_access_tuning.sql` — 접근 판단 튜닝 보강
  21. `021_case_assignment_requests.sql` — 사건 배정 요청/승인 흐름

확인 테스트: `tests/unit/test_db_placeholder.py`

---

## §8-4. 인증 / 세션 / 접근제어 강화

- `security/mfa_service.py`
  - `pyotp.TOTP(...).verify(otp, valid_window=±1)` 사용, 모듈 부재 시 HMAC-SHA1 폴백.
- `security/jwt_handler.py` — `iss` / `aud` 클레임 추가, decode 시 검증.
- `core/session_guard.py`
  - `check_session()` 이 IDLE(15m) / HIGH_SENS(5m) / ABSOLUTE(8h) 순으로 만료 판정.
  - `SessionCheckResult(ok, reason, event_type)` 리턴 → `BaseHandler.require_auth()` 가 해당 AuditEvent 발행.
- `core/travel_service.py`
  - `IMPOSSIBLE_TRAVEL_KMH = 800` 기준 동적 판정.
  - `access_evaluator.py` 의 하드코딩 `"impossible_travel": False` 를 대체.
- `config.PRE_APPROVAL_TTL_SEC` 가 production 에서 `1800`.
  - 기존 `elapsed < 3600` 하드코드가 이 변수로 교체됨 (자원 단위 사전 승인).

확인 테스트:
  `tests/unit/test_st_session.py`, `tests/unit/test_mfa_gating.py`,
  `tests/unit/test_jwt_handler.py`, `tests/unit/test_an_anomaly.py`,
  `tests/e2e/test_e2e_break_glass.py`, `tests/e2e/test_e2e_session_timeouts.py`

---

## §8-5. 감사 3계층 + 외부 응답 최소화

### 감사 3계층
- `core/audit_events.py` — `AuditEvent` 문자열 enum + `_SCHEMAS` 로 필수 필드 계약.
- `audit_log(db, event, ..., layer=...)` 이 `layer` 값에 따라 테이블을 분기:
  - `operation` → `operation_logs`
  - `audit`     → `audit_logs` (append-only 트리거, DELETE/UPDATE 차단)
  - `sensitive` → `sensitive_logs` (RLS: sec_audit_reader 롤만 SELECT)
- stdout 구조화 JSON 로거 (`zerotrust.audit`) 병렬 출력.

### 외부 응답 최소화
- `api/response_formatter.py` 가 production 외부 바디에 `{request_id, status, external_message, decision:{level, label_en}, resource}` 만 남기고, 내부 reason/risk_score/scoring/policy_check/anomaly_check 은 모두 제거.
- demo/staging 은 `debug` 필드로 디버그 정보 포함.

확인 테스트:
  `tests/unit/test_au_audit.py`, `tests/unit/test_response_formatter.py`,
  `tests/unit/test_opm_audit_emit_consistency.py`, `tests/e2e/test_e2e_response_redaction.py`

---

## §8-6. 운영 경화 (L6)

- `server.py`
  - `HealthzHandler` / `ReadyzHandler` / `MetricsHandler` 추가. production 에서 `/api/metrics` 는 관리자 토큰 필수.
  - SIGTERM / SIGINT 수신 시 최대 5초 drain 후 IOLoop.stop().
  - `debug` 는 `config.TORNADO_DEBUG` (production → False) 기반.
  - production 빈 DB 에서 자동 시드 금지.
- `api/base_handler.py`
  - `X-Request-ID` 생성·응답, 보안 헤더(`X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options: DENY`, production 에서 HSTS, CSP)
  - `write_error()` 가 production 에서 stacktrace 를 제거, `request_id` 포함.
  - 401 응답에 `WWW-Authenticate: Bearer error="token_expired"` 삽입.
- 배포:
  - `scripts/run.bat` / `scripts/run.ps1` — `.env` 로드, 마이그레이션, wipe + reseed, Tornado 기동 통합 (운영 모드 단일).
  - `scripts/README.md` — 기동 순서 / 롤백 / 헬스·레디니스 / 모드별 기동 커맨드.

확인 테스트: `tests/e2e/test_e2e_healthz_readyz.py`, `tests/e2e/test_e2e_security_headers.py`, `tests/unit/test_opm_secrets.py`

---

## 주의 / 한계

- **실제 pytest 실행 및 커버리지 측정은 본 세션
