# Deployment / Operations Scripts

운영 모드 단일 시스템의 기동·테스트·관리 스크립트.

---

## 한눈에 보기

| 스크립트 | 역할 |
|----------|------|
| `run.bat` / `run.ps1` | 통합 실행 — 운영 기동 + 테스트 실행 (인자 분기) |
| `run_migrations.py` | PG 마이그레이션 적용 (멱등) |
| `wipe_traces.py` | 운영 데이터 흔적 청소 (TRUNCATE 13 tables) |
| `bootstrap_admin.py` | 빈 운영 DB 에 관리자 1명 부트스트랩 (운영 정공) |
| `regenerate_launchers.py` | DB 의 토큰 기기 정보로 `apps/launchers/*.pyw` 재작성 |
| `build_exe_launchers.py` | 토큰 앱 런처를 PyInstaller 로 `.exe` 빌드 |

---

## 사전 준비 (1회)

1. **PostgreSQL 15+ 설치 + 가동**
2. **운영 / 테스트 DB 두 개 생성** (postgres 슈퍼유저로):
   ```sql
   CREATE USER ztuser WITH PASSWORD '...';
   CREATE DATABASE zerotrust       OWNER ztuser;
   CREATE DATABASE zerotrust_test  OWNER ztuser;
   ```
3. **`.env` 작성**: `cp .env.example .env` 후 값 채우기
   - `SECRET_KEY`: 32자 이상 랜덤 — `python -c "import secrets;print(secrets.token_hex(32))"`
   - `DATABASE_URL=postgresql://ztuser:...@localhost:5432/zerotrust`

---

## 운영 기동 — `scripts\run.bat`

원클릭으로 다음을 차례 수행:

```
1) 포트 8000 점유 프로세스 자동 종료 (이전 서버 잔재 정리)
2) .env 로드 + SECRET_KEY / postgresql:// URL 검증
3) 마이그레이션 적용 (멱등 — 첫 실행이면 스키마 생성, 이후 skip)
4) 사용 흔적 청소 (TRUNCATE 운영 데이터 테이블 13개)
5) 시드 재삽입 (사용자 7명 + 자료 15건 + 토큰 기기 + 런처 .pyw 갱신)
6) Tornado 서버 기동 (포트 8000)
```

**결과**: 매 실행 = 깨끗한 시드 + 떠있는 서버. 발표/시연 환경에 최적화.

**주의**: 시연 도중 다시 실행하면 진행 데이터(승인 처리 내역, 새로 만든 계정 등)가 모두 사라진다. 한 번에 한 번만 실행할 것.

PowerShell 사용자는 `scripts\run.ps1` 로 동일 동작.

> PowerShell 처음 실행 시 ExecutionPolicy 차단이 뜨면 다음 한 번만 실행:
> ```
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> 또는 매번 우회: `powershell -ExecutionPolicy Bypass -File scripts\run.ps1`

---

## 테스트 실행 — `scripts\run.bat test`

```
scripts\run.bat test                  # 전체 테스트 스위트
scripts\run.bat test -k smoke         # smoke 시나리오만
scripts\run.bat test -v -k decision   # verbose + decision 매트릭스만
scripts\run.bat test --tb=long        # 실패 시 상세 traceback
```

`test` 뒤의 인자는 그대로 `pytest` 에 전달된다.

테스트는 **`zerotrust_test` DB 만** 사용한다. 운영 DB(`zerotrust`)는 절대 건드리지 않으며 `tests/conftest.py` 가 환경변수 강제 격리로 보장한다.

PowerShell: `scripts\run.ps1 test [pytest args]`

---

## 첫 관리자 부트스트랩 — `scripts/bootstrap_admin.py`

데모 시드 대신 운영용 관리자 1명만 만들고 싶을 때 사용. `init_data.py seed()` 와 달리 `detective_kim / password123` 같은 데모 계정을 섞지 않는다.

```cmd
set ADMIN_USERNAME=sec_admin
set ADMIN_PASSWORD=...32자이상...
python scripts\bootstrap_admin.py
```

생성하는 것:
1. `users` 행 — `role='admin'`, `trust_score=95`, 모든 직무 카테고리를 `job_scope` 로 포함
2. `user_devices` 행 2개 — 업무 기기(`work`) + 토큰 기기(`totp_token` + `api_key` + `mfa_secret`)
3. `audit_logs` 에 `ADMIN_BOOTSTRAPPED` 이벤트

**`api_key` 는 출력 시점에만 평문 노출**. 즉시 안전한 곳에 보관 + 터미널 스크롤백 청소.

재실행 시 `users` 에 데이터가 있으면 아무 것도 하지 않고 종료(idempotent).

---

## 마이그레이션 운영

- 파일 위치: `migrations/001_init_postgres.sql` … `013_sessions_pending_reauth.sql`
- 실행자: `scripts/run_migrations.py`
- 적용 이력: `schema_migrations(filename, applied_at)` 테이블
- 이미 적용된 버전은 자동 skip

### 신규 마이그레이션 작성 규칙
1. 파일명: `NNN_short_description.sql` (3자리 zero-padding, 014 부터)
2. **idempotent DDL** (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`) 사용
3. `BEGIN ... COMMIT` 으로 트랜잭션 명시
4. `audit_logs` append-only 트리거를 건드리지 말 것
5. 적용 전에 `zerotrust_test` 에서 검증 (`scripts\run.bat test`)

---

## `audit_logs` append-only 검증

`migrations/002_audit_split.sql` 이 `audit_logs` 에 BEFORE UPDATE OR DELETE 트리거(`trg_audit_logs_no_update`)를 걸어 모든 수정·삭제를 거부한다.

설치 확인:
```sql
SELECT tgname FROM pg_trigger WHERE tgname='trg_audit_logs_no_update';
```

거부 동작 회귀 검증:
```
scripts\run.bat test -k audit_log
```

→ `tests/scenarios/test_security_p0.py::test_audit_log_update_blocked_by_trigger`,
   `test_audit_log_delete_blocked_by_trigger` 가 트리거 동작을 자동 단언.

---

## 운영 단말 발급 흐름 (웹 UI)

부트스트랩된 관리자가 추가 운영 단말을 발급하는 표준 경로:

1. 브라우저로 `http://localhost:8000` 접속, 관리자 로그인
2. 좌측 사이드바 **"📱 기기 설정"**
3. **"+ 토큰 기기 등록"** → `POST /api/devices` → `device_id` / `api_key` / `launch_hint` 가 1회만 노출
4. 표시된 값으로 `apps/virtual_device.py` 실행

권한: 일반 사용자도 자기 기기는 본인이 등록/삭제 가능. 계정당 토큰 기기는 1개만(`device_handler.py` 가 중복 거부). 사용자당 최대 기기 수 10개.

---

## 헬스 / 레디니스 / 메트릭

| Endpoint | 목적 | 인증 |
|---|---|---|
| `/healthz` | 프로세스 생존 여부 | 없음 |
| `/readyz`  | DB 핑 + 설정 로드 | 없음 |
| `/api/metrics` | 인프로세스 카운터 | 관리자 토큰 필수 |

L4 로드밸런서 헬스체크는 `/readyz` 권장.

---

## SIGTERM / 우아한 종료

`server.py` 는 SIGTERM / SIGINT 수신 시:
1. 진행 중인 요청을 최대 **5초** drain
2. 활성 세션 일괄 비활성화 (감사 로그 기록)
3. IOLoop.stop() → 프로세스 종료

데몬 매니저(systemd 등) 설정 권장: `KillSignal=SIGTERM` + `TimeoutStopSec=10`.

---

## 롤백 절차

마이그레이션은 forward-only 설계. 롤백 필요 시:

1. **보상 마이그레이션** 작성 — 예: `014_revert_013.sql`
2. `zerotrust_test` 에서 적용 검증 (`scripts\run.bat test`)
3. 운영 적용

`audit_logs` / `sensitive_logs` 는 append-only 트리거가 걸려 있어 절대 직접 삭제하지 말 것.

---

## 참고

- NIST SP 800-207 Zero Trust Architecture
- ISO 27001 9.4 (privileged access exception)
