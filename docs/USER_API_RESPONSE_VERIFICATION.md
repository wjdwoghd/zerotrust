# 사용자 API 응답 최소화: 수동 검증 절차

대상: `feat/user-api-response-minimal`의 `d3d4d9d` 이후 변경. 격리 PostgreSQL
API 회귀와 실제 화면 흐름은 2026-10-04 검증했다. 이 문서는 재검증할 때
사용한다. 공개 필드 기준은 [POLICY](POLICY.md)의
**일반 사용자 상태 응답 범위**를 따른다.

## 1. 폐기 가능한 DB 확인

테스트 픽스처(`source/tests/conftest.py`)는 시작할 때 마이그레이션을 적용하고,
DB를 쓰는 테스트마다 `wipe_traces.py`로 테이블을 초기화한 뒤 합성 시드를 넣는다.
`wipe_traces.py`는 감사 로그를 포함한 13개 테이블을 비운다. 따라서 전용
클러스터·컨테이너의 **폐기 가능한** `zerotrust_test`만 대상으로 지정한다.
이름만 `zerotrust_test`인 공유 DB도 사용하면 안 된다.

1. PostgreSQL 서비스 또는 전용 컨테이너를 가동하고, 그 안의 `zerotrust_test`
   DB가 폐기 가능함을 확인한다. 설치·생성 안내는 [README](../README.md#소스에서-실행하기)를
   참고한다. 테스트 DB가 준비되지 않으면 아래 테스트와 초기화 명령을 실행하지
   않고 `ROADMAP.md`에 원인을 남긴다.
2. PowerShell에서 저장소의 `source`로 이동해 Python 환경을 활성화한다.
   `.venv`가 없다면 README의 Python 환경 준비 단계를 먼저 수행한다.

   ```powershell
   cd C:\zerotrust\source
   .\.venv\Scripts\Activate.ps1
   $secureUrl = Read-Host '폐기 가능한 POSTGRES_TEST_URL 전체 입력' -AsSecureString
   $env:POSTGRES_TEST_URL = [System.Net.NetworkCredential]::new('', $secureUrl).Password
   Remove-Variable secureUrl
   ```

   URL 형식은 `postgresql://<사용자>:<비밀번호>@<전용 호스트>:<포트>/zerotrust_test`다.
   비밀번호에 특수문자가 있다면 URL 인코딩한다. URL·OTP·토큰을 명령 출력이나
   결과 기록에 복사하지 않는다.
3. **초기화 전에** 아래 읽기 전용 확인을 실행한다. 출력된 DB명·호스트·포트가
   준비한 전용 DB와 일치해야 한다. 접속 성공만으로 폐기 가능성이 증명되지는
   않으므로 컨테이너/클러스터 소유와 보존할 데이터가 없는지도 확인한다.

   ```powershell
   @'
   import os
   from urllib.parse import urlsplit
   import psycopg2

   url = os.environ.get("POSTGRES_TEST_URL", "")
   target = urlsplit(url)
   if target.scheme != "postgresql" or target.path != "/zerotrust_test":
       raise SystemExit("테스트 DB URL의 스킴 또는 DB명이 올바르지 않습니다")
   with psycopg2.connect(url) as connection:
       with connection.cursor() as cursor:
           cursor.execute("SELECT current_database(), inet_server_addr(), inet_server_port()")
           database, host, port = cursor.fetchone()
   if database != "zerotrust_test":
       raise SystemExit("실제 연결 DB가 zerotrust_test가 아닙니다")
   print(f"확인된 DB: {database}, 서버: {host}, 포트: {port}")
   '@ | python -
   ```

## 2. API·회귀 테스트

위의 **같은 PowerShell 창**에서 실행한다. 테스트를 실행하는 동안 화면용
서버를 같은 DB에 붙이지 않는다. 테스트마다 시드가 초기화되기 때문이다.

```powershell
python -m pytest tests/unit/test_user_response_minimal.py tests/unit/test_case_response_contract.py tests/unit/test_case_screen_state.py tests/scenarios/test_access_consistency.py tests/scenarios/test_smoke.py tests/scenarios/test_security_p0.py tests/scenarios/test_security_p1.py tests/scenarios/test_security_p2.py tests/scenarios/test_session_lifecycle.py -q -ra --show-capture=no
.\scripts\run.bat test -q -ra --show-capture=no
git diff --check
```

첫 명령은 관련 단위·API 시나리오, 두 번째는 코드 규칙 검사와 전체 pytest를
실행한다. 종료 코드, 통과·실패·skip 개수와 skip 이유를 적는다. DB 연결 실패로
skip된 API 시나리오는 통과로 간주하지 않는다. OTP 시간대나 세션 상태에 따른
실패는 해당 테스트의 오류부터 확인하고, 기대값이나 정책을 임의로 바꾸지 않는다.

## 3. 실제 화면과 네트워크 응답

테스트를 마친 뒤 같은 전용 DB를 화면 검증용 합성 시드로 초기화한다. **1절의
대상을 다시 확인한 후에만** 다음 명령을 실행한다. `run.ps1`의 인자 없는 기본
실행은 `.env`를 로드하고 DB 초기화 및 포트 8000의 기존 프로세스 종료까지
수행하므로, 여기서는 사용하지 않는다.

```powershell
$env:DATABASE_URL = $env:POSTGRES_TEST_URL
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python scripts\run_migrations.py
if ($LASTEXITCODE -ne 0) { throw '마이그레이션 실패: 초기화 중단' }
python scripts\wipe_traces.py
if ($LASTEXITCODE -ne 0) { throw '초기화 실패: 시드 중단' }
python init_data.py
if ($LASTEXITCODE -ne 0) { throw '시드 실패: 서버 시작 중단' }
python server.py
```

각 명령이 성공한 경우에만 다음 명령으로 진행한다. 서버가 실행 중인 창은
그대로 두고 `http://127.0.0.1:8000`을 브라우저에서 연다. 시드 계정과 토큰
기기 실행법은 [README의 데모 계정](../README.md#데모-계정)을 따른다.
재시드 후 `source/apps/launchers/`의 토큰 런처가 갱신되므로 새 런처를 사용한다.
브라우저 A는 일반 사용자, 브라우저 B 또는 시크릿 창은 `admin_lee`로 사용한다.
같은 계정을 두 창에서 로그인하면 동시 세션 재인증 흐름이 개입할 수 있다.

개발자 도구의 **Network → Fetch/XHR → Response**와 화면을 함께 본다.
실제 응답의 상태·필드 이름만 기록하고 토큰·OTP·본문 전체는 기록하지 않는다.

| 확인 흐름 | 화면과 API에서 기대할 결과 |
| --- | --- |
| 로그인 후 `/api/auth/me` | `user`에는 `id`, `username`, `name`, `role`, `trust_score`, `violation_count`만, `session`에는 유휴 제한·잔여 시간, 절대 잔여 시간, 관리자 게이트 여부만 표시. 등록 기기, 허용 위치, 담당 사건, 세션 ID·접속 이력 없음. |
| 사건 목록 `GET /api/resources/cases` | 각 행은 `id`, `title`, `is_assigned_case`만 포함. |
| 비담당 사건 클릭·담당 등록 | 목록 클릭은 담당 등록 요청 창을 연다. `assignment_request` 객체에는 요청 ID·자료 ID·상태, 상태 목록에서는 제목만 추가. 사건번호·사유·검토자·처리 시각 없음. 관리자 OTP 요구 후 사용자 OTP와 최종 승인 전후의 상태도 확인. |
| 제한·거부 상세 | 목록 응답의 `id`로 `#case-detail/<id>`에 직접 이동할 수 있다. `GET .../cases/<id>`에서 `VERIFY`/`DENY`이면 `resource`는 `id`, `title`뿐이고 본문·등급·사건번호·내부 점수·근거가 없다. 열람·다운로드 버튼은 비활성. |
| 재인증·승인 전후 | 상세 응답의 `actions.reauthenticate`가 참인 자료에서는 OTP 재인증 전후를, `actions.request_approval`이 참인 자료에서는 사용자 요청과 다른 관리자 계정의 승인 전후를 확인. 허용 전 본문 없음, 허용 후 상세 재조회에서만 본문 등장. 열람 전용 승인 시 다운로드는 계속 제한. 적합한 자료가 없으면 그 흐름은 `미실증`으로 남긴다. |
| 상태 폴링·권한 변화 | 허용된 자료의 열람 창을 연 상태에서 시뮬레이션 패널의 접근 위치를 `비허용위치`로 바꾼다. 약 3초 간격의 `GET .../status` 응답에는 `resource`가 없고, `can_view=false`가 오면 열린 창과 화면 보관 본문이 사라져야 한다. 위치를 되돌리고 서버가 다시 `can_view=true`를 내면 상세 GET이 새로 발생한 뒤에만 본문이 보여야 한다. 세션 잠금이 발생하면 정해진 재인증 절차를 거친다. |
| Break-Glass | `actions.attempt_break_glass=true`인 상세에서 발동하고 `POST /api/break-glass/activate`, `GET /api/break-glass/my-active`, 해제 응답을 확인. 발동·활성 응답에는 ID·범위·자료 ID·최소 등급·만료·상태만 있고 정당화 사유·세션·IP·User-Agent·내부 처리 시각은 없다. |
| 다운로드 | 제한 상태의 `GET .../file`은 본문을 반환하지 않고, 허용 상태에서만 파일을 반환한다. `GET .../status` 폴링 자체로 행동 위험도가 올라가지 않아야 한다. |

정상 허용 자료는 `detective_kim`의 담당 자료에서 시작할 수 있다. 승인 자료
탐색 시에는 비담당 목록 클릭이 상세 대신 담당 등록 창을 여므로, 목록 응답의
ID로 상세 주소에 직접 이동한다. 시간대·위치 시뮬레이션은 판단 결과에 영향을
줄 수 있다. 특정 시드가 반드시 L3/L4가 된다고 가정하지 말고 실제
`status`와 `actions`를 기준으로 검증한다. 화면만 가려지고 API에 본문이 남아
있다면 실패다.

## 4. 결과 기록과 다음 단계

`ROADMAP.md`의 **일반 사용자 API 응답 최소화** 항목에 실행 날짜, 브랜치·
커밋, 전용 DB의 호스트·포트·DB명(비밀번호 제외), 테스트 명령과 통과·실패·
skip 수, 화면에서 실제로 확인한 흐름을 적는다. 실패는 API 경로·상태·노출된
필드 이름·재현 단계만 기록한다. 실행하지 못한 흐름은 계속 `검증 대기`로 둔다.

격리 DB API 회귀와 실제 화면 검증이 모두 끝나고 발견된 결함까지 수정·재검증된
뒤에 `develop` 통합을 판단한다. 통합 후에는 전체 회귀 검증을 다시 수행한다.
