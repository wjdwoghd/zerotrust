# 작업 계획

## v2 준비 — AI 정책 도전자

목표: 관리자가 합성된 접근 조건의 경계를 탐색하고 예상 밖 결정 조합을
검토할 수 있도록 한다. AI는 합성 시나리오 생성과 결과 설명을 맡고,
실제 접근 레벨·점수·승인 여부는 기존 서버 정책이 계산한다. 모델 학습과
파인튜닝은 범위에 포함하지 않는다. 상세 권한·데이터 경계는
[POLICY](docs/POLICY.md)의 「v2 AI 정책 도전자」를 따른다.
OpenAI API 호출과 `OPENAI_API_KEY` 사용은 v2부터 시작한다. v1 실행·설치·
테스트에는 이 키가 필요하지 않으며 v1의 규칙 기반 접근 경로는 외부 AI
서비스에 의존하지 않는다.

현재 상태: **설계 문서 준비 완료, 구현 대기**. 기능 코드, API 호출, 화면,
테스트는 아직 구현·검증하지 않았다.

초기 API 계약(구현 예정): 관리자 전용
`POST /api/admin/policy-lab/challenges`는 자유 문장 대신 고정된 실험 목표
(`boundary`, `immediate_block`, `approval_path`)와 허용 목록의 합성 조건,
요청 시나리오 수를 받는다. 서버가 개수 상한과 필드 범위를 검증하고 AI가
제안한 조건을 재검증한 뒤 정책 엔진으로 계산한다. 응답은 각 시나리오의
합성 입력, 정책 엔진 결과, AI 설명, 지원 범위·불확실성을 분리한다.
요청에서 실제 DB 사용자·자료 ID나 본문을 받지 않는다. AI 키는 서버 설정에만
두며, 키 미설정·호출 실패 시 실험 API가 명시적으로 실패한다.

| 순서 | 작업 | 완료 조건 | 상태 |
| --- | --- | --- | --- |
| 1 | 상태 변경 없는 정책 시뮬레이터 | 합성 입력만으로 지원하는 4축·즉시 차단·L1~L5 결과가 기존 정책과 일치한다. 지원하지 않는 조건은 명시적으로 거부하며, 접근 로그·세션·신뢰도·승인 상태가 바뀌지 않는다. | 예정 |
| 2 | AI 시나리오 생성 경계 | 구조화된 합성 조건만 외부 API로 전송한다. 출력은 서버가 허용 필드·범위·개수를 재검증하며, 모델 거부·시간 초과·형식 오류는 명시적으로 실패한다. 키가 없어도 기존 접근 API는 정상 동작한다. | 예정 |
| 3 | 관리자 API·화면 | 관리자 권한을 서버에서 확인한다. 시뮬레이션임을 표시하고 정책 결과와 AI 설명·불확실성을 구분한다. 실행 사실은 감사 경로에 남긴다. 일반 사용자와 미인증 요청은 차단한다. | 예정 |
| 4 | 검증·배포 준비 | 점수 경계, 즉시 차단, 인증·승인·Break-Glass 관련 지원 범위와 실제 평가의 일치 여부를 격리 DB에서 검증한다. 전체 회귀, API 응답, 실제 화면, Windows 설치·키 미설정 경로를 확인한다. | 예정 |

초기 버전은 합성 조건의 일회성 실험으로 제한한다. 실험 결과 저장 테이블과
DB 마이그레이션은 현재 필요하지 않다. 실제 사건·개인정보의 외부 전송,
자연어 자유 입력, 실험 결과의 영구 보관은 별도 정책 결정 후 확장한다.
구현 후보 경로는 `source/core/policy_simulator.py`,
`source/integrations/openai_scenario_client.py`,
`source/core/ai_policy_challenger.py`, `source/api/policy_lab_handler.py`이며
실제 기능과 함께 필요한 파일만 만든다. 기존 `source/server.py`,
`source/static/index.html`, 설정·감사 이벤트·의존성 파일과 관련 테스트를
작업 범위에 포함한다.

## v1.0.1 릴리스 검증 — 설치 검증 대기

목표: `main`에 포함된 새 버전 태그를 기준으로 격리된 PostgreSQL 테스트,
Windows 설치 파일 빌드, GitHub Release 초안 생성을 연결한다.
기존 접근 정책과 설치 데이터 교체 방식은 변경하지 않는다.

완료 조건:
- 목적별 작업 브랜치 → develop → main 절차 준수.
- PostgreSQL과 Python 의존성을 고정하고 테스트와 빌드에 같은 버전 사용.
- 기존 023 야간 정책을 검증하는 테스트 수정 및 multiplier 선택 규칙 보존.
- 코드 규칙 검사·전체 테스트·설치 파일 빌드 검증 결과 기록.
- 태그 형식 및 main 포함 여부 검사, 버전별 Release 초안 생성.
- 실제 GitHub Actions 실행과 새 Windows 환경 설치 확인은 별도 `검증 대기`로 보고.

이번 검증 범위: 전체 회귀 테스트, Windows installer 빌드, 태그별 Release
보존, CHANGELOG 정리. 수동 workflow 실행에서도 태그 생성 전에 빌드를
검증할 수 있게 하고 Release 생성은 태그 실행에만 허용한다.

- 기준: origin/main `48511d8`, origin/develop `9717bf6` (동일 파일 트리).
- 작업 브랜치: `ci/release-v1.0.1` (origin/develop에서 분기).
- 기존 main Actions: [35686506028](https://github.com/wjdwoghd/zerotrust/actions/runs/35686506028)
  테스트 성공, installer job은 태그 실행이 아니므로 미실행.
- 테스트 보강 브랜치: `test/release-validation` (`bb223cd`, `c312671`). 목표와 완료 조건은
  로그인 승인 TTL 테스트가 시드의 허용 위치에서 승인 요청을 만들고 만료를
  실제 검증하는 것. 잘못된 위치 입력을 수정하고 skip을 assertion으로 교체.
- 2026-09-22 로컬 검증: Python 3.12.10, 고정 Python 의존성, PostgreSQL 18.6.
  새 전용 클러스터 `127.0.0.1:55439/zerotrust_test` 사용.
  `scripts/run.bat test -q -ra` 최초 결과 223 passed / 1 skipped.
  누락 검증 수정 후 `scripts/run.bat test -q -ra -k session_lifecycle`: 3 passed.
  전체 반복 실행에서 테스트 전용 배율 행 잔류로 2 failed / 222 passed 확인.
  테스트 전용 행·캐시 정리를 추가한 뒤 관련 19개 테스트를 같은 DB에서
  두 번 실행해 모두 통과, 전용 행 0건과 기존 시드 배율 보존 확인.
  수정 후 전체 `scripts/run.bat test -q -ra --show-capture=no`:
  **224 passed / 0 skipped**, 283.84초. 기존 utcnow 폐기 예정 경고 333건.
- 코드 규칙 검사(70 Python 파일), pip check, actionlint 1.7.12,
  workflow 내 PowerShell 14개 단계 구문 검사 통과.
  정상 버전 4종·잘못된 태그 4종, main 미포함 커밋 거부 확인.
- 테스트 DB에서 `python scripts/run_migrations.py`: applied=0, 재적용 없음.
- 공식 installer 빌드 성공: `source/dist/ZeroTrustDemoSetup.exe`, 94,711,808 bytes.
  번들 Python import, SHA-256, 필수 런타임 포함, .env·생성 토큰 런처 제외 확인.
  workflow의 실제 metadata 단계로 체크섬·빌드 정보·의존성 목록 생성 확인.
- 사전 Actions: [35692306968](https://github.com/wjdwoghd/zerotrust/actions/runs/35692306968),
  테스트·Windows installer 빌드·메타데이터 생성·artifact 업로드 성공.
  수동 실행의 Release 단계는 생략됐음을 확인.
- develop 통합: `7064699`. 통합 후 전체 회귀는
  [Actions 35693532608](https://github.com/wjdwoghd/zerotrust/actions/runs/35693532608)에서 실행.
  이후 문서 기록 반영을 포함한 최종 통합 커밋의 결과는
  [develop Actions](https://github.com/wjdwoghd/zerotrust/actions/workflows/release.yml?query=branch%3Adevelop)와
  [main Actions](https://github.com/wjdwoghd/zerotrust/actions/workflows/release.yml?query=branch%3Amain)에서
  커밋별로 확인한다. develop 성공 후 main 반영, main 전체 회귀 성공을 순서대로 확인한다.
- v1.0.1 태그 및 Release: 사용자 승인에 따라 진행. 태그 빌드와 Release에는
  실제 Windows 설치·화면 흐름 미검증을 명시한다.
- 깨끗한 Windows 환경의 설치·바로가기·로그인/OTP·서버 종료: 미검증.
  비대화형 러너에서 설치 잠금이 해제되지 않아 자동 검사가 실패했다.
  v1.0.1에서만 생략하며 이후 버전의 검사 조건은 유지한다.
- 2026-10-05 후보 재검증: `feat/localhost-token-connection`에서 설치 실행기의
  포트 충돌 처리와 서비스 식별 확인, 설치 내용 최소화를 보완했다. 새 격리
  PostgreSQL 18.6(`127.0.0.1:55441/zerotrust_test`)에서 전체 회귀
  **252 passed / 1 skipped**. 건너뛴 1개는 호스트가 KST/+09:00일 때만
  실행하는 세션 시간대 매트릭스이며 `TZ=Asia/Seoul`로 별도 실행해 통과했다.
  마이그레이션 재실행 `applied=0`, 코드 규칙
  74개 파일·`pip check` 통과.
- 새 Windows installer 빌드와 payload 검사를 통과했다. `.env`·DB·생성 토큰
  런처·테스트/개발 스크립트가 없음을 확인했다. 압축을 별도 폴더에 풀어 번들
  Python·PostgreSQL 기동, 마이그레이션·시드, 포트 충돌 시 18080 선택,
  `/healthz`·`/readyz`·무인증 차단, 토큰 런처 주소 일치와 서버·DB 종료를 확인했다.
  이는 실제 설치기 실행·바로가기·화면 흐름 검증을 대신하지 않는다.
- `feat/localhost-token-connection` → `develop` 초안 PR #4를 생성했다.
  [최초 PR Actions 37269265746](https://github.com/wjdwoghd/zerotrust/actions/runs/37269265746)의
  Windows 회귀 검사는 성공했고 설치 빌드는 기존 조건에 따라 미실행됐다.
  설치 검증 단계 추가 후 새 Actions 결과를 확인한 뒤 통합한다.

## 후속 정책 정합성 — 진행 중

[POLICY](docs/POLICY.md)의 미확정 항목을 합의한 뒤 별도 작업으로 수행한다.
릴리스 준비 단계에서는 L3/L4 본문, OTP 승인 조건, 응답 축약, 행동 가산점을
변경하지 않았다. 후속 정책 정합성 작업은 각각 별도 브랜치에서 진행한다.

### 일반 사용자 API 응답 최소화 — 검증 완료

직접 실행할 DB·API·화면 검증 절차: [사용자 API 응답 최소화 수동 검증](docs/USER_API_RESPONSE_VERIFICATION.md).

목표: 담당 등록·Break-Glass·인증 전 승인 상태·`/auth/me` 응답에서
내부 기록 필드를 제거하고, 사건 목록·상세·상태·다운로드 평가에서 합의된
최소 공개 필드만 제공한다.
완료 조건: 사용자 화면에 필요한 상태·범위 정보가 유지되고, 사건번호·정당화 사유·
세션·접속 정보·내부 처리 시각이 해당 응답에 없다. 사건 자료는 재인증·승인
전과 거부 상태에 본문·등급·내부 근거가 없고, 허용 후에만 본문을 반환한다.
상태 폴링에서 권한이 내려가면 화면 보관 본문을 비우고, 다시 허용되면 상세를
재조회한다. 단위·API 회귀 후 격리 DB 통합 검증과 실제 화면 실증을 확인한다.

- 2026-10-04 격리 PostgreSQL 18.3 클러스터를 `build/` 아래 새로 만들고
  `127.0.0.1:55439/zerotrust_test` 연결 대상과 폐기 가능성을 확인했다.
  관련 API·단위 회귀 98개 통과·1개 건너뜀, 전체 테스트 248개 통과·1개
  건너뜀, Python 코드 규칙 검사 73개 파일 통과. 건너뛴 항목은 현재 실행 환경의
  시간대가 KST가 아닐 때 제외되는 세션 수명 시간대 매트릭스 1개다.
- 실제 React 화면을 격리 DB 서버에 연결해 로그인·MFA, 허용된 상세와 제한된
  본문, 재인증 전후, 승인 요청·관리자 승인 전후, 상태 폴링으로 권한 하락 시
  본문 삭제 및 권한 회복 시 상세 재조회를 확인했다. 담당 등록 생성·내 요청,
  Break-Glass 발동·내 활성·본인 해제, `/auth/me`의 실제 사용자 응답 필드도
  확인했다. 권한 하락·회복은 격리 DB의 시연 계정 허용 위치를 임시 변경해
  유발했으며 운영 환경 신호의 보안성 검증을 뜻하지 않는다.
- 2026-10-04 후속 점검: `d3d4d9d`의 담당 등록 생성·중복·내 요청·OTP,
  Break-Glass 발동·내 활성·해제, `/api/auth/me` 핸들러와 화면 소비 필드를
  대조했다. 합의된 최소 응답 외 내부 필드 반환은 발견되지 않아 공개 정책과
  서버·화면 코드는 변경하지 않았다. 생성·발동 핸들러 회귀 테스트 2개를 추가해
  사건번호·사유·세션·접속 정보·내부 시각이 응답에 섞이지 않는지 확인했다.
  관련 응답·화면 상태 단위 테스트 25개 통과, 전체 단위 테스트 72개 통과·
  DB 의존 47개 건너뜀, Python 코드 규칙 검사 73개 파일 통과.
- 2026-10-04 로컬 검증: 사건 응답·화면 상태 단위 테스트와 기존 응답·결정
  단위 테스트 61개 통과. 헤드리스 Chromium에서 권한 하락 시 본문 삭제와
  재인증·승인 후 상세 재조회 조건을 실행했다. 관련 DB 시나리오 59개는
  수집만 확인했고 실행하지 않았다. Python 코드 규칙 검사 73개 파일 통과.
