# 작업 계획

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
- v1.0.1 태그 및 Release 생성: 보류. 모든 검증 후 태그를 생성한다는
  작업 조건에 따라 깨끗한 Windows 설치 확인 전에는 태그를 만들지 않는다.
- 깨끗한 Windows 환경에서 설치·바로가기·로그인/OTP·서버 종료: 검증 대기.
  현 환경에 Windows Sandbox 없음. 빌드 성공을 설치 성공으로 간주하지 않음.

## 후속 정책 정합성 — 진행 중

[POLICY](docs/POLICY.md)의 미확정 항목을 합의한 뒤 별도 작업으로 수행한다.
릴리스 준비 단계에서는 L3/L4 본문, OTP 승인 조건, 응답 축약, 행동 가산점을
변경하지 않았다. 후속 정책 정합성 작업은 각각 별도 브랜치에서 진행한다.

### 일반 사용자 API 응답 최소화 — 검증 대기

목표: 담당 등록·Break-Glass·인증 전 승인 상태·`/auth/me` 응답에서
내부 기록 필드를 제거하고, 사건 목록·상세·상태·다운로드 평가에서 합의된
최소 공개 필드만 제공한다.
완료 조건: 사용자 화면에 필요한 상태·범위 정보가 유지되고, 사건번호·정당화 사유·
세션·접속 정보·내부 처리 시각이 해당 응답에 없다. 사건 자료는 재인증·승인
전과 거부 상태에 본문·등급·내부 근거가 없고, 허용 후에만 본문을 반환한다.
상태 폴링에서 권한이 내려가면 화면 보관 본문을 비우고, 다시 허용되면 상세를
재조회한다. 단위·API 회귀 후 격리 DB 통합 검증과 실제 화면 실증을 확인한다.

- 격리 PostgreSQL API 회귀와 최종 통합 검증: **검증 대기**. 현재
  `POSTGRES_TEST_URL`이 설정되지 않았고 기본 `localhost:5432/zerotrust_test`와
  과거 전용 `127.0.0.1:55439/zerotrust_test` 모두 연결되지 않는다.
- 실제 화면에서 허용·거부·재인증·승인 전후와 상태 폴링 변화 확인:
  **검증 대기**. 최종 통합 검증에서 한 번에 실증한다.
- 2026-10-04 로컬 검증: 사건 응답·화면 상태 단위 테스트와 기존 응답·결정
  단위 테스트 61개 통과. 헤드리스 Chromium에서 권한 하락 시 본문 삭제와
  재인증·승인 후 상세 재조회 조건을 실행했다. 관련 DB 시나리오 59개는
  수집만 확인했고 실행하지 않았다. Python 코드 규칙 검사 73개 파일 통과.
