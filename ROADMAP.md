# 작업 계획

## v1.0.1 릴리스 검증 — 진행 중

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
- 새 변경의 전체 테스트·installer 빌드·Actions·깨끗한 Windows 설치: 검증 대기.

## 후속 정책 정합성 — 미착수

[POLICY](docs/POLICY.md)의 미확정 항목을 합의한 뒤 별도 작업으로 수행한다.
현재 작업은 L3/L4 본문, OTP 승인 조건, 응답 축약, 행동 가산점을 변경하지 않는다.
