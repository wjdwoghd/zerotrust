# ZeroTrust 개발 규칙

이 문서는 사람과 자동화 도구가 함께 따르는 단일 개발 규칙입니다. 세부 기능과 실행 방법은 [README](README.md), 설계 근거는 [REPORT](docs/REPORT.md)를 참고합니다.

## 브랜치 운영

- `main`: 시연·배포 가능한 기존 안정 버전을 유지합니다. 검증되지 않은 변경을 직접 커밋하지 않습니다.
- `develop`: 개선 및 보완 작업을 통합합니다.
- 기능 추가·수정·개선·보완은 `develop`에서 `feat/<기능명>` 브랜치를 분기해 작업합니다.
- 변경은 테스트와 리뷰가 끝난 뒤 `develop`에 반영하고, 배포 가능한 상태에서만 `main`으로 병합합니다.

## 프로젝트 불변 원칙

1. 애플리케이션 데이터베이스는 PostgreSQL만 사용합니다. 편의를 위한 SQLite 또는 별도 운영 모드를 추가하지 않습니다.
2. `audit_logs`와 `sensitive_logs`는 append-only입니다. 애플리케이션에서 기존 감사 기록을 수정하거나 삭제하지 않습니다.
3. 마이그레이션은 forward-only입니다. 적용된 `source/migrations/0NN_*.sql`을 고치지 않고 다음 번호의 새 마이그레이션을 추가합니다.
4. 운영 DB에 `TRUNCATE`나 `DROP`을 직접 실행하지 않습니다. 시연 데이터 초기화는 `source/scripts/wipe_traces.py`, 테스트는 격리된 `zerotrust_test` DB를 사용합니다.
5. `detective_kim`, `admin_lee`, `patrol_jung` 등 시드 페르소나의 신뢰도·위반 횟수·직무 범위는 시연 시나리오의 입력입니다. 의미를 확인하지 않고 변경하지 않습니다.
6. 비밀값, 생성된 토큰 런처, 로그, 로컬 DB, 설치 파일과 빌드 산출물은 커밋하지 않습니다.

## 코드 작성 기준

- 함수와 변수는 `snake_case`, 클래스는 `PascalCase`, 상수는 `UPPER_SNAKE_CASE`를 사용합니다.
- 공개 함수에는 역할, 입력, 반환값과 보안상 주의점을 설명하는 docstring을 작성합니다.
- SQL 입력값은 문자열 보간이 아니라 파라미터 바인딩을 사용합니다.
- HTTP 핸들러는 요청 검증과 응답 조립을 담당하고, 정책·점수·세션 판단은 `source/core/`에 둡니다.
- 인증과 비밀 처리는 `source/security/`, 데이터 변경은 DB 래퍼와 서비스 계층을 통하게 합니다.
- 접근 결정, 승인, 인증, 세션, Break-Glass 사건은 `AuditEvent`를 사용해 기록합니다.
- 원본 민감 정보는 `sensitive_logs`, 정책 사건은 `audit_logs`, 앱 동작 추적은 `operation_logs`에 기록합니다.
- 현재 confidence는 진단 정보이며 접근 레벨을 변경하지 않습니다. 별도의 confidence 보정 단계를 추가하려면 정책 근거와 회귀 테스트가 필요합니다.
- 사용되지 않는 호환 함수나 임시 파일을 남길 때는 실제 호출자와 제거 조건을 주석으로 명시합니다.

## 변경 절차

1. `rg`와 코드 열람으로 실제 호출 경로, DB 컬럼, 관련 테스트를 확인합니다.
2. 정책 변경은 `source/core/scoring_engine.py`와 [설계 보고서](docs/REPORT.md)의 근거를 함께 확인합니다.
3. 한 커밋에는 하나의 관심사를 담습니다. 예를 들어 점수 정책 변경과 감사 저장 방식 변경을 섞지 않습니다.
4. 동작이 바뀌면 단위 또는 시나리오 테스트를 추가합니다. 기존 테스트를 바꿀 때는 먼저 테스트가 보호하는 정책 의도를 확인합니다.
5. 문서와 코드가 다르면 구현, 테스트, 보고서를 함께 갱신합니다.

## 검증

Windows에서는 `source` 디렉터리에서 다음 명령을 실행합니다.

```powershell
.\scripts\run.bat test
```

테스트 명령은 pytest 전에 `scripts/check_code_conventions.py`를 실행해 Python
구문·이름 규칙·핵심 공개 함수 docstring·감사 로그 불변성·마이그레이션
파일명을 검사합니다. 외부 의존성 설치 전에도 검사기만 직접 실행할 수 있습니다.

```powershell
python scripts\check_code_conventions.py
```

변경 완료 전 다음을 확인합니다.

- 전체 pytest 결과
- `git diff --check`
- `git diff --stat`과 `git status --short`
- 마이그레이션 추가 시 테스트 DB에서 반복 실행해도 안전한지 여부
- 시연 영향이 있으면 `detective_kim`, `admin_lee`, `patrol_jung` 핵심 흐름

테스트 환경이 준비되지 않아 검증하지 못한 항목은 통과한 것으로 표현하지 않고 원인을 작업 기록에 남깁니다.

## 커밋과 원격 반영

커밋 제목은 `feat`, `fix`, `refactor`, `docs`, `test`, `build`, `chore` 등의 접두어와 변경 목적을 조합합니다.

```text
refactor: 미사용 정책 호환 코드와 중간 산출물 정리
```

자동화 도구는 사용자가 명시적으로 요청한 경우에만 커밋하거나 푸시합니다.
