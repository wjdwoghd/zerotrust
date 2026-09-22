# source 작업 지침

공통 작업 원칙은 루트 [AGENTS.md](../AGENTS.md), 브랜치·코드 작성 기준은
[CONTRIBUTING.md](../CONTRIBUTING.md)를 따른다. 같은 지침을 이 파일에 복제하지 않는다.

- HTTP 요청 검증·응답은 api/, 정책·점수·세션은 core/, 인증·비밀 처리는 security/에 둔다.
- 공개 함수 docstring, SQL 파라미터 바인딩, AuditEvent 사용 기준을 유지한다.
- source에서 scripts/run.bat test로 코드 규칙 검사와 pytest를 실행한다.
- DB 테스트 전 POSTGRES_TEST_URL이 폐기 가능한 격리 DB를 가리키는지 확인한다.
- 기본 실행 스크립트는 wipe/reseed를 수행하므로 검증 목적으로 운영 환경에서 실행하지 않는다.
- 적용된 migrations 파일과 기존 시드의 의미를 임의로 변경하지 않는다.
- 패키징 절차는 ../docs/RELEASE.md를 따른다. 생성된 토큰 런처·설치 파일은 커밋하지 않는다.
