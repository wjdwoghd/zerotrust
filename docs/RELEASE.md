# Windows 릴리스 절차

## 버전과 산출물

버전의 기준은 `main`에 포함된 커밋의 새 `vMAJOR.MINOR.PATCH` Git 태그다.
별도의 애플리케이션 버전 파일은 없다. 태그를 이동하거나 재사용하지 않는다.
`v1.0.1` 후보는 `v1.0.0` 이후의 수정·정리와 배포 자동화를 포함한다.

`.github/workflows/release.yml`은 격리 PostgreSQL 테스트가 성공한 뒤 Windows
installer를 빌드한다. 각 태그의 새 Release **초안**에 다음 파일을 첨부한다.

- `ZeroTrustDemoSetup.exe`
- `SHA256SUMS.txt`: 설치 파일의 SHA-256
- `BUILD-INFO.txt`: 태그, 소스 커밋, Python/PostgreSQL 버전과 DB 배포본 체크섬
- `DEPENDENCIES.txt`: 빌드 환경의 Python 의존성

파일명이 같아도 Release별로 독립 저장된다. `gh release create --verify-tag
--draft`만 사용하며 기존 Release 수정·asset 덮어쓰기를 수행하지 않는다.
같은 태그의 Release가 이미 있으면 생성이 실패하므로 기존 asset을 지우지 말고
Actions artifact와 실패 로그를 확인한다. 명령 동작은
[GitHub CLI 문서](https://cli.github.com/manual/gh_release_create)를 참고한다.

## 검증과 통합

1. 목적에 맞는 작업 브랜치를 develop에서 분기한다. CI 수정은 `ci/*`,
   installer 수정은 `build/*`, 테스트는 `test/*`, 문서는 `docs/*`를 사용한다.
2. Python 3.12.10과 `source/requirements-release.txt`의 고정 의존성을 사용한다.
   `.github/scripts/setup-postgres.ps1 -Destination <전용 임시 경로>`로
   PostgreSQL 18.6 공식 배포본의 SHA-256과 실행 버전을 검증한다.
3. 폐기 가능한 전용 클러스터에 `zerotrust_test`를 생성하고
   `POSTGRES_TEST_URL`을 지정한다. 테스트 fixture는 해당 DB를 초기화하므로
   보존할 DB를 지정하지 않는다. source에서 `scripts/run.ps1 test -q -ra`를
   실행한다. 실패뿐 아니라 skip 이유도 기록한다.
4. `DATABASE_URL`도 같은 테스트 DB로 지정한 뒤
   `python scripts/run_migrations.py`를 실행해 재적용이 없는지 확인한다.
5. source에서 공식 빌드를 실행한다.

   ```powershell
   python packaging/windows/build_installer.py --postgres-source <검증된-pgsql-경로> --python-source <python.exe가-있는-경로>
   ```

   출력은 `source/dist/ZeroTrustDemoSetup.exe`다. IExpress가 필요하며,
   Python 런타임과 애플리케이션 의존성, PostgreSQL의 bin/lib/share를 포함한다.
   개인 전역 Python 환경 대신 깨끗한 빌드 런타임을 사용한다.
6. 태그 전 CI 빌드 검증은 Actions의 Run workflow에서 대상 브랜치를 선택한다.
   수동 실행은 테스트·빌드·`installer-validation-<run_id>` artifact까지만 생성한다.
   Release는 만들지 않는다. [수동 실행 안내](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
7. 검증 결과를 ROADMAP에 기록하고 develop 통합 후 전체 테스트를 다시 실행한다.
   main 반영 후에도 전체 회귀 검증과 CHANGELOG·빌드 조건을 확인한다.
8. 검증된 main 커밋에 `v1.0.1` annotated tag를 만들고 push한다.
   태그 workflow는 형식과 origin/main 포함 여부를 검사한다. 기존 `v1.0.0`은
   수정하지 않는다. 이후 `v1.0.2`, `v1.1.0`, `v2.0.0`도 같은 절차를 사용한다.

## 공개 전 수동 검증과 복구

새 Release 초안의 installer와 체크섬을 내려받아 해시를 대조한다.
기존 설치·데이터가 없는 Windows 환경에서 설치, 바로가기, 서버 시작·종료,
로그인·OTP·관리자 승인 흐름을 확인한 뒤 초안을 공개한다. 설치 성공은 운영
보안성 검증을 의미하지 않는다. 정책 한계는 [POLICY](POLICY.md)를 따른다.

현재 설치기는 기존 설치 폴더와 데이터를 교체한다. 데이터 보존형 업데이트가
아니므로 기존 데이터가 있는 환경에서 검증하지 않는다. v1.0.1 후보에는
v1.0.0 대비 새 DB 마이그레이션이 없다. 설치 실패 시 이전 설치 파일은 기존
Release에서 구할 수 있으나, 이전 파일의 재설치가 삭제된 DB를 복구하지는 않는다.
보존할 데이터가 있다면 별도의 백업·복구 검증이 선행돼야 한다.
