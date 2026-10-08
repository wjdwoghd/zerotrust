# ZeroTrust Demo Windows Installer

This packaging path builds a single Windows self-extracting installer:

```bat
python packaging\windows\build_installer.py
```

The installer deploys to `%LOCALAPPDATA%\ZeroTrustDemo`, creates Desktop and
Start Menu shortcuts, and runs PostgreSQL from the install directory as a user
process on `127.0.0.1:55432`.
The web server binds to local IPv4. If port 8000 is unavailable, the launcher
selects another local port and uses it for the browser and token devices.

It does not install or use SQLite. The application still uses PostgreSQL only.
The payload includes only the application runtime scripts. Local `.env`, database
files, generated token launchers, tests, and developer scripts are excluded.

Created shortcuts:

- `ZeroTrust` starts PostgreSQL/server in the background and opens the web UI.
- `ZeroTrust 제어` opens a GUI reset/stop control app.
- `ZeroTrust 토큰 기기` opens the token-device launcher folder.

## 승인 AI 참고 검토 설정

최초 실행 후 `ZeroTrust 제어`에서 서버를 종료하고
`%LOCALAPPDATA%\ZeroTrustDemo\.env`에 다음 항목을 추가합니다.
기존 SECRET_KEY·DATABASE_URL 등은 유지합니다.

```dotenv
OPENAI_API_KEY=<별도로 발급받은 서버용 키>
OPENAI_REVIEW_MODEL=gpt-4o-mini
OPENAI_REVIEW_TIMEOUT_SEC=20
```

저장 후 `ZeroTrust` 바로가기로 다시 시작합니다. 기존
`OPENAI_SCENARIO_MODEL`·`OPENAI_SCENARIO_TIMEOUT_SEC`는 읽지 않습니다.
키가 없으면 AI 참고 의견 요청만 `key_not_configured`로 실패하며, 수동 승인과
기존 접근 결정은 사용할 수 있습니다. 키를 배포 파일·스크린샷·로그에 넣지 않습니다.
AI 호출에는 인터넷이 필요하며 현재 웹 UI도 CDN 연결을 사용합니다.
실제 자료의 외부 전송 범위는 미확정이므로 검증은 합성 시연 데이터로 수행합니다.

## 빌드와 설치본 검증

빌드는 `integrations`를 포함하고 번들 Python에서 패키징된 서버의 import를
검사합니다. 이 검사는 DB 연결·서버 기동·AI 호출·실제 설치 검증을 대신하지 않습니다.
격리 DB/API 회귀 후 설치 파일을 생성하고, 폐기 가능한 Windows 환경에서
[설치본 E2E 절차](../../PRESENTATION_DEMO.md#v2-설치본-e2e-검증)를 수행합니다.
설치기는 기존 설치 폴더와 DB를 교체하므로 보존할 데이터가 있는 환경에서 실행하지 않습니다.
