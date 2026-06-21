# 토큰 기기 앱 런처

이 디렉터리의 파일은 `scripts/regenerate_launchers.py` 가 DB 를 읽어
자동 생성합니다. 수동 편집하지 마세요.

## 사용 방법 (Windows)

1. 서버가 떠 있는 상태에서
2. `token_<계정>.pyw` 파일을 **더블클릭** → GUI 창이 열립니다.
3. 웹 로그인 화면에서 'OTP 전송' 을 누르면, 이 창에 6자리 코드가 표시됩니다.
4. 표시된 코드를 웹 로그인 창 OTP 칸에 직접 입력하세요.

## `.pyw` 가 동작하지 않을 때

Python 설치 시 `.pyw` 확장자 연결이 안 되어 있으면 같은 이름의 `token_<계정>.bat` 을 대신 더블클릭하세요.

## api_key 갱신

`python init_data.py` 로 재시드하면 api_key 가 새로 발급되고, 이 디렉터리의 런처 파일들도 함께 재작성됩니다.

## macOS / Linux

`.pyw` 대신 `python3 apps/virtual_device.py --account <u> --device-id <tok> --api-key <k> --base-url http://127.0.0.1:8000` 로 실행해도 동일합니다. macOS 에서 더블클릭 앱 형태가 필요하면 Automator 또는 py2app 를 참고하세요.
