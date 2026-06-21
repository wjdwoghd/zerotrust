"""
PG 기반 테스트 인프라 (운영 모드 단일)

전제:
  - postgres 슈퍼유저로 사전 1회 실행:
        CREATE DATABASE zerotrust_test OWNER ztuser;
  - 또는 환경변수 POSTGRES_TEST_URL 로 별도 테스트 DB 지정.

각 테스트는:
  1) 세션 시작 시: zerotrust_test 에 마이그레이션 적용 (이미 됐으면 skip)
  2) 테스트마다: wipe_traces.py + init_data.seed() 로 깨끗한 시드 상태로 reset
  3) 끝나면 라이브 서버 stop (사용한 경우)

운영 DB(zerotrust)는 절대 건드리지 않는다 — DATABASE_URL 을 모듈 로드 직후
강제로 zerotrust_test 로 덮어쓴다.
"""
from __future__ import annotations

import json as _json
import os
import socket
import sys
import threading
import time as _time
import urllib.error as _urlerr
import urllib.request as _urlreq
from pathlib import Path
from urllib.parse import quote

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ─── 환경 강제 격리 (프로젝트 모듈 import 전에 실행돼야 함) ─────
# .env 의 운영 DATABASE_URL 이 config 로 흘러 들어가지 않도록 차단한다.
TEST_DATABASE_URL = os.environ.get(
    "POSTGRES_TEST_URL",
    "postgresql://ztuser:2639@localhost:5432/zerotrust_test",
)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("JWT_ALGORITHM", "HS256")

# config.py 의 dotenv 자동 로드 차단 — 위 강제 값이 .env 로 덮이지 않게
try:
    import dotenv as _dotenv  # type: ignore
    _dotenv.load_dotenv = lambda *a, **k: False  # type: ignore[assignment]
except ImportError:
    pass


# ─── 세션 1회: DB 연결 확인 + 마이그레이션 ──────────────────────
# DB 가용 여부를 세션에 한 번 확인. 가용하면 마이그레이션 보장. 미가용이면
# DB 의존 테스트는 skip 처리 (순수 로직 테스트는 영향 안 받게).
_DB_AVAILABLE = False
_DB_ERROR_MESSAGE = ""


def _check_db_available():
    global _DB_AVAILABLE, _DB_ERROR_MESSAGE
    try:
        from database import get_db
        c = get_db()
        c.execute("SELECT 1").fetchone()
        c.close()
        _DB_AVAILABLE = True
        return True
    except Exception as e:
        _DB_ERROR_MESSAGE = (
            f"테스트 DB 연결 실패 ({type(e).__name__})\n"
            f"  DATABASE_URL={TEST_DATABASE_URL}\n"
            f"  postgres 로 다음을 한 번 실행하세요:\n"
            f"  CREATE DATABASE zerotrust_test OWNER ztuser;"
        )
        _DB_AVAILABLE = False
        return False


@pytest.fixture(scope="session", autouse=True)
def _session_setup():
    """DB 가용하면 마이그레이션 1회 적용. 미가용이면 skip (DB 의존 테스트만 영향)."""
    if _check_db_available():
        from scripts.run_migrations import main as run_migrations
        # 빈 argv 명시 — pytest 의 sys.argv 가 흘러들어가지 않도록
        rc = run_migrations(argv=[])
        if rc != 0:
            pytest.fail(f"migration failed (rc={rc})")
    yield


# ─── DB 사용 테스트 전용 reset (autouse 아님) ──────────────────
@pytest.fixture
def _reset_db_state():
    """db / live_server 가 의존하는 reset 픽스처. 순수 로직 테스트엔 영향 없음."""
    if not _DB_AVAILABLE:
        pytest.skip(_DB_ERROR_MESSAGE)
    from scripts.wipe_traces import main as wipe
    from init_data import seed
    rc = wipe()
    if rc != 0:
        pytest.fail(f"wipe failed (rc={rc})")
    seed()
    yield


@pytest.fixture
def db(_reset_db_state):
    """깨끗한 시드 상태의 PG 연결."""
    from database import get_db
    conn = get_db()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ─── 라이브 Tornado 서버 (랜덤 포트) ────────────────────────────
class _LiveServer:
    def __init__(self, app):
        self.app = app
        self.port = None
        self._thread = None
        self._loop = None
        self._http_server = None

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        ready = threading.Event()

        def _runner():
            import asyncio
            from tornado.httpserver import HTTPServer
            from tornado.ioloop import IOLoop
            asyncio.set_event_loop(asyncio.new_event_loop())
            self._loop = IOLoop.current()
            self._http_server = HTTPServer(self.app)
            self._http_server.listen(self.port, address="127.0.0.1")
            ready.set()
            self._loop.start()

        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()
        ready.wait(timeout=5)
        # 포트가 실제 열렸는지 확인
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                _time.sleep(0.05)
        raise RuntimeError(f"server did not start on port {self.port}")

    def stop(self):
        if self._loop and self._http_server:
            def _shutdown():
                self._http_server.stop()
                self._loop.stop()
            try:
                self._loop.add_callback(_shutdown)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def live_server(_reset_db_state):
    """라이브 Tornado 서버 (랜덤 포트). 테스트별 fresh DB 위에 동작."""
    from server import make_app
    app = make_app()
    server = _LiveServer(app)
    server.start()
    try:
        yield server
    finally:
        server.stop()


# ─── HTTP 헬퍼 ───────────────────────────────────────────────────
def _http_call(base_url, method, path, body=None, token=None, device=None,
               location=None, ip=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if device:
        headers["X-Device-Id"] = device
    if location:
        headers["X-Location"] = quote(location)
    if ip:
        headers["X-IP-Address"] = ip
    data = (
        _json.dumps(body, ensure_ascii=False).encode("utf-8")
        if body is not None else None
    )
    req = _urlreq.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with _urlreq.urlopen(req) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            try:
                return resp.status, _json.loads(raw)
            except _json.JSONDecodeError:
                return resp.status, {"_raw": raw}
    except _urlerr.HTTPError as e:
        try:
            return e.code, _json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}


@pytest.fixture
def http(live_server):
    """live_server 에 대한 HTTP 호출 헬퍼."""
    base = live_server.base_url

    def _call(method, path, **kw):
        return _http_call(base, method, path, **kw)
    _call.base = base
    return _call


# 시드 사용자 → 기본 device_id 매핑 (init_data.py 와 1:1 대응)
_DEFAULT_WORK_DEVICE = {
    "detective_kim":     "registered-001",
    "investigator_park": "registered-003",
    "admin_lee":         "registered-004",
    "officer_choi":      "registered-006",
    "patrol_jung":       "registered-007",
    "deputy_han":        "registered-008",
    "deputy_oh":         "registered-009",
}
_DEFAULT_TOKEN_DEVICE = {
    "detective_kim":     "token-001",
    "investigator_park": "token-002",
    "admin_lee":         "token-003",
    "officer_choi":      "token-004",
    # patrol_jung 은 토큰 기기 없음 (의심 계정 시뮬레이션용)
    "deputy_han":        "token-006",
    "deputy_oh":         "token-007",
}


@pytest.fixture
def login_as(http):
    """
    시드 사용자로 로그인 + MFA 완료까지 — 사용 가능한 JWT 토큰 반환.

    Usage:
        tok = login_as("admin_lee")
        tok = login_as("detective_kim", location="강남서")

    반환: (token | None, status_code, response_body)
    """
    def _login(username, password="password123", device_id=None,
               location="본청", ip=None, otp_code=None):
        if device_id is None:
            device_id = _DEFAULT_WORK_DEVICE.get(username, "registered-001")

        # 1) 로그인
        code, data = http(
            "POST", "/api/auth/login",
            body={
                "username": username, "password": password,
                "device_id": device_id, "location": location,
            },
            device=device_id, location=location, ip=ip,
        )
        if code != 200:
            return None, code, data
        tok = data.get("token")

        # 2) MFA 필요하면 실제 TOTP 발급해 검증
        if data.get("mfa_required"):
            otp = otp_code
            if otp is None:
                # 토큰 기기의 mfa_secret 으로 실제 TOTP 생성
                token_dev_id = _DEFAULT_TOKEN_DEVICE.get(username)
                if not token_dev_id:
                    return None, 0, {"error": f"no token device for {username}"}
                from database import get_db
                from security.mfa_service import generate_totp
                _db = get_db()
                try:
                    row = _db.execute(
                        "SELECT mfa_secret FROM user_devices "
                        "WHERE device_id=? AND user_id=(SELECT id FROM users WHERE username=?)",
                        (token_dev_id, username),
                    ).fetchone()
                finally:
                    _db.close()
                if not row or not row.get("mfa_secret"):
                    return None, 0, {"error": f"mfa_secret missing for {username}"}
                otp = generate_totp(row["mfa_secret"])

            code, data = http(
                "POST", "/api/auth/mfa/verify",
                body={
                    "otp_code": otp,
                    "device_id": device_id, "location": location,
                },
                token=tok, device=device_id, location=location, ip=ip,
            )
            if code != 200:
                return None, code, data
            tok = data.get("token") or tok

        return tok, 200, data

    return _login


# DB 의존 테스트의 자동 skip 은 _reset_db_state 픽스처가 처리한다.
# (DB 미가용 시 pytest.skip 호출 → 그 픽스처를 의존하는 테스트만 skip)
# 순수 로직 테스트 (db / live_server / http 미사용) 는 DB 가용성과 무관하게 실행.
