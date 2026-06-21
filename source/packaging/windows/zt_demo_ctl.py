from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
PYTHON = RUNTIME / "python" / "python.exe"
PYTHONW = RUNTIME / "python" / "pythonw.exe"
PG_ROOT = RUNTIME / "postgres"
PG_BIN = PG_ROOT / "bin"
PG_DATA = ROOT / "data" / "postgres"
LOG_DIR = ROOT / "logs"
ENV_FILE = ROOT / ".env"
SERVER_PID = LOG_DIR / "server.pid"

PG_PORT = os.environ.get("ZT_PG_PORT", "55432")
SERVER_PORT = os.environ.get("SERVER_PORT", "8000")
DATABASE_NAME = "zerotrust"
DATABASE_URL = f"postgresql://postgres@127.0.0.1:{PG_PORT}/{DATABASE_NAME}"
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"


def _append_launcher_log(text: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / "launcher.log").open("a", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n")
    except Exception:
        pass


def _log(message: str) -> None:
    line = f"[ZeroTrust] {message}"
    print(line, flush=True)
    _append_launcher_log(line)


def _show_error(message: str) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(
            None,
            message,
            "ZeroTrust 실행 실패",
            0x00000010,
        )
    except Exception:
        pass


def _exe(name: str) -> str:
    path = PG_BIN / name
    if not path.exists():
        raise SystemExit(f"missing PostgreSQL binary: {path}")
    return str(path)


def no_window_flags() -> int:
    if os.name != "nt":
        return 0
    flags = 0
    flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return flags


def detached_flags() -> int:
    flags = no_window_flags()
    if os.name == "nt":
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0)
    return flags


def subprocess_kwargs(**kwargs) -> dict:
    if os.name == "nt":
        kwargs.setdefault("creationflags", no_window_flags())
    return kwargs


def _read_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def ensure_env_file() -> dict[str, str]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    values = _read_env_file()
    changed = False

    if not values.get("SECRET_KEY") or len(values.get("SECRET_KEY", "")) < 32:
        values["SECRET_KEY"] = secrets.token_hex(32)
        changed = True
    if values.get("DATABASE_URL") != DATABASE_URL:
        values["DATABASE_URL"] = DATABASE_URL
        changed = True
    if values.get("SERVER_PORT") != SERVER_PORT:
        values["SERVER_PORT"] = SERVER_PORT
        changed = True
    values.setdefault("JWT_ALGORITHM", "HS256")
    values.setdefault("JWT_EXPIRY_HOURS", "1")

    if changed or not ENV_FILE.exists():
        body = "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"
        ENV_FILE.write_text(body, encoding="utf-8")
    return values


def app_env() -> dict[str, str]:
    values = ensure_env_file()
    env = os.environ.copy()
    env.update(values)
    env["DATABASE_URL"] = DATABASE_URL
    env["SERVER_PORT"] = SERVER_PORT
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["ZT_PYTHONW"] = str(PYTHONW)
    env["PATH"] = str(PG_BIN) + os.pathsep + str(RUNTIME / "python") + os.pathsep + env.get("PATH", "")
    return env


def _decode_output(data: bytes | None) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "mbcs", "cp949"):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=app_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            **subprocess_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        output = _decode_output(exc.stdout)
        if output:
            _append_launcher_log(output)
        raise SystemExit(
            f"command timed out after {int(timeout or 0)} seconds: {' '.join(cmd)}"
        )
    result.stdout = _decode_output(result.stdout)  # type: ignore[assignment]
    if result.stdout:
        _append_launcher_log(result.stdout)
    if check and result.returncode != 0:
        if capture and result.stdout:
            print(result.stdout)
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(cmd)}")
    return result


def verify_runtime_dependencies() -> None:
    code = (
        "import bcrypt, dotenv, jwt, psycopg2, pyotp, tornado\n"
        "print('runtime imports ok')\n"
    )
    result = subprocess.run(
        [str(PYTHON), "-I", "-c", code],
        cwd=str(ROOT),
        env=app_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **subprocess_kwargs(),
    )
    output = _decode_output(result.stdout)
    if output:
        _append_launcher_log(output)
    if result.returncode != 0:
        raise SystemExit(
            "bundled Python runtime dependencies are missing. "
            "Reinstall with the latest ZeroTrustDemoSetup.exe."
        )


def pg_isready_result() -> subprocess.CompletedProcess:
    try:
        return run(
            [_exe("pg_isready.exe"), "-h", "127.0.0.1", "-p", PG_PORT, "-U", "postgres"],
            check=False,
            capture=True,
            timeout=5,
        )
    except SystemExit as exc:
        result = subprocess.CompletedProcess(
            [_exe("pg_isready.exe")],
            1,
        )
        result.stdout = str(exc)  # type: ignore[assignment]
        return result


def pg_ready() -> bool:
    return pg_isready_result().returncode == 0


def postgres_log_tail(max_chars: int = 1400) -> str:
    log_path = LOG_DIR / "postgres.log"
    if not log_path.exists():
        return ""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-max_chars:].strip()
    return result.returncode == 0


def wait_for_postgres_ready(timeout_seconds: float = 120.0) -> None:
    deadline = time.time() + timeout_seconds
    last_status = ""
    while time.time() < deadline:
        result = pg_isready_result()
        last_status = (result.stdout or "").strip()
        if result.returncode == 0:
            return
        time.sleep(0.5)

    detail = (
        f"PostgreSQL did not become ready on 127.0.0.1:{PG_PORT} "
        f"within {int(timeout_seconds)} seconds."
    )
    if last_status:
        detail += f"\nlast pg_isready: {last_status}"
    tail = postgres_log_tail()
    if tail:
        detail += f"\npostgres.log tail:\n{tail}"
    raise SystemExit(detail)


def init_postgres_if_needed() -> None:
    if (PG_DATA / "PG_VERSION").exists():
        return
    _log("PostgreSQL data directory initializing...")
    PG_DATA.parent.mkdir(parents=True, exist_ok=True)
    run([
        _exe("initdb.exe"),
        "-D", str(PG_DATA),
        "-U", "postgres",
        "-A", "trust",
        "-E", "UTF8",
        "--locale=C",
    ])


def start_postgres() -> None:
    init_postgres_if_needed()
    if pg_ready():
        _log(f"PostgreSQL already running on 127.0.0.1:{PG_PORT}")
        return
    _log(f"PostgreSQL starting on 127.0.0.1:{PG_PORT}...")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with (LOG_DIR / "pg_ctl.log").open("ab") as out:
            proc = subprocess.Popen(
                [
                    _exe("pg_ctl.exe"),
                    "-D", str(PG_DATA),
                    "-l", str(LOG_DIR / "postgres.log"),
                    "-o", f"-p {PG_PORT} -h 127.0.0.1",
                    "start",
                ],
                cwd=str(ROOT),
                env=app_env(),
                stdout=out,
                stderr=subprocess.STDOUT,
                **subprocess_kwargs(),
            )
        _log(f"pg_ctl start issued pid={proc.pid}")
    except SystemExit as exc:
        detail = str(exc) if str(exc) else "PostgreSQL start command failed."
        tail = postgres_log_tail()
        if tail:
            detail += f"\npostgres.log tail:\n{tail}"
        raise SystemExit(detail)
    except OSError as exc:
        raise SystemExit(f"PostgreSQL start command failed: {exc}")
    wait_for_postgres_ready()


def stop_postgres() -> None:
    if not (PG_DATA / "PG_VERSION").exists():
        return
    if not pg_ready():
        return
    _log("PostgreSQL stopping...")
    run([
        _exe("pg_ctl.exe"),
        "-D", str(PG_DATA),
        "stop",
        "-m", "fast",
        "-w",
        "-t", "30",
    ], check=False)


def ensure_database() -> None:
    query = f"SELECT 1 FROM pg_database WHERE datname='{DATABASE_NAME}'"
    result = run([
        _exe("psql.exe"),
        "-h", "127.0.0.1",
        "-p", PG_PORT,
        "-U", "postgres",
        "-d", "postgres",
        "-tAc", query,
    ], check=False, capture=True)
    if "1" in (result.stdout or ""):
        return
    _log(f"creating database {DATABASE_NAME}...")
    run([
        _exe("createdb.exe"),
        "-h", "127.0.0.1",
        "-p", PG_PORT,
        "-U", "postgres",
        DATABASE_NAME,
    ])


def run_migrations() -> None:
    _log("applying migrations...")
    run([str(PYTHON), "scripts/run_migrations.py"])


def user_count() -> int:
    code = (
        "from database import get_db\n"
        "db=get_db()\n"
        "try:\n"
        " r=db.execute(\"SELECT to_regclass('public.users') AS t\").fetchone()\n"
        " print(0 if not r or not r.get('t') else db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c'])\n"
        "finally:\n"
        " db.close()\n"
    )
    result = run([str(PYTHON), "-c", code], capture=True)
    try:
        return int((result.stdout or "0").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def seed_if_needed() -> None:
    if user_count() > 0:
        run([str(PYTHON), "scripts/regenerate_launchers.py"], check=False)
        return
    _log("seeding initial presentation data...")
    run([str(PYTHON), "init_data.py"])


def reset_data() -> None:
    start_postgres()
    ensure_database()
    run_migrations()
    _log("wiping presentation traces...")
    run([str(PYTHON), "scripts/wipe_traces.py"])
    _log("re-seeding presentation data...")
    run([str(PYTHON), "init_data.py"])


def health_ok() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/healthz", timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def pid_alive(pid_text: str) -> bool:
    if not pid_text.isdigit():
        return False
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid_text}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        **subprocess_kwargs(),
    )
    return pid_text in (result.stdout or "")


def deactivate_all_sessions(reason: str) -> None:
    if not pg_ready():
        return
    code = (
        "import json\n"
        "from database import get_db\n"
        "db=get_db()\n"
        "try:\n"
        " row=db.execute('SELECT COUNT(*) AS c FROM sessions WHERE is_active').fetchone()\n"
        " active=int(row['c']) if row else 0\n"
        " if active:\n"
        "  db.execute('UPDATE sessions SET is_active=FALSE WHERE is_active')\n"
        " db.execute('INSERT INTO operation_logs (event_type, severity, details) VALUES (?,?,?)', "
        "('SYSTEM_SESSIONS_TERMINATED', 2, json.dumps({'reason': %r, 'active_sessions': active}, ensure_ascii=False)))\n"
        " db.commit()\n"
        "finally:\n"
        " db.close()\n"
    ) % reason
    run([str(PYTHON), "-c", code], check=False)


def close_browser_windows() -> None:
    profiles = ROOT / "browser_profiles"
    if not profiles.exists():
        return

    needle = str(profiles)
    ps_needle = "'" + needle.replace("'", "''") + "'"
    script = "\n".join([
        f"$needle = {ps_needle}",
        "$names = @('msedge.exe', 'chrome.exe')",
        "Get-CimInstance Win32_Process | Where-Object {",
        "    $_.CommandLine -and $names -contains $_.Name -and $_.CommandLine.Contains($needle)",
        "} | ForEach-Object {",
        "    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue",
        "}",
    ])
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **subprocess_kwargs(),
    )


def stop_server() -> None:
    if not SERVER_PID.exists():
        return
    pid_text = SERVER_PID.read_text(encoding="utf-8").strip()
    if not pid_text:
        SERVER_PID.unlink(missing_ok=True)
        return
    _log(f"stopping server pid={pid_text}...")
    subprocess.run(
        ["taskkill", "/PID", pid_text, "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **subprocess_kwargs(),
    )
    SERVER_PID.unlink(missing_ok=True)


def start_server() -> None:
    if SERVER_PID.exists():
        pid_text = SERVER_PID.read_text(encoding="utf-8").strip()
        if pid_alive(pid_text) and health_ok():
            _log(f"server already responding at {BASE_URL}")
            return
        stop_server()
    elif health_ok():
        raise SystemExit(
            f"port {SERVER_PORT} already has a responding service. "
            f"Stop that process first, then run ZeroTrust again."
        )

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stdout = open(LOG_DIR / "server.out.log", "ab")
    stderr = open(LOG_DIR / "server.err.log", "ab")
    proc = subprocess.Popen(
        [str(PYTHON), "server.py"],
        cwd=str(ROOT),
        env=app_env(),
        stdout=stdout,
        stderr=stderr,
        creationflags=detached_flags(),
    )
    SERVER_PID.write_text(str(proc.pid), encoding="utf-8")
    _log(f"server starting pid={proc.pid}...")
    for _ in range(60):
        if health_ok():
            _log(f"server ready at {BASE_URL}")
            return
        time.sleep(0.5)
    raise SystemExit(f"server did not become ready. See {LOG_DIR / 'server.err.log'}")


def ensure_system_ready() -> None:
    verify_runtime_dependencies()
    start_postgres()
    ensure_database()
    run_migrations()
    seed_if_needed()
    start_server()


def _chromium_browser() -> Path | None:
    candidates: list[Path] = []
    for root in (
        os.environ.get("PROGRAMFILES(X86)"),
        os.environ.get("PROGRAMFILES"),
        os.environ.get("LOCALAPPDATA"),
    ):
        if not root:
            continue
        base = Path(root)
        candidates.extend([
            base / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            base / "Google" / "Chrome" / "Application" / "chrome.exe",
        ])
    for command in ("msedge.exe", "chrome.exe", "msedge", "chrome"):
        found = shutil.which(command)
        if found:
            candidates.append(Path(found))
    for path in candidates:
        if path.exists():
            return path
    return None


def _launch_browser(url: str, profile_name: str) -> None:
    browser = _chromium_browser()
    if not browser:
        _log("Edge/Chrome not found; opening default browser without isolated profile.")
        webbrowser.open(url)
        return

    profiles = ROOT / "browser_profiles"
    profile = profiles / profile_name
    profile.mkdir(parents=True, exist_ok=True)
    args = [
        str(browser),
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--disable-default-apps",
        "--new-window",
        "--window-size=1050,860",
        "--window-position=40,40",
        url,
    ]
    try:
        subprocess.Popen(
            args,
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=no_window_flags(),
        )
        _log("browser window opened")
    except OSError as exc:
        _log(f"browser launch failed, falling back to default browser: {exc}")
        webbrowser.open_new(url)


def start_all() -> None:
    ensure_system_ready()
    _launch_browser(BASE_URL, "main")


def reset_and_start() -> None:
    deactivate_all_sessions("control_reset")
    close_browser_windows()
    time.sleep(0.5)
    stop_server()
    reset_data()
    start_server()
    _launch_browser(BASE_URL, "main")
    _log("reset complete; server restarted")


def stop_all() -> None:
    deactivate_all_sessions("control_stop")
    close_browser_windows()
    time.sleep(0.5)
    stop_server()
    stop_postgres()
    _log("stopped")


def create_shortcuts() -> None:
    desktop_fallback = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"
    start_menu = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "ZeroTrust Demo"
    start_menu.mkdir(parents=True, exist_ok=True)
    icons = ROOT / "icons"
    obsolete = [
        "ZeroTrust 시작.lnk",
        "ZeroTrust 초기화.lnk",
        "ZeroTrust 중지.lnk",
        "ZeroTrust 실행.lnk",
        "ZeroTrust 시연 계정.lnk",
    ]
    pythonw = PYTHONW if PYTHONW.exists() else PYTHON
    shortcuts = [
        (
            "ZeroTrust.lnk",
            pythonw,
            f'"{ROOT / "zt_demo_ctl.py"}" start',
            "Start ZeroTrust demo and open the web system",
            icons / "zerotrust_shield.ico",
        ),
        (
            "ZeroTrust 제어.lnk",
            pythonw,
            f'"{ROOT / "zt_control_gui.pyw"}"',
            "Reset or stop the ZeroTrust demo system",
            icons / "control_panel.ico",
        ),
        (
            "ZeroTrust 토큰 기기.lnk",
            pythonw,
            f'"{ROOT / "zt_demo_ctl.py"}" token-launchers',
            "Open token device launchers",
            icons / "token_device.ico",
        ),
    ]
    def ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    ps_lines = [
        "$ws = New-Object -ComObject WScript.Shell",
        "$desktop = $ws.SpecialFolders.Item('Desktop')",
        f"if ([string]::IsNullOrWhiteSpace($desktop)) {{ $desktop = {ps_quote(str(desktop_fallback))} }}",
        f"$menu = {ps_quote(str(start_menu))}",
        "New-Item -ItemType Directory -Force -Path $desktop | Out-Null",
        "New-Item -ItemType Directory -Force -Path $menu | Out-Null",
    ]
    for name in obsolete:
        for base_var in ("$desktop", "$menu"):
            ps_lines.extend([
                f"$old = Join-Path {base_var} {ps_quote(name)}",
                "if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }",
            ])
    for name, target, args, desc, icon in shortcuts:
        for base_var in ("$desktop", "$menu"):
            ps_lines.extend([
                f"$s = $ws.CreateShortcut((Join-Path {base_var} {ps_quote(name)}))",
                f"$s.TargetPath = {ps_quote(str(target))}",
                f"$s.Arguments = {ps_quote(args)}",
                f"$s.WorkingDirectory = {ps_quote(str(ROOT))}",
                f"$s.Description = {ps_quote(desc)}",
                f"$s.IconLocation = {ps_quote(str(icon))}",
                "$s.Save()",
            ])
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "\n".join(ps_lines)],
        check=True,
        **subprocess_kwargs(),
    )
    _log("shortcuts created on Desktop and Start Menu")


def open_token_launchers() -> None:
    launchers = ROOT / "apps" / "launchers"
    launchers.mkdir(parents=True, exist_ok=True)
    os.startfile(str(launchers))  # type: ignore[attr-defined]


def main(argv: list[str]) -> int:
    command = argv[1].lower() if len(argv) > 1 else "start"
    if not PYTHON.exists():
        raise SystemExit(f"bundled python not found: {PYTHON}")
    if command == "start":
        start_all()
    elif command == "reset":
        stop_server()
        reset_data()
        _log("reset complete")
    elif command == "reset-start":
        reset_and_start()
    elif command == "stop":
        stop_all()
    elif command == "shortcuts":
        create_shortcuts()
    elif command == "token-launchers":
        open_token_launchers()
    elif command == "status":
        _log(f"PostgreSQL ready: {pg_ready()}")
        _log(f"Server ready: {health_ok()}")
    else:
        raise SystemExit(f"unknown command: {command}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        if code:
            detail = str(exc) if str(exc) else f"exit code {code}"
            _log(f"ERROR: {detail}")
            _show_error(
                "ZeroTrust를 시작하지 못했습니다.\n\n"
                f"{detail}\n\n"
                f"상세 로그: {LOG_DIR / 'launcher.log'}"
            )
        raise
    except BaseException as exc:
        detail = traceback.format_exc()
        _append_launcher_log(detail)
        _show_error(
            "ZeroTrust를 시작하지 못했습니다.\n\n"
            f"{exc}\n\n"
            f"상세 로그: {LOG_DIR / 'launcher.log'}"
        )
        raise SystemExit(1)
