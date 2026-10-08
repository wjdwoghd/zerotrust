"""Windows 설치 파일의 실행 경로와 공개 상태 확인 계약."""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "packaging" / "windows"


def _load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PACKAGING / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b'{"status":"ok","service":"zerotrust"}', True),
        (b'{"status":"ok"}', False),
        (b"<html>other service</html>", False),
    ],
)
def test_launcher_accepts_only_zerotrust_health_response(body, expected):
    ctl = _load_module("zt_demo_ctl_test", "zt_demo_ctl.py")

    class Response(io.BytesIO):
        status = 200

    with patch.object(ctl.urllib.request, "urlopen", return_value=Response(body)):
        assert ctl.health_ok() is expected


def test_launcher_uses_free_local_port_for_server_and_token_device(tmp_path, monkeypatch):
    ctl = _load_module("zt_demo_ctl_port_test", "zt_demo_ctl.py")
    monkeypatch.setattr(ctl, "SERVER_PID", tmp_path / "server.pid")
    monkeypatch.setattr(ctl, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(ctl, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(ctl, "SERVER_PORT", "8000")
    monkeypatch.setattr(ctl, "BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setattr(ctl, "_available_server_port", lambda port: port == 18080)

    ctl.configure_server_port()
    env = ctl.app_env()
    assert ctl.SERVER_PORT == "18080"
    assert ctl.BASE_URL == "http://127.0.0.1:18080"
    assert env["ZT_BIND_ADDRESS"] == "127.0.0.1"
    assert env["ZT_BASE_URL"] == ctl.BASE_URL
    assert env["SERVER_PORT"] == "18080"


def test_launcher_preserves_server_pid_when_stop_fails(tmp_path, monkeypatch):
    ctl = _load_module("zt_demo_ctl_stop_test", "zt_demo_ctl.py")
    pid_file = tmp_path / "server.pid"
    pid_file.write_text("1234", encoding="utf-8")
    monkeypatch.setattr(ctl, "SERVER_PID", pid_file)
    monkeypatch.setattr(ctl, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(ctl, "pid_alive", lambda _pid: True)
    monkeypatch.setattr(ctl.time, "sleep", lambda _seconds: None)
    with patch.object(ctl.subprocess, "run"), patch.object(
        ctl.os, "kill", side_effect=PermissionError("access denied")
    ):
        with pytest.raises(SystemExit, match="did not stop"):
            ctl.stop_server()
    assert pid_file.read_text(encoding="utf-8") == "1234"


def test_launcher_recognizes_its_running_process():
    ctl = _load_module("zt_demo_ctl_pid_test", "zt_demo_ctl.py")
    assert ctl.pid_alive(str(os.getpid()))
    assert not ctl.pid_alive("not-a-pid")


def test_installer_payload_contains_runtime_scripts_only(tmp_path, monkeypatch):
    builder = _load_module("build_installer_test", "build_installer.py")
    payload = tmp_path / "payload"
    monkeypatch.setattr(builder, "PAYLOAD", payload)
    builder.copy_app()

    for relative in (
        "server.py",
        "integrations/openai_review_transport.py",
        "integrations/openai_approval_review_client.py",
        "integrations/openai_other_approval_client.py",
        "apps/virtual_device.py",
        "scripts/run_migrations.py",
        "scripts/regenerate_launchers.py",
        "scripts/wipe_traces.py",
    ):
        assert (payload / relative).is_file()
    for relative in (
        ".env",
        "scripts/run.bat",
        "scripts/check_code_conventions.py",
        "scripts/build_exe_launchers.py",
        "scripts/bootstrap_admin.py",
        "scripts/trust_recalibration.py",
        "apps/launchers/token_admin_lee.pyw",
    ):
        assert not (payload / relative).exists()
    assert (payload / "apps" / "launchers").is_dir()


@pytest.mark.parametrize("include_integrations", [True, False])
def test_packaged_server_imports_detect_missing_integration(tmp_path, monkeypatch, include_integrations):
    builder = _load_module("build_installer_import_test", "build_installer.py")
    monkeypatch.setattr(builder, "PAYLOAD", tmp_path / "payload")
    if not include_integrations:
        monkeypatch.setattr(builder, "APP_PATHS", [p for p in builder.APP_PATHS if p != "integrations"])
    builder.copy_app()
    runtime = Path(sys.executable).parent
    if include_integrations:
        builder.verify_app_imports(runtime)
    else:
        with pytest.raises(SystemExit, match="packaged server import verification failed"):
            builder.verify_app_imports(runtime)
