"""Reinstall preserves configured AI access without retaining prior application data."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


HELPER = Path(__file__).resolve().parents[2] / "packaging/windows/install_helpers.ps1"


@pytest.mark.skipif(os.name != "nt", reason="Windows installer helper")
def test_reinstall_keeps_only_optional_ai_settings(tmp_path):
    installed = tmp_path / "ZeroTrustDemo"
    staging = tmp_path / "ZeroTrustDemo.installing"
    installed.mkdir()
    staging.mkdir()
    (installed / ".env").write_text(
        "DATABASE_URL=old-database\nSECRET_KEY=old-secret\n"
        "OPENAI_API_KEY=synthetic-ai-key\nOPENAI_REVIEW_MODEL=test-model\n",
        encoding="utf-8",
    )
    (installed / "old-data.txt").write_text("old data", encoding="utf-8")
    (staging / "server.py").write_text("new runtime", encoding="utf-8")
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(HELPER), "-Action", "replace", "-InstallDir", str(installed),
         "-StagingDir", str(staging)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    settings = (installed / ".env").read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=synthetic-ai-key" in settings
    assert "OPENAI_REVIEW_MODEL=test-model" in settings
    assert "old-database" not in settings and "old-secret" not in settings
    assert "synthetic-ai-key" not in result.stdout + result.stderr
    assert not (installed / "old-data.txt").exists()
    assert (installed / "server.py").read_text(encoding="utf-8") == "new runtime"
