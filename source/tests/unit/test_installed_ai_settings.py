"""Only the optional AI settings may cross from source into the installed demo."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "packaging/windows/sync_ai_settings.py"
spec = importlib.util.spec_from_file_location("sync_ai_settings", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_sync_preserves_installed_secrets_and_replaces_only_ai_settings(tmp_path, capsys):
    source = tmp_path / "source/.env"
    installed = tmp_path / "installed/.env"
    source.parent.mkdir()
    installed.parent.mkdir()
    source.write_text("DATABASE_URL=source-db\nSECRET_KEY=source-secret\n"
                      "OPENAI_API_KEY=fake-source-ai-key\nOPENAI_REVIEW_MODEL=model-example\n",
                      encoding="utf-8")
    installed.write_text("DATABASE_URL=installed-db\nSECRET_KEY=installed-secret\n"
                         "OPENAI_API_KEY=old-ai-key\n", encoding="utf-8")
    module.sync_settings(source, installed)
    result = installed.read_text(encoding="utf-8")
    assert "DATABASE_URL=installed-db" in result
    assert "SECRET_KEY=installed-secret" in result
    assert "source-secret" not in result and "source-db" not in result
    assert "OPENAI_API_KEY=fake-source-ai-key" in result
    assert "OPENAI_REVIEW_MODEL=model-example" in result
    assert "fake-source-ai-key" not in capsys.readouterr().out


def test_sync_rejects_empty_key_without_touching_install(tmp_path):
    source = tmp_path / "source/.env"
    installed = tmp_path / "installed/.env"
    source.parent.mkdir()
    installed.parent.mkdir()
    source.write_text("OPENAI_API_KEY=\n", encoding="utf-8")
    installed.write_text("SECRET_KEY=keep\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not configured"):
        module.sync_settings(source, installed)
    assert installed.read_text(encoding="utf-8") == "SECRET_KEY=keep\n"
