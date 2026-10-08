"""Copy only optional AI settings from a source .env to an installed demo .env.

Run this locally after installation. Neither keys nor their values are printed.
"""
from __future__ import annotations

import argparse
from pathlib import Path


KEYS = ("OPENAI_API_KEY", "OPENAI_REVIEW_MODEL", "OPENAI_REVIEW_TIMEOUT_SEC")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig").splitlines()


def sync_settings(source: Path, target: Path) -> None:
    """Update only explicit AI settings; preserve every other installed setting."""
    source = source.resolve(strict=True)
    target = target.resolve(strict=True)
    if source == target or source.name != ".env" or target.name != ".env":
        raise ValueError("source and target must be distinct existing .env files")
    incoming = {}
    for line in _lines(source):
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in KEYS and value.strip():
            incoming[key] = value.strip()
    if not incoming.get("OPENAI_API_KEY"):
        raise ValueError("source AI key is not configured")
    retained = [line for line in _lines(target)
                if not ("=" in line and line.split("=", 1)[0].strip() in KEYS)]
    content = "\n".join([*retained, *(f"{key}={incoming[key]}" for key in KEYS if key in incoming)]) + "\n"
    target.write_text(content, encoding="utf-8")
    print("Installed AI settings updated. Restart ZeroTrust to apply them.")


def main() -> None:
    """Accept explicit source and installed .env paths without logging secrets."""
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    sync_settings(args.source, args.target)


if __name__ == "__main__":
    main()
