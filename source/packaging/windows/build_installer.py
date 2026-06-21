from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "packaging" / "windows"
BUILD = Path(os.environ.get("TEMP", str(PACKAGING))) / "ZeroTrustDemoInstallerBuild"
PAYLOAD = BUILD / "payload"
IEXPRESS_DIR = BUILD / "iexpress"
DIST = ROOT / "dist"
INSTALLER = DIST / "ZeroTrustDemoSetup.exe"
TEMP_INSTALLER = BUILD / "ZeroTrustDemoSetup.exe"


APP_PATHS = [
    "api",
    "apps",
    "core",
    "migrations",
    "scripts",
    "security",
    "static",
    "config.py",
    "database.py",
    "init_data.py",
    "requirements.txt",
    "server.py",
]

CONTROL_FILES = [
    "zt_demo_ctl.py",
    "zt_control_gui.pyw",
    "zerotrust.bat",
    "open_token_launchers.bat",
]

ICON_FILES = [
    "zerotrust_shield.ico",
    "token_device.ico",
    "control_panel.ico",
]

EXCLUDE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    "_build",
    "dist",
}

EXCLUDE_SUFFIXES = {
    ".pyc",
    ".pyo",
}

RUNTIME_DEPENDENCIES = {
    # import name -> top-level package / metadata / binary support folders
    "psycopg2": [
        "psycopg2",
        "psycopg2_binary-*.dist-info",
        "psycopg2_binary.libs",
    ],
    "tornado": [
        "tornado",
        "tornado-*.dist-info",
    ],
    "jwt": [
        "jwt",
        "pyjwt-*.dist-info",
    ],
    "bcrypt": [
        "bcrypt",
        "bcrypt-*.dist-info",
    ],
    "pyotp": [
        "pyotp",
        "pyotp-*.dist-info",
    ],
    "dotenv": [
        "dotenv",
        "python_dotenv-*.dist-info",
    ],
}


def log(message: str) -> None:
    print(f"[build-installer] {message}", flush=True)


def remove(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def ignore_names(_src: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        p = Path(name)
        if name in EXCLUDE_DIRS or p.suffix in EXCLUDE_SUFFIXES:
            ignored.add(name)
        if name.startswith("token_") and p.suffix in {".bat", ".pyw"}:
            ignored.add(name)
    return ignored


def copy_path(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, ignore=ignore_names)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix.lower() in {".bat", ".cmd"}:
            dst.write_text(
                src.read_text(encoding="utf-8"),
                encoding="utf-8",
                newline="\r\n",
            )
            return
        if src.suffix.lower() == ".ps1":
            dst.write_text(
                src.read_text(encoding="utf-8"),
                encoding="utf-8-sig",
                newline="\r\n",
            )
            return
        shutil.copy2(src, dst)


def resolve_postgres(path_arg: str | None) -> Path:
    if path_arg:
        root = Path(path_arg)
    else:
        pg_ctl = shutil.which("pg_ctl.exe")
        if not pg_ctl:
            raise SystemExit("pg_ctl.exe not found. Pass --postgres-source.")
        root = Path(pg_ctl).resolve().parents[1]
    required = root / "bin" / "postgres.exe"
    if not required.exists():
        raise SystemExit(f"invalid PostgreSQL root: {root}")
    return root


def resolve_python(path_arg: str | None) -> Path:
    if path_arg:
        root = Path(path_arg)
    else:
        root = Path(sys.executable).resolve().parent
    if not (root / "python.exe").exists():
        raise SystemExit(f"invalid Python root: {root}")
    return root


def copy_postgres(src: Path, dst: Path) -> None:
    log(f"copy PostgreSQL runtime: {src}")
    dst.mkdir(parents=True, exist_ok=True)
    for name in ("bin", "lib", "share"):
        copy_path(src / name, dst / name)
    for file in src.iterdir():
        if file.is_file():
            copy_path(file, dst / file.name)


def copy_python(src: Path, dst: Path) -> None:
    log(f"copy Python runtime: {src}")
    shutil.copytree(src, dst, ignore=ignore_names)


def ci_matches(root: Path, pattern: str) -> list[Path]:
    lowered = pattern.lower()
    return sorted(
        child for child in root.iterdir()
        if fnmatch.fnmatch(child.name.lower(), lowered)
    )


def dependency_site_root(import_name: str) -> Path:
    spec = importlib.util.find_spec(import_name)
    if spec is None or not spec.origin:
        raise SystemExit(
            f"missing Python dependency {import_name!r}; "
            "install requirements before building the installer"
        )
    package_path = Path(spec.origin).resolve()
    if package_path.name == "__init__.py":
        return package_path.parent.parent
    return package_path.parent


def replace_path(src: Path, dst: Path) -> None:
    if dst.exists():
        if dst.is_dir():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    copy_path(src, dst)


def copy_runtime_dependencies(python_runtime: Path) -> None:
    site_packages = python_runtime / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    log("copy Python runtime dependencies")
    copied: set[str] = set()
    for import_name, patterns in RUNTIME_DEPENDENCIES.items():
        source_site = dependency_site_root(import_name)
        for pattern in patterns:
            matches = ci_matches(source_site, pattern)
            if not matches:
                raise SystemExit(
                    f"dependency artifact not found for {import_name}: "
                    f"{source_site / pattern}"
                )
            for src in matches:
                dst = site_packages / src.name
                replace_path(src, dst)
                copied.add(src.name)
    log("bundled dependencies: " + ", ".join(sorted(copied)))


def verify_python_runtime(python_runtime: Path) -> None:
    log("verify bundled Python imports")
    code = (
        "import bcrypt, dotenv, jwt, psycopg2, pyotp, tornado\n"
        "print('runtime imports ok')\n"
    )
    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    result = subprocess.run(
        [str(python_runtime / "python.exe"), "-I", "-c", code],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        print(result.stdout)
        raise SystemExit("bundled Python dependency verification failed")


def ensure_icons() -> None:
    icons = PACKAGING / "icons"
    if all((icons / name).exists() for name in ICON_FILES):
        return
    log("generate shortcut icons")
    subprocess.run([sys.executable, str(PACKAGING / "make_icons.py")], check=True)


def copy_app() -> None:
    log("copy application files")
    ensure_icons()
    for rel in APP_PATHS:
        copy_path(ROOT / rel, PAYLOAD / rel)
    for name in CONTROL_FILES:
        copy_path(PACKAGING / name, PAYLOAD / name)
    copy_path(PACKAGING / "icons", PAYLOAD / "icons")


def make_zip() -> Path:
    zip_path = IEXPRESS_DIR / "payload.zip"
    log(f"create payload zip: {zip_path}")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for file in PAYLOAD.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(PAYLOAD))
    return zip_path


def write_sed() -> Path:
    sed = BUILD / "ZeroTrustDemoSetup.sed"
    target = str(TEMP_INSTALLER)
    source = str(IEXPRESS_DIR)
    sed.write_text(
        "\n".join([
            "[Version]",
            "Class=IEXPRESS",
            "SEDVersion=3",
            "",
            "[Options]",
            "PackagePurpose=InstallApp",
            "ShowInstallProgramWindow=0",
            "HideExtractAnimation=0",
            "UseLongFileName=1",
            "InsideCompressed=0",
            "CAB_FixedSize=0",
            "CAB_ResvCodeSigning=0",
            "RebootMode=N",
            "InstallPrompt=ZeroTrust Demo setup will start. Please run only one copy at a time.",
            "DisplayLicense=",
            "FinishMessage=ZeroTrust Demo installation complete.",
            f"TargetName={target}",
            "FriendlyName=ZeroTrust Demo Setup",
            "AppLaunched=install.cmd",
            "PostInstallCmd=<None>",
            "AdminQuietInstCmd=install.cmd /quiet",
            "UserQuietInstCmd=install.cmd /quiet",
            "SourceFiles=SourceFiles",
            "",
            "[SourceFiles]",
            f"SourceFiles0={source}",
            "",
            "[SourceFiles0]",
            "%FILE0%=",
            "%FILE1%=",
            "%FILE2%=",
            "%FILE3%=",
            "",
            "[Strings]",
            "FILE0=install.cmd",
            "FILE1=payload.zip",
            "FILE2=install_progress.ps1",
            "FILE3=install_helpers.ps1",
            "",
        ]),
        encoding="utf-8",
    )
    return sed


def build_installer() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    copy_path(PACKAGING / "install.cmd", IEXPRESS_DIR / "install.cmd")
    copy_path(PACKAGING / "install_progress.ps1", IEXPRESS_DIR / "install_progress.ps1")
    copy_path(PACKAGING / "install_helpers.ps1", IEXPRESS_DIR / "install_helpers.ps1")
    sed = write_sed()
    iexpress = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "iexpress.exe"
    if not iexpress.exists():
        raise SystemExit(f"iexpress.exe not found: {iexpress}")
    log("run IExpress")
    result = subprocess.run([str(iexpress), "/N", str(sed)], cwd=str(BUILD))
    if result.returncode != 0:
        raise SystemExit(f"IExpress failed: {result.returncode}")
    if not TEMP_INSTALLER.exists():
        raise SystemExit(f"installer was not created: {TEMP_INSTALLER}")
    shutil.copy2(TEMP_INSTALLER, INSTALLER)
    log(f"created {INSTALLER}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--postgres-source", help="PostgreSQL installation root, e.g. C:\\Program Files\\PostgreSQL\\18")
    parser.add_argument("--python-source", help="Python runtime root containing python.exe")
    args = parser.parse_args(argv)

    postgres = resolve_postgres(args.postgres_source)
    python = resolve_python(args.python_source)

    remove(BUILD)
    PAYLOAD.mkdir(parents=True)
    IEXPRESS_DIR.mkdir(parents=True)

    copy_app()
    python_runtime = PAYLOAD / "runtime" / "python"
    copy_python(python, python_runtime)
    copy_runtime_dependencies(python_runtime)
    verify_python_runtime(python_runtime)
    copy_postgres(postgres, PAYLOAD / "runtime" / "postgres")
    make_zip()
    build_installer()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
