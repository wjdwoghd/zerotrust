"""외부 패키지 없이 실행하는 ZeroTrust 코드 작성 규칙 검사기."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
SNAKE_CASE = re.compile(r"^_*[a-z][a-z0-9_]*$")
PASCAL_CASE = re.compile(r"^_*[A-Z][A-Za-z0-9]*$")
MIGRATION_NAME = re.compile(r"^\d{3}_[a-z0-9_]+\.sql$")
PROTECTED_LOG_MUTATION = re.compile(
    r"\b(?:UPDATE|DELETE\s+FROM)\s+(?:audit_logs|sensitive_logs)\b",
    re.IGNORECASE,
)
EXCLUDED_DIRECTORIES = {
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "venv",
}


def _iter_python_files() -> list[Path]:
    """캐시와 생성 디렉터리를 제외한 Python 소스 목록을 반환한다."""
    return sorted(
        path
        for path in SOURCE_ROOT.rglob("*.py")
        if not EXCLUDED_DIRECTORIES & set(path.parts)
    )


def _requires_public_docstrings(path: Path) -> bool:
    """도메인 API로 취급해 공개 함수 설명을 강제할 모듈인지 반환한다."""
    relative = path.relative_to(SOURCE_ROOT)
    return (
        relative.parts[0] in {"core", "security"}
        or relative == Path("api/response_formatter.py")
    )


def _check_python(path: Path) -> list[str]:
    """한 Python 파일의 구문, 이름, 공개 함수 설명 규칙을 검사한다."""
    relative = path.relative_to(SOURCE_ROOT)
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(relative))
    except SyntaxError as error:
        return [f"{relative}:{error.lineno}: Python 구문 오류: {error.msg}"]

    errors: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_dunder = node.name.startswith("__") and node.name.endswith("__")
            if not is_dunder and not SNAKE_CASE.fullmatch(node.name):
                errors.append(
                    f"{relative}:{node.lineno}: 함수 이름이 snake_case가 아님: "
                    f"{node.name}"
                )
        elif isinstance(node, ast.ClassDef) and not PASCAL_CASE.fullmatch(node.name):
            errors.append(
                f"{relative}:{node.lineno}: 클래스 이름이 PascalCase가 아님: "
                f"{node.name}"
            )

    if _requires_public_docstrings(path):
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not node.name.startswith("_")
                and not ast.get_docstring(node)
            ):
                errors.append(
                    f"{relative}:{node.lineno}: 공개 함수 docstring 누락: "
                    f"{node.name}"
                )

    if "tests" not in relative.parts and PROTECTED_LOG_MUTATION.search(source):
        errors.append(
            f"{relative}: 보호 로그의 UPDATE/DELETE 문장이 애플리케이션 코드에 있음"
        )
    return errors


def check_repository() -> list[str]:
    """저장소의 자동 검증 가능한 코드 컨벤션 위반 목록을 반환한다."""
    errors: list[str] = []
    for path in _iter_python_files():
        errors.extend(_check_python(path))

    for migration in sorted((SOURCE_ROOT / "migrations").glob("*.sql")):
        if not MIGRATION_NAME.fullmatch(migration.name):
            errors.append(
                f"migrations/{migration.name}: NNN_snake_case.sql 형식이 아님"
            )
    return errors


def main() -> int:
    """검사 결과를 출력하고 위반이 있으면 실패 종료 코드를 반환한다."""
    errors = check_repository()
    if errors:
        print("[conventions] FAILED")
        for error in errors:
            print(f"  - {error}")
        return 1

    python_count = len(_iter_python_files())
    print(f"[conventions] OK ({python_count} Python files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
