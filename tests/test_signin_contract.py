"""Application integration uses the installed library's supported API only."""

import ast
from pathlib import Path


def test_no_private_signin_window_imports_in_product():
    root = Path(__file__).resolve().parents[1] / "src" / "newsclip"
    failures = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("signin_window")
            ):
                failures.extend(
                    f"{path.name}:{node.lineno}:{alias.name}"
                    for alias in node.names
                    if alias.name.startswith("_")
                )
    assert not failures, failures
