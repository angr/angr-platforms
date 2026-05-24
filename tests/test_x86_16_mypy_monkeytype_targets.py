from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
MYPY_TARGETS: tuple[str, ...] = (
    "inertia_decompiler/monkeytype_tools.py",
    "inertia_decompiler/cli_access_object_hints.py",
    "inertia_decompiler/cli_access_trait_rewrite.py",
    "inertia_decompiler/cli_cod_globals.py",
    "monkeytype_config.py",
    "scripts/run_monkeytype_tracing.py",
    "scripts/export_monkeytype_stubs.py",
    "scripts/apply_monkeytype_annotations.py",
)


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def test_monkeytype_small_modules_typecheck_cleanly():
    subprocess.run(
        [
            _python(),
            "-m",
            "mypy",
            "--config-file",
            "pyproject.toml",
            *MYPY_TARGETS,
        ],
        cwd=REPO_ROOT,
        check=True,
    )
