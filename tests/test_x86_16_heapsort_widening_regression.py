from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _run_decompile_addr(
    path: Path,
    addr: int,
    *,
    analysis_timeout: int = 8,
    subprocess_timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--addr",
            hex(addr),
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=subprocess_timeout,
        check=False,
    )


def test_sortdemo_heapsort_uses_widened_word_access_for_crow_anchor():
    result = _run_decompile_addr(SORTDEMO_EXE, 0x10970)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x10970 HeapSort" in result.stdout
    assert "whole-tail validation clean" in f"{result.stderr}{result.stdout}"
    assert "| ir_" not in result.stdout
    assert "unsigned short far *)MK_FP(ds, 2978)" in result.stdout
