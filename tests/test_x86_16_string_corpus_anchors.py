from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
MONOPRIN_DEC = REPO_ROOT / "cod" / "f14" / "MONOPRIN.dec"
SCRIPT_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"


def test_monoprin_fimemset_emits_string_intrinsic_fallback_anchor():
    previous = MONOPRIN_DEC.read_text(encoding="utf-8", errors="replace") if MONOPRIN_DEC.exists() else None
    try:
        env = dict(os.environ)
        existing_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = "angr_platforms" if not existing_pythonpath else f"angr_platforms:{existing_pythonpath}"
        result = subprocess.run(
            [
                str(REPO_ROOT / ".venv" / "bin" / "python"),
                str(SCRIPT_PATH),
                "cod",
                "--cod-file",
                "f14/MONOPRIN.COD",
                "--timeout",
                "20",
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        assert result.returncode in {0, 1}
        rendered = MONOPRIN_DEC.read_text(encoding="utf-8", errors="replace")
        assert "/* == 4/6 MONOPRIN.COD :: __fimemset [NEAR] == */" in rendered
        section_start = rendered.index("/* == 4/6 MONOPRIN.COD :: __fimemset [NEAR] == */")
        section_end = rendered.find("/* == end 4/6 MONOPRIN.COD :: __fimemset [NEAR] == */", section_start)
        if section_end == -1:
            section_end = rendered.find("/* == 5/6", section_start)
        section = rendered[section_start:section_end if section_end != -1 else None]
        assert "/* == c (string intrinsic fallback) == */" not in section
        assert "/* -- c (string intrinsic fallback) -- */" not in section
        assert "__x86_16_stos(2);" in rendered
    finally:
        if previous is None:
            if MONOPRIN_DEC.exists():
                MONOPRIN_DEC.unlink()
        else:
            MONOPRIN_DEC.write_text(previous, encoding="utf-8")
