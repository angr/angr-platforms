from __future__ import annotations

from .recompilable_cases import (
    describe_x86_16_recompilable_subset,
    get_x86_16_recompilable_subset_cases,
)
from .recompilable_checks import (
    check_recompilable_c_text_shape,
    compile_recompilable_c_text,
    syntax_check_recompilable_c_text,
)
from .recompilable_cli_bridge import decompile_recompilable_subset_case

__all__ = [
    "describe_x86_16_recompilable_subset",
    "run_x86_16_recompilable_subset_syntax_checks",
]


def run_x86_16_recompilable_subset_syntax_checks() -> tuple[dict[str, object], ...]:
    results: list[dict[str, object]] = []
    for case in get_x86_16_recompilable_subset_cases():
        c_text, decompile_meta = decompile_recompilable_subset_case(case)
        syntax_proc = syntax_check_recompilable_c_text(c_text)
        compile_proc = compile_recompilable_c_text(c_text)
        shape = check_recompilable_c_text_shape(c_text, case)
        results.append(
            {
                "name": case.name,
                "expected_kind": case.expected_kind,
                **decompile_meta,
                "returncode": syntax_proc.returncode,
                "stderr": syntax_proc.stderr,
                "syntax_ok": syntax_proc.returncode == 0,
                "compile_returncode": compile_proc.returncode,
                "compile_stderr": compile_proc.stderr,
                "compile_ok": compile_proc.returncode == 0,
                **shape,
            }
        )
    return tuple(results)
