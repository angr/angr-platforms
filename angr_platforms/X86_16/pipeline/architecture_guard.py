from __future__ import annotations

"""Architecture enforcement: block legacy paths in normal runs, gate final C emission.

AGENTS.md rules:
- No text-based recovery on generated C
- No flattening of segmented memory
- No guessing structs, arrays, or intent
- No silent fallback
- rewrite must not do semantic recovery

This module is the single chokepoint that enforces these rules.
"""

__all__ = [
    "FORBIDDEN_NORMAL_PATHS",
    "assert_no_legacy_path_8616",
    "assert_final_c_quality_8616",
]

from ..validation_semantics import assert_known_call_semantics_8616
import os


FORBIDDEN_NORMAL_PATHS: set[str] = {
    "collect_semantic_alias_facts_from_project_8616",
    "_inertia_module_alias_fact_cache",
    "apply_stack_variable_bindings_to_c_text",
    "substitute_ss_bp_dereferences_with_variables",
}


def _legacy_allowed(project) -> bool:
    return bool(getattr(project, "_inertia_debug_allow_legacy_paths", False))


def assert_no_legacy_path_8616(name: str, *, project=None) -> None:
    if _legacy_allowed(project):
        return
    if name in FORBIDDEN_NORMAL_PATHS:
        from .errors import PipelineHardError

        raise PipelineHardError(
            f"legacy semantic path used in normal run: {name}",
            layer="architecture",
        )


_FORBIDDEN_FINAL_C_TOKENS: tuple[str, ...] = (
    "ds << 4",
    "es << 4",
    "ss << 4",
    "*((ds << 4)",
    "*((es << 4)",
    "*((ss << 4)",
    "stack[",
)


def assert_final_c_quality_8616(c_text: str, *, function_addr: int | None = None) -> None:
    if os.environ.get("INERTIA_DEBUG_ALLOW_FORBIDDEN_FINAL_C"):
        return
    for token in _FORBIDDEN_FINAL_C_TOKENS:
        if token in c_text:
            from .errors import PipelineHardError

            raise PipelineHardError(
                f"forbidden final C token leaked: {token!r}",
                layer="final_emission",
                function_addr=function_addr,
            )
    assert_known_call_semantics_8616(c_text, function_addr=function_addr)
