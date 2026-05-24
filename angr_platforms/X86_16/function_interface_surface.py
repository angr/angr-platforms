from __future__ import annotations

import re
from typing import Any

from .analysis_helpers import collect_neighbor_call_targets
from .function_state_summary import FunctionStateSummary, summarize_x86_16_function_state
from .low_memory_regions import format_x86_16_low_memory_access

__all__ = ["apply_x86_16_function_interface_surface"]

_PROTOTYPE_RE = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")


def _bp_disp(offset: int) -> str:
    if offset == 0:
        return "[bp]"
    sign = "+" if offset > 0 else "-"
    return f"[bp{sign}0x{abs(offset):x}]"


def _join(items: tuple[str, ...] | tuple[int, ...], *, ints: bool = False) -> str:
    if not items:
        return "-"
    if ints:
        return ", ".join(_bp_disp(int(item)) for item in items)
    return ", ".join(str(item) for item in items)


def _summary_from_source(source: Any) -> FunctionStateSummary:
    info = getattr(source, "info", None)
    if isinstance(info, dict) and info:
        return summarize_x86_16_function_state(info)
    return summarize_x86_16_function_state(source)


def _format_memory_summary(items: tuple[str, ...]) -> str:
    if not items:
        return "-"
    return ", ".join(format_x86_16_low_memory_access(str(item)) for item in items)


def _has_surface_data(summary: FunctionStateSummary) -> bool:
    return any(
        (
            summary.gp_register_inputs,
            summary.gp_register_outputs,
            summary.segment_register_inputs,
            summary.segment_register_outputs,
            summary.flag_inputs,
            summary.flag_outputs,
            summary.frame_stack_reads,
            summary.frame_stack_writes,
            summary.memory_reads,
            summary.memory_writes,
            summary.return_kind != "unknown",
        )
    )


def _function_header_lines(name: str, summary: FunctionStateSummary) -> list[str]:
    if not _has_surface_data(summary):
        return []
    inputs = tuple((*summary.gp_register_inputs, *summary.segment_register_inputs, *summary.flag_inputs))
    outputs = tuple((*summary.gp_register_outputs, *summary.segment_register_outputs, *summary.flag_outputs))
    lines = [
        f"// interface {name}",
        f"//   in:  {_join(inputs)}",
        f"//   out: {_join(outputs)}",
        f"//   ret: {summary.return_kind}",
    ]
    if summary.frame_stack_reads:
        lines.append(f"//   stack-in:  {_join(summary.frame_stack_reads, ints=True)}")
    if summary.frame_stack_writes:
        lines.append(f"//   stack-out: {_join(summary.frame_stack_writes, ints=True)}")
    if summary.memory_reads:
        lines.append(f"//   mem-r: {_format_memory_summary(summary.memory_reads)}")
    if summary.memory_writes:
        lines.append(f"//   mem-w: {_format_memory_summary(summary.memory_writes)}")
    return lines


def _call_comment(name: str, summary: FunctionStateSummary) -> str | None:
    if not _has_surface_data(summary):
        return None
    inputs = tuple((*summary.gp_register_inputs, *summary.segment_register_inputs, *summary.flag_inputs))
    outputs = tuple((*summary.gp_register_outputs, *summary.segment_register_outputs, *summary.flag_outputs))
    return (
        f"/* io {name}: in={_join(inputs)}; out={_join(outputs)}; ret={summary.return_kind} */"
    )


def _prepend_header(rendered: str, header_lines: list[str]) -> str:
    if not header_lines:
        return rendered
    header = "\n".join(header_lines)
    if rendered.startswith(header):
        return rendered
    return f"{header}\n{rendered}"


def _annotate_call_lines(rendered: str, call_comments: dict[str, str]) -> str:
    if not call_comments:
        return rendered
    lines = rendered.splitlines()
    updated: list[str] = []
    for line in lines:
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith(("//", "/*", "*"))
            or stripped.endswith("{")
            or _PROTOTYPE_RE.match(stripped)
            or "/* io " in stripped
        ):
            updated.append(line)
            continue
        appended = False
        for name, comment in call_comments.items():
            if f"{name}(" not in line or not stripped.endswith(";"):
                continue
            updated.append(f"{line} {comment}")
            appended = True
            break
        if not appended:
            updated.append(line)
    return "\n".join(updated)


def _render_with_interface_surface(project, codegen, rendered: str) -> str:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return rendered
    function = project.kb.functions.function(addr=getattr(cfunc, "addr", None), create=False)
    if function is None:
        return rendered
    current_summary = _summary_from_source(function)
    rendered = _prepend_header(rendered, _function_header_lines(getattr(cfunc, "name", "sub"), current_summary))

    call_comments: dict[str, str] = {}
    for seed in collect_neighbor_call_targets(function):
        callee = project.kb.functions.function(addr=getattr(seed, "target_addr", None), create=False)
        if callee is None:
            continue
        callee_name = getattr(callee, "name", None)
        if not isinstance(callee_name, str) or not callee_name:
            continue
        comment = _call_comment(callee_name, _summary_from_source(callee))
        if comment is None:
            continue
        call_comments.setdefault(callee_name, comment)
    return _annotate_call_lines(rendered, call_comments)


def apply_x86_16_function_interface_surface(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    original = getattr(codegen, "render_text", None)
    if not callable(original):
        return False
    if getattr(codegen, "_inertia_function_interface_surface_installed", False):
        return False

    def _render_text_with_interface(_cfunc):  # noqa: ANN001
        # ── Runtime contract: facts produced must be consumed before C emission ──
        from .pipeline.contracts import assert_pipeline_contracts_8616
        assert_pipeline_contracts_8616(codegen)

        rendered = original(_cfunc)
        if not isinstance(rendered, str):
            return rendered
        return _render_with_interface_surface(project, codegen, rendered)

    setattr(codegen, "_inertia_function_interface_surface_installed", True)
    setattr(codegen, "_inertia_function_interface_original_render_text", original)
    setattr(codegen, "render_text", _render_text_with_interface)
    return True
