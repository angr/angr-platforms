from __future__ import annotations

from dataclasses import dataclass

from .callsite_summary import summarize_x86_16_callsite

__all__ = ["FunctionSummary8616", "summarize_x86_16_function"]


@dataclass(frozen=True, slots=True)
class FunctionSummary8616:
    function_addr: int
    direct_call_count: int
    callsite_kinds: tuple[str, ...]
    typed_ir_condition_kinds: tuple[str, ...]
    typed_ir_register_clobbers: tuple[str, ...]
    typed_ir_address_spaces: tuple[str, ...]
    typed_ir_stable_address_spaces: tuple[str, ...]
    frame_slot_count: int | None


def summarize_x86_16_function(project, function) -> FunctionSummary8616 | None:
    if project is None or function is None:
        return None
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return None

    callsite_kinds: list[str] = []
    for callsite_addr in tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ())):
        summary = summarize_x86_16_callsite(function, callsite_addr)
        if summary is None or not isinstance(summary.kind, str):
            continue
        callsite_kinds.append(summary.kind)

    info = getattr(function, "info", None)
    vex_ir_summary = info.get("x86_16_vex_ir_summary", {}) if isinstance(info, dict) else {}
    condition_counts = vex_ir_summary.get("condition_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    register_clobbers = vex_ir_summary.get("register_clobbers", {}) if isinstance(vex_ir_summary, dict) else {}
    address_space_counts = vex_ir_summary.get("address_space_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    stable_address_space_counts = vex_ir_summary.get("stable_address_space_counts", {}) if isinstance(vex_ir_summary, dict) else {}
    frame_slot_count = vex_ir_summary.get("frame_slot_count") if isinstance(vex_ir_summary, dict) else None
    typed_ir_condition_kinds = tuple(sorted(str(key) for key in condition_counts))
    typed_ir_register_clobbers = tuple(sorted(str(key) for key, count in register_clobbers.items() if isinstance(count, int) and count > 0))
    typed_ir_address_spaces = tuple(
        sorted(str(key) for key, count in address_space_counts.items() if isinstance(count, int) and count > 0)
    )
    typed_ir_stable_address_spaces = tuple(
        sorted(str(key) for key, count in stable_address_space_counts.items() if isinstance(count, int) and count > 0)
    )
    return FunctionSummary8616(
        function_addr=int(getattr(function, "addr")),
        direct_call_count=len(callsite_kinds),
        callsite_kinds=tuple(sorted(callsite_kinds)),
        typed_ir_condition_kinds=typed_ir_condition_kinds,
        typed_ir_register_clobbers=typed_ir_register_clobbers,
        typed_ir_address_spaces=typed_ir_address_spaces,
        typed_ir_stable_address_spaces=typed_ir_stable_address_spaces,
        frame_slot_count=frame_slot_count if isinstance(frame_slot_count, int) else None,
    )
