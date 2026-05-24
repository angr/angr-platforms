from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CTypeCast

from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _global_memory_addr_8616,
    _match_segmented_dereference_8616,
)

__all__ = [
    "_global_load_addr_8616",
    "_segmented_load_addr_8616",
    "_match_global_scaled_high_byte_8616",
]


def _global_load_addr_8616(node) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    return _global_memory_addr_8616(node)


def _segmented_load_addr_8616(node, project) -> tuple[str | None, int | None]:
    while isinstance(node, CTypeCast):
        node = node.expr
    seg_name, linear = _match_segmented_dereference_8616(node, project)
    if seg_name is None or not isinstance(linear, int):
        return None, None
    return seg_name, linear


def _match_global_scaled_high_byte_8616(node) -> int | None:
    if not isinstance(node, CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 0x100:
                continue
            addr = _global_load_addr_8616(maybe_load)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if _c_constant_value_8616(maybe_scale) != 8:
                continue
            addr = _global_load_addr_8616(maybe_load)
            if addr is not None:
                return addr

    return None
