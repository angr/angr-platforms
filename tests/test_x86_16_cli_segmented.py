from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from inertia_decompiler import cli_segmented


def _const(value: int, codegen):
    return structured_c.CConstant(value, SimTypeShort(False).with_arch(codegen.project.arch), codegen=codegen)


def _flatten_add_terms(node, seen=None):
    if seen is None:
        seen = set()
    if id(node) in seen:
        return [node]
    seen.add(id(node))
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_add_terms(node.lhs, seen) + _flatten_add_terms(node.rhs, seen)
    return [node]


def test_classify_segmented_addr_expr_treats_sp_virtual_register_as_stack_anchor():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, cfunc=SimpleNamespace(addr=0x1000), next_idx=lambda _name: 0, cstyle_null_cmp=False)
    ss_offset, ss_size = project.arch.registers["ss"]
    ss_reg = structured_c.CVariable(SimRegisterVariable(ss_offset, ss_size, name="ss"), codegen=codegen)
    sp_offset, sp_size = project.arch.registers["sp"]
    sp_reg = structured_c.CVariable(SimRegisterVariable(sp_offset, sp_size, name="vvar_5"), codegen=codegen)
    expr = structured_c.CBinaryOp(
        "Add",
        structured_c.CBinaryOp("Shl", ss_reg, _const(4, codegen), codegen=codegen),
        structured_c.CBinaryOp("Sub", sp_reg, _const(2, codegen), codegen=codegen),
        codegen=codegen,
    )

    cache_store = {}

    classified = cli_segmented._classify_segmented_addr_expr(
        expr,
        project,
        project_rewrite_cache=lambda _project: cache_store,
        flatten_c_add_terms=_flatten_add_terms,
        unwrap_c_casts=lambda node: node.expr if isinstance(node, structured_c.CTypeCast) else node,
        c_constant_value=lambda node: node.value if isinstance(node, structured_c.CConstant) else None,
        match_stack_cvar_and_offset=lambda _node: None,
        normalize_16bit_signed_offset=lambda value: ((value + 0x8000) & 0xFFFF) - 0x8000,
        stack_slot_identity_for_variable=lambda _variable: None,
    )

    assert classified is not None
    assert classified.kind == "stack"
    assert classified.seg_name == "ss"
    assert classified.cvar is not None
    assert classified.stack_var is not None
    assert classified.stack_var.base == "sp"
    assert classified.extra_offset == -2
