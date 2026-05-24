from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from inertia_decompiler.cli_access_object_hints import _build_stable_access_object_hints
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_cod_globals import _coalesce_cod_word_global_loads


def _make_word_pair_rhs(low_addr: int, *, codegen):
    return structured_c.CBinaryOp(
        "Or",
        structured_c.CVariable(SimMemoryVariable(low_addr, 1, name=f"g_{low_addr:x}"), codegen=codegen),
        structured_c.CBinaryOp(
            "Mul",
            structured_c.CVariable(SimMemoryVariable(low_addr + 1, 1, name=f"g_{low_addr + 1:x}"), codegen=codegen),
            structured_c.CConstant(0x100, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _replace_c_children(root, transform):
    changed = False
    for statement in getattr(root, "statements", ()):
        if isinstance(statement, structured_c.CAssignment):
            new_rhs = transform(statement.rhs)
            if new_rhs is not statement.rhs:
                statement.rhs = new_rhs
                changed = True
    return changed


def _global_load_addr(expr, _project):
    if isinstance(expr, structured_c.CVariable) and isinstance(expr.variable, SimMemoryVariable):
        return expr.variable.addr
    return None


def _match_scaled_high_byte(expr, _project):
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Mul":
        return None
    lhs = expr.lhs
    rhs = expr.rhs
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(lhs.variable, SimMemoryVariable):
        return None
    if not isinstance(rhs, structured_c.CConstant) or rhs.value != 0x100:
        return None
    return lhs.variable.addr


def _synthetic_word_global_variable(codegen, _synthetic_globals, low_addr, created):
    cvar = created.get(low_addr)
    if cvar is not None:
        return cvar
    variable = SimMemoryVariable(low_addr, 2, name=f"g_{low_addr:x}_word")
    cvar = structured_c.CVariable(variable, codegen=codegen)
    created[low_addr] = cvar
    return cvar


def _make_codegen():
    project = SimpleNamespace(arch=SimpleNamespace(byte_width=8, name="X86"))
    cfunc = SimpleNamespace(
        addr=0x10010,
        variables_in_use={},
        unified_local_vars={},
        arg_list=(),
        sort_local_vars=lambda: None,
    )
    codegen = SimpleNamespace(
        cfunc=cfunc,
        project=project,
        next_idx=lambda _name: 0,
        cstyle_null_cmp=False,
    )
    lhs = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="s_0", region=0x10010),
        codegen=codegen,
    )
    cfunc.statements = structured_c.CStatements(
        [structured_c.CAssignment(lhs, _make_word_pair_rhs(0x200, codegen=codegen), codegen=codegen)],
        addr=0x10010,
        codegen=codegen,
    )
    return project, codegen


def test_cod_globals_refusal_does_not_invent_member_shape():
    project, codegen = _make_codegen()
    project._inertia_access_traits = {
        codegen.cfunc.addr: {
            "member_evidence": {
                (("mem", 0x200), 0, 2): 3,
            },
            "array_evidence": {
                (("mem", 0x200), ("reg", "bx"), 2, 4, 2): 1,
            },
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
        }
    }

    changed = _coalesce_cod_word_global_loads(
        project,
        codegen,
        {0x200: ("table_word", 2)},
        collect_access_traits=lambda *_args, **_kwargs: None,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda traits: _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
        global_load_addr=_global_load_addr,
        match_scaled_high_byte=_match_scaled_high_byte,
        synthetic_word_global_variable=_synthetic_word_global_variable,
        replace_c_children=_replace_c_children,
    )

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, structured_c.CVariable)
    assert isinstance(rhs.variable, SimMemoryVariable)
    assert rhs.variable.size == 2


def test_cod_globals_member_record_blocks_word_coalesce():
    project, codegen = _make_codegen()
    project._inertia_access_traits = {
        codegen.cfunc.addr: {
            "member_evidence": {
                (("mem", 0x200), 0, 2): 1,
            },
            "array_evidence": {},
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
        }
    }

    changed = _coalesce_cod_word_global_loads(
        project,
        codegen,
        {0x200: ("table_word", 2)},
        collect_access_traits=lambda *_args, **_kwargs: None,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda traits: _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
        global_load_addr=_global_load_addr,
        match_scaled_high_byte=_match_scaled_high_byte,
        synthetic_word_global_variable=_synthetic_word_global_variable,
        replace_c_children=_replace_c_children,
    )

    assert changed is False
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, structured_c.CBinaryOp)
    assert rhs.op == "Or"
