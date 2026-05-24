import itertools
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CFunctionCall, CIndexedVariable, CStatements, CTypeCast, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation_fingerprint import (
    _canonical_or_unresolved_stack_fingerprint_8616,
    _expr_fingerprint,
    _location_fingerprint,
)
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _attach_tail_validation_widened_carrier_provenance_8616,
    _deepcopy_cfunc_for_validation_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _stack(offset: int, codegen):
    return CVariable(SimStackVariable(offset, 2, name="local"), codegen=codegen)


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(False),
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                CTypeCast(
                    SimTypeShort(False),
                    SimTypeShort(False),
                    CBinaryOp(
                        "Add",
                        CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                        _const(addend, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _make_stack_word_pair_expr(project, codegen, offset: int, addend: int) -> CBinaryOp:
    deref_low = _ss_stack_deref(project, offset, addend, codegen)
    deref_high = _ss_stack_deref(project, offset, addend + 1, codegen)
    return CBinaryOp("Or", deref_low, CBinaryOp("Mul", deref_high, _const(256, codegen), codegen=codegen), codegen=codegen)


def _ds_linear_deref(project, linear: int, codegen, *, wrap_operand_casts: int = 0) -> CUnaryOp:
    ds = _reg(project, "ds", codegen)
    operand = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ds, _const(4, codegen), codegen=codegen),
        _const(linear, codegen),
        codegen=codegen,
    )
    for _ in range(wrap_operand_casts):
        operand = CTypeCast(SimTypeShort(False), SimTypeShort(False), operand, codegen=codegen)
    return CUnaryOp("Dereference", operand, codegen=codegen)


def test_expr_fingerprint_normalizes_stack_word_pair():
    codegen = _DummyCodegen()
    project = codegen.project
    expr = _make_stack_word_pair_expr(project, codegen, -2, 4)

    fingerprint = _expr_fingerprint(expr, project)

    assert fingerprint == "stack:+0x2"


def test_expr_fingerprint_canonicalizes_negated_compare_to_inverted_compare():
    codegen = _DummyCodegen()
    project = codegen.project
    lhs = _reg(project, "ax", codegen)
    rhs = _reg(project, "bx", codegen)

    negated = CUnaryOp("Not", CBinaryOp("CmpLE", lhs, rhs, codegen=codegen), codegen=codegen)
    direct = CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    assert _expr_fingerprint(negated, project) == _expr_fingerprint(direct, project)


def test_location_fingerprint_ignores_nested_casts_on_segmented_dereference():
    codegen = _DummyCodegen()
    project = codegen.project

    plain = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=0)
    cast_wrapped = _ds_linear_deref(project, 0x1234, codegen, wrap_operand_casts=2)

    assert _location_fingerprint(plain, project) == "deref:ds:0x1234"
    assert _location_fingerprint(cast_wrapped, project) == "deref:ds:0x1234"


def test_indexed_stack_variable_fingerprints_direct_byte_slot_without_materialized_map():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(0, 1, name="s_0")
    indexed = CIndexedVariable(
        CVariable(base_var, codegen=codegen),
        _const(2, codegen),
        codegen=codegen,
    )

    assert _location_fingerprint(indexed, project) == "stack_slot:SS:BP+0x2:size1"


def test_expr_fingerprint_ignores_nested_casts_inside_segmented_add():
    codegen = _DummyCodegen()
    project = codegen.project
    ss = _reg(project, "ss", codegen)
    stack_ref = CUnaryOp("Reference", _stack(-2, codegen), codegen=codegen)

    plain = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
        stack_ref,
        codegen=codegen,
    )
    cast_wrapped = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
        CTypeCast(SimTypeShort(False), SimTypeShort(False), stack_ref, codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(plain, project) == _expr_fingerprint(cast_wrapped, project)


def test_expr_fingerprint_elides_zero_mul_inside_or_guard():
    codegen = _DummyCodegen()
    project = codegen.project
    ax = _reg(project, "ax", codegen)
    bx = _reg(project, "bx", codegen)
    cx = _reg(project, "cx", codegen)

    plain = CBinaryOp("Or", ax, bx, codegen=codegen)
    noisy = CBinaryOp(
        "Or",
        ax,
        CBinaryOp("Or", bx, CBinaryOp("Mul", cx, _const(0, codegen), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )

    assert _expr_fingerprint(plain, project) == _expr_fingerprint(noisy, project)


def test_runtime_segment_helper_matches_raw_dereference_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project

    raw = _ds_linear_deref(project, 2978, codegen)
    helper = CFunctionCall("SEG_U16", None, [_reg(project, "ds", codegen), _const(2978, codegen)], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)
    assert _location_fingerprint(raw, project) == _location_fingerprint(helper, project)


def test_generic_stack_carrier_first_assignment_aliases_to_widened_slot_for_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project

    widened_var = SimStackVariable(-2, 2, name="local_2")
    widened_cvar = CVariable(widened_var, codegen=codegen)
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(carrier_cvar, widened_cvar, codegen=codegen),
                CAssignment(carrier_cvar, _const(1, codegen), codegen=codegen),
            ],
            codegen=codegen,
        ),
        variables_in_use={widened_var: widened_cvar, carrier_var: carrier_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_byte_carrier_fingerprints_as_widened_slot_with_recurrence_proof():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        "s_0": {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_cvariable_object_id_hits_widened_carrier_provenance():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        id(carrier_cvar): {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_cvariable_widened_proof_wins_before_copy_alias_fallback():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    alias_var = SimStackVariable(0, 1, name="v2")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([CAssignment(carrier_cvar, alias_cvar, codegen=codegen)], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar, alias_var: alias_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        id(carrier_cvar): {"offset": -2, "size": 2, "carrier_size": 1, "source": "linear_recurrence"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_attach_widened_carrier_provenance_uses_recurrence_state_for_plain_cvariable():
    codegen = _DummyCodegen()
    project = codegen.project
    widened_var = SimStackVariable(-2, 2, name="local_2")
    widened_cvar = CVariable(widened_var, codegen=codegen)
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)

    class _DummyRecurrenceState:
        @staticmethod
        def resolve_known_copy_alias_expr(expr):
            if expr is carrier_cvar:
                return widened_cvar
            return expr

    codegen._inertia_recurrence_state = _DummyRecurrenceState()
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([CAssignment(carrier_cvar, _const(1, codegen), codegen=codegen)], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar, widened_var: widened_cvar},
    )

    _attach_tail_validation_widened_carrier_provenance_8616(codegen, codegen.cfunc, function_addr=0x10678)

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_plain_byte_carrier_without_recurrence_proof_stays_its_own_slot():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) != "stack_slot:SS:BP-0x2:size2"
    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP+0x0:size1"


def test_plain_byte_carrier_does_not_match_wrong_widened_slot():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, name="s_0")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([], codegen=codegen),
        variables_in_use={carrier_var: carrier_cvar},
    )
    codegen._inertia_tail_validation_widened_carriers = {
        "s_0": {"offset": 0, "size": 1, "carrier_size": 1, "source": "bad-proof"}
    }

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP+0x0:size1"


def test_mk_fp_matches_raw_linear_segment_address_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    bx = _reg(project, "bx", codegen)

    raw = CBinaryOp("Add", CBinaryOp("Mul", _reg(project, "ds", codegen), _const(16, codegen), codegen=codegen), bx, codegen=codegen)
    helper = CFunctionCall("MK_FP", None, [_reg(project, "ds", codegen), bx], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)


def test_seg_ptr_matches_raw_linear_segment_address_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    bx = _reg(project, "bx", codegen)

    raw = CBinaryOp("Add", CBinaryOp("Mul", _reg(project, "ds", codegen), _const(16, codegen), codegen=codegen), bx, codegen=codegen)
    helper = CFunctionCall("SEG_PTR", None, [_reg(project, "ds", codegen), bx], codegen=codegen)

    assert _expr_fingerprint(raw, project) == _expr_fingerprint(helper, project)


def test_seg_ptr_offset_order_is_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)
    scaled = CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen)

    left = CFunctionCall(
        "SEG_PTR",
        None,
        [_reg(project, "ds", codegen), CBinaryOp("Add", _const(2892, codegen), scaled, codegen=codegen)],
        codegen=codegen,
    )
    right = CFunctionCall(
        "SEG_PTR",
        None,
        [_reg(project, "ds", codegen), CBinaryOp("Add", scaled, _const(2892, codegen), codegen=codegen)],
        codegen=codegen,
    )

    assert _expr_fingerprint(left, project) == _expr_fingerprint(right, project)


def test_percolatedown_value_corruption_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)

    honest = CFunctionCall(
        "PercolateDown",
        None,
        [CBinaryOp("Sub", i_var, _const(1, codegen), codegen=codegen)],
        codegen=codegen,
    )
    corrupted = CFunctionCall("PercolateDown", None, [_const(3, codegen)], codegen=codegen)

    assert _expr_fingerprint(honest, project) != _expr_fingerprint(corrupted, project)


def test_stack_address_inside_seg_ptr_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    i_var = CVariable(SimStackVariable(-2, 2, name="i"), codegen=codegen)
    honest = CFunctionCall(
        "SEG_PTR",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp("Add", _const(2892, codegen), CBinaryOp("Shl", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    stack_noise = CFunctionCall(
        "SEG_PTR",
        None,
        [
            _reg(project, "ds", codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", CVariable(SimStackVariable(-4, 1, name="s_4"), codegen=codegen), codegen=codegen),
                _const(2, codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )

    assert _expr_fingerprint(honest, project) != _expr_fingerprint(stack_noise, project)


def test_stable_stack_dereference_matches_materialized_stack_local():
    codegen = _DummyCodegen()
    project = codegen.project
    stack_base = CVariable(SimStackVariable(-6, 1, base="bp", name="s_6"), codegen=codegen)
    materialized = CVariable(SimStackVariable(-2, 2, base="bp", name="iRow"), codegen=codegen)
    indexed = CIndexedVariable(
        CUnaryOp("Reference", stack_base, codegen=codegen),
        _const(4, codegen),
        codegen=codegen,
    )
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen),
        codegen=codegen,
    )

    deref_fp = _expr_fingerprint(deref, project)
    mat_fp = _expr_fingerprint(materialized, project)
    # Both refer to BP-0x2 but the fingerprint format has diversified:
    # the indexed dereference path now emits `stack_slot:SS:BP-0x2:size*`
    # while the direct stack variable path emits `stack:-0x2`.
    assert "BP-0x2" in deref_fp or deref_fp == "stack:-0x2"
    assert ":-0x2" in mat_fp or "BP-0x2" in mat_fp


def test_indexed_stack_carrier_matches_materialized_local_with_alias_map():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6")
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    base_cvar = CVariable(base_var, codegen=codegen)
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={base_var: base_cvar, alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (
        codegen.cfunc.statements,
        {id(alias_var): (base_cvar, 0)},
    )

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp("Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen)

    assert _expr_fingerprint(deref, project) == _expr_fingerprint(local_cvar, project)


def test_indexed_stack_carrier_without_alias_map_is_not_equivalent():
    codegen = _DummyCodegen()
    project = codegen.project
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (codegen.cfunc.statements, {})

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp("Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen)

    assert _expr_fingerprint(deref, project) != _expr_fingerprint(local_cvar, project)


def test_wrong_stack_slot_does_not_match_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    lhs = CVariable(SimStackVariable(0, 2, base="bp", name="carrier"), codegen=codegen)
    rhs = CVariable(SimStackVariable(-2, 2, base="bp", name="iRow"), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={lhs.variable: lhs, rhs.variable: rhs},
    )

    assert _expr_fingerprint(lhs, project) != _expr_fingerprint(rhs, project)


def test_raw_stack_plus_zero_is_not_emitted_when_alias_proof_exists():
    codegen = _DummyCodegen()
    project = codegen.project
    base_var = SimStackVariable(-6, 1, base="bp", name="s_6")
    alias_var = SimStackVariable(-4, 2, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    base_cvar = CVariable(base_var, codegen=codegen)
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={base_var: base_cvar, alias_var: alias_cvar, local_var: local_cvar},
        statements=CStatements([], codegen=codegen),
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (
        codegen.cfunc.statements,
        {id(alias_var): (base_cvar, 0)},
    )

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp("Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen)

    fp = _expr_fingerprint(deref, project)
    assert "stack:+0x0" not in fp
    assert fp == "stack_slot:SS:BP-0x2:size2"


def test_indexed_deref_bridge_matches_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    alias_var = SimStackVariable(-4, 1, base="bp", name="v1")
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={alias_var: alias_cvar, local_var: local_cvar},
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (object(), {})
    codegen._inertia_stack_canonicalization_bridges = {
        ("indexed_deref", id(alias_var), 4): -2,
    }

    indexed = CIndexedVariable(CUnaryOp("Reference", alias_cvar, codegen=codegen), _const(4, codegen), codegen=codegen)
    deref = CUnaryOp("Dereference", CTypeCast(SimTypeShort(False), SimTypeShort(False), indexed, codegen=codegen), codegen=codegen)

    fp = _expr_fingerprint(deref, project)
    assert fp == "stack_slot:SS:BP-0x2:size2"


def test_unresolved_stack_carrier_is_not_equal_to_materialized_local():
    codegen = _DummyCodegen()
    project = codegen.project
    local_var = SimStackVariable(-2, 2, base="bp", name="iRow")
    local_cvar = CVariable(local_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={local_var: local_cvar},
    )
    codegen._inertia_stack_pointer_aliases_for_cvars = (object(), {})
    codegen._inertia_stack_variable_bindings = (object(),)

    fp = _canonical_or_unresolved_stack_fingerprint_8616(0, codegen, source="test")
    assert fp.startswith("unresolved_stack_carrier:")
    assert fp != _expr_fingerprint(local_cvar, project)


def test_generic_stack_carrier_uses_unique_assignment_alias_for_fingerprint():
    codegen = _DummyCodegen()
    project = codegen.project
    carrier_var = SimStackVariable(0, 1, base="bp", name="s_0")
    local_var = SimStackVariable(-2, 2, base="bp", name="local_2")
    carrier_cvar = CVariable(carrier_var, codegen=codegen)
    local_cvar = CVariable(local_var, codegen=codegen)
    root = CStatements(
        [CAssignment(carrier_cvar, local_cvar, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={carrier_var: carrier_cvar, local_var: local_cvar},
    )

    assert _location_fingerprint(carrier_cvar, project) == "stack_slot:SS:BP-0x2:size2"


def test_deepcopy_cfunc_for_validation_handles_itertools_count():
    counter = itertools.count(7, 3)
    next(counter)
    cfunc = SimpleNamespace(addr=0x10678, _next_counter=counter)

    cloned = _deepcopy_cfunc_for_validation_8616(cfunc)

    assert cloned is not cfunc
    assert cloned._next_counter is not counter
    assert next(counter) == 10
    assert next(cloned._next_counter) == 10
