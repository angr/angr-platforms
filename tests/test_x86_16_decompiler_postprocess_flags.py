from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_flags import (
    _c_expr_uses_var_8616,
    _fix_interval_guard_conditions_8616,
    _rewrite_flag_bit_value_uses_8616,
    _rewrite_flag_condition_pairs_8616,
)
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = _project()

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def _empty_body(codegen):
    return CStatements([], codegen=codegen)


def test_rewrite_flag_condition_pairs_recovers_zero_flag_guard_without_tail_delta():
    project = _project()
    before_codegen = _codegen([])
    before_flags = _reg(project, "flags", before_codegen, var_name="flags_tmp")
    before_predicate = CBinaryOp(
        "CmpEQ",
        CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        codegen=before_codegen,
    )
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                before_flags,
                CBinaryOp("Mul", before_predicate, _const(0x40, before_codegen), codegen=before_codegen),
                codegen=before_codegen,
            ),
            CIfElse(
                [(
                    CUnaryOp(
                        "Not",
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", before_flags, _const(0x40, before_codegen), codegen=before_codegen),
                            _const(0, before_codegen),
                            codegen=before_codegen,
                        ),
                        codegen=before_codegen,
                    ),
                    _empty_body(before_codegen),
                )],
                codegen=before_codegen,
            ),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = _rewrite_flag_condition_pairs_8616(after_codegen)

    assert changed is True
    assert len(after_codegen.cfunc.statements.statements) == 1
    after_if = after_codegen.cfunc.statements.statements[0]
    after_condition = after_if.condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpEQ"
    assert _c_expr_uses_var_8616(after_condition, before_flags) is False

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_rewrite_flag_bit_value_uses_recovers_carry_predicate_for_numeric_use():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    target_var = _reg(project, "dx", codegen, var_name="dx_tmp")
    carry_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    flags_value = CBinaryOp("Mul", carry_predicate, _const(1, codegen), codegen=codegen)
    numeric_carry_use = CBinaryOp(
        "And",
        CBinaryOp("Shr", flags_var, _const(0, codegen), codegen=codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CAssignment(
                target_var,
                CBinaryOp("Add", _reg(project, "dx", codegen), numeric_carry_use, codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_bit_value_uses_8616(codegen)

    assert changed is True
    after_assign = codegen.cfunc.statements.statements[1]
    assert isinstance(after_assign, CAssignment)
    assert _c_expr_uses_var_8616(after_assign.rhs, flags_var) is False
    assert isinstance(after_assign.rhs, CBinaryOp)
    assert isinstance(after_assign.rhs.rhs, CBinaryOp)
    assert after_assign.rhs.rhs.op == "CmpLT"


def test_rewrite_flag_bit_value_uses_recovers_shift_materialized_carry_predicate():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    target_var = _reg(project, "dx", codegen, var_name="dx_tmp")
    carry_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    flags_value = CBinaryOp(
        "Or",
        CBinaryOp(
            "Shl",
            CBinaryOp("And", carry_predicate, _const(1, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        codegen=codegen,
    )
    numeric_carry_use = CBinaryOp(
        "And",
        CBinaryOp("Shr", flags_var, _const(0, codegen), codegen=codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CAssignment(
                target_var,
                CBinaryOp("Add", _reg(project, "dx", codegen), numeric_carry_use, codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_bit_value_uses_8616(codegen)

    assert changed is True
    after_assign = codegen.cfunc.statements.statements[1]
    assert isinstance(after_assign, CAssignment)
    assert _c_expr_uses_var_8616(after_assign.rhs, flags_var) is False
    assert isinstance(after_assign.rhs, CBinaryOp)
    assert isinstance(after_assign.rhs.rhs, CBinaryOp)
    assert after_assign.rhs.rhs.op == "CmpLT"


def test_rewrite_flag_bit_value_uses_refuses_masked_flag_value_that_is_not_zero_or_one():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    target_var = _reg(project, "dx", codegen, var_name="dx_tmp")
    zero_predicate = CBinaryOp("CmpEQ", _reg(project, "ax", codegen), _const(0, codegen), codegen=codegen)
    flags_value = CBinaryOp("Mul", zero_predicate, _const(0x40, codegen), codegen=codegen)
    masked_flag_use = CBinaryOp("And", flags_var, _const(0x40, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CAssignment(target_var, masked_flag_use, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_bit_value_uses_8616(codegen)

    assert changed is False
    after_assign = codegen.cfunc.statements.statements[1]
    assert isinstance(after_assign, CAssignment)
    assert _c_expr_uses_var_8616(after_assign.rhs, flags_var) is True


def test_rewrite_flag_condition_pairs_recovers_signed_mask_compare_without_raw_flags():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    of_predicate = CBinaryOp("CmpLT", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    flags_value = CBinaryOp(
        "Or",
        CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CIfElse([(condition, _empty_body(codegen))], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpNE"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False
    assert isinstance(after_condition.lhs, CBinaryOp)
    assert isinstance(after_condition.rhs, CBinaryOp)


def test_rewrite_flag_condition_pairs_refuses_rewrite_that_still_reads_raw_flags():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    flags_read = _reg(project, "flags", codegen, var_name="flags_read")
    flags_value = CBinaryOp(
        "Mul",
        CBinaryOp("And", flags_read, _const(0x40, codegen), codegen=codegen),
        _const(0x40, codegen),
        codegen=codegen,
    )
    condition = CUnaryOp(
        "Not",
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags_read, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(flags_var, flags_value, codegen=codegen),
            CIfElse([(condition, _empty_body(codegen))], codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is False
    after_condition = codegen.cfunc.statements.statements[1].condition_and_nodes[0][0]
    assert _c_expr_uses_var_8616(after_condition, flags_read) is True


def test_rewrite_flag_condition_pairs_refuses_incomplete_signed_mask_recovery():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "CmpNE",
                        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is False
    after_condition = codegen.cfunc.statements.statements[1].condition_and_nodes[0][0]
    assert _c_expr_uses_var_8616(after_condition, flags_var) is True


def test_rewrite_flag_condition_pairs_recovers_nested_flag_mask_inside_logical_and():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    of_predicate = CBinaryOp("CmpLT", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    other_guard = CUnaryOp(
        "Not",
        CBinaryOp("CmpLE", _reg(project, "si", codegen), _reg(project, "di", codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                    CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalAnd",
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                            CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                            codegen=codegen,
                        ),
                        other_guard,
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "LogicalAnd"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False
    assert isinstance(after_condition.lhs, CUnaryOp)
    assert after_condition.lhs.op == "Not"
    assert isinstance(after_condition.rhs, CUnaryOp)
    assert after_condition.rhs.op == "Not"


def test_rewrite_flag_condition_pairs_collapses_signed_gt_combo_from_zf_and_sf_of():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    lhs = _reg(project, "ax", codegen)
    rhs = _reg(project, "bx", codegen)
    zf_predicate = CBinaryOp("CmpEQ", lhs, rhs, codegen=codegen)
    sf_predicate = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    of_predicate = CBinaryOp("CmpEQ", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", zf_predicate, _const(0x40, codegen), codegen=codegen),
                    CBinaryOp(
                        "Or",
                        CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                        CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalAnd",
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", flags_var, _const(0x40, codegen), codegen=codegen),
                            _const(0, codegen),
                            codegen=codegen,
                        ),
                        CBinaryOp(
                            "CmpEQ",
                            CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                            CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                            codegen=codegen,
                        ),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpGT"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False


def test_rewrite_flag_condition_pairs_collapses_signed_le_combo_from_zf_or_sf_of():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    lhs = _reg(project, "ax", codegen)
    rhs = _reg(project, "bx", codegen)
    zf_predicate = CBinaryOp("CmpEQ", lhs, rhs, codegen=codegen)
    sf_predicate = CBinaryOp("CmpLT", lhs, rhs, codegen=codegen)
    of_predicate = CBinaryOp("CmpEQ", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", zf_predicate, _const(0x40, codegen), codegen=codegen),
                    CBinaryOp(
                        "Or",
                        CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                        CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalOr",
                        CBinaryOp("And", flags_var, _const(0x40, codegen), codegen=codegen),
                        CBinaryOp(
                            "CmpNE",
                            CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                            CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                            codegen=codegen,
                        ),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    after_if = next(
        stmt for stmt in codegen.cfunc.statements.statements if type(stmt).__name__ == "CIfElse"
    )
    after_condition = after_if.condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpLE"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False


def test_rewrite_flag_condition_pairs_rewrites_when_flags_assignment_is_not_immediately_before_if():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    scratch = _reg(project, "ax", codegen, var_name="scratch")
    sf_predicate = CBinaryOp("CmpLT", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen)
    of_predicate = CBinaryOp("CmpLT", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                    CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(scratch, _const(1, codegen), codegen=codegen),
            CIfElse(
                [(
                    CBinaryOp(
                        "CmpNE",
                        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
                        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    after_if = next(
        stmt for stmt in codegen.cfunc.statements.statements if type(stmt).__name__ == "CIfElse"
    )
    after_condition = after_if.condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "CmpNE"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False


def test_fix_interval_guard_conditions_rewrites_impossible_bool_cite_interval():
    codegen = _codegen([])
    project = _project()
    guard_value = CBinaryOp("Sub", _reg(project, "ax", codegen), _const(3, codegen), codegen=codegen)
    limit = _const(10, codegen)
    low = CBinaryOp("CmpGT", guard_value, limit, codegen=codegen)
    high = CBinaryOp("CmpLT", guard_value, limit, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CIfElse(
                [(
                    CBinaryOp(
                        "LogicalAnd",
                        CITE(low, _const(1, codegen), _const(0, codegen), codegen=codegen),
                        CITE(high, _const(1, codegen), _const(0, codegen), codegen=codegen),
                        codegen=codegen,
                    ),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _fix_interval_guard_conditions_8616(codegen)

    assert changed is True
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CBinaryOp)
    assert after_condition.op == "LogicalAnd"


def test_rewrite_flag_condition_pairs_strips_redundant_signed_flag_pair_when_explicit_gt_exists():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    lhs = _reg(project, "ax", codegen)
    rhs = _reg(project, "bx", codegen)
    sf_predicate = CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)
    of_predicate = CBinaryOp("CmpEQ", _reg(project, "cx", codegen), _reg(project, "dx", codegen), codegen=codegen)
    explicit_guard = CUnaryOp(
        "Not",
        CBinaryOp("CmpLE", lhs, rhs, codegen=codegen),
        codegen=codegen,
    )
    raw_flag_guard = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                flags_var,
                CBinaryOp(
                    "Or",
                    CBinaryOp("Mul", sf_predicate, _const(0x80, codegen), codegen=codegen),
                    CBinaryOp("Mul", of_predicate, _const(0x800, codegen), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CIfElse(
                [(
                    CBinaryOp("LogicalAnd", raw_flag_guard, explicit_guard, codegen=codegen),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_flag_condition_pairs_8616(codegen)

    assert changed is True
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CUnaryOp)
    assert after_condition.op == "Not"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False


def test_fix_interval_guard_conditions_strips_standalone_signed_flag_pair_when_strict_compare_exists():
    project = _project()
    codegen = _codegen([])
    flags_var = _reg(project, "flags", codegen, var_name="flags_tmp")
    strict_compare = CUnaryOp(
        "Not",
        CBinaryOp("CmpLE", _reg(project, "ax", codegen), _reg(project, "bx", codegen), codegen=codegen),
        codegen=codegen,
    )
    raw_flag_guard = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags_var, _const(0x80, codegen), codegen=codegen),
        CBinaryOp("And", flags_var, _const(0x800, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CIfElse(
                [(
                    CBinaryOp("LogicalAnd", raw_flag_guard, strict_compare, codegen=codegen),
                    _empty_body(codegen),
                )],
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _fix_interval_guard_conditions_8616(codegen)

    assert changed is True
    after_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(after_condition, CUnaryOp)
    assert after_condition.op == "Not"
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False


def test_fix_interval_guard_conditions_simplifies_split_ordering_if_chain_with_nested_flag_pair():
    project = _project()
    before_codegen = _codegen([])
    flags_var = _reg(project, "flags", before_codegen, var_name="flags_tmp")
    high_guard = CITE(
        CBinaryOp("CmpLE", _reg(project, "dx", before_codegen), _reg(project, "cx", before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        _const(1, before_codegen),
        codegen=before_codegen,
    )
    nested_flag_pair = CUnaryOp(
        "Not",
        CITE(
            CBinaryOp(
                "CmpEQ",
                CBinaryOp(
                    "CmpNE",
                    CBinaryOp("And", flags_var, _const(0x80, before_codegen), codegen=before_codegen),
                    _const(0, before_codegen),
                    codegen=before_codegen,
                ),
                CBinaryOp(
                    "CmpNE",
                    CBinaryOp("And", flags_var, _const(0x800, before_codegen), codegen=before_codegen),
                    _const(0, before_codegen),
                    codegen=before_codegen,
                ),
                codegen=before_codegen,
            ),
            _const(0, before_codegen),
            _const(1, before_codegen),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    low_guard = CITE(
        CBinaryOp("CmpLE", _reg(project, "ax", before_codegen), _reg(project, "bx", before_codegen), codegen=before_codegen),
        _const(0, before_codegen),
        _const(1, before_codegen),
        codegen=before_codegen,
    )
    before_codegen.cfunc.statements = CStatements(
        [
            CIfElse(
                [
                    (high_guard, _empty_body(before_codegen)),
                    (CBinaryOp("LogicalAnd", nested_flag_pair, low_guard, codegen=before_codegen), _empty_body(before_codegen)),
                ],
                codegen=before_codegen,
            ),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = _fix_interval_guard_conditions_8616(after_codegen)

    assert changed is True
    after_condition = after_codegen.cfunc.statements.statements[0].condition_and_nodes[1][0]
    assert isinstance(after_condition, CITE)
    assert _c_expr_uses_var_8616(after_condition, flags_var) is False
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False
