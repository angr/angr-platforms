from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia_decompiler.cli_access_profiles import (
    AccessTraitEvidenceProfile,
    AccessTraitInductionVar,
    InductionSummary,
    AccessTraitStrideEvidence,
    infer_induction_variable,
)

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from angr_platforms.X86_16.type_array_matching import _rewrite_induction_loops_8616


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project(traits=None):
    return SimpleNamespace(arch=Arch86_16(), _inertia_access_traits=traits or {})


def _codegen(project, statements):
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "i"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def _break_if(cond, codegen):
    return CIfElse(
        [(cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )


def _induction_traits(reg_offset: int, stride: int, *, conflicting_stride: int | None = None):
    base = {
        ("induction_like", "ss", ("stack", "bp", -4), ("reg", reg_offset), stride, 0, 2): AccessTraitStrideEvidence(
            segment="ss",
            base_key=("stack", "bp", -4),
            index_key=("reg", reg_offset),
            stride=stride,
            offset=0,
            width=2,
            count=3,
            kind="induction_like",
        )
    }
    if conflicting_stride is not None:
        base[("induction_like", "ss", ("stack", "bp", -4), ("reg", reg_offset), conflicting_stride, 0, 2)] = AccessTraitStrideEvidence(
            segment="ss",
            base_key=("stack", "bp", -4),
            index_key=("reg", reg_offset),
            stride=conflicting_stride,
            offset=0,
            width=2,
            count=2,
            kind="induction_like",
        )
    return {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": base,
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }


def _increment_loop_fixture(project, codegen, *, reg_name: str, bound: int, stride: int):
    var = _reg(project, reg_name, codegen)
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements(
            [
                _break_if(CBinaryOp("CmpGE", var, _const(bound, codegen), codegen=codegen), codegen),
                CAssignment(var, CBinaryOp("Add", var, _const(stride, codegen), codegen=codegen), codegen=codegen),
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([loop, CReturn(var, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    return codegen


def test_infer_induction_variable_accepts_stable_stride_profile():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=2,
                offset=0,
                width=2,
                count=3,
                kind="induction_like",
            ),
        ),
    )

    inferred = infer_induction_variable(profile)

    assert inferred is not None
    assert inferred.index_key == ("reg", 30)
    assert inferred.stride == 2


def test_infer_induction_variable_refuses_mixed_stride_profile():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=2,
                offset=0,
                width=2,
                count=3,
                kind="induction_like",
            ),
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=4,
                offset=0,
                width=2,
                count=2,
                kind="induction_like",
            ),
        ),
    )

    assert infer_induction_variable(profile) is None


def test_infer_induction_variable_refuses_single_evidence_profile():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=2,
                offset=0,
                width=2,
                count=1,
                kind="induction_like",
            ),
        ),
    )

    assert infer_induction_variable(profile) is None


def test_array_matching_rewrites_simple_increment_loop_without_tail_delta(monkeypatch):
    project = _project(_induction_traits(_project().arch.registers["si"][0], 1))
    before_codegen = _increment_loop_fixture(project, _codegen(project, []), reg_name="si", bound=10, stride=1)
    after_codegen = _increment_loop_fixture(project, _codegen(project, []), reg_name="si", bound=10, stride=1)
    monkeypatch.setattr(
        "angr_platforms.X86_16.type_array_matching._profile_induction_match_8616",
        lambda _codegen, _loop_var: AccessTraitInductionVar(
            base_key=("stack", "bp", -4),
            index_key=("reg", project.arch.registers["si"][0]),
            stride=1,
            width=2,
            offset=0,
            count=3,
        ),
    )

    changed = _rewrite_induction_loops_8616(after_codegen)

    assert changed is True
    loop = after_codegen.cfunc.statements.statements[0]
    assert isinstance(loop, CWhileLoop)
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert len(loop.body.statements) == 1

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen)
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen)
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_array_matching_uses_structuring_induction_summary_artifact_without_monkeypatch():
    project = _project()
    codegen = _increment_loop_fixture(project, _codegen(project, []), reg_name="si", bound=10, stride=1)
    codegen._inertia_induction_summaries = (
        InductionSummary(
            base_key=("stack", "bp", -4),
            index_key=("reg", project.arch.registers["si"][0]),
            stride=1,
            direction="increment",
            bound_candidate=10,
            width=2,
            offset=0,
            count=3,
        ),
    )

    changed = _rewrite_induction_loops_8616(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert isinstance(loop, CWhileLoop)
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"


def test_array_matching_rewrites_decrement_loop(monkeypatch):
    project = _project(_induction_traits(_project().arch.registers["cx"][0], 2))
    codegen = _codegen(project, [])
    i = _reg(project, "cx", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpLE", i, _const(0, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Sub", i, _const(2, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.type_array_matching._profile_induction_match_8616",
        lambda _codegen, _loop_var: AccessTraitInductionVar(
            base_key=("stack", "bp", -4),
            index_key=("reg", project.arch.registers["cx"][0]),
            stride=2,
            width=2,
            offset=0,
            count=3,
        ),
    )

    changed = _rewrite_induction_loops_8616(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert loop.condition.op == "CmpGT"
    update = loop.body.statements[0]
    assert isinstance(update, CAssignment)


def test_array_matching_rewrites_stack_local_induction_loop_from_summary_artifact():
    project = _project()
    codegen = _codegen(project, [])
    i = _stack(-2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(10, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(2, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_induction_summaries = (
        InductionSummary(
            base_key=("stack", "bp", -4),
            index_key=("stack", "bp", -2, 0x4010),
            stride=2,
            direction="increment",
            bound_candidate=10,
            width=2,
            offset=0,
            count=3,
        ),
    )

    changed = _rewrite_induction_loops_8616(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"


def test_array_matching_rewrites_stride_non_unit_loop(monkeypatch):
    project = _project(_induction_traits(_project().arch.registers["di"][0], 4))
    codegen = _codegen(project, [])
    i = _reg(project, "di", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(16, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(4, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.type_array_matching._profile_induction_match_8616",
        lambda _codegen, _loop_var: AccessTraitInductionVar(
            base_key=("stack", "bp", -4),
            index_key=("reg", project.arch.registers["di"][0]),
            stride=4,
            width=2,
            offset=0,
            count=3,
        ),
    )

    changed = _rewrite_induction_loops_8616(codegen)

    assert changed is True
    loop = codegen.cfunc.statements.statements[0]
    assert loop.condition.op == "CmpLT"
    update = loop.body.statements[0]
    assert update.rhs.rhs.value == 4


def test_array_matching_refuses_loop_with_conflicting_induction_evidence():
    dummy = _DummyCodegen(_project())
    reg_offset = dummy.project.arch.registers["si"][0]
    project = _project({0x4010: _induction_traits(reg_offset, 2, conflicting_stride=4)})
    codegen = _codegen(project, [])
    i = _reg(project, "si", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CWhileLoop(
                _const(1, codegen),
                CStatements(
                    [
                        _break_if(CBinaryOp("CmpGE", i, _const(10, codegen), codegen=codegen), codegen),
                        CAssignment(i, CBinaryOp("Add", i, _const(1, codegen), codegen=codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_induction_loops_8616(codegen)

    assert changed is False
    loop = codegen.cfunc.statements.statements[0]
    assert isinstance(loop.condition, CConstant)
