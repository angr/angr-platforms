from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
import angr_platforms.X86_16.tail_validation as tail_validation_module
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
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


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements, codegen=None):
    codegen = codegen or _DummyCodegen()
    body = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=body)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name), codegen=codegen)


def _global(addr: int, codegen, *, name: str = "g"):
    return CVariable(SimMemoryVariable(addr, 2, name=name), codegen=codegen)


def _ds_deref(project, linear: int, codegen):
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ds", codegen), _const(16, codegen), codegen=codegen),
            _const(linear, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypeShort(False),
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
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


def _ss_dynamic_deref(project, codegen):
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            _reg(project, "ax", codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _flags_zero(project, codegen):
    return CBinaryOp(
        "CmpNE",
        CBinaryOp("And", _reg(project, "flags", codegen), _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
    )


def test_tail_validation_micro_slice_explicit_compare_branch_is_stable():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    condition_before = CBinaryOp("CmpGT", _reg(project, "ax", before_codegen), _reg(project, "bx", before_codegen), codegen=before_codegen)
    condition_after = CBinaryOp("CmpGT", _reg(project, "ax", after_codegen), _reg(project, "bx", after_codegen), codegen=after_codegen)
    before = _codegen(
        [
            CIfElse(
                [(condition_before, CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen))],
                None,
                codegen=before_codegen,
            ),
            CReturn(None, codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CIfElse(
                [(condition_after, CStatements([CBreak(codegen=after_codegen)], codegen=after_codegen))],
                None,
                codegen=after_codegen,
            ),
            CReturn(None, codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False


def test_tail_validation_micro_slice_detects_raw_flags_condition_regression():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpEQ",
                            _reg(project, "ax", before_codegen),
                            _const(0, before_codegen),
                            codegen=before_codegen,
                        ),
                        CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen),
                    )
                ],
                None,
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CIfElse(
                [(_flags_zero(project, after_codegen), CStatements([CBreak(codegen=after_codegen)], codegen=after_codegen))],
                None,
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["conditions"]["added"]
    assert diff["delta"]["conditions"]["removed"]


def test_tail_validation_micro_slice_detects_segmented_write_observable():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CAssignment(_global(0x1234, before_codegen), _const(7, before_codegen), codegen=before_codegen),
            CReturn(None, codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CAssignment(
                _ds_deref(project, 0x1234, after_codegen),
                _const(7, after_codegen),
                codegen=after_codegen,
            ),
            CReturn(None, codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="coarse"),
        collect_x86_16_tail_validation_summary(project, after, mode="coarse"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["global_writes"]["removed"] == ("global:0x1234",)
    assert diff["delta"]["segmented_writes"]["added"] == ("deref:ds:0x1234",)


def test_tail_validation_micro_slice_detects_stack_slot_to_segmented_ss_regression():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CAssignment(_stack(-2, before_codegen), _const(5, before_codegen), codegen=before_codegen),
            CReturn(None, codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CAssignment(
                _ss_dynamic_deref(project, after_codegen),
                _const(5, after_codegen),
                codegen=after_codegen,
            ),
            CReturn(None, codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="coarse"),
        collect_x86_16_tail_validation_summary(project, after, mode="coarse"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["stack_writes"]["removed"] == ("stack:-0x2",)
    assert diff["delta"]["segmented_writes"]["added"] == ("deref:Add(Mul(reg:ss,const:16),reg:ax)",)


def test_tail_validation_micro_slice_preserves_stack_loop_write_shape():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CWhileLoop(
                CBinaryOp("CmpGT", _stack(-2, before_codegen), _const(0, before_codegen), codegen=before_codegen),
                CStatements(
                    [
                        CAssignment(_stack(-2, before_codegen), _const(1, before_codegen), codegen=before_codegen),
                        CBreak(codegen=before_codegen),
                    ],
                    codegen=before_codegen,
                ),
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                CBinaryOp("CmpGT", _stack(-2, after_codegen), _const(0, after_codegen), codegen=after_codegen),
                CStatements(
                    [
                        CAssignment(_stack(-2, after_codegen), _const(1, after_codegen), codegen=after_codegen),
                        CBreak(codegen=after_codegen),
                    ],
                    codegen=after_codegen,
                ),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False


def test_tail_validation_micro_slice_preserves_helper_call_identity():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CExpressionStatement(CFunctionCall("helper_ping", None, [_const(1, before_codegen)], codegen=before_codegen), codegen=before_codegen),
            CReturn(None, codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CExpressionStatement(CFunctionCall("helper_ping", None, [_const(1, after_codegen)], codegen=after_codegen), codegen=after_codegen),
            CReturn(None, codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False


def test_tail_validation_micro_slice_detects_helper_call_identity_regression():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CExpressionStatement(CFunctionCall("helper_ping", None, [], codegen=before_codegen), codegen=before_codegen),
            CReturn(None, codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CExpressionStatement(CFunctionCall("helper_pong", None, [], codegen=after_codegen), codegen=after_codegen),
            CReturn(None, codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["helper_calls"]["added"] == ("helper_pong",)
    assert diff["delta"]["helper_calls"]["removed"] == ("helper_ping",)


def test_tail_validation_micro_slice_detects_return_value_regression():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CReturn(_const(0, before_codegen), codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CReturn(_reg(project, "ax", after_codegen), codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["returns"]["added"] == ("reg:ax",)
    assert diff["delta"]["returns"]["removed"] == ("const:0",)


def test_tail_validation_micro_slice_detects_control_flow_effect_regression():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CWhileLoop(
                _const(1, before_codegen),
                CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen),
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CWhileLoop(
                _const(1, after_codegen),
                CStatements([CContinue(codegen=after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["control_flow_effects"]["added"]
    assert diff["delta"]["control_flow_effects"]["removed"]


def test_tail_validation_micro_slice_live_out_ignores_register_write_used_only_by_condition():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CIfElse(
                [
                    (
                        CBinaryOp("Sub", _reg(project, "ax", before_codegen), _const(2, before_codegen), codegen=before_codegen),
                        CStatements([], codegen=before_codegen),
                    )
                ],
                None,
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CAssignment(_reg(project, "ax", after_codegen), _const(1, after_codegen), codegen=after_codegen),
            CIfElse(
                [
                    (
                        _reg(project, "ax", after_codegen),
                        CStatements([], codegen=after_codegen),
                    )
                ],
                None,
                codegen=after_codegen,
            ),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is True
    assert diff["delta"]["register_writes"] == {"added": (), "removed": ()}


def test_tail_validation_micro_slice_preserves_if_else_and_while_control_flow_surface():
    project = _project()
    before_codegen = _DummyCodegen()
    after_codegen = _DummyCodegen()
    before_cond = CBinaryOp("CmpEQ", _reg(project, "ax", before_codegen), _const(0, before_codegen), codegen=before_codegen)
    after_cond = CBinaryOp("CmpEQ", _reg(project, "ax", after_codegen), _const(0, after_codegen), codegen=after_codegen)
    before = _codegen(
        [
            CIfElse(
                [(before_cond, CStatements([CBreak(codegen=before_codegen)], codegen=before_codegen))],
                else_node=CStatements([CContinue(codegen=before_codegen)], codegen=before_codegen),
                codegen=before_codegen,
            ),
            CWhileLoop(before_cond, CStatements([], codegen=before_codegen), codegen=before_codegen),
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CIfElse(
                [(after_cond, CStatements([CBreak(codegen=after_codegen)], codegen=after_codegen))],
                else_node=CStatements([CContinue(codegen=after_codegen)], codegen=after_codegen),
                codegen=after_codegen,
            ),
            CWhileLoop(after_cond, CStatements([], codegen=after_codegen), codegen=after_codegen),
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False


def test_tail_validation_micro_slice_sortdemo_helper_target_identity_prefers_summary_addr(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: function if addr == 0x4010 else None
        )
    )
    codegen = _DummyCodegen()
    wrapped = _codegen(
        [
            CExpressionStatement(CFunctionCall(None, None, [_const(97, codegen)], codegen=codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        codegen,
    )
    wrapped.cfunc.get_call_sites = lambda: (0x4012,)

    monkeypatch.setattr(
        tail_validation_module,
        "summarize_x86_16_callsite",
        lambda _function, _callsite_addr: SimpleNamespace(target_addr=0x14AE, arg_count=1),
    )

    summary = collect_x86_16_tail_validation_summary(project, wrapped, mode="live_out")

    assert summary.helper_calls == ("addr:0x14ae",)


def test_tail_validation_micro_slice_sortdemo_ds_global_lowering_equivalence():
    project = _project()
    before_codegen = _DummyCodegen()
    before_codegen._inertia_segmented_memory_lowering = {
        "DS": {
            "classification": "const",
            "associated_space": "data",
            "allow_linear_lowering": True,
            "allow_object_lowering": True,
        }
    }
    after_codegen = _DummyCodegen()
    before = _codegen(
        [
            CAssignment(
                _ds_deref(project, 0x7000, before_codegen),
                _const(1, before_codegen),
                codegen=before_codegen,
            )
        ],
        before_codegen,
    )
    after = _codegen(
        [
            CAssignment(
                _global(0x7000, after_codegen),
                _const(1, after_codegen),
                codegen=after_codegen,
            )
        ],
        after_codegen,
    )

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before, mode="live_out"),
        collect_x86_16_tail_validation_summary(project, after, mode="live_out"),
    )

    assert diff["changed"] is False
