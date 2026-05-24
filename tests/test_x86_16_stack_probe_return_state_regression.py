from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler import structured_codegen as _scg
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CExpressionStatement, CFunctionCall, CStatements
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.callsite_stack_metadata import _generic_stack_carrier_name_8616
from angr_platforms.X86_16.decompiler_postprocess_calls import _materialize_callsite_stack_arguments_8616
from angr_platforms.X86_16.lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering import run_stack_lowering_pass_8616
from angr_platforms.X86_16.decompiler_postprocess_utils import _same_c_expression_8616
from angr_platforms.X86_16.stack_probe_fact_trace import format_stack_probe_fact_stats_8616


def _args_match(args: list, expected: list) -> bool:
    if len(args) != len(expected):
        return False
    return all(_same_c_expression_8616(a, e) for a, e in zip(args, expected))


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _empty_codegen(project):
    codegen = _DummyCodegen(project)
    root = CStatements([], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def test_stack_probe_typed_return_state_refuses_partial_recovery_when_summary_arg_count_is_oversized():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    arg_slot = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(
        CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen),
        codegen=codegen,
    )
    draw_bar = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(draw_bar, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(draw_bar): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert len(codegen.cfunc.statements.statements) == 3
    final_stmt = codegen.cfunc.statements.statements[2]
    assert isinstance(final_stmt, CExpressionStatement)
    assert final_stmt.expr.args == []
    assert codegen._inertia_callsite_summaries[id(draw_bar)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(draw_bar)].arg_widths == (2, 2)
    assert codegen._inertia_stack_probe_fact_stats == {
        "summaries_attached": 0,
        "stack_probe_summaries": 1,
        "ss_stack_address_returns": 1,
        "stack_arg_materializations": 0,
        "stable_ss_lowering_replacements": 0,
        "stable_ss_lowering_refusals": 0,
        "callsite_count": 0,
        "call_target_fact_count": 0,
        "call_target_materialized_count": 0,
        "call_arg_fact_count": 0,
        "call_arg_materialized_count": 0,
        "bp_slot_arg_value_normalized_count": 0,
        "pointer_arg_materialized_count": 0,
        "push_order_reversed_count": 0,
        "consumed_outgoing_stack_placeholder_count": 0,
        "stale_target_rejected_count": 0,
        "known_prototype_arg_mismatch_count": 0,
        "failure_count": 0,
    }


def test_stack_probe_fact_stats_split_arg_pickup_from_later_lowering_refusal():
    project = _project()
    codegen = _empty_codegen(project)
    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        )
    }
    codegen._inertia_stack_probe_fact_stats = {
        "summaries_attached": 0,
        "stack_probe_summaries": 1,
        "ss_stack_address_returns": 1,
        "stack_arg_materializations": 3,
        "stable_ss_lowering_replacements": 0,
        "stable_ss_lowering_refusals": 0,
    }

    changed = run_stack_lowering_pass_8616(
        rewrite_ss_stack_byte_offsets=lambda: False,
        canonicalize_stack_cvars=lambda: False,
        lower_stable_ss_stack_accesses=lambda: False,
        codegen=codegen,
        max_rounds=1,
    )

    assert changed is False
    assert codegen._inertia_stack_probe_fact_stats == {
        "summaries_attached": 0,
        "stack_probe_summaries": 1,
        "ss_stack_address_returns": 1,
        "stack_arg_materializations": 3,
        "stable_ss_lowering_replacements": 0,
        "stable_ss_lowering_refusals": 1,
        "callsite_count": 0,
        "call_target_fact_count": 0,
        "call_target_materialized_count": 0,
        "call_arg_fact_count": 0,
        "call_arg_materialized_count": 0,
        "bp_slot_arg_value_normalized_count": 0,
        "pointer_arg_materialized_count": 0,
        "push_order_reversed_count": 0,
        "consumed_outgoing_stack_placeholder_count": 0,
        "stale_target_rejected_count": 0,
        "known_prototype_arg_mismatch_count": 0,
        "failure_count": 0,
    }
    assert (
        format_stack_probe_fact_stats_8616(codegen)
        == "summaries_attached=0 stack_probe_summaries=1 ss_stack_address_returns=1 "
        "stack_arg_materializations=3 stable_ss_lowering_replacements=0 stable_ss_lowering_refusals=1 "
        "callsite_count=0 call_target_fact_count=0 call_target_materialized_count=0 "
        "call_arg_fact_count=0 call_arg_materialized_count=0 "
        "bp_slot_arg_value_normalized_count=0 pointer_arg_materialized_count=0 "
        "push_order_reversed_count=0 consumed_outgoing_stack_placeholder_count=0 "
        "stale_target_rejected_count=0 known_prototype_arg_mismatch_count=0 failure_count=0"
    )


def test_stack_probe_materialized_arg_prunes_adjacent_segment_metadata_stores():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(_ss_store(stack_carrier), zero_arg, codegen=codegen),
            CAssignment(_ss_store(stack_carrier), cs_reg, codegen=codegen),
            CAssignment(
                structured_c.CUnaryOp(
                    "Dereference",
                    structured_c.CBinaryOp(
                        "Add",
                        stack_carrier,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                structured_c.CBinaryOp(
                    "Shr",
                    cs_reg,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(call.args, [zero_arg])
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(codegen.cfunc.statements.statements[1], CExpressionStatement)


def test_stack_probe_materialized_arg_prunes_only_current_call_metadata():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    one_arg = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier_a = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_b = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="vvar_28"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call_a = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)
    call_b = CFunctionCall("displaycursor", SimpleNamespace(name="displaycursor"), [one_arg], codegen=codegen)
    stray_metadata = CAssignment(_ss_store(carrier_b), cs_reg, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(_ss_store(carrier_a), zero_arg, codegen=codegen),
            CAssignment(_ss_store(carrier_a), cs_reg, codegen=codegen),
            CExpressionStatement(call_a, codegen=codegen),
            stray_metadata,
            CExpressionStatement(call_b, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call_a): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
        id(call_b): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1666,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(call_a.args, [zero_arg])
    assert codegen.cfunc.statements.statements[2] is stray_metadata
    assert codegen.cfunc.statements.statements[3].expr is call_b


def test_stack_probe_materialize_refuses_segment_metadata_without_matching_typed_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(_ss_store(stack_carrier), zero_arg, codegen=codegen),
            CAssignment(_ss_store(stack_carrier), cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ds",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []
    assert len(codegen.cfunc.statements.statements) == 4


def test_stack_probe_materialize_preserves_typed_ss_pickup_across_call_and_global_store_noise():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ds_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        codegen=codegen,
    )
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ax_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_a = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_20"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_b = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_slot = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    setup_call = CExpressionStatement(CFunctionCall("settextrows", SimpleNamespace(name="settextrows"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)

    ss_base = structured_c.CBinaryOp(
        "Shl",
        ss_reg,
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    ds_store = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ds_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(2978, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    typed_arg_store = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            ss_base,
            structured_c.CBinaryOp(
                "Sub",
                carrier_a,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    metadata_lo = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", ss_base, carrier_b, codegen=codegen),
        codegen=codegen,
    )
    metadata_hi = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            carrier_b,
            structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(ax_reg, cs_reg, codegen=codegen),
            setup_call,
            CAssignment(carrier_a, structured_c.CUnaryOp("Reference", stack_slot, codegen=codegen), codegen=codegen),
            CAssignment(ds_store, ax_reg, codegen=codegen),
            CAssignment(typed_arg_store, zero_arg, codegen=codegen),
            CAssignment(
                carrier_b,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_a,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(-2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(metadata_lo, cs_reg, codegen=codegen),
            CAssignment(
                metadata_hi,
                structured_c.CBinaryOp(
                    "Shr",
                    cs_reg,
                    structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(setup_call.expr): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1200,
            return_addr=0x4014,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4015,
            target_addr=0x1544,
            return_addr=0x4018,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(call.args, [zero_arg])


def test_stack_probe_materialize_rebinds_stale_summary_node_ids_by_callsite_addr():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], tags={"ins_addr": 0x4010}, codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], tags={"ins_addr": 0x4012}, codegen=codegen)
    probe = CExpressionStatement(probe_call, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(_ss_store(stack_carrier), zero_arg, codegen=codegen),
            CAssignment(_ss_store(stack_carrier), cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        0xDEAD: CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        0xBEEF: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(call.args, [zero_arg])
    assert id(probe_call) in codegen._inertia_callsite_summaries
    assert id(call) in codegen._inertia_callsite_summaries


def test_stack_probe_materialize_carries_probe_state_across_sibling_cstatements_wrappers():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _wrapper(stmt, addr):
        return CStatements([stmt], addr=addr, codegen=codegen)

    def _ss_store(offset_expr):
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp(
                "Add",
                structured_c.CBinaryOp(
                    "Shl",
                    ss_reg,
                    structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                offset_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        )

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    clear_call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [], codegen=codegen)
    wrapped_probe = _wrapper(CExpressionStatement(probe_call, codegen=codegen), 0x4010)
    wrapped_arg = _wrapper(CAssignment(_ss_store(stack_carrier), zero_arg, codegen=codegen), 0x4011)
    wrapped_meta = _wrapper(CAssignment(_ss_store(stack_carrier), cs_reg, codegen=codegen), 0x4012)
    wrapped_call = _wrapper(CExpressionStatement(clear_call, codegen=codegen), 0x4013)
    codegen.cfunc.statements = CStatements(
        [wrapped_probe, wrapped_arg, wrapped_meta, wrapped_call],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(clear_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(clear_call.args, [zero_arg])


def test_stack_probe_builder_records_only_typed_ss_width_bearing_facts():
    project = _project()
    codegen = _empty_codegen(project)
    probe = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    not_probe = CFunctionCall("callee", SimpleNamespace(name="callee"), [], codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(probe): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(not_probe): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    facts = build_typed_stack_probe_return_facts_8616(codegen)

    assert facts == {
        id(probe): TypedStackProbeReturnFact8616(
            call_node_id=id(probe),
            segment_space="ss",
            width=2,
            carrier_keys=(),
        )
    }


def test_stack_probe_builder_refuses_unknown_width_and_non_ss_summaries():
    project = _project()
    codegen = _empty_codegen(project)
    probe_a = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    probe_b = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    codegen._inertia_callsite_summaries = {
        id(probe_a): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_address_kind="stack",
        ),
        id(probe_b): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1001,
            return_addr=0x4014,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ds",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
    }

    facts = build_typed_stack_probe_return_facts_8616(codegen)

    assert facts == {}


def test_stack_probe_materialized_arg_prunes_dead_stack_address_carriers():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    stack_slot = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_a = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_20"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_b = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="vvar_24"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [zero_arg], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier_a,
                structured_c.CUnaryOp("Reference", stack_slot, codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                carrier_b,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_a,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == [probe, codegen.cfunc.statements.statements[1]]
    assert isinstance(codegen.cfunc.statements.statements[1], CExpressionStatement)
    assert codegen.cfunc.statements.statements[1].expr is call
    assert _args_match(call.args, [zero_arg])


def test_stack_probe_dead_carrier_pruning_keeps_later_reads():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    stack_slot = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_20"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    live_out = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2, name="dx"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [zero_arg], codegen=codegen)
    live_read = CAssignment(live_out, carrier, codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CUnaryOp("Reference", stack_slot, codegen=codegen),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
            live_read,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[1].lhs is carrier
    assert codegen.cfunc.statements.statements[-1] is live_read


def test_stack_probe_prunes_dead_register_identity_stack_carriers_without_temp_names():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    zero_arg = structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)
    stack_slot = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_a = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_b = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["dx"][0], 2),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("clearscreen", SimpleNamespace(name="clearscreen"), [zero_arg], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier_a,
                structured_c.CUnaryOp("Reference", stack_slot, codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                carrier_b,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_a,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(probe.expr): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1001,
            return_addr=0x4012,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements == [probe, codegen.cfunc.statements.statements[1]]
    assert isinstance(codegen.cfunc.statements.statements[1], CExpressionStatement)
    assert codegen.cfunc.statements.statements[1].expr is call


def test_stack_probe_carrier_name_prefers_node_temp_name_over_arch_register_name():
    node = SimpleNamespace(name="vvar_20", variable=SimpleNamespace(name="ax"))

    assert _generic_stack_carrier_name_8616(node) == "vvar_20"
