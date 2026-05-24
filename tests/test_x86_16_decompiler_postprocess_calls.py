from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler import structured_codegen as _scg
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeBottom, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_stack_metadata import _prune_dead_stack_carrier_assignments_8616
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _attach_callsite_summaries_8616,
    _materialize_callsite_stack_arguments_8616,
    _materialize_callsite_prototypes_8616,
    _align_cod_call_names_8616,
    _normalize_call_target_names_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _match_bp_stack_load_8616, _same_c_expression_8616
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


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


class _LoopLikeNode:
    def __init__(self, body):
        self.body = body
        self.statements = None
        self.else_node = None
        self.condition_and_nodes = ()


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(project, statements):
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _empty_codegen(project):
    return _codegen(project, [])


def test_normalize_call_target_names_rewrites_namespaced_callee_target():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_normalize_call_target_names_strips_wrapper_suffix_parens():
    project = _project()
    codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars()", None, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    call = codegen.cfunc.statements.statements[0]
    assert changed is True
    assert call.callee_target == "InitBars"


def test_normalize_call_target_names_rewrites_namespaced_callee_func_name():
    project = _project()
    codegen = _empty_codegen(project)
    callee_func = SimpleNamespace(name="::0x1544::InitBars")
    call = CFunctionCall(None, callee_func, [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert callee_func.name == "InitBars"


def test_normalize_call_target_names_keeps_tail_validation_stable():
    project = _project()
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("::0x1544::InitBars", None, [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_keeps_tail_validation_stable_for_same_addr_sidecar_rename():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    before_codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=before_codegen)
    ret = CReturn(None, codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([call, ret], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = deepcopy(before_codegen)
    changed = _normalize_call_target_names_8616(after_codegen)

    assert changed is True
    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_normalize_call_target_names_prefers_sidecar_label_for_sub_target_without_summary():
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _normalize_call_target_names_8616(codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_attach_callsite_summaries_prefers_sidecar_labels_for_sub_targets(monkeypatch):
    project = _project()
    project._inertia_original_project = SimpleNamespace(
        kb=SimpleNamespace(labels={0x1005D: "_InitMenu"}),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x1005D: "_InitMenu"}),
    )
    project._inertia_original_linear_delta = 0xF010
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else SimpleNamespace(addr=addr, name="sub_104d")
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr: CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x104D,
            return_addr=0x4015,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func.name == "InitMenu"
    assert call.callee_target == "InitMenu"


def test_attach_callsite_summaries_matches_unaddressed_calls_by_target_instead_of_zip_order(monkeypatch):
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4010, 0x4012))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else SimpleNamespace(addr=addr, name={0x1001: "aNchkstk", 0x14A0: "outp"}.get(addr, f"sub_{addr:x}"))
        )
    )
    codegen = _empty_codegen(project)
    call_outp = CFunctionCall("outp", SimpleNamespace(addr=0x14A0, name="outp"), [], codegen=codegen)
    call_probe = CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements([call_outp, call_probe], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    def _summary_for_callsite(_function, callsite_addr):
        if callsite_addr == 0x4010:
            return CallsiteSummary8616(
                callsite_addr=0x4010,
                target_addr=0x1001,
                return_addr=0x4011,
                kind="near",
                arg_count=0,
                arg_widths=(),
                stack_cleanup=0,
                return_register="ax",
                return_used=True,
                stack_probe_helper=True,
            )
        return CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x14A0,
            return_addr=0x4015,
            kind="near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        )

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _summary_for_callsite,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("speaker", "outp")),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call_probe.callee_target == "aNchkstk"
    assert call_outp.callee_target == "outp"
    assert codegen._inertia_callsite_summaries[id(call_probe)].target_addr == 0x1001
    assert codegen._inertia_callsite_summaries[id(call_outp)].target_addr == 0x14A0


def test_align_cod_call_names_rewrites_unknown_call_by_source_order(monkeypatch):
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(
            call_names=("aNchkstk", "InitBars", "InitMenu", "RunMenu")
        ),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is True
    assert calls[2].callee_func.name == "InitMenu"
    assert calls[2].callee_target == "InitMenu"


def test_align_cod_call_names_does_not_override_known_repeated_calls_without_unknown_nodes(monkeypatch):
    project = _project()
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1001, name="aNchkstk"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1040, name="DrawBar"), [], codegen=codegen),
        CFunctionCall("DrawBar", SimpleNamespace(addr=0x1041, name="DrawBar"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(calls, addr=0x4010, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_names=("aNchkstk", "DrawBar", "DrawTime")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is False
    assert calls[2].callee_func.name == "DrawBar"
    assert calls[2].callee_target == "DrawBar"


def test_align_cod_call_names_uses_rebased_original_function_metadata(monkeypatch):
    project = _project()
    original_project = _project()
    project._inertia_original_project = original_project
    project._inertia_original_linear_delta = 0xF010
    project._inertia_lst_metadata = SimpleNamespace(cod_path="/tmp/missing.cod", cod_proc_kinds={})
    original_project._inertia_lst_metadata = SimpleNamespace(
        cod_path="/tmp/fake.cod",
        cod_proc_kinds={0x10010: "NEAR"},
    )
    original_project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(addr=addr, name="main") if addr == 0x10010 else None
        )
    )
    codegen = _empty_codegen(project)
    calls = [
        CFunctionCall("InitBars", SimpleNamespace(addr=0x1040, name="InitBars"), [], codegen=codegen),
        CFunctionCall("sub_104d", SimpleNamespace(addr=0x104D, name="sub_104d"), [], codegen=codegen),
        CFunctionCall("RunMenu", SimpleNamespace(addr=0x1060, name="RunMenu"), [], codegen=codegen),
    ]
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=CStatements(calls, addr=0x1000, codegen=codegen),
        body=None,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.extract_cod_proc_metadata",
        lambda _path, _name, _kind: SimpleNamespace(call_names=("InitBars", "InitMenu", "RunMenu")),
    )

    changed = _align_cod_call_names_8616(project, codegen)

    assert changed is True
    assert calls[1].callee_func.name == "InitMenu"
    assert calls[1].callee_target == "InitMenu"


def test_materialize_callsite_stack_arguments_rewrites_preceding_stack_store_into_call_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
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
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
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
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    only_stmt = codegen.cfunc.statements.statements[0]
    assert isinstance(only_stmt, CExpressionStatement)
    assert _args_match(only_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_resolves_register_carrier_before_materializing():
    project = _project()
    before_codegen = _empty_codegen(project)
    structured_c = _scg.c
    ax = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=before_codegen,
    )
    computed_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0BAA, SimTypeShort(False), codegen=before_codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=before_codegen),
        codegen=before_codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Mul",
                structured_c.CVariable(
                    SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
                    codegen=before_codegen,
                ),
                structured_c.CConstant(16, SimTypeShort(False), codegen=before_codegen),
                codegen=before_codegen,
            ),
            structured_c.CBinaryOp(
                "Add",
                structured_c.CUnaryOp(
                    "Reference",
                    structured_c.CVariable(
                        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                        variable_type=SimTypeShort(False),
                        codegen=before_codegen,
                    ),
                    codegen=before_codegen,
                ),
                structured_c.CConstant(-2, SimTypeShort(False), codegen=before_codegen),
                codegen=before_codegen,
            ),
            codegen=before_codegen,
        ),
        codegen=before_codegen,
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(ax, computed_arg, codegen=before_codegen),
            CAssignment(outgoing, ax, codegen=before_codegen),
            CExpressionStatement(call, codegen=before_codegen),
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    before_codegen._inertia_callsite_summaries = {
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
        )
    }

    after_codegen = deepcopy(before_codegen)
    after_call = after_codegen.cfunc.statements.statements[2].expr
    after_codegen._inertia_callsite_summaries = {
        id(after_call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }
    changed = _materialize_callsite_stack_arguments_8616(project, after_codegen)

    assert changed is True
    only_stmt = after_codegen.cfunc.statements.statements[1]
    assert isinstance(only_stmt, CExpressionStatement)
    assert len(only_stmt.expr.args) == 1
    actual_fp = _expr_fingerprint(only_stmt.expr.args[0], project)
    # The new materialization preserves full segment addressing in expressions.
    # The computed_arg (Add(const:0xBAA, const:2)) is now embedded within
    # the segment-relative address rather than extracted standalone.
    assert actual_fp.startswith("Add(Mul(reg:")

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )
    assert diff["changed"] is False


def test_materialize_callsite_stack_arguments_infers_one_arg_after_stack_probe_helper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
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
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert _args_match(only_call_stmt.expr.args, [arg_slot])
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_infers_multi_args_after_stack_probe_helper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
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
    outgoing_b = structured_c.CUnaryOp(
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
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
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
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
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
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert _args_match(only_call_stmt.expr.args, [arg_slot_b, arg_slot_a])
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_keeps_generic_ss_backtracking_without_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    frequency = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    sp_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["sp"][0], 2, name="sp"),
        codegen=codegen,
    )

    def _ss_sp_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        sp_reg,
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_sp_store(-4, structured_c.CConstant(97, SimTypeShort(False), codegen=codegen)),
            _ss_sp_store(-2, frequency),
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
            target_addr=0x2400,
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

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 2
    assert _same_c_expression_8616(only_call_stmt.expr.args[0], frequency)
    assert only_call_stmt.expr.args[1].value == 97


def test_materialize_callsite_stack_arguments_accepts_virtual_dirty_ss_carrier_without_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    frequency = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="frequency", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_dirty_store(-4, structured_c.CConstant(97, SimTypeShort(False), codegen=codegen)),
            _ss_dirty_store(-2, frequency),
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
            target_addr=0x2400,
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

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    only_call_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 2
    assert _same_c_expression_8616(only_call_stmt.expr.args[0], frequency)
    assert only_call_stmt.expr.args[1].value == 97


def test_materialize_callsite_stack_arguments_matches_same_register_with_renamed_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier_def = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_use = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(carrier_def, row_index, codegen=codegen),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    carrier_use,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
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
    assert len(codegen.cfunc.statements.statements) == 3
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 1
    arg = only_call_stmt.expr.args[0]
    assert isinstance(getattr(arg, "variable", None), SimStackVariable)
    assert isinstance(getattr(getattr(arg, "variable", None), "offset", None), int)
    assert not any(
        (
            getattr(getattr(node, "variable", None), "name", None)
            or getattr(node, "name", None)
        ) in {"ax", "ax_7"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_walks_same_register_chain_across_shorter_prefixes():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_0 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_9 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(ax_0, row_index, codegen=codegen),
            CAssignment(ax_7, ax_0, codegen=codegen),
            CAssignment(
                ax_9,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_7,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_9,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
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
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (
            getattr(getattr(node, "variable", None), "name", None)
            or getattr(node, "name", None)
        ) in {"ax", "ax_7", "ax_9"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_rewrites_nested_indexed_pointer_offsets_to_named_stack_vars():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    def _work_offset(index_value: int):
        return structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                structured_c.CIndexedVariable(
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(index_value, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            _ss_dirty_store(-4, _work_offset(6)),
            _ss_dirty_store(-2, _work_offset(8)),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
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

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    arg_nodes = [(arg, *_iter_c_nodes_deep_8616(arg)) for arg in final_stmt.expr.args]
    stack_offsets = {
        getattr(getattr(node, "variable", None), "offset", None)
        for nodes in arg_nodes
        for node in nodes
        if isinstance(getattr(node, "variable", None), SimStackVariable)
    }
    assert -3 in stack_offsets
    assert -2 in stack_offsets
    assert not any(
        (
            getattr(getattr(node, "variable", None), "name", None)
            or getattr(node, "name", None)
        ) == "s_6"
        for nodes in arg_nodes
        for node in nodes
    )


def test_materialize_callsite_stack_arguments_falls_back_to_recent_dirty_value_carrier():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_6 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                CDirtyExpression("vvar_90", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        row_index,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                ax_7,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_6,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_7,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
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
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    assert len(only_call_stmt.expr.args) == 1
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (
            getattr(getattr(node, "variable", None), "name", None)
            or getattr(node, "name", None)
        ) in {"ax_6", "ax_7"}
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_prefers_named_dirty_value_carrier_over_placeholder():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    row_index = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    placeholder = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_fffa_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    ax_6 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    def _ss_dirty_store(displacement: int, rhs):
        return CAssignment(
            structured_c.CUnaryOp(
                "Dereference",
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        ss_reg,
                        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CBinaryOp(
                        "Sub",
                        CDirtyExpression("vvar_85", codegen=codegen),
                        structured_c.CConstant(-displacement, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            rhs,
            codegen=codegen,
        )

    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DemoCall", SimpleNamespace(name="DemoCall"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                CDirtyExpression("vvar_91", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        row_index,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                CDirtyExpression("vvar_92", codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        placeholder,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                ax_7,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_6,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _ss_dirty_store(
                -2,
                structured_c.CBinaryOp(
                    "Add",
                    ax_7,
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x2400,
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
    only_call_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(only_call_stmt, CExpressionStatement)
    arg = only_call_stmt.expr.args[0]
    assert any(_same_c_expression_8616(node, row_index) for node in (arg, *_iter_c_nodes_deep_8616(arg)))
    assert not any(
        (
            getattr(getattr(node, "variable", None), "name", None)
            or getattr(node, "name", None)
        ) == "s_fffa_2"
        for node in (arg, *_iter_c_nodes_deep_8616(arg))
    )


def test_materialize_callsite_stack_arguments_accepts_vvar_carrier_store_with_typed_probe_fact():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(outgoing, arg_slot, codegen=codegen),
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
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_prefers_typed_probe_stores_over_push_arg_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(outgoing, arg_slot, codegen=codegen),
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
            push_arg_sources=(("imm", 3),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_prefers_generic_probe_stores_over_push_arg_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(outgoing, arg_slot, codegen=codegen),
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
            helper_return_state="unknown",
            helper_return_space=None,
            helper_return_width=None,
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
            push_arg_sources=(("imm", 3),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_rematerializes_typed_probe_call_even_with_existing_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    outgoing_base = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    store = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Sub",
            carrier,
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    ds_expr = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(name="DrawBar"),
        [
            CFunctionCall("SEG_PTR", None, [ds_expr, structured_c.CConstant(3, SimTypeShort(False), codegen=codegen)], codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CUnaryOp("Reference", outgoing_base, codegen=codegen),
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(store, arg_slot, codegen=codegen),
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
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_allows_temp_carrier_between_store_and_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_a = structured_c.CUnaryOp(
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
    outgoing_b = structured_c.CUnaryOp(
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
                        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
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
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing_a, arg_slot_a, codegen=codegen),
            CAssignment(outgoing_b, arg_slot_b, codegen=codegen),
            CAssignment(
                carrier,
                structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0x200, SimTypeShort(False), codegen=codegen),
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
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

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot_b, arg_slot_a])


def test_materialize_callsite_stack_arguments_overrides_conflicting_bp_slot_existing_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
        wrong_arg1.variable: wrong_arg1,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_respects_push_sources_without_positive_alias_around():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expected_arg0 = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expected_arg1 = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        wrong_arg0.variable: wrong_arg0,
        wrong_arg1.variable: wrong_arg1,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [expected_arg0, expected_arg1])


def test_materialize_callsite_stack_arguments_overrides_stack_base_existing_arg_from_bp_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CIndexedVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        structured_c.CConstant(6, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_overrides_plain_stack_base_existing_arg_from_bp_push_sources():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    i_parent = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    i_value = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg0 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iMaxLevel", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    wrong_arg1 = structured_c.CVariable(
        structured_c.CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("SwapBars", SimpleNamespace(name="SwapBars"), [wrong_arg0, wrong_arg1], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        i_parent.variable: i_parent,
        i_value.variable: i_value,
        wrong_arg0.variable: wrong_arg0,
    }
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(call, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -4), ("bp", -2)),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [i_parent, i_value])


def test_materialize_callsite_stack_arguments_scans_past_value_assignments_between_stores():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_65"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_after = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_7 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_7"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ax_8 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_8"),
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
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_a,
                codegen=codegen,
            ),
            CAssignment(
                carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(ax_7, structured_c.CConstant(3, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                ax_8,
                structured_c.CBinaryOp(
                    "Shl",
                    ax_7,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_b,
                codegen=codegen,
            ),
            CAssignment(
                carrier_after,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_next,
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
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

    assert changed is True
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    assert ax_7 in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]
    assert ax_8 in [getattr(stmt, "lhs", None) for stmt in codegen.cfunc.statements.statements]


def test_materialize_callsite_stack_arguments_upgrades_undercounted_probe_summary():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot_a = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_slot_b = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_65"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_after = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cx"][0], 2, name="vvar_72"),
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
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_a,
                codegen=codegen,
            ),
            CAssignment(
                carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                arg_slot_b,
                codegen=codegen,
            ),
            CAssignment(
                carrier_after,
                structured_c.CBinaryOp(
                    "Sub",
                    carrier_next,
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
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
    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 2
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2, 2)


def test_materialize_callsite_stack_arguments_carries_probe_evidence_into_loop_body():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                stack_carrier,
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)
    loop_body = CStatements(
        [
            CAssignment(outgoing, arg_slot, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4020,
        codegen=codegen,
    )
    loop = CForLoop(None, None, None, loop_body, codegen=codegen)
    codegen.cfunc.statements = CStatements([probe, loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(loop_body.statements) == 1
    final_stmt = loop_body.statements[0]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 1
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == (2,)


def test_materialize_callsite_stack_arguments_does_not_promote_segment_carrier_as_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name="cs"),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_stack_arguments_skips_segment_metadata_store():
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
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stack_carrier_next = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["bx"][0], 2, name="vvar_33"),
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
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        stack_carrier,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                zero_arg,
                codegen=codegen,
            ),
            CAssignment(
                stack_carrier_next,
                structured_c.CBinaryOp(
                    "Sub",
                    stack_carrier,
                    structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                _ss_store(
                    structured_c.CBinaryOp(
                        "Sub",
                        stack_carrier_next,
                        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                ),
                cs_reg,
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
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


def test_materialize_callsite_stack_arguments_refuses_unnamed_segment_register_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    cs_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["cs"][0], 2, name=None),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name=None),
        codegen=codegen,
    )
    stack_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            stack_carrier,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("RunMenu", SimpleNamespace(name="RunMenu"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            probe,
            CAssignment(outgoing, cs_reg, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert call.args == []


def test_materialize_callsite_prototypes_keeps_materialized_stack_probe_args_visible():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    callee = SimpleNamespace(name="DrawBar", prototype=None, is_prototype_guessed=False)
    call = CFunctionCall("DrawBar", callee, [arg_slot], codegen=codegen)
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_prototypes_8616(project, codegen)

    assert changed is False
    assert getattr(callee, "prototype", None) is None


def test_materialize_callsite_stack_arguments_clears_known_zero_arg_helper_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    call = CFunctionCall(
        "clock",
        SimpleNamespace(name="clock", prototype=None, is_prototype_guessed=False),
        [
            structured_c.CConstant(45, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(14, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([CExpressionStatement(call, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert call.args == []
    assert codegen._inertia_callsite_summaries[id(call)].arg_count == 0
    assert codegen._inertia_callsite_summaries[id(call)].arg_widths == ()


def test_materialize_callsite_stack_arguments_handles_tuple_statement_blocks():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
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
    probe = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        (
            probe,
            CAssignment(outgoing, arg_slot, codegen=codegen),
            call,
        ),
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {}

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_call = codegen.cfunc.statements.statements[1]
    assert isinstance(final_call, CFunctionCall)
    assert _args_match(final_call.args, [arg_slot])


def test_materialize_callsite_stack_arguments_accepts_ss_shift_linear_store_shape():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                structured_c.CVariable(
                    SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
                    variable_type=SimTypeShort(False),
                    codegen=codegen,
                ),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [probe, CAssignment(outgoing, arg_slot, codegen=codegen), CExpressionStatement(call, codegen=codegen)],
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
        ),
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    final_stmt = codegen.cfunc.statements.statements[1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert _args_match(final_stmt.expr.args, [arg_slot])


def test_materialize_callsite_stack_arguments_refuses_dirty_probe_offset_store_shape():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c
    arg_slot = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ss_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ss"][0], 2, name="ss"),
        codegen=codegen,
    )
    outgoing = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CBinaryOp(
                "Shl",
                ss_reg,
                structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            structured_c.CBinaryOp(
                "Sub",
                CDirtyExpression("probe_ret", codegen=codegen),
                structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    probe = CExpressionStatement(CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen), codegen=codegen)
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [probe, CAssignment(outgoing, arg_slot, codegen=codegen), CExpressionStatement(call, codegen=codegen)],
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
        helper_return_width=2,
        helper_return_address_kind="stack",
            helper_return_state="stack_address",
            helper_return_space="ss",
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
    assert len(codegen.cfunc.statements.statements) == 3


def test_materialize_callsite_stack_arguments_extracts_inline_store_before_call_from_cstatements_wrapper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
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
            ),
            rhs_expr,
            codegen=codegen,
        )

    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    drawbar_call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)
    irow2 = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CStatements([CExpressionStatement(probe_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow2), CExpressionStatement(drawbar_call, codegen=codegen)], codegen=codegen),
            CStatements([_ss_store(irow1), CExpressionStatement(drawtime_call, codegen=codegen)], codegen=codegen),
        ],
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
        id(drawbar_call): CallsiteSummary8616(
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
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
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
    wrapped_drawbar = codegen.cfunc.statements.statements[1]
    wrapped_drawtime = codegen.cfunc.statements.statements[2]
    assert isinstance(wrapped_drawbar, CStatements)
    assert isinstance(wrapped_drawtime, CStatements)
    assert len(wrapped_drawbar.statements) == 1
    assert len(wrapped_drawtime.statements) == 1
    assert isinstance(wrapped_drawbar.statements[0], CExpressionStatement)
    assert isinstance(wrapped_drawtime.statements[0], CExpressionStatement)
    assert _args_match(wrapped_drawbar.statements[0].expr.args, [irow2])
    assert _args_match(wrapped_drawtime.statements[0].expr.args, [irow1])


def test_materialize_callsite_stack_arguments_consumes_repeated_value_carrier_assignments():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_31"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    first_arg = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4C, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    call = CFunctionCall("Swaps", SimpleNamespace(name="Swaps"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(carrier, second_arg, codegen=codegen),
                    CAssignment(carrier, first_arg, codegen=codegen),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1794,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        )
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert len(wrapped.statements) == 1
    assert isinstance(wrapped.statements[0], CExpressionStatement)
    assert len(wrapped.statements[0].expr.args) == 2
    assert wrapped.statements[0].expr.args[0].callee_target == "SEG_PTR"
    assert wrapped.statements[0].expr.args[1].callee_target == "SEG_PTR"
    first_offset = wrapped.statements[0].expr.args[0].args[1]
    second_offset = wrapped.statements[0].expr.args[1].args[1]
    assert any(getattr(node, "value", None) == 0x0B4C for node in _iter_c_nodes_deep_8616(first_offset))
    assert any(getattr(node, "value", None) == 8 for node in _iter_c_nodes_deep_8616(first_offset))
    assert any(getattr(node, "value", None) == 0x0B4C for node in _iter_c_nodes_deep_8616(second_offset))
    assert any(getattr(node, "value", None) == 4 for node in _iter_c_nodes_deep_8616(second_offset))


def test_materialize_callsite_stack_arguments_consumes_trailing_store_after_previous_call_wrapper():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
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
            ),
            rhs_expr,
            codegen=codegen,
        )

    irow = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRowTmp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_82"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_value = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(0x0B4A, SimTypeShort(False), codegen=codegen),
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    probe_call = CFunctionCall("aNchkstk", SimpleNamespace(name="aNchkstk"), [], codegen=codegen)
    drawbar_call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [irow], codegen=codegen)
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements([CExpressionStatement(probe_call, codegen=codegen)], codegen=codegen),
            CStatements(
                [
                    CExpressionStatement(drawbar_call, codegen=codegen),
                    CAssignment(carrier, carrier_value, codegen=codegen),
                    _ss_store(irow),
                ],
                codegen=codegen,
            ),
            CExpressionStatement(drawtime_call, codegen=codegen),
        ],
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
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
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
    assert _args_match(drawtime_call.args, [irow])


def test_materialize_callsite_stack_arguments_handles_assignment_wrapped_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    def _ss_store(rhs_expr):
        return CAssignment(
            structured_c.CUnaryOp(
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
            ),
            rhs_expr,
            codegen=codegen,
        )

    irow = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRowTmp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    result_var = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ax_5"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    drawtime_call = CFunctionCall("DrawTime", SimpleNamespace(name="DrawTime"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            _ss_store(irow),
            CAssignment(result_var, drawtime_call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(drawtime_call): CallsiteSummary8616(
            callsite_addr=0x4016,
            target_addr=0x1550,
            return_addr=0x4019,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register="ax",
            return_used=True,
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    assert _args_match(drawtime_call.args, [irow])


def test_materialize_callsite_stack_arguments_consumes_inline_stack_placeholder_assignment_before_call():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    vvar_2 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(vvar_2, irow1, codegen=codegen),
                    CAssignment(
                        outgoing_slot,
                        CDirtyExpression(SimpleNamespace(varid=2, name="vvar_2"), codegen=codegen),
                        codegen=codegen,
                    ),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
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
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert isinstance(wrapped.statements[-1], CExpressionStatement)
    assert len(wrapped.statements[-1].expr.args) == 1
    arg0 = wrapped.statements[-1].expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "iRow1"


def test_materialize_callsite_stack_arguments_prefers_bp_push_source_metadata_for_real_arg():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_bp0 = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="arg_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("DrawBar", SimpleNamespace(name="DrawBar"), [], codegen=codegen)

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(outgoing_bp0, irow1, codegen=codegen),
                    CAssignment(outgoing_slot, outgoing_bp0, codegen=codegen),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
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
            push_arg_sources=(("bp", 4),),
        ),
    }

    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is True
    wrapped = codegen.cfunc.statements.statements[0]
    assert isinstance(wrapped, CStatements)
    assert isinstance(wrapped.statements[-1], CExpressionStatement)
    assert len(wrapped.statements[-1].expr.args) == 1
    arg0 = wrapped.statements[-1].expr.args[0]
    assert getattr(getattr(arg0, "variable", None), "name", None) == "iRow1"


def test_callsite_stats_count_materialized_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    irow1 = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    vvar_2 = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_slot = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="s_2_2_2_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "DrawBar",
        SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CStatements(
                [
                    CAssignment(vvar_2, irow1, codegen=codegen),
                    CAssignment(
                        outgoing_slot,
                        CDirtyExpression(SimpleNamespace(varid=2, name="vvar_2"), codegen=codegen),
                        codegen=codegen,
                    ),
                    CExpressionStatement(call, codegen=codegen),
                ],
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
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

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    assert _normalize_call_target_names_8616(codegen) is False

    assert _normalize_call_target_names_8616(codegen) is False
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.callsite_count == 1
    assert stats.call_target_fact_count == 1
    assert stats.call_target_materialized_count == 1
    assert stats.call_arg_fact_count == 1
    assert stats.call_arg_materialized_count == 1
    assert stats.known_prototype_arg_mismatch_count == 0


def test_materialize_callsite_stack_arguments_normalizes_bp_slot_values_and_pointer_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    local_i = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_1", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    local_base = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="s_4", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_first = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    outgoing_second = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="s_8", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bp_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp(
            "Add",
            structured_c.CUnaryOp("Reference", local_base, codegen=codegen),
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    call = CFunctionCall(
        "Swaps",
        SimpleNamespace(addr=0x1544, name="Swaps", block_addrs_set={0x1544}),
        [],
        codegen=codegen,
    )

    codegen.cfunc.statements = CStatements(
        [
            CAssignment(local_i, structured_c.CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(outgoing_first, structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen), codegen=codegen),
            CAssignment(
                outgoing_second,
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CBinaryOp(
                        "Shl",
                        bp_load,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
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
        id(call): CallsiteSummary8616(
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

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_stmt = codegen.cfunc.statements.statements[-1]
    assert isinstance(final_stmt, CExpressionStatement)
    assert len(final_stmt.expr.args) == 2
    assert final_stmt.expr.args[0].callee_target == "SEG_PTR"
    assert final_stmt.expr.args[1].callee_target == "SEG_PTR"
    offset_expr = final_stmt.expr.args[1].args[1]
    assert not any(
        _match_bp_stack_load_8616(node, project) is not None
        for node in _iter_c_nodes_deep_8616(offset_expr)
    )

    assert _normalize_call_target_names_8616(codegen) is False
    stats = codegen._inertia_callsite_materialization_stats
    assert stats.call_arg_materialized_count == 2
    assert stats.bp_slot_arg_value_normalized_count >= 1
    assert stats.pointer_arg_materialized_count == 2
    assert stats.push_order_reversed_count >= 1


def test_materialize_callsite_stack_arguments_normalizes_existing_pointer_helper_args():
    project = _project()
    codegen = _empty_codegen(project)
    structured_c = _scg.c

    ds_reg = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ds"][0], 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    named_local = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    other_local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    offset_carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="ir_9"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "Swaps",
        SimpleNamespace(addr=0x1544, name="Swaps", block_addrs_set={0x1544}),
        [
            CFunctionCall(
                "SEG_PTR",
                None,
                [
                    ds_reg,
                    structured_c.CBinaryOp(
                        "Add",
                        offset_carrier,
                        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    ),
                ],
                codegen=codegen,
            ),
            CFunctionCall("SEG_PTR", None, [ds_reg, other_local], codegen=codegen),
        ],
        codegen=codegen,
    )

    codegen.cfunc.variables_in_use = {
        named_local.variable: named_local,
        other_local.variable: other_local,
    }
    codegen.cfunc.unified_local_vars = {
        named_local.variable: {(named_local, named_local.variable_type)},
        other_local.variable: {(other_local, other_local.variable_type)},
    }
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(offset_carrier, named_local, codegen=codegen),
            CExpressionStatement(call, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
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

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True

    final_call = codegen.cfunc.statements.statements[1].expr
    first_offset = final_call.args[0].args[1]
    assert "ir_" not in _expr_fingerprint(first_offset, project)


def test_tail_validation_call_fingerprint_prefers_resolved_function_addr_for_named_target():
    project = _project()
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: SimpleNamespace(addr=0x104D, name="InitMenu")
            if name == "InitMenu"
            else None
        )
    )
    codegen = _empty_codegen(project)
    call = CFunctionCall("InitMenu", None, [], codegen=codegen)

    fingerprint = _expr_fingerprint(call, project)

    assert fingerprint == "call:addr:0x104d()"


def test_tail_validation_stays_stable_for_unknown_to_named_call_when_callsite_matches():
    project = _project()
    function = SimpleNamespace(get_call_sites=lambda: (0x4012,))
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr=None, name=None, create=False: (
                function
                if addr == 0x4010
                else SimpleNamespace(addr=0x104D, name="InitMenu")
                if name == "InitMenu"
                else None
            )
        )
    )
    before_codegen = _empty_codegen(project)
    before_call = CFunctionCall(None, None, [], codegen=before_codegen)
    before_codegen.cfunc.statements = CStatements([before_call, CReturn(None, codegen=before_codegen)], addr=0x4010, codegen=before_codegen)
    before_codegen.cfunc.body = before_codegen.cfunc.statements

    after_codegen = _empty_codegen(project)
    after_call = CFunctionCall("InitMenu", None, [], codegen=after_codegen)
    after_codegen.cfunc.statements = CStatements([after_call, CReturn(None, codegen=after_codegen)], addr=0x4010, codegen=after_codegen)
    after_codegen.cfunc.body = after_codegen.cfunc.statements

    diff = compare_x86_16_tail_validation_summaries(
        collect_x86_16_tail_validation_summary(project, before_codegen),
        collect_x86_16_tail_validation_summary(project, after_codegen),
    )

    assert diff["changed"] is False


def test_prune_dead_stack_carriers_only_recurses_into_plain_statement_blocks():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loop_body = CStatements(
        [
            CAssignment(
                carrier,
                structured_c.CUnaryOp("Reference", local_slot, codegen=codegen),
                codegen=codegen,
            ),
            CExpressionStatement(CFunctionCall("Inner", SimpleNamespace(name="Inner"), [], codegen=codegen), codegen=codegen),
        ],
        addr=0x4020,
        codegen=codegen,
    )
    loop_like = _LoopLikeNode(loop_body)
    prefix = CStatements([], addr=0x4000, codegen=codegen)
    suffix = CStatements([CReturn(None, codegen=codegen)], addr=0x4030, codegen=codegen)
    root = CStatements([prefix, loop_like, suffix], addr=0x4010, codegen=codegen)
    loop_like.statements = root.statements

    codegen._inertia_enable_safe_dead_carrier_prune = True
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_target_fact_count=1,
        call_target_materialized_count=1,
        call_arg_fact_count=1,
        call_arg_materialized_count=1,
    )
    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is True
    assert root.statements[1] is loop_like
    assert len(loop_body.statements) == 1
    assert isinstance(loop_body.statements[0], CExpressionStatement)


def test_prune_dead_stack_carriers_disabled_by_default():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(carrier, structured_c.CUnaryOp("Reference", local_slot, codegen=codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is False
    assert len(root.statements) == 2


def test_prune_dead_stack_carriers_refuses_without_materialization_evidence():
    project = _project()
    codegen = _DummyCodegen(project)
    structured_c = _scg.c
    local_slot = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = structured_c.CVariable(
        SimRegisterVariable(project.arch.registers["ax"][0], 2, name="vvar_11"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    root = CStatements(
        [
            CAssignment(carrier, structured_c.CUnaryOp("Reference", local_slot, codegen=codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )

    changed = _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen)

    assert changed is False
    assert len(root.statements) == 2
