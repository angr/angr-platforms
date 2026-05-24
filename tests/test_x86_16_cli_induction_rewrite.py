from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CITE,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CIndexedVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia_decompiler.cli_access_profiles import AccessTraitStrideEvidence, build_access_trait_evidence_profiles, infer_induction_variable
from inertia_decompiler.cli_induction_rewrite import rewrite_for_loop_conditions_from_access_traits

from angr_platforms.X86_16.arch_86_16 import Arch86_16


class _DummyCodegen:
    def __init__(self, project):
        self.project = project
        self.cstyle_null_cmp = False
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack_var(offset: int, codegen, *, name: str):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def _iter_c_nodes_deep(node):
    if node is None:
        return
    yield node
    if isinstance(node, CStatements):
        for stmt in node.statements:
            yield from _iter_c_nodes_deep(stmt)
        return
    for attr in ("lhs", "rhs", "operand", "expr", "variable", "index", "condition", "initializer", "iterator", "cond", "iftrue", "iffalse", "body"):
        child = getattr(node, attr, None)
        if child is None:
            continue
        yield from _iter_c_nodes_deep(child)


def _traits_for_stack_index(index_key):
    return {
        0x4010: {
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "induction_evidence": {
                ("induction_like", "expr", None, index_key, 1, 0, 2): AccessTraitStrideEvidence(
                    segment="expr",
                    base_key=None,
                    index_key=index_key,
                    stride=1,
                    offset=0,
                    width=2,
                    count=3,
                    kind="induction_like",
                )
            },
            "stride_evidence": {},
            "member_evidence": {},
            "array_evidence": {},
        }
    }


def test_cli_induction_rewrite_simplifies_boolified_for_condition_from_stable_stack_evidence():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    loop_index = _stack_var(0, codegen, name="i")
    stack_base = _stack_var(-4, codegen, name="s_4")
    index_expr = CIndexedVariable(
        CUnaryOp("Reference", stack_base, codegen=codegen),
        _const(4, codegen),
        codegen=codegen,
    )
    deref_index = CUnaryOp(
        "Dereference",
        CTypeCast(SimTypeShort(False), SimTypeShort(False), index_expr, codegen=codegen),
        codegen=codegen,
    )
    cond = CBinaryOp("CmpGT", deref_index, _const(0, codegen), codegen=codegen)
    loop = CForLoop(
        CAssignment(loop_index, _const(1, codegen), codegen=codegen),
        CUnaryOp("Not", CITE(cond, _const(0, codegen), _const(1, codegen), codegen=codegen), codegen=codegen),
        CAssignment(loop_index, CBinaryOp("Add", loop_index, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    project._inertia_access_traits = _traits_for_stack_index(("stack", "bp", 0, 0x4010))

    changed = rewrite_for_loop_conditions_from_access_traits(
        project,
        codegen,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        infer_induction_variable=infer_induction_variable,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

    assert changed is True
    assert loop.condition is cond


def test_cli_induction_rewrite_refuses_boolified_for_condition_without_stable_evidence():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    loop_index = _stack_var(0, codegen, name="i")
    cond = CBinaryOp("CmpGT", loop_index, _const(0, codegen), codegen=codegen)
    loop = CForLoop(
        CAssignment(loop_index, _const(1, codegen), codegen=codegen),
        CUnaryOp("Not", CITE(cond, _const(0, codegen), _const(1, codegen), codegen=codegen), codegen=codegen),
        CAssignment(loop_index, CBinaryOp("Add", loop_index, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    project._inertia_access_traits = {
        0x4010: {
            "base_const": {},
            "base_stride": {},
            "repeated_offsets": {},
            "repeated_offset_widths": {},
            "base_stride_widths": {},
            "induction_evidence": {
                ("induction_like", "expr", None, ("stack", "bp", 0, 0x4010), 1, 0, 2): AccessTraitStrideEvidence(
                    segment="expr",
                    base_key=None,
                    index_key=("stack", "bp", 0, 0x4010),
                    stride=1,
                    offset=0,
                    width=2,
                    count=1,
                    kind="induction_like",
                ),
                ("induction_like", "expr", None, ("stack", "bp", 0, 0x4010), 2, 0, 2): AccessTraitStrideEvidence(
                    segment="expr",
                    base_key=None,
                    index_key=("stack", "bp", 0, 0x4010),
                    stride=2,
                    offset=0,
                    width=2,
                    count=1,
                    kind="induction_like",
                ),
            },
            "stride_evidence": {},
            "member_evidence": {},
            "array_evidence": {},
        }
    }

    changed = rewrite_for_loop_conditions_from_access_traits(
        project,
        codegen,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        infer_induction_variable=infer_induction_variable,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

    assert changed is False
    assert isinstance(loop.condition, CUnaryOp)


def test_cli_induction_rewrite_simplifies_double_negated_for_condition_from_stable_evidence():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    loop_index = _stack_var(0, codegen, name="i")
    cond = CBinaryOp("CmpGT", loop_index, _const(0, codegen), codegen=codegen)
    loop = CForLoop(
        CAssignment(loop_index, _const(1, codegen), codegen=codegen),
        CUnaryOp("Not", CUnaryOp("Not", cond, codegen=codegen), codegen=codegen),
        CAssignment(loop_index, CBinaryOp("Add", loop_index, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    project._inertia_access_traits = _traits_for_stack_index(("stack", "bp", 0, 0x4010))

    changed = rewrite_for_loop_conditions_from_access_traits(
        project,
        codegen,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        infer_induction_variable=infer_induction_variable,
        iter_c_nodes_deep=_iter_c_nodes_deep,
    )

    assert changed is True
    assert loop.condition is cond
