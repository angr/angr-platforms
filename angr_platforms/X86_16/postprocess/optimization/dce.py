from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Conservative dead-code elimination.
Only removes plain local/temp assignments proven unread by backward liveness.
Unknown cases are refused and preserved.

Forbidden: semantic recovery, alias decisions beyond liveness, type inference.
"""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
    CStructField,
)

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = ["_dead_code_elimination_8616"]


def _dead_code_elimination_8616(codegen) -> bool:
    """Eliminate only definitely-dead assignments within each statement block."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def _var_key(node: CVariable) -> tuple[str, int | str]:
        var = getattr(node, "variable", None)
        if var is None:
            return ("node", id(node))
        ident = getattr(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("var", id(var))

    def _var_name(node: CVariable) -> str:
        var = getattr(node, "variable", None)
        name = getattr(var, "name", None)
        if isinstance(name, str) and name:
            return name
        node_name = getattr(node, "name", None)
        return node_name if isinstance(node_name, str) else ""

    def _is_observable_lvalue(lhs: object) -> bool:
        if isinstance(lhs, (CUnaryOp, CStructField, CBinaryOp)):
            return True
        if isinstance(lhs, CFunctionCall):
            return True
        if isinstance(lhs, CVariable):
            var = getattr(lhs, "variable", None)
            region = getattr(var, "region", None)
            if isinstance(region, str) and region.lower() in {"stack", "global", "argument", "arg"}:
                return True
        return False

    def _rhs_has_side_effects(rhs: object) -> bool:
        if rhs is None:
            return False
        for node in _iter_c_nodes_deep_8616(rhs):
            if isinstance(node, CFunctionCall):
                return True
        return False

    def _iter_statement_blocks(root):
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if hasattr(node, "statements"):
                yield node
                for stmt in list(getattr(node, "statements", ()) or ()):
                    stack.append(stmt)
            for attr in (
                "condition",
                "cond",
                "body",
                "else_node",
                "iftrue",
                "iffalse",
                "true_node",
                "false_node",
                "expr",
                "retval",
            ):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
            for pair in getattr(node, "condition_and_nodes", ()) or ():
                if len(pair) >= 2:
                    stack.append(pair[0])
                    stack.append(pair[1])
            cases = getattr(node, "cases", None)
            if isinstance(cases, dict):
                for body in cases.values():
                    stack.append(body)
            default = getattr(node, "default", None)
            if default is not None:
                stack.append(default)

    def _collect_stmt_reads(stmt: object) -> set[tuple[str, int | str]]:
        reads: set[tuple[str, int | str]] = set()
        if isinstance(stmt, CAssignment):
            rhs = getattr(stmt, "rhs", None)
            for node in _iter_c_nodes_deep_8616(rhs):
                if isinstance(node, CVariable):
                    reads.add(_var_key(node))
            lhs = getattr(stmt, "lhs", None)
            if isinstance(lhs, CUnaryOp) and getattr(lhs, "op", None) in {"Dereference", "Reference"}:
                for node in _iter_c_nodes_deep_8616(lhs):
                    if isinstance(node, CVariable):
                        reads.add(_var_key(node))
            return reads
        for node in _iter_c_nodes_deep_8616(stmt):
            if isinstance(node, CVariable):
                reads.add(_var_key(node))
        return reads

    def _is_temp_like_var(var_node: CVariable) -> bool:
        name = _var_name(var_node)
        if not name:
            return False
        return name.startswith("vvar_") or name.startswith("tmp_") or name.startswith("ir_")

    def _protected_var_keys() -> set[tuple[str, int | str]]:
        protected: set[tuple[str, int | str]] = set()
        attrs = (
            "_inertia_callsite_arg_sources",
            "_inertia_stack_variable_bindings",
            "_inertia_stack_canonicalization_bridges",
            "_inertia_tail_validation_widened_carriers",
            "_inertia_linear_recurrence_state",
        )
        for attr in attrs:
            obj = getattr(codegen, attr, None)
            if obj is None:
                continue
            work = [obj]
            seen: set[int] = set()
            while work:
                cur = work.pop()
                cur_id = id(cur)
                if cur_id in seen:
                    continue
                seen.add(cur_id)
                if isinstance(cur, CVariable):
                    protected.add(_var_key(cur))
                    continue
                if isinstance(cur, dict):
                    work.extend(cur.values())
                    work.extend(cur.keys())
                    continue
                if isinstance(cur, (list, tuple, set, frozenset)):
                    work.extend(cur)
                    continue
                name = cur if isinstance(cur, str) else getattr(cur, "name", None)
                if isinstance(name, str) and name:
                    protected.add(("name", name))
        return protected

    protected = _protected_var_keys()

    def walk_statements(statements):
        nonlocal changed
        stmts = list(getattr(statements, "statements", ()) or ())
        if not stmts:
            return
        live: set[tuple[str, int | str]] = set()
        new_rev: list[object] = []

        for stmt in reversed(stmts):
            if not isinstance(stmt, CAssignment):
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            lhs = getattr(stmt, "lhs", None)
            rhs = getattr(stmt, "rhs", None)
            if not isinstance(lhs, CVariable):
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            key = _var_key(lhs)
            name_key = ("name", _var_name(lhs))
            removable = (
                _is_temp_like_var(lhs)
                and not _is_observable_lvalue(lhs)
                and not _rhs_has_side_effects(rhs)
                and key not in protected
                and name_key not in protected
                and key not in live
            )
            if removable:
                changed = True
                continue
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
        new_stmts = list(reversed(new_rev))
        if new_stmts != stmts:
            statements.statements = new_stmts

    for block in _iter_statement_blocks(cfunc):
        walk_statements(block)
    return changed
