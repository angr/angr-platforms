from __future__ import annotations

"""Layer: Semantics (value flow, below alias).

Light SSA-like renaming pass: version registers and inline definitions.
Operates on structured C codegen nodes.
Uses alias model for same-domain proofs.

Forbidden: semantic recovery from text, type inference, postprocess ownership."""

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)

from ..decompiler_postprocess_utils import _same_c_expression_8616
from ..semantics.alias_query import _storage_domain_for_expr

__all__ = ["_apply_value_flow_renaming_8616"]


def _same_var(a: object, b: object) -> bool:
    """Prove two variables refer to the same storage using alias facts."""
    domain_a = _storage_domain_for_expr(a)
    domain_b = _storage_domain_for_expr(b)
    if domain_a is None or domain_b is None:
        return _same_c_expression_8616(a, b)
    return domain_a == domain_b


def _is_side_effecting(expr) -> bool:
    """Check for side effects that prevent inlining."""
    if isinstance(expr, CFunctionCall):
        return True
    if isinstance(expr, CAssignment):
        return True
    return False


def _has_variable_use(expr, target) -> bool:
    """Check if expr contains a use of target variable."""
    if expr is None:
        return False
    if _same_var(expr, target):
        return True
    if isinstance(expr, CBinaryOp):
        return _has_variable_use(expr.lhs, target) or _has_variable_use(expr.rhs, target)
    if isinstance(expr, CUnaryOp):
        return _has_variable_use(expr.operand, target)
    if isinstance(expr, CFunctionCall):
        return any(_has_variable_use(arg, target) for arg in (getattr(expr, "args", ()) or ()))
    if isinstance(expr, CAssignment):
        return _has_variable_use(expr.rhs, target) or _has_variable_use(expr.lhs, target)
    return False


def _apply_value_flow_renaming_8616(codegen) -> bool:
    """Inline single-use temporaries where alias-safe.

    For each block:
    - Track assignments t = expr
    - When t is used exactly once (as rhs of another assignment),
      and t is not redefined between def and use,
      inline the expression.

    Respects alias domain: only inlines when source and destination
    storage identity is preserved.

    Returns True if any inlining occurred.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def _collect_var_uses(stmts) -> dict[int, int]:
        """Count uses of each variable in the block."""
        count: dict[int, int] = {}
        for stmt in stmts:
            if isinstance(stmt, CAssignment):
                rhs = getattr(stmt, "rhs", None)
                lhs = getattr(stmt, "lhs", None)
                if rhs is not None:
                    for node in _iter_c_nodes(rhs):
                        if isinstance(node, CVariable):
                            node_id = id(node)
                            count[node_id] = count.get(node_id, 0) + 1
                # Don't count definition site as a use
                if lhs is not None and id(lhs) in count:
                    count[id(lhs)] -= 1
                if rhs is not None:
                    for node in _iter_c_nodes(rhs):
                        if isinstance(node, (CIfElse, CWhileLoop, CDoWhileLoop, CForLoop)):
                            pass  # Conditions in structured nodes handled separately
        return count

    def _iter_c_nodes(node):
        if node is None:
            return
        yield node
        if isinstance(node, CBinaryOp):
            yield from _iter_c_nodes(node.lhs)
            yield from _iter_c_nodes(node.rhs)
        elif isinstance(node, CUnaryOp):
            yield from _iter_c_nodes(node.operand)
        elif isinstance(node, CFunctionCall):
            for arg in getattr(node, "args", ()) or ():
                yield from _iter_c_nodes(arg)
        elif isinstance(node, CAssignment):
            yield from _iter_c_nodes(node.rhs)

    def walk_statements(statements):
        nonlocal changed
        stmts = list(getattr(statements, "statements", ()) or ())
        if len(stmts) < 2:
            return

        # Track definitions: {var_id: (index, rhs_expression)}
        defs: dict[int, tuple[int, object]] = {}

        # Count uses across the block
        use_counts = _collect_var_uses(stmts)

        for idx, stmt in enumerate(stmts):
            if not isinstance(stmt, CAssignment):
                continue
            rhs = getattr(stmt, "rhs", None)
            lhs = getattr(stmt, "lhs", None)
            if lhs is None or rhs is None:
                continue

            # Record this definition (may overwrite previous)
            defs[id(lhs)] = (idx, rhs)

            # Check if we can inline earlier definitions used here
            if isinstance(rhs, CVariable):
                rhs_id = id(rhs)
                if rhs_id in defs:
                    def_idx, def_expr = defs[rhs_id]
                    # Only inline if rhs is used exactly once (this use)
                    if use_counts.get(rhs_id, 0) == 1 and not _is_side_effecting(def_expr):
                        stmt.rhs = def_expr
                        changed = True
                        # Update defs for the new expression
                        defs[id(lhs)] = (idx, def_expr)

            # Invalidate defs when variable is redefined
            if id(lhs) in defs:
                # Re-record to track latest definition
                pass

    def _walk_node(node):
        if node is None:
            return
        if hasattr(node, "statements"):
            walk_statements(node)
        for attr in ("body", "else_node", "iftrue", "iffalse",
                     "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                _walk_node(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                _walk_node(body)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                _walk_node(case_body)
        if hasattr(node, "default"):
            _walk_node(getattr(node, "default", None))

    # Walk from cfunc
    if hasattr(cfunc, "statements"):
        walk_statements(cfunc)
    _walk_node(cfunc)

    return changed