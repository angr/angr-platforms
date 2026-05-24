from __future__ import annotations

# Layer: Widening
# Responsibility: copy propagation using proven alias storage domains.
# Equivalent to LLVM: EarlyCSE + local copy prop (Local.cpp).
# Forbidden: C text generation, type inference, rewrite ownership.

from ..decompiler_postprocess_utils import _unwrap_statements_8616
from ..semantics.alias_query import (
    _storage_domain_for_expr,
    describe_alias_storage,
    same_alias_storage_domain,
)
from ..semantics.expression_analysis import _unwrap_c_casts

__all__ = ["_widening_copy_propagation_8616"]


def _widening_copy_propagation_8616(codegen) -> bool:
    """Propagate copies using alias storage domains.

    For each block, maintain a map from storage domain to the last
    definition. When a RHS is a CVariable with the same storage domain
    as a prior definition, replace it with the original source.

    Returns True if any copy was propagated.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def _block_def_key(storage_facts) -> str | None:
        """Create a deterministic key for a storage domain within a block."""
        domain = getattr(storage_facts, "domain", None)
        identity = getattr(storage_facts, "identity", None)
        if domain is None:
            return None
        domain_repr = getattr(domain, "_repr", None) or str(domain)
        identity_repr = str(identity) if identity is not None else ""
        return f"{domain_repr}:{identity_repr}"

    def _walk_statements(statements_obj):
        nonlocal changed
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        stmts = _unwrap_statements_8616(statements_obj)
        # Map storage domain key → (source_expr, storage_facts) for last definition
        block_defs: dict[str, object] = {}

        for stmt in stmts:
            if isinstance(stmt, structured_c.CAssignment):
                rhs = getattr(stmt, "rhs", None)
                lhs = getattr(stmt, "lhs", None)

                # Attempt copy propagation: if RHS is a variable, check for prior def
                if isinstance(rhs, structured_c.CVariable):
                    rhs_facts = describe_alias_storage(rhs)
                    rhs_key = _block_def_key(rhs_facts)
                    if rhs_key is not None and rhs_key in block_defs:
                        replacement = block_defs[rhs_key]
                        if replacement is not None and not _is_same_expr(replacement, rhs):
                            stmt.rhs = _unwrap_c_casts(replacement)
                            changed = True

                # Record this definition's source for future propagation
                if lhs is not None and not _is_side_effecting(rhs):
                    lhs_facts = describe_alias_storage(lhs)
                    lhs_key = _block_def_key(lhs_facts)
                    if lhs_key is not None:
                        block_defs[lhs_key] = rhs

                # Side-effecting calls kill all domain state
                if _is_side_effecting(rhs):
                    block_defs.clear()

                # Record writes via pointer-like stores (kill specific domains)
                if isinstance(rhs, structured_c.CFunctionCall):
                    block_defs.clear()

            _walk_node(stmt)

    def _walk_node(node):
        if node is None:
            return
        if hasattr(node, "statements"):
            _walk_statements(node)
        for attr in (
            "condition", "cond", "body", "else_node", "iftrue", "iffalse",
            "retval", "expr", "switch", "initializer", "iterator",
        ):
            child = getattr(node, attr, None)
            if child is not None:
                _walk_node(child)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                _walk_node(cond)
                _walk_node(body)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                _walk_node(case_body)
        if hasattr(node, "default"):
            _walk_node(getattr(node, "default", None))

    _walk_statements(cfunc)
    return changed


def _is_side_effecting(expr) -> bool:
    """Check if expression has side effects that prevent copy propagation."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CFunctionCall):
        return True
    if isinstance(expr, structured_c.CAssignment):
        return True
    return False


def _is_same_expr(a, b) -> bool:
    """Check if two expressions are structurally identical."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if type(a) is not type(b):
        return False
    if isinstance(a, structured_c.CVariable):
        return (
            getattr(a, "variable", None) is getattr(b, "variable", None)
            and getattr(a, "offset", None) == getattr(b, "offset", None)
        )
    if isinstance(a, structured_c.CConstant):
        return getattr(a, "value", None) == getattr(b, "value", None)
    if isinstance(a, structured_c.CBinaryOp):
        return (
            a.op == b.op
            and _is_same_expr(a.lhs, b.lhs)
            and _is_same_expr(a.rhs, b.rhs)
        )
    if isinstance(a, structured_c.CUnaryOp):
        return a.op == b.op and _is_same_expr(a.operand, b.operand)
    return a is b