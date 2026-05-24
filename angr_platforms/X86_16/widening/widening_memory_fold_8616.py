from __future__ import annotations

# Layer: Widening
# Responsibility: store-to-load forwarding (GVN-like) using alias storage domains.
# Equivalent to LLVM: Mem2Reg + GVN for store-to-load chains within blocks.
# Forbidden: cross-block value numbering, type-promotion, C text generation.

from ..decompiler_postprocess_utils import _unwrap_statements_8616
from ..semantics.alias_query import describe_alias_storage, same_alias_storage_domain
from ..semantics.expression_analysis import _unwrap_c_casts

__all__ = ["_widening_store_to_load_forwarding_8616"]


def _widening_store_to_load_forwarding_8616(codegen) -> bool:
    """Forward stored values to subsequent loads within the same block.

    Pattern:
        *(addr) = value;
        ...
        use = *(addr);   →  use = value;

    Only forwards when the address expressions have identical alias storage
    domains and there is no intervening side-effecting operation.

    Returns True if any load was forwarded.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    changed = False

    def _addr_expr_from_deref(expr):
        """Extract the address expression from a pointer-like expr: *((ds<<4)+bx) → (ds<<4)+bx."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        # Pattern: CBinaryOp('Mul', CVariable(seg), CConstant(16)) → seg reg
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Add":
            return expr
        # Reference through a dereference: *(addr)
        if isinstance(expr, structured_c.CUnaryOp):
            return _addr_expr_from_deref(expr.operand)
        return expr

    def _is_deref_write(stmt) -> bool:
        """Check if stmt is a memory store through a pointer expression."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = getattr(stmt, "lhs", None)
        # The lhs is typically a CUnaryOp('Reference') or similar for pointer stores
        if isinstance(lhs, structured_c.CUnaryOp):
            return True
        return False

    def _is_deref_read(rhs) -> bool:
        """Check if rhs is a memory load through a pointer expression."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(rhs, structured_c.CUnaryOp):
            return True
        return False

    def _addr_key(addr_expr) -> str | None:
        """Create a deterministic key for alias comparison of address expressions."""
        facts = describe_alias_storage(addr_expr)
        domain = getattr(facts, "domain", None)
        identity = getattr(facts, "identity", None)
        if domain is None:
            return None
        domain_repr = getattr(domain, "_repr", None) or str(domain)
        identity_repr = str(identity) if identity is not None else ""
        # Include structural hash for disambiguation
        structural = _structural_hash(addr_expr)
        return f"{domain_repr}:{identity_repr}:{structural}"

    def _structural_hash(expr) -> str:
        """Create a structural hash for expression equivalence."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(expr, structured_c.CVariable):
            var = getattr(expr, "variable", None)
            off = getattr(expr, "offset", None)
            return f"v:{id(var)}:{off}"
        if isinstance(expr, structured_c.CConstant):
            return f"c:{getattr(expr, 'value', None)}"
        if isinstance(expr, structured_c.CBinaryOp):
            return f"b:{expr.op}:{_structural_hash(expr.lhs)}:{_structural_hash(expr.rhs)}"
        if isinstance(expr, structured_c.CUnaryOp):
            return f"u:{expr.op}:{_structural_hash(expr.operand)}"
        return str(id(expr))

    def _walk_statements(statements_obj):
        nonlocal changed
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        stmts = _unwrap_statements_8616(statements_obj)
        # Map addr_key → stored_value for pending stores
        pending_stores: dict[str, object] = {}

        for stmt in stmts:
            # Kill pending stores on side effects
            if _has_side_effects_stmt(stmt):
                pending_stores.clear()

            if isinstance(stmt, structured_c.CAssignment):
                rhs = getattr(stmt, "rhs", None)
                lhs = getattr(stmt, "lhs", None)

                # Forward: if reading from a stored-to address
                if rhs is not None and _is_deref_read(rhs):
                    addr_expr = _addr_expr_from_deref(rhs)
                    key = _addr_key(addr_expr)
                    if key is not None and key in pending_stores:
                        replacement = pending_stores[key]
                        if replacement is not None and not _is_same_expr(replacement, rhs):
                            stmt.rhs = _unwrap_c_casts(replacement)
                            changed = True

                # Record: if this is a store through a pointer, record it
                if lhs is not None and _is_deref_write(stmt):
                    addr_expr = _addr_expr_from_deref(lhs)
                    key = _addr_key(addr_expr)
                    if key is not None and rhs is not None:
                        pending_stores[key] = _unwrap_c_casts(rhs)

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


def _has_side_effects_stmt(stmt) -> bool:
    """Check if a statement has side effects that invalidate memory forwarding."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(stmt, structured_c.CFunctionCall):
        return True
    if isinstance(stmt, structured_c.CReturn):
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