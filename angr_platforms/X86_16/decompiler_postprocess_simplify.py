from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .semantics.alias_query import _storage_domain_for_expr
from .widening_alias import join_adjacent_register_slices
from .widening_model import prove_adjacent_storage_slices
from .decompiler_postprocess_flags import _bool_cite_values_8616
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)

PROJECTION_CLEANUP_RULES = (
    (
        "concat_fold",
        "Fold concatenations of constant halves into one constant and preserve the narrower shift width otherwise.",
    ),
    (
        "or_zero_elimination",
        "Eliminate redundant zero terms in Or expressions after the low-level expression facts are stable.",
    ),
    (
        "and_zero_collapse",
        "Collapse And expressions with a zero operand into typed zero constants.",
    ),
    (
        "double_not_collapse",
        "Remove redundant boolean negation pairs after boolean cite recovery.",
    ),
    (
        "zero_compare_projection",
        "Convert zero comparisons into the underlying projection or flag source when the evidence is explicit.",
    ),
    (
        "sub_self_zero",
        "Collapse self-subtractions into typed zero constants once the low-level operands are proven identical.",
    ),
)


__all__ = [
    "_simplify_structured_expressions_8616",
    "_simplify_boolean_cites_8616",
    "_eliminate_single_use_temporaries_8616",
    "_maybe_eliminate_single_use_temporaries_8616",
    "describe_x86_16_projection_cleanup_rules",
]


def describe_x86_16_projection_cleanup_rules() -> tuple[tuple[str, str], ...]:
    return PROJECTION_CLEANUP_RULES


def _simplify_boolean_cites_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        if not isinstance(node, CITE):
            return node
        values = _bool_cite_values_8616(node)
        if values == (1, 0):
            return node.cond
        if values == (0, 1):
            return CUnaryOp("Not", node.cond, codegen=codegen, tags=getattr(node, "tags", None))
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen)
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _simplify_structured_expressions_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _invert_cmp_op_8616(op: str) -> str | None:
        return {
            "CmpGT": "CmpLE",
            "CmpGE": "CmpLT",
            "CmpLT": "CmpGE",
            "CmpLE": "CmpGT",
            "CmpEQ": "CmpNE",
            "CmpNE": "CmpEQ",
        }.get(op)

    def _is_c_constant_int_8616(expr, value: int) -> bool:
        return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

    def _is_power_of_two_minus_one_8616(value: int) -> bool:
        """Check if value is of form 2^n - 1 (all bits set up to position n-1)."""
        if value <= 0:
            return False
        return (value & (value + 1)) == 0

    def _bit_position_of_power_of_two_8616(value: int) -> int | None:
        """Return n if value == 2^n, else None."""
        if value <= 0 or (value & (value - 1)) != 0:
            return None
        return (value - 1).bit_length()

    def _leading_set_bits_8616(value: int) -> int:
        """Return position of highest set bit (1-indexed, so 0xFF -> 8)."""
        if value == 0:
            return 0
        return value.bit_length()

    def _extract_same_zero_compare_expr_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
            return None
        if _is_c_constant_int_8616(expr.rhs, 0):
            return expr.lhs
        if _is_c_constant_int_8616(expr.lhs, 0):
            return expr.rhs
        return None

    def _extract_zero_flag_source_expr_8616(expr):
        if isinstance(expr, CBinaryOp):
            if expr.op == "Mul":
                for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                    if not _is_c_constant_int_8616(maybe_scale, 64):
                        continue
                    source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                        return lhs_expr

            for child in (expr.lhs, expr.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(expr, CUnaryOp):
            child = getattr(expr, "operand", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(expr, CTypeCast):
            child = getattr(expr, "expr", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    def _shifted_high_byte_source_8616(expr):
        if not isinstance(expr, CBinaryOp):
            return None
        if expr.op == "Shl" and _is_c_constant_int_8616(expr.rhs, 8):
            return expr.lhs
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.rhs, 0x100):
            return expr.lhs
        if expr.op == "Mul" and _is_c_constant_int_8616(expr.lhs, 0x100):
            return expr.rhs
        return None

    def _materialize_joined_word_expr_8616(low_expr, high_expr):
        low_domain = _storage_domain_for_expr(low_expr)
        high_domain = _storage_domain_for_expr(high_expr)
        alias_state = getattr(codegen, "_inertia_alias_state", None)
        if alias_state is None:
            alias_state = getattr(getattr(codegen, "cfunc", None), "_inertia_alias_state", None)
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if isinstance(low_expr, CVariable) and isinstance(high_expr, CVariable):
            widened_register = join_adjacent_register_slices(
                low_expr,
                high_expr,
                codegen,
                alias_state=alias_state,
                proof=proof,
            )
            if widened_register is not None:
                return widened_register
            if isinstance(getattr(low_expr, "variable", None), SimRegisterVariable) or isinstance(
                getattr(high_expr, "variable", None), SimRegisterVariable
            ):
                return None
        joined = proof.merged_domain if proof.ok else None
        if joined is None and alias_state is None:
            joined = low_domain.join(high_domain)
        if joined is None or joined.width != 2:
            return None
        if not isinstance(low_expr, CVariable) or not isinstance(high_expr, CVariable):
            return None

        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        vartype = getattr(low_expr, "variable_type", None) or getattr(high_expr, "variable_type", None) or SimTypeShort(False)

        if joined.space == "stack" and joined.stack_slot is not None:
            stack_slot = joined.stack_slot
            variable = SimStackVariable(
                stack_slot.offset,
                2,
                base=stack_slot.base,
                name=f"s_{stack_slot.offset & 0xFFFF:x}",
                region=stack_slot.region if stack_slot.region is not None else region,
            )
            return CVariable(variable, variable_type=vartype, codegen=codegen)

        if joined.space == "memory":
            # Keep structuring-stage guard operands in register form.
            # Folding to a global memory word here can perturb whole-tail
            # validation fingerprints (reg -> memory read) even when the
            # expression is algebraically equivalent.
            stage = str(getattr(getattr(codegen, "project", None), "_inertia_decompiler_stage", "") or "")
            if stage in {"core", "structuring"}:
                return None
            low_var = getattr(low_expr, "variable", None)
            high_var = getattr(high_expr, "variable", None)
            low_addr = getattr(low_var, "addr", None)
            high_addr = getattr(high_var, "addr", None)
            if isinstance(low_addr, int) and isinstance(high_addr, int):
                addr = min(low_addr, high_addr)
                variable = SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=region)
                return CVariable(variable, variable_type=vartype, codegen=codegen)

        if joined.space == "register":
            low_var = getattr(low_expr, "variable", None)
            high_var = getattr(high_expr, "variable", None)
            low_reg = getattr(low_var, "reg", None)
            high_reg = getattr(high_var, "reg", None)
            if isinstance(low_reg, int) and isinstance(high_reg, int):
                reg = min(low_reg, high_reg)
                variable = SimRegisterVariable(reg, 2, name=getattr(low_var, "name", None) or getattr(high_var, "name", None))
                return CVariable(variable, variable_type=vartype, codegen=codegen)

        return None

    def _simplify_zero_flag_comparison_8616(expr):
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return expr

        if _is_c_constant_int_8616(expr.rhs, 0):
            source = expr.lhs
        elif _is_c_constant_int_8616(expr.lhs, 0):
            source = expr.rhs
        else:
            return expr

        source_expr = _extract_zero_flag_source_expr_8616(source)
        if source_expr is None:
            return expr
        if expr.op == "CmpEQ":
            return source_expr
        return CUnaryOp("Not", source_expr, codegen=codegen)

    def transform(node):
        if isinstance(node, CBinaryOp) and node.op == "Concat":
            lhs_val = _c_constant_value_8616(node.lhs)
            rhs_val = _c_constant_value_8616(node.rhs)
            rhs_bits = getattr(getattr(node.rhs, "type", None), "size", None)
            lhs_bits = getattr(getattr(node.lhs, "type", None), "size", None)
            if rhs_bits is None:
                rhs_bits = lhs_bits if lhs_bits is not None else 16

            if lhs_val is not None and rhs_val is not None:
                return CConstant((lhs_val << rhs_bits) | rhs_val, getattr(node, "type", None), codegen=codegen)

            shift = CConstant(rhs_bits, getattr(node.rhs, "type", None) or getattr(node.lhs, "type", None), codegen=codegen)
            return CBinaryOp(
                "Or",
                CBinaryOp("Shl", node.lhs, shift, codegen=codegen, tags=getattr(node, "tags", None)),
                node.rhs,
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )

        if isinstance(node, CBinaryOp) and node.op == "Mul":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CBinaryOp) and node.op == "Or":
            folded = None
            shifted_rhs = _shifted_high_byte_source_8616(node.rhs)
            if shifted_rhs is not None:
                folded = _materialize_joined_word_expr_8616(node.lhs, shifted_rhs)
            if folded is None:
                shifted_lhs = _shifted_high_byte_source_8616(node.lhs)
                if shifted_lhs is not None:
                    folded = _materialize_joined_word_expr_8616(node.rhs, shifted_lhs)
            if folded is not None:
                return folded
            if _is_c_constant_int_8616(node.lhs, 0):
                return node.rhs
            if _is_c_constant_int_8616(node.rhs, 0):
                return node.lhs

        if isinstance(node, CBinaryOp) and node.op == "And":
            if _is_c_constant_int_8616(node.lhs, 0) or _is_c_constant_int_8616(node.rhs, 0):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None) or getattr(node.rhs, "type", None)
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = getattr(node, "operand", None)
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return operand.operand
            if isinstance(operand, CBinaryOp):
                inverted = _invert_cmp_op_8616(operand.op)
                if inverted is not None:
                    return CBinaryOp(
                        inverted,
                        operand.lhs,
                        operand.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None) or getattr(operand, "tags", None),
                    )

        simplified = _simplify_zero_flag_comparison_8616(node)
        if simplified is not node:
            return simplified
        
        if (
            isinstance(node, CBinaryOp)
            and node.op in {"LogicalAnd", "LogicalOr", "And", "Or"}
            and _same_c_expression_8616(node.lhs, node.rhs)
        ):
            return node.lhs
        if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
            if isinstance(node.rhs, CConstant) and node.rhs.value == 0:
                if (
                    isinstance(node.lhs, CBinaryOp)
                    and node.lhs.op == "Sub"
                    and isinstance(node.lhs.rhs, CConstant)
                ):
                    return CBinaryOp(
                        node.op,
                        node.lhs.lhs,
                        node.lhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
            if isinstance(node.lhs, CConstant) and node.lhs.value == 0:
                if (
                    isinstance(node.rhs, CBinaryOp)
                    and node.rhs.op == "Sub"
                    and isinstance(node.rhs.rhs, CConstant)
                ):
                    return CBinaryOp(
                        node.op,
                        node.rhs.lhs,
                        node.rhs.rhs,
                        codegen=codegen,
                        tags=getattr(node, "tags", None),
                    )
        if isinstance(node, CBinaryOp) and node.op == "Sub" and _same_c_expression_8616(node.lhs, node.rhs):
            type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
            if type_ is not None:
                return CConstant(0, type_, codegen=codegen)
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        if isinstance(root, CStatements) and not isinstance(new_root, CStatements):
            new_root = CStatements(statements=[new_root] if not isinstance(new_root, list) else new_root, codegen=codegen)
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    for _ in range(3):
        if not _replace_c_children_8616(root, transform):
            break
        changed = True
    return changed


def _eliminate_single_use_temporaries_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    def _safe_inline_expr(expr) -> bool:
        if isinstance(expr, (CConstant, CVariable)):
            return True
        if isinstance(expr, CTypeCast):
            return _safe_inline_expr(expr.expr)
        if isinstance(expr, CUnaryOp):
            if expr.op == "Dereference":
                return False
            return _safe_inline_expr(expr.operand)
        if isinstance(expr, CBinaryOp):
            return _safe_inline_expr(expr.lhs) and _safe_inline_expr(expr.rhs)
        if isinstance(expr, CITE):
            return (
                _safe_inline_expr(expr.cond)
                and _safe_inline_expr(expr.iftrue)
                and _safe_inline_expr(expr.iffalse)
            )
        return False

    def _count_var_uses(node, target, *, assignment_lhs: bool = False) -> int:
        if node is None:
            return 0
        if isinstance(node, CVariable):
            return 0 if assignment_lhs else int(_same_c_expression_8616(node, target))

        total = 0
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                total += _count_var_uses(
                    child,
                    target,
                    assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
                )
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    total += _count_var_uses(item, target)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            total += _count_var_uses(subitem, target)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    total += _count_var_uses(cond, target)
                if _structured_codegen_node_8616(body):
                    total += _count_var_uses(body, target)
        return total

    def _replace_var_use(node, target, replacement, *, assignment_lhs: bool = False):
        if isinstance(node, CVariable):
            if not assignment_lhs and _same_c_expression_8616(node, target):
                return replacement, True
            return node, False

        changed_local = False
        for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "else_node"):
            child = getattr(node, attr, None)
            if not _structured_codegen_node_8616(child):
                continue
            new_child, child_changed = _replace_var_use(
                child,
                target,
                replacement,
                assignment_lhs=assignment_lhs and attr == "lhs" and isinstance(node, CAssignment),
            )
            if child_changed:
                setattr(node, attr, new_child)
                changed_local = True
        for attr in ("statements", "operands", "args"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            new_seq = []
            seq_changed = False
            for item in seq:
                if _structured_codegen_node_8616(item):
                    new_item, item_changed = _replace_var_use(item, target, replacement)
                    new_seq.append(new_item)
                    seq_changed |= item_changed
                else:
                    new_seq.append(item)
            if seq_changed:
                setattr(node, attr, new_seq)
                changed_local = True
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            new_pairs = []
            pair_changed = False
            for cond, body in pairs:
                new_cond, cond_changed = (
                    _replace_var_use(cond, target, replacement) if _structured_codegen_node_8616(cond) else (cond, False)
                )
                new_body, body_changed = (
                    _replace_var_use(body, target, replacement) if _structured_codegen_node_8616(body) else (body, False)
                )
                new_pairs.append((new_cond, new_body))
                pair_changed |= cond_changed or body_changed
            if pair_changed:
                setattr(node, "condition_and_nodes", new_pairs)
                changed_local = True
        return node, changed_local

    changed = False

    def visit(node):
        nonlocal changed
        if not isinstance(node, CStatements):
            return

        new_statements = []
        statements = list(node.statements)
        idx = 0
        while idx < len(statements):
            stmt = statements[idx]
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            removed = False

            if (
                isinstance(stmt, CAssignment)
                and isinstance(stmt.lhs, CVariable)
                and _safe_inline_expr(stmt.rhs)
                and next_stmt is not None
            ):
                immediate_uses = _count_var_uses(next_stmt, stmt.lhs)
                later_uses = sum(_count_var_uses(rest, stmt.lhs) for rest in statements[idx + 2 :])
                if immediate_uses == 1 and later_uses == 0:
                    _, replaced = _replace_var_use(next_stmt, stmt.lhs, stmt.rhs)
                    if replaced:
                        changed = True
                        removed = True

            if not removed:
                new_statements.append(stmt)
                visit(stmt)
            idx += 1

        if len(new_statements) != len(node.statements):
            node.statements = new_statements

    root = codegen.cfunc.statements
    visit(root)
    return changed


def _maybe_eliminate_single_use_temporaries_8616(project, codegen) -> bool:
    if not getattr(project, "_inertia_postprocess_single_use_temporaries_enabled", False):
        return False
    return _eliminate_single_use_temporaries_8616(codegen)
