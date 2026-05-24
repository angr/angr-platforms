from __future__ import annotations

# Layer: Postprocess
# Responsibility: normalize already-recovered flag/condition expressions.
# Forbidden: primary semantic recovery ownership for branch meaning.

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable

from ..decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
    _unwrap_statements_8616,
)

__all__ = [
    "_extract_flag_test_info_8616",
    "_extract_flag_predicate_from_expr_8616",
    "_rewrite_flag_bit_value_uses_8616",
    "_recover_ordering_condition_from_flag_mask_8616",
    "_recover_signed_condition_8616",
    "_recover_unsigned_condition_8616",
    "_rewrite_flag_condition_expr_8616",
    "_c_expr_uses_var_8616",
    "_rewrite_flag_condition_pairs_8616",
    "_bool_cite_values_8616",
    "_extract_bool_compare_term_8616",
    "_make_bool_cite_8616",
    "_invert_cmp_op_8616",
    "_make_bool_expr_from_compare_8616",
    "_fix_impossible_interval_guard_expr_8616",
    "_fix_interval_guard_conditions_8616",
    "_prune_unused_flag_assignments_8616",
    "_c_expr_uses_register_8616",
    "_stmt_reads_reg_before_write_8616",
    "_prune_overwritten_flag_assignments_8616",
]

_CF_MASK_8616 = 0x1
_ZF_MASK_8616 = 0x40
_SF_MASK_8616 = 0x80
_OF_MASK_8616 = 0x800


def _c_variable_register_offset_8616(node) -> int | None:
    if not isinstance(node, CVariable):
        return None
    for attr in ("variable", "unified_variable"):
        variable = getattr(node, attr, None)
        if isinstance(variable, SimRegisterVariable) and isinstance(getattr(variable, "reg", None), int):
            return variable.reg
    return None


def _flags_register_offset_8616(codegen) -> int | None:
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is None:
        return None
    reg = arch.registers.get("flags")
    return None if reg is None else int(reg[0])


def _expr_uses_raw_flags_register_8616(expr, codegen) -> bool:
    flags_offset = _flags_register_offset_8616(codegen)
    if flags_offset is None:
        return False
    return _c_expr_uses_register_8616(expr, flags_offset)


def _extract_flag_test_info_8616(node):
    invert = False
    while True:
        if isinstance(node, CUnaryOp) and node.op == "Not":
            invert = not invert
            node = node.operand
            continue
        if isinstance(node, CITE):
            values = _bool_cite_values_8616(node)
            if values == (1, 0):
                node = node.cond
                continue
            if values == (0, 1):
                invert = not invert
                node = node.cond
                continue
        break

    if isinstance(node, CBinaryOp) and node.op == "And":
        if isinstance(node.lhs, CVariable) and isinstance(node.rhs, CConstant) and isinstance(node.rhs.value, int):
            return node.lhs, node.rhs.value, invert
        if isinstance(node.rhs, CVariable) and isinstance(node.lhs, CConstant) and isinstance(node.lhs.value, int):
            return node.rhs, node.lhs.value, invert

    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None

    lhs = node.lhs
    rhs = node.rhs

    # Pattern 1: (flags & bit) == 0  or 0 == (flags & bit)
    zero = None
    masked = None
    if isinstance(lhs, CBinaryOp) and lhs.op == "And" and isinstance(rhs, CConstant) and rhs.value == 0:
        masked = lhs
        zero = rhs
    elif isinstance(rhs, CBinaryOp) and rhs.op == "And" and isinstance(lhs, CConstant) and lhs.value == 0:
        masked = rhs
        zero = lhs

    if masked is not None and zero is not None:
        mask_lhs = masked.lhs
        mask_rhs = masked.rhs
        if isinstance(mask_lhs, CConstant) and isinstance(mask_lhs.value, int) and isinstance(mask_rhs, CVariable):
            bit = mask_lhs.value
            var = mask_rhs
        elif isinstance(mask_rhs, CConstant) and isinstance(mask_rhs.value, int) and isinstance(mask_lhs, CVariable):
            bit = mask_rhs.value
            var = mask_lhs
        else:
            return None
        predicate_negated = invert
        if node.op == "CmpEQ":
            predicate_negated = not predicate_negated
        return var, bit, predicate_negated

    # Pattern 2: (flags & bit1) == (flags & bit2)  (or !=)
    # Both sides must be And with same variable
    if isinstance(lhs, CBinaryOp) and lhs.op == "And" and isinstance(rhs, CBinaryOp) and rhs.op == "And":
        # Extract variable and bits from each side
        def extract_bit_and_var(expr):
            if isinstance(expr.lhs, CConstant) and isinstance(expr.lhs.value, int) and isinstance(expr.rhs, CVariable):
                return expr.lhs.value, expr.rhs
            if isinstance(expr.rhs, CConstant) and isinstance(expr.rhs.value, int) and isinstance(expr.lhs, CVariable):
                return expr.rhs.value, expr.lhs
            return None, None
        bit1, var1 = extract_bit_and_var(lhs)
        bit2, var2 = extract_bit_and_var(rhs)
        if bit1 is not None and bit2 is not None and var1 is not None and var2 is not None:
            if _same_c_expression_8616(var1, var2):
                predicate_negated = invert
                if node.op == "CmpEQ":
                    predicate_negated = not predicate_negated
                # Return var, bit1, bit2, predicate_negated
                # We'll pack as a 4-tuple; caller must adapt
                return var1, bit1, bit2, predicate_negated

    return None


def _extract_flag_predicate_from_expr_8616(node, bit: int):
    node = _unwrap_c_casts_8616(node)

    if bit == 1:
        if isinstance(node, CBinaryOp) and node.op == "And":
            lhs_const = _c_constant_value_8616(_unwrap_c_casts_8616(node.lhs))
            rhs_const = _c_constant_value_8616(_unwrap_c_casts_8616(node.rhs))
            if lhs_const == 1:
                return node.rhs
            if rhs_const == 1:
                return node.lhs

    if isinstance(node, CBinaryOp):
        if node.op == "Shl":
            lhs = _unwrap_c_casts_8616(node.lhs)
            rhs = _unwrap_c_casts_8616(node.rhs)
            shift = _c_constant_value_8616(rhs)
            if shift is not None and shift >= 0 and (1 << shift) == bit:
                if bit == 1:
                    predicate = _extract_flag_predicate_from_expr_8616(lhs, 1)
                    return lhs if predicate is None else predicate
                return lhs
        if node.op == "Mul":
            if isinstance(node.lhs, CConstant) and node.lhs.value == bit:
                return node.rhs
            if isinstance(node.rhs, CConstant) and node.rhs.value == bit:
                return node.lhs
        if node.op in {"Or", "And"}:
            lhs = _extract_flag_predicate_from_expr_8616(node.lhs, bit)
            if lhs is not None:
                return lhs
            rhs = _extract_flag_predicate_from_expr_8616(node.rhs, bit)
            if rhs is not None:
                return rhs
    return None


def _unwrap_c_casts_8616(node):
    while type(node).__name__ == "CTypeCast":
        expr = getattr(node, "expr", None)
        if expr is None:
            break
        node = expr
    return node


def _extract_flag_bit_value_info_8616(node):
    node = _unwrap_c_casts_8616(node)
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return None

    def _extract_shifted_flag_value(expr):
        expr = _unwrap_c_casts_8616(expr)
        if isinstance(expr, CVariable):
            return expr, 0
        if not isinstance(expr, CBinaryOp) or expr.op not in {"Shr", "Sar"}:
            return None
        lhs = _unwrap_c_casts_8616(expr.lhs)
        rhs = _unwrap_c_casts_8616(expr.rhs)
        if not isinstance(lhs, CVariable):
            return None
        shift = _c_constant_value_8616(rhs)
        if shift is None or shift < 0:
            return None
        return lhs, shift

    for masked, mask in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _c_constant_value_8616(_unwrap_c_casts_8616(mask)) != 1:
            continue
        shifted = _extract_shifted_flag_value(masked)
        if shifted is None:
            continue
        flag_var, shift = shifted
        bit = 1 << shift
        return flag_var, bit
    return None


def _rewrite_flag_bit_value_expr_8616(node, assignments, codegen):
    changed = False

    def transform(expr):
        nonlocal changed
        info = _extract_flag_bit_value_info_8616(expr)
        if info is None:
            return expr
        flag_var, bit = info
        for assign_stmt, _assign_container in reversed(assignments):
            if not isinstance(assign_stmt, CAssignment):
                continue
            if not _same_c_expression_8616(assign_stmt.lhs, flag_var):
                continue
            predicate = _extract_flag_predicate_from_expr_8616(assign_stmt.rhs, bit)
            if predicate is None:
                return expr
            if _c_expr_uses_var_8616(predicate, flag_var) or _expr_uses_raw_flags_register_8616(predicate, codegen):
                return expr
            changed = True
            return predicate
        return expr

    new_node = transform(node)
    if _replace_c_children_8616(new_node, transform):
        changed = True
    return new_node, changed


def _rewrite_flag_bit_value_uses_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    flags_offset = None
    project_arch = getattr(getattr(codegen, "project", None), "arch", None)
    if project_arch is not None:
        flags_offset = project_arch.registers.get("flags", (None, None))[0]

    def _last_assignment_in_stmt(stmt):
        if isinstance(stmt, CAssignment):
            return stmt, None
        if isinstance(stmt, CStatements) and stmt.statements:
            last = stmt.statements[-1]
            if isinstance(last, CAssignment):
                return last, stmt
        return None, None

    def _is_flags_assignment(stmt) -> bool:
        if flags_offset is None or not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
            return False
        return _c_variable_register_offset_8616(stmt.lhs) == flags_offset

    def _rewrite_expr(node, assignments):
        nonlocal changed
        rewritten, expr_changed = _rewrite_flag_bit_value_expr_8616(node, assignments, codegen)
        changed = changed or expr_changed
        return rewritten

    def visit_stmt(stmt, assignments):
        if isinstance(stmt, CStatements):
            visit_block(stmt, assignments)
            return
        if isinstance(stmt, CIfElse):
            new_pairs = []
            pair_changed = False
            for cond, body in getattr(stmt, "condition_and_nodes", ()) or ():
                new_cond = _rewrite_expr(cond, assignments)
                if isinstance(body, CStatements):
                    visit_block(body, list(assignments))
                new_pairs.append((new_cond, body))
                pair_changed = pair_changed or (new_cond is not cond)
            if pair_changed:
                stmt.condition_and_nodes = new_pairs
            else_node = getattr(stmt, "else_node", None)
            if isinstance(else_node, CStatements):
                visit_block(else_node, list(assignments))
            return
        condition = getattr(stmt, "condition", None)
        if condition is not None and type(condition).__name__.startswith("C"):
            new_condition = _rewrite_expr(condition, assignments)
            if new_condition is not condition:
                stmt.condition = new_condition
        body = getattr(stmt, "body", None)
        if isinstance(body, CStatements):
            visit_block(body, list(assignments))
        _rewrite_expr(stmt, assignments)

    def visit_block(node, incoming_assignments):
        local_assignments = list(incoming_assignments)
        for stmt in _unwrap_statements_8616(node):
            visit_stmt(stmt, local_assignments)
            assign_stmt, assign_container = _last_assignment_in_stmt(stmt)
            if _is_flags_assignment(assign_stmt):
                local_assignments.append((assign_stmt, assign_container))

    visit_block(codegen.cfunc.statements, [])
    return changed


def _recover_unsigned_condition_8616(expr, bit: int, codegen):
    if bit not in {_CF_MASK_8616, _ZF_MASK_8616}:
        return None
    return _extract_flag_predicate_from_expr_8616(expr, bit)


def _recover_signed_condition_8616(expr, bit1: int, bit2: int, codegen):
    if {bit1, bit2} != {_SF_MASK_8616, _OF_MASK_8616}:
        return None

    sf_predicate = _extract_flag_predicate_from_expr_8616(expr, _SF_MASK_8616)
    of_predicate = _extract_flag_predicate_from_expr_8616(expr, _OF_MASK_8616)
    if sf_predicate is None or of_predicate is None:
        return None

    return CBinaryOp(
        "CmpNE",
        sf_predicate,
        of_predicate,
        codegen=codegen,
    )


def _recover_ordering_condition_from_flag_mask_8616(expr, flag_test_info, codegen):
    if flag_test_info is None:
        return None

    if len(flag_test_info) == 3:
        _flag_var, bit, negate_predicate = flag_test_info
        predicate = _recover_unsigned_condition_8616(expr, bit, codegen)
    elif len(flag_test_info) == 4:
        _flag_var, bit1, bit2, negate_predicate = flag_test_info
        predicate = _recover_signed_condition_8616(expr, bit1, bit2, codegen)
    else:
        return None

    if predicate is None:
        return None
    if negate_predicate:
        return CUnaryOp("Not", predicate, codegen=codegen)
    return predicate


def _invert_compare_op_8616(op: str) -> str | None:
    return {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }.get(op)


def _normalize_effective_compare_8616(node):
    if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}:
        return node.op, node.lhs, node.rhs
    if isinstance(node, CUnaryOp) and node.op == "Not" and isinstance(node.operand, CBinaryOp):
        inverted = _invert_compare_op_8616(node.operand.op)
        if inverted is not None:
            return inverted, node.operand.lhs, node.operand.rhs
    return None


def _flag_component_compare_kind_8616(node, flag_var, flag_expr, codegen):
    info = _extract_flag_test_info_8616(node)
    if info is None or not _same_c_expression_8616(info[0], flag_var):
        return None
    if len(info) == 3:
        bit = info[1]
        if bit != _ZF_MASK_8616:
            return None
        predicate = _recover_ordering_condition_from_flag_mask_8616(flag_expr, info, codegen)
        normalized = _normalize_effective_compare_8616(predicate)
        if normalized is None:
            return None
        op, lhs, rhs = normalized
        if op not in {"CmpEQ", "CmpNE"}:
            return None
        return op, lhs, rhs
    if len(info) == 4 and {info[1], info[2]} == {_SF_MASK_8616, _OF_MASK_8616}:
        zf_predicate = _recover_unsigned_condition_8616(flag_expr, _ZF_MASK_8616, codegen)
        normalized = _normalize_effective_compare_8616(zf_predicate)
        if normalized is None:
            return None
        _zf_op, lhs, rhs = normalized
        return ("CmpGE" if info[3] else "CmpLT"), lhs, rhs
    return None


def _recover_combined_signed_flag_condition_8616(node, flag_var, flag_expr, codegen):
    if not isinstance(node, CBinaryOp) or node.op not in {"And", "LogicalAnd", "Or", "LogicalOr"}:
        return None

    lhs_info = _flag_component_compare_kind_8616(node.lhs, flag_var, flag_expr, codegen)
    rhs_info = _flag_component_compare_kind_8616(node.rhs, flag_var, flag_expr, codegen)
    if lhs_info is None or rhs_info is None:
        return None
    lhs_op, lhs_cmp_lhs, lhs_cmp_rhs = lhs_info
    rhs_op, rhs_cmp_lhs, rhs_cmp_rhs = rhs_info
    if not _same_c_expression_8616(lhs_cmp_lhs, rhs_cmp_lhs) or not _same_c_expression_8616(lhs_cmp_rhs, rhs_cmp_rhs):
        return None

    ordered_ops = {lhs_op, rhs_op}
    replacement_op = None
    if node.op in {"And", "LogicalAnd"}:
        if ordered_ops == {"CmpEQ", "CmpGE"}:
            replacement_op = "CmpEQ"
        elif ordered_ops == {"CmpNE", "CmpGE"}:
            replacement_op = "CmpGT"
        elif ordered_ops == {"CmpNE", "CmpLT"}:
            replacement_op = "CmpLT"
    else:
        if ordered_ops == {"CmpEQ", "CmpLT"}:
            replacement_op = "CmpLE"
        elif ordered_ops == {"CmpEQ", "CmpGE"}:
            replacement_op = "CmpGE"
        elif ordered_ops == {"CmpNE", "CmpLT"}:
            replacement_op = "CmpNE"
    if replacement_op is None:
        return None
    return CBinaryOp(
        replacement_op,
        lhs_cmp_lhs,
        lhs_cmp_rhs,
        codegen=codegen,
        tags=getattr(node, "tags", None),
    )


def _canonical_compare_guard_8616(node):
    if isinstance(node, CUnaryOp) and node.op == "Not" and isinstance(node.operand, CBinaryOp):
        operand = node.operand
        inverted = {
            "CmpLE": "CmpGT",
            "CmpLT": "CmpGE",
            "CmpGE": "CmpLT",
            "CmpGT": "CmpLE",
        }.get(operand.op)
        if inverted is not None:
            return inverted, operand.lhs, operand.rhs
    if isinstance(node, CBinaryOp) and node.op in {"CmpGT", "CmpGE", "CmpLT", "CmpLE"}:
        return node.op, node.lhs, node.rhs
    return None


def _compare_matches_or_swapped_8616(compare_info, other_info) -> bool:
    if compare_info is None or other_info is None:
        return False
    op, lhs, rhs = compare_info
    other_op, other_lhs, other_rhs = other_info
    if op == other_op and _same_c_expression_8616(lhs, other_lhs) and _same_c_expression_8616(rhs, other_rhs):
        return True
    swapped = {
        "CmpGT": "CmpLT",
        "CmpGE": "CmpLE",
        "CmpLT": "CmpGT",
        "CmpLE": "CmpGE",
    }.get(op)
    return (
        swapped == other_op
        and _same_c_expression_8616(lhs, other_rhs)
        and _same_c_expression_8616(rhs, other_lhs)
    )


def _maybe_strip_redundant_signed_flag_pair_guard_8616(node, flag_var, flag_expr):
    if not isinstance(node, CBinaryOp) or node.op != "LogicalAnd":
        return None

    def _strip(flag_guard, other_guard):
        info = _extract_flag_test_info_8616(flag_guard)
        if info is None or len(info) != 4 or not _same_c_expression_8616(info[0], flag_var):
            return None
        if {info[1], info[2]} != {_SF_MASK_8616, _OF_MASK_8616}:
            return None
        sf_predicate = _extract_flag_predicate_from_expr_8616(flag_expr, _SF_MASK_8616)
        if sf_predicate is None:
            return None
        sf_compare = _canonical_compare_guard_8616(sf_predicate)
        other_compare = _canonical_compare_guard_8616(other_guard)
        if not _compare_matches_or_swapped_8616(sf_compare, other_compare):
            return None
        pair_is_equal = bool(info[3])
        other_kind = other_compare[0]
        if pair_is_equal and other_kind == "CmpGT":
            return other_guard
        if not pair_is_equal and other_kind == "CmpLT":
            return other_guard
        return None

    simplified = _strip(node.lhs, node.rhs)
    if simplified is not None:
        return simplified
    return _strip(node.rhs, node.lhs)


def _maybe_strip_standalone_signed_flag_pair_guard_8616(node):
    if not isinstance(node, CBinaryOp) or node.op != "LogicalAnd":
        return None

    def _strip(flag_guard, other_guard):
        info = _extract_flag_test_info_8616(flag_guard)
        if info is None or len(info) != 4:
            return None
        if {info[1], info[2]} != {_SF_MASK_8616, _OF_MASK_8616}:
            return None
        other_compare = _canonical_compare_guard_8616(other_guard)
        if other_compare is None:
            return None
        # If branch meaning is already carried by a strict signed compare, the raw
        # SF/OF pair is duplicate flag syntax and not additional branch meaning.
        if other_compare[0] in {"CmpGT", "CmpLT"}:
            return other_guard
        return None

    simplified = _strip(node.lhs, node.rhs)
    if simplified is not None:
        return simplified
    return _strip(node.rhs, node.lhs)


def _extract_nested_flag_bit_predicate_8616(node):
    while isinstance(node, CUnaryOp) and node.op == "Not":
        node = node.operand
    while isinstance(node, CITE):
        values = _bool_cite_values_8616(node)
        if values == (1, 0):
            node = node.cond
            continue
        if values == (0, 1):
            node = node.cond
            continue
        break
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None
    zero = None
    masked = None
    if isinstance(node.lhs, CBinaryOp) and node.lhs.op == "And" and isinstance(node.rhs, CConstant) and node.rhs.value == 0:
        masked = node.lhs
        zero = node.rhs
    elif isinstance(node.rhs, CBinaryOp) and node.rhs.op == "And" and isinstance(node.lhs, CConstant) and node.lhs.value == 0:
        masked = node.rhs
        zero = node.lhs
    if masked is None or zero is None:
        return None
    if isinstance(masked.lhs, CVariable) and isinstance(masked.rhs, CConstant):
        return masked.lhs, masked.rhs.value
    if isinstance(masked.rhs, CVariable) and isinstance(masked.lhs, CConstant):
        return masked.rhs, masked.lhs.value
    return None


def _extract_flag_pair_compare_info_8616(node):
    invert = False
    while True:
        if isinstance(node, CUnaryOp) and node.op == "Not":
            invert = not invert
            node = node.operand
            continue
        if isinstance(node, CITE):
            values = _bool_cite_values_8616(node)
            if values == (1, 0):
                node = node.cond
                continue
            if values == (0, 1):
                invert = not invert
                node = node.cond
                continue
        break
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None
    lhs_info = _extract_nested_flag_bit_predicate_8616(node.lhs)
    rhs_info = _extract_nested_flag_bit_predicate_8616(node.rhs)
    if lhs_info is None or rhs_info is None:
        return None
    lhs_var, lhs_bit = lhs_info
    rhs_var, rhs_bit = rhs_info
    if not _same_c_expression_8616(lhs_var, rhs_var):
        return None
    equality = node.op == "CmpEQ"
    if invert:
        equality = not equality
    return lhs_var, lhs_bit, rhs_bit, equality


def _normalize_bool_compare_guard_8616(node, codegen):
    info = _extract_bool_compare_term_8616(node)
    if info is None:
        if isinstance(node, CBinaryOp) and node.op in {"CmpGT", "CmpGE", "CmpLT", "CmpLE"}:
            return node
        if isinstance(node, CUnaryOp) and node.op == "Not" and isinstance(node.operand, CBinaryOp):
            inverted = _invert_cmp_op_8616(node.operand.op)
            if inverted is not None:
                return CBinaryOp(
                    inverted,
                    node.operand.lhs,
                    node.operand.rhs,
                    codegen=codegen,
                    tags=getattr(node.operand, "tags", None),
                )
        return None
    compare, negated, _template = info
    return _make_bool_expr_from_compare_8616(compare, negated, codegen)


def _same_compare_direction_family_8616(lhs: CBinaryOp, rhs: CBinaryOp) -> bool:
    if lhs.op in {"CmpGT", "CmpGE"} and rhs.op in {"CmpGT", "CmpGE"}:
        return True
    if lhs.op in {"CmpLT", "CmpLE"} and rhs.op in {"CmpLT", "CmpLE"}:
        return True
    return False


def _split_ordering_if_chain_replacement_condition_8616(prev_cond, curr_cond, codegen):
    prev_compare = _normalize_bool_compare_guard_8616(prev_cond, codegen)
    if not isinstance(prev_compare, CBinaryOp) or prev_compare.op not in {"CmpGT", "CmpLT"}:
        return None
    if not isinstance(curr_cond, CBinaryOp) or curr_cond.op != "LogicalAnd":
        return None

    def _strip(flag_guard, low_guard):
        pair_info = _extract_flag_pair_compare_info_8616(flag_guard)
        if pair_info is None:
            return None
        if {pair_info[1], pair_info[2]} != {_SF_MASK_8616, _OF_MASK_8616}:
            return None
        if not pair_info[3]:
            return None
        low_compare = _normalize_bool_compare_guard_8616(low_guard, codegen)
        if not isinstance(low_compare, CBinaryOp) or low_compare.op not in {"CmpGT", "CmpLT"}:
            return None
        if not _same_compare_direction_family_8616(prev_compare, low_compare):
            return None
        if _same_c_expression_8616(prev_compare.lhs, low_compare.lhs) and _same_c_expression_8616(prev_compare.rhs, low_compare.rhs):
            return None
        return low_guard

    replacement = _strip(curr_cond.lhs, curr_cond.rhs)
    if replacement is not None:
        return replacement
    return _strip(curr_cond.rhs, curr_cond.lhs)


def _simplify_split_ordering_if_chain_8616(node: CIfElse, codegen) -> bool:
    pairs = list(getattr(node, "condition_and_nodes", ()) or ())
    if len(pairs) < 2:
        return False

    changed = False
    for idx in range(1, len(pairs)):
        prev_cond, _prev_body = pairs[idx - 1]
        curr_cond, curr_body = pairs[idx]
        replacement = _split_ordering_if_chain_replacement_condition_8616(prev_cond, curr_cond, codegen)
        if replacement is None:
            continue
        pairs[idx] = (replacement, curr_body)
        changed = True

    if changed:
        node.condition_and_nodes = pairs
    return changed


def _rewrite_flag_condition_expr_8616(node, flag_var, flag_expr, codegen):
    changed = False

    def transform(expr):
        nonlocal changed
        combined = _recover_combined_signed_flag_condition_8616(expr, flag_var, flag_expr, codegen)
        if combined is not None:
            changed = True
            return combined
        simplified = _maybe_strip_redundant_signed_flag_pair_guard_8616(expr, flag_var, flag_expr)
        if simplified is not None:
            changed = True
            return simplified
        info = _extract_flag_test_info_8616(expr)
        if info is None or not _same_c_expression_8616(info[0], flag_var):
            return expr
        rewritten = _recover_ordering_condition_from_flag_mask_8616(flag_expr, info, codegen)
        if (
            rewritten is None
            or _c_expr_uses_var_8616(rewritten, flag_var)
            or _expr_uses_raw_flags_register_8616(rewritten, codegen)
        ):
            return expr
        changed = True
        return rewritten

    new_node = transform(node)
    if _replace_c_children_8616(new_node, transform):
        changed = True
    return new_node, changed


def _c_expr_uses_var_8616(node, target) -> bool:
    if node is None:
        return False
    if isinstance(node, CVariable):
        return _same_c_expression_8616(node, target)
    for attr in (
        "lhs",
        "rhs",
        "operand",
        "cond",
        "iftrue",
        "iffalse",
        "expr",
        "condition",
        "else_node",
    ):
        child = getattr(node, attr, None)
        if hasattr(child, "__class__") and child.__class__.__name__.startswith("C"):
            if _c_expr_uses_var_8616(child, target):
                return True
    for attr in ("statements", "operands", "condition_and_nodes"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for item in child:
                if isinstance(item, tuple):
                    for sub in item:
                        if hasattr(sub, "__class__") and sub.__class__.__name__.startswith("C"):
                            if _c_expr_uses_var_8616(sub, target):
                                return True
                elif hasattr(item, "__class__") and item.__class__.__name__.startswith("C"):
                    if _c_expr_uses_var_8616(item, target):
                        return True
    return False


def _rewrite_flag_condition_pairs_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    flags_offset = None
    with_context_arch = getattr(getattr(codegen, "project", None), "arch", None)
    if with_context_arch is not None:
        flags_offset = with_context_arch.registers.get("flags", (None, None))[0]

    def _last_assignment_in_stmt(stmt):
        if isinstance(stmt, CAssignment):
            return stmt, None
        if isinstance(stmt, CStatements) and stmt.statements:
            last = stmt.statements[-1]
            if isinstance(last, CAssignment):
                return last, stmt
        return None, None

    def _is_flags_assignment(stmt) -> bool:
        if flags_offset is None or not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
            return False
        return _c_variable_register_offset_8616(stmt.lhs) == flags_offset

    def _rewrite_condition_with_assignments(cond, assignments: list[tuple[CAssignment, CStatements | None]]):
        nonlocal changed
        if not isinstance(cond, (CBinaryOp, CUnaryOp, CITE, CVariable, CConstant)):
            return cond
        for assign_stmt, _assign_container in reversed(assignments):
            if not _is_flags_assignment(assign_stmt):
                continue
            new_cond, cond_changed = _rewrite_flag_condition_expr_8616(
                cond,
                assign_stmt.lhs,
                assign_stmt.rhs,
                codegen,
            )
            if cond_changed:
                changed = True
                return new_cond
        return cond

    def transform(node, prior_assignments: list[tuple[CAssignment, CStatements | None]] | None = None):
        nonlocal changed
        if not isinstance(node, CStatements):
            return node

        scope_assignments = list(prior_assignments or [])
        new_statements = []
        statements = list(node.statements)
        i = 0
        while i < len(statements):
            stmt = statements[i]
            next_stmt = statements[i + 1] if i + 1 < len(statements) else None

            if isinstance(stmt, CStatements):
                new_stmt = transform(stmt, scope_assignments)
                if new_stmt is not stmt:
                    changed = True
                new_statements.append(new_stmt)
                i += 1
                continue

            if isinstance(stmt, CIfElse) and isinstance(getattr(stmt, "condition_and_nodes", None), list):
                new_pairs = []
                pair_changed = False
                for cond, body in stmt.condition_and_nodes:
                    new_cond = _rewrite_condition_with_assignments(cond, scope_assignments)
                    new_body = body
                    if isinstance(body, CStatements):
                        new_body = transform(body, scope_assignments)
                    pair_changed = pair_changed or (new_cond is not cond) or (new_body is not body)
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    stmt.condition_and_nodes = new_pairs
                    changed = True
                new_statements.append(stmt)
                i += 1
                continue

            matched = False
            assign_stmt, assign_container = _last_assignment_in_stmt(stmt)
            if (
                isinstance(assign_stmt, CAssignment)
                and isinstance(assign_stmt.lhs, CVariable)
                and type(next_stmt).__name__ == "CIfElse"
            ):
                cond_nodes = getattr(next_stmt, "condition_and_nodes", None)
                if isinstance(cond_nodes, list) and cond_nodes:
                    pair_changed = False
                    new_pairs = []
                    for cond, body in cond_nodes:
                        new_cond, cond_changed = _rewrite_flag_condition_expr_8616(
                            cond,
                            assign_stmt.lhs,
                            assign_stmt.rhs,
                            codegen,
                        )
                        pair_changed = pair_changed or cond_changed
                        new_pairs.append((new_cond, body))
                    if pair_changed:
                        next_stmt.condition_and_nodes = new_pairs
                        changed = True
                        later_uses = _c_expr_uses_var_8616(next_stmt, assign_stmt.lhs) or any(
                            _c_expr_uses_var_8616(rest, assign_stmt.lhs) for rest in statements[i + 2 :]
                        )
                        if not later_uses:
                            if assign_container is None:
                                matched = True
                            else:
                                assign_container.statements = assign_container.statements[:-1]

            if not matched:
                new_statements.append(stmt)

            if isinstance(assign_stmt, CAssignment) and isinstance(assign_stmt.lhs, CVariable):
                scope_assignments.append((assign_stmt, assign_container))
            i += 1

        if len(new_statements) != len(node.statements):
            node.statements = new_statements
        return node

    root = codegen.cfunc.statements
    transform(root)
    return changed


def _bool_cite_values_8616(node):
    if not isinstance(node, CITE):
        return None
    iftrue = _c_constant_value_8616(node.iftrue)
    iffalse = _c_constant_value_8616(node.iffalse)
    if iftrue in (0, 1) and iffalse in (0, 1):
        return iftrue, iffalse
    return None


def _extract_bool_compare_term_8616(node):
    negated = False
    if isinstance(node, CUnaryOp) and node.op == "Not":
        negated = True
        node = node.operand
    if not isinstance(node, CITE):
        return None
    values = _bool_cite_values_8616(node)
    if values is None:
        return None
    if values == (1, 0):
        effective_negated = negated
    elif values == (0, 1):
        effective_negated = not negated
    else:
        return None
    compare = node.cond
    if not isinstance(compare, CBinaryOp):
        return None
    if compare.op not in {"CmpGT", "CmpGE", "CmpLT", "CmpLE"}:
        return None
    return compare, effective_negated, node


def _make_bool_cite_8616(template: CITE, negated: bool, codegen):
    values = _bool_cite_values_8616(template)
    if values is None:
        return template
    zero = CConstant(0, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
    one = CConstant(1, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
    if negated:
        return CITE(template.cond, zero, one, tags=getattr(template, "tags", None), codegen=codegen)
    return CITE(template.cond, one, zero, tags=getattr(template, "tags", None), codegen=codegen)


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
    }.get(op)


def _make_bool_expr_from_compare_8616(compare: CBinaryOp, negated: bool, codegen):
    if negated:
        inverted = _invert_cmp_op_8616(compare.op)
        if inverted is not None:
            return CBinaryOp(
                inverted,
                compare.lhs,
                compare.rhs,
                codegen=codegen,
                tags=getattr(compare, "tags", None),
            )
    return CBinaryOp(
        compare.op,
        compare.lhs,
        compare.rhs,
        codegen=codegen,
        tags=getattr(compare, "tags", None),
    )


def _fix_impossible_interval_guard_expr_8616(node, codegen):
    simplified_signed = _maybe_strip_standalone_signed_flag_pair_guard_8616(node)
    if simplified_signed is not None:
        return simplified_signed
    if not isinstance(node, CBinaryOp) or node.op != "LogicalAnd":
        return node
    left_info = _extract_bool_compare_term_8616(node.lhs)
    right_info = _extract_bool_compare_term_8616(node.rhs)
    if left_info is None or right_info is None:
        return node
    left_cmp, left_negated, left_template = left_info
    right_cmp, right_negated, right_template = right_info
    if not _same_c_expression_8616(left_cmp.rhs, right_cmp.rhs):
        return node

    low_ops = {"CmpGT", "CmpGE"}
    high_ops = {"CmpLT", "CmpLE"}

    if left_cmp.op in low_ops and right_cmp.op in high_ops and not left_negated and not right_negated:
        return CBinaryOp(
            "LogicalAnd",
            _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
            _make_bool_expr_from_compare_8616(right_cmp, True, codegen),
            codegen=codegen,
            tags=getattr(node, "tags", None),
        )

    if left_cmp.op in low_ops and right_cmp.op == "CmpGE" and not left_negated and right_negated:
        return CBinaryOp(
            "LogicalAnd",
            _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
            _make_bool_expr_from_compare_8616(right_cmp, False, codegen),
            codegen=codegen,
            tags=getattr(node, "tags", None),
        )

    return node


def _fix_interval_guard_conditions_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    changed = False

    def transform(node):
        nonlocal changed
        if isinstance(node, CIfElse) and _simplify_split_ordering_if_chain_8616(node, codegen):
            changed = True
            return node
        fixed = _fix_impossible_interval_guard_expr_8616(node, codegen)
        if fixed is not node:
            changed = True
            return fixed
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root

    if _replace_c_children_8616(root, transform):
        changed = True
    return changed


def _prune_unused_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(root):
        traversal_stack = [(root, False)]
        seen: set[int] = set()
        while traversal_stack:
            node, assignment_lhs = traversal_stack.pop()
            if not _structured_codegen_node_8616(node):
                continue

            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)

            if isinstance(node, CVariable) and not assignment_lhs:
                variable = getattr(node, "variable", None)
                if variable is not None:
                    used_variables.add(id(variable))
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                        used_registers.add(variable.reg)
                unified = getattr(node, "unified_variable", None)
                if unified is not None:
                    used_variables.add(id(unified))
                    if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                        used_registers.add(unified.reg)
                continue

            for attr in ("rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "callee_target", "else_node", "retval"):
                child = getattr(node, attr, None)
                if _structured_codegen_node_8616(child):
                    traversal_stack.append((child, False))

            lhs = getattr(node, "lhs", None)
            if _structured_codegen_node_8616(lhs):
                traversal_stack.append((lhs, isinstance(node, CAssignment)))

            for attr in ("args", "operands", "statements"):
                seq = getattr(node, attr, None)
                if not seq:
                    continue
                for item in seq:
                    if _structured_codegen_node_8616(item):
                        traversal_stack.append((item, False))
                        continue
                    if isinstance(item, tuple):
                        for subitem in item:
                            if _structured_codegen_node_8616(subitem):
                                traversal_stack.append((subitem, False))

            pairs = getattr(node, "condition_and_nodes", None)
            if pairs:
                for cond, body in pairs:
                    if _structured_codegen_node_8616(cond):
                        traversal_stack.append((cond, False))
                    if _structured_codegen_node_8616(body):
                        traversal_stack.append((body, False))

    collect_reads(codegen.cfunc.statements)

    changed = False

    stack = [codegen.cfunc.statements]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if not _structured_codegen_node_8616(node):
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)

        if isinstance(node, CStatements):
            new_statements = []
            for stmt in getattr(node, "statements", ()):
                if (
                    isinstance(stmt, CAssignment)
                    and isinstance(stmt.lhs, CVariable)
                    and _c_variable_register_offset_8616(stmt.lhs) == flags_offset
                ):
                    variable = getattr(stmt.lhs, "variable", None)
                    unified = getattr(stmt.lhs, "unified_variable", None)
                    if (
                        all(id(candidate) not in used_variables for candidate in (variable, unified) if candidate is not None)
                        and flags_offset not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
                if _structured_codegen_node_8616(stmt):
                    stack.append(stmt)

            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                stack.append(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    stack.append(body)
    return changed


def _c_expr_uses_register_8616(node, reg_offset: int) -> bool:
    if not _structured_codegen_node_8616(node):
        return False

    traversal_stack = [node]
    seen: set[int] = set()
    while traversal_stack:
        current = traversal_stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)

        if isinstance(current, CVariable):
            if _c_variable_register_offset_8616(current) == reg_offset:
                return True
            continue

        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iftrue", "iffalse", "callee_target", "else_node", "retval"):
            child = getattr(current, attr, None)
            if _structured_codegen_node_8616(child):
                traversal_stack.append(child)

        for attr in ("args", "operands", "statements"):
            seq = getattr(current, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    traversal_stack.append(item)
                    continue
                if isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            traversal_stack.append(subitem)

        pairs = getattr(current, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    traversal_stack.append(cond)
                if _structured_codegen_node_8616(body):
                    traversal_stack.append(body)

    return False


def _stmt_reads_reg_before_write_8616(stmt, reg_offset: int) -> tuple[bool, bool]:
    if not _structured_codegen_node_8616(stmt):
        return False, False

    if isinstance(stmt, CAssignment):
        lhs = stmt.lhs
        writes = isinstance(lhs, CVariable) and _c_variable_register_offset_8616(lhs) == reg_offset
        reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
        return reads, writes

    if isinstance(stmt, CStatements):
        for substmt in stmt.statements:
            reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
            if reads:
                return True, writes
            if writes:
                return False, True
        return False, False

    if type(stmt).__name__ == "CIfElse":
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        for cond, body in cond_nodes:
            if _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
            if reads:
                return True, writes
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
            if reads:
                return True, writes
        return False, False

    if type(stmt).__name__ == "CWhileLoop":
        cond = getattr(stmt, "condition", None)
        if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
            return True, False
        body = getattr(stmt, "body", None)
        if body is not None:
            return _stmt_reads_reg_before_write_8616(body, reg_offset)
        return False, False

    return _c_expr_uses_register_8616(stmt, reg_offset), False


def _prune_overwritten_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    stack = [codegen.cfunc.statements]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if not _structured_codegen_node_8616(node):
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)

        if isinstance(node, CStatements):
            new_statements = []
            statements = list(getattr(node, "statements", ()))
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    if _c_variable_register_offset_8616(stmt.lhs) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if remove:
                    changed = True
                    continue
                new_statements.append(stmt)
                stack.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                stack.append(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    stack.append(body)

    return changed
