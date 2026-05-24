from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c


def run_typed_widening_pass_8616(
    project,
    codegen,
    *,
    coalesce_direct_ss_local_word_statements,
    coalesce_segmented_word_store_statements,
    copy_propagation_fn=None,
) -> bool:
    """
    Execute widening-owned passes in deterministic order.

    Order:
    1. Word-store coalescing (SROA-like)
    2. Copy propagation (EarlyCSE-like)
    3. Load/store folding (GVN-like)

    This pass is the widening ownership boundary: callers provide typed helpers,
    widening decides pass ordering and changed-state aggregation.
    """
    changed = False
    changed = coalesce_direct_ss_local_word_statements(project, codegen) or changed
    changed = coalesce_segmented_word_store_statements(project, codegen) or changed
    if copy_propagation_fn is not None:
        changed = copy_propagation_fn(codegen) or changed
    return changed


def _coalesce_direct_ss_local_word_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_shift_right_8_expr,
    stack_slot_identity_can_join,
    same_c_expression,
    unwrap_c_casts,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    match_byte_store_addr_expr,
    addr_exprs_are_byte_pair,
    resolve_stack_cvar_from_addr_expr,
    canonicalize_stack_cvar_expr,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    replacement = None
                    replacement_lhs = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            high_expr = match_shift_right_8_expr(next_stmt.rhs)
                            if (
                                extra_offset == 1
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                                and high_expr is not None
                                and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                            ):
                                replacement_lhs = stmt.lhs

                    if replacement_lhs is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        high_expr = match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and high_expr is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                            and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                        ):
                            resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                            if isinstance(resolved_lhs, structured_c.CVariable):
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)

                    if isinstance(replacement_lhs, structured_c.CVariable):
                        if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, stack_type_for_size(2)):
                            changed = True
                        replacement = structured_c.CAssignment(replacement_lhs, stmt.rhs, codegen=codegen)

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return changed


def _coalesce_segmented_word_store_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_word_rhs_from_byte_pair,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    stack_slot_identity_can_join,
    canonicalize_stack_cvar_expr,
    match_byte_store_addr_expr,
    addr_exprs_are_byte_pair,
    resolve_stack_cvar_from_addr_expr,
    make_word_dereference_from_addr_expr,
    classify_segmented_addr_expr,
    describe_alias_storage,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = stack_type_for_size(2)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and isinstance(target_cvar, structured_c.CVariable)
                                and target_cvar is not None
                                and rhs_word is not None
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                            ):
                                replacement_lhs = canonicalize_stack_cvar_expr(stmt.lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            low_facts = describe_alias_storage(low_addr_expr)
                            high_facts = describe_alias_storage(high_addr_expr)
                            low_class = classify_segmented_addr_expr(low_addr_expr, project)
                            high_class = classify_segmented_addr_expr(high_addr_expr, project)
                            joinable_segment_const_pair = (
                                low_class is not None
                                and high_class is not None
                                and low_class.kind == high_class.kind == "segment_const"
                                and low_class.seg_name == high_class.seg_name
                                and low_class.linear is not None
                                and high_class.linear == low_class.linear + 1
                            )
                            joinable_stack_alias_pair = (
                                low_class is not None
                                and low_class.kind == "stack"
                                and high_class is None
                            )
                            if (
                                (low_facts.identity is None or high_facts.identity is None or not low_facts.can_join(high_facts))
                                and not joinable_segment_const_pair
                                and not joinable_stack_alias_pair
                            ):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            if low_class is not None and low_class.kind == "stack":
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                if resolved_lhs is None:
                                    visit(stmt)
                                    new_statements.append(stmt)
                                    i += 1
                                    continue
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)
                            else:
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                replacement = structured_c.CAssignment(
                                    resolved_lhs if resolved_lhs is not None else make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                    rhs_word,
                                    codegen=codegen,
                                )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return changed
