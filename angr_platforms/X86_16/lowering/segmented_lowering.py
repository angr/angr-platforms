from __future__ import annotations

# Layer: Lowering
# Responsibility: typed segmented-address classification and SS/DS/ES lowering helpers.
# Forbidden: CLI formatting, rendered-text pattern recovery, late postprocess ownership.

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable


@dataclass(frozen=True)
class _SegmentedAccess:
    kind: str
    seg_name: str | None
    assoc_kind: str = "unknown"
    assoc_state: object | None = None
    linear: int | None = None
    cvar: structured_c.CVariable | None = None
    stack_var: SimStackVariable | None = None
    extra_offset: int = 0
    addr_expr: object | None = None

    def allows_object_rewrite(self) -> bool:
        if self.assoc_state is not None and hasattr(self.assoc_state, "is_over_associated"):
            return not self.assoc_state.is_over_associated()
        return self.assoc_kind != "over"


@dataclass(frozen=True)
class _SegmentAssociationState:
    seg_name: str | None
    base_terms: int = 0
    other_terms: int = 0
    const_offset: int = 0
    stack_slots: tuple[object, ...] = ()

    @property
    def assoc_kind(self) -> str:
        if self.seg_name is None:
            return "unknown"
        if len(self.stack_slots) > 1:
            return "over"
        if self.base_terms == 0:
            return "const" if self.other_terms == 0 else "over"
        if self.other_terms > 0:
            return "over"
        return "single"

    def is_over_associated(self) -> bool:
        return self.assoc_kind == "over"


def _segment_reg_name(node, project, *, project_rewrite_cache):
    cache = project_rewrite_cache(project).setdefault("segment_reg_name", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CVariable):
        cache[key] = None
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        cache[key] = None
        return None
    result = project.arch.register_names.get(variable.reg)
    cache[key] = result
    return result


def _classify_segmented_addr_expr(
    node,
    project,
    *,
    project_rewrite_cache,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    match_stack_cvar_and_offset,
    normalize_16bit_signed_offset,
    stack_slot_identity_for_variable,
):
    cache = project_rewrite_cache(project).setdefault("segmented_addr_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    seg_name = None
    cvar = None
    stack_var = None
    const_offset = 0
    other_terms = []
    base_terms = 0
    stack_slots: list[object] = []
    resolved_term_cache: dict[int, object] = {}

    def _synthetic_sp_anchor(term):
        if not isinstance(term, structured_c.CVariable):
            return None
        variable = getattr(term, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return None
        sp_offset = getattr(getattr(project, "arch", None), "registers", {}).get("sp", (None, None))[0]
        if not isinstance(sp_offset, int) or getattr(variable, "reg", None) != sp_offset:
            return None
        codegen = getattr(term, "codegen", None)
        region = getattr(getattr(codegen, "cfunc", None), "addr", None)
        synthetic = SimStackVariable(0, getattr(variable, "size", None) or 2, base="sp", name="sp_0", region=region)
        return structured_c.CVariable(synthetic, variable_type=getattr(term, "variable_type", None), codegen=codegen), 0

    def _synthetic_sp_match(term):
        synthetic = _synthetic_sp_anchor(term)
        if synthetic is not None:
            return synthetic
        if not isinstance(term, structured_c.CBinaryOp) or term.op not in {"Add", "Sub"}:
            return None
        lhs = _synthetic_sp_anchor(unwrap_c_casts(term.lhs))
        rhs = _synthetic_sp_anchor(unwrap_c_casts(term.rhs))
        lhs_const = c_constant_value(unwrap_c_casts(term.lhs))
        rhs_const = c_constant_value(unwrap_c_casts(term.rhs))
        if lhs is not None and rhs_const is not None:
            base, offset = lhs
            return base, offset + (rhs_const if term.op == "Add" else -rhs_const)
        if rhs is not None and lhs_const is not None and term.op == "Add":
            base, offset = rhs
            return base, offset + lhs_const
        return None

    def _segment_scale_name(term) -> str | None:
        if not isinstance(term, structured_c.CBinaryOp):
            return None
        if term.op == "Mul":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                local_seg = _segment_reg_name(
                    unwrap_c_casts(maybe_seg),
                    project,
                    project_rewrite_cache=project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
            return None
        if term.op == "Shl":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 4:
                    continue
                local_seg = _segment_reg_name(
                    unwrap_c_casts(maybe_seg),
                    project,
                    project_rewrite_cache=project_rewrite_cache,
                )
                if local_seg is not None:
                    return local_seg
        return None

    def _iter_statement_nodes(root):
        stack = [root]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if not isinstance(current, structured_c.CConstruct):
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            yield current

            nested_statements = getattr(current, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                for item in reversed(tuple(nested_statements)):
                    stack.append(item)
            body = getattr(current, "body", None)
            if body is not None:
                stack.append(body)
            else_node = getattr(current, "else_node", None)
            if else_node is not None:
                stack.append(else_node)
            condition_and_nodes = getattr(current, "condition_and_nodes", None)
            if isinstance(condition_and_nodes, (list, tuple)):
                for pair in reversed(tuple(condition_and_nodes)):
                    if isinstance(pair, tuple):
                        for item in reversed(pair):
                            stack.append(item)

    def _single_assignment_rhs_for_cvar(term):
        if not isinstance(term, structured_c.CVariable):
            return None
        term_var = getattr(term, "variable", None)
        term_name = getattr(term, "name", None) or getattr(term_var, "name", None)
        term_reg = getattr(term_var, "reg", None)
        term_size = getattr(term_var, "size", None)
        codegen = getattr(term, "codegen", None)
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        if root is None:
            return None

        def _same_lhs(lhs) -> bool:
            if not isinstance(lhs, structured_c.CVariable):
                return False
            lhs_var = getattr(lhs, "variable", None)
            if lhs_var is term_var:
                return True
            lhs_name = getattr(lhs, "name", None) or getattr(lhs_var, "name", None)
            if isinstance(term_name, str) and term_name and lhs_name == term_name:
                return True
            lhs_reg = getattr(lhs_var, "reg", None)
            lhs_size = getattr(lhs_var, "size", None)
            return (
                isinstance(term_reg, int)
                and isinstance(term_size, int)
                and isinstance(lhs_reg, int)
                and isinstance(lhs_size, int)
                and lhs_reg == term_reg
                and lhs_size == term_size
            )

        matches = []
        for stmt in _iter_statement_nodes(root):
            if not isinstance(stmt, structured_c.CAssignment):
                continue
            if not _same_lhs(getattr(stmt, "lhs", None)):
                continue
            matches.append(getattr(stmt, "rhs", None))
            if len(matches) > 1:
                return None
        return matches[0] if len(matches) == 1 else None

    def _resolve_term_aliases(term):
        current = unwrap_c_casts(term)
        seen_ids: set[int] = set()
        while isinstance(current, structured_c.CVariable):
            key = id(current)
            if key in resolved_term_cache:
                return resolved_term_cache[key]
            if key in seen_ids:
                break
            seen_ids.add(key)
            rhs = _single_assignment_rhs_for_cvar(current)
            if rhs is None:
                break
            rhs_unwrapped = unwrap_c_casts(rhs)
            if rhs_unwrapped is current:
                break
            resolved_term_cache[key] = rhs_unwrapped
            current = rhs_unwrapped
        return current

    for term in flatten_c_add_terms(node):
        inner = _resolve_term_aliases(term)
        local_seg = _segment_scale_name(inner)
        if local_seg is not None:
            seg_name = local_seg
            continue

        constant = c_constant_value(inner)
        if constant is not None:
            const_offset += constant
            continue

        matched_stack = match_stack_cvar_and_offset(inner)
        if matched_stack is None:
            matched_stack = _synthetic_sp_match(inner)
        if matched_stack is not None:
            matched_cvar, stack_offset = matched_stack
            stack_offset = normalize_16bit_signed_offset(stack_offset)
            matched_var = getattr(matched_cvar, "variable", None)
            current_var = getattr(cvar, "variable", None) if cvar is not None else None
            if cvar is None:
                cvar = matched_cvar
                if isinstance(matched_var, SimStackVariable):
                    stack_var = matched_var
                    identity = stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            elif current_var is matched_var:
                if isinstance(matched_var, SimStackVariable):
                    identity = stack_slot_identity_for_variable(matched_var)
                    if identity is not None:
                        if not stack_slots:
                            stack_slots.append(identity)
                        elif stack_slots[0] == identity:
                            pass
                        elif hasattr(stack_slots[0], "can_join") and stack_slots[0].can_join(identity):
                            joined_identity = stack_slots[0].join(identity)
                            if joined_identity is not None:
                                stack_slots[0] = joined_identity
                        else:
                            stack_slots.append(identity)
                const_offset += stack_offset
                base_terms += 1
            else:
                other_terms.append(term)
            continue

        other_terms.append(term)

    if seg_name is None:
        cache[key] = None
        return None

    assoc_state = _SegmentAssociationState(
        seg_name=seg_name,
        base_terms=base_terms,
        other_terms=len(other_terms),
        const_offset=const_offset,
        stack_slots=tuple(stack_slots),
    )
    assoc_kind = assoc_state.assoc_kind

    if seg_name == "ss" and cvar is not None and not other_terms:
        normalized_offset = normalize_16bit_signed_offset(const_offset)
        result = _SegmentedAccess(
            "stack",
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            cvar=cvar,
            stack_var=stack_var,
            extra_offset=normalized_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    if cvar is None and not other_terms:
        if seg_name == "es":
            kind = "extra"
            linear = const_offset
        else:
            kind = "segment_const"
            linear = const_offset
        result = _SegmentedAccess(
            kind,
            seg_name,
            assoc_kind=assoc_kind,
            assoc_state=assoc_state,
            linear=linear,
            extra_offset=const_offset,
            addr_expr=node,
        )
        cache[key] = result
        return result

    result = _SegmentedAccess(
        "unknown",
        seg_name,
        assoc_kind=assoc_kind,
        assoc_state=assoc_state,
        linear=const_offset if cvar is None else None,
        cvar=cvar,
        stack_var=stack_var,
        extra_offset=const_offset,
        addr_expr=node,
    )
    cache[key] = result
    return result


def _classify_segmented_dereference(node, project, *, project_rewrite_cache, classify_segmented_addr_expr):
    cache = project_rewrite_cache(project).setdefault("segmented_dereference_class", {})
    key = id(node)
    if key in cache:
        return cache[key]

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        cache[key] = None
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        operand = operand.expr
    result = classify_segmented_addr_expr(operand, project)
    cache[key] = result
    return result


def _match_real_mode_linear_expr(node, project, *, project_rewrite_cache, classify_segmented_addr_expr):
    cache = project_rewrite_cache(project).setdefault("real_mode_linear_expr", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_addr_expr(node, project)
    if classified is None or classified.kind not in {"extra", "segment_const"}:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result


def _match_segmented_dereference(node, project, *, project_rewrite_cache, classify_segmented_dereference):
    cache = project_rewrite_cache(project).setdefault("segmented_dereference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.linear is None:
        cache[key] = (None, None)
        return None, None
    result = (classified.seg_name, classified.linear)
    cache[key] = result
    return result
