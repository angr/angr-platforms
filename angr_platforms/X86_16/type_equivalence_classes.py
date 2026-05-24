from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Set

from .ir.core import IRAddress, IRCondition, MemSpace, SegmentOrigin

logger = logging.getLogger(__name__)


def _typed_ir_summary_from_codegen(codegen) -> dict[str, object]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        summary = getattr(codegen, "_inertia_vex_ir_summary", None)
        return dict(summary) if isinstance(summary, dict) else {}

    provisional_addresses = 0
    multi_base_addresses = 0
    segment_origin_counts = {origin.value: 0 for origin in SegmentOrigin}
    condition_counts: dict[str, int] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            for atom in tuple(getattr(instr, "args", ()) or ()):
                if isinstance(atom, IRAddress):
                    if getattr(atom, "status", None) is not None and getattr(atom.status, "value", "") == "provisional":
                        provisional_addresses += 1
                    if len(getattr(atom, "base", ()) or ()) > 1:
                        multi_base_addresses += 1
                    origin = getattr(getattr(atom, "segment_origin", None), "value", "unknown")
                    segment_origin_counts[origin] = segment_origin_counts.get(origin, 0) + 1
                elif isinstance(atom, IRCondition):
                    op = str(getattr(atom, "op", "unknown"))
                    condition_counts[op] = condition_counts.get(op, 0) + 1

    summary = getattr(codegen, "_inertia_vex_ir_summary", None)
    base = dict(summary) if isinstance(summary, dict) else {}
    base["provisional_address_count"] = provisional_addresses
    base["multi_base_address_count"] = multi_base_addresses
    base["segment_origin_counts"] = dict(sorted(segment_origin_counts.items()))
    if condition_counts:
        base["condition_counts"] = dict(sorted(condition_counts.items()))
    return base


@dataclass(frozen=True)
class ExpressionPattern:
    pattern_type: str
    base_expr: Optional[str]
    offset: Optional[int]
    stride: Optional[int]
    width: int

    def __repr__(self) -> str:
        if self.pattern_type == "pointer_add":
            return f"ptr({self.base_expr} + {self.offset} * {self.stride})"
        elif self.pattern_type == "memory_load":
            return f"mem[{self.base_expr}]:{self.width}"
        else:
            return f"{self.pattern_type}:{self.width}"


@dataclass
class EquivalenceClass:
    class_id: int
    expressions: Set[str] = field(default_factory=set)
    type_constraints: Set[str] = field(default_factory=set)
    width: int = 0

    def add_expression(self, expr: str) -> None:
        self.expressions.add(expr)

    def add_type_constraint(self, constraint: str) -> None:
        self.type_constraints.add(constraint)

    def merge(self, other: EquivalenceClass) -> None:
        self.expressions.update(other.expressions)
        self.type_constraints.update(other.type_constraints)
        self.width = max(self.width, other.width)


class ExpressionNormalizer:
    def normalize(self, expr: str) -> ExpressionPattern:
        return ExpressionPattern(
            pattern_type="variable",
            base_expr=expr,
            offset=None,
            stride=None,
            width=16,
        )


class EquivalenceClassBuilder:
    def __init__(self) -> None:
        self.next_class_id = 0
        self.expr_to_class: dict[str, int] = {}
        self.classes: dict[int, EquivalenceClass] = {}

    def build(self, expressions: list[str]) -> dict[int, EquivalenceClass]:
        for expr in expressions:
            if expr not in self.expr_to_class:
                class_id = self.next_class_id
                self.classes[class_id] = EquivalenceClass(class_id=class_id)
                self.classes[class_id].add_expression(expr)
                self.expr_to_class[expr] = class_id
                self.next_class_id += 1
        return self.classes

    def merge_classes(self, expr1: str, expr2: str) -> None:
        if expr1 not in self.expr_to_class or expr2 not in self.expr_to_class:
            return

        class_id1 = self.expr_to_class[expr1]
        class_id2 = self.expr_to_class[expr2]

        if class_id1 == class_id2:
            return

        class1 = self.classes[class_id1]
        class2 = self.classes[class_id2]
        class1.merge(class2)
        for expr in class2.expressions:
            self.expr_to_class[expr] = class_id1
        self.classes.pop(class_id2)


class TypeCollector:
    def collect(self, expr_classes: dict[int, EquivalenceClass]) -> None:
        for eq_class in expr_classes.values():
            for expr in eq_class.expressions:
                if "_offset" in expr or "+" in expr:
                    eq_class.add_type_constraint("pointer")
                elif any(op in expr for op in ["*", "<<", ">>"]):
                    eq_class.add_type_constraint("integer")


def _expr_key_for_value(value) -> str | None:
    name = getattr(value, "name", None)
    if name:
        return f"value:{str(getattr(value, 'space', 'unknown')).lower()}:{name}"
    const = getattr(value, "const", None)
    if const is not None:
        return f"const:{int(const)}"
    return None


def _expr_key_for_address(address: IRAddress) -> str | None:
    base = tuple(getattr(address, "base", ()) or ())
    if not base:
        return None
    space = getattr(getattr(address, "space", None), "value", "unknown")
    return f"base:{space}:{'+'.join(base)}"


def _typed_ir_equivalence_from_codegen(codegen) -> tuple[dict[int, EquivalenceClass], dict[str, str]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}, {}
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)

    builder = EquivalenceClassBuilder()
    exprs: list[str] = []
    typed_constraints: dict[str, set[str]] = {}
    merges: list[tuple[str, str]] = []

    def ensure_expr(expr: str | None) -> None:
        if expr is None:
            return
        if expr not in exprs:
            exprs.append(expr)

    def add_constraint(expr: str | None, constraint: str) -> None:
        if expr is None:
            return
        ensure_expr(expr)
        typed_constraints.setdefault(expr, set()).add(constraint)

    def add_merge(left: str | None, right: str | None) -> None:
        if left is None or right is None or left == right:
            return
        ensure_expr(left)
        ensure_expr(right)
        merges.append((left, right))

    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            dst_key = _expr_key_for_value(getattr(instr, "dst", None))
            ensure_expr(dst_key)
            for atom in tuple(getattr(instr, "args", ()) or ()):
                if isinstance(atom, IRAddress):
                    base_key = _expr_key_for_address(atom)
                    status_value = getattr(getattr(atom, "status", None), "value", "")
                    if base_key is not None and status_value not in {"unknown", "provisional"}:
                        add_constraint(base_key, "pointer")
                    elif base_key is not None:
                        add_constraint(base_key, "address_like")
                elif isinstance(atom, IRCondition):
                    add_constraint(f"cond:{atom.op}", "boolean")
                    for cond_arg in tuple(getattr(atom, "args", ()) or ()):
                        add_constraint(_expr_key_for_value(cond_arg), "integer")
                else:
                    ensure_expr(_expr_key_for_value(atom))

    for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ()):
        target = getattr(phi, "target", None)
        if target is None:
            continue
        phi_key = _expr_key_for_value(target)
        add_constraint(phi_key, "ssa_join")
        if getattr(target, "space", None) == MemSpace.REG:
            add_constraint(phi_key, "integer")
        for incoming in tuple(getattr(phi, "incoming", ()) or ()):
            incoming_key = _expr_key_for_value(getattr(incoming, "value", None))
            add_merge(phi_key, incoming_key)

    if not exprs:
        return {}, {}

    classes = builder.build(exprs)
    for left, right in merges:
        builder.merge_classes(left, right)
    for expr, constraints in typed_constraints.items():
        class_id = builder.expr_to_class.get(expr)
        if class_id is None:
            continue
        for constraint in sorted(constraints):
            classes[class_id].add_type_constraint(constraint)

    resolved = TypeVariableReplacer().replace(classes)
    resolved_by_expr = {
        expr: resolved[class_id]
        for expr, class_id in builder.expr_to_class.items()
        if class_id in resolved
    }
    return classes, dict(sorted(resolved_by_expr.items()))


class TypeVariableReplacer:
    def replace(self, expr_classes: dict[int, EquivalenceClass]) -> dict[int, str]:
        resolved_types: dict[int, str] = {}

        for class_id, eq_class in expr_classes.items():
            if "pointer" in eq_class.type_constraints:
                resolved_types[class_id] = "ptr_t"
            elif "boolean" in eq_class.type_constraints:
                resolved_types[class_id] = "bool_t"
            elif "address_like" in eq_class.type_constraints:
                resolved_types[class_id] = "address_like_t"
            elif "integer" in eq_class.type_constraints:
                resolved_types[class_id] = "int_t"
            else:
                resolved_types[class_id] = "void_t"

        return resolved_types


def apply_x86_16_type_equivalence_classes(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        codegen._inertia_type_equivalence_applied = True
        ir_summary = _typed_ir_summary_from_codegen(codegen)
        typed_classes, resolved_by_expr = _typed_ir_equivalence_from_codegen(codegen)
        if isinstance(ir_summary, dict):
            codegen._inertia_type_equivalence_ir_summary = {
                "aliasable_value_count": int(ir_summary.get("aliasable_value_count", 0) or 0),
                "frame_slot_count": int(ir_summary.get("frame_slot_count", 0) or 0),
                "space_counts": dict(ir_summary.get("space_counts", {}) or {}),
                "provisional_address_count": int(ir_summary.get("provisional_address_count", 0) or 0),
                "multi_base_address_count": int(ir_summary.get("multi_base_address_count", 0) or 0),
                "segment_origin_counts": dict(ir_summary.get("segment_origin_counts", {}) or {}),
                "condition_counts": dict(ir_summary.get("condition_counts", {}) or {}),
            }
        function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
        codegen._inertia_type_equivalence_resolved_types = resolved_by_expr
        codegen._inertia_type_equivalence_classes = {
            class_id: {
                "expressions": tuple(sorted(eq_class.expressions)),
                "type_constraints": tuple(sorted(eq_class.type_constraints)),
                "width": eq_class.width,
            }
            for class_id, eq_class in sorted(typed_classes.items())
        }
        codegen._inertia_type_equivalence_stats = {
            "equivalence_classes": len(typed_classes),
            "type_constraints": sum(len(eq_class.type_constraints) for eq_class in typed_classes.values()),
            "resolved_types": len(resolved_by_expr),
            "ir_aliasable_values": int(ir_summary.get("aliasable_value_count", 0) or 0) if isinstance(ir_summary, dict) else 0,
            "ir_frame_slots": int(ir_summary.get("frame_slot_count", 0) or 0) if isinstance(ir_summary, dict) else 0,
            "ir_provisional_addresses": int(ir_summary.get("provisional_address_count", 0) or 0) if isinstance(ir_summary, dict) else 0,
            "ir_multi_base_addresses": int(ir_summary.get("multi_base_address_count", 0) or 0) if isinstance(ir_summary, dict) else 0,
            "ir_phi_nodes": int(getattr(function_ssa, "summary", {}).get("phi_node_count", 0) or 0) if function_ssa is not None else 0,
        }

        logger.debug("Type equivalence class pass completed")
        return False
    except Exception as ex:
        logger.warning("Type equivalence class pass failed: %s", ex)
        codegen._inertia_type_equivalence_error = str(ex)
        return False
