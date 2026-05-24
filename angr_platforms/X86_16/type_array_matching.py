"""
Array expression matching for Inertia decompiler Phase 2.2.

Detects array access patterns (base + index * stride + offset)
and loop induction variables with stride to enable array subscript
recovery instead of raw pointer arithmetic.

Pattern: base[index * stride + offset]
Evidence: loop-carried stride patterns, consistent field access
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Set

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CForLoop,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia_decompiler.cli_access_profiles import (
    build_access_trait_evidence_profiles,
    infer_induction_variable,
)

from .ir.core import IRAddress
from .type_storage_object_bridge import load_storage_object_bridge
from .decompiler_postprocess_utils import _replace_c_children_8616, _same_c_expression_8616

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
MAX_TYPED_ARRAY_CANDIDATES = 64


def _limit_sorted_mapping_8616(mapping: dict, limit: int) -> dict:
    if limit <= 0 or len(mapping) <= limit:
        return mapping
    return dict(list(mapping.items())[:limit])


def _typed_ir_array_candidates(codegen) -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}

    phi_registers = {
        getattr(phi.target, "name", None)
        for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ())
        if getattr(getattr(phi, "target", None), "name", None) is not None
    }
    candidates: dict[tuple[str, tuple[str, ...], int], dict[str, object]] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            for atom in tuple(getattr(instr, "args", ()) or ()):
                if not isinstance(atom, IRAddress):
                    continue
                if len(getattr(atom, "base", ()) or ()) < 2:
                    continue
                if not phi_registers.intersection(set(atom.base)):
                    continue
                key = (atom.space.value, tuple(atom.base), int(atom.size or 0))
                candidates[key] = {
                    "space": atom.space.value,
                    "base": tuple(atom.base),
                    "element_size": int(atom.size or 0),
                    "has_phi_index": True,
                }
    return dict(sorted(candidates.items()))


def _typed_string_array_candidates(codegen) -> dict[tuple[str, tuple[str, ...], int], dict[str, object]]:
    artifact = getattr(codegen, "_inertia_string_effect_artifact", None)
    if artifact is None or not hasattr(artifact, "records"):
        return {}

    candidates: dict[tuple[str, tuple[str, ...], int], dict[str, object]] = {}
    for record in tuple(getattr(artifact, "records", ()) or ()):
        for role, address in (("source", record.source), ("destination", record.destination)):
            if not isinstance(address, IRAddress):
                continue
            if not address.base:
                continue
            if address.status.value != "stable":
                continue
            key = (address.space.value, tuple(address.base), int(address.size or 0))
            candidates[key] = {
                "space": address.space.value,
                "base": tuple(address.base),
                "element_size": int(address.size or 0),
                "has_string_effect": True,
                "segment_origin": address.segment_origin.value,
                "string_family": record.family,
                "repeat_kind": record.repeat_kind,
                "role": role,
            }
    return dict(sorted(candidates.items()))


def _cached_access_trait_profiles_8616(project, func_addr: int):
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or func_addr not in traits_cache:
        return None
    traits = traits_cache.get(func_addr)
    if not isinstance(traits, dict):
        return None

    profile_cache = getattr(project, "_inertia_access_trait_profiles_cache", None)
    if not isinstance(profile_cache, dict):
        profile_cache = {}
        setattr(project, "_inertia_access_trait_profiles_cache", profile_cache)

    cache_key = (func_addr, id(traits))
    profiles = profile_cache.get(cache_key)
    if profiles is None:
        profiles = build_access_trait_evidence_profiles(traits)
        profile_cache[cache_key] = profiles
    return profiles


@dataclass(frozen=True)
class InductionVariable:
    """Represents a loop-carried induction variable with stride."""

    var_name: str
    stride: int  # Bytes per iteration
    base_value: int  # Initial value
    loop_bound: Optional[int]  # Upper bound if known
    element_width: int  # Bit width of element (8, 16, 32)

    def __repr__(self) -> str:
        return f"IndVar({self.var_name}, stride={self.stride}, width={self.element_width})"


@dataclass
class ArrayAccessPattern:
    """Detected array access pattern."""

    base_expr: str  # Base pointer
    index_var: str  # Index variable
    stride: int  # Bytes per element
    offset: int  # Constant offset
    element_type: str  # "int", "char", "ptr", etc.
    element_width: int  # Bit width

    def __repr__(self) -> str:
        return f"Array({self.base_expr}[{self.index_var} * {self.stride} + {self.offset}]:{self.element_type})"


@dataclass
class ArrayRecoveryInfo:
    """Information about recovered array structure."""

    array_name: str
    base_ptr: str
    element_type: str
    element_width: int
    element_stride: int
    access_patterns: Set[str]  # Collected access patterns
    confidence: float  # 0.0-1.0 based on pattern consistency

    def __repr__(self) -> str:
        return f"ArrayInfo({self.array_name}: {self.element_type}[{len(self.access_patterns)} accesses])"


class InductionVariableCollector:
    """
    Collect loop induction variables with stride patterns.

    Identifies variables that are:
    - Incremented/decremented by constant stride each iteration
    - Used as array indices or pointer offsets
    - Loop-carried across function calls
    """

    def __init__(self):
        self.induction_vars: dict[str, InductionVariable] = {}
        self.stride_patterns: dict[str, int] = {}

    def collect(self, expressions: list[str]) -> dict[str, InductionVariable]:
        """
        Collect induction variables from expression list.

        Args:
            expressions: List of expression strings

        Returns:
            Dictionary mapping variable name to InductionVariable
        """
        # Placeholder: would analyze loop bodies and variable updates
        # For now, demonstrate structure

        for expr in expressions:
            if "+=" in expr or "-=" in expr:
                self._analyze_update_expr(expr)

        return self.induction_vars

    def _analyze_update_expr(self, expr: str) -> None:
        """Analyze variable update expression for stride patterns."""
        # Example: "si += 2" or "di -= 4"
        if "+=" in expr:
            parts = expr.split("+=")
            if len(parts) == 2:
                var = parts[0].strip()
                stride_str = parts[1].strip()
                try:
                    stride = int(stride_str)
                    self.stride_patterns[var] = stride
                    self.induction_vars[var] = InductionVariable(
                        var_name=var, stride=stride, base_value=0, loop_bound=None, element_width=16
                    )
                except ValueError:
                    pass


class ArrayExpressionMatcher:
    """
    Detect and match array access patterns.

    Recognizes:
    - Simple indexed access: base[index]
    - Strided access: base + index * stride
    - Offset access: base + index * stride + offset
    - Nested arrays: base[i][j]
    """

    def __init__(self):
        self.detected_patterns: list[ArrayAccessPattern] = []
        self.array_infos: dict[str, ArrayRecoveryInfo] = {}

    def match_patterns(
        self, expressions: list[str], induction_vars: dict[str, InductionVariable]
    ) -> list[ArrayAccessPattern]:
        """
        Match array access patterns in expressions.

        Args:
            expressions: List of expression strings
            induction_vars: Known induction variables with strides

        Returns:
            List of detected ArrayAccessPattern
        """
        patterns = []

        for expr in expressions:
            if self._looks_like_array_access(expr):
                pattern = self._extract_array_pattern(expr, induction_vars)
                if pattern:
                    patterns.append(pattern)
                    self.detected_patterns.append(pattern)

        return patterns

    def _looks_like_array_access(self, expr: str) -> bool:
        """Heuristic check if expression might be array access."""
        # Check for patterns like "[", "*", "+", "-"
        return any(marker in expr for marker in ["[", "mem[", "*"])

    def _extract_array_pattern(self, expr: str, induction_vars: dict[str, InductionVariable]) -> Optional[ArrayAccessPattern]:
        """Extract array pattern from expression if possible."""
        # Placeholder: would parse expression into base, index, stride, offset
        # For now, return generic pattern

        for var_name, ind_var in induction_vars.items():
            if var_name in expr:
                # Found expression with induction variable
                return ArrayAccessPattern(
                    base_expr="array_base",
                    index_var=var_name,
                    stride=ind_var.stride,
                    offset=0,
                    element_type="int",
                    element_width=ind_var.element_width,
                )

        return None

    def synthesize_arrays(self, patterns: list[ArrayAccessPattern]) -> dict[str, ArrayRecoveryInfo]:
        """
        Synthesize array recovery info from matched patterns.

        Groups patterns by base expression to recover array structure.

        Args:
            patterns: List of detected array access patterns

        Returns:
            Dictionary mapping base_expr to ArrayRecoveryInfo
        """
        arrays: dict[str, ArrayRecoveryInfo] = {}

        for pattern in patterns:
            if pattern.base_expr not in arrays:
                arrays[pattern.base_expr] = ArrayRecoveryInfo(
                    array_name=f"array_{pattern.base_expr}",
                    base_ptr=pattern.base_expr,
                    element_type=pattern.element_type,
                    element_width=pattern.element_width,
                    element_stride=pattern.stride,
                    access_patterns=set(),
                    confidence=0.5,
                )

            arrays[pattern.base_expr].access_patterns.add(str(pattern))

            # Increase confidence with more consistent patterns
            num_patterns = len(arrays[pattern.base_expr].access_patterns)
            arrays[pattern.base_expr].confidence = min(1.0, 0.5 + (num_patterns * 0.1))

        self.array_infos = arrays
        return arrays


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
    }.get(op)


def _literal_true_8616(node) -> bool:
    return isinstance(node, CConstant) and isinstance(node.value, int) and node.value != 0


def _extract_break_guard_8616(stmt):
    if type(stmt).__name__ not in {"CIfElse", "CIfBreak"}:
        return None
    cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
    if len(cond_nodes) != 1:
        return None
    cond, body = cond_nodes[0]
    if not isinstance(body, CStatements) or len(getattr(body, "statements", ()) or ()) != 1:
        return None
    if not isinstance(body.statements[0], CBreak):
        return None
    else_node = getattr(stmt, "else_node", None)
    if else_node is not None and not (isinstance(else_node, CStatements) and not else_node.statements):
        return None
    return cond


def _extract_monotonic_update_8616(stmt):
    if not isinstance(stmt, CAssignment) or not isinstance(stmt.lhs, CVariable):
        return None
    rhs = stmt.rhs
    if not isinstance(rhs, CBinaryOp) or rhs.op not in {"Add", "Sub"}:
        return None
    if _same_c_expression_8616(rhs.lhs, stmt.lhs) and isinstance(rhs.rhs, CConstant) and isinstance(rhs.rhs.value, int):
        delta = rhs.rhs.value if rhs.op == "Add" else -rhs.rhs.value
        return stmt.lhs, delta
    if rhs.op == "Add" and _same_c_expression_8616(rhs.rhs, stmt.lhs) and isinstance(rhs.lhs, CConstant) and isinstance(rhs.lhs.value, int):
        return stmt.lhs, rhs.lhs.value
    return None


def _cond_uses_var_8616(node, target) -> bool:
    if isinstance(node, CVariable):
        return _same_c_expression_8616(node, target)
    target_key = _expr_index_key_8616(target)
    if target_key is not None and _expr_index_key_8616(node) == target_key:
        return True
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval"):
        child = getattr(node, attr, None)
        if child is not None and _cond_uses_var_8616(child, target):
            return True
    return False


def _loop_index_key_8616(loop_var) -> tuple[object, ...] | None:
    variable = getattr(loop_var, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        return ("reg", getattr(variable, "reg", None))
    if isinstance(variable, SimStackVariable):
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        region = getattr(variable, "region", None)
        if base is None or offset is None:
            return None
        return ("stack", base, offset, region)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", None)
        if addr is None:
            return None
        return ("mem", addr)
    return None


def _expr_index_key_8616(expr) -> tuple[object, ...] | None:
    if isinstance(expr, CVariable):
        return _loop_index_key_8616(expr)
    if isinstance(expr, CTypeCast):
        return _expr_index_key_8616(expr.expr)
    if isinstance(expr, CUnaryOp) and expr.op in {"Dereference", "Reference"}:
        return _expr_index_key_8616(expr.operand)
    if isinstance(expr, CIndexedVariable):
        base_expr = getattr(expr, "variable", None)
        if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
            base_expr = base_expr.operand
        index_expr = getattr(expr, "index", None)
        if not isinstance(base_expr, CVariable) or not isinstance(index_expr, CConstant) or not isinstance(index_expr.value, int):
            return None
        variable = getattr(base_expr, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        base = getattr(variable, "base", None)
        offset = getattr(variable, "offset", None)
        region = getattr(variable, "region", None)
        if base is None or not isinstance(offset, int):
            return None
        return ("stack", base, offset + int(index_expr.value), region)
    return None


def _unwrap_double_negation_8616(node):
    if isinstance(node, CUnaryOp) and node.op == "Not" and isinstance(node.operand, CUnaryOp) and node.operand.op == "Not":
        return node.operand.operand
    return None


def _condition_index_key_8616(node) -> tuple[object, ...] | None:
    if isinstance(node, CBinaryOp):
        lhs_key = _expr_index_key_8616(node.lhs)
        if lhs_key is not None:
            return lhs_key
        rhs_key = _expr_index_key_8616(node.rhs)
        if rhs_key is not None:
            return rhs_key
    return None


def _has_induction_evidence_for_key_8616(codegen, index_key: tuple[object, ...]) -> bool:
    summaries = tuple(getattr(codegen, "_inertia_induction_summaries", ()) or ())
    if any(getattr(summary, "index_key", None) == index_key for summary in summaries):
        return True
    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if project is None or not isinstance(func_addr, int):
        return False
    profiles = _cached_access_trait_profiles_8616(project, func_addr)
    if profiles is None:
        return False
    direct_profile = profiles.get(index_key)
    if direct_profile is not None and infer_induction_variable(direct_profile) is not None:
        return True
    for profile in profiles.values():
        candidate = infer_induction_variable(profile)
        if candidate is not None and candidate.index_key == index_key:
            return True
    return False


def _profile_induction_match_8616(codegen, loop_var) -> InductionVariable | None:
    variable = getattr(loop_var, "variable", None)
    index_key = _loop_index_key_8616(loop_var)
    if variable is None or index_key is None:
        return None

    summaries = tuple(getattr(codegen, "_inertia_induction_summaries", ()) or ())
    best_summary = None
    best_summary_score: tuple[int, int, int] | None = None
    for summary in summaries:
        if getattr(summary, "index_key", None) != index_key:
            continue
        score = (
            int(getattr(summary, "count", 0) or 0),
            abs(int(getattr(summary, "stride", 0) or 0)),
            int(getattr(summary, "width", 0) or 0),
        )
        if best_summary_score is None or score > best_summary_score:
            best_summary = summary
            best_summary_score = score
    if best_summary is not None:
        return InductionVariable(
            var_name=getattr(variable, "name", None) or f"reg_{getattr(variable, 'reg', 'unknown')}",
            stride=int(getattr(best_summary, "stride", 0) or 0),
            base_value=int(getattr(best_summary, "offset", 0) or 0),
            loop_bound=int(getattr(best_summary, "bound_candidate", 0)) if getattr(best_summary, "bound_candidate", None) is not None else None,
            element_width=int(getattr(best_summary, "width", 0) or 0),
        )

    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None

    profiles = _cached_access_trait_profiles_8616(project, func_addr)
    if profiles is None:
        return None
    direct_profile = profiles.get(index_key)
    if direct_profile is not None:
        direct_match = infer_induction_variable(direct_profile)
        if direct_match is not None and direct_match.index_key == index_key:
            return direct_match

    best_match: InductionVariable | None = None
    best_score: tuple[int, int, int, int] | None = None
    for profile_key, profile in profiles.items():
        candidate = infer_induction_variable(profile)
        if candidate is None or candidate.index_key != index_key:
            continue
        score = (
            int(candidate.count),
            abs(int(candidate.stride)),
            int(candidate.width),
            1 if profile_key == index_key else 0,
        )
        if best_score is None or score > best_score:
            best_match = candidate
            best_score = score
    return best_match


def _rewrite_induction_loops_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        if isinstance(node, CForLoop):
            simplified = _unwrap_double_negation_8616(getattr(node, "condition", None))
            if simplified is not None:
                index_key = _condition_index_key_8616(simplified)
                if index_key is not None:
                    if _has_induction_evidence_for_key_8616(codegen, index_key):
                        node.condition = simplified
                        changed = True
            return node
        if not isinstance(node, CWhileLoop):
            return node
        if not _literal_true_8616(getattr(node, "condition", None)):
            return node
        body = getattr(node, "body", None)
        if not isinstance(body, CStatements):
            return node
        statements = list(getattr(body, "statements", ()) or ())
        if len(statements) < 2:
            return node
        guard = _extract_break_guard_8616(statements[0])
        if not isinstance(guard, CBinaryOp):
            return node
        inverted = _invert_cmp_op_8616(guard.op)
        if inverted is None:
            return node

        update = None
        for stmt in reversed(statements[1:]):
            update = _extract_monotonic_update_8616(stmt)
            if update is not None:
                break
        if update is None:
            return node
        loop_var, _delta = update
        if not _cond_uses_var_8616(guard, loop_var):
            return node
        induction_info = _profile_induction_match_8616(codegen, loop_var)
        if induction_info is None:
            return node
        if abs(int(_delta)) != int(getattr(induction_info, "stride", 0) or 0):
            return node

        node.condition = CBinaryOp(
            inverted,
            guard.lhs,
            guard.rhs,
            codegen=codegen,
            tags=getattr(guard, "tags", None),
        )
        body.statements = statements[1:]
        changed = True
        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        from .decompiler_postprocess_utils import _safe_assign_cfunc_statements_8616
        root = _safe_assign_cfunc_statements_8616(codegen, new_root, root)
        if hasattr(codegen.cfunc, "body"):
            codegen.cfunc.body = codegen.cfunc.statements
    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    return changed


def apply_x86_16_array_expression_matching(codegen) -> bool:
    """
    Apply array expression matching pass to codegen.

    This is the entry point for Phase 2.2 decompiler framework integration.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if array patterns were detected, False otherwise

    Note:
        This pass collects array recovery metadata but doesn't modify
        codegen text directly (that happens in later phases).
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        project = getattr(codegen, "project", None)
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        bridge = None
        if project is not None:
            bridge = load_storage_object_bridge(project, function_addr, codegen=codegen)
        lowerable_arrays = (
            {}
            if bridge is None
            else {
                base_key: fact
                for base_key, fact in bridge.array_facts.items()
                if bridge.allows_object_lowering(base_key)
            }
        )
        refused_arrays = (
            {}
            if bridge is None
            else {
                base_key: bridge.lowering_refusal_reason(base_key)
                for base_key in bridge.array_facts
                if not bridge.allows_object_lowering(base_key)
            }
        )
        typed_ir_candidates = _typed_ir_array_candidates(codegen)
        typed_string_candidates = _typed_string_array_candidates(codegen)
        typed_ir_candidates = _limit_sorted_mapping_8616(typed_ir_candidates, MAX_TYPED_ARRAY_CANDIDATES)
        typed_string_candidates = _limit_sorted_mapping_8616(typed_string_candidates, MAX_TYPED_ARRAY_CANDIDATES)
        # Track that array matching pass ran
        codegen._inertia_array_matching_applied = True
        codegen._inertia_array_matching_bridge = bridge
        codegen._inertia_array_matching_lowerable_arrays = lowerable_arrays
        codegen._inertia_array_matching_refused_arrays = refused_arrays
        codegen._inertia_array_matching_typed_ir_candidates = typed_ir_candidates
        codegen._inertia_array_matching_string_candidates = typed_string_candidates
        codegen._inertia_array_matching_stats = {
            "induction_vars": len(typed_ir_candidates),
            "array_patterns": 0 if bridge is None else len(bridge.array_facts),
            "recovered_arrays": len(lowerable_arrays) + len(typed_ir_candidates) + len(typed_string_candidates),
            "refused_arrays": len(refused_arrays),
            "string_arrays": len(typed_string_candidates),
        }

        changed = _rewrite_induction_loops_8616(codegen)
        logger.debug("Array expression matching pass completed")
        return changed
    except Exception as ex:
        logger.warning("Array expression matching pass failed: %s", ex)
        codegen._inertia_array_matching_error = str(ex)
        return False
