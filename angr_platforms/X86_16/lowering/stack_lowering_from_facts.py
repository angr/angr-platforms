from __future__ import annotations

# Layer: Lowering
# Responsibility:
#   Consume alias-proven stack facts and materialize them into real variables
#   before final C emission.
#
# Input:
#   AliasStorageFacts(identity=("stack", _StackSlotIdentity(...)))
#
# Output:
#   Real C/Sim stack variables registered through variables_in_use.
#
# Forbidden:
#   - generated-C regex recovery
#   - counting StackVariableBinding as materialization
#   - fallback to rewrite/postprocess for semantics
#
# Contract:
#   bindings_count > 0 and materialized_count == 0 is PipelineHardError.

import contextlib
from dataclasses import dataclass
import logging
import os
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimStackVariable

from .stack_lowering_result import (
    StackLoweringResult,
    StackSlotFailure,
)
from .stack_variable_binding import (
    StackVariableBinding,
    build_stack_variable_bindings_8616,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "build_stack_variable_bindings_from_alias_facts_8616",
    "lower_stack_accesses_from_alias_facts_8616",
]

log = logging.getLogger(__name__)


def _canonical_stack_offset_8616(offset):
    if not isinstance(offset, int):
        return offset
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def build_stack_variable_bindings_from_alias_facts_8616(
    alias_facts: list[object],
) -> list[StackVariableBinding]:
    """Build StackVariableBinding list from alias storage facts.

    Only stack-space facts with proven BP base are accepted.
    Naming: offset < 0 → local_N, offset > 0 → arg_N, offset == 0 → frame_base.

    Returns empty list if no stack facts exist.
    """
    address_sizes: dict[int, int] = {}
    preferred_names: dict[int, str] = {}

    for fact in alias_facts:
        identity = getattr(fact, "identity", None)
        if identity is None:
            continue

        kind = identity[0] if isinstance(identity, tuple) and len(identity) >= 2 else None
        if kind != "stack":
            continue

        slot = identity[1] if len(identity) >= 2 else None
        if slot is None:
            continue

        offset = _canonical_stack_offset_8616(getattr(slot, "offset", None))
        width = getattr(slot, "width", None)

        if not isinstance(offset, int):
            continue

        size = width if isinstance(width, int) and width > 0 else 1
        current_size = address_sizes.get(offset)
        if current_size is None or size > current_size:
            address_sizes[offset] = size

        if offset < 0:
            name = f"local_{abs(offset):x}"
        elif offset > 0:
            name = f"arg_{abs(offset):x}"
        else:
            name = "frame_base"
        preferred_names[offset] = name

    if not address_sizes:
        return []

    return build_stack_variable_bindings_8616(
        sorted(address_sizes.items()),
        preferred_names=preferred_names,
    )


def _stack_object_name(offset: int, codegen=None) -> str:
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return "arg_0"

    arg_offsets: set[int] = set()
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    if cfunc is not None:
        for arg in getattr(cfunc, "arg_list", ()) or ():
            arg_var = getattr(arg, "variable", None)
            if isinstance(arg_var, SimStackVariable):
                arg_offset = _canonical_stack_offset_8616(getattr(arg_var, "offset", None))
                if isinstance(arg_offset, int):
                    arg_offsets.add(arg_offset)

    if offset in arg_offsets:
        return f"arg_{offset:x}"

    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"


def _stack_type_for_size(size: int, *, codegen=None):
    """Return SimTypeInt for the given byte size with arch attached if available."""
    t = SimTypeInt(signed=False)
    if codegen is not None:
        arch = getattr(getattr(codegen, "project", None), "arch", None) or getattr(
            getattr(codegen, "cfunc", None), "arch", None
        )
        if arch is not None:
            t = t.with_arch(arch)
    return t


def _promote_direct_stack_cvariable(codegen, cvar, size, target_type):
    """Update the type and size on an existing stack CVariable."""
    if cvar is not None:
        cvar.variable_type = target_type
        variable = getattr(cvar, "variable", None)
        if isinstance(variable, SimStackVariable):
            if not isinstance(variable.size, int) or variable.size < size:
                variable.size = size


def _apply_stack_binding_name_8616(cvar, preferred_name: str | None) -> str | None:
    if not isinstance(preferred_name, str) or not preferred_name:
        return None
    variable = getattr(cvar, "variable", None)
    changed_name = None
    if isinstance(variable, SimStackVariable) and getattr(variable, "name", None) != preferred_name:
        variable.name = preferred_name
        changed_name = preferred_name
    if getattr(cvar, "name", None) != preferred_name:
        with contextlib.suppress(Exception):
            cvar.name = preferred_name
            changed_name = preferred_name
    unified = getattr(cvar, "unified_variable", None)
    if unified is not None and getattr(unified, "name", None) != preferred_name:
        unified.name = preferred_name
        changed_name = preferred_name
    return changed_name


def _materialize_stack_cvar_at_offset(
    codegen,
    offset: int,
    size: int = 2,
    *,
    preferred_name: str | None = None,
):
    """Self-contained: register a SimStackVariable + CVariable for offset.

    This is a standalone copy of the logic in stack_lowering_impl.py
    for use by fact-based lowering, to avoid circular dependency on
    the injected helpers used in the canonicalization pass.
    """
    if getattr(codegen, "cfunc", None) is None:
        return None
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return None

    # Check if already exists in variables_in_use
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for var, cvar in variables_in_use.items():
            if (
                isinstance(var, SimStackVariable)
                and _canonical_stack_offset_8616(getattr(var, "offset", None)) == offset
            ):
                target_type = _stack_type_for_size(size, codegen=codegen)
                _promote_direct_stack_cvariable(codegen, cvar, size, target_type)
                _apply_stack_binding_name_8616(cvar, preferred_name)
                return cvar

    target_type = _stack_type_for_size(size, codegen=codegen)
    variable = SimStackVariable(
        offset,
        size,
        base="bp",
        name=_stack_object_name(offset),
        region=getattr(codegen.cfunc, "addr", None),
    )
    cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
    _apply_stack_binding_name_8616(cvar, preferred_name)

    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, target_type)}

    stack_local_candidates = getattr(codegen, "_inertia_stack_local_declaration_candidates", None)
    if isinstance(stack_local_candidates, dict):
        stack_local_candidates[id(variable)] = (variable, cvar)

    sort_local_vars = getattr(codegen.cfunc, "sort_local_vars", None)
    if callable(sort_local_vars):
        with contextlib.suppress(Exception):
            sort_local_vars()

    return cvar


def lower_stack_accesses_from_alias_facts_8616(
    codegen,
    alias_facts: list[object],
) -> StackLoweringResult:
    """Primary stack lowering: consume alias facts, not linear expression patterns.

    Rules:
    - Only consume alias facts
    - No regex on generated C
    - No linear expression guessing
    - If facts exist but variables cannot be materialized, report failure

    Materialization means registering real SimStackVariable + CVariable objects
    in codegen.cfunc.variables_in_use. Creating StackVariableBinding metadata is
    NOT materialization.
    """
    bindings = build_stack_variable_bindings_from_alias_facts_8616(alias_facts)
    stable_stack_fact_count = len(
        [
            fact for fact in alias_facts
            if isinstance(getattr(fact, "identity", None), tuple)
            and len(getattr(fact, "identity", None)) >= 2
            and getattr(fact, "identity", None)[0] == "stack"
        ]
    )
    stable_bp_fact_count = len(
        [
            fact for fact in alias_facts
            if isinstance(getattr(fact, "identity", None), tuple)
            and len(getattr(fact, "identity", None)) >= 2
            and getattr(fact, "identity", None)[0] == "stack"
            and getattr(getattr(fact, "identity", None)[1], "base", None) == "bp"
        ]
    )
    debug_stats = {
        "stable_stack_fact_count": stable_stack_fact_count,
        "stable_bp_fact_count": stable_bp_fact_count,
        "stack_binding_count": len(bindings),
        "stack_slot_candidates": len(bindings),
        "stack_slot_bindings": len(bindings),
        "stack_slot_materialized": 0,
        "stack_slot_failed": 0,
    }
    codegen._inertia_stack_lowering_debug = debug_stats
    codegen._inertia_stack_variable_bindings = tuple(bindings)
    if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
        log.warning(
            "[stack-lowering] bindings=%d stable_stack=%d stable_bp=%d",
            len(bindings),
            stable_stack_fact_count,
            stable_bp_fact_count,
        )
        for binding in bindings[:16]:
            log.warning("[stack-lowering] binding=%r", binding)

    if not bindings:
        return StackLoweringResult(
            status="ok",
            failures=[],
            materialized=[],
            diagnostics=[
                "stack_lowering_source=alias_facts bindings=0 materialized=0",
                f"stable_stack_fact_count={stable_stack_fact_count}",
                f"stable_bp_fact_count={stable_bp_fact_count}",
            ],
        )

    codegen._inertia_stack_bindings = bindings
    codegen._inertia_stack_lowering_source = "alias_facts"
    codegen._inertia_semantic_stack_binding_count = len(bindings)

    materialized_count = 0
    failures_list: list[StackSlotFailure] = []
    materialized: list[tuple[int, str]] = []

    for binding in bindings:
        try:
            offset = _canonical_stack_offset_8616(getattr(binding, "bp_offset", None))
            if offset is None:
                offset = _canonical_stack_offset_8616(getattr(binding, "offset", None))
            size = getattr(binding, "size", None)
            if size is None or not isinstance(size, int):
                size = 2

            cvar = _materialize_stack_cvar_at_offset(
                codegen,
                offset,
                size,
                preferred_name=getattr(binding, "var_name", None),
            )
            materialized_name = getattr(getattr(cvar, "variable", None), "name", None) or getattr(cvar, "name", None)
            materialized_count += 1
            materialized.append((int(offset), str(materialized_name or _stack_object_name(int(offset), codegen=codegen))))
        except Exception as exc:
            fallback_offset = _canonical_stack_offset_8616(
                getattr(binding, "bp_offset", None) or getattr(binding, "offset", 0)
            )
            failures_list.append(
                StackSlotFailure(
                    offset=fallback_offset,
                    size=size if isinstance(size, int) else 2,
                    reason=str(exc),
                )
            )
            log.debug(
                "stage=stack_lowering_from_facts function=%#x offset=%r failed: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                fallback_offset,
                exc,
            )

    codegen._inertia_semantic_stack_materialized_count = materialized_count
    debug_stats["stack_slot_materialized"] = materialized_count
    debug_stats["stack_slot_failed"] = len(failures_list)

    # ── Update STACK lane contract counters ──
    # AGENTS rule: bindings are NOT materialization.
    # bound = number of StackVariableBindings created
    # materialized = number of SimStackVariables registered in variables_in_use
    lane = getattr(codegen, "_inertia_stack_lane", None)
    if lane is not None:
        lane.bound = len(bindings)
        lane.materialized = materialized_count

    # ── HARD CONTRACT: bindings > 0 && materialized == 0 → PipelineHardError ──
    if len(bindings) > 0 and materialized_count == 0:
        from ..pipeline.errors import PipelineHardError
        raise PipelineHardError(
            "stable stack slots not materialized",
            layer="stack_lowering",
        )

    ok = len(failures_list) == 0

    return StackLoweringResult(
        status="ok" if ok else "partial",
        failures=failures_list,
        materialized=materialized,
        diagnostics=[
            "stack_lowering_source=alias_facts "
            f"bindings={len(bindings)} "
            f"materialized={materialized_count}",
            f"stable_stack_fact_count={stable_stack_fact_count}",
            f"stable_bp_fact_count={stable_bp_fact_count}",
        ],
    )
