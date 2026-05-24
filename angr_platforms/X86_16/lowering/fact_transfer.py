from __future__ import annotations

import logging
import os

# Layer: Lowering (bridge)
# Responsibility: transfer semantic alias facts from VEX lifter to codegen.
# Input: AliasStorageFacts from IR lifting
# Output: materialized SimStackVariable/CVariable
# Forbidden:
# - generated-C inspection
# - regex recovery
# - rewrite-only fixes
# Contract:
# classified_count > 0 requires materialized_count > 0
#
# Facts are recorded on the DataAccess emulator during lifting via
# _record_semantic_memory_access().  The emulator is ephemeral (discarded
# after block lifting), so we collect facts by re-lifting blocks through
# a fresh DataAccess with facts recording enabled.

__all__ = [
    "transfer_semantic_alias_facts_to_codegen_8616",
    "collect_semantic_alias_facts_from_project_8616",
    "collect_normalized_semantic_alias_facts_from_project_8616",
]


def _lift_block_and_collect_facts(project, block_addr: int) -> list[object]:
    """Lift one block and collect semantic alias facts from the MODULE CACHE.

    During VEX lifting, _record_semantic_memory_access() writes AliasStorageFacts
    into the _inertia_module_alias_fact_cache dict in access.py, keyed by block
    address.  This function re-lifts the block (to ensure the cache is populated)
    then reads facts from the module-level cache.

    Returns list of AliasStorageFacts / AliasFailure objects.
    """
    try:
        # Re-lift to populate the module cache (keyed by block_addr)
        project.factory.block(block_addr, opt_level=0)
    except Exception as ex:
        import logging
        logging.getLogger(__name__).debug(
            "fact transfer block lift failed block_addr=%#x: %s",
            block_addr,
            ex,
        )

    # Read from module-level cache in access.py
    from ..access import _inertia_module_alias_fact_cache

    facts = _inertia_module_alias_fact_cache.get(block_addr, None)
    if isinstance(facts, list):
        return list(facts)
    return []


def _set_function_context(function_addr: int) -> None:
    """Set module-level function context for the coming block lift."""
    from ..semantics.evidence_cache import set_current_function_addr
    set_current_function_addr(function_addr)


def _clear_function_context() -> None:
    """Clear module-level function context after block lift."""
    from ..semantics.evidence_cache import set_current_function_addr
    set_current_function_addr(None)


def collect_normalized_semantic_alias_facts_from_project_8616(project, function_addr: int):
    """Collect and normalize semantic alias facts AFTER stack-frame recovery.

    Pipeline order:
      1. IR lifting records raw semantic addresses (no alias facts)
      2. This function reads raw accesses
      3. Detects BP frame
      4. Normalizes SS addresses to BP-relative STABLE
      5. Asserts no unresolved STABLE SS reaches alias
      6. Calls alias_facts_for_ir_address_8616() on normalized addresses
      7. Caches results in _inertia_module_alias_fact_cache

    This replaces the old pattern where alias facts were created during lifting
    before frame normalization.
    """
    from ..access import _inertia_module_alias_fact_cache
    from ..alias.alias_model_impl import alias_facts_for_ir_address_8616, AliasFailure
    from ..semantics.evidence_cache import get_accesses_for_function as _evidence_get_accesses
    from ..semantics.stack_frame_recovery import (
        StackFrameInfo8616,
        assert_no_unresolved_stable_ss_before_alias_8616,
        detect_stack_frame_8616,
        _gather_ir_artifacts_from_function_blocks,
        _detect_sp_proven_delta_from_blocks,
        normalize_semantic_accesses_8616,
    )

    # ── Migrate block-keyed accesses → function-keyed ──
    # During initial CFG construction (when function context is unknown),
    # accesses are recorded by block address.  Now that we know which
    # blocks belong to this function, migrate them.
    from ..semantics.evidence_cache import (
        get_accesses_for_block,
        migrate_block_accesses_to_function,
    )
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is not None:
        func = kb.functions.function(addr=function_addr, create=False)
        if func is not None:
            block_addrs = sorted(getattr(func, "block_addrs_set", set()) or set())
            total_migrated = 0
            for ba in block_addrs:
                n = migrate_block_accesses_to_function(ba, function_addr)
                total_migrated += n
            if total_migrated > 0:
                logging.getLogger(__name__).debug(
                    "migrated %d block-keyed accesses from %d blocks for 0x%x",
                    total_migrated,
                    len(block_addrs),
                    function_addr,
                )

    # Read raw semantic accesses from canonical evidence_cache (function-keyed)
    raw_accesses = _evidence_get_accesses(function_addr)

    # ── Collect IR artifacts for BP frame detection (VEX blocks, NOT text) ──
    ir_artifacts = _gather_ir_artifacts_from_function_blocks(project, function_addr)

    frame = detect_stack_frame_8616(
        function_addr=function_addr,
        ir_artifacts=ir_artifacts,
        semantic_accesses=raw_accesses,
    )

    # ── SP delta: detect proven frame size from VEX ──
    proven_sp_delta = _detect_sp_proven_delta_from_blocks(project, function_addr)
    if proven_sp_delta is not None and frame.uses_bp_frame:
        frame = StackFrameInfo8616(
            function_addr=function_addr,
            uses_bp_frame=True,
            bp_established=True,
            sp_delta_known=True,
            frame_base="bp",
            frame_kind="bp",
            evidence=tuple(frame.evidence) + (f"proven_sp_delta={proven_sp_delta}",),
        )

    normalized = normalize_semantic_accesses_8616(raw_accesses, frame)
    assert_no_unresolved_stable_ss_before_alias_8616(normalized)

    facts = []
    failures = []

    for acc in normalized:
        addr = acc.addr if hasattr(acc, 'addr') else acc[1]
        fact = alias_facts_for_ir_address_8616(addr)
        if isinstance(fact, AliasFailure):
            failures.append(fact)
        elif fact is not None:
            facts.append(fact)

    _inertia_module_alias_fact_cache[function_addr] = facts + failures
    return facts, failures


def collect_semantic_alias_facts_from_project_8616(project, func_addr: int) -> list[object]:
    """Collect semantic alias facts for a function by re-lifting its blocks.

    During VEX→IR lifting, _record_semantic_memory_access() writes facts into
    the _inertia_module_alias_fact_cache dict in access.py, keyed by block
    address.  This function re-lifts every block in the function and aggregates
    facts from the module cache.

    Returns a deduplicated, deterministic list of alias facts.
    """
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is None:
        return []

    func = kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return []

    block_addrs = sorted(getattr(func, "block_addrs_set", set()) or set())
    if not block_addrs:
        return []

    all_facts: list[object] = []
    for block_addr in block_addrs:
        all_facts.extend(_lift_block_and_collect_facts(project, block_addr))

    # Deduplicate — AliasStorageFacts and AliasFailure are frozen dataclasses
    seen: set[int] = set()
    unique: list[object] = []
    for fact in all_facts:
        try:
            key = hash(fact)
        except TypeError:
            key = id(fact)
        if key not in seen:
            seen.add(key)
            unique.append(fact)

    # Deterministic sort: stack facts by offset, then others
    def _sort_key(fact: object) -> tuple:
        identity = getattr(fact, "identity", None)
        if identity is None:
            return ("z", 0, 0)
        kind = identity[0] if isinstance(identity, tuple) and len(identity) >= 2 else "z"
        slot = identity[1] if len(identity) >= 2 else None
        offset = getattr(slot, "offset", 0) if slot is not None else 0
        width = getattr(slot, "width", 0) if slot is not None and getattr(slot, "width", None) is not None else 0
        order = {"stack": "a", "register": "b", "memory": "c"}.get(kind, "z")
        return (order, offset, width)

    unique.sort(key=_sort_key)
    return unique


def transfer_semantic_alias_facts_to_codegen_8616(project, codegen) -> int:
    """Transfer semantic alias facts from project blocks to codegen.

    This bridges the gap between the VEX lifter (which records facts on
    the emulator) and the invariant gate/stack lowering (which consume
    facts from codegen).

    Sets codegen._inertia_stack_lane with a SemanticLaneState for the STACK lane.
    Returns the number of facts transferred.
    """
    from ..pipeline.contracts import SemanticLaneState

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        codegen._inertia_semantic_alias_facts = []
        codegen._inertia_semantic_facts_transferred = True
        return 0

    func_addr = getattr(cfunc, "addr", None)
    if func_addr is None:
        codegen._inertia_semantic_alias_facts = []
        codegen._inertia_semantic_facts_transferred = True
        return 0

    # Only allow legacy fallback if explicitly enabled by debug flag.
    # Silent fallback is FORBIDDEN — it makes regressions invisible.
    allow_legacy = bool(getattr(project, "_inertia_allow_legacy_fact_fallback", False))

    try:
        facts, failures = collect_normalized_semantic_alias_facts_from_project_8616(project, func_addr)
    except Exception as e:
        codegen._inertia_semantic_fact_transfer_error = repr(e)
        if allow_legacy:
            facts = collect_semantic_alias_facts_from_project_8616(project, func_addr)
            failures = []
            codegen._inertia_semantic_fact_transfer_fallback_used = True
        else:
            raise

    # Read raw semantic access counts from canonical evidence_cache
    # MUST be read AFTER collect_normalized (which re-lifts blocks and populates the cache).
    from ..semantics.evidence_cache import get_accesses_for_function as _evidence_get_accesses_raw
    raw_accesses = _evidence_get_accesses_raw(func_addr)
    raw_count = len(raw_accesses)

    codegen._inertia_semantic_alias_facts = facts + failures
    codegen._inertia_semantic_facts_transferred = True
    codegen._inertia_semantic_alias_fact_count = len(facts) + len(failures)

    # Count stack facts and normalized accesses for diagnostics
    normalized_count = sum(
        1 for fact in facts
        if getattr(fact, "identity", None) is not None
        and isinstance(fact.identity, tuple)
    )
    stack_count = sum(
        1 for fact in facts
        if getattr(fact, "identity", None) is not None
        and isinstance(fact.identity, tuple)
        and len(fact.identity) >= 2
        and fact.identity[0] == "stack"
    )

    codegen._inertia_semantic_raw_access_count = raw_count
    codegen._inertia_semantic_normalized_access_count = normalized_count
    codegen._inertia_semantic_stack_fact_count = stack_count
    codegen._inertia_semantic_failure_count = len(failures)

    # Initialize consumption counters (filled later by materialization passes)
    if not hasattr(codegen, "_inertia_semantic_stack_materialized_count"):
        codegen._inertia_semantic_stack_materialized_count = 0
    if not hasattr(codegen, "_inertia_semantic_condition_fact_count"):
        codegen._inertia_semantic_condition_fact_count = 0
    if not hasattr(codegen, "_inertia_semantic_condition_materialized_count"):
        codegen._inertia_semantic_condition_materialized_count = 0

    # ── Initialize STACK lane contract ──
    codegen._inertia_stack_lane = SemanticLaneState(
        name="stack",
        raw=raw_count,
        normalized=normalized_count,
        classified=stack_count,
        bound=0,              # filled by lowering pass
        materialized=0,       # filled by materialization pass
        verified=0,           # filled by validation pass
        failures=len(failures),
    )

    # Compact diagnostic report — single structured line, collected here
    # so downstream failures don't lose the data.
    _diagnostic = {
        "function": f"0x{func_addr:x}",
        "raw_accesses": raw_count,
        "normalized_accesses": normalized_count,
        "alias_facts": len(facts),
        "stack_facts": stack_count,
        "stack_materialized": getattr(
            codegen, "_inertia_semantic_stack_materialized_count", 0
        ),
        "condition_facts": getattr(
            codegen, "_inertia_semantic_condition_fact_count", 0
        ),
        "condition_materialized": getattr(
            codegen, "_inertia_semantic_condition_materialized_count", 0
        ),
        "failures": len(failures),
        "primary_blocker": (
            "raw_accesses=0 (check lifter access recording / function context)"
            if raw_count == 0
            else (
                "stack_materialized=0 (fix lowering/stack_lowering_from_facts.py)"
                if stack_count > 0
                else None
            )
        ),
    }
    codegen._inertia_pipeline_diag = _diagnostic
    if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
        logging.getLogger(__name__).warning(
            "[stack-facts] func=0x%x raw=%d normalized=%d facts=%d stack=%d failures=%d blocker=%s",
            func_addr,
            raw_count,
            normalized_count,
            len(facts),
            stack_count,
            len(failures),
            _diagnostic.get("primary_blocker"),
        )
        for fact in facts[:16]:
            logging.getLogger(__name__).warning("[stack-facts] fact=%r", fact)

    return len(facts) + len(failures)


def emit_pipeline_diagnostic_8616(codegen) -> dict:
    """Return the compact pipeline diagnostic dict for this function.

    Callers should print or log this dict.  The dict is already attached
    to codegen._inertia_pipeline_diag after fact transfer.
    """
    return getattr(codegen, "_inertia_pipeline_diag", {})
