from __future__ import annotations

# Layer: Lowering (bridge)
# Responsibility: transfer typed conditions from the emulator to codegen.
# Input: ConditionIR from IR lifting
# Output: materialized C condition nodes (CBinaryOp/CUnaryOp in C AST)
# Forbidden:
# - semantic recovery
# - text-pattern semantics
# - generated-C inspection
# - regex recovery
# - rewrite-only fixes
# Contract:
# classified_count > 0 requires materialized_count > 0
#
# During lifting, _emit_simple_jcc() records ConditionIR objects onto
# self.emu._inertia_typed_conditions.  This module collects those records
# and transfers them to codegen before the invariant gate runs.

__all__ = [
    "transfer_typed_conditions_to_codegen_8616",
    "collect_typed_conditions_from_emulator_8616",
    "transfer_typed_conditions_from_emulator_8616",
]

from ..ir.condition_ir import (
    ConditionIR,
    ConditionFailure,
    deduplicate_conditions_8616,
)
from ..ir.core import IRValue
from ..condition_trace import record_classified_conditions_trace_8616
import logging
import os

log = logging.getLogger(__name__)


def _relift_blocks_for_condition_cache_8616(project, block_addrs: list[int]) -> None:
    factory = getattr(project, "factory", None) if project is not None else None
    block_lifter = getattr(factory, "block", None)
    if not callable(block_lifter):
        return
    for block_addr in block_addrs:
        try:
            block_lifter(block_addr, opt_level=0)
        except TypeError:
            try:
                block_lifter(block_addr)
            except Exception:
                continue
        except Exception:
            continue


def collect_typed_conditions_from_emulator_8616(
    project,
    func_addr: int,
) -> list[ConditionIR]:
    """Collect ConditionIR objects from the module-level cache in lift_86_16.

    During lifting, _record_typed_condition_8616() writes ConditionIR objects
    into Instruction_ANY._inertia_module_condition_cache (keyed by block address).
    This function reads from that cache instead of re-lifting.

    Returns a deduplicated, deterministically sorted list of ConditionIR.
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

    # Read from the module-level cache populated during the initial lift
    try:
        from ..lift_86_16 import Instruction_ANY
        module_cache = Instruction_ANY._inertia_module_condition_cache
    except Exception as ex:
        import logging
        logging.getLogger(__name__).warning(
            "condition transfer import failed: %s: %s",
            type(ex).__name__,
            ex,
        )
        module_cache = {}

    if not any(isinstance(module_cache.get(block_addr, None), list) for block_addr in block_addrs):
        _relift_blocks_for_condition_cache_8616(project, block_addrs)
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
        cache_keys = tuple(sorted(k for k in module_cache.keys() if isinstance(k, int)))
        log.warning(
            "[condition-transfer] func=%#x blocks=%s cache_keys=%s",
            func_addr,
            tuple(hex(a) for a in block_addrs),
            tuple(hex(a) for a in cache_keys),
        )

    all_conditions: list[ConditionIR] = []
    for block_addr in block_addrs:
        block_conds = module_cache.get(block_addr, None)
        if isinstance(block_conds, list):
            for cond in block_conds:
                if isinstance(cond, ConditionIR):
                    all_conditions.append(cond)
                    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                        log.warning(
                            "[condition-transfer] cond cache_block=%#x src_insn=%r block=%r op=%s source=%s lhs=%r rhs=%r",
                            block_addr,
                            cond.src_insn,
                            cond.block_addr,
                            cond.op,
                            cond.source,
                            cond.lhs,
                            cond.rhs,
                        )

    return deduplicate_conditions_8616(all_conditions)


def transfer_typed_conditions_from_emulator_8616(
    instructions: list,
    codegen,
) -> int:
    """Transfer typed conditions from lifted instruction emulators to codegen.

    After block lifting, each instruction's emulator may have
    _inertia_typed_conditions recorded.  This function aggregates them
    and sets codegen._inertia_typed_conditions.

    Returns the number of ConditionIR objects transferred.
    """
    all_conditions: list[ConditionIR] = []
    for instr in instructions:
        emu = getattr(instr, "emu", None)
        if emu is not None:
            conds = getattr(emu, "_inertia_typed_conditions", None)
            if isinstance(conds, list):
                for cond in conds:
                    if isinstance(cond, ConditionIR):
                        all_conditions.append(cond)

    unique = deduplicate_conditions_8616(all_conditions)
    codegen._inertia_typed_conditions = unique
    codegen._inertia_condition_facts = unique  # compatibility alias
    return len(unique)


def transfer_typed_conditions_to_codegen_8616(
    project,
    func_addr: int,
    codegen,
) -> int:
    """Full pipeline: collect conditions by re-lifting, then transfer to codegen.

    Sets:
        codegen._inertia_typed_conditions
        codegen._inertia_condition_facts
        codegen._inertia_condition_lane (SemanticLaneState for CONDITION lane)

    Returns the number of ConditionIR objects transferred.
    """
    from ..pipeline.contracts import SemanticLaneState

    conditions = collect_typed_conditions_from_emulator_8616(project, func_addr)
    codegen._inertia_typed_conditions = conditions
    codegen._inertia_condition_facts = conditions  # compatibility alias
    record_classified_conditions_trace_8616(project, codegen, conditions)

    def _materializable_condition(cond: ConditionIR) -> bool:
        if not isinstance(cond.src_insn, int) or not isinstance(cond.block_addr, int):
            return False
        if not isinstance(cond.lhs, (str, int, IRValue)):
            return False
        if cond.rhs is not None and not isinstance(cond.rhs, (str, int, IRValue)):
            return False
        return True

    classified_count = sum(1 for cond in conditions if _materializable_condition(cond))

    # ── Initialize CONDITION lane contract ──
    # classified = number of ConditionIR facts
    # bound = 0 (no equivalent of StackVariableBinding for conditions yet)
    # materialized = 0 (filled by postprocess typed conditions pass)
    codegen._inertia_condition_lane = SemanticLaneState(
        name="condition",
        raw=len(conditions),       # raw facts = all ConditionIR from lifting
        normalized=len(conditions),
        classified=classified_count,
        bound=0,
        materialized=0,
        verified=0,
        failures=0,
    )

    return len(conditions)
