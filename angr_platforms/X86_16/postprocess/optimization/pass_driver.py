from __future__ import annotations

"""Layer: Optimization (mid-level, pre-rewrite).

Pass driver: runs optimization passes on structured codegen before postprocess.
Inserted early in the postprocess stage, before rewrite passes.

Forbidden: semantic recovery, alias decisions, type inference."""

from dataclasses import dataclass
from typing import Callable

from .const_prop import _constant_propagation_8616
from .copy_prop import _copy_propagation_8616 as _legacy_copy_prop
from .dce import _dead_code_elimination_8616
from .dead_setup import _prune_dead_setup_carriers_8616
from ...widening.widening_copyprop_8616 import _widening_copy_propagation_8616
from ...widening.widening_memory_fold_8616 import _widening_store_to_load_forwarding_8616

__all__ = [
    "OptimizationPassSpec",
    "OPTIMIZATION_PASSES",
    "_run_optimization_passes_8616",
    "describe_x86_16_optimization_passes",
    "_normalize_cfunc_root_for_optimization_8616",
]


# Monkey-patch: CStatements is not iterable in angr, so tuple(CStatements(...))
# fails.  Optimization pass walkers call tuple(getattr(node, 'statements', ()))
# on the root, which hits this.  Add __iter__ so the walkers work without
# having to corrupt cfunc.statements (which needs to stay a CStatements for
# c_repr_chunks() during C text rendering).
from angr.analyses.decompiler.structured_codegen.c import CStatements as _CStatements
if not hasattr(_CStatements, "__iter__"):
    _CStatements.__iter__ = lambda self: iter(self.statements)


def _normalize_cfunc_root_for_optimization_8616(codegen) -> None:
    """No-op: CStatements is now iterable via the module-level monkey-patch.

    Previously this function replaced cfunc.statements (a CStatements wrapper)
    with a raw list, which broke c_repr_chunks() downstream.
    The monkey-patch above makes tuple(CStatements) work natively.

    Kept as a hook point for future optimization setup."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    if not isinstance(getattr(cfunc, "statements", None), _CStatements):
        return


@dataclass(frozen=True, slots=True)
class OptimizationPassSpec:
    name: str
    func: Callable[..., bool]
    description: str


OPTIMIZATION_PASSES: tuple[OptimizationPassSpec, ...] = (
    OptimizationPassSpec(
        "const_prop",
        _constant_propagation_8616,
        "Fold constant sub-expressions",
    ),
    OptimizationPassSpec(
        "widening_copy_prop",
        _widening_copy_propagation_8616,
        "Propagate copies using alias storage domains (Widening)",
    ),
    OptimizationPassSpec(
        "widening_memory_fold",
        _widening_store_to_load_forwarding_8616,
        "Forward store values to loads using alias domains (Widening)",
    ),
    OptimizationPassSpec(
        "dce",
        _dead_code_elimination_8616,
        "Eliminate dead assignments",
    ),
    OptimizationPassSpec(
        "dead_setup_prune",
        _prune_dead_setup_carriers_8616,
        "Prune dead setup/staging carrier assignments (typed def-use)",
    ),
)


def describe_x86_16_optimization_passes() -> tuple[tuple[str, str], ...]:
    return tuple((spec.name, spec.description) for spec in OPTIMIZATION_PASSES)


def _run_optimization_passes_8616(codegen) -> bool:
    """Run optimization passes on codegen.

    Returns True if any pass modified the codegen.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    # Normalize: unwrap CStatements before passes walk the tree.
    # Some angr codegen produces CStatements objects that are not iterable.
    _normalize_cfunc_root_for_optimization_8616(codegen)

    changed = False
    for spec in OPTIMIZATION_PASSES:
        if spec.func(codegen):
            changed = True

    return changed
