from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat widening_model import surface during widening package migration.
# Forbidden: semantic ownership; import canonical widening.stack_widening only.

from .widening import stack_widening as _stack_widening

_register_version_for_expr = _stack_widening._register_version_for_expr


def prove_adjacent_storage_slices(low_expr, high_expr, *, alias_state=None):
    return _stack_widening.prove_adjacent_storage_slices(
        low_expr,
        high_expr,
        alias_state=alias_state,
        register_version_for_expr=_register_version_for_expr,
    )


def analyze_adjacent_storage_slices(low_expr, high_expr, *, alias_state=None):
    return _stack_widening.StorageJoinAnalysis(
        prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    )


def can_join_adjacent_storage_slices(low_expr, high_expr, *, alias_state=None) -> bool:
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok:
        return False
    try:
        low_candidate = _stack_widening.RegisterWideningCandidate.from_expr(low_expr)
        high_candidate = _stack_widening.RegisterWideningCandidate.from_expr(high_expr)
    except ValueError:
        low_candidate = None
        high_candidate = None
    if low_candidate is not None and high_candidate is not None:
        if alias_state is None:
            return low_candidate.is_joinable_with(high_candidate)
        return _stack_widening.can_join_adjacent_register_slices(
            low_expr,
            high_expr,
            alias_state=alias_state,
            proof=proof,
        )
    try:
        low_generic = _stack_widening.WideningCandidate.from_expr(low_expr)
        high_generic = _stack_widening.WideningCandidate.from_expr(high_expr)
    except ValueError:
        return False
    if low_generic.domain.is_unknown() or high_generic.domain.is_unknown():
        return False
    if low_generic.domain.is_mixed() or high_generic.domain.is_mixed():
        return False
    return low_generic.is_joinable_with(high_generic)


def merge_storage_slice_domains(low_expr, high_expr, *, alias_state=None):
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok or proof.merged_domain is None:
        return _stack_widening._StorageDomainSignature("mixed")
    return proof.merged_domain


globals().update(
    {
        name: getattr(_stack_widening, name)
        for name in dir(_stack_widening)
        if not name.startswith("__") and name not in {
            "prove_adjacent_storage_slices",
            "analyze_adjacent_storage_slices",
            "can_join_adjacent_storage_slices",
            "merge_storage_slice_domains",
        }
    }
)

__all__ = getattr(
    _stack_widening,
    "__all__",
    tuple(name for name in dir(_stack_widening) if not name.startswith("__")),
)
__all__ = tuple(__all__) + (
    "_register_version_for_expr",
    "prove_adjacent_storage_slices",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_storage_slices",
    "merge_storage_slice_domains",
)
