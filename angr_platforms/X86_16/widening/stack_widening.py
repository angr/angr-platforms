from __future__ import annotations

# Layer: Widening
# Responsibility: alias-proven widening compatibility and slice-join proofs.
# Forbidden: rendered-text joins, CLI ownership, and postprocess semantics.

from dataclasses import dataclass
from typing import Iterable

from ..alias_domains import DomainKey, register_pair_name
from ..alias.alias_model import (
    AliasStorageFacts,
    _merge_storage_domains,
    _StorageDomainSignature,
    _StorageView,
)
from ..alias_state import AliasState
from ..semantics.alias_query import (
    _storage_domain_for_expr,
    can_join_alias_storage,
    describe_alias_storage,
    same_alias_storage_domain,
)
from .register_widening import RegisterWideningCandidate, can_join_adjacent_register_slices


@dataclass(frozen=True)
class WideningCandidate:
    domain: _StorageDomainSignature
    view: _StorageView
    expr: object

    def is_joinable_with(self, other: "WideningCandidate") -> bool:
        return self.domain.can_join(other.domain) and self.view.can_join(other.view)

    @classmethod
    def from_expr(cls, expr: object) -> "WideningCandidate":
        domain = _storage_domain_for_expr(expr)
        if domain.view is None:
            raise ValueError("cannot build widening candidate without a concrete storage view")
        return cls(domain, domain.view, expr)


@dataclass(frozen=True)
class WideningProof:
    ok: bool
    reason: str
    left: AliasStorageFacts
    right: AliasStorageFacts
    merged_domain: _StorageDomainSignature | None = None
    register_pair: str | None = None
    left_version: int | None = None
    right_version: int | None = None

    def is_safe(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class StorageJoinAnalysis:
    proof: WideningProof

    @property
    def ok(self) -> bool:
        return self.proof.ok

    @property
    def reason(self) -> str:
        return self.proof.reason

    @property
    def left(self) -> AliasStorageFacts:
        return self.proof.left

    @property
    def right(self) -> AliasStorageFacts:
        return self.proof.right

    @property
    def merged_domain(self) -> _StorageDomainSignature | None:
        return self.proof.merged_domain

    def same_domain(self) -> bool:
        return self.left.same_domain(self.right)

    def compatible_view(self) -> bool:
        return self.left.compatible_view(self.right)

    def needs_synthesis(self) -> bool:
        return self.left.needs_synthesis() or self.right.needs_synthesis()


@dataclass(frozen=True)
class WideningPipelineSpec:
    name: str
    purpose: str
    helpers: tuple[str, ...]


def _register_version_for_expr(expr: object, state: AliasState | None) -> int | None:
    if state is None:
        return None
    facts = describe_alias_storage(expr)
    if facts.identity is None:
        return None
    kind, name = facts.identity
    if kind != "register" or not isinstance(name, str):
        return None
    pair_name = register_pair_name(name)
    if pair_name is None:
        return None
    return state.version_of(DomainKey("reg", pair_name.upper()))


def prove_adjacent_storage_slices(
    low_expr,
    high_expr,
    *,
    alias_state: AliasState | None = None,
    register_version_for_expr=None,
) -> WideningProof:
    version_resolver = register_version_for_expr or _register_version_for_expr
    low_facts = describe_alias_storage(low_expr)
    high_facts = describe_alias_storage(high_expr)
    register_pair = None
    if low_facts.identity is not None and high_facts.identity is not None:
        low_kind, low_value = low_facts.identity
        high_kind, high_value = high_facts.identity
        low_view = low_facts.domain.view
        high_view = high_facts.domain.view
        if (
            low_kind == high_kind == "register"
            and low_value == high_value
            and low_view is not None
            and high_view is not None
            and low_view.bit_offset < high_view.bit_offset
        ):
            register_pair = low_value
    low_version = version_resolver(low_expr, alias_state)
    high_version = version_resolver(high_expr, alias_state)

    if low_facts.needs_synthesis() or high_facts.needs_synthesis():
        return WideningProof(False, "needs_synthesis", low_facts, high_facts, left_version=low_version, right_version=high_version)
    if not same_alias_storage_domain(low_expr, high_expr):
        return WideningProof(False, "domain_mismatch", low_facts, high_facts, left_version=low_version, right_version=high_version)
    if not can_join_alias_storage(low_expr, high_expr):
        return WideningProof(False, "view_mismatch", low_facts, high_facts, left_version=low_version, right_version=high_version)
    if alias_state is not None:
        if (
            low_facts.identity is not None
            and high_facts.identity is not None
            and low_facts.identity[0] == "register"
            and high_facts.identity[0] == "register"
        ):
            if register_pair is None:
                return WideningProof(
                    False,
                    "register_pair_mismatch",
                    low_facts,
                    high_facts,
                    left_version=low_version,
                    right_version=high_version,
                )
            if low_version is None or high_version is None:
                return WideningProof(
                    False,
                    "missing_version_evidence",
                    low_facts,
                    high_facts,
                    left_version=low_version,
                    right_version=high_version,
                )
            if low_version != high_version:
                return WideningProof(
                    False,
                    "version_mismatch",
                    low_facts,
                    high_facts,
                    left_version=low_version,
                    right_version=high_version,
                )

    merged_domain = _merge_storage_domains(_storage_domain_for_expr(low_expr), _storage_domain_for_expr(high_expr))
    return WideningProof(
        True,
        "ok",
        low_facts,
        high_facts,
        merged_domain=merged_domain,
        register_pair=register_pair,
        left_version=low_version,
        right_version=high_version,
    )


def analyze_adjacent_storage_slices(low_expr, high_expr, *, alias_state: AliasState | None = None) -> StorageJoinAnalysis:
    return StorageJoinAnalysis(prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state))


def collect_widening_candidates(exprs: Iterable[object]) -> list[WideningCandidate]:
    candidates: list[WideningCandidate] = []
    for expr in exprs:
        try:
            candidates.append(WideningCandidate.from_expr(expr))
        except ValueError:
            continue
    return candidates


def describe_widening_candidates(exprs: Iterable[object]) -> tuple[dict[str, object], ...]:
    descriptions: list[dict[str, object]] = []
    for candidate in collect_widening_candidates(exprs):
        descriptions.append(
            {
                "domain": str(candidate.domain),
                "view": {
                    "bit_offset": candidate.view.bit_offset,
                    "bit_width": candidate.view.bit_width,
                },
            }
        )
    return tuple(descriptions)


WIDENING_PIPELINE: tuple[WideningPipelineSpec, ...] = (
    WideningPipelineSpec(
        name="candidate_extraction",
        purpose="Collect joinable storage candidates before proof or rewrite decisions.",
        helpers=("collect_widening_candidates", "describe_widening_candidates", "analyze_adjacent_storage_slices"),
    ),
    WideningPipelineSpec(
        name="compatibility_proof",
        purpose="Prove adjacent slices are safe before widening proceeds.",
        helpers=("prove_adjacent_storage_slices",),
    ),
    WideningPipelineSpec(
        name="join_decision",
        purpose="Gate widening on alias facts, compatible views, and version safety.",
        helpers=("can_join_adjacent_storage_slices", "merge_storage_slice_domains"),
    ),
)


def describe_x86_16_widening_pipeline() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    return tuple((spec.name, spec.purpose, spec.helpers) for spec in WIDENING_PIPELINE)


def can_join_adjacent_storage_slices(low_expr, high_expr, *, alias_state: AliasState | None = None) -> bool:
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok:
        return False
    try:
        low_candidate = RegisterWideningCandidate.from_expr(low_expr)
        high_candidate = RegisterWideningCandidate.from_expr(high_expr)
    except ValueError:
        low_candidate = None
        high_candidate = None
    if low_candidate is not None and high_candidate is not None:
        if alias_state is None:
            return low_candidate.is_joinable_with(high_candidate)
        return can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=proof)

    try:
        low_candidate = WideningCandidate.from_expr(low_expr)
        high_candidate = WideningCandidate.from_expr(high_expr)
    except ValueError:
        return False
    if low_candidate.domain.is_unknown() or high_candidate.domain.is_unknown():
        return False
    if low_candidate.domain.is_mixed() or high_candidate.domain.is_mixed():
        return False
    if not low_candidate.is_joinable_with(high_candidate):
        return False
    return True


def merge_storage_slice_domains(low_expr, high_expr, *, alias_state: AliasState | None = None) -> _StorageDomainSignature:
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok or proof.merged_domain is None:
        return _StorageDomainSignature("mixed")
    return proof.merged_domain


__all__ = [
    "StorageJoinAnalysis",
    "WideningCandidate",
    "WideningPipelineSpec",
    "WideningProof",
    "WIDENING_PIPELINE",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_storage_slices",
    "collect_widening_candidates",
    "describe_widening_candidates",
    "describe_x86_16_widening_pipeline",
    "merge_storage_slice_domains",
    "prove_adjacent_storage_slices",
]
