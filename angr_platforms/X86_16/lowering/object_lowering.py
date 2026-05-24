from __future__ import annotations

# Layer: Lowering
# Responsibility: stable object/array lowering and segment-scale removal helpers from typed address evidence.
# Forbidden: rendered-text pattern recovery and CLI formatting ownership.

from dataclasses import dataclass
from typing import Any, Callable, TypeAlias

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable


def _match_segment_register_based_dereference(
    node,
    project,
    *,
    classify_segmented_dereference,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    segment_reg_name,
):
    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
        return None
    if not classified.allows_object_rewrite():
        return None

    addr_expr = classified.addr_expr
    base_terms = []

    def _is_segment_scale(term) -> bool:
        if not isinstance(term, structured_c.CBinaryOp):
            return False
        if term.op == "Mul":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    return True
            return False
        if term.op == "Shl":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 4:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    return True
        return False

    for term in flatten_c_add_terms(addr_expr):
        inner = unwrap_c_casts(term)
        if _is_segment_scale(inner):
            continue

        if c_constant_value(inner) is not None:
            continue

        if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
            base_terms.append(inner)
            continue

        return None

    if len(base_terms) != 1:
        return None
    return classified, base_terms[0]


def _strip_segment_scale_from_addr_expr(
    addr_expr,
    project,
    *,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    segment_reg_name,
):
    kept_terms = []

    def _is_segment_scale(term) -> bool:
        if not isinstance(term, structured_c.CBinaryOp):
            return False
        if term.op == "Mul":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    return True
            return False
        if term.op == "Shl":
            for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 4:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    return True
        return False

    for term in flatten_c_add_terms(addr_expr):
        inner = unwrap_c_casts(term)
        if _is_segment_scale(inner):
            continue
        kept_terms.append(term)

    if not kept_terms:
        return None
    result = kept_terms[0]
    for term in kept_terms[1:]:
        result = structured_c.CBinaryOp("Add", result, term, codegen=getattr(term, "codegen", None))
    return result


def _match_ss_stack_reference(node, project, *, project_rewrite_cache, classify_segmented_dereference):
    cache = project_rewrite_cache(project).setdefault("ss_stack_reference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_dereference(node, project)
    if classified is not None and classified.kind == "stack" and classified.stack_var is not None and classified.cvar is not None:
        result = (classified.stack_var, classified.cvar, classified.extra_offset)
        cache[key] = result
        return result

    cache[key] = None
    return None


BaseKey: TypeAlias = tuple[object, ...]
NamingCandidate: TypeAlias = tuple[int, int, int]
TraitCache: TypeAlias = dict[str, dict[BaseKey, object]]
BuildAccessTraitEvidenceProfiles: TypeAlias = Callable[[TraitCache], dict[BaseKey, Any]]
AccessTraitFieldName: TypeAlias = Callable[[int, int], str]


@dataclass(frozen=True)
class AccessTraitObjectHint:
    base_key: BaseKey
    kind: str
    candidates: tuple[NamingCandidate, ...]

    def should_rename_stack(self) -> bool:
        return self.kind in {"member", "array", "stack"}

    def candidate_field_names(self, *, access_trait_field_name: AccessTraitFieldName) -> tuple[str, ...]:
        names: list[str] = []
        seen: set[str] = set()
        for offset, _size, _count in self.candidates:
            field_name = access_trait_field_name(offset, 1)
            if field_name in seen:
                continue
            seen.add(field_name)
            names.append(field_name)
        return tuple(names)


def _stable_hint_kind(profile: Any, base_key: BaseKey) -> str | None:
    structured_kinds = set()
    for evidence in getattr(profile, "induction_evidence", ()) + getattr(profile, "stride_evidence", ()):
        kind = getattr(evidence, "kind", None)
        if kind == "member_like":
            structured_kinds.add("member")
        elif kind == "array_like":
            structured_kinds.add("array")
        elif kind == "induction_like":
            structured_kinds.add("induction")
    if structured_kinds:
        return next(iter(structured_kinds)) if len(structured_kinds) == 1 else None
    if (
        base_key
        and base_key[0] == "stack"
        and getattr(profile, "stack_like", ())
        and not getattr(profile, "array_like", ())
        and not getattr(profile, "induction_like", ())
    ):
        return "stack"
    simple_kinds = set()
    if getattr(profile, "member_like", ()):
        simple_kinds.add("member")
    if getattr(profile, "array_like", ()):
        simple_kinds.add("array")
    if getattr(profile, "induction_like", ()):
        simple_kinds.add("induction")
    if len(simple_kinds) == 1:
        return next(iter(simple_kinds))
    if simple_kinds:
        return None
    if base_key and base_key[0] == "stack" and getattr(profile, "stack_like", ()):
        return "stack"
    return None


def _build_stable_access_object_hints(
    traits: TraitCache,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> dict[BaseKey, AccessTraitObjectHint]:
    profiles = build_access_trait_evidence_profiles(traits)
    hints: dict[BaseKey, AccessTraitObjectHint] = {}
    for base_key, profile in profiles.items():
        kind = _stable_hint_kind(profile, base_key)
        if kind is None:
            continue
        candidates = profile.naming_candidates(base_key)
        if not candidates:
            continue
        hints[base_key] = AccessTraitObjectHint(
            base_key=base_key,
            kind=kind,
            candidates=candidates,
        )
    return hints


def _stable_access_object_hint_for_key(
    hints: dict[BaseKey, AccessTraitObjectHint],
    base_key: BaseKey | None,
) -> AccessTraitObjectHint | None:
    if base_key is None:
        return None
    hint = hints.get(base_key)
    if hint is not None:
        return hint
    if len(base_key) == 4 and base_key[0] == "stack":
        return hints.get(base_key[:3])
    return None


def _has_stable_access_object_hints(
    codegen: Any,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    return bool(
        _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        )
    )
