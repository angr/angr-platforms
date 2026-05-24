from __future__ import annotations

# Layer: Semantics
# Responsibility: expression-facing alias queries over typed alias storage facts.
# Forbidden: alias-state ownership, CLI formatting, rendered-text matching.

from ..alias.alias_model_impl import (
    AliasStorageFacts,
    _StorageDomainSignature,
    _StorageView,
    _alias_identity_for_variable,
    _storage_domain_for_variable,
)
from .expression_analysis import _mk_fp_components, _unwrap_c_casts


def _storage_domain_for_expr(expr) -> _StorageDomainSignature:
    expr = _unwrap_c_casts(expr)
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if variable is None:
            return _StorageDomainSignature("unknown")
        return _storage_domain_for_variable(variable)
    if isinstance(expr, structured_c.CConstant):
        return _StorageDomainSignature("const")
    mk_fp_components = _mk_fp_components(expr)
    if mk_fp_components is not None:
        return _StorageDomainSignature("far_pointer", 32, _StorageView(0, 32))
    if isinstance(expr, structured_c.CUnaryOp):
        return _storage_domain_for_expr(expr.operand)
    if isinstance(expr, structured_c.CBinaryOp):
        domains: set[_StorageDomainSignature] = set()
        domain_list: list[_StorageDomainSignature] = []
        for child in (expr.lhs, expr.rhs):
            domain = _storage_domain_for_expr(child)
            if domain.is_const():
                continue
            if domain.is_unknown():
                return _StorageDomainSignature("unknown")
            domains.add(domain)
            domain_list.append(domain)
        if not domains:
            return _StorageDomainSignature("const")
        if len(domains) == 1:
            return next(iter(domains))
        if len(domain_list) == 2:
            joined = domain_list[0].join(domain_list[1])
            if joined is not None:
                return joined
        return _StorageDomainSignature("mixed")
    return _StorageDomainSignature("unknown")


def describe_alias_storage(expr) -> AliasStorageFacts:
    domain = _storage_domain_for_expr(expr)
    identity = None
    expr = _unwrap_c_casts(expr)
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CVariable):
        variable = getattr(expr, "variable", None)
        if variable is not None:
            identity = _alias_identity_for_variable(variable)
    else:
        mk_fp_components = _mk_fp_components(expr)
        if mk_fp_components is not None:
            identity = ("far_pointer", mk_fp_components)
    return AliasStorageFacts(domain, identity)


def same_alias_storage_domain(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).same_domain(describe_alias_storage(rhs))


def compatible_alias_storage_views(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).compatible_view(describe_alias_storage(rhs))


def needs_alias_synthesis(expr) -> bool:
    return describe_alias_storage(expr).needs_synthesis()


def can_join_alias_storage(lhs, rhs) -> bool:
    return describe_alias_storage(lhs).can_join(describe_alias_storage(rhs))


__all__ = [
    "_storage_domain_for_expr",
    "describe_alias_storage",
    "same_alias_storage_domain",
    "compatible_alias_storage_views",
    "needs_alias_synthesis",
    "can_join_alias_storage",
]
