from __future__ import annotations

# Layer: Alias
# Responsibility: canonical alias transfer functions.
# Forbidden: lowering and rewrite ownership.

from dataclasses import dataclass

from .domains import FULL16, HIGH8, LOW8, register_domain_for_name, register_pair_name, register_view_for_name
from .state import AliasCell, AliasState


@dataclass(frozen=True)
class RegisterSliceExpr:
    expr: object
    view: object


@dataclass(frozen=True)
class RegisterConcatExpr:
    high: object
    low: object


def write_register(alias: AliasState, reg_name: str, expr: object) -> AliasCell | None:
    domain = register_domain_for_name(reg_name)
    view = register_view_for_name(reg_name)
    if domain is None or view is None:
        return None

    version = alias.bump_domain(domain)
    cell = alias.set(domain, view, expr, version=version)

    if view == FULL16:
        alias.set(domain, LOW8, RegisterSliceExpr(expr, LOW8), version=version)
        alias.set(domain, HIGH8, RegisterSliceExpr(expr, HIGH8), version=version)
        return cell

    full = alias.get(domain, FULL16)
    if full is None:
        alias.set(domain, FULL16, None, needs_synthesis=True, version=version)
    else:
        alias.mark_needs_synthesis(domain, FULL16)
    return cell


def synthesize_full_register(alias: AliasState, reg_name: str) -> RegisterConcatExpr | object | None:
    pair_name = register_pair_name(reg_name)
    if pair_name is None:
        return None
    domain = register_domain_for_name(pair_name)
    if domain is None:
        return None
    low = alias.get(domain, LOW8)
    high = alias.get(domain, HIGH8)
    if low is None or high is None:
        full = alias.get(domain, FULL16)
        return None if full is None else full.expr
    if low.expr is None or high.expr is None:
        return None
    return RegisterConcatExpr(high.expr, low.expr)


def read_register(alias: AliasState, reg_name: str) -> object | None:
    domain = register_domain_for_name(reg_name)
    view = register_view_for_name(reg_name)
    if domain is None or view is None:
        return None

    cell = alias.get(domain, view)
    if cell is not None and cell.expr is not None and cell.is_ready():
        return cell.expr

    if view == FULL16:
        synthesized = synthesize_full_register(alias, reg_name)
        return synthesized

    full = alias.get(domain, FULL16)
    if full is not None and full.expr is not None and full.is_ready():
        return RegisterSliceExpr(full.expr, view)
    return None


__all__ = ["RegisterConcatExpr", "RegisterSliceExpr", "read_register", "synthesize_full_register", "write_register"]
