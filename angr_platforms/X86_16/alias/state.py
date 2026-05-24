from __future__ import annotations

# Layer: Alias
# Responsibility: canonical alias-state ownership.
# Forbidden: lowering and rewrite ownership.

from dataclasses import dataclass, field

from .domains import DomainKey, View


@dataclass(frozen=True)
class AliasCell:
    domain: DomainKey
    view: View
    expr: object
    needs_synthesis: bool = False
    version: int = 0

    def is_ready(self) -> bool:
        return not self.needs_synthesis


@dataclass
class AliasState:
    _cells: dict[tuple[DomainKey, View], AliasCell] = field(default_factory=dict)
    _versions: dict[DomainKey, int] = field(default_factory=dict)

    def version_of(self, domain: DomainKey) -> int:
        return self._versions.get(domain, 0)

    def bump_domain(self, domain: DomainKey) -> int:
        new_version = self.version_of(domain) + 1
        self._versions[domain] = new_version
        return new_version

    def get(self, domain: DomainKey, view: View) -> AliasCell | None:
        return self._cells.get((domain, view))

    def set(self, domain: DomainKey, view: View, expr: object, *, needs_synthesis: bool = False, version: int | None = None) -> AliasCell:
        if version is None:
            version = self.version_of(domain)
        cell = AliasCell(domain, view, expr, needs_synthesis=needs_synthesis, version=version)
        self._cells[(domain, view)] = cell
        return cell

    def mark_needs_synthesis(self, domain: DomainKey, view: View) -> None:
        cell = self.get(domain, view)
        if cell is not None:
            self._cells[(domain, view)] = AliasCell(cell.domain, cell.view, cell.expr, needs_synthesis=True, version=cell.version)

    def clear_domain(self, domain: DomainKey) -> None:
        doomed = [key for key in self._cells if key[0] == domain]
        for key in doomed:
            del self._cells[key]


__all__ = ["AliasCell", "AliasState"]
