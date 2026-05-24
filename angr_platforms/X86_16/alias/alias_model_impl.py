from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from ..alias_domains import register_pair_name


def _canonical_stack_base(base: str | None) -> str:
    if not isinstance(base, str) or not base:
        return "bp"
    normalized = base.lower()
    if normalized in {"bp", "sp", "ss"}:
        return "bp"
    return normalized


@dataclass(frozen=True)
class _StorageView:
    bit_offset: int = 0
    bit_width: int | None = None

    def is_full_width(self) -> bool:
        return self.bit_offset == 0 and self.bit_width is not None

    def end_bit(self) -> int | None:
        if self.bit_width is None:
            return None
        return self.bit_offset + self.bit_width

    def can_join(self, other: "_StorageView") -> bool:
        if self.bit_width is None or other.bit_width is None:
            return False
        return self.end_bit() == other.bit_offset or other.end_bit() == self.bit_offset

    def join(self, other: "_StorageView") -> "_StorageView | None":
        if self.bit_width is None or other.bit_width is None:
            return None
        if self.bit_offset <= other.bit_offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_bit() != second.bit_offset:
            return None
        return _StorageView(first.bit_offset, first.bit_width + second.bit_width)


@dataclass(frozen=True)
class _StackSlotIdentity:
    base: str
    offset: int
    width: int | None = None
    region: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "base", _canonical_stack_base(self.base))

    def end_offset(self) -> int | None:
        if self.width is None:
            return None
        return self.offset + self.width

    def can_join(self, other: "_StackSlotIdentity") -> bool:
        if self.base != other.base:
            return False
        if self.region is not None and other.region is not None and self.region != other.region:
            return False
        if self.width is None or other.width is None:
            return False
        return self.end_offset() == other.offset or other.end_offset() == self.offset

    def join(self, other: "_StackSlotIdentity") -> "_StackSlotIdentity | None":
        if not self.can_join(other):
            return None
        if self.offset <= other.offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_offset() != second.offset:
            return None
        region = first.region if first.region == second.region else first.region or second.region
        return _StackSlotIdentity(first.base, first.offset, first.width + second.width, region=region)


def _storage_view_for_variable(variable) -> _StorageView:
    size = getattr(variable, "size", 0) or 0
    width_bits = size * 8 if size else None
    name = (getattr(variable, "ident", None) or getattr(variable, "name", None) or "").lower()
    if isinstance(variable, SimRegisterVariable):
        low_high_offsets = {
            "al": 0,
            "ah": 8,
            "bl": 0,
            "bh": 8,
            "cl": 0,
            "ch": 8,
            "dl": 0,
            "dh": 8,
        }
        if name in low_high_offsets:
            return _StorageView(low_high_offsets[name], width_bits)
        reg = getattr(variable, "reg", None)
        if isinstance(reg, int) and size in {1, 2}:
            if size == 1:
                return _StorageView(8 if reg % 2 else 0, 8)
            return _StorageView(0, width_bits)
    if isinstance(variable, SimStackVariable):
        return _StorageView(getattr(variable, "offset", 0) * 8, width_bits)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", 0)
        if isinstance(addr, int):
            return _StorageView(addr * 8, width_bits)
    return _StorageView(0, width_bits)


@dataclass(frozen=True)
class _StorageDomainSignature:
    space: str
    width: int | None = None
    view: _StorageView | None = None
    stack_slot: _StackSlotIdentity | None = field(default=None, compare=False)

    def is_mixed(self) -> bool:
        return self.space == "mixed"

    def is_unknown(self) -> bool:
        return self.space == "unknown"

    def is_const(self) -> bool:
        return self.space == "const"

    def __str__(self) -> str:
        if self.width is None:
            return self.space
        return f"{self.space}:{self.width}"

    def can_join(self, other: "_StorageDomainSignature") -> bool:
        if self.space != other.space:
            return False
        if self.view is None or other.view is None:
            return False
        if self.space == "stack":
            if self.stack_slot is None or other.stack_slot is None:
                return self.view.can_join(other.view)
            if not self.stack_slot.can_join(other.stack_slot):
                return False
        return self.view.can_join(other.view)

    def join(self, other: "_StorageDomainSignature") -> "_StorageDomainSignature | None":
        if not self.can_join(other):
            return None
        joined_view = self.view.join(other.view)
        if joined_view is None:
            return None
        width = self.width or 0
        other_width = other.width or 0
        stack_slot = None
        if self.space == "stack" and self.stack_slot is not None and other.stack_slot is not None:
            stack_slot = self.stack_slot.join(other.stack_slot)
        return _StorageDomainSignature(self.space, width + other_width, joined_view, stack_slot=stack_slot)


@dataclass(frozen=True)
class _CopyAliasState:
    domain: _StorageDomainSignature
    expr: object
    needs_synthesis: bool = False

    def can_inline(self) -> bool:
        return not self.domain.is_mixed() and not self.needs_synthesis

    def merge(self, other: "_CopyAliasState") -> "_CopyAliasState":
        merged_domain = _merge_storage_domains(self.domain, other.domain)
        merged_expr = self.expr if self.expr is not None else other.expr
        merged_needs_synthesis = self.needs_synthesis or other.needs_synthesis
        if merged_domain.is_mixed():
            merged_needs_synthesis = True
            merged_expr = other.expr
        return _CopyAliasState(merged_domain, merged_expr, needs_synthesis=merged_needs_synthesis)


@dataclass(frozen=True)
class _StackPointerAliasState:
    base: structured_c.CVariable
    offset: int = 0

    def shifted(self, delta: int) -> "_StackPointerAliasState":
        return _StackPointerAliasState(self.base, self.offset + delta)


@dataclass(frozen=True)
class AliasStorageFacts:
    domain: _StorageDomainSignature
    identity: tuple[str, Any] | None = None

    def same_domain(self, other: "AliasStorageFacts") -> bool:
        if self.domain.space != other.domain.space:
            return False
        if self.identity is None or other.identity is None:
            return True
        kind, value = self.identity
        other_kind, other_value = other.identity
        if kind != other_kind:
            return False
        if kind == "register":
            return value == other_value
        if kind == "stack":
            return value == other_value or (hasattr(value, "can_join") and value.can_join(other_value))
        if kind in {"memory", "far_pointer"}:
            return value == other_value
        return value == other_value

    def compatible_view(self, other: "AliasStorageFacts") -> bool:
        if self.domain.view is None or other.domain.view is None:
            return False
        return self.domain.view.can_join(other.domain.view)

    def needs_synthesis(self) -> bool:
        return self.domain.is_mixed() or self.domain.is_unknown()

    def can_join(self, other: "AliasStorageFacts") -> bool:
        return self.same_domain(other) and self.compatible_view(other) and not self.needs_synthesis() and not other.needs_synthesis()


@dataclass(frozen=True)
class AliasRecoveryAPISpec:
    name: str
    purpose: str
    helpers: tuple[str, ...]


def _storage_domain_for_variable(variable) -> _StorageDomainSignature:
    if isinstance(variable, SimStackVariable):
        width = getattr(variable, "size", 0)
        base = _canonical_stack_base(getattr(variable, "base", None))
        offset = getattr(variable, "offset", 0)
        region = getattr(variable, "region", None)
        return _StorageDomainSignature(
            "stack",
            width,
            _storage_view_for_variable(variable),
            stack_slot=_StackSlotIdentity(base, offset, width, region=region),
        )
    if isinstance(variable, SimRegisterVariable):
        width = getattr(variable, "size", 0)
        return _StorageDomainSignature("register", width, _storage_view_for_variable(variable))
    if isinstance(variable, SimMemoryVariable):
        width = getattr(variable, "size", 0)
        return _StorageDomainSignature("memory", width, _storage_view_for_variable(variable))
    return _StorageDomainSignature("unknown")


def _alias_identity_for_variable(variable) -> tuple[str, Any] | None:
    if isinstance(variable, SimStackVariable):
        slot = _stack_slot_identity_for_variable(variable)
        if slot is not None:
            return ("stack", slot)
    if isinstance(variable, SimRegisterVariable):
        name = getattr(variable, "name", None)
        reg = getattr(variable, "reg", None)
        size = getattr(variable, "size", 0) or 0
        if isinstance(reg, int) and size in {1, 2}:
            pair_index = reg // 2
            pair_names = ("ax", "cx", "dx", "bx")
            if 0 <= pair_index < len(pair_names):
                return ("register", pair_names[pair_index])
        pair_name = register_pair_name(name)
        if pair_name is not None:
            return ("register", pair_name)
    if isinstance(variable, SimMemoryVariable):
        addr = getattr(variable, "addr", None)
        if isinstance(addr, int):
            return ("memory", addr)
    return None


def _canonical_stack_offset(offset: Any) -> Any:
    if not isinstance(offset, int):
        return offset
    # 16-bit stack slots may surface through wrapped unsigned offsets such as
    # 0xfffe for BP-2. Canonicalize those identities before local/materialized
    # consumers compare slots.
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def _stack_slot_identity_for_variable(variable) -> _StackSlotIdentity | None:
    if not isinstance(variable, SimStackVariable):
        return None
    base = _canonical_stack_base(getattr(variable, "base", None))
    offset = _canonical_stack_offset(getattr(variable, "offset", 0))
    width = getattr(variable, "size", 0) or None
    region = getattr(variable, "region", None)
    return _StackSlotIdentity(base, offset, width, region=region)


def _stack_storage_facts_for_segmented_address_8616(
    segment_name: str | None,
    offset: int | None,
    width: int | None,
    *,
    region: int | None = None,
) -> AliasStorageFacts | None:
    if not isinstance(segment_name, str) or segment_name.lower() != "ss":
        return None
    if not isinstance(offset, int):
        return None

    stack_width = width if isinstance(width, int) and width > 0 else None
    bit_width = stack_width * 8 if stack_width is not None else None
    stack_slot = _StackSlotIdentity("bp", offset, stack_width, region=region)
    domain = _StorageDomainSignature(
        "stack",
        stack_width,
        _StorageView(offset * 8, bit_width),
        stack_slot=stack_slot,
    )
    return AliasStorageFacts(domain=domain, identity=("stack", stack_slot))


def _same_stack_slot_identity(lhs, rhs) -> bool:
    if not isinstance(lhs, SimStackVariable) or not isinstance(rhs, SimStackVariable):
        return False
    lhs_identity = _stack_slot_identity_for_variable(lhs)
    rhs_identity = _stack_slot_identity_for_variable(rhs)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity == rhs_identity


def _stack_slot_identity_can_join(lhs, rhs) -> bool:
    if not isinstance(lhs, SimStackVariable) or not isinstance(rhs, SimStackVariable):
        return False
    lhs_identity = _stack_slot_identity_for_variable(lhs)
    rhs_identity = _stack_slot_identity_for_variable(rhs)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity.can_join(rhs_identity)


def _storage_domain_for_expr(expr) -> _StorageDomainSignature:
    from ..semantics.alias_query import _storage_domain_for_expr as _impl

    return _impl(expr)


@dataclass(frozen=True)
class AliasFailure:
    """Explicit failure record when alias recovery cannot resolve a proven address.

    AGENTS rule: proven SS must become stack slot, never silently fallback to memory.
    """
    reason: str
    address: "object | None" = None
    space: str | None = None
    offset: int | None = None


def alias_facts_for_ir_address_8616(addr: "object") -> AliasStorageFacts | AliasFailure | None:
    """Build alias storage facts from a typed IRAddress.

    This is the canonical IR→Alias entry point.  Must be called at IR creation time,
    not later in the pipeline.

    Returns:
        AliasStorageFacts on success.
        AliasFailure when the address cannot be classified yet (not silently hidden).
        None for addresses that are genuinely unclassifiable.
    Raises PipelineHardError for proven addresses that cannot be resolved.

    AGENTS rule #1: Must not guess. If SS is proven but unresolvable, fail hard.
    """
    from ..ir.core import IRAddress, MemSpace, AddressStatus, SegmentOrigin, is_stack_address_8616
    from ..pipeline.errors import PipelineHardError

    if not isinstance(addr, IRAddress):
        return None

    if addr.space == MemSpace.SS:
        # Only create stable stack facts when all conditions are met:
        #   1. Base contains "bp"
        #   2. Status is STABLE
        #   3. Offset is an integer (not symbolic)
        # IMPORTANT:
        # ("sp",) alone is NOT sufficient.
        # Stability additionally requires:
        #   - proven SP delta
        #   - stable offset
        #
        # Dynamic SP traffic must remain PROVISIONAL.
        has_stack_base = addr.base in {("bp",), ("sp",)}
        has_stable_offset = isinstance(addr.offset, int) and addr.status == AddressStatus.STABLE

        if is_stack_address_8616(addr) and has_stack_base and has_stable_offset:
            return _stack_storage_facts_for_segmented_address_8616(
                "ss",
                addr.offset,
                addr.size,
                region=None,
            )

        # Hard-fail only for STABLE SS addresses without a recognized BP base.
        # PROVISIONAL SS addresses (e.g. SP-relative push/pop during prologue
        # before BP is set up, or symbolic offsets not yet resolved) are expected
        # and must not block decompilation.
        if addr.status == AddressStatus.STABLE:
            raise PipelineHardError(
                f"unresolved SS address: base={addr.base} offset={addr.offset} status={addr.status}",
                layer="alias",
            )
        # PROVISIONAL SS: return explicit AliasFailure — not silently hidden
        return AliasFailure(
            reason="provisional SS address cannot be classified",
            address=addr,
            space="SS",
            offset=addr.offset if isinstance(addr.offset, int) else None,
        )

    # DS/ES memory
    if addr.space in {MemSpace.DS, MemSpace.ES}:
        return AliasStorageFacts(
            domain=_StorageDomainSignature(
                "memory",
                addr.size,
                _StorageView(addr.offset * 8 if isinstance(addr.offset, int) else 0, addr.size * 8 if addr.size else None),
            ),
            identity=("memory", addr.offset) if isinstance(addr.offset, int) else None,
        )

    return None


def describe_alias_storage(expr) -> AliasStorageFacts:
    from ..semantics.alias_query import describe_alias_storage as _impl

    return _impl(expr)


def same_alias_storage_domain(lhs, rhs) -> bool:
    from ..semantics.alias_query import same_alias_storage_domain as _impl

    return _impl(lhs, rhs)


def compatible_alias_storage_views(lhs, rhs) -> bool:
    from ..semantics.alias_query import compatible_alias_storage_views as _impl

    return _impl(lhs, rhs)


def needs_alias_synthesis(expr) -> bool:
    from ..semantics.alias_query import needs_alias_synthesis as _impl

    return _impl(expr)


def can_join_alias_storage(lhs, rhs) -> bool:
    from ..semantics.alias_query import can_join_alias_storage as _impl

    return _impl(lhs, rhs)


ALIAS_RECOVERY_API: tuple[AliasRecoveryAPISpec, ...] = (
    AliasRecoveryAPISpec(
        name="same_domain",
        purpose="Determine whether two expressions belong to the same storage family.",
        helpers=("same_alias_storage_domain",),
    ),
    AliasRecoveryAPISpec(
        name="compatible_view",
        purpose="Determine whether two expressions can join as adjacent or compatible slices.",
        helpers=("compatible_alias_storage_views",),
    ),
    AliasRecoveryAPISpec(
        name="needs_synthesis",
        purpose="Detect mixed or unknown storage that should remain explicitly synthesized.",
        helpers=("needs_alias_synthesis",),
    ),
    AliasRecoveryAPISpec(
        name="can_join",
        purpose="Check the downstream-ready join condition used by widening and object recovery.",
        helpers=("can_join_alias_storage",),
    ),
)


def describe_x86_16_alias_recovery_api() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    return tuple((spec.name, spec.purpose, spec.helpers) for spec in ALIAS_RECOVERY_API)


def _merge_storage_domains(existing: _StorageDomainSignature | None, incoming: _StorageDomainSignature) -> _StorageDomainSignature:
    if existing is None:
        return incoming
    if existing == incoming:
        return existing
    joined = existing.join(incoming)
    if joined is not None:
        return joined
    return _StorageDomainSignature("mixed")


def _unwrap_c_casts(expr):
    from ..semantics.expression_analysis import _unwrap_c_casts as _impl

    return _impl(expr)


__all__ = [
    "_StorageView",
    "_StackSlotIdentity",
    "_StorageDomainSignature",
    "_CopyAliasState",
    "_StackPointerAliasState",
    "_stack_slot_identity_for_variable",
    "_stack_storage_facts_for_segmented_address_8616",
    "_same_stack_slot_identity",
    "_stack_slot_identity_can_join",
    "_storage_view_for_variable",
    "_storage_domain_for_variable",
    "_storage_domain_for_expr",
    "_merge_storage_domains",
    "AliasFailure",
    "AliasStorageFacts",
    "AliasRecoveryAPISpec",
    "ALIAS_RECOVERY_API",
    "alias_facts_for_ir_address_8616",
    "can_join_alias_storage",
    "compatible_alias_storage_views",
    "describe_alias_storage",
    "describe_x86_16_alias_recovery_api",
    "needs_alias_synthesis",
    "same_alias_storage_domain",
]
