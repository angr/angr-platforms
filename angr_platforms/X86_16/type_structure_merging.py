"""
Structure field merging for Inertia decompiler Phase 2.3.

Merges field access patterns from multiple functions to synthesize
common struct layouts. Detects overlapping field accesses and 
unifies struct type definitions across the binary.

Evidence: consistent field offset patterns, matching widths, shared base pointers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Set

from .ir.core import IRAddress
from .type_storage_object_bridge import load_storage_object_bridge

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _typed_ir_struct_candidates(codegen) -> dict[tuple[str, tuple[str, ...]], dict[str, object]]:
    artifact = getattr(codegen, "_inertia_vex_ir_artifact", None)
    function_ssa = getattr(codegen, "_inertia_vex_ir_function_ssa", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}

    phi_registers = {
        getattr(phi.target, "name", None)
        for phi in tuple(getattr(function_ssa, "phi_nodes", ()) or ())
        if getattr(getattr(phi, "target", None), "name", None) is not None
    }
    offsets_by_key: dict[tuple[str, tuple[str, ...]], set[int]] = {}
    widths_by_key: dict[tuple[str, tuple[str, ...]], set[int]] = {}
    for block in tuple(getattr(artifact, "blocks", ()) or ()):
        for instr in tuple(getattr(block, "instrs", ()) or ()):
            for atom in tuple(getattr(instr, "args", ()) or ()):
                if not isinstance(atom, IRAddress) or not atom.base:
                    continue
                if not phi_registers.intersection(set(atom.base)):
                    continue
                key = (atom.space.value, tuple(atom.base))
                offsets_by_key.setdefault(key, set()).add(int(atom.offset))
                widths_by_key.setdefault(key, set()).add(int(atom.size or 0))

    candidates: dict[tuple[str, tuple[str, ...]], dict[str, object]] = {}
    for key, offsets in sorted(offsets_by_key.items()):
        if len(offsets) < 2:
            continue
        candidates[key] = {
            "space": key[0],
            "base": key[1],
            "candidate_offsets": tuple(sorted(offsets)),
            "candidate_widths": tuple(sorted(widths_by_key.get(key, {0}))),
            "has_phi_evidence": True,
        }
    return candidates


@dataclass
class StructField:
    """Represents a recovered struct field."""

    name: str
    offset: int  # Bytes from struct start
    width: int  # Bit width (8, 16, 32, etc.)
    field_type: str  # "int", "char", "ptr", "struct", etc.
    access_count: int = 0  # How many times accessed
    functions: Set[str] = field(default_factory=set)  # Functions accessing this field

    def __repr__(self) -> str:
        return f"{self.name}@+{self.offset}:{self.field_type}({self.width}b)"

    def overlaps_with(self, other: StructField) -> bool:
        """Check if this field overlaps with another."""
        my_end = self.offset + (self.width // 8)
        other_end = other.offset + (other.width // 8)
        return not (my_end <= other.offset or self.offset >= other_end)


@dataclass
class StructType:
    """Recovered struct type definition."""

    name: str
    struct_id: int
    fields: dict[int, StructField] = field(default_factory=dict)  # offset -> StructField
    total_size: int = 0  # Union size if fields overlap
    is_union: bool = False  # True if fields overlap
    confidence: float = 0.5  # 0.0-1.0 based on evidence consistency

    def add_field(self, field: StructField) -> None:
        """Add a field to this struct."""
        if field.offset in self.fields:
            existing = self.fields[field.offset]
            if existing.name != field.name:
                # Field name conflict - possible union
                self.is_union = True
        else:
            self.fields[field.offset] = field
            self.total_size = max(self.total_size, field.offset + (field.width // 8))

    def merge_field(self, other_field: StructField) -> None:
        """Merge another struct's field into this one."""
        if other_field.offset not in self.fields:
            self.add_field(other_field)
        else:
            existing = self.fields[other_field.offset]
            existing.access_count += other_field.access_count
            existing.functions.update(other_field.functions)

    def __repr__(self) -> str:
        kind = "union" if self.is_union else "struct"
        return f"{kind} {self.name} {{ {len(self.fields)} fields, size={self.total_size} }}"


@dataclass
class FieldAccessPattern:
    """Observed field access from decompiled code."""

    struct_base: str  # Pointer to struct
    field_offset: int  # Bytes from base
    field_width: int  # Bit width accessed
    field_name: Optional[str]  # If known
    access_type: str  # "read", "write", "mixed"
    function: str  # Where accessed
    line_number: Optional[int]  # For tracking

    def __repr__(self) -> str:
        name_str = f".{self.field_name}" if self.field_name else f"+{self.field_offset}"
        return f"{self.struct_base}{name_str}:{self.access_type}"


class FieldAccessCollector:
    """Collects field access patterns from multiple functions."""

    def __init__(self):
        self.patterns: list[FieldAccessPattern] = []

    def collect_from_function(self, func_name: str, accesses: list[FieldAccessPattern]) -> None:
        """Collect field access patterns from a function."""
        for access in accesses:
            access.function = func_name
            self.patterns.append(access)

    def get_patterns_for_base(self, base_ptr: str) -> list[FieldAccessPattern]:
        """Get all patterns for a specific base pointer."""
        return [p for p in self.patterns if p.struct_base == base_ptr]

    def get_patterns_by_function(self, func_name: str) -> list[FieldAccessPattern]:
        """Get all patterns accessed in a function."""
        return [p for p in self.patterns if p.function == func_name]


class StructureFieldMerger:
    """
    Merges field access patterns into struct type definitions.

    Algorithm:
    1. Group patterns by base pointer
    2. Cluster by consistent offset/width/type patterns
    3. Detect overlapping accesses (union candidates)
    4. Synthesize struct definitions with confidence scoring
    5. Merge compatible structs across functions
    """

    def __init__(self):
        self.next_struct_id = 0
        self.structs: dict[str, StructType] = {}
        self.base_ptr_to_struct: dict[str, int] = {}  # base_ptr -> struct_id

    def merge_structs(self, patterns: list[FieldAccessPattern]) -> dict[str, StructType]:
        """
        Merge patterns into struct definitions.

        Args:
            patterns: List of FieldAccessPattern from all functions

        Returns:
            Dictionary mapping struct name to StructType
        """
        # Stage 1: Group patterns by base pointer
        by_base = {}
        for pattern in patterns:
            if pattern.struct_base not in by_base:
                by_base[pattern.struct_base] = []
            by_base[pattern.struct_base].append(pattern)

        # Stage 2: Create struct for each base pointer
        for base_ptr, base_patterns in by_base.items():
            struct_name = f"struct_{base_ptr.replace('*', 'p')}"
            struct_id = self.next_struct_id
            self.next_struct_id += 1

            struct = StructType(name=struct_name, struct_id=struct_id)

            # Add fields from all access patterns
            for pattern in base_patterns:
                field_name = pattern.field_name or f"field_{pattern.field_offset}"
                field = StructField(
                    name=field_name,
                    offset=pattern.field_offset,
                    width=pattern.field_width,
                    field_type="int",  # Would infer real type
                    access_count=1,
                    functions={pattern.function},
                )

                # Check for overlap
                for existing_field in struct.fields.values():
                    if field.overlaps_with(existing_field):
                        struct.is_union = True

                struct.add_field(field)

            # Confidence: more functions accessing = higher confidence
            functions_accessing = set()
            for pattern in base_patterns:
                functions_accessing.add(pattern.function)
            struct.confidence = min(1.0, 0.5 + (len(functions_accessing) * 0.1))

            self.structs[struct_name] = struct
            self.base_ptr_to_struct[base_ptr] = struct_id

        return self.structs

    def merge_compatible_structs(self) -> None:
        """Merge structs that have compatible layouts."""
        # Find structs with same field patterns
        merged = set()

        struct_list = list(self.structs.values())
        for i, struct1 in enumerate(struct_list):
            if i in merged:
                continue

            for j, struct2 in enumerate(struct_list[i + 1 :], i + 1):
                if j in merged:
                    continue

                if self._are_compatible(struct1, struct2):
                    # Merge struct2 into struct1
                    for field in struct2.fields.values():
                        struct1.merge_field(field)
                    merged.add(j)


    def _are_compatible(self, struct1: StructType, struct2: StructType) -> bool:
        """Check if two structs have compatible layouts."""
        if struct1.is_union != struct2.is_union:
            return False

        # Check field overlap
        common_offsets = set(struct1.fields.keys()) & set(struct2.fields.keys())
        for offset in common_offsets:
            field1 = struct1.fields[offset]
            field2 = struct2.fields[offset]
            if field1.width != field2.width:
                return False

        return True


class StructRecoveryInfo:
    """High-level struct recovery metadata."""

    def __init__(self, struct_type: StructType):
        self.name = struct_type.name
        self.size = struct_type.total_size
        self.fields = struct_type.fields
        self.is_union = struct_type.is_union
        self.confidence = struct_type.confidence

    def __repr__(self) -> str:
        return f"{self.name} (size={self.size}, confidence={self.confidence:.1%})"


def apply_x86_16_structure_field_merging(codegen) -> bool:
    """
    Apply structure field merging pass to codegen.

    This is the entry point for Phase 2.3 decompiler framework integration.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if struct synthesis occurred, False otherwise

    Note:
        This pass collects struct recovery metadata but doesn't modify
        codegen text directly (that happens in later phases).
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    try:
        project = getattr(codegen, "project", None)
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        bridge = None
        if project is not None:
            bridge = load_storage_object_bridge(project, function_addr, codegen=codegen)
        typed_ir_facts = _typed_ir_struct_candidates(codegen)

        # Track that struct merging pass ran
        codegen._inertia_struct_merging_applied = True
        codegen._inertia_struct_merging_bridge = bridge
        codegen._inertia_struct_merging_struct_facts = {} if bridge is None else bridge.facts_by_base
        codegen._inertia_struct_merging_member_facts = {} if bridge is None else bridge.member_facts
        codegen._inertia_struct_merging_array_facts = {} if bridge is None else bridge.array_facts
        codegen._inertia_struct_merging_refusal_facts = {} if bridge is None else bridge.refusal_facts
        codegen._inertia_struct_merging_typed_ir_facts = typed_ir_facts
        codegen._inertia_struct_merging_changed = bool((bridge is not None and bridge.facts_by_base) or typed_ir_facts)
        codegen._inertia_struct_merging_stats = {
            "field_accesses": 0 if bridge is None else sum(len(fact.candidate_offsets) for fact in bridge.facts_by_base.values()),
            "structs_synthesized": (0 if bridge is None else len(bridge.facts_by_base)) + len(typed_ir_facts),
            "structs_merged": 0,
            "member_facts": 0 if bridge is None else len(bridge.member_facts),
            "array_facts": 0 if bridge is None else len(bridge.array_facts),
            "refusal_facts": 0 if bridge is None else len(bridge.refusal_facts),
        }

        logger.debug(
            "Structure field merging pass completed: records=%s members=%s arrays=%s refusals=%s typed_ir=%s",
            0 if bridge is None else len(bridge.facts_by_base),
            0 if bridge is None else len(bridge.member_facts),
            0 if bridge is None else len(bridge.array_facts),
            0 if bridge is None else len(bridge.refusal_facts),
            len(typed_ir_facts),
        )
        return False  # No direct modifications at this stage
    except Exception as ex:
        logger.warning("Structure field merging pass failed: %s", ex)
        codegen._inertia_struct_merging_error = str(ex)
        return False
