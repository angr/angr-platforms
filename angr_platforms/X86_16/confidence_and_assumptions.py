"""
Confidence levels and assumption tracking for decompiler recovery.

Extends recovery_confidence.py with explicit confidence/assumption reporting
infrastructure for structuring and type inference stages.

Confidence assignments:
- HIGH: Strong evidence from multiple sources (e.g., proven types from alias model)
- MEDIUM: Single evidence source or weak evidence (e.g., inferred from pattern)
- LOW: Guessed or assumed (e.g., no evidence, convention-based)

Tracking:
- Unresolved indirect targets
- Guessed helper signatures
- Uncertain segmented pointers
- Weak type inferences
- Conservative fallback choices

Output:
- Function comment headers with confidence breakdown
- Milestone reports with confidence statistics
- Scan summary with confidence distribution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .codegen_metadata import get_codegen_sequence_attr, get_codegen_side_metadata

__all__ = [
    "ConfidenceLevel",
    "ConfidenceMarker",
    "ConfidenceTracker",
    "FunctionConfidenceReport",
    "ScanConfidenceSummary",
    "build_function_with_confidence_markers",
    "apply_x86_16_confidence_and_assumptions",
]


class ConfidenceLevel(Enum):
    """Confidence level for recovery facts."""

    HIGH = "HIGH"  # Strong multiple-source evidence
    MEDIUM = "MEDIUM"  # Single source or weak evidence
    LOW = "LOW"  # Guessed or assumed


@dataclass(frozen=True, slots=True)
class ConfidenceMarker:
    """Confidence marker attached to recovered facts."""

    fact_kind: str  # 'struct', 'array', 'pointer', 'type', 'loop', 'switch'
    fact_detail: str  # Description of what was recovered
    confidence: ConfidenceLevel
    evidence_count: int  # Number of sources supporting this
    reason: Optional[str] = None  # Why we chose this confidence level


@dataclass(slots=True)
class ConfidenceTracker:
    """Aggregates confidence markers from recovery stages."""

    markers: list[ConfidenceMarker] = field(default_factory=list)

    def add_marker(
        self,
        fact_kind: str,
        fact_detail: str,
        confidence: ConfidenceLevel,
        evidence_count: int = 1,
        reason: Optional[str] = None,
    ) -> None:
        """Add a confidence marker."""
        marker = ConfidenceMarker(
            fact_kind=fact_kind,
            fact_detail=fact_detail,
            confidence=confidence,
            evidence_count=evidence_count,
            reason=reason,
        )
        self.markers.append(marker)

    def high_count(self) -> int:
        """Count HIGH confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.HIGH)

    def medium_count(self) -> int:
        """Count MEDIUM confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.MEDIUM)

    def low_count(self) -> int:
        """Count LOW confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.LOW)

    def total_count(self) -> int:
        """Total marker count."""
        return len(self.markers)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "high_count": self.high_count(),
            "medium_count": self.medium_count(),
            "low_count": self.low_count(),
            "total_count": self.total_count(),
            "markers": [
                {
                    "fact_kind": m.fact_kind,
                    "fact_detail": m.fact_detail,
                    "confidence": m.confidence.value,
                    "evidence_count": m.evidence_count,
                    "reason": m.reason,
                }
                for m in self.markers
            ],
        }


@dataclass(slots=True)
class FunctionConfidenceReport:
    """Confidence report for a single function."""

    func_addr: int
    func_name: str
    confidence_tracker: ConfidenceTracker
    assumptions: list[str] = field(default_factory=list)
    critical_unknowns: list[str] = field(default_factory=list)

    def add_assumption(self, assumption: str) -> None:
        """Record an assumption."""
        self.assumptions.append(assumption)

    def add_critical_unknown(self, unknown: str) -> None:
        """Record a critical unknown (may affect correctness)."""
        self.critical_unknowns.append(unknown)

    def overall_confidence(self) -> ConfidenceLevel:
        """Determine overall function confidence."""
        # Critical unknowns always lower confidence to LOW
        if self.critical_unknowns:
            return ConfidenceLevel.LOW

        total = self.confidence_tracker.total_count()
        if total == 0:
            return ConfidenceLevel.MEDIUM

        high = self.confidence_tracker.high_count()
        medium = self.confidence_tracker.medium_count()
        low = self.confidence_tracker.low_count()

        high_ratio = high / total
        low_ratio = low / total

        if high_ratio >= 0.8 and low_ratio == 0:
            return ConfidenceLevel.HIGH
        elif low_ratio >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.MEDIUM

    def comment_header(self) -> str:
        """Generate function comment header with confidence breakdown."""
        lines = [
            f"// {self.func_name} @ {hex(self.func_addr)}",
            f"// Confidence: {self.overall_confidence().value}",
        ]

        total = self.confidence_tracker.total_count()
        if total > 0:
            high = self.confidence_tracker.high_count()
            medium = self.confidence_tracker.medium_count()
            low = self.confidence_tracker.low_count()
            lines.append(f"// Evidence: {high} HIGH, {medium} MEDIUM, {low} LOW")

        if self.assumptions:
            lines.append(f"// Assumptions: {len(self.assumptions)} recorded")
            for assumption in self.assumptions[:3]:  # Show first 3
                lines.append(f"//   - {assumption}")
            if len(self.assumptions) > 3:
                lines.append(f"//   ... and {len(self.assumptions) - 3} more")

        if self.critical_unknowns:
            lines.append("// ⚠️ CRITICAL UNKNOWNS:")
            for unknown in self.critical_unknowns:
                lines.append(f"//   - {unknown}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "func_addr": hex(self.func_addr),
            "func_name": self.func_name,
            "overall_confidence": self.overall_confidence().value,
            "confidence_breakdown": self.confidence_tracker.to_dict(),
            "assumptions_count": len(self.assumptions),
            "assumptions": self.assumptions,
            "critical_unknowns_count": len(self.critical_unknowns),
            "critical_unknowns": self.critical_unknowns,
        }


@dataclass(slots=True)
class ScanConfidenceSummary:
    """Summary of confidence levels across multiple functions."""

    total_functions: int = 0
    high_confidence_count: int = 0
    medium_confidence_count: int = 0
    low_confidence_count: int = 0
    total_assumptions: int = 0
    total_critical_unknowns: int = 0

    def add_function_report(self, report: FunctionConfidenceReport) -> None:
        """Add a function report to the summary."""
        self.total_functions += 1
        confidence = report.overall_confidence()

        if confidence == ConfidenceLevel.HIGH:
            self.high_confidence_count += 1
        elif confidence == ConfidenceLevel.MEDIUM:
            self.medium_confidence_count += 1
        else:
            self.low_confidence_count += 1

        self.total_assumptions += len(report.assumptions)
        self.total_critical_unknowns += len(report.critical_unknowns)

    def high_confidence_ratio(self) -> float:
        """Percentage of high-confidence functions."""
        if self.total_functions == 0:
            return 0.0
        return self.high_confidence_count / self.total_functions

    def scan_classification(self) -> str:
        """Overall scan classification based on confidence distribution."""
        if self.total_functions == 0:
            return "empty"

        high_ratio = self.high_confidence_ratio()
        low_ratio = (
            self.low_confidence_count / self.total_functions if self.total_functions > 0 else 0
        )

        if high_ratio >= 0.8 and low_ratio == 0 and self.total_critical_unknowns == 0:
            return "strong"
        elif low_ratio >= 0.3 or self.total_critical_unknowns > 0:
            return "weak"
        else:
            return "partial"

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "total_functions": self.total_functions,
            "high_confidence_count": self.high_confidence_count,
            "medium_confidence_count": self.medium_confidence_count,
            "low_confidence_count": self.low_confidence_count,
            "high_confidence_ratio": self.high_confidence_ratio(),
            "total_assumptions": self.total_assumptions,
            "total_critical_unknowns": self.total_critical_unknowns,
            "scan_classification": self.scan_classification(),
        }


def build_function_with_confidence_markers(
    cfunc, confidence_report: FunctionConfidenceReport, *, codegen=None
) -> bool:
    """
    Attach confidence markers to decompiled function.

    Args:
        cfunc: Decompiled function (CFunction)
        confidence_report: Confidence report with markers and assumptions

    Returns:
        True if markers were successfully attached
    """
    if cfunc is None:
        return False

    # Attach confidence data as metadata
    if codegen is not None:
        metadata = get_codegen_side_metadata(codegen)
        metadata["confidence_report"] = confidence_report
    try:
        cfunc_metadata = getattr(cfunc, "_recovery_metadata", None)
        if not isinstance(cfunc_metadata, dict):
            cfunc_metadata = {}
            cfunc._recovery_metadata = cfunc_metadata
        cfunc_metadata["confidence_report"] = confidence_report
    except Exception:
        pass

    # Prepend comment header to function
    if hasattr(cfunc, "decompile"):
        original_decomp = cfunc.decompile()
        header = confidence_report.comment_header()
        if original_decomp:
            cfunc._cached_decomp = header + "\n\n" + original_decomp

    return True


def apply_x86_16_confidence_and_assumptions(codegen) -> bool:
    """
    Decompiler pass: Attach confidence markers to all recovered functions.

    This pass:
    1. Collects confidence markers from type inference stages
    2. Aggregates assumptions from structuring/type analysis
    3. Attaches metadata to decompiled functions
    4. Emits confidence hierarchy in function comment headers

    Args:
        codegen: Decompiler code generator

    Returns:
        True if pass succeeded
    """
    try:
        # For each function in the decompiler
        if hasattr(codegen, "cfunc") and codegen.cfunc:
            cfunc = codegen.cfunc
            func_addr = getattr(cfunc, "addr", 0)
            func_name = getattr(cfunc, "name", f"func_{hex(func_addr)}")

            # Build confidence tracker from recovered types/structures
            tracker = ConfidenceTracker()

            # Check for recovered structs (Phase 2.3)
            if hasattr(cfunc, "_struct_recovery_info"):
                struct_info = cfunc._struct_recovery_info
                if struct_info and hasattr(struct_info, "structs"):
                    for struct in struct_info.structs:
                        # Struct from multi-function agreement = HIGH confidence
                        struct_name = getattr(struct, "name", "unknown_struct")
                        evidence_count = len(
                            getattr(struct, "functions", [])
                        )  # Number of functions using it
                        confidence = ConfidenceLevel.HIGH if evidence_count >= 2 else ConfidenceLevel.MEDIUM
                        tracker.add_marker(
                            fact_kind="struct",
                            fact_detail=f"struct {struct_name}",
                            confidence=confidence,
                            evidence_count=evidence_count,
                            reason=f"recovered from {evidence_count} function(s)",
                        )

            # Check for recovered arrays (Phase 2.2)
            if hasattr(cfunc, "_array_recovery_info"):
                array_info = cfunc._array_recovery_info
                if array_info and hasattr(array_info, "arrays"):
                    for array in array_info.arrays:
                        # Array with stride pattern = MEDIUM to HIGH confidence
                        array_name = getattr(array, "array_name", "unknown_array")
                        pattern_count = len(getattr(array, "access_patterns", []))
                        confidence = (
                            ConfidenceLevel.HIGH if pattern_count >= 3 else ConfidenceLevel.MEDIUM
                        )
                        tracker.add_marker(
                            fact_kind="array",
                            fact_detail=f"array {array_name}",
                            confidence=confidence,
                            evidence_count=pattern_count,
                            reason=f"detected from {pattern_count} access pattern(s)",
                        )

            # Check for segmented memory associations (Phase 3)
            if hasattr(cfunc, "_segmented_memory_info"):
                seg_info = cfunc._segmented_memory_info
                if seg_info and hasattr(seg_info, "associations"):
                    for assoc in seg_info.associations:
                        # Stable segment association = HIGH, over-associated = LOW
                        seg_str = getattr(assoc, "segment_reg", "unknown").value
                        stability = getattr(assoc, "stability", 0.5)
                        if stability >= 0.8:
                            confidence = ConfidenceLevel.HIGH
                        elif stability >= 0.5:
                            confidence = ConfidenceLevel.MEDIUM
                        else:
                            confidence = ConfidenceLevel.LOW
                        tracker.add_marker(
                            fact_kind="segmented_memory",
                            fact_detail=f"segment {seg_str} association",
                            confidence=confidence,
                            evidence_count=int(stability * 10),
                            reason=f"stability={stability:.2f}",
                        )

            # Build report
            report = FunctionConfidenceReport(
                func_addr=func_addr, func_name=func_name, confidence_tracker=tracker
            )

            # Add assumptions from analysis
            for assumption in get_codegen_sequence_attr(codegen, cfunc, "_assumptions"):
                report.add_assumption(assumption)

            # Add critical unknowns
            for unknown in get_codegen_sequence_attr(codegen, cfunc, "_critical_unknowns"):
                report.add_critical_unknown(unknown)

            # Attach to function
            build_function_with_confidence_markers(cfunc, report, codegen=codegen)

        return True

    except Exception:
        return False
