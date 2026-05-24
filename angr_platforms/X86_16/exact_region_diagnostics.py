from __future__ import annotations

"""Layer: Diagnostics (cross-cutting).

Responsibility: exact-region recovery coverage diagnostics and region_split classification.
Forbidden: semantic recovery, postprocess ownership, text-pattern semantics."""

from dataclasses import dataclass, field
from typing import Mapping, Sequence


__all__ = [
    "ExactRegionDiagnostics",
    "RegionSplitDiagnostics",
    "build_exact_region_diagnostics_8616",
    "format_exact_region_diagnostics_8616",
    "classify_region_split_8616",
]


@dataclass(slots=True)
class ExactRegionDiagnostics:
    """Coverage diagnostics for a sidecar exact-region recovery."""

    function_name: str = "unknown"
    proc_identity: str = ""
    requested_start: int = 0
    requested_end: int = 0
    rebased_start: int = 0
    rebased_end: int = 0
    covered_block_addrs: tuple[int, ...] = ()
    covered_byte_count: int = 0
    cfg_function_count_in_region: int = 1
    actual_cfg_entries: tuple[int, ...] = ()
    region_size: int = 0
    coverage_fraction: float = 1.0
    split_detected: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "function_name": self.function_name,
            "proc_identity": self.proc_identity,
            "requested_start": f"0x{self.requested_start:x}",
            "requested_end": f"0x{self.requested_end:x}",
            "rebased_start": f"0x{self.rebased_start:x}" if self.rebased_start else "N/A",
            "rebased_end": f"0x{self.rebased_end:x}" if self.rebased_end else "N/A",
            "region_size": self.region_size,
            "covered_byte_count": self.covered_byte_count,
            "coverage_fraction": round(self.coverage_fraction, 4),
            "cfg_function_count_in_region": self.cfg_function_count_in_region,
            "split_detected": self.split_detected,
            "covered_block_addrs": [f"0x{a:x}" for a in self.covered_block_addrs],
            "actual_cfg_entries": [f"0x{a:x}" for a in self.actual_cfg_entries],
        }


@dataclass(slots=True)
class RegionSplitDiagnostics:
    """Classification result when an exact region recovery splits across multiple CFG functions."""

    split_detected: bool = False
    cfg_entry_count: int = 1
    entries: tuple[int, ...] = ()
    note: str = ""

    @property
    def is_split(self) -> bool:
        return self.split_detected and self.cfg_entry_count > 1


def build_exact_region_diagnostics_8616(
    function_name: str,
    *,
    requested_start: int = 0,
    requested_end: int = 0,
    rebased_start: int = 0,
    rebased_end: int = 0,
    covered_block_addrs: Sequence[int] = (),
    cfg_functions: Mapping[int, object] | None = None,
    proc_identity: str = "",
) -> ExactRegionDiagnostics:
    """Build exact-region diagnostics from sidecar recovery inputs.

    Args:
        function_name: Human-readable function name
        requested_start: Requested region start address (original)
        requested_end: Requested region end address (original)
        rebased_start: Rebasing base (or 0 if not rebased)
        rebased_end: Rebasing end (or 0 if not rebased)
        covered_block_addrs: Block addresses recovered
        cfg_functions: CFG function mapping for counting entries in region
        proc_identity: PROC identity label from sidecar metadata
    """
    region_size = max(0, requested_end - requested_start)
    covered_byte_count = sum(
        # Heuristic: each block covers ~6 bytes on average for 16-bit code
        min(max(abs(b - requested_start) + 6, 0), region_size)
        for b in covered_block_addrs
        if requested_start <= b < requested_end
    )
    covered_byte_count = min(covered_byte_count, region_size)
    coverage_fraction = 1.0 if region_size <= 0 else min(covered_byte_count / region_size, 1.0)

    # Count CFG functions whose entries fall within the requested region
    actual_entries: tuple[int, ...] = ()  # noqa: F841
    cfg_function_count = 1
    if isinstance(cfg_functions, Mapping):
        entries: list[int] = []
        for addr in sorted(cfg_functions.keys()):
            if isinstance(addr, int) and requested_start <= addr < requested_end:
                entries.append(addr)
        actual_entries = tuple(entries)
        cfg_function_count = max(len(actual_entries), 1)
    else:
        actual_entries = (requested_start,)
        cfg_function_count = 1

    split_detected = cfg_function_count > 1

    return ExactRegionDiagnostics(
        function_name=function_name,
        proc_identity=proc_identity,
        requested_start=requested_start,
        requested_end=requested_end,
        rebased_start=rebased_start,
        rebased_end=rebased_end,
        covered_block_addrs=tuple(sorted(covered_block_addrs)),
        covered_byte_count=covered_byte_count,
        cfg_function_count_in_region=cfg_function_count,
        actual_cfg_entries=actual_entries,
        region_size=region_size,
        coverage_fraction=coverage_fraction,
        split_detected=split_detected,
    )


def format_exact_region_diagnostics_8616(d: ExactRegionDiagnostics) -> str:
    """Format exact-region diagnostics as a human-readable report line."""
    parts: list[str] = [
        f"[exact_region] {d.function_name}",
        f"requested={d.requested_start:#x}-{d.requested_end:#x}",
    ]
    if d.rebased_start or d.rebased_end:
        parts.append(f"rebased={d.rebased_start:#x}-{d.rebased_end:#x}")
    parts.append(f"covered_bytes={d.covered_byte_count}/{d.region_size}")
    parts.append(f"coverage={d.coverage_fraction:.1%}")
    parts.append(f"cfg_entries={d.cfg_function_count_in_region}")
    if d.split_detected:
        entries_str = ",".join(f"{a:#x}" for a in d.actual_cfg_entries)
        parts.append(f"SPLIT entries=[{entries_str}]")
    else:
        parts.append("ok")
    return " ".join(parts)


def classify_region_split_8616(
    diagnostics: ExactRegionDiagnostics,
) -> RegionSplitDiagnostics:
    """Classify whether a region recovery should be treated as ``region_split``.

    A region_split occurs when a single sidecar function produces multiple
    CFG function entries. This is a recovery failure — the decompiler should
    not treat the result as a normal function decompilation.
    """
    if diagnostics.split_detected:
        return RegionSplitDiagnostics(
            split_detected=True,
            cfg_entry_count=diagnostics.cfg_function_count_in_region,
            entries=diagnostics.actual_cfg_entries,
            note=f"Exact region {diagnostics.requested_start:#x}-{diagnostics.requested_end:#x} "
            f"split into {diagnostics.cfg_function_count_in_region} CFG functions",
        )
    return RegionSplitDiagnostics(
        split_detected=False,
        cfg_entry_count=1,
        entries=(diagnostics.requested_start,),
    )