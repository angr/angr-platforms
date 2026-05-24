from __future__ import annotations

"""Emit original COD assembly and C source as comment blocks in .dec output.

AGENTS rule: no semantic recovery — this is pure formatting/fidelity output.
"""

import re
from pathlib import Path


def format_cod_comment_block(
    *,
    func_name: str,
    proc_kind: str = "NEAR",
    cod_path: str | None = None,
    entries: list[dict[str, object]] | None = None,
    source_lines: tuple[str, ...] = (),
) -> str:
    """Produce a ``/// ORIGINAL: ...`` comment block for a function.

    Args:
        func_name: Name of the function (e.g. ``_sort_array``).
        proc_kind: ``NEAR`` or ``FAR``.
        cod_path: Path to the .COD file (for provenance).
        entries: List of ``{"offset": int, "bytes": bytes, "text": str}``.
        source_lines: Original C source lines from the COD prelude/proc header.
    """
    lines: list[str] = []

    cod_source = Path(cod_path).name if cod_path else "unknown.COD"
    header = f"/// ORIGINAL: {func_name} ({proc_kind}) — {cod_source}"
    lines.append("/// " + "═" * 68)
    lines.append(header)

    if source_lines:
        lines.append("///")
        lines.append("/// C source:")
        for src_line in source_lines:
            safe_line = src_line.rstrip("\n\r")
            if safe_line.endswith("\\"):
                safe_line = safe_line[:-1] + "<backslash>"
            lines.append(f"///   {safe_line}")

    if entries:
        lines.append("///")
        lines.append("/// Assembly:")
        for entry in entries:
            offset = int(entry["offset"])
            raw_bytes = entry["bytes"]
            asm_text = str(entry.get("text", "")).strip()
            hex_bytes = " ".join(f"{b:02X}" for b in raw_bytes)
            # Pad hex bytes to 16 chars for alignment
            hex_padded = hex_bytes.ljust(16)
            lines.append(f"///   {offset:04X}  {hex_padded}  {asm_text}")

    lines.append("/// " + "═" * 68)
    return "\n".join(lines)


def format_cod_comment_block_from_proc_metadata(
    *,
    func_name: str,
    proc_kind: str = "NEAR",
    cod_path: str | None = None,
    entries: list[dict[str, object]] | None = None,
    source_lines: tuple[str, ...] = (),
) -> str:
    """Same as :func:`format_cod_comment_block`, provided as an alias for direct use
    with ``CODProcMetadata`` fields."""
    return format_cod_comment_block(
        func_name=func_name,
        proc_kind=proc_kind,
        cod_path=cod_path,
        entries=entries,
        source_lines=source_lines,
    )
