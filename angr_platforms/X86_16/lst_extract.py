from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class LSTMetadata:
    data_labels: dict[int, str]
    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)
    signature_code_addrs: frozenset[int] = field(default_factory=frozenset)
    absolute_addrs: bool = False
    source_format: str = "generic_lst"
    struct_names: tuple[str, ...] = ()
    cod_path: str | None = None
    cod_proc_kinds: dict[int, str] = field(default_factory=dict)


_DATA_LABEL_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+(?:(?:[0-9A-Fa-f]{2,}(?:\s+[0-9A-Fa-f]{2,})*\s+)?)"
    r"([A-Za-z_$?@][\w$?@]*)\s+(db|dw|dd|dq|dt)\b",
    re.IGNORECASE,
)
_PROC_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s+proc(?:\s+\w+)?\b",
    re.IGNORECASE,
)
_ENDP_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s+endp\b",
    re.IGNORECASE,
)
_CODE_LABEL_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s*:\s*$",
    re.IGNORECASE,
)
_SEGMENT_RE = re.compile(r"^(?:[0-9A-Fa-f]{4,8}\s+)?([A-Za-z_$?@][\w$?@]*)\s+segment\b", re.IGNORECASE)
_ENDS_RE = re.compile(r"^(?:[0-9A-Fa-f]{4,8}\s+)?([A-Za-z_$?@][\w$?@]*)\s+ends\b", re.IGNORECASE)
_DOT_SEGMENT_RE = re.compile(r"^\.(code|data)\b", re.IGNORECASE)
_END_RE = re.compile(r"^end\s+([A-Za-z_$?@][\w$?@]*)\b", re.IGNORECASE)
_PROCEDURES_HEADER_RE = re.compile(r"^Procedures,\s+parameters and locals:", re.IGNORECASE)
_SYMBOLS_HEADER_RE = re.compile(r"^Symbols:", re.IGNORECASE)
_SECTION_HEADER_RE = re.compile(r"^[A-Za-z].*:$")
_MASM_PROCEDURE_ROW_RE = re.compile(
    r"^([A-Za-z_$?@][\w$?@]*)\b.*\bP\s+\w+\s+([0-9A-Fa-f]{4,8})\b.*Length=\s*([0-9A-Fa-f]{4,8})",
    re.IGNORECASE,
)
_MASM_SYMBOL_ROW_RE = re.compile(
    r"^([A-Za-z_$?@][\w$?@]*)\b.*\b(Byte|Word|DWord|QWord|TByte)\s+([0-9A-Fa-f]{4,8})\b",
    re.IGNORECASE,
)


def extract_lst_metadata(lst_path: Path) -> LSTMetadata:
    lines = lst_path.read_text(errors="ignore").splitlines()
    data_labels: dict[int, str] = {}
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    colon_code_labels: dict[str, int] = {}

    current_segment: str | None = None
    current_summary_section: str | None = None
    open_proc_starts: dict[str, int] = {}
    entry_label_name: str | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        upper = stripped.upper()
        if _PROCEDURES_HEADER_RE.match(stripped):
            current_summary_section = "procedures"
            continue
        if _SYMBOLS_HEADER_RE.match(stripped):
            current_summary_section = "symbols"
            continue
        if current_summary_section is not None and _SECTION_HEADER_RE.match(stripped):
            current_summary_section = None
        if current_summary_section == "procedures":
            procedure_row = _MASM_PROCEDURE_ROW_RE.match(stripped)
            if procedure_row is not None:
                name = procedure_row.group(1)
                start_offset = int(procedure_row.group(2), 16)
                length = int(procedure_row.group(3), 16)
                code_labels.setdefault(start_offset, name)
                if length > 0:
                    code_ranges.setdefault(start_offset, (start_offset, start_offset + length))
            continue
        if current_summary_section == "symbols":
            symbol_row = _MASM_SYMBOL_ROW_RE.match(stripped)
            if symbol_row is not None:
                name = symbol_row.group(1)
                offset = int(symbol_row.group(3), 16)
                data_labels.setdefault(offset, name)
            continue

        segment_match = _SEGMENT_RE.match(stripped)
        if segment_match is not None:
            segment_name = segment_match.group(1).lower()
            if "code" in segment_name or segment_name in {"text", "_text"}:
                current_segment = "CODE"
            elif "data" in segment_name or segment_name in {"_data", "dseg"}:
                current_segment = "DATA"
            continue

        ends_match = _ENDS_RE.match(stripped)
        if ends_match is not None:
            segment_name = ends_match.group(1).lower()
            if current_segment == "CODE" and ("code" in segment_name or segment_name in {"text", "_text"}):
                current_segment = None
            elif current_segment == "DATA" and ("data" in segment_name or segment_name in {"_data", "dseg"}):
                current_segment = None
            continue

        dot_segment_match = _DOT_SEGMENT_RE.match(stripped)
        if dot_segment_match is not None:
            current_segment = dot_segment_match.group(1).upper()
            continue

        end_match = _END_RE.match(stripped)
        if end_match is not None:
            entry_label_name = end_match.group(1)
            continue

        if "SEGMENT" in upper and "USE16" in upper:
            if "CODE" in upper:
                current_segment = "CODE"
            elif "DATA" in upper:
                current_segment = "DATA"
            continue

        match = _DATA_LABEL_RE.match(stripped)
        if match is not None:
            offset = int(match.group(1), 16)
            data_labels.setdefault(offset, match.group(2))
            continue

        if current_segment == "CODE":
            proc_match = _PROC_RE.match(stripped)
            if proc_match is not None:
                offset = int(proc_match.group(1), 16)
                name = proc_match.group(2)
                code_labels.setdefault(offset, name)
                open_proc_starts[name] = offset
                continue

            endp_match = _ENDP_RE.match(stripped)
            if endp_match is not None:
                end_offset = int(endp_match.group(1), 16)
                name = endp_match.group(2)
                start_offset = open_proc_starts.pop(name, None)
                if start_offset is not None and end_offset > start_offset:
                    code_ranges[start_offset] = (start_offset, end_offset)
                continue

            label_match = _CODE_LABEL_RE.match(stripped)
            if label_match is not None:
                offset = int(label_match.group(1), 16)
                colon_code_labels.setdefault(label_match.group(2), offset)

    if entry_label_name is not None:
        entry_offset = colon_code_labels.get(entry_label_name)
        if entry_offset is not None:
            code_labels.setdefault(entry_offset, entry_label_name)

    if lines and lines[0].startswith("UASM "):
        source_format = "uasm_lst"
    elif lines and lines[0].startswith("Microsoft (R) Macro Assembler"):
        source_format = "masm_lst"
    elif any(line.startswith("seg") and "; |" not in line for line in lines[:32]):
        source_format = "ida_lst"
    else:
        source_format = "generic_lst"
    return LSTMetadata(data_labels=data_labels, code_labels=code_labels, code_ranges=code_ranges, source_format=source_format)
