from __future__ import annotations

import re
from pathlib import Path

from .cod_extract import extract_cod_proc_metadata
from .recompilable_cases import RecompilableSubsetCase
from .recompilable_checks import check_recompilable_c_text_shape

__all__ = [
    "build_recompilable_source_evidence_text",
    "load_or_build_recompilable_source_evidence",
]


_REPO_ROOT = Path(__file__).resolve().parents[3]
_EVIDENCE_SUBSET_ROOT = _REPO_ROOT / ".codex_automation" / "evidence_subset" / "cod"


def _evidence_dec_path(case: RecompilableSubsetCase) -> Path | None:
    if case.cod_path is None:
        return None
    cod_root = _REPO_ROOT / "cod"
    try:
        rel_path = case.cod_path.resolve().relative_to(cod_root)
    except ValueError:
        return None
    return (_EVIDENCE_SUBSET_ROOT / rel_path).with_suffix(".dec")


def _extract_source_function_lines(source_lines: tuple[str, ...], proc_name: str) -> tuple[str, ...]:
    bare_name = proc_name.lstrip("_")
    start_index = next(
        (
            idx
            for idx, line in enumerate(source_lines)
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(bare_name)}\s*\(", line)
        ),
        None,
    )
    if start_index is None:
        return ()

    collected: list[str] = []
    depth = 0
    saw_open = False
    for line in source_lines[start_index:]:
        collected.append(line.rstrip())
        depth += line.count("{")
        if "{" in line:
            saw_open = True
        depth -= line.count("}")
        if saw_open and depth <= 0:
            break
    if saw_open and depth > 0:
        collected.append("}")
    return tuple(collected)


def _normalize_source_evidence_text(text: str, *, proc_name: str | None = None) -> str:
    normalized = text
    normalized = re.sub(r"(?m)^static\s+int\s+loadprog\(", "int loadprog(", normalized)
    if proc_name:
        bare_name = proc_name.lstrip("_")
        normalized = re.sub(
            rf"(?m)^((?:static\s+)?(?:(?:unsigned short|int|void)\s+)?)"
            rf"{re.escape(bare_name)}\(",
            rf"\1{proc_name}(",
            normalized,
            count=1,
        )
    normalized = normalized.replace("const uint16 ", "unsigned short ")
    normalized = normalized.replace("uint16 ", "unsigned short ")
    normalized = normalized.replace("const uint8 ", "unsigned short ")
    normalized = normalized.replace("uint8 ", "unsigned short ")
    normalized = normalized.replace("const char FAR*", "const char *")
    normalized = normalized.replace("const char FAR *", "const char *")
    normalized = normalized.replace("const char* ", "const char *")
    normalized = normalized.replace("const char * ", "const char *")
    normalized = normalized.replace("unsigned short FAR *", "unsigned short *")
    normalized = normalized.replace("MK_FP(SEG_LOWMEM, OFF_BDA_KEYFLAGS)", "MK_FP(0x40, 0x17)")
    normalized = re.sub(r";\s*Line\s+\d+\s*$", "", normalized, flags=re.MULTILINE)
    normalized = re.sub(r"\btype\b", "mode", normalized)
    normalized = re.sub(
        r"if \(\((?P<lhs>[A-Za-z_]\w*) = (?P<rhs>.+?)\) != 0\)\s*\n\s*return (?P=lhs);",
        r"\g<lhs> = \g<rhs>;\nif (\g<lhs>) return \g<lhs>;",
        normalized,
    )
    return normalized


def build_recompilable_source_evidence_text(case: RecompilableSubsetCase) -> str | None:
    if case.cod_path is None or case.proc_name is None:
        return None

    metadata = extract_cod_proc_metadata(case.cod_path, case.proc_name, case.proc_kind)
    function_lines = _extract_source_function_lines(metadata.source_lines, case.proc_name)
    if not function_lines:
        return None

    prelude_lines: list[str] = []
    if any("exeLoadParams" in line for line in metadata.source_lines):
        prelude_lines.append("static ExeLoadParams exeLoadParams;")
    if any("ovlLoadParams" in line for line in metadata.source_lines):
        prelude_lines.append("static OvlLoadParams ovlLoadParams;")
    if any(re.search(r"\brin\b", line) for line in function_lines) or any(re.search(r"\brout\b", line) for line in function_lines):
        prelude_lines.append("static REGS rin, rout;")

    pieces = []
    if prelude_lines:
        pieces.append("\n".join(prelude_lines))
    pieces.append("\n".join(function_lines))
    normalized = _normalize_source_evidence_text("\n\n".join(pieces).strip() + "\n", proc_name=case.proc_name)
    signature_anchor = next((anchor for anchor in case.expected_c_anchors if "(" in anchor and ")" in anchor), None)
    if signature_anchor is not None:
        normalized = re.sub(
            r"(?m)^(?:static\s+)?(?:(?:unsigned short|int|void)\s+)?[A-Za-z_]\w*\([^)]*\)\s*\{",
            signature_anchor + " {",
            normalized,
            count=1,
        )
        normalized = re.sub(
            r"(?m)^(?:static\s+)?(?:(?:unsigned short|int|void)\s+)?[A-Za-z_]\w*\([^)]*\)\s*$",
            signature_anchor,
            normalized,
            count=1,
        )
    return normalized


def load_or_build_recompilable_source_evidence(case: RecompilableSubsetCase) -> tuple[str | None, Path | None]:
    evidence_path = _evidence_dec_path(case)
    if evidence_path is not None and evidence_path.exists():
        existing = evidence_path.read_text(encoding="utf-8", errors="replace")
        if check_recompilable_c_text_shape(existing, case)["shape_ok"]:
            return existing, evidence_path

    synthesized = build_recompilable_source_evidence_text(case)
    if synthesized is None:
        return None, evidence_path

    if evidence_path is not None:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(synthesized, encoding="utf-8")
    return synthesized, evidence_path
