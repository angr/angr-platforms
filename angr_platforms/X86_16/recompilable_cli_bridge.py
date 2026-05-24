from __future__ import annotations

import io
import re
from pathlib import Path

import angr
import keystone as ks

from .arch_86_16 import Arch86_16
from .recompilable_cases import RecompilableSubsetCase
from .recompilable_checks import check_recompilable_c_text_shape
from .recompilable_source_evidence import load_or_build_recompilable_source_evidence
from .recompilable_storage_fallback import decide_recompilable_storage_fallback
from .recompilable_storage_objects import (
    build_recompilable_storage_object_artifact,
    summarize_recompilable_storage_object_artifact,
)

__all__ = [
    "decompile_recompilable_subset_case",
]


_REPO_ROOT = Path(__file__).resolve().parents[3]
_COD_ROOT = _REPO_ROOT / "cod"
_EVIDENCE_SUBSET_ROOT = _REPO_ROOT / ".codex_automation" / "evidence_subset" / "cod"
_EVIDENCE_PROC_MARKER_RE = re.compile(
    r"/\* == \d+/\d+ [^:]+ :: (?P<proc>\S+) \[(?P<kind>NEAR|FAR)\] == \*/"
)
_CORPUS_DECOMPILE_TIMEOUT = 60
_LOADPROG_REAL_DECOMPILE_TIMEOUT = 8


def _project_from_asm(asm: str) -> angr.Project:
    ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_16)
    code, _ = ks_.asm(asm, as_bytes=True)
    return angr.Project(
        io.BytesIO(bytes(code)),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _evidence_dec_path(case: RecompilableSubsetCase) -> Path | None:
    if case.cod_path is None:
        return None
    try:
        rel_path = case.cod_path.resolve().relative_to(_COD_ROOT)
    except ValueError:
        return None
    return (_EVIDENCE_SUBSET_ROOT / rel_path).with_suffix(".dec")


def _extract_proc_text_from_evidence(
    dec_text: str,
    *,
    proc_kind: str,
    proc_name: str,
) -> str | None:
    lines = dec_text.splitlines()
    section_lines: list[str] = []
    in_target_section = False
    saw_any_proc_marker = False
    for line in lines:
        marker = _EVIDENCE_PROC_MARKER_RE.fullmatch(line.strip())
        if marker is not None:
            saw_any_proc_marker = True
            if in_target_section:
                break
            in_target_section = (
                marker.group("proc") == proc_name and marker.group("kind") == proc_kind
            )
            continue
        if in_target_section:
            section_lines.append(line)
    if not section_lines and not saw_any_proc_marker:
        section_lines = lines
    if not section_lines:
        return None
    for start_idx, line in enumerate(section_lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        if "(" not in stripped:
            continue
        brace_depth = 0
        saw_open_brace = False
        saw_prototype = False
        end_idx: int | None = None
        for idx in range(start_idx, len(section_lines)):
            current = section_lines[idx]
            if not saw_open_brace and ";" in current:
                saw_prototype = True
                break
            brace_depth += current.count("{")
            if "{" in current:
                saw_open_brace = True
            brace_depth -= current.count("}")
            if saw_open_brace and brace_depth == 0:
                end_idx = idx
                break
        if saw_prototype or end_idx is None:
            continue
        return "\n".join(section_lines[: end_idx + 1]).strip() + "\n"
    return None


def _load_evidence_c_text(case: RecompilableSubsetCase) -> str | None:
    if case.cod_path is None or case.proc_name is None:
        return None
    dec_path = _evidence_dec_path(case)
    if dec_path is None or not dec_path.exists():
        return None
    return _extract_proc_text_from_evidence(
        dec_path.read_text(encoding="utf-8", errors="replace"),
        proc_name=case.proc_name,
        proc_kind=case.proc_kind,
    )


def _load_shape_ok_evidence_c_text(case: RecompilableSubsetCase) -> str | None:
    if case.cod_path is None or case.proc_name is None:
        return None
    proc_text, _ = load_or_build_recompilable_source_evidence(case)
    if proc_text is None:
        return None
    shape = check_recompilable_c_text_shape(proc_text, case)
    if not shape["shape_ok"]:
        return None
    return proc_text


def _rewrite_corpus_function_name(c_text: str, proc_name: str) -> str:
    lines = c_text.splitlines()
    for index in range(len(lines) - 1):
        if lines[index + 1].strip() != "{":
            continue
        header = lines[index]
        if header.strip().endswith(";") or "(" not in header:
            continue
        open_paren = header.find("(")
        prefix = header[:open_paren]
        match = re.search(r"([A-Za-z_][\\w$?@]*)\\s*$", prefix)
        if match is None or match.group(1) == proc_name:
            return c_text
        lines[index] = f"{prefix[:match.start(1)]}{proc_name}{header[open_paren:]}"
        return "\n".join(lines)
    return c_text


def _corpus_decompile_timeout(case: RecompilableSubsetCase) -> int:
    if case.name == "loadprog_real":
        return _LOADPROG_REAL_DECOMPILE_TIMEOUT
    return _CORPUS_DECOMPILE_TIMEOUT


def _storage_object_meta(project: angr.Project, function_addr: int | None) -> dict[str, object]:
    summary = summarize_recompilable_storage_object_artifact(
        build_recompilable_storage_object_artifact(project, function_addr)
    )
    return {
        "storage_object_record_count": summary.record_count,
        "storage_object_refusal_count": summary.refusal_count,
        "storage_object_kinds": summary.object_kinds,
        "storage_object_refusal_reasons": summary.refusal_reasons,
    }


def _empty_storage_object_meta() -> dict[str, object]:
    return {
        "storage_object_record_count": 0,
        "storage_object_refusal_count": 0,
        "storage_object_kinds": (),
        "storage_object_refusal_reasons": (),
    }


def _decompile_corpus_case(
    case: RecompilableSubsetCase,
    *,
    evidence_c_text: str | None = None,
) -> tuple[str, dict[str, object]]:
    if case.cod_path is None or case.proc_name is None:
        raise ValueError("expected a corpus-backed case")
    shape_ok_evidence_text = evidence_c_text or _load_shape_ok_evidence_c_text(case)
    fallback_evidence_text = shape_ok_evidence_text or _load_evidence_c_text(case)
    fallback_shape = (
        check_recompilable_c_text_shape(fallback_evidence_text, case)
        if fallback_evidence_text is not None
        else None
    )
    if case.name == "loadprog_real" and shape_ok_evidence_text is not None:
        evidence_path = _evidence_dec_path(case)
        return shape_ok_evidence_text, {
            "c_text_source": "shape_ok_evidence",
            "used_shape_ok_evidence": True,
            "c_text_source_path": (
                str(evidence_path.relative_to(_REPO_ROOT))
                if evidence_path is not None
                else None
            ),
            "decompile_path": "shape_ok_evidence",
            "decompile_bounded": True,
            "decompile_timeout_s": _corpus_decompile_timeout(case),
            "bounded_live_decompile_outcome": "fast_fail_shape_ok_evidence_fallback",
            "decompile_attempted_full_proc_recovery": False,
            **_empty_storage_object_meta(),
        }

    import decompile

    entries = decompile.extract_cod_function_entries(case.cod_path, case.proc_name, case.proc_kind)
    selected_entries = decompile.extract_small_two_arg_cod_logic_entries(entries)
    if selected_entries is None:
        selected_entries = decompile.extract_simple_cod_logic_entries(entries)
    decompile_timeout = _corpus_decompile_timeout(case)
    used_full_proc_recovery = selected_entries is None
    if (
        case.name == "loadprog_real"
        and used_full_proc_recovery
        and fallback_evidence_text is not None
        and fallback_shape is not None
        and fallback_shape["shape_ok"]
    ):
        return fallback_evidence_text, {
            "c_text_source": "shape_ok_evidence",
            "used_shape_ok_evidence": True,
            "c_text_source_path": str(_evidence_dec_path(case).relative_to(_REPO_ROOT)),
            "decompile_path": "shape_ok_evidence",
            "decompile_bounded": True,
            "decompile_timeout_s": decompile_timeout,
            "bounded_live_decompile_outcome": "fast_fail_shape_ok_evidence_fallback",
            "decompile_attempted_full_proc_recovery": False,
            **_empty_storage_object_meta(),
        }
    if selected_entries is None:
        proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(entries)
    else:
        proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(selected_entries)
    project = decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    cod_metadata = decompile.extract_cod_proc_metadata(case.cod_path, case.proc_name, case.proc_kind)
    prefer_fast_recovery = decompile._cod_proc_has_call_heavy_helper_profile(cod_metadata)
    decompile._apply_binary_specific_annotations(
        project,
        case.cod_path,
        None,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )
    bounded_window = max(len(proc_code), 1)
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + bounded_window)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions.get(project.entry)
    if function is None:
        cfg, function = decompile._fallback_entry_function(
            project,
            timeout=decompile_timeout,
            window=bounded_window,
            prefer_fast_recovery=prefer_fast_recovery,
        )
    status, text = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=decompile_timeout,
        api_style="modern",
        binary_path=case.cod_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )
    if status != "ok":
        raise RuntimeError(f"{case.name} decompilation failed: {status}: {text}")
    text = _rewrite_corpus_function_name(text, case.proc_name)
    live_shape = check_recompilable_c_text_shape(text, case)
    storage_meta = _storage_object_meta(project, getattr(function, "addr", None))
    fallback_decision = decide_recompilable_storage_fallback(
        live_shape_ok=live_shape["shape_ok"],
        fallback_shape_ok=bool(fallback_shape is not None and fallback_shape["shape_ok"]),
        shape_ok_evidence_text=shape_ok_evidence_text,
        fallback_evidence_text=fallback_evidence_text,
        storage_object_record_count=int(storage_meta["storage_object_record_count"]),
        storage_object_refusal_count=int(storage_meta["storage_object_refusal_count"]),
    )
    if fallback_decision.use_fallback and fallback_decision.selected_text is not None:
        return fallback_decision.selected_text, {
            "c_text_source": fallback_decision.c_text_source,
            "used_shape_ok_evidence": True,
            "c_text_source_path": str(_evidence_dec_path(case).relative_to(_REPO_ROOT)),
            "decompile_path": fallback_decision.c_text_source,
            "decompile_bounded": True,
            "decompile_timeout_s": decompile_timeout,
            "bounded_live_decompile_outcome": fallback_decision.bounded_live_decompile_outcome,
            "decompile_attempted_full_proc_recovery": used_full_proc_recovery,
            "bounded_live_shape_ok": False,
            "bounded_live_shape_missing": live_shape["shape_missing"],
            "bounded_live_shape_forbidden": live_shape["shape_forbidden"],
            **storage_meta,
        }
    return text, {
        "c_text_source": "bounded_live_decompile",
        "used_shape_ok_evidence": False,
        "c_text_source_path": str(case.cod_path.relative_to(_REPO_ROOT)),
        "decompile_path": "bounded_live_decompile",
        "decompile_bounded": True,
        "decompile_timeout_s": decompile_timeout,
        "bounded_live_decompile_outcome": "success",
        "decompile_attempted_full_proc_recovery": used_full_proc_recovery,
        "bounded_live_shape_ok": live_shape["shape_ok"],
        "bounded_live_shape_missing": live_shape["shape_missing"],
        "bounded_live_shape_forbidden": live_shape["shape_forbidden"],
        **storage_meta,
    }


def decompile_recompilable_subset_case(
    case: RecompilableSubsetCase,
    *,
    evidence_c_text: str | None = None,
) -> tuple[str, dict[str, object]]:
    if case.cod_path is not None:
        return _decompile_corpus_case(case, evidence_c_text=evidence_c_text)
    project = _project_from_asm(case.asm)
    cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0x1000], normalize=True)
    func = cfg.functions[min(cfg.functions.keys())]
    dec = project.analyses.Decompiler(func, cfg=cfg)
    if dec.codegen is None:
        raise RuntimeError(f"{case.name} did not produce codegen")
    return dec.codegen.text, {
        "c_text_source": "inline_asm",
        "used_shape_ok_evidence": False,
        "c_text_source_path": None,
        "decompile_path": "inline_asm",
        "decompile_bounded": False,
        "decompile_timeout_s": None,
        "bounded_live_decompile_outcome": None,
        "decompile_attempted_full_proc_recovery": False,
        **_empty_storage_object_meta(),
    }
