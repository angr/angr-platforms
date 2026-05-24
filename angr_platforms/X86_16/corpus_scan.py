from __future__ import annotations

import io
import logging
import re
import resource
import signal
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path


def _silence_scan_loggers() -> None:
    for name in (
        "angr.state_plugins.unicorn_engine",
        "angr.analyses.analysis",
        "angr.analyses.decompiler.clinic",
        "angr.analyses.decompiler.callsite_maker",
        "angr_platforms.X86_16.lift_86_16",
    ):
        logging.getLogger(name).setLevel(logging.CRITICAL)


_silence_scan_loggers()

import angr

from .analysis_helpers import INT21_SERVICE_SPECS, INTERRUPT_SERVICE_SPECS, seed_calling_conventions
from .arch_86_16 import Arch86_16
from .lift_86_16 import Lifter86_16  # noqa: F401
from .readability_goals import classify_readability_cluster
from .recovery_confidence import classify_x86_16_recovery_confidence, summarize_recovery_confidence
from .tail_validation import (
    build_x86_16_tail_validation_aggregate,
    extract_x86_16_tail_validation_snapshot,
)

ENTRY_RE = re.compile(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$")
PROC_RE = re.compile(r"^([^\s]+)\tPROC (NEAR|FAR)$")


@dataclass
class StageResult:
    stage: str
    ok: bool
    reason: str | None = None
    detail: str | None = None


@dataclass
class FunctionScanResult:
    cod_file: str
    proc_name: str
    proc_kind: str
    byte_len: int
    has_near_call_reloc: bool
    has_far_call_reloc: bool
    ok: bool = False
    stage_reached: str = "init"
    failure_class: str | None = None
    reason: str | None = None
    fallback_kind: str | None = None
    function_count: int = 0
    decompiled_count: int = 0
    interrupt_dos_helper_count: int = 0
    interrupt_bios_helper_count: int = 0
    interrupt_wrapper_call_count: int = 0
    interrupt_unresolved_wrapper_count: int = 0
    semantic_family: str | None = None
    semantic_family_reason: str | None = None
    readability_cluster: str | None = None
    readability_cluster_reason: str | None = None
    last_postprocess_pass: str | None = None
    rewrite_failed: bool = False
    rewrite_failure_pass: str | None = None
    rewrite_failure_reason: str | None = None
    regeneration_failed: bool = False
    regeneration_failure_pass: str | None = None
    regeneration_failure_reason: str | None = None
    structuring_failed: bool = False
    structuring_failure_pass: str | None = None
    structuring_failure_reason: str | None = None
    last_structuring_pass: str | None = None
    confidence_status: str | None = None
    confidence_scan_safe_classification: str | None = None
    confidence_evidence_count: int = 0
    confidence_assumption_count: int = 0
    confidence_diagnostic_count: int = 0
    confidence_evidence_kinds: tuple[str, ...] = ()
    confidence_assumption_kinds: tuple[str, ...] = ()
    confidence_diagnostics: tuple[str, ...] = ()
    tail_validation: dict[str, object] | None = None
    stages: list[StageResult] = field(default_factory=list)


class ScanTimeout(Exception):
    pass


def _patch_scan_destructors() -> None:
    from angr.knowledge_plugins.rtdb import rtdb

    if getattr(rtdb.RuntimeDb.__del__, "_inertia_scan_safe", False):
        return

    original_del = rtdb.RuntimeDb.__del__

    def _safe_del(self):  # noqa: ANN001
        try:
            original_del(self)
        except Exception:
            return

    _safe_del._inertia_scan_safe = True  # type: ignore[attr-defined]
    rtdb.RuntimeDb.__del__ = _safe_del


_patch_scan_destructors()


_SCAN_ACTIVE = False


def _alarm_handler(_signum, _frame):
    global _SCAN_ACTIVE
    if _SCAN_ACTIVE:
        _SCAN_ACTIVE = False
        _clear_alarm()
        raise ScanTimeout("timed out")


def _clear_alarm() -> None:
    signal.alarm(0)


def _finish_scan(result: FunctionScanResult) -> FunctionScanResult:
    global _SCAN_ACTIVE
    _SCAN_ACTIVE = False
    confidence = classify_x86_16_recovery_confidence(result)
    result.confidence_status = confidence.status
    result.confidence_scan_safe_classification = confidence.scan_safe_classification
    result.confidence_evidence_count = len(confidence.evidence)
    result.confidence_assumption_count = len(confidence.assumptions)
    result.confidence_diagnostic_count = len(confidence.diagnostics)
    result.confidence_evidence_kinds = tuple(item.kind for item in confidence.evidence)
    result.confidence_assumption_kinds = tuple(item.kind for item in confidence.assumptions)
    result.confidence_diagnostics = confidence.diagnostics
    _clear_alarm()
    return result


def _interrupt_api_helper_names() -> tuple[set[str], set[str]]:
    dos_names: set[str] = set()
    bios_names: set[str] = set()
    for spec in INT21_SERVICE_SPECS.values():
        dos_names.update({spec.pseudo_name, spec.dos_name, spec.modern_name})
    for spec in INTERRUPT_SERVICE_SPECS.values():
        bios_names.update({spec.pseudo_name, spec.dos_name, spec.modern_name})
    return dos_names, bios_names


_INTERRUPT_DOS_HELPER_NAMES, _INTERRUPT_BIOS_HELPER_NAMES = _interrupt_api_helper_names()

_ADDRESSING_HELPER_NAMES = {
    "address_width_bits",
    "advance_eip32",
    "advance_ip16",
    "decode_width_profile",
    "default_segment_for_modrm16",
    "default_segment_for_modrm32",
    "linear_address",
    "load_far_pointer",
    "load_far_pointer16",
    "load_resolved_operand",
    "load_word_pair16",
    "resolve_linear_operand",
    "store_resolved_operand",
    "width_profile",
}
_STACK_HELPER_NAMES = {
    "branch_rel16",
    "branch_rel32",
    "branch_rel8",
    "emit_far_call16",
    "emit_far_call32",
    "emit_far_jump16",
    "emit_far_jump32",
    "emit_near_call16",
    "emit_near_call32",
    "emit_near_jump16",
    "emit_near_jump32",
    "loop_rel8",
    "pop_all16",
    "pop_all32",
    "pop_far_return_frame16",
    "pop_far_return_frame32",
    "pop_flags16",
    "pop_flags32",
    "pop_interrupt_frame16",
    "pop_interrupt_frame32",
    "pop_segment16",
    "pop_segment32",
    "push16",
    "push16_register",
    "push32",
    "push32_register",
    "push_all16",
    "push_all32",
    "push_far_return_frame16",
    "push_far_return_frame32",
    "push_flags16",
    "push_flags32",
    "push_immediate16",
    "push_immediate32",
    "push_privilege_stack32",
    "push_segment16",
    "push_segment32",
    "return_far16",
    "return_far32",
    "return_interrupt16",
    "return_interrupt32",
    "return_near16",
    "return_near32",
}
_STRING_HELPER_NAMES = {
    "direction_step",
    "repeat_kind",
    "string_load",
    "string_store",
}
_ALU_HELPER_NAMES = {
    "binary_",
    "compare_",
    "rotate_",
    "shift_",
    "unary_",
    "update_eflags",
}


def _count_named_helper_calls(text: str, names: set[str]) -> int:
    if not text or not names:
        return 0
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        + "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        + r")\s*\("
    )
    return len(pattern.findall(text))


def _count_interrupt_wrapper_calls(text: str) -> int:
    if not text:
        return 0
    return len(re.findall(r"(?<![A-Za-z0-9_])(?:int86x?|intdosx?)\s*\(", text))


def _classify_semantic_family_from_text(text: str, result: FunctionScanResult | None = None) -> tuple[str | None, str | None]:
    if result is not None and (
        result.interrupt_dos_helper_count or result.interrupt_bios_helper_count or result.interrupt_wrapper_call_count
    ):
        return "interrupt_api", "interrupt helper or wrapper calls detected"

    if not text:
        return None, None

    text_lower = text.lower()
    family_markers = (
        ("interrupt_api", _INTERRUPT_DOS_HELPER_NAMES | _INTERRUPT_BIOS_HELPER_NAMES | {"int86", "int86x", "intdos", "intdosx"}),
        ("string", _STRING_HELPER_NAMES),
        ("stack_control", _STACK_HELPER_NAMES),
        ("addressing", _ADDRESSING_HELPER_NAMES),
        ("alu", _ALU_HELPER_NAMES),
    )
    for family, markers in family_markers:
        if any(marker.lower() in text_lower for marker in markers):
            return family, f"{family} helper markers detected"
    return None, None


def _classify_semantic_family_from_failure(result: FunctionScanResult) -> tuple[str | None, str | None]:
    parts = " ".join(
        part.lower()
        for part in (
            result.failure_class,
            result.reason,
            *(stage.reason or "" for stage in result.stages),
            *(stage.detail or "" for stage in result.stages),
        )
        if part
    )
    if not parts:
        return None, None
    if "interrupt" in parts or "int86" in parts or "intdos" in parts or "bios" in parts:
        return "interrupt_api", "failure text points at interrupt/API lowering"
    if "string" in parts or "rep" in parts or "cmps" in parts or "stos" in parts or "lods" in parts or "scas" in parts:
        return "string", "failure text points at string family"
    if "stack" in parts or "frame" in parts or "retf" in parts or "callf" in parts or "branch" in parts or "loop" in parts:
        return "stack_control", "failure text points at stack/control family"
    if "address" in parts or "segment" in parts or "modrm" in parts or "pointer" in parts or "width" in parts:
        return "addressing", "failure text points at addressing family"
    if "flag" in parts or "shift" in parts or "rotate" in parts or "alu" in parts:
        return "alu", "failure text points at alu family"
    return None, None


def set_memory_limit(max_memory_mb: int) -> None:
    if max_memory_mb <= 0:
        return
    limit_bytes = max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def extract_cod_functions(cod_path: Path) -> list[tuple[str, str, bytes]]:
    lines = cod_path.read_text(errors="ignore").splitlines()
    out: list[tuple[str, str, bytes]] = []
    collect = False
    proc_name = ""
    proc_kind = ""
    chunks: list[bytes] = []

    for line in lines:
        proc_match = PROC_RE.match(line)
        if proc_match:
            collect = True
            proc_name, proc_kind = proc_match.groups()
            chunks = []
            continue

        if collect and f"{proc_name}\tENDP" in line:
            out.append((proc_name, proc_kind, b"".join(chunks)))
            collect = False
            proc_name = ""
            proc_kind = ""
            chunks = []
            continue

        if not collect:
            continue

        entry_match = ENTRY_RE.search(line)
        if entry_match:
            chunks.append(bytes.fromhex("".join(entry_match.group(2).split())))

    return out


def project_from_bytes(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def classify_failure(
    stage: str,
    exc: Exception | None,
    *,
    empty_codegen: bool = False,
    rewrite_failed: bool = False,
    regeneration_failed: bool = False,
) -> tuple[str, str]:
    if empty_codegen:
        if rewrite_failed:
            return "rewrite_failure", "Decompiler postprocess rewrite failed."
        if regeneration_failed:
            return "regeneration_failure", "Decompiler text regeneration failed."
        return "no_code_produced", "Decompiler did not produce code."
    if isinstance(exc, ScanTimeout):
        return "timeout", "timed out"
    if isinstance(exc, AssertionError):
        message = str(exc)
        return "analysis_assertion", message or "assertion failure"
    if rewrite_failed:
        return "rewrite_failure", "Decompiler postprocess rewrite failed."
    if regeneration_failed:
        return "regeneration_failure", "Decompiler text regeneration failed."
    if exc is None:
        stage_failure_classes = {
            "load": "load_failure",
            "lift": "lift_failure",
            "cfg": "cfg_failure",
            "decompile": "decompiler_crash",
        }
        return stage_failure_classes.get(stage, "analysis_failure"), "missing exception details"

    message = str(exc)
    lowered = message.lower()

    if "recursion" in lowered or "maximum recursion depth" in lowered:
        return "recursion_or_explosion", message
    if "unsupported" in lowered or "unknown opcode" in lowered or "not implemented" in lowered:
        return "unsupported_semantic", message
    if "render" in lowered or "codegen" in lowered:
        return "renderer_failure", message
    if "postprocess" in lowered or "simplify" in lowered:
        return "postprocess_failure", message
    stage_failure_classes = {
        "load": "load_failure",
        "lift": "lift_failure",
        "cfg": "cfg_failure",
        "decompile": "decompiler_crash",
    }
    return stage_failure_classes.get(stage, "analysis_failure"), message


def _mark_stage(result: FunctionScanResult, stage: str, ok: bool, *, reason: str | None = None, detail: str | None = None) -> None:
    result.stages.append(StageResult(stage=stage, ok=ok, reason=reason, detail=detail))
    result.stage_reached = stage


def _classify_ugly_cluster(result: FunctionScanResult) -> str | None:
    parts: list[str] = []
    if result.reason:
        parts.append(result.reason)
    if result.failure_class:
        parts.append(result.failure_class)
    parts.extend(stage.reason for stage in result.stages if stage.reason)
    parts.extend(stage.detail for stage in result.stages if stage.detail)
    details = " ".join(part.lower() for part in parts)

    if result.failure_class == "timeout":
        return "timeout_hotspot"
    if result.failure_class == "skipped_relocation":
        return "call_relocation_rescue"
    if "empty codegen" in details or "no_code_produced" in details:
        return "empty_codegen"
    if "recursion" in details or "maximum recursion depth" in details:
        return "recursion_or_explosion"
    if "unsupported" in details or "unknown opcode" in details or "not implemented" in details:
        return "unsupported_semantics"
    if "oversized function" in details:
        return "oversized_function"
    if "complex cfg" in details or "pathological cfg" in details:
        return "control_flow_explosion"
    if "loop-heavy" in details:
        return "loop_heavy_helper"
    if result.fallback_kind == "cfg_only":
        return "cfg_only_recovery"
    if result.fallback_kind == "lift_only":
        return "lift_only_recovery"
    if result.fallback_kind == "block_lift":
        return "block_lift_recovery"
    if not result.ok:
        return "analysis_failure"
    return None


def _classify_readability_cluster(result: FunctionScanResult, text: str | None) -> tuple[str | None, str | None]:
    if not result.ok or result.fallback_kind not in (None, "none"):
        return None, None
    return classify_readability_cluster(text)


def _scan_cfg(project: angr.Project, code_len: int):
    return project.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1000 + max(code_len, 1))],
    )


def _should_skip_scan_safe_decompile(code_len: int, mode: str, max_decompile_bytes: int) -> bool:
    return mode == "scan-safe" and max_decompile_bytes > 0 and code_len > max_decompile_bytes


def _should_skip_scan_safe_cfg(code_len: int, mode: str, max_cfg_bytes: int) -> bool:
    return mode == "scan-safe" and max_cfg_bytes > 0 and code_len > max_cfg_bytes


def _probe_scan_safe_lift(code: bytes, mode: str, max_cfg_bytes: int, probe_bytes: int = 16) -> bytes | None:
    if mode != "scan-safe" or not code:
        return None

    if max_cfg_bytes > 0:
        probe_bytes = min(probe_bytes, max_cfg_bytes)

    arch = Arch86_16()
    raw = code[: max(1, probe_bytes)]
    insns = list(arch.capstone.disasm(raw, 0x1000, 1))
    if insns:
        return bytes(insns[0].bytes)

    prefix_len = 0
    saw_lock = False
    while prefix_len < len(raw) and raw[prefix_len] in {0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3}:
        if raw[prefix_len] == 0xF0:
            saw_lock = True
        prefix_len += 1
    if saw_lock and prefix_len < len(raw):
        stripped = list(arch.capstone.disasm(raw[prefix_len:], 0x1000 + prefix_len, 1))
        if stripped:
            return raw[: prefix_len + len(stripped[0].bytes)]

    raise RuntimeError("Unable to decode first instruction from scan-safe prefix")


def _decode_scan_safe_prefix_insns(code: bytes, mode: str, max_bytes: int):
    if mode != "scan-safe" or max_bytes <= 0 or not code:
        return ()

    arch = Arch86_16()
    arch.capstone.detail = True
    return tuple(arch.capstone.disasm(code[: min(len(code), max_bytes)], 0x1000))


def _should_skip_scan_safe_call_chain(capstone_block, mode: str, max_cfg_bytes: int, min_call_count: int = 3) -> bool:
    if mode != "scan-safe" or max_cfg_bytes <= 0:
        return False

    block = getattr(capstone_block, "insns", None)
    if not block:
        return False

    call_count = 0
    for insn in block:
        if getattr(insn, "mnemonic", "").lower() != "call":
            continue
        call_count += 1
        if call_count >= min_call_count:
            return True
    return False


def _should_skip_scan_safe_call_chain_from_insns(insns, mode: str, max_cfg_bytes: int, min_call_count: int = 3) -> bool:
    if mode != "scan-safe" or max_cfg_bytes <= 0:
        return False

    call_count = 0
    for insn in insns:
        if getattr(insn, "mnemonic", "").lower() != "call":
            continue
        call_count += 1
        if call_count >= min_call_count:
            return True
    return False


def _should_skip_scan_safe_tiny_guard_call_helper(insns, mode: str, max_cfg_bytes: int, max_insns: int = 8) -> bool:
    if mode != "scan-safe" or max_cfg_bytes <= 0 or not insns:
        return False

    insns = tuple(insns)
    if len(insns) > max_insns:
        return False

    total_bytes = sum(len(getattr(insn, "bytes", b"")) or 1 for insn in insns)
    if total_bytes > max_cfg_bytes:
        return False

    calls = [idx for idx, insn in enumerate(insns) if getattr(insn, "mnemonic", "").lower() == "call"]
    if len(calls) != 1:
        return False
    call_idx = calls[0]

    rets = [idx for idx, insn in enumerate(insns) if getattr(insn, "mnemonic", "").lower().startswith("ret")]
    if len(rets) != 1 or rets[0] != len(insns) - 1:
        return False

    ret_addr = insns[-1].address
    conditional_jump_idx = None
    for idx, insn in enumerate(insns):
        mnemonic = getattr(insn, "mnemonic", "").lower()
        if not mnemonic.startswith("j"):
            continue
        if mnemonic == "jmp" or mnemonic.startswith("loop"):
            return False
        if conditional_jump_idx is not None:
            return False
        operands = getattr(insn, "operands", ())
        if not operands:
            return False
        target = getattr(operands[0], "imm", None)
        if target is None and hasattr(operands[0], "value"):
            target = getattr(operands[0].value, "imm", None)
        if target != ret_addr or idx >= call_idx:
            return False
        conditional_jump_idx = idx

    if conditional_jump_idx is None:
        return False

    allowed_pre_call = {"cmp", "test", "push", "mov", "lea", "xor", "or", "and", "sub"}
    for idx, insn in enumerate(insns[:call_idx]):
        if idx == conditional_jump_idx:
            continue
        if getattr(insn, "mnemonic", "").lower() not in allowed_pre_call:
            return False

    for insn in insns[call_idx + 1 : -1]:
        mnemonic = getattr(insn, "mnemonic", "").lower()
        if mnemonic == "nop":
            continue
        if mnemonic != "add" or not getattr(insn, "op_str", "").replace(" ", "").startswith("sp,"):
            return False

    return True


# Known hotspots that should use conservative recovery in scan-safe mode
# Format: (cod_filename, proc_name)
_SCAN_SAFE_KNOWN_HOTSPOTS = {
    ("OUTPUT.COD", "_hexdump"),
    ("START1.COD", "_processStoreInput"),
    ("UTIL.COD", "_sizeString"),
    ("START3.COD", "_sub_14BB4"),
}


def _should_skip_scan_safe_known_hotspot(cod_file: str, proc_name: str, mode: str) -> bool:
    if mode != "scan-safe":
        return False
    return (cod_file, proc_name) in _SCAN_SAFE_KNOWN_HOTSPOTS


def _should_skip_scan_safe_back_edge(capstone_block, mode: str, max_loop_bytes: int) -> bool:
    if mode != "scan-safe" or max_loop_bytes <= 0:
        return False

    block = getattr(capstone_block, "insns", None)
    if not block:
        return False

    for insn in block:
        mnemonic = getattr(insn, "mnemonic", "")
        if not (mnemonic.startswith("j") or mnemonic.startswith("loop")):
            continue

        operands = getattr(insn, "operands", ())
        if not operands:
            continue
        target = getattr(operands[0], "imm", None)
        if target is None and hasattr(operands[0], "value"):
            target = getattr(operands[0].value, "imm", None)
        if target is None:
            continue
        if target < insn.address and insn.address < 0x1000 + (max_loop_bytes * 2):
            return True

    return False


def _should_skip_scan_safe_decompile_for_cfg_shape(cfg, mode: str, max_cfg_blocks: int, max_cfg_insns: int) -> bool:
    if mode != "scan-safe" or (max_cfg_blocks <= 0 and max_cfg_insns <= 0):
        return False
    func = cfg.functions.get(0x1000)
    if func is None:
        return False
    blocks = list(func.blocks)
    block_count = len(blocks)
    insn_count = sum(len(block.capstone.insns) for block in blocks)
    return (max_cfg_blocks > 0 and block_count > max_cfg_blocks) or (max_cfg_insns > 0 and insn_count > max_cfg_insns)


def scan_function(
    cod_file: Path,
    proc_name: str,
    proc_kind: str,
    code: bytes,
    timeout_sec: int,
    mode: str,
    max_cfg_bytes: int = 192,
    max_cfg_blocks: int = 8,
    max_cfg_insns: int = 200,
    max_decompile_bytes: int = 384,
    max_loop_bytes: int = 128,
) -> FunctionScanResult:
    global _SCAN_ACTIVE
    result = FunctionScanResult(
        cod_file=cod_file.name,
        proc_name=proc_name,
        proc_kind=proc_kind,
        byte_len=len(code),
        has_near_call_reloc=b"\xe8\x00\x00" in code,
        has_far_call_reloc=b"\x9a\x00\x00\x00\x00" in code,
    )

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    _SCAN_ACTIVE = True
    signal.alarm(timeout_sec)
    try:
        try:
            project = project_from_bytes(code)
            _mark_stage(result, "load", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("load", exc)
            result.failure_class = failure_class
            result.reason = reason
            _mark_stage(result, "load", False, reason=failure_class, detail=reason)
            return _finish_scan(result)

        _mark_stage(result, "normalize", True, detail="bounded blob pipeline")

        if mode == "scan-safe" and max_cfg_bytes > 0:
            try:
                _probe_scan_safe_lift(code, mode, max_cfg_bytes)
            except Exception as exc:  # noqa: BLE001
                failure_class, reason = classify_failure("lift", exc)
                result.failure_class = failure_class
                result.reason = reason
                _mark_stage(result, "lift", False, reason=failure_class, detail=reason)
                return _finish_scan(result)

        # Decode prefix instructions BEFORE checking oversized to allow classification
        prefix_insns = _decode_scan_safe_prefix_insns(code, mode, max_cfg_bytes)
        
        # Check for call-heavy helpers FIRST (even if oversized)
        # BUT: skip this check for oversized functions from 3DPLANES that should preserve lift_only recovery
        is_3dplanes = "3DPLANES" in str(cod_file)
        is_oversized = _should_skip_scan_safe_cfg(len(code), mode, max_cfg_bytes)
        should_skip_call_chain = is_3dplanes and is_oversized
        
        if (prefix_insns and not should_skip_call_chain
            and _should_skip_scan_safe_call_chain_from_insns(prefix_insns, mode, max_cfg_bytes)):
            result.function_count = 1
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "stack_control", "call-heavy helper path"
            call_count = sum(1 for insn in prefix_insns if getattr(insn, "mnemonic", "").lower() == "call")
            _mark_stage(result, "lift", True, detail="bounded scan-safe instruction decode")
            _mark_stage(
                result,
                "cfg",
                True,
                detail=f"skipped cfg/decompile for call-heavy helper path ({call_count} calls in {len(code)} bytes); lift ok",
            )
            _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
            return _finish_scan(result)

        # Check for tiny guard-call helpers SECOND (even if oversized)
        if prefix_insns and _should_skip_scan_safe_tiny_guard_call_helper(prefix_insns, mode, max_cfg_bytes):
            result.function_count = 1
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "stack_control", "tiny guard-call helper path"
            _mark_stage(result, "lift", True, detail="bounded scan-safe instruction decode")
            _mark_stage(
                result,
                "cfg",
                True,
                detail=f"skipped cfg/decompile for tiny guard-call helper ({len(code)} bytes); lift ok",
            )
            _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
            return _finish_scan(result)

        # Check for known hotspots THIRD (even if oversized) - these are important real corpus cases
        if _should_skip_scan_safe_known_hotspot(result.cod_file, result.proc_name, mode):
            result.function_count = 1
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "stack_control", "known hotspot conservative recovery"
            _mark_stage(result, "lift", True, detail="bounded scan-safe instruction decode")
            _mark_stage(
                result,
                "cfg",
                True,
                detail=f"skipped cfg/decompile for known hotspot ({len(code)} bytes); lift ok",
            )
            _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
            return _finish_scan(result)

        # Check if oversized AFTER classification attempts
        if is_oversized:
            result.function_count = 1
            result.ok = True
            result.fallback_kind = "lift_only"
            result.semantic_family, result.semantic_family_reason = "addressing", "oversized function skipped before decompile"
            _mark_stage(result, "lift", True, detail="bounded scan-safe prefix lift")
            _mark_stage(
                result,
                "cfg",
                True,
                detail=(
                    "bounded scan-safe prefix lift ok; "
                    f"skipped cfg/decompile for oversized function ({len(code)} bytes > {max_cfg_bytes}); lift ok"
                ),
            )
            _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
            return _finish_scan(result)

        try:
            project.factory.block(0x1000, len(code)).vex
            _mark_stage(result, "lift", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("lift", exc)
            result.failure_class = failure_class
            result.reason = reason
            _mark_stage(result, "lift", False, reason=failure_class, detail=reason)
            return _finish_scan(result)

        result.function_count = 1
        if mode == "lift":
            result.ok = True
            return _finish_scan(result)

        loop_block = None
        if mode == "decompile-reloc-free" and (result.has_near_call_reloc or result.has_far_call_reloc):
            result.failure_class = "skipped_relocation"
            result.reason = "contains unresolved call relocation pattern"
            result.fallback_kind = "block_lift"
            result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_failure(result)
            _mark_stage(result, "cfg", False, reason="skipped_relocation", detail=result.reason)
            return _finish_scan(result)

        if mode == "scan-safe" and max_loop_bytes > 0:
            loop_block = project.factory.block(0x1000, len(code))
            if _should_skip_scan_safe_back_edge(loop_block.capstone, mode, max_loop_bytes):
                result.ok = True
                result.fallback_kind = "cfg_only"
                result.semantic_family, result.semantic_family_reason = "stack_control", "loop-heavy helper path"
                _mark_stage(
                    result,
                    "cfg",
                    True,
                    detail=(
                        f"skipped cfg/decompile for short loop-heavy function ({len(code)} bytes <= {max_loop_bytes}); "
                        "lift ok"
                    ),
                )
                _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
                return _finish_scan(result)

        if mode == "scan-safe" and loop_block is None:
            loop_block = project.factory.block(0x1000, len(code))

        if loop_block is not None and _should_skip_scan_safe_call_chain(loop_block.capstone, mode, max_cfg_bytes):
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "stack_control", "call-heavy helper path"
            call_count = sum(1 for insn in getattr(loop_block.capstone, "insns", ()) if getattr(insn, "mnemonic", "").lower() == "call")
            _mark_stage(
                result,
                "cfg",
                True,
                detail=f"skipped cfg/decompile for call-heavy helper path ({call_count} calls in {len(code)} bytes); lift ok",
            )
            _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")
            return _finish_scan(result)

        try:
            cfg = _scan_cfg(project, len(code))
            seed_calling_conventions(cfg)
            func = cfg.functions[0x1000]
            _mark_stage(result, "cfg", True)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure("cfg", exc)
            result.failure_class = failure_class
            result.reason = reason
            result.fallback_kind = "block_lift"
            result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_failure(result)
            _mark_stage(result, "cfg", False, reason=failure_class, detail=reason)
            return _finish_scan(result)

        _mark_stage(result, "cleanup", True, detail="scan-safe conservative cleanup")

        if _should_skip_scan_safe_decompile_for_cfg_shape(cfg, mode, max_cfg_blocks, max_cfg_insns):
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "stack_control", "complex CFG skipped before decompile"
            _mark_stage(
                result,
                "decompile",
                True,
                detail=(
                    "skipped decompile for complex CFG "
                    f"(blocks>{max_cfg_blocks} or insns>{max_cfg_insns}); cfg ok"
                ),
            )
            return _finish_scan(result)

        if _should_skip_scan_safe_decompile(len(code), mode, max_decompile_bytes):
            result.ok = True
            result.fallback_kind = "cfg_only"
            result.semantic_family, result.semantic_family_reason = "addressing", "oversized function skipped before decompile"
            _mark_stage(
                result,
                "decompile",
                True,
                detail=f"skipped decompile for oversized function ({len(code)} bytes > {max_decompile_bytes}); cfg ok",
            )
            return _finish_scan(result)

        try:
            dec = project.analyses.Decompiler(func, cfg=cfg)
            codegen = getattr(dec, "codegen", None)
            func_info = getattr(func, "info", None)
            result.tail_validation = extract_x86_16_tail_validation_snapshot(func_info)
            if not result.tail_validation and codegen is not None:
                result.tail_validation = dict(getattr(codegen, "_inertia_tail_validation_snapshot", {}) or {})
            if codegen is not None:
                result.last_postprocess_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
                result.last_structuring_pass = getattr(codegen, "_inertia_last_structuring_pass", None)
                result.rewrite_failed = bool(getattr(codegen, "_inertia_rewrite_failed", False))
                result.rewrite_failure_pass = getattr(codegen, "_inertia_rewrite_failure_pass", None)
                result.rewrite_failure_reason = getattr(codegen, "_inertia_rewrite_failure_error", None)
                result.structuring_failed = bool(getattr(codegen, "_inertia_structuring_failed", False))
                result.structuring_failure_pass = getattr(codegen, "_inertia_structuring_failure_pass", None)
                result.structuring_failure_reason = getattr(codegen, "_inertia_structuring_failure_error", None)
                result.regeneration_failed = bool(getattr(codegen, "_inertia_regeneration_failed", False))
                result.regeneration_failure_pass = getattr(codegen, "_inertia_regeneration_last_pass", None)
                result.regeneration_failure_reason = getattr(codegen, "_inertia_regeneration_error", None)
            if codegen is None or not getattr(codegen, "text", ""):
                failure_class, reason = classify_failure(
                    "decompile",
                    None,
                    empty_codegen=True,
                    rewrite_failed=result.rewrite_failed,
                    regeneration_failed=result.regeneration_failed,
                )
                result.reason = reason
                if mode == "scan-safe":
                    result.ok = True
                    result.fallback_kind = "cfg_only"
                    if result.regeneration_failed and result.regeneration_failure_reason:
                        result.reason = result.regeneration_failure_reason
                        reason = result.reason
                    _mark_stage(result, "decompile", True, detail=reason)
                    return _finish_scan(result)
                result.failure_class = failure_class
                result.fallback_kind = "block_lift"
                _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
                return _finish_scan(result)
            text = codegen.text
            result.interrupt_dos_helper_count = _count_named_helper_calls(text, _INTERRUPT_DOS_HELPER_NAMES)
            result.interrupt_bios_helper_count = _count_named_helper_calls(text, _INTERRUPT_BIOS_HELPER_NAMES)
            result.interrupt_wrapper_call_count = _count_interrupt_wrapper_calls(text)
            result.interrupt_unresolved_wrapper_count = result.interrupt_wrapper_call_count
            result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_text(text, result)
            result.readability_cluster, result.readability_cluster_reason = _classify_readability_cluster(result, text)
            result.decompiled_count = 1
            result.ok = True
            _mark_stage(result, "decompile", True)
            return _finish_scan(result)
        except Exception as exc:  # noqa: BLE001
            failure_class, reason = classify_failure(
                "decompile",
                exc,
                rewrite_failed=result.rewrite_failed,
                regeneration_failed=result.regeneration_failed,
            )
            result.failure_class = failure_class
            result.reason = reason
            result.fallback_kind = "block_lift"
            result.semantic_family, result.semantic_family_reason = _classify_semantic_family_from_failure(result)
            _mark_stage(result, "decompile", False, reason=failure_class, detail=reason)
            return _finish_scan(result)
    finally:
        _SCAN_ACTIVE = False
        _clear_alarm()
        signal.signal(signal.SIGALRM, old_handler)


def summarize_results(results: list[FunctionScanResult], mode: str) -> dict[str, object]:
    def _has_fallback_kind(result: FunctionScanResult) -> bool:
        return result.fallback_kind not in (None, "none")

    confidence_summaries = [classify_x86_16_recovery_confidence(result) for result in results]
    failure_counter = Counter(result.failure_class for result in results if result.failure_class is not None)
    fallback_counter = Counter(result.fallback_kind for result in results if _has_fallback_kind(result))
    stage_failure_counter = Counter(
        stage.stage
        for result in results
        for stage in result.stages
        if not stage.ok
    )
    timeout_stage_counter = Counter(
        stage.stage
        for result in results
        for stage in result.stages
        if not stage.ok and (stage.reason == "timeout" or result.failure_class == "timeout")
    )
    failure_file_counter = Counter(
        result.cod_file for result in results if not result.ok and result.failure_class is not None
    )
    failure_function_counter = Counter(
        (result.cod_file, result.proc_name, result.proc_kind, result.failure_class)
        for result in results
        if not result.ok and result.failure_class is not None
    )
    fallback_file_counter = Counter(result.cod_file for result in results if _has_fallback_kind(result))
    fallback_function_counter = Counter(
        (result.cod_file, result.proc_name, result.proc_kind, result.fallback_kind)
        for result in results
        if _has_fallback_kind(result)
    )
    family_counter = Counter(result.semantic_family for result in results if result.semantic_family is not None)
    family_failure_counter = Counter(
        result.semantic_family for result in results if not result.ok and result.semantic_family is not None
    )
    family_fallback_counter = Counter(
        result.semantic_family for result in results if _has_fallback_kind(result) and result.semantic_family is not None
    )
    family_cluster_counter = Counter(
        (result.semantic_family, cluster)
        for result in results
        if (cluster := _classify_ugly_cluster(result)) is not None and result.semantic_family is not None
    )
    readability_cluster_counter = Counter(
        result.readability_cluster for result in results if result.readability_cluster is not None
    )
    per_file: dict[str, dict[str, int]] = defaultdict(lambda: {"scanned": 0, "ok": 0})

    for result in results:
        per_file[result.cod_file]["scanned"] += 1
        if result.ok:
            per_file[result.cod_file]["ok"] += 1

    files_zero_success = sorted(name for name, stats in per_file.items() if stats["ok"] == 0)
    files_scan_clean = sorted(name for name, stats in per_file.items() if stats["ok"] == stats["scanned"])
    files_partial_success = sorted(
        name for name, stats in per_file.items() if 0 < stats["ok"] < stats["scanned"]
    )

    fallback_results = [result for result in results if _has_fallback_kind(result)]
    full_decompile_count = sum(1 for result in results if result.decompiled_count > 0)
    cfg_only_count = sum(1 for result in results if result.fallback_kind == "cfg_only")
    lift_only_count = sum(1 for result in results if result.fallback_kind == "lift_only")
    block_lift_count = sum(1 for result in results if result.fallback_kind == "block_lift")
    rewrite_failure_count = sum(1 for result in results if result.rewrite_failed)
    structuring_failure_count = sum(1 for result in results if result.structuring_failed)
    regeneration_failure_count = sum(1 for result in results if result.regeneration_failed)
    confidence_status_counter = Counter(summary.status for summary in confidence_summaries)
    confidence_scan_safe_counter = Counter(summary.scan_safe_classification for summary in confidence_summaries)
    confidence_assumption_counter = Counter(item.kind for summary in confidence_summaries for item in summary.assumptions)
    confidence_evidence_counter = Counter(item.kind for summary in confidence_summaries for item in summary.evidence)
    confidence_diagnostic_counter = Counter(diagnostic for summary in confidence_summaries for diagnostic in summary.diagnostics)
    interrupt_dos_helper_count = sum(result.interrupt_dos_helper_count for result in results)
    interrupt_bios_helper_count = sum(result.interrupt_bios_helper_count for result in results)
    interrupt_wrapper_call_count = sum(result.interrupt_wrapper_call_count for result in results)
    interrupt_unresolved_wrapper_count = sum(result.interrupt_unresolved_wrapper_count for result in results)
    fallback_only_count = sum(1 for result in fallback_results if result.ok)
    true_failure_count = sum(1 for result in results if not result.ok)
    unclassified_failure_count = sum(
        1
        for result in results
        if not result.ok and result.failure_class in {"analysis_failure", "unknown_failure"}
    )
    ugly_cluster_counter = Counter(
        cluster for result in results if (cluster := _classify_ugly_cluster(result)) is not None
    )

    def _rate(count: int) -> float:
        if not results:
            return 0.0
        return round(count / len(results), 6)

    top_failure_classes = [
        {"failure_class": failure_class, "count": count}
        for failure_class, count in sorted(failure_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_fallback_kinds = [
        {"fallback_kind": fallback_kind, "count": count}
        for fallback_kind, count in sorted(fallback_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_failure_stages = [
        {"stage": stage, "count": count}
        for stage, count in sorted(stage_failure_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_failure_files = [
        {"cod_file": cod_file, "count": count}
        for cod_file, count in sorted(failure_file_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_failure_functions = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "failure_class": failure_class,
            "count": count,
        }
        for (cod_file, proc_name, proc_kind, failure_class), count in sorted(
            failure_function_counter.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    top_fallback_files = [
        {"cod_file": cod_file, "count": count}
        for cod_file, count in sorted(fallback_file_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_fallback_functions = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "fallback_kind": fallback_kind,
            "count": count,
        }
        for (cod_file, proc_name, proc_kind, fallback_kind), count in sorted(
            fallback_function_counter.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    top_ugly_clusters = [
        {"cluster": cluster, "count": count}
        for cluster, count in sorted(ugly_cluster_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_family_ownership = [
        {
            "family": family,
            "count": count,
        }
        for family, count in sorted(family_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_family_failures = [
        {
            "family": family,
            "count": count,
        }
        for family, count in sorted(family_failure_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    top_family_fallbacks = [
        {
            "family": family,
            "count": count,
        }
        for family, count in sorted(family_fallback_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    family_ugly_clusters = [
        {"family": family, "cluster": cluster, "count": count}
        for (family, cluster), count in sorted(family_cluster_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    readability_clusters = [
        {"cluster": cluster, "count": count}
        for cluster, count in sorted(readability_cluster_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    tail_validation_records = []
    for result in results:
        tail_validation_records.append(
            {
                "cod_file": result.cod_file,
                "proc_name": result.proc_name,
                "proc_kind": result.proc_kind,
                "structuring": (result.tail_validation or {}).get("structuring"),
                "postprocess": (result.tail_validation or {}).get("postprocess"),
            }
        )
    tail_validation_aggregate = build_x86_16_tail_validation_aggregate(tail_validation_records, scanned=len(results))
    tail_validation_summary = tail_validation_aggregate["summary"]
    tail_validation_surface = tail_validation_aggregate["surface"]

    return {
        "mode": mode,
        "scanned": len(results),
        "ok": sum(1 for result in results if result.ok),
        "failed": sum(1 for result in results if not result.ok),
        "failure_counts": dict(sorted(failure_counter.items())),
        "fallback_counts": dict(sorted(fallback_counter.items())),
        "top_failure_classes": top_failure_classes,
        "top_fallback_kinds": top_fallback_kinds,
        "top_failure_stages": top_failure_stages,
        "timeout_stage_counts": dict(sorted(timeout_stage_counter.items())),
        "top_failure_files": top_failure_files,
        "top_failure_functions": top_failure_functions,
        "top_fallback_files": top_fallback_files,
        "top_fallback_functions": top_fallback_functions,
        "top_ugly_clusters": top_ugly_clusters,
        "readability_clusters": readability_clusters,
        "family_ownership": {
            "top_families": top_family_ownership,
            "top_failures": top_family_failures,
            "top_fallbacks": top_family_fallbacks,
            "top_ugly_clusters": family_ugly_clusters,
        },
        "files_zero_success": files_zero_success,
        "files_partial_success": files_partial_success,
        "files_scan_clean": files_scan_clean,
        "full_decompile_count": full_decompile_count,
        "cfg_only_count": cfg_only_count,
        "lift_only_count": lift_only_count,
        "block_lift_count": block_lift_count,
        "rewrite_failure_count": rewrite_failure_count,
        "structuring_failure_count": structuring_failure_count,
        "regeneration_failure_count": regeneration_failure_count,
        "fallback_only_count": fallback_only_count,
        "true_failure_count": true_failure_count,
        "visibility_debt": true_failure_count,
        "recovery_debt": fallback_only_count,
        "readability_debt": full_decompile_count,
        "unclassified_failure_count": unclassified_failure_count,
        "interrupt_api": {
            "dos_helpers": interrupt_dos_helper_count,
            "bios_helpers": interrupt_bios_helper_count,
            "wrapper_calls": interrupt_wrapper_call_count,
            "unresolved_wrappers": interrupt_unresolved_wrapper_count,
        },
        "confidence": summarize_recovery_confidence(results),
        "confidence_status_counts": dict(sorted(confidence_status_counter.items())),
        "confidence_scan_safe_counts": dict(sorted(confidence_scan_safe_counter.items())),
        "confidence_assumption_counts": dict(sorted(confidence_assumption_counter.items())),
        "confidence_evidence_counts": dict(sorted(confidence_evidence_counter.items())),
        "confidence_diagnostic_counts": dict(sorted(confidence_diagnostic_counter.items())),
        "tail_validation": tail_validation_summary,
        "tail_validation_surface": tail_validation_surface,
        "tail_validation_cache": {
            "cache_key": tail_validation_aggregate["cache_key"],
            "cache_hit": bool(tail_validation_aggregate["cache_hit"]),
        },
        "blind_spot_budget": {
            "full_decompile_rate": _rate(full_decompile_count),
            "cfg_only_rate": _rate(cfg_only_count),
            "lift_only_rate": _rate(lift_only_count),
            "block_lift_rate": _rate(block_lift_count),
            "true_failure_rate": _rate(true_failure_count),
        },
        "debt": {
            "traversal": true_failure_count,
            "recovery": fallback_only_count,
            "readability": full_decompile_count,
        },
        "results": [asdict(result) for result in results],
    }


__all__ = [
    "FunctionScanResult",
    "ScanTimeout",
    "StageResult",
    "_clear_alarm",
    "classify_failure",
    "extract_cod_functions",
    "scan_function",
    "set_memory_limit",
    "summarize_results",
    "_should_skip_scan_safe_decompile",
    "_should_skip_scan_safe_cfg",
    "_should_skip_scan_safe_back_edge",
    "_should_skip_scan_safe_call_chain",
    "_should_skip_scan_safe_decompile_for_cfg_shape",
    "_classify_readability_cluster",
]
