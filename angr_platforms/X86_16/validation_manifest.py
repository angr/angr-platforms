from __future__ import annotations

from dataclasses import dataclass

from .structuring_grouped_refusal_report import describe_x86_16_structuring_grouped_refusal_report_surface
from .structuring_grouping_report import describe_x86_16_structuring_grouping_report_surface
from .validation_helper_report import describe_x86_16_validation_helper_report_surface


@dataclass(frozen=True)
class ValidationLayerSpec:
    name: str
    purpose: str
    default_checks: tuple[str, ...]


@dataclass(frozen=True)
class ValidationFamilySpec:
    name: str
    purpose: str
    default_checks: tuple[str, ...]


VALIDATION_LAYERS = (
    ValidationLayerSpec(
        name="unit",
        purpose="Keep alias, widening, and low-level recovery helpers individually safe.",
        default_checks=(
            "tests/test_x86_16_alias_register_mvp.py",
            "tests/test_x86_16_storage_domain_alias.py",
            "tests/test_x86_16_widening_model.py",
            "tests/test_x86_16_word_global_helpers.py",
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_readability_set.py",
            "tests/test_x86_16_validation_manifest.py",
        ),
    ),
    ValidationLayerSpec(
        name="focused_corpus",
        purpose="Keep sample-backed and semantic regressions green on real bounded inputs.",
        default_checks=(
            "tests/test_x86_16_smoketest.py",
            "tests/test_x86_16_compare_semantics.py",
            "tests/test_x86_16_corpus_scan.py",
            "tests/test_x86_16_sample_matrix.py",
        ),
    ),
    ValidationLayerSpec(
        name="whole_program",
        purpose="Keep the bounded scan-safe lane and sample-matrix whole-program probes stable.",
        default_checks=(
            "scripts/scan_cod_dir.py --mode scan-safe",
            "tests/test_x86_16_runtime_samples.py",
            "tests/test_x86_16_sample_matrix.py",
        ),
    ),
)


VALIDATION_FAMILIES = (
    ValidationFamilySpec(
        name="addressing",
        purpose="Keep effective-address, far-pointer, and width-matrix behavior explicit.",
        default_checks=(
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
    ),
    ValidationFamilySpec(
        name="stack_control",
        purpose="Keep call/ret/enter/leave, privilege stack, and branch helpers stable.",
        default_checks=(
            "tests/test_x86_16_stack_helpers.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
    ),
    ValidationFamilySpec(
        name="string",
        purpose="Keep REP, direction-flag, and compare/store string behavior stable.",
        default_checks=(
            "tests/test_x86_16_string_helpers.py",
            "tests/test_x86_16_compare_semantics.py",
        ),
    ),
    ValidationFamilySpec(
        name="alu",
        purpose="Keep flag-update and arithmetic/shift/rotate behavior stable.",
        default_checks=(
            "tests/test_x86_16_alu_helpers.py",
            "tests/test_x86_16_compare_semantics.py",
        ),
    ),
    ValidationFamilySpec(
        name="interrupt_api",
        purpose="Keep interrupt-core semantics and DOS/BIOS/API lowering separable.",
        default_checks=(
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_corpus_scan.py",
        ),
    ),
    ValidationFamilySpec(
        name="correctness",
        purpose="Keep decompilation correctness anchored to COD-source, runtime, and hardware-backed probes.",
        default_checks=(
            "tests/test_x86_16_cod_samples.py",
            "tests/test_x86_16_compare_semantics.py",
            "tests/test_x86_16_runtime_samples.py",
            "tests/test_x86_16_sample_matrix.py",
            "tests/test_x86_16_80286_verifier.py",
        ),
    ),
    ValidationFamilySpec(
        name="tail_validation_accounting",
        purpose="Keep changed, unknown, and uncollected PROC identities attributable in summaries and artifacts.",
        default_checks=(
            "tests/test_x86_16_tail_validation.py",
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_corpus_scan.py",
            "tests/test_decompile_cod_dir_parallelism.py",
        ),
    ),
    ValidationFamilySpec(
        name="alias_model",
        purpose="Keep storage identity evidence-driven before widening, traits, types, or rewrite consume it.",
        default_checks=(
            "tests/test_x86_16_alias_register_mvp.py",
            "tests/test_x86_16_alias_api_and_widening_proof.py",
            "tests/test_x86_16_storage_domain_alias.py",
            "tests/test_x86_16_segmented_memory.py",
        ),
    ),
    ValidationFamilySpec(
        name="widening",
        purpose="Keep widened storage alias-gated instead of shape-only.",
        default_checks=(
            "tests/test_x86_16_widening_model.py",
            "tests/test_x86_16_alias_api_and_widening_proof.py",
            "tests/test_x86_16_word_global_store_widening.py",
        ),
    ),
    ValidationFamilySpec(
        name="segmented_memory",
        purpose="Keep real-mode DS, SS, and ES storage distinct unless association is proven.",
        default_checks=(
            "tests/test_x86_16_segmented_memory.py",
            "tests/test_x86_16_storage_domain_alias.py",
            "tests/test_x86_16_tail_validation.py",
        ),
    ),
    ValidationFamilySpec(
        name="types_objects",
        purpose="Keep type and object recovery downstream from stable evidence.",
        default_checks=(
            "tests/test_x86_16_type_equivalence_classes.py",
            "tests/test_x86_16_stack_prototype_promotion.py",
        ),
    ),
    ValidationFamilySpec(
        name="readability_guard",
        purpose="Keep readability work non-semantic and behind validation guardrails.",
        default_checks=(
            "tests/test_x86_16_readability_set.py",
            "tests/test_x86_16_readability_goals.py",
            "tests/test_x86_16_tail_validation.py",
        ),
    ),
)


def describe_x86_16_validation_layers() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


def describe_x86_16_validation_families() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((family.name, family.default_checks) for family in VALIDATION_FAMILIES)


def describe_x86_16_validation_triage() -> dict[str, object]:
    return {
        "reference_role": "secondary semantic reference",
        "target_families": (
            "string",
            "stack_control",
            "addressing",
            "interrupt_api",
            "alu",
        ),
        "bounded_opcode_sets": (
            {
                "family": "string",
                "opcodes": ("movsb", "movsw", "cmpsb", "cmpsw", "scasb", "scasw", "stosb", "stosw", "lodsb", "lodsw"),
            },
            {
                "family": "stack_control",
                "opcodes": ("call", "ret", "iret", "enter", "leave", "push", "pop", "pushf", "popf"),
            },
            {
                "family": "addressing",
                "opcodes": ("lea", "xlat", "bound", "les", "lds", "mov"),
            },
            {
                "family": "interrupt_api",
                "opcodes": ("int 0x10", "int 0x21", "int 0x33"),
            },
            {
                "family": "alu",
                "opcodes": ("add", "adc", "sub", "sbb", "cmp", "test", "shl", "shr", "rol", "ror"),
            },
        ),
        "workflow": (
            "compare Inertia output first",
            "confirm against hardware-backed or compare-style references when available",
        ),
        "evidence_sources": ("Inertia output", "hardware-backed or compare-style reference"),
        "use_case": "debugging and triage only, not sole truth source",
        "outputs": (
            "family notes",
            "opcode notes",
            "minimal repro snippets",
        ),
        "artifacts": ("disassembly", "decompile text", "semantic notes"),
        "report_consumers": (
            describe_x86_16_validation_helper_report_surface(),
            describe_x86_16_structuring_grouping_report_surface(),
            describe_x86_16_structuring_grouped_refusal_report_surface(),
        ),
    }


__all__ = [
    "VALIDATION_FAMILIES",
    "VALIDATION_LAYERS",
    "ValidationFamilySpec",
    "ValidationLayerSpec",
    "describe_x86_16_validation_triage",
    "describe_x86_16_validation_families",
    "describe_x86_16_validation_layers",
]
