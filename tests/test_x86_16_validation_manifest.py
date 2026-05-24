from angr_platforms.X86_16.validation_manifest import (
    VALIDATION_FAMILIES,
    VALIDATION_LAYERS,
    describe_x86_16_validation_families,
    describe_x86_16_validation_helper_report_surface,
    describe_x86_16_validation_layers,
    describe_x86_16_validation_triage,
)
from angr_platforms.X86_16.structuring_grouping_report import (
    describe_x86_16_structuring_grouping_report_surface,
)
from angr_platforms.X86_16.structuring_grouped_refusal_report import (
    describe_x86_16_structuring_grouped_refusal_report_surface,
)


def test_x86_16_validation_layers_cover_three_tier_discipline():
    assert [layer.name for layer in VALIDATION_LAYERS] == ["unit", "focused_corpus", "whole_program"]
    assert describe_x86_16_validation_layers() == tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


def test_x86_16_validation_layers_pin_expected_focus_checks():
    unit, focused, whole_program = VALIDATION_LAYERS

    assert "tests/test_x86_16_alias_register_mvp.py" in unit.default_checks
    assert "tests/test_x86_16_widening_model.py" in unit.default_checks
    assert "tests/test_x86_16_validation_manifest.py" in unit.default_checks
    assert "tests/test_x86_16_sample_matrix.py" in focused.default_checks
    assert "scripts/scan_cod_dir.py --mode scan-safe" in whole_program.default_checks


def test_x86_16_validation_families_cover_key_instruction_core_slices():
    assert [family.name for family in VALIDATION_FAMILIES] == [
        "addressing",
        "stack_control",
        "string",
        "alu",
        "interrupt_api",
        "correctness",
        "tail_validation_accounting",
        "alias_model",
        "widening",
        "segmented_memory",
        "types_objects",
        "readability_guard",
    ]
    assert describe_x86_16_validation_families() == tuple(
        (family.name, family.default_checks) for family in VALIDATION_FAMILIES
    )
    assert "tests/test_x86_16_addressing_helpers.py" in VALIDATION_FAMILIES[0].default_checks
    assert "tests/test_x86_16_stack_helpers.py" in VALIDATION_FAMILIES[1].default_checks
    assert "tests/test_x86_16_string_helpers.py" in VALIDATION_FAMILIES[2].default_checks
    assert "tests/test_x86_16_alu_helpers.py" in VALIDATION_FAMILIES[3].default_checks
    assert "tests/test_x86_16_milestone_report.py" in VALIDATION_FAMILIES[4].default_checks
    assert "tests/test_x86_16_compare_semantics.py" in VALIDATION_FAMILIES[5].default_checks
    assert "tests/test_x86_16_80286_verifier.py" in VALIDATION_FAMILIES[5].default_checks
    assert "tests/test_x86_16_tail_validation.py" in VALIDATION_FAMILIES[6].default_checks
    assert "tests/test_decompile_cod_dir_parallelism.py" in VALIDATION_FAMILIES[6].default_checks
    assert "tests/test_x86_16_storage_domain_alias.py" in VALIDATION_FAMILIES[7].default_checks
    assert "tests/test_x86_16_widening_model.py" in VALIDATION_FAMILIES[8].default_checks
    assert "tests/test_x86_16_segmented_memory.py" in VALIDATION_FAMILIES[9].default_checks
    assert "tests/test_x86_16_type_equivalence_classes.py" in VALIDATION_FAMILIES[10].default_checks
    assert "tests/test_x86_16_readability_set.py" in VALIDATION_FAMILIES[11].default_checks


def test_x86_16_validation_triage_surface_spells_out_workflow():
    assert describe_x86_16_validation_triage() == {
        "reference_role": "secondary semantic reference",
        "target_families": ("string", "stack_control", "addressing", "interrupt_api", "alu"),
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
        "outputs": ("family notes", "opcode notes", "minimal repro snippets"),
        "artifacts": ("disassembly", "decompile text", "semantic notes"),
        "report_consumers": (
            describe_x86_16_validation_helper_report_surface(),
            describe_x86_16_structuring_grouping_report_surface(),
            describe_x86_16_structuring_grouped_refusal_report_surface(),
        ),
    }
