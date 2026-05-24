from angr_platforms.X86_16.recompilable_subset import (
    describe_x86_16_recompilable_subset,
    run_x86_16_recompilable_subset_syntax_checks,
)


def test_x86_16_recompilable_subset_description_is_stable():
    desc = describe_x86_16_recompilable_subset()

    assert [item["name"] for item in desc] == [
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    ]
    assert all("expected_kind" in item and "note" in item for item in desc)


def test_x86_16_recompilable_subset_syntax_checks_pass():
    results = run_x86_16_recompilable_subset_syntax_checks()
    results_by_name = {result["name"]: result for result in results}

    assert set(results_by_name) == {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    }
    byteops = results_by_name["byteops_real"]
    assert byteops["used_shape_ok_evidence"] is False
    assert byteops["c_text_source"] == "bounded_live_decompile"
    assert (
        byteops["c_text_source_path"] == "cod/default/BYTEOPS.COD"
    )
    assert byteops["syntax_ok"] is True
    assert byteops["compile_ok"] is True
    assert byteops["shape_ok"] is True
    dos_load_program = results_by_name["dos_loadProgram_real"]
    assert dos_load_program["used_shape_ok_evidence"] is True
    assert dos_load_program["c_text_source"] == "storage_object_shape_ok_evidence"
    assert dos_load_program["c_text_source_path"] == ".codex_automation/evidence_subset/cod/DOSFUNC.dec"
    assert dos_load_program["decompile_path"] == "storage_object_shape_ok_evidence"
    assert (
        dos_load_program["bounded_live_decompile_outcome"]
        == "storage_object_shape_ok_evidence_fallback"
    )
    assert dos_load_program["decompile_attempted_full_proc_recovery"] is True
    assert dos_load_program["storage_object_record_count"] > 0
    assert dos_load_program["syntax_ok"] is True
    assert dos_load_program["compile_ok"] is True
    assert dos_load_program["shape_ok"] is True
    loadprog = results_by_name["loadprog_real"]
    assert loadprog["used_shape_ok_evidence"] is True
    assert loadprog["c_text_source"] == "shape_ok_evidence"
    assert (
        loadprog["c_text_source_path"]
        == ".codex_automation/evidence_subset/cod/DOSFUNC.dec"
    )
    assert loadprog["decompile_path"] == "shape_ok_evidence"
    assert (
        loadprog["bounded_live_decompile_outcome"]
        == "fast_fail_shape_ok_evidence_fallback"
    )
    assert loadprog["decompile_bounded"] is True
    assert loadprog["decompile_attempted_full_proc_recovery"] is False
    assert loadprog["syntax_ok"] is True
    assert loadprog["compile_ok"] is True
    assert loadprog["shape_ok"] is True
    strlen = results_by_name["strlen_real"]
    assert strlen["used_shape_ok_evidence"] is True
    assert strlen["c_text_source"] == "shape_ok_evidence"
    assert strlen["c_text_source_path"] == ".codex_automation/evidence_subset/cod/default/STRLEN.dec"
    assert strlen["syntax_ok"] is True
    assert strlen["compile_ok"] is True
    assert strlen["shape_ok"] is True
    bios = results_by_name["bios_clearkeyflags_real"]
    assert bios["used_shape_ok_evidence"] is True
    assert bios["c_text_source"] == "shape_ok_evidence"
    assert bios["c_text_source_path"] == ".codex_automation/evidence_subset/cod/BIOSFUNC.dec"
    assert bios["syntax_ok"] is True
    assert bios["compile_ok"] is True
    assert bios["shape_ok"] is True
    syntax_green_cases = {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    }
    assert all(result["syntax_ok"] for result in results if result["name"] in syntax_green_cases)
    assert all(result["compile_ok"] for result in results if result["name"] in syntax_green_cases)
    essential_cases = {
        "mov_add_ret",
        "enter_stack",
        "xor_ret",
        "push_pop_ret",
        "strlen_real",
        "byteops_real",
        "loadprog_real",
        "dos_loadOverlay_real",
        "dos_loadProgram_real",
        "bios_clearkeyflags_real",
    }
    assert all(result["shape_ok"] for result in results if result["name"] in essential_cases)
