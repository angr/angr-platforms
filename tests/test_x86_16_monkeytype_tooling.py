from __future__ import annotations

from pathlib import Path

from inertia_decompiler import monkeytype_tools


def test_monkeytype_code_filter_accepts_repo_python_sources():
    assert monkeytype_tools.is_traceable_repo_path(Path("/home/xor/vextest/inertia_decompiler/cli_access_object_hints.py"))
    assert monkeytype_tools.is_traceable_repo_path(Path("/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_model.py"))
    assert monkeytype_tools.is_traceable_repo_path(Path("/home/xor/vextest/decompile.py"))


def test_monkeytype_code_filter_rejects_external_sources():
    assert not monkeytype_tools.is_traceable_repo_path(Path("/home/xor/vextest/.venv/lib/python3.14/site-packages/monkeytype/cli.py"))
    assert not monkeytype_tools.is_traceable_repo_path(Path("/tmp/random_script.py"))


def test_parse_list_modules_output_filters_and_sorts_modules():
    output = "\n".join(
        [
            "pytest",
            "inertia_decompiler.cli_access_object_hints",
            "angr_platforms.X86_16.alias_model",
            "decompile",
            "inertia_decompiler.cli_access_object_hints",
            "other.module",
        ]
    )
    assert monkeytype_tools.parse_list_modules_output(output) == (
        "angr_platforms.X86_16.alias_model",
        "decompile",
        "inertia_decompiler.cli_access_object_hints",
    )


def test_stub_path_for_module_uses_monkeytype_stub_cache():
    stub_path = monkeytype_tools.stub_path_for_module("inertia_decompiler.cli_access_object_hints")
    assert stub_path == monkeytype_tools.MONKEYTYPE_STUBS_DIR / "inertia_decompiler" / "cli_access_object_hints.pyi"


def test_source_path_for_module_maps_both_repo_roots():
    assert monkeytype_tools.source_path_for_module("decompile") == monkeytype_tools.REPO_ROOT / "decompile.py"
    assert monkeytype_tools.source_path_for_module("inertia_decompiler.runtime_support") == (
        monkeytype_tools.REPO_ROOT / "inertia_decompiler" / "runtime_support.py"
    )
    assert monkeytype_tools.source_path_for_module("angr_platforms.X86_16.alias_model") == (
        monkeytype_tools.REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "alias_model.py"
    )


def test_default_monkeytype_targets_cover_phase7_tests():
    targets = monkeytype_tools.DEFAULT_MONKEYTYPE_TEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_access_trait_policy.py" in targets
    assert "angr_platforms/tests/test_x86_16_access_trait_arrays.py" in targets
    assert "angr_platforms/tests/test_x86_16_segmented_memory.py" in targets
    assert "angr_platforms/tests/test_x86_16_tail_validation.py" in targets
