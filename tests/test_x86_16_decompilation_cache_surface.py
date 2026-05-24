from pathlib import Path

from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES


def test_decompilation_cache_surface_includes_tail_validation_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "tail_validation.py" in names
    assert "tail_validation_fingerprint.py" in names
    assert "tail_validation_routing.py" in names


def test_decompilation_cache_surface_includes_condition_and_induction_rewrite_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "cli_decompilation.py" in names
    assert "condition_ir.py" in names
    assert "decompiler_postprocess_flags.py" in names
    assert "decompiler_postprocess_stage.py" in names
    assert "type_array_matching.py" in names
    assert "cli_access_object_hints.py" in names
    assert "cli_access_profiles.py" in names
    assert "cli_access_traits.py" in names
