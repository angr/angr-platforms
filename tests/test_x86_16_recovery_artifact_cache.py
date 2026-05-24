import json

from angr_platforms.X86_16.recovery_artifact_cache import (
    cache_x86_16_recovery_artifact,
    describe_x86_16_recovery_artifact_cache_surface,
)


def test_recovery_artifact_cache_persists_and_hits(tmp_path):
    path = tmp_path / "artifact.json"
    artifact = {
        "proc_name": "_helper",
        "confidence": {"status": "bounded_recovery"},
        "helper_family_rows": [],
    }

    first = cache_x86_16_recovery_artifact("recovery_artifact.function", artifact, cache_path=path)
    second = cache_x86_16_recovery_artifact("recovery_artifact.function", artifact, cache_path=path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert payload["cache_key"] == first["cache_key"] == second["cache_key"]
    assert payload["artifact"]["proc_name"] == "_helper"


def test_recovery_artifact_cache_surface_is_deterministic():
    assert describe_x86_16_recovery_artifact_cache_surface() == {
        "namespace_family": "recovery_artifact.*",
        "artifact_fields": (
            "effect_summary",
            "helper_summary",
            "confidence",
            "helper_family_rows",
        ),
        "cache_descriptor_source": "build_x86_16_validation_cache_descriptor",
        "persistence_format": "json",
    }
