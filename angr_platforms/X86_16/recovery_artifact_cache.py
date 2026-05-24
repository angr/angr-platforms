from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from .tail_validation import build_x86_16_validation_cache_descriptor

__all__ = [
    "cache_x86_16_recovery_artifact",
    "describe_x86_16_recovery_artifact_cache_surface",
]


def cache_x86_16_recovery_artifact(
    namespace: str,
    artifact: Mapping[str, object],
    *,
    cache_path: str | Path | None,
) -> dict[str, object]:
    descriptor = build_x86_16_validation_cache_descriptor(namespace, artifact)
    payload = {
        "cache_key": descriptor.cache_key,
        "artifact": dict(artifact),
    }
    if cache_path is None:
        return {
            "cache_key": descriptor.cache_key,
            "cache_hit": False,
            "artifact": dict(artifact),
            "path": None,
        }

    path = Path(cache_path)
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
        if cached.get("cache_key") == descriptor.cache_key:
            cached_artifact = cached.get("artifact", {})
            return {
                "cache_key": descriptor.cache_key,
                "cache_hit": True,
                "artifact": dict(cached_artifact) if isinstance(cached_artifact, Mapping) else dict(artifact),
                "path": path,
            }
    except Exception:
        pass

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception:
        pass
    return {
        "cache_key": descriptor.cache_key,
        "cache_hit": False,
        "artifact": dict(artifact),
        "path": path,
    }


def describe_x86_16_recovery_artifact_cache_surface() -> dict[str, object]:
    return {
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
