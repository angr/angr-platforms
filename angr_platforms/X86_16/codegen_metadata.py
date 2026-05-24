from __future__ import annotations

__all__ = [
    "append_codegen_sequence_attr",
    "get_codegen_sequence_attr",
    "get_codegen_side_metadata",
]


def get_codegen_side_metadata(codegen) -> dict[str, object]:
    metadata = getattr(codegen, "_inertia_recovery_metadata", None)
    if isinstance(metadata, dict):
        return metadata
    metadata = {}
    setattr(codegen, "_inertia_recovery_metadata", metadata)
    return metadata


def get_codegen_sequence_attr(codegen, cfunc, name: str) -> tuple[str, ...]:
    value = getattr(codegen, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    value = getattr(cfunc, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    return ()


def append_codegen_sequence_attr(codegen, cfunc, name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = list(get_codegen_sequence_attr(codegen, cfunc, name))
    for value in values:
        if value not in merged:
            merged.append(value)
    merged_tuple = tuple(merged)
    setattr(codegen, name, merged_tuple)
    try:
        setattr(cfunc, name, merged_tuple)
    except Exception:
        pass
    return merged_tuple
