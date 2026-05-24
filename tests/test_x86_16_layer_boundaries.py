from __future__ import annotations

import ast
from pathlib import Path

from angr_platforms.X86_16.widening.widening_rules import run_typed_widening_pass_8616


_ROOT = Path(__file__).resolve().parents[1] / "angr_platforms" / "X86_16"
_OWNING_LAYERS = ("semantics", "alias", "widening", "structuring", "lowering")
_ALL_GUARDED_LAYERS = _OWNING_LAYERS + ("postprocess",)


def _iter_layer_py_files(layer: str):
    layer_dir = _ROOT / layer
    if not layer_dir.exists():
        return
    for path in sorted(layer_dir.rglob("*.py")):
        if path.name == "__pycache__":
            continue
        yield path


def _import_targets(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                targets.append(module)
    return targets


def test_layer_modules_do_not_import_cli_modules() -> None:
    offenders: list[str] = []
    for layer in _ALL_GUARDED_LAYERS:
        for path in _iter_layer_py_files(layer):
            for target in _import_targets(path):
                if target == "inertia_decompiler.cli" or target.startswith("inertia_decompiler.cli_"):
                    offenders.append(f"{path}: {target}")
    assert offenders == []


def test_owning_layers_do_not_import_postprocess_layer() -> None:
    offenders: list[str] = []
    for layer in _OWNING_LAYERS:
        for path in _iter_layer_py_files(layer):
            for target in _import_targets(path):
                if target == "angr_platforms.X86_16.postprocess" or target.startswith("angr_platforms.X86_16.postprocess."):
                    offenders.append(f"{path}: {target}")
    assert offenders == []


def test_cli_segmented_modules_are_compatibility_shims_only() -> None:
    shim_paths = (
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented_lowering.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_access_object_hints.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_stack_coalesce.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_segmented_store_coalesce.py",
        Path(__file__).resolve().parents[2] / "inertia_decompiler" / "cli_word_loads.py",
    )
    offenders: list[str] = []
    for path in shim_paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))
    assert offenders == []


def test_alias_stack_lowering_module_is_compatibility_shim_only() -> None:
    path = _ROOT / "alias" / "stack_lowering.py"
    tree = ast.parse(path.read_text(), filename=str(path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body)


def test_flat_widening_modules_are_compatibility_shims_only() -> None:
    widening_alias_path = _ROOT / "widening_alias.py"
    alias_tree = ast.parse(widening_alias_path.read_text(), filename=str(widening_alias_path))
    assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in alias_tree.body)

    widening_model_path = _ROOT / "widening_model.py"
    model_tree = ast.parse(widening_model_path.read_text(), filename=str(widening_model_path))
    assert not any(isinstance(node, ast.ClassDef) for node in model_tree.body)
    allowed_wrappers = {
        "prove_adjacent_storage_slices",
        "analyze_adjacent_storage_slices",
        "can_join_adjacent_storage_slices",
        "merge_storage_slice_domains",
    }
    wrapper_names = {
        node.name
        for node in model_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert wrapper_names <= allowed_wrappers


def test_flat_alias_modules_are_compatibility_shims_only() -> None:
    shim_paths = (
        _ROOT / "alias_domains.py",
        _ROOT / "alias_state.py",
        _ROOT / "alias_transfer.py",
    )
    offenders: list[str] = []
    for path in shim_paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in tree.body):
            offenders.append(str(path))
    assert offenders == []


def test_layer_headers_present_on_migrated_modules() -> None:
    targets = (
        _ROOT / "alias" / "alias_model.py",
        _ROOT / "alias" / "domains.py",
        _ROOT / "alias" / "state.py",
        _ROOT / "alias" / "transfer.py",
        _ROOT / "lowering" / "stack_lowering.py",
        _ROOT / "ir" / "condition_ir.py",
        _ROOT / "ir" / "address_ir.py",
        _ROOT / "ir" / "value_ir.py",
        _ROOT / "widening" / "store_width.py",
        _ROOT / "widening" / "register_widening.py",
        _ROOT / "widening" / "stack_widening.py",
        _ROOT / "postprocess" / "flags_cleanup.py",
        _ROOT / "postprocess" / "cleanup.py",
    )
    missing: list[str] = []
    for path in targets:
        head = "\n".join(path.read_text().splitlines()[:20])
        if "# Layer:" not in head or "# Responsibility:" not in head:
            missing.append(str(path))
    assert missing == []


def test_widening_entrypoint_runs_subpasses_in_fixed_order() -> None:
    calls: list[str] = []

    def _direct(_project, _codegen) -> bool:
        calls.append("direct")
        return False

    def _segmented(_project, _codegen) -> bool:
        calls.append("segmented")
        return True

    changed = run_typed_widening_pass_8616(
        object(),
        object(),
        coalesce_direct_ss_local_word_statements=_direct,
        coalesce_segmented_word_store_statements=_segmented,
    )
    assert changed is True
    assert calls == ["direct", "segmented"]
