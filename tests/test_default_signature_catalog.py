from __future__ import annotations

from pathlib import Path

from inertia_decompiler import default_signature_catalog


def test_default_signature_catalog_reuses_existing_catalog_without_rescan(monkeypatch, tmp_path):
    default_signature_catalog.default_signature_catalog_path.cache_clear()
    repo_root = tmp_path / "repo"
    catalog_root = repo_root / "signature_catalogs"
    catalog_root.mkdir(parents=True)
    (catalog_root / "base.pat").write_text("---\n")

    build_calls: list[tuple[Path, ...]] = []

    def _fake_build_signature_catalog(roots, output_path, *, recursive, cache_dir):
        build_calls.append(tuple(Path(root) for root in roots))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("---\n")

    monkeypatch.setattr(default_signature_catalog, "build_signature_catalog", _fake_build_signature_catalog)

    first = default_signature_catalog.default_signature_catalog_path(repo_root)
    second = default_signature_catalog.default_signature_catalog_path(repo_root)
    (catalog_root / "user_added.pat").write_text("---\n")
    third = default_signature_catalog.default_signature_catalog_path(repo_root)

    assert first is not None
    assert second == first
    assert third == first
    assert len(build_calls) == 1
