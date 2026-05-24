from __future__ import annotations

from pathlib import Path

from angr_platforms.X86_16.flair_extract import list_flair_sig_libraries, match_flair_startup_entry
from inertia_decompiler.default_signature_catalog import default_signature_catalog_path
from omf_pat import parse_pat_file
from signature_catalog import match_signature_catalog


def test_signature_matching_policy_disables_flair_and_catalog(monkeypatch, tmp_path):
    monkeypatch.setenv("INERTIA_DISABLE_SIGNATURES", "1")

    catalog = tmp_path / "demo.pat"
    catalog.write_text("---\n")

    result = match_signature_catalog(catalog, tmp_path / "demo.exe", object())

    assert match_flair_startup_entry(b"\x90" * 32, tmp_path) == ()
    assert list_flair_sig_libraries(tmp_path) == ()
    assert default_signature_catalog_path(tmp_path) is None
    assert parse_pat_file(catalog) == ()
    assert result.code_labels == {}
    assert result.code_ranges == {}
    assert result.source_formats == ()
    assert result.matched_compiler_names == ()
