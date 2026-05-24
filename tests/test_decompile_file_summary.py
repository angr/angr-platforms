from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.decompile_file_summary import emit_file_decompilation_summary


def test_emit_file_decompilation_summary_reports_compilers_and_signature_sources(capsys) -> None:
    project = SimpleNamespace(
        _inertia_signature_compiler_names=("IDA FLAIR", "v", "Microsoft C v5", "Microsoft C v6ax"),
        _inertia_flair_sig_titles=("Turbo Pascal V5.0/5.5/6.0/7.0",),
        _inertia_flair_local_pat_sources=("/tmp/microsoft_c_reimported.pat",),
        _inertia_peer_exe_titles=("SORTDEMO.EXE",),
    )
    metadata = SimpleNamespace(signature_code_addrs=frozenset({0x1000, 0x1010}))

    emit_file_decompilation_summary(
        project,
        metadata,
        shown_total=8,
        decompiled=5,
        failed=3,
        skipped_signature_labels=60,
        same_family_retry_stops=1,
        fallback_family_labels=("structurer_retry",),
        dead_setup_candidates=9,
        dead_setup_pruned=7,
        dead_setup_refused=2,
        dead_setup_escaped=0,
    )

    out = capsys.readouterr().out
    assert "summary: probable compiler versions: Microsoft C v5, Microsoft C v6ax" in out
    assert "summary: probable library/signature sources:" in out
    assert "microsoft_c_reimported" in out
    assert "SORTDEMO" in out
    assert "summary: signature-matched library functions: 2" in out
    assert "summary: hidden signature-matched labels: 60" in out
    assert "summary: same_family_retry_stops=1 fallback_family_labels=structurer_retry" in out
    assert "summary: dead_setup_candidates=9 dead_setup_pruned=7 dead_setup_refused=2 dead_setup_escaped=0" in out
    assert "summary: shown=8 decompiled=5 asm_or_detail_fallback=3" in out
