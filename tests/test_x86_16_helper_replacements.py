from __future__ import annotations

from types import SimpleNamespace

import decompile


def test_int21_call_replacements_render_each_recovered_call(monkeypatch) -> None:
    calls = [SimpleNamespace(kind="a"), SimpleNamespace(kind="b")]
    monkeypatch.setattr(decompile, "collect_dos_int21_calls", lambda _function, _binary_path=None: calls)
    monkeypatch.setattr(decompile, "render_dos_int21_call", lambda call, style: f"{style}:{call.kind}")

    replacements = decompile._int21_call_replacements(SimpleNamespace(), SimpleNamespace(), "modern", None)

    assert replacements == ["modern:a", "modern:b"]


def test_known_helper_declarations_dedupes_and_skips_unknown() -> None:
    cod_metadata = SimpleNamespace(call_names=["foo", "bar", "foo", "baz"])
    original = decompile.preferred_known_helper_signature_decl
    try:
        decompile.preferred_known_helper_signature_decl = lambda name: {
            "foo": "int foo(void);",
            "bar": None,
            "baz": "void baz(int x);",
        }.get(name)
        declarations = decompile._known_helper_declarations(cod_metadata)
    finally:
        decompile.preferred_known_helper_signature_decl = original

    assert declarations == ["int foo(void);", "void baz(int x);"]
