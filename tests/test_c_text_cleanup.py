from __future__ import annotations

from inertia_decompiler.c_text_cleanup import normalize_unresolved_c_text


def test_normalize_unresolved_c_text_strips_register_fragments_and_placeholders() -> None:
    rendered = """
short PercolateUp(void)
{
    unsigned short vvar_35;
    int <0x1000[is_1]|Stack bp-0x6, 1 B>;

    vvar_35{r8|2b} = 1;
    *((short **)((ss << 4) + (unsigned int)(short *)((char *)&<0x1000[is_1]|Stack bp-0x6, 1 B> + 1))) = 0;
}
"""
    normalized = normalize_unresolved_c_text(rendered)
    assert "vvar_35{r8|2b}" not in normalized
    assert "<0x1000[is_1]|Stack bp-0x6, 1 B>" not in normalized
    assert "stack_bp_m6_b1" in normalized


def test_normalize_unresolved_c_text_dedupes_duplicate_local_decls() -> None:
    rendered = """
short f(void)
{
    unsigned short ir_10;
    char ir_10;  // 4221
    return ir_10;
}
"""
    normalized = normalize_unresolved_c_text(rendered)
    decl_lines = [line.strip() for line in normalized.splitlines() if "ir_10;" in line and "return" not in line]
    assert decl_lines == ["char ir_10;  // 4221"]
    assert "char ir_10;  // 4221" in normalized


def test_normalize_unresolved_c_text_strips_false_noreturn_comment() -> None:
    rendered = "sub_1234(); /* do not return */\nreturn;\n"
    normalized = normalize_unresolved_c_text(rendered)
    assert "do not return" not in normalized
    assert "sub_1234();" in normalized


def test_normalize_unresolved_c_text_strips_callee_namespace_prefixes() -> None:
    rendered = "ax = ::0x1e22::sprintf();\nSleep();\n"
    normalized = normalize_unresolved_c_text(rendered)
    assert "::0x1e22::" not in normalized
    assert "sprintf();" in normalized
