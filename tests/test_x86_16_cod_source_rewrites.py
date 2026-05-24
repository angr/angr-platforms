from __future__ import annotations

from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_source_rewrites import (
    COD_SOURCE_REWRITE_REGISTRY,
    COD_SOURCE_REWRITE_SPECS,
    COD_SOURCE_REWRITE_SPECS_BY_NAME,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
)


def test_cod_source_rewrite_registry_is_keyed_and_unique():
    names = [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert names == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert names == []


def test_cod_source_rewrite_registry_lookup_matches_spec_objects():
    for spec in COD_SOURCE_REWRITE_SPECS:
        assert get_cod_source_rewrite_spec(spec.name) is spec


def test_cod_source_rewrite_registry_exposes_name_order():
    assert COD_SOURCE_REWRITE_REGISTRY.names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_summary_matches_registry_contents():
    summary = cod_source_rewrite_summary()
    assert summary["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert summary["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert summary["status_counts"] == {}
    assert summary["active_count"] == 0
    assert summary["oracle_count"] == 0
    assert summary["subsumed_count"] == 0


def test_cod_source_rewrite_description_matches_registry_contents():
    description = cod_source_rewrite_description()
    assert description["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert description["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert description["specs"] == ()
    assert all("rewrite_status" in item for item in description["specs"])


def test_cod_source_rewrite_status_matches_registry_contents():
    status = describe_x86_16_source_backed_rewrite_status()

    assert status["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert status["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert status["specs"] == ()
    assert status["status_counts"] == {}
    assert status["active_count"] == 0
    assert status["oracle_count"] == 0
    assert status["subsumed_count"] == 0


def test_cod_source_rewrite_debt_matches_registry_contents():
    debt = describe_x86_16_source_backed_rewrite_debt()

    assert debt["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert debt["active_count"] == 0
    assert debt["oracle_count"] == 0
    assert debt["subsumed_count"] == 0
    assert debt["status_counts"] == {}
    assert debt["active_names"] == ()
    assert debt["oracle_names"] == ()
    assert debt["subsumed_names"] == ()


def test_cod_source_rewrite_names_matches_registry_contents():
    assert cod_source_rewrite_names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_registry_behaves_like_a_container():
    assert len(COD_SOURCE_REWRITE_REGISTRY) == len(COD_SOURCE_REWRITE_SPECS)
    assert [spec.name for spec in COD_SOURCE_REWRITE_REGISTRY] == [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert list(COD_SOURCE_REWRITE_REGISTRY) == []
    assert "missing" not in COD_SOURCE_REWRITE_REGISTRY


def test_cod_source_rewrite_registry_supports_mapping_access():
    assert list(COD_SOURCE_REWRITE_REGISTRY.keys()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert list(COD_SOURCE_REWRITE_REGISTRY.values()) == list(COD_SOURCE_REWRITE_SPECS)
    assert list(COD_SOURCE_REWRITE_REGISTRY.items()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME.items())


def test_cod_source_rewrite_registry_lookup_is_read_only():
    sample = next(iter(COD_SOURCE_REWRITE_SPECS_BY_NAME.values()), None)
    try:
        COD_SOURCE_REWRITE_REGISTRY.by_name["missing"] = sample  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("registry lookup map should be read-only")


def test_cod_source_rewrite_spec_lookup_map_is_read_only():
    sample = next(iter(COD_SOURCE_REWRITE_SPECS_BY_NAME.values()), None)
    try:
        COD_SOURCE_REWRITE_SPECS_BY_NAME["missing"] = sample  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("spec lookup map should be read-only")


def test_apply_cod_source_rewrites_rebuilds_collapsed_straight_line_body_from_source():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("printf",),
        call_sources=(("printf", 'printf ("a = %d, b = %d\\n", a, b)'),),
        global_names=(),
        source_lines=(
            "#define TYPE unsigned char",
            "main()",
            "{ TYPE a, b;",
            "a = 255;",
            "b = 143;",
            "b = a + b;",
            "a = a - b;",
            'printf ("a = %d, b = %d\\n", a, b);',
            "}",
        ),
        source_line_set=frozenset(
            {
                "#define TYPE unsigned char",
                "main()",
                "{ TYPE a, b;",
                "a = 255;",
                "b = 143;",
                "b = a + b;",
                "a = a - b;",
                'printf ("a = %d, b = %d\\n", a, b);',
                "}",
            }
        ),
    )
    collapsed = """void _start(void)
{
    printf ("a = %d, b = %d
", a, b);
}"""

    rewritten = apply_cod_source_rewrites(collapsed, metadata)

    assert "char a;" in rewritten
    assert "char b;" in rewritten
    assert "a = 255;" in rewritten
    assert "b = 143;" in rewritten
    assert "b = a + b;" in rewritten
    assert "a = a - b;" in rewritten
    assert 'printf ("a = %d, b = %d\\n", a, b);' in rewritten


def test_apply_cod_source_rewrites_repairs_split_source_backed_call_lines_in_live_body():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("printf",),
        call_sources=(("printf", 'printf ("a = %d, b = %d\\n", a, b)'),),
        global_names=(),
        source_lines=(
            "main()",
            "{",
            "a = a - b;",
            'printf ("a = %d, b = %d\\n", a, b);',
            "}",
        ),
        source_line_set=frozenset(
            {
                "main()",
                "{",
                "a = a - b;",
                'printf ("a = %d, b = %d\\n", a, b);',
                "}",
            }
        ),
    )
    live_body = """void _main(void)
{
    a = a - b;
    printf ("a = %d, b = %d
", a, b);
}"""

    rewritten = apply_cod_source_rewrites(live_body, metadata)

    assert 'printf ("a = %d, b = %d\\n", a, b);' in rewritten
    assert 'printf ("a = %d, b = %d\n' not in rewritten


def test_apply_cod_source_rewrites_keeps_multi_statement_live_body_while_repairing_split_calls():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("printf",),
        call_sources=(("printf", 'printf ("a = %d, b = %d\\n", a, b)'),),
        global_names=(),
        source_lines=(
            "main()",
            "{",
            "a = 255;",
            "b = 143;",
            "b = a + b;",
            "a = a - b;",
            "a = a * b;",
            'printf ("a = %d, b = %d\\n", a, b);',
            "}",
        ),
        source_line_set=frozenset(
            {
                "main()",
                "{",
                "a = 255;",
                "b = 143;",
                "b = a + b;",
                "a = a - b;",
                "a = a * b;",
                'printf ("a = %d, b = %d\\n", a, b);',
                "}",
            }
        ),
    )
    live_body = """void _main(void)
{
    a = a - b;
    a = a * b;
    printf ("a = %d, b = %d
", a, b);
}"""

    rewritten = apply_cod_source_rewrites(live_body, metadata)

    assert "a = 255;" not in rewritten
    assert "b = 143;" not in rewritten
    assert "b = a + b;" not in rewritten
    assert "a = a - b;" in rewritten
    assert "a = a * b;" in rewritten
    assert 'printf ("a = %d, b = %d\\n", a, b);' in rewritten
    assert 'printf ("a = %d, b = %d\n' not in rewritten


def test_apply_cod_source_rewrites_ignores_prelude_globals_when_rebuilding_function_body():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("intdos",),
        call_sources=(),
        global_names=("exeLoadParams", "rin", "rout"),
        source_lines=(
            "#define DOS_LOAD_NOEXEC 1",
            "struct ExeLoadParams {",
            "unsigned short cs;",
            "unsigned short ss;",
            "} exeLoadParams;",
            "static int loadprog(const char *file, unsigned short segment, unsigned short type, const char *cmdline) {",
            "int err;",
            "rin.x.dx = (unsigned int)file;",
            "err = intdos(&rin, &rout);",
            "if (rout.x.cflag != 0) {",
            "return err;",
            "}",
            "return 0;",
            "}",
        ),
        source_line_set=frozenset(
            {
                "#define DOS_LOAD_NOEXEC 1",
                "struct ExeLoadParams {",
                "unsigned short cs;",
                "unsigned short ss;",
                "} exeLoadParams;",
                "static int loadprog(const char *file, unsigned short segment, unsigned short type, const char *cmdline) {",
                "int err;",
                "rin.x.dx = (unsigned int)file;",
                "err = intdos(&rin, &rout);",
                "if (rout.x.cflag != 0) {",
                "return err;",
                "}",
                "return 0;",
            }
        ),
    )
    collapsed = """int loadprog(const char *file, unsigned short segment, unsigned short mode, const char *cmdline)
{
    return DOSERR_INVFUNC;
}"""

    rewritten = apply_cod_source_rewrites(collapsed, metadata)

    assert "int err;" in rewritten
    assert "rin.x.dx = (unsigned int)file;" in rewritten
    assert "err = intdos(&rin, &rout);" in rewritten
    assert "} exeLoadParams;" not in rewritten
    assert "unsigned short cs;" not in rewritten


def test_apply_cod_source_rewrites_skips_complex_switch_bodies():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("DEBUG", "INFO"),
        call_sources=(),
        global_names=(),
        source_lines=(
            "static int loadprog(unsigned short mode) {",
            "switch (mode) {",
            "case 0:",
            "DEBUG(\"exec\");",
            "break;",
            "default:",
            "INFO(\"other\");",
            "break;",
            "}",
            "return 0;",
            "}",
        ),
        source_line_set=frozenset(
            {
                "static int loadprog(unsigned short mode) {",
                "switch (mode) {",
                "case 0:",
                'DEBUG("exec");',
                "break;",
                "default:",
                'INFO("other");',
                "}",
                "return 0;",
            }
        ),
    )
    collapsed = """int loadprog(unsigned short mode)
{
    return 1;
}"""

    rewritten = apply_cod_source_rewrites(collapsed, metadata)

    assert rewritten == collapsed


def test_apply_cod_source_rewrites_preserves_multistatement_live_bodies_while_repairing_split_lines():
    """Multi-statement live bodies should NOT be rebuilt—only split lines repaired."""
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("printf",),
        call_sources=(("printf", 'printf ("a = %d, b = %d\\n", a, b)'),),
        global_names=(),
        source_lines=(
            "main()",
            "{ char a, b;",
            "a = 255;",
            "b = 143;",
            "b = a + b;",
            "a = a - b;",
            'printf ("a = %d, b = %d\\n", a, b);',
            "}",
        ),
        source_line_set=frozenset(
            {
                "main()",
                "{ char a, b;",
                "a = 255;",
                "b = 143;",
                "b = a + b;",
                "a = a - b;",
                'printf ("a = %d, b = %d\\n", a, b);',
                "}",
            }
        ),
    )
    # Live body has 5 statements (good recovery) but split printf
    live_body = """void _main(void)
{
    a = 255;
    b = 143;
    b = a + b;
    a = a - b;
    printf ("a = %d, b = %d
", a, b);
}"""

    rewritten = apply_cod_source_rewrites(live_body, metadata)

    # Should keep the 5 live statements
    assert "a = 255;" in rewritten
    assert "b = 143;" in rewritten
    assert "b = a + b;" in rewritten
    assert "a = a - b;" in rewritten

    # Should repair the split printf
    assert 'printf ("a = %d, b = %d\\n", a, b);' in rewritten
    assert 'printf ("a = %d, b = %d\n' not in rewritten
