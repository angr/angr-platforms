from angr_platforms.X86_16.decompiler_postprocess_simplify import describe_x86_16_projection_cleanup_rules


def test_x86_16_projection_cleanup_rules_expose_low_level_cleanup_surface():
    assert describe_x86_16_projection_cleanup_rules() == (
        (
            "concat_fold",
            "Fold concatenations of constant halves into one constant and preserve the narrower shift width otherwise.",
        ),
        (
            "or_zero_elimination",
            "Eliminate redundant zero terms in Or expressions after the low-level expression facts are stable.",
        ),
        (
            "and_zero_collapse",
            "Collapse And expressions with a zero operand into typed zero constants.",
        ),
        (
            "double_not_collapse",
            "Remove redundant boolean negation pairs after boolean cite recovery.",
        ),
        (
            "zero_compare_projection",
            "Convert zero comparisons into the underlying projection or flag source when the evidence is explicit.",
        ),
        (
            "sub_self_zero",
            "Collapse self-subtractions into typed zero constants once the low-level operands are proven identical.",
        ),
    )
