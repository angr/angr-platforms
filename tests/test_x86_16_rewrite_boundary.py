from __future__ import annotations

"""Regression tests for pre-rewrite invariant gate.

AGENTS rule: rewrite must not hide bad alias/type/condition recovery.
If invariants fail, rewrite is blocked and honest partial output is emitted.
"""

import pytest
from angr_platforms.X86_16.pipeline.invariants import (
    InvariantStatus,
    InvariantCheck,
    InvariantReport,
    validate_before_rewrite_8616,
    format_invariant_report_8616,
)


class TestInvariantStatusEnum:
    """InvariantStatus must have PASSED, FAILED, SKIPPED, UNCERTAIN states."""

    def test_all_states_exist(self):
        assert InvariantStatus.PASSED.value == "passed"
        assert InvariantStatus.FAILED.value == "failed"
        assert InvariantStatus.SKIPPED.value == "skipped"
        assert InvariantStatus.UNCERTAIN.value == "uncertain"

    def test_failed_is_blocking(self):
        check = InvariantCheck(name="test", status=InvariantStatus.FAILED)
        assert check.is_blocking

    def test_passed_is_not_blocking(self):
        check = InvariantCheck(name="test", status=InvariantStatus.PASSED)
        assert not check.is_blocking

    def test_uncertain_is_not_blocking(self):
        check = InvariantCheck(name="test", status=InvariantStatus.UNCERTAIN)
        assert not check.is_blocking


class TestInvariantReport:
    """InvariantReport must aggregate checks and decide rewrite blocking."""

    def test_empty_report_all_passed(self):
        report = InvariantReport()
        assert report.all_passed
        assert not report.rewrite_blocked

    def test_single_failure_blocks_rewrite(self):
        report = InvariantReport()
        report.checks.append(
            InvariantCheck(name="no_ss_linear_expr", status=InvariantStatus.FAILED,
                          detail="found linear SS expression")
        )
        report.rewrite_blocked = True
        report.skip_reason = "1 invariant(s) failed"
        assert not report.all_passed
        assert report.rewrite_blocked
        assert len(report.failed_checks) == 1

    def test_uncertain_does_not_block(self):
        report = InvariantReport()
        report.checks.append(
            InvariantCheck(name="no_tmp_conditions", status=InvariantStatus.UNCERTAIN)
        )
        assert report.all_passed
        assert not report.rewrite_blocked

    def test_serialization(self):
        report = InvariantReport(function_addr=0x100, function_name="test_func")
        report.checks.append(
            InvariantCheck(name="no_stack_indexing", status=InvariantStatus.PASSED)
        )
        d = report.to_dict()
        assert d["function_addr"] == 0x100
        assert d["function_name"] == "test_func"
        assert len(d["checks"]) == 1
        assert d["checks"][0]["status"] == "passed"


class TestValidateBeforeRewrite:
    """validate_before_rewrite_8616 must detect bad patterns in C text."""

    def _make_mock_codegen(self, **kwargs):
        """Create a minimal mock codegen object."""
        return type("MockCodegen", (), kwargs)()

    def test_detects_ss_linear_expr(self):
        c_text = """
        void test() {
            unsigned short v1 = ((ss << 4) + 0xfffc);
            v1 = v1 + 1;
        }
        """
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x100, "name": "test_func"})(),
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        assert report.rewrite_blocked, "SS linear expr should block rewrite"
        no_ss_checks = [c for c in report.checks if c.name == "no_ss_linear_expr"]
        assert len(no_ss_checks) == 1
        assert no_ss_checks[0].status == InvariantStatus.FAILED

    def test_detects_stack_indexing(self):
        c_text = 'unsigned short v1 = stack[0xfffc];'
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x200, "name": "test_func"})(),
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        stack_checks = [c for c in report.checks if c.name == "no_stack_indexing"]
        assert len(stack_checks) == 1
        assert stack_checks[0].status == InvariantStatus.FAILED

    def test_detects_flags_in_condition(self):
        c_text = "if ((flags & 0x40) != 0) { v1 = 1; }"
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x300, "name": "test_func"})(),
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        flag_checks = [c for c in report.checks if c.name == "no_raw_flag_conditions"]
        assert len(flag_checks) == 1
        assert flag_checks[0].status == InvariantStatus.FAILED

    def test_detects_tmp_conditions_with_typed_available(self):
        c_text = "if (tmp_14 != 0) { v1 = 1; }"
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x400, "name": "test_func"})(),
            _inertia_typed_conditions=[{"op": "eq", "args": ["ax", "bx"]}],
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        tmp_checks = [c for c in report.checks if c.name == "no_tmp_conditions"]
        assert len(tmp_checks) == 1
        assert tmp_checks[0].status == InvariantStatus.FAILED

    def test_tmp_without_typed_is_uncertain_not_blocking(self):
        c_text = "if (tmp_14 != 0) { v1 = 1; }"
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x500, "name": "test_func"})(),
            # No _inertia_typed_conditions
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        tmp_checks = [c for c in report.checks if c.name == "no_tmp_conditions"]
        assert len(tmp_checks) == 1
        assert tmp_checks[0].status == InvariantStatus.UNCERTAIN
        # UNCERTAIN should NOT block rewrite unless other failures exist
        if not report.rewrite_blocked:
            pass  # expected
        else:
            # If blocked, it must be from another check, not from tmp
            blocking = [c for c in report.failed_checks if c.name != "no_tmp_conditions"]
            assert len(blocking) > 0, "UNCERTAIN tmp should not be the sole blocking reason"

    def test_clean_code_passes_all(self):
        c_text = """
        void test_func(short arg_4) {
            short local_2;
            local_2 = arg_4 + 1;
            if (local_2 == 0) {
                local_2 = 1;
            }
        }
        """
        codegen = self._make_mock_codegen(
            cfunc=type("MockFunc", (), {"addr": 0x600, "name": "test_func"})(),
            _inertia_validation_passed=True,
            _inertia_semantic_alias_facts=[],
        )
        report = validate_before_rewrite_8616(codegen, c_text=c_text)
        # Clean code should pass, or at most be UNCERTAIN for stack slots
        failed = [c for c in report.checks if c.is_blocking]
        # The only potential failure is stack_slots_materialized (which may be SKIPPED)
        stack_fails = [c for c in failed if c.name == "stack_slots_materialized"]
        assert len(failed) == len(stack_fails), f"Unexpected failures: {failed}"


class TestFormatInvariantReport:
    """Invariant report formatting must be readable."""

    def test_format_passed_report(self):
        report = InvariantReport(function_addr=0x100, function_name="test")
        report.checks.append(
            InvariantCheck(name="no_ss_linear_expr", status=InvariantStatus.PASSED)
        )
        report.checks.append(
            InvariantCheck(name="no_stack_indexing", status=InvariantStatus.PASSED)
        )
        text = format_invariant_report_8616(report)
        assert "All invariants passed" in text
        assert "test" in text

    def test_format_blocked_report(self):
        report = InvariantReport(function_addr=0x100, function_name="test")
        report.checks.append(
            InvariantCheck(name="no_ss_linear_expr", status=InvariantStatus.FAILED,
                          detail="found 2 linear SS expressions")
        )
        report.rewrite_blocked = True
        report.skip_reason = "1 invariant(s) failed: no_ss_linear_expr"
        text = format_invariant_report_8616(report)
        assert "REWRITE BLOCKED" in text
        assert "no_ss_linear_expr" in text