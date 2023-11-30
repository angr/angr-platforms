import unittest
from pathlib import Path

import angr
from angr_platforms.ebpf import ArchExtendedBPF, LifterEbpf


TEST_PROGRAMS_BASE = Path(__file__).parent.parent / "test_programs" / "ebpf"


def test_prog_always_returns_42(filename: str) -> None:
    proj = angr.Project(TEST_PROGRAMS_BASE / filename)
    assert isinstance(proj.arch, ArchExtendedBPF)

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    simgr.run()

    assert len(simgr.deadended) == 1
    assert state.solver.eval_exact(simgr.deadended[0].regs.R0, 1) == [42]


class TestEbpf(unittest.TestCase):
    # pylint:disable=missing-class-docstring,no-self-use
    def test_trivial_return(self):
        test_prog_always_returns_42("return_42.o")

    def test_branched_return(self):
        test_prog_always_returns_42("return_if.o")

    def test_get_ns(self):
        test_prog_always_returns_42("get_ns.o")

    def test_ebpf_lift(self):
        proj = angr.Project(TEST_PROGRAMS_BASE / "return_42.o")
        state = proj.factory.entry_state()
        block = proj.factory.block(state.addr)
        lifter = LifterEbpf(proj.arch, block.addr)
        lifter.lift(block.bytes)
        assert len(lifter.disassemble()) == 2


if __name__ == "__main__":
    unittest.main()
