from pathlib import Path

import angr
from angr_platforms.ebpf import ArchExtendedBPF

TEST_PROGRAMS_BASE = Path(__file__).parent.parent / "test_programs" / "ebpf"

def test_prog_always_returns_42(filename: str) -> None:
    proj = angr.Project(TEST_PROGRAMS_BASE / filename)
    assert isinstance(proj.arch, ArchExtendedBPF)

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    simgr.run()

    assert len(simgr.deadended) == 1
    assert state.solver.eval_exact(simgr.deadended[0].regs.R0, 1) == [42]


def test_trivial_return():
    test_prog_always_returns_42("return_42.o")


def test_branched_return():
    test_prog_always_returns_42("return_if.o")


def test_get_ns():
    test_prog_always_returns_42("get_ns.o")


if __name__ == "__main__":
    test_trivial_return()
    test_branched_return()
    test_get_ns()
