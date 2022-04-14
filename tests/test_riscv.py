import os

import angr
from angr_platforms.risc_v import *


def test_schoolbook_multiplication():
    #binary from the NaCl implementation in risc_v
    the_bin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/risc_v/program.elf'))

    proj = angr.Project(the_bin)

    targetAddress = 0x200142c8
    end = 0x200146cc

    startState = proj.factory.call_state(targetAddress)

    A = startState.solver.BVS("A",32)
    B = startState.solver.BVS("B",32)
    startState.memory.store(startState.regs.a0, A)
    startState.memory.store(startState.regs.a1, B)

    simgr = proj.factory.simulation_manager(startState)

    simgr.explore(find=(end,))

    assert len(simgr.found) == 1


def main():
    test_schoolbook_multiplication()


if __name__ == '__main__':
    main()
