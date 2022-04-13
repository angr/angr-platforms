
import os

import angr
from angr_platforms.bpf import *
from angr_platforms.bpf.lift_bpf import MAX_INSTR_ID

TEST_PROGRAMS_BASE = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'test_programs', 'bpf'))


def test_idea_correct_flag():

    idea_bpf = os.path.join(TEST_PROGRAMS_BASE, 'idea.bpf')
    proj = angr.Project(idea_bpf, main_opts={'backend': 'bpf'})

    assert proj.arch.name == 'BPF'

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # Initialize the state with the correct flag
    flag = "w0w_y0u_are_Master-0F-secc0mp///>_w_<///"
    # the syscall number must be 0x1337
    state.memory.store(proj.arch.DATA_BASE, 0x1337, endness='Iend_LE')
    # input variables
    for i in range(0, len(flag), 4):
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i, state.solver.BVV(ord(flag[i]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 1, state.solver.BVV(ord(flag[i+1]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 2, state.solver.BVV(ord(flag[i+2]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 3, state.solver.BVV(ord(flag[i+3]), 8))

    # Execute until it returns
    simgr.explore(find=(MAX_INSTR_ID * 8,))

    assert len(simgr.found) == 1
    assert simgr.found[0].history.addr == 4058 * 8  # executed until "ret ALLOW"
    assert simgr.found[0].regs._res._model_concrete.value == 1  # the result is ALLOW


def test_idea_incorrect_flag():

    idea_bpf = os.path.join(TEST_PROGRAMS_BASE, 'idea.bpf')
    proj = angr.Project(idea_bpf, main_opts={'backend': 'bpf'})

    assert proj.arch.name == 'BPF'

    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # Initialize the state with the incorrect flag
    flag = "w0w_y0u_are_Master-0F-secc0mp///>_w_<//\\"
    # the syscall number must be 0x1337
    state.memory.store(proj.arch.DATA_BASE, 0x1337, endness='Iend_LE')
    # input variables
    for i in range(0, len(flag), 4):
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i, state.solver.BVV(ord(flag[i]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 1, state.solver.BVV(ord(flag[i+1]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 2, state.solver.BVV(ord(flag[i+2]), 8))
        state.memory.store(proj.arch.DATA_BASE + 0x10 + i + 3, state.solver.BVV(ord(flag[i+3]), 8))

    # Execute until it returns
    simgr.explore(find=(MAX_INSTR_ID * 8,))

    assert len(simgr.found) == 1
    assert simgr.found[0].history.addr == 4045 * 8  # executed until "ret DENY"
    assert simgr.found[0].regs._res._model_concrete.value == 0  # the result is DENY


def main():
    test_idea_correct_flag()
    test_idea_incorrect_flag()


if __name__ == '__main__':
    main()

