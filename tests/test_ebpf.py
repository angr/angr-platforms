import logging
import os

import angr
from archinfo import Endness
from angr_platforms.ebpf import ArchEbpf, SimOsEbpf

logging.root.setLevel(logging.DEBUG)

TEST_PROGRAMS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'test_programs', 'ebpf')


def print_(s, indent=0):
    """
    printing function with indentation
    """
    print('\t' * indent + str(s))


def create_program(program_name):
    proj = angr.Project(os.path.join(TEST_PROGRAMS_BASE, program_name), arch=ArchEbpf(Endness.LE), simos=SimOsEbpf)
    state = proj.factory.entry_state()
    state.regs.R1 = 1
    simgr = proj.factory.simgr(state)  # type:angr.SimulationManager
    simgr.run()

    print(f'Result of running {program_name}')
    print(simgr)
    for state in simgr.deadended:
        print_(f'state {state} constraints:', indent=1)
        constraints = state.solver.constraints
        if len(constraints) > 0:
            for constraint in state.solver.constraints:
                print_(constraint, indent=2)
        else:
            print_('[]', indent=2)


test_programs_to_run = [
    'return_42.o',
    'return_42_long.o',
    'return_if.o',
    'dynamic_return.o'
]

for prog_name in test_programs_to_run:
    print(f"Running program {prog_name} :")
    create_program(prog_name)
