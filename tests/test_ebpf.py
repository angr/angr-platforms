import logging
import os

import angr
from archinfo import Endness
from angr_platforms.ebpf import ArchEbpf, SimOsEbpf

logging.root.setLevel(logging.WARNING)

TEST_PROGRAMS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'test_programs', 'ebpf')


def create_program(program_name):
    proj = angr.Project(os.path.join(TEST_PROGRAMS_BASE, program_name), arch=ArchEbpf(Endness.LE), simos=SimOsEbpf)
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)

    r = simgr.run()
    print('running result: ', r)


test_programs_to_run = [
    'return_42.o',
    'return_42_long.o',
    'return_if.o'
]

for prog_name in test_programs_to_run:
    print(f"Running program {prog_name} :")
    create_program(prog_name)
