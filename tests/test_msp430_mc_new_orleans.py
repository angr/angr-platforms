import logging
from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
import angr
import os


def test_new_orleans():
    thebin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              '../test_programs/msp430/microcorruption_new_orleans/out.elf'))
    p = angr.Project(thebin, load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simulation_manager()
    simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
    stdin_contents = simgr.found[0].posix.dumps(0)
    assert '7d493c6a51373f' in stdin_contents.hex()

if __name__ == '__main__':
    test_new_orleans()
