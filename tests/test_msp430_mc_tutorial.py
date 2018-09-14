from angr_platforms.msp430 import *
import os
import angr
import nose


def test_tutorial():
    thebin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/msp430/microcorruption_tutorial/out.elf'))
    p = angr.Project(thebin, load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simulation_manager()
    simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
    stdin_contents = simgr.found[0].posix.dumps(0)
    nose.tools.assert_true('ffffffffffffffff00' in stdin_contents.hex())

if __name__ == '__main__':
    test_tutorial()
