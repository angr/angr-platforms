from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
import os
import angr


def test_tutorial():
    thebin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/msp430/microcorruption_tutorial/out.elf'))
    p = angr.Project(thebin, load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simulation_manager(save_unconstrained=True)
    simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
    stdin_contents = simgr.found[0].posix.dumps(0)
    assert b'\0' not in stdin_contents[:8]
    assert stdin_contents[8] == 0

if __name__ == '__main__':
    test_tutorial()
