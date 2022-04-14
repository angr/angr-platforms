from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
import angr
import os

def test_hanoi():
    the_bin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              '../test_programs/msp430/microcorruption_hanoi/out.elf'))
    p = angr.Project(the_bin, load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simulation_manager()
    simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
    stdin_contents = simgr.found[0].posix.dumps(0)
    assert stdin_contents.hex() == '00000000000000000000000000000000960000000000000000000000'

if __name__ == '__main__':
    test_hanoi()
