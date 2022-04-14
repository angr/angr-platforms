from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
import angr
import os

def test_sydney():
    thebin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              '../test_programs/msp430/microcorruption_sydney/out.elf'))
    p = angr.Project(thebin, load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simulation_manager()
    simgr.explore(find=0x4462)
    stdin_contents = simgr.found[0].posix.dumps(0)
    assert '47544e6b7b5f443a00' in stdin_contents.hex()

if __name__ == '__main__':
    test_sydney()
