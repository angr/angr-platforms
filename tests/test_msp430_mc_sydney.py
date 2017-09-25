from angr_platforms.msp430 import *
import angr

def test_sydney():
    p = angr.Project("../test_programs/msp430/microcorruption_sydney/out.elf", load_options={'rebase_granularity': 8})
    p.hook_symbol('getsn', simos_msp430.MCgetsn())
    p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
    p.hook_symbol('puts', simos_msp430.MCputs())
    simgr = p.factory.simgr()
    simgr.explore(find=0x4462)
    stdin_contents = simgr.found[0].posix.dumps(0)
    print 'Password (in hex):', stdin_contents.encode('hex')

if __name__ == '__main__':
    test_sydney()