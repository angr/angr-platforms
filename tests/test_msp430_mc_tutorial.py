from angr_platforms.msp430 import simos_msp430
from angr import options as o
import angr

p = angr.Project("../test_programs/msp430/microcorruption_tutorial/out.elf", load_options={'rebase_granularity': 8})
p.hook_symbol('getsn', simos_msp430.MCgetsn())
p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
p.hook_symbol('puts', simos_msp430.MCputs())
state = p.factory.entry_state()
state.options.update(o.refs)
# state.posix.files[0].content.store(0, 'AAAAAAAA' + '\x00')
simgr = p.factory.simgr(state)
simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
stdin_contents = simgr.found[0].posix.dumps(0)
print 'Password (in hex):', stdin_contents.encode('hex')
