import logging
from action_pp import action_pp
logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.DEBUG)
linspect = logging.getLogger('angr.state_plugins.inspect')
linspect.setLevel(logging.ERROR)
logging.getLogger("claripy.backends.backend_z3").setLevel(logging.ERROR)
from angr_platforms.msp430 import simos_msp430
from angr import options as o
import angr

p = angr.Project("../test_programs/msp430/microcorruption_tutorial/tutorial.elf", load_options={'rebase_granularity': 8})
p.hook_symbol('getsn', simos_msp430.MCgetsn())
p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
state = p.factory.entry_state()
state.options.update(o.refs)
state.options.add(o.TRACK_ACTION_HISTORY)
state.options.add(o.TRACK_OP_ACTIONS)
for _ in xrange(8):
    k = state.posix.files[0].read_from(1)
    state.se.add(k == 0x41)
k = state.posix.files[0].read_from(1)
state.se.add(k == 0)
state.posix.files[0].seek(0)

# p.entry = 0x
simgr = p.factory.simgr(state)
#simgr.explore()

