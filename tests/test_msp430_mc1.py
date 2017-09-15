import logging
from action_pp import action_pp
logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.DEBUG)
linspect = logging.getLogger('angr.state_plugins.inspect')
linspect.setLevel(logging.ERROR)
logging.getLogger("claripy.backends.backend_z3").setLevel(logging.ERROR)
from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
from angr import options as o
import angr

p = angr.Project("tutorial.elf", main_opts={'custom_base_addr':0x10}, load_options={'rebase_granularity': 8})
p.hook(0x10a, simos_msp430.MCgetsn())
p.hook(0x7e, simos_msp430.MCstopexec())
state = p.factory.entry_state()
state.ip = 0x12
state.options.update(o.refs)
state.options.add(o.TRACK_ACTION_HISTORY)
state.options.add(o.TRACK_OP_ACTIONS)
for _ in xrange(8):         
    k = state.posix.files[0].read_from(1)
    state.se.add(k == 0x41)
k = state.posix.files[0].read_from(1)
state.se.add(k == 0)
state.posix.files[0].seek(0)

p.entry = 0x12
simgr = p.factory.simgr(state)
#simgr.explore()

