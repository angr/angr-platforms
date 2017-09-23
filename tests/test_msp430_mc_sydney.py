import logging
from action_pp import action_pp
logging.basicConfig()
l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)
linspect = logging.getLogger('angr.state_plugins.inspect')
linspect.setLevel(logging.ERROR)
logging.getLogger("claripy.backends.backend_z3").setLevel(logging.WARNING)
logging.getLogger("angr.engines.vex.expressions").setLevel(logging.WARNING)
logging.getLogger('pyvex.lift.util.lifter_helper').setLevel(logging.WARNING)
logging.getLogger('angr_platforms.msp430.instrs_msp430').setLevel(logging.WARNING)
from angr_platforms.msp430 import simos_msp430
from angr import options as o
import angr

p = angr.Project("../test_programs/msp430/microcorruption_sydney/out.elf", load_options={'rebase_granularity': 8})
p.hook_symbol('getsn', simos_msp430.MCgetsn())
p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
p.hook_symbol('puts', simos_msp430.MCputs())
state = p.factory.entry_state()
state.options.update(o.refs)
# state.posix.files[0].content.store(0, 'AAAAAAAA' + '\x00')
simgr = p.factory.simgr(state)
simgr.explore(find=0x4462)
stdin_contents = simgr.found[0].posix.dumps(0)
print 'Password (in hex):', stdin_contents.encode('hex')
