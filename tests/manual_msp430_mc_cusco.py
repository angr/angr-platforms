import logging
logging.basicConfig()
l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)
linspect = logging.getLogger('angr.state_plugins.inspect')
linspect.setLevel(logging.ERROR)
logging.getLogger("claripy.backends.backend_z3").setLevel(logging.WARNING)
logging.getLogger("angr.engines.vex.expressions").setLevel(logging.WARNING)
logging.getLogger('pyvex.lifting.util.lifter_helper').setLevel(logging.WARNING)
logging.getLogger('angr_platforms.msp430.instrs_msp430').setLevel(logging.WARNING)
from angr_platforms.msp430 import *
from angr import options as o
import angr

p = angr.Project("../test_programs/msp430/microcorruption_cusco/out.elf", load_options={'rebase_granularity': 8})
p.hook_symbol('getsn', simos_msp430.MCgetsn())
p.hook_symbol('__stop_progExec__', simos_msp430.MCstopexec())
p.hook_symbol('puts', simos_msp430.MCputs())
state = p.factory.entry_state()
state.options.update(o.refs)
simgr = p.factory.simulation_manager(state)
simgr.explore(find=p.loader.find_symbol('unlock_door').rebased_addr)
print 'That last log message means we have ip control :)'
