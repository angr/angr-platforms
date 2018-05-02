from clint.textui.colored import red, green, blue, yellow
from angr.state_plugins.sim_action import *
def action_pp(state):
    actions = state.actions.hardcopy
    for a in actions:
        if isinstance(a, SimActionExit):
            print(blue("[%#08x] ===> %s %s" % (a.ins_addr, a.exit_type, a.target)))
        elif isinstance(a, SimActionData):
            print("[%#08x] %s %s: %s" % (a.ins_addr, a.action, str(a.tmp), a.data))
        elif isinstance(a, SimActionOperation):
            print(red("[%#08x] %s %s" % (a.ins_addr, a.op, ", ".join([str(e) for e in a.exprs]))))
