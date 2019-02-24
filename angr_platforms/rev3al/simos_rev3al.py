from angr.simos import SimOS, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_default_cc
from .arch_rev3al import ArchRev3al

class SimCCMSP430(SimCC):
    STACKARG_SP_DIFF = 8
    ARCH = ArchRev3al

class SimRev3al(SimOS):
    SYSCALL_TABLE = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, name='hell86', **kwargs)

    def configure_project(self):
        super().configure_project()

    def state_blank(self, *args, **kwargs):
        state = super().state_blank(*args, **kwargs)
        state.regs.mode = 0
        state.regs.r0 = 0
        state.regs.r1 = 0
        state.regs.r2 = 0
        state.globals['thingything'] = False
        return state

    def state_entry(self, *args, **kwargs):
        state = super().state_entry(*args, **kwargs)
        return state


register_simos('rev3al', SimRev3al)
register_default_cc('rev3al', SimCCMSP430)