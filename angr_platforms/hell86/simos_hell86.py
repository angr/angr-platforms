from angr.simos import SimOS, register_simos
from angr.calling_conventions import SimStackArg, SimRegArg, SimCC, register_default_cc
from .arch_hell86 import ArchHell86

class SimCCMSP430(SimCC):
    STACKARG_SP_DIFF = 8
    ARCH =ArchHell86

class SimHell86(SimOS):
    SYSCALL_TABLE = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, name='hell86', **kwargs)

    def configure_project(self):
        super().configure_project()

    def state_blank(self, *args, **kwargs):
        return super().state_blank(*args, **kwargs)

    def state_entry(self, *args, **kwargs):
        return super().state_entry(*args, **kwargs)

register_simos('hell86', SimHell86)
register_default_cc('hell86', SimCCMSP430)
