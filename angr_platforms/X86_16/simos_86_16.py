from angr.calling_conventions import (
    SimCC,
    SimRegArg,
    SimStackArg,
    register_default_cc,
    register_syscall_cc,
)

from .arch_86_16 import Arch86_16


class SimDOSintcall(SimCC):
    ARG_REGS = ["ax", "bx", "cx", "dx"]  # TODO
    RETURN_VAL = SimRegArg("ax", 2)
    ARCH = Arch86_16

    @staticmethod
    def _match(arch, args: list, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        print("DOS int was called %s" % state.regs.ip_at_syscall)
        return state.regs.ax


class SimCC8616MSC(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


register_default_cc("86_16", SimCC8616MSC)
register_syscall_cc("86_16", "Linux", SimDOSintcall)
register_syscall_cc("86_16", "default", SimDOSintcall)
