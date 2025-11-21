from angr.calling_conventions import SimStackArg, SimComboArg, SimRegArg, SimCC, register_default_cc


class SimCCAVR(SimCC):
    """
    The AVR calling convention.
    """

    ARG_REGS = []  # ???
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimComboArg([SimRegArg("R22", 1), SimRegArg("R23", 1), SimRegArg("R24", 1), SimRegArg("R25", 1)])
    CALLER_SAVED_REGS = ["R18", "R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27", "R30", "R31"]


register_default_cc("AVR", SimCCAVR)