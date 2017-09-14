import pyvex
from arch_msp430 import ArchMSP430
import instrs_msp430 as instrs
from pyvex.lift import register
from pyvex.lift.util import *


class LifterMSP430(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterMSP430)


if __name__ == '__main__':
    import logging
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    arch = ArchMSP430()
    irsb = pyvex.IRSB('\x0f\x43', 0, arch)
    #l = LifterMSP430(irsb, '\x0f\x43', 1, 1, 0)
    #irsb = l.lift()
    print irsb.statements
    irsb.pp()
