from .arch_msp430 import ArchMSP430
from . import instrs_msp430 as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter


class LifterMSP430(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterMSP430, 'MSP430')
