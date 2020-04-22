from .arch_riscv import ArchRISCV
from . import instrs_riscv as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter


class LifterRISCV32(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterRISCV32, 'RISCV')
