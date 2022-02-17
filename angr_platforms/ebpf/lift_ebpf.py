from . import instrs_ebpf as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter


class LifterEbpf(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(
        lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]


register(LifterEbpf, 'eBPF')
