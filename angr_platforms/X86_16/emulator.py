from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type

from .interrupt import Interrupt
from .processor import Processor
from .stack_helpers import pop16 as stack_pop16
from .stack_helpers import push16 as stack_push16


class Emulator(Interrupt):
    def __init__(self, arch, lifter=None):
        Processor.__init__(self)
        Interrupt.__init__(self)
        self.arch = arch
        self.lifter = lifter
        self.irsb = lifter.irsb if lifter else None
        self.vex_offsets = {r.name.lower(): r.vex_offset for r in arch.register_list if hasattr(r, 'vex_offset')}
        self.regs = {}

    def chk_ring(self, dpl: int) -> bool:
        # The current x86-16 lifter only models real-mode execution, where ring checks
        # should not block instructions like HLT inside the verification harness.
        return True

    def _vv(self, value, ty=None):
        if isinstance(value, VexValue):
            return value
        if isinstance(value, int):
            if ty is None:
                raise ValueError("type is required to wrap an integer into a VEX value")
            return self.constant(value, ty)
        if self.lifter_instruction is None:
            raise ValueError("cannot wrap a non-constant VEX expression without an active lifter instruction")
        return VexValue(self.lifter_instruction, self.lifter_instruction._settmp(value))

    def push16(self, val):
        if isinstance(val, VexValue) and self.lifter_instruction is not None:
            # Snapshot register-backed values like PUSH SP before we mutate SP itself.
            val = self._vv(val.rdt)
        if isinstance(val, int):
            val = self.constant(val, Type.int_16)
        stack_push16(self, val)

    def pop16(self):
        return stack_pop16(self)

    def get_data16(self, seg, addr):
        return self.read_mem16_seg(seg, addr)

    def put_data16(self, seg, addr, val):
        self.write_mem16_seg(seg, addr, val)
