from typing import Dict, Optional

from pyvex.lifting.util.vex_helper import Type

from .dev_io import MemoryIO, PortIO
from .memory import Memory


class IO:
    def __init__(self, memory: Memory):
        self.memory = memory
        self.port_io: Dict[int, PortIO] = {}
        self.port_io_map: Dict[int, int] = {}
        self.mem_io: Dict[int, MemoryIO] = {}
        self.mem_io_map: Dict[int, int] = {}

    def __del__(self):
        self.port_io.clear()
        self.mem_io.clear()
        self.mem_io_map.clear()

    def set_portio(self, addr: int, length: int, dev: PortIO):
        addr &= ~1
        self.port_io[addr] = dev
        self.port_io_map[addr] = length

    def get_portio_base(self, addr: int) -> Optional[int]:
        for i in range(5):  # max_mask: 0xfff0
            base = (addr & ~1) - (2 * i)
            if base in self.port_io_map:
                return base if addr < base + self.port_io_map[base] else None
        return None

    def in_io32(self, addr: int) -> int:
        return self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_IN", [addr, self.constant(32)]).cast_to(Type.int_32)

    def in_io16(self, addr: int) -> int:
        return self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_IN", [addr, self.constant(16)]).cast_to(Type.int_16)

    def in_io8(self, addr: int) -> int:
        return self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_IN", [addr, self.constant(8)]).cast_to(Type.int_8)

    def out_io32(self, addr: int, value: int):
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [addr, value, self.constant(32)])

    def out_io16(self, addr: int, value: int):
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [addr, value, self.constant(16)])

    def out_io8(self, addr: int, value: int):
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [addr, value, self.constant(8)])

    def set_memio(self, base: int, length: int, dev: MemoryIO):
        assert base & ((1 << 12) - 1) == 0

        dev.set_mem(self.memory, base, length)
        self.mem_io[base] = dev

        for addr in range(base, base + length, 1 << 12):
            self.mem_io_map[addr] = base

    def get_memio_base(self, addr: int) -> Optional[int]:
        addr &= ~((1 << 12) - 1)
        return self.mem_io_map.get(addr)

    def read_memio32(self, base: int, offset: int) -> int:
        assert base in self.mem_io
        return self.mem_io[base].read32(offset)

    def read_memio16(self, base: int, offset: int) -> int:
        assert base in self.mem_io
        return self.mem_io[base].read16(offset)

    def read_memio8(self, base: int, offset: int) -> int:
        assert base in self.mem_io
        return self.mem_io[base].read8(offset)

    def write_memio32(self, base: int, offset: int, value: int):
        assert base in self.mem_io
        self.mem_io[base].write32(offset, value)

    def write_memio16(self, base: int, offset: int, value: int):
        assert base in self.mem_io
        self.mem_io[base].write16(offset, value)

    def write_memio8(self, base: int, offset: int, value: int):
        assert base in self.mem_io
        self.mem_io[base].write8(offset, value)

    def chk_memio(self, addr: int) -> Optional[int]:
        return self.get_memio_base(addr)
