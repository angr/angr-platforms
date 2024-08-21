from typing import Optional

from bitstring import ConstBitStream
from pyvex.lifting.util.vex_helper import Type

DEFAULT_MEMORY_SIZE = 1024  # 1 KB

class Memory:
    def __init__(self, size: int = DEFAULT_MEMORY_SIZE):
        self.mem_size = size
        self.memory = bytearray(size)
        self.a20gate = False

    def __del__(self):
        del self.memory
        self.mem_size = 0

    def dump_mem(self, addr: int, size: int):
        addr &= ~(0x10 - 1)

        for i in range(0, size, 0x10):
            print(f"0x{addr + i:08x}: ", end="")
            for j in range(4):
                print(
                    f"{int.from_bytes(self.memory[addr + i + j * 4:addr + i + (j + 1) * 4], 'little'):08x} ",
                    end="",
                )
            print()

    def read_data(self, addr: int, size: int) -> Optional[bytearray]:
        if not self.in_range(addr, size):
            return None
        return self.memory[addr : addr + size]

    def write_data(self, addr: int, data: bytearray) -> bool:
        if not self.in_range(addr, len(data)):
            return False
        self.memory[addr : addr + len(data)] = data
        return True

    def read_mem32(self, addr: int) -> int:
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        return self.lifter_instruction.load(addr, Type.int_32)

    def read_mem16(self, addr: int) -> int:
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        return self.lifter_instruction.load(addr, Type.int_16)

    def read_mem8(self, addr: int) -> int:
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        return self.lifter_instruction.load(addr, Type.int_8)

    def write_mem32(self, addr: int, value: int):
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        self.lifter_instruction.store(value, addr)

    def write_mem16(self, addr: int, value: int):
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        self.lifter_instruction.store(value, addr)

    def write_mem8(self, addr: int, value: int):
        if isinstance(addr, int):
            addr = self.lifter_instruction.constant(addr, Type.int_32)
        self.lifter_instruction.store(value, addr)

    def is_ena_a20gate(self) -> bool:
        return self.a20gate

    def set_a20gate(self, ena: bool):
        self.a20gate = ena

    def in_range(self, addr: int, length: int) -> bool:
        return addr + length - 1 < self.mem_size

    def set_bitstream(self, bitstream):
        self.bitstream: ConstBitStream = bitstream
