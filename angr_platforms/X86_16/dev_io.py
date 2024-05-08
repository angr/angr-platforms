from abc import ABC, abstractmethod
from typing import Optional

from .memory import Memory


class PortIO(ABC):
    @abstractmethod
    def in8(self, addr: int) -> int:
        """Reads an 8-bit value from the specified port address."""

    @abstractmethod
    def out8(self, addr: int, value: int):
        """Writes an 8-bit value to the specified port address."""


class MemoryIO(ABC):
    def __init__(self):
        self.memory: Optional[Memory] = None
        self.paddr = 0
        self.size = 0

    def set_mem(self, mem: Memory, addr: int, length: int):
        """Sets the memory object, base address, and size for the device."""
        self.memory = mem
        self.paddr = addr
        self.size = length

    def read32(self, offset: int) -> int:
        """Reads a 32-bit value from the specified offset."""
        value = 0
        for i in range(4):
            value += self.read8(offset + i) << (8 * i)
        return value

    def read16(self, offset: int) -> int:
        """Reads a 16-bit value from the specified offset."""
        value = 0
        for i in range(2):
            value += self.read8(offset + i) << (8 * i)
        return value

    @abstractmethod
    def read8(self, offset: int) -> int:
        """Reads an 8-bit value from the specified offset."""

    def write32(self, offset: int, value: int):
        """Writes a 32-bit value to the specified offset."""
        for i in range(4):
            self.write8(offset + i, (value >> (8 * i)) & 0xFF)

    def write16(self, offset: int, value: int):
        """Writes a 16-bit value to the specified offset."""
        for i in range(2):
            self.write8(offset + i, (value >> (8 * i)) & 0xFF)

    @abstractmethod
    def write8(self, offset: int, value: int):
        """Writes an 8-bit value to the specified offset."""
