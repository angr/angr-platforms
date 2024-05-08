from enum import Enum


class reg32_t(Enum):
    EAX = 0
    ECX = 1
    EDX = 2
    EBX = 3
    ESP = 4
    EBP = 5
    ESI = 6
    EDI = 7
    GPREGS_COUNT = 8
    EIP = 9
    EFLAGS = 10


class reg16_t(Enum):
    AX = 0
    CX = 1
    DX = 2
    BX = 3
    SP = 4
    BP = 5
    SI = 6
    DI = 7
    IP = 8
    FLAGS = 9


class reg8_t(Enum):
    AL = 0
    CL = 1
    DL = 2
    BL = 3
    AH = 4
    CH = 5
    DH = 6
    BH = 7


class sgreg_t(Enum):
    ES = 0
    CS = 1
    SS = 2
    DS = 3
    FS = 4
    GS = 5
    SGREGS_COUNT = 6


class dtreg_t(Enum):
    GDTR = 0
    IDTR = 1
    LDTR = 2
    TR = 3
    DTREGS_COUNT = 4
