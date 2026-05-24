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


def _coerce_enum(enum_cls, value):
    if isinstance(value, enum_cls):
        return value
    try:
        raw_value = getattr(value, "value", value)
    except Exception:
        raw_value = None
    if isinstance(raw_value, enum_cls):
        return raw_value
    if isinstance(raw_value, int):
        try:
            return enum_cls(raw_value)
        except Exception:
            pass
    raise ValueError(f"Register {value!r} does not exist")


def coerce_reg32_t(value) -> reg32_t:
    return _coerce_enum(reg32_t, value)


def coerce_reg16_t(value) -> reg16_t:
    return _coerce_enum(reg16_t, value)


def coerce_reg8_t(value) -> reg8_t:
    return _coerce_enum(reg8_t, value)


def coerce_sgreg_t(value) -> sgreg_t:
    return _coerce_enum(sgreg_t, value)


def register_name_8616(value) -> str:
    if hasattr(value, "name") and isinstance(getattr(value, "name"), str):
        return value.name.lower()
    try:
        coerced = _coerce_enum(reg32_t, value)
        return coerced.name.lower()
    except Exception:
        pass
    try:
        coerced = _coerce_enum(reg16_t, value)
        return coerced.name.lower()
    except Exception:
        pass
    try:
        coerced = _coerce_enum(reg8_t, value)
        return coerced.name.lower()
    except Exception:
        pass
    raise ValueError(f"Register {value!r} does not exist")
