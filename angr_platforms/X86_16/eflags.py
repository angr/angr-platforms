from pyvex.lifting.util.vex_helper import Type

from .regs import reg16_t, reg32_t


class Eflags:
    def __init__(self):
        #self.eflags = 0
        pass

    def get_eflags(self):
        return self.get_gpreg(reg32_t.EFLAGS)

    def set_eflags(self, v):
        self.set_gpreg(reg32_t.EFLAGS, v)

    def get_flags(self):
        return self.get_gpreg(reg16_t.FLAGS)

    def set_flags(self, v):
        self.set_gpreg(reg16_t.FLAGS, v)

    def get_flag(self, idx):
        return self.get_gpreg(reg16_t.FLAGS)[idx].cast_to(Type.int_1)

    def is_carry(self):
        return self.get_flag(0)

    def is_parity(self):
        return self.get_flag(2)

    def is_zero(self):
        return self.get_flag(6)

    def is_sign(self):
        return self.get_flag(7)

    def is_overflow(self):
        return self.get_flag(11)

    def is_interrupt(self):
        return self.get_flag(9)

    def is_direction(self):
        return self.get_flag(10)

    @staticmethod
    def set_flag(flags, idx, value):
        #value = value.cast_to(Type.int_1)
        return flags & ~(1 << idx) | (value.cast_to(Type.int_16) << idx)

    def set_carry(self, flags, carry):
        return self.set_flag(flags, 0, carry)

    def set_parity(self, flags, parity):
        return
        eflags = self.get_gpreg(reg16_t.FLAGS)
        eflags[self.constant(2)] = parity.cast_to(Type.int_16)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def set_zero(self, flags, zero):
        return self.set_flag(flags, 6, zero)

    def set_sign(self, flags, sign):
        return self.set_flag(flags, 7, sign)

    def set_overflow(self, flags, over):
        return self.set_flag(flags, 11, over)

    def set_interrupt(self, interrupt):
        flags = self.get_gpreg(reg16_t.FLAGS)
        interrupt = self.constant(interrupt, Type.int_1)
        flags = self.set_flag(flags, 9, interrupt)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def set_direction(self, direction):
        flags = self.get_gpreg(reg16_t.FLAGS)
        direction = self.constant(direction, Type.int_1)
        flags = self.set_flag(flags, 10, direction)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_inc(self, v1):
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1

        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v1 == self.constant(1 << (size - 1), v1.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_add(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2

        flags = self.set_carry(flags, result < v1)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags,
            ~(~(1 ^ v1[size - 1] ^ v2[size - 1]) | ~((v1 ^ (v1 + v2))[size - 1])),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_adc(self, v1, v2, carry):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2 + carry

        flags = self.set_carry(flags, result < v1)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags,
            ~(~(1 ^ v1[size - 1] ^ v2[size - 1]) | ~((v1 ^ (v1 + v2))[size - 1])),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)


    def update_eflags_or(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 | v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_and(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 & v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sub(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self.set_carry(flags, v2 > v1)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags,
            ~(~(v1[size-1] ^ v2[size-1]) | ~(((v1 & (1<<(size-1))) ^ v1 + v2 * -1)[size-1])),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)


    def update_eflags_sbb(self, v1, v2, c):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2 - c
        size = v1.width

        flags = self.set_carry(flags, (v2 >= v1) if c else (v2 > v1))  # TODO
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags,
            ~(~(v1[size-1] ^ v2[size-1]) | ~(((v1 & (1<<(size-1))) ^ v1 + (v2 + c) * -1)[size-1])),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_xor(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 ^ v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_neg(self, v2):
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = (v2 * -1).cast_to(Type.int_16)
        size = v2.width

        flags = self.set_carry(flags, v2 != 0)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags,
                                  ~(~v2[size - 1] | (~(v2 * -1).cast_to(Type.int_16))[size - 1]),
        )
        # v2 == (self.constant(1 << (size - 1), v2.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_dec(self, v1):
        v2 = self.constant(1, v1.ty)
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v1 == (self.constant(1 << (size - 1), v1.ty)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_mul(self, v1, v2):
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1.cast_to(Type.int_32) * v2.cast_to(Type.int_32)
        size = v1.width

        flags = self.set_carry(flags, (result >> size) != 0)
        flags = self.set_zero(flags, result.cast_to(type1) == 0)
        flags = self.set_sign(flags, (v1*v2)[size - 1])
        flags = self.set_overflow(flags, (result >> size) != 0)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_imul(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        type1 = v1.ty
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1.widen_signed(Type.int_32) * v2.widen_signed(Type.int_32)
        size = v1.width

        sign = (v1.cast_to(v2.ty, signed=True)*v2.signed)[size - 1]
        #_7fff = self.constant(0xffff8000, Type.int_32)
        #cfof = ((result & _7fff) == 0) and ((result & _7fff) == _7fff)
        #cfof = (result.signed >> 16).signed == (result.signed >> 15).signed
        #flags = self.set_carry(flags, cfof)
        flags = self.set_zero(flags, result.cast_to(type1) == 0)
        flags = self.set_sign(flags, sign)
        #flags = self.set_overflow(flags, cfof)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shl(self, v, c):
        #if c == 0:
        #    return
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v << c
        size = v.width

        flags = self.set_carry(flags, (v >> (size - c - 1)) & 1)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, (result ^ v)[size - 1])
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shr(self, v, c):
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v >> c
        size = v.width

        flags = self.set_carry(flags, v >> (c - 1) & 1)
        #self.set_parity(flags, self.chk_parity(result & 0xFF))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        if c == 1:
            flags = self.set_overflow(flags, v >> (size - 1) & 1)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def chk_parity(self, v):
        return None
        p = self.constant(1, Type.int_1)
        for i in range(8):
            p ^= v[i].cast_to(Type.int_1)
        return p
