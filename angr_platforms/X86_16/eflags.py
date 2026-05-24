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

    def set_flag(self, flags, idx, value):
        flags16 = self.constant(flags, Type.int_16) if isinstance(flags, int) else flags.cast_to(Type.int_16)
        value16 = self.constant(value, Type.int_1) if isinstance(value, int) else value.cast_to(Type.int_1)
        clear_mask = self.constant((~(1 << idx)) & 0xFFFF, Type.int_16)
        bit_mask = self.constant((1 << idx) & 0xFFFF, Type.int_16)
        return (flags16 & clear_mask) | ((value16.cast_to(Type.int_16) << idx) & bit_mask)

    def set_carry(self, flags, carry):
        return self.set_flag(flags, 0, carry)

    def set_parity(self, flags, parity):
        return self.set_flag(flags, 2, parity)

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

    @staticmethod
    def _wider_type(ty):
        if ty == Type.int_8:
            return Type.int_16
        if ty == Type.int_16:
            return Type.int_32
        return Type.int_32

    def _count8(self, count):
        return self.constant(count, Type.int_8) if isinstance(count, int) else count.cast_to(Type.int_8)

    def _mask_shift_count(self, count):
        return self._count8(count) & self.constant(0x1F, Type.int_8)

    @staticmethod
    def _const_u8_value(v):
        if isinstance(v, int):
            return v & 0xFF
        try:
            return v.value & 0xFF
        except (AttributeError, ValueError):
            return None

    def _ite(self, cond, when_true, when_false):
        cond = self.constant(cond, Type.int_1) if isinstance(cond, int) else cond.cast_to(Type.int_1)
        expr = self.lifter_instruction.irsb_c.ite(
            cond.rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self._vv(expr)

    def _adjust_flag(self, v1, v2, result):
        one = self.constant(1, result.ty)
        return (((v1 ^ v2) ^ result) >> 4 & one).cast_to(Type.int_1)

    def update_eflags_inc(self, v1):
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + self.constant(1, v1.ty)

        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, self.constant(1, v1.ty), result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, v1 == self.constant((1 << (size - 1)) - 1, v1.ty))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_add(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2
        wide = self._wider_type(v1.ty)
        carry = ((v1.cast_to(wide) + v2.cast_to(wide)) >> size & self.constant(1, wide)).cast_to(Type.int_1)

        flags = self.set_carry(flags, carry)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, (((~(v1 ^ v2)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)).cast_to(Type.int_1))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_adc(self, v1, v2, carry):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        carry = self.constant(carry, v1.ty) if isinstance(carry, int) else carry.cast_to(v1.ty)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v1.width
        result = v1 + v2 + carry
        wide = self._wider_type(v1.ty)
        carry_out = ((v1.cast_to(wide) + v2.cast_to(wide) + carry.cast_to(wide)) >> size & self.constant(1, wide)).cast_to(Type.int_1)

        flags = self.set_carry(flags, carry_out)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, (((~(v1 ^ v2)) & (v1 ^ result)) >> (size - 1) & self.constant(1, v1.ty)).cast_to(Type.int_1))
        self.set_gpreg(reg16_t.FLAGS, flags)


    def update_eflags_or(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 | v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
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
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sub(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2
        size = v1.width

        flags = self.set_carry(flags, (v1 < v2).cast_to(Type.int_1))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, ((((v1 ^ v2) & (v1 ^ result)) >> (size - 1)) & self.constant(1, v1.ty)).cast_to(Type.int_1))
        self.set_gpreg(reg16_t.FLAGS, flags)


    def update_eflags_sbb(self, v1, v2, c):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        c = self.constant(c, v1.ty) if isinstance(c, int) else c.cast_to(v1.ty)
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 - v2 - c
        size = v1.width
        borrow = (v1.cast_to(self._wider_type(v1.ty)) < (v2.cast_to(self._wider_type(v1.ty)) + c.cast_to(self._wider_type(v1.ty)))).cast_to(Type.int_1)

        flags = self.set_carry(flags, borrow)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, ((((v1 ^ v2) & (v1 ^ result)) >> (size - 1)) & self.constant(1, v1.ty)).cast_to(Type.int_1))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_xor(self, v1, v2):
        v2 = self.constant(v2, v1.ty) if isinstance(v2, int) else v2
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = v1 ^ v2
        size = v1.width

        flags = self.set_carry(flags, self.constant(0))
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
        flags = self.set_zero(flags, result == 0)
        flags = self.set_sign(flags, result[size - 1])
        flags = self.set_overflow(flags, self.constant(0))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_neg(self, v2):
        flags = self.get_gpreg(reg16_t.FLAGS)
        result = (v2 * -1).cast_to(Type.int_16)
        size = v2.width

        flags = self.set_carry(flags, v2 != 0)
        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(self.constant(0, v2.ty), v2, result))
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

        flags = self.set_parity(flags, self.chk_parity(result))
        flags = self.set_flag(flags, 4, self._adjust_flag(v1, v2, result))
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
        low = result.cast_to(type1)
        high = (result >> self.constant(size, Type.int_8)).cast_to(type1)
        sign_ext = self._ite(
            low[size - 1].cast_to(Type.int_1),
            self.constant((1 << size) - 1, type1),
            self.constant(0, type1),
        ).cast_to(type1)
        sign_ext_ok = (high == sign_ext).cast_to(Type.int_1)
        cfof = (sign_ext_ok == self.constant(0, Type.int_1)).cast_to(Type.int_1)
        flags = self.set_carry(flags, cfof)
        flags = self.set_zero(flags, result.cast_to(type1) == 0)
        flags = self.set_sign(flags, sign)
        flags = self.set_overflow(flags, cfof)
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shl(self, v, c):
        const_count = self._const_u8_value(c)
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v << self.constant(1, Type.int_8)
            cf = v[v.width - 1].cast_to(Type.int_1)
            flags = self.set_carry(flags, cf)
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(0, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            flags = self.set_overflow(flags, (result[v.width - 1].cast_to(Type.int_1) ^ cf).cast_to(Type.int_1))
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        step_result = v
        step_cf = self.get_flag(0)
        result = v
        cf = self.get_flag(0)
        for step in range(1, 32):
            step_cf = step_result[size - 1].cast_to(Type.int_1)
            step_result = step_result << self.constant(1, Type.int_8)
            use_step = c == self.constant(step, Type.int_8)
            result = self._ite(use_step, step_result, result)
            cf = self._ite(use_step, step_cf, cf)

        unchanged = c == self.constant(0, Type.int_8)
        one = c == self.constant(1, Type.int_8)
        flags = self._ite(unchanged, self.get_gpreg(reg16_t.FLAGS), flags)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(0, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(
                one,
                (result[size - 1].cast_to(Type.int_1) ^ cf).cast_to(Type.int_1),
                self.constant(0, Type.int_1),
            ),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_rol(self, v, c):
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v << c) | (v >> (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[0].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[0]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_ror(self, v, c):
        size = v.width
        masked = self._mask_shift_count(c)
        c = masked % self.constant(size, Type.int_8)
        result = (v >> c) | (v << (self.constant(size, Type.int_8) - c))
        flags = self.get_gpreg(reg16_t.FLAGS)
        unchanged = masked == self.constant(0, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(
            flags,
            self._ite(unchanged, self.get_flag(11), (result[size - 1] ^ result[size - 2]).cast_to(Type.int_1)),
        )
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_shr(self, v, c):
        const_count = self._const_u8_value(c)
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v >> self.constant(1, Type.int_8)
            flags = self.set_carry(flags, v[0].cast_to(Type.int_1))
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(1, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            flags = self.set_overflow(flags, v[v.width - 1].cast_to(Type.int_1))
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        step_result = v
        step_cf = self.get_flag(0)
        result = v
        cf = self.get_flag(0)
        for step in range(1, 32):
            step_cf = step_result[0].cast_to(Type.int_1)
            step_result = step_result >> self.constant(1, Type.int_8)
            use_step = c == self.constant(step, Type.int_8)
            result = self._ite(use_step, step_result, result)
            cf = self._ite(use_step, step_cf, cf)

        unchanged = c == self.constant(0, Type.int_8)
        one = c == self.constant(1, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(1, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(flags, self._ite(one, v[size - 1].cast_to(Type.int_1), self.constant(0, Type.int_1)))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def update_eflags_sar(self, v, c):
        const_count = self._const_u8_value(c)
        if const_count == 1:
            flags = self.get_gpreg(reg16_t.FLAGS)
            result = v.sar(self.constant(1, Type.int_8))
            flags = self.set_carry(flags, v[0].cast_to(Type.int_1))
            flags = self.set_parity(flags, self.chk_parity(result))
            flags = self.set_flag(flags, 4, self.constant(1, Type.int_1))
            flags = self.set_zero(flags, (result == 0).cast_to(Type.int_1))
            flags = self.set_sign(flags, result[v.width - 1].cast_to(Type.int_1))
            flags = self.set_overflow(flags, self.constant(0, Type.int_1))
            self.set_gpreg(reg16_t.FLAGS, flags)
            return
        c = self._mask_shift_count(c)
        flags = self.get_gpreg(reg16_t.FLAGS)
        size = v.width
        step_result = v
        step_cf = self.get_flag(0)
        result = v
        cf = self.get_flag(0)
        for step in range(1, 32):
            step_cf = step_result[0].cast_to(Type.int_1)
            step_result = step_result.sar(self.constant(1, Type.int_8))
            use_step = c == self.constant(step, Type.int_8)
            result = self._ite(use_step, step_result, result)
            cf = self._ite(use_step, step_cf, cf)

        unchanged = c == self.constant(0, Type.int_8)
        one = c == self.constant(1, Type.int_8)
        flags = self.set_carry(flags, self._ite(unchanged, self.get_flag(0), cf))
        flags = self.set_parity(flags, self._ite(unchanged, self.get_flag(2), self.chk_parity(result)))
        flags = self.set_flag(flags, 4, self._ite(unchanged, self.get_flag(4), self.constant(1, Type.int_1)))
        flags = self.set_zero(flags, self._ite(unchanged, self.get_flag(6), (result == 0).cast_to(Type.int_1)))
        flags = self.set_sign(flags, self._ite(unchanged, self.get_flag(7), result[size - 1].cast_to(Type.int_1)))
        flags = self.set_overflow(flags, self.constant(0, Type.int_1))
        self.set_gpreg(reg16_t.FLAGS, flags)

    def chk_parity(self, v):
        v = self.constant(v, Type.int_8) if isinstance(v, int) else v.cast_to(Type.int_8)
        parity = v ^ (v >> self.constant(4, Type.int_8))
        parity = parity ^ (parity >> self.constant(2, Type.int_8))
        parity = parity ^ (parity >> self.constant(1, Type.int_8))
        return ((~parity) & self.constant(1, Type.int_8)).cast_to(Type.int_1)
