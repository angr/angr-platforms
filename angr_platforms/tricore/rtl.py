#!/usr/bin/env python3
""" rtl.py
A module for RTL functions.
"""
from pyvex.lifting.util import Type


INT32_MAX_POS  =  0x7fffffff  #(1 << (32 - 1))-1
UINT32_MAX_POS =  0xffffffff
INT32_MAX_NEG  = -0x80000000  #-(1 << (32 - 1))
INT64_MAX_POS  =  0x7fffffffffffffff
INT64_MAX_NEG  = -0x8000000000000000

SV_MASK =  0x10000000  # bit 29 of PSW
ASV_MASK = 0x4000000   # bit 27 of PSW

def carry(a, b, c):
    result_sum = a+b+c

    cond_32_lsb_z = (a+b+c) == 0

    cond_smaller_a = (result_sum < a)
    cond_smaller_b = (result_sum < b)
    cond_smaller_c = (result_sum < c)
    cond_32_lsb_nz = cond_smaller_a | cond_smaller_b | cond_smaller_c

    return cond_32_lsb_z | cond_32_lsb_nz


def overflow(val):
    """ Check Overflow for 32-bit values:
        - result > 0x7FFFFFFF or result < -0x80000000
    """
    return (val >> 32) != 0


def overflow_64(val):
    """ Check Overflow for 64-bit values:
        - result > 0xFFFFFFFFFFFFFFFF
    """
    return (val >> 64) != 0


def advanced_overflow(val):
    """ Check advanced overflow for 32-bit values. """
    return val[31] ^ val[30]


def advanced_overflow_64(val):
    """ Check Advanced Overflow for 64-bit values. """
    return val[63] ^ val[62]


def set_usb(psw, C, V, SV, AV, SAV):
    """ Set User Status Bits. """
    psw = psw & 0x7ffffff  # zero psw[31-27]
    temp = (C   << 31) | \
           (V   << 30) | \
           (SV  << 29) | \
           (AV  << 28) | \
           (SAV << 27)
    return psw | temp


def extend_to_32_bits(val):
    val = (val << 31) | (val << 30) | (val << 29) | \
          (val << 28) | (val << 27) | (val << 26) | \
          (val << 25) | (val << 24) | (val << 23) | \
          (val << 22) | (val << 21) | (val << 20) | \
          (val << 19) | (val << 18) | (val << 17) | \
          (val << 16) | (val << 15) | (val << 14) | \
          (val << 13) | (val << 12) | (val << 11) | \
          (val << 10) | (val << 9)  | (val << 8)  | \
          (val << 7)  | (val << 6)  | (val << 5)  | \
          (val << 4)  | (val << 3)  | (val << 2)  | \
          (val << 1)  | val
    return val


def extend_to_16_bits(val):
    val = (val << 15) | (val << 14) | (val << 13) | \
          (val << 12) | (val << 11) | (val << 10) | \
          (val << 9)  | (val << 8)  | (val << 7)  | \
          (val << 6)  | (val << 5)  | (val << 4)  | \
          (val << 3)  | (val << 2)  | (val << 1)  | val
    return val


def extend_to_8_bits(val):
    val = (val << 7)  | (val << 6)  | (val << 5)  | \
          (val << 4)  | (val << 3)  | (val << 2)  | \
          (val << 1)  | val
    return val


def extend_to_6_bits(val):
    val = (val << 5)  | (val << 4)  | (val << 3)  | \
          (val << 2)  | (val << 1)  | val
    return val


def extend_bits(val, bits):
    ret = 0
    for i in range(bits+1):
        ret |= (val << bits-i)
    return ret


def ssov(x, y):
    """ Saturation on signed overflow. """
    max_pos = (1 << (y - 1)) - 1
    max_neg = 1 << (y - 1)

    cond_x = extend_to_32_bits(x < max_pos)
    cond_max_neg = extend_to_32_bits(x > max_neg)

    ret = (x       &  cond_x & ~cond_max_neg)   | \
          (max_pos & ~cond_x & ~cond_max_neg)   | \
          (max_neg & ~cond_x &  cond_max_neg)

    return ret


def ssov16(x):
    """ Saturation on signed overflow. """
    return x


def ssov32(x, max_pos, max_neg):
    """ Saturation on signed overflow.
        :param x: Vex Constant (64-bit value).
        :param max_pos: Vex Constant (64-bit value).
        :param max_neg: Vex Constant (64-bit value).
        :return: x or max_pos or max_neg  (32-bit value).
    """
    cond_max_pos = extend_to_32_bits(x.signed > max_pos)
    cond_max_neg = extend_to_32_bits(x.signed < max_neg)
    ret = (max_pos &  cond_max_pos & ~cond_max_neg)   | \
          (max_neg & ~cond_max_pos &  cond_max_neg)   | \
          (x       & ~cond_max_pos & ~cond_max_neg)

    return ret


def ssov64(x):
    """ Saturation on signed overflow. """
    return x


def suov(x, y):
    """ Saturation on unsigned overflow. """
    max_pos = (1 << y) - 1
    cond_max_pos = extend_to_32_bits(x > max_pos)

    ret = (max_pos & cond_max_pos) | (x & ~cond_max_pos)

    return ret


def suov16(x):
    """ Saturation on unsigned overflow. """
    cond_x_neg = extend_to_16_bits((x >> 15) == 1)
    ret = x & (cond_x_neg^0xffff)

    return ret


def suov32(x):
    """ Saturation on unsigned overflow.
        :param x: VexValue.
    """
    max_pos = (1 << 32) - 1

    cond_max_pos = extend_to_32_bits(x > max_pos)
    cond_neg = extend_to_32_bits(x < 0)

    ret = (max_pos &  cond_max_pos & ~cond_neg)   | \
          (0       & ~cond_max_pos &  cond_neg)   | \
          (x       & ~cond_max_pos & ~cond_neg)

    return ret

def suov32_sub(x):
    """ Saturation on unsigned overflow.
        :param x: VexValue.
    """
    cond_pos = extend_to_32_bits(x.signed > 0)
    ret = x & cond_pos
    return ret

def suov32_pos(x):
    """ Saturation on unsigned overflow.
        :param x: VexValue.
    """
    cond_pos = extend_to_32_bits(x > UINT32_MAX_POS)
    ret = (UINT32_MAX_POS & cond_pos) | (x & ~cond_pos)
    return ret

def suov64(x):
    """ Saturation on unsigned overflow. """
    cond_x_neg = extend_bits((x[63] == 1), 64)
    ret = 0 | (x & ~cond_x_neg)

    return ret


def extract_16s(reg, halfword):
    """ Return signed halfword value of register.
        :param reg: register to extract bits from it.
        :param halfword: 0 or 1 for corresponding halfwords.
    """
    return (reg >> (halfword * 16)).cast_to(Type.int_16).cast_to(Type.int_32, signed=True)


def sign_extend(val, bits=32):
    """ Sign extension. High-order bit of val is left extended.
        :param val: VexValue
    """
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


def sign_extend_2(val, width):
    """ Sign extension. High-order bit of val is left extended.
        :param val:  VexValue
        :param width: int
    """
    cond_sign_bit_1 = extend_to_32_bits((val & ((1 << width)-1)) == 1)
    mask_1 = ((0xffffffff >> width) << width) & cond_sign_bit_1
    result = val | mask_1
    return result


def sign_extend_3(val, width, tmp):
    """ Sign extension. High-order bit of val is left extended.
        :param val:  VexValue
        :param width: VexValue
        :param tmp: VexValue of 0xffffffff
    """
    mask_sign_bit = (1 << (width-1)).cast_to(Type.int_32)
    cond_sign_bit_1 = extend_to_32_bits(val & mask_sign_bit == 1)
    mask_2 = ((tmp >> width) << width).cast_to(Type.int_32) & cond_sign_bit_1.cast_to(Type.int_32)
    result = val | mask_2
    return result


def twos_comp(val, bits):
    """compute 2's complement """
    if val & (1 << (bits - 1)):
        val = val - (1 << bits)
    return val


def twos_comp_2(val, bits):
    """compute 2's complement
        :param val: VexValue
    """
    mask = 1 << (bits - 1)
    condition = extend_bits((val & mask) == mask, bits)
    val = (val - (1 << bits)) & condition
    return val


def get_abs_val(val, bits):
    """ Compute absolute value
        :param val: VexValue
    """
    mask = 1 << (bits - 1)
    ones = (mask << 1) - 1
    condition = extend_to_32_bits(mask & (val & ones) == 0)
    result = (val & condition) | (((val ^ ones) + 1) & ~condition)

    return result


def clo32(val):
    """ Count Leading Ones starting from bit 32. """
    # pylint: disable=line-too-long
    first_bit = val[31] ^ 0x0
    ctr = (1 & val[31]) + \
          (1 & val[30]) + \
          (1 & val[29] & val[30]) + \
          (1 & val[28] & val[30] & val[29]) + \
          (1 & val[27] & val[30] & val[29] & val[28]) + \
          (1 & val[26] & val[30] & val[29] & val[28] & val[27]) + \
          (1 & val[25] & val[30] & val[29] & val[28] & val[27] & val[26]) + \
          (1 & val[24] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25]) + \
          (1 & val[23] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24]) + \
          (1 & val[22] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23]) + \
          (1 & val[21] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22]) + \
          (1 & val[20] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21]) + \
          (1 & val[19] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20]) + \
          (1 & val[18] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19]) + \
          (1 & val[17] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18]) + \
          (1 & val[16] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17]) + \
          (1 & val[15] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16]) + \
          (1 & val[14] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15]) + \
          (1 & val[13] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14]) + \
          (1 & val[12] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13]) + \
          (1 & val[11] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12]) + \
          (1 & val[10] & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11]) + \
          (1 & val[9]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10]) + \
          (1 & val[8]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9]) + \
          (1 & val[7]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8]) + \
          (1 & val[6]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7]) + \
          (1 & val[5]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6]) + \
          (1 & val[4]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5]) + \
          (1 & val[3]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4]) + \
          (1 & val[2]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3]) + \
          (1 & val[1]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3] & val[2]) + \
          (1 & val[0]  & val[30] & val[29] & val[28] & val[27] & val[26] & val[25] & val[24] & val[23] & val[22] & val[21] & val[20] & val[19] & val[18] & val[17] & val[16] & val[15] & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3] & val[2] & val[1])

    return ctr * first_bit


def clo16(val):
    """ Count Leading Ones starting from bit 16. """
    # pylint: disable=line-too-long
    first_bit = val[15] ^ 0x0
    ctr = (1 & val[15]) + \
          (1 & val[14]) + \
          (1 & val[13] & val[14]) + \
          (1 & val[12] & val[14] & val[13]) + \
          (1 & val[11] & val[14] & val[13] & val[12]) + \
          (1 & val[10] & val[14] & val[13] & val[12] & val[11]) + \
          (1 & val[9]  & val[14] & val[13] & val[12] & val[11] & val[10]) + \
          (1 & val[8]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9]) + \
          (1 & val[7]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8]) + \
          (1 & val[6]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7]) + \
          (1 & val[5]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6]) + \
          (1 & val[4]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5]) + \
          (1 & val[3]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4]) + \
          (1 & val[2]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3]) + \
          (1 & val[1]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3] & val[2]) + \
          (1 & val[0]  & val[14] & val[13] & val[12] & val[11] & val[10] & val[9] & val[8] & val[7] & val[6] & val[5] & val[4] & val[3] & val[2] & val[1])

    return ctr * first_bit


def cls(val, disp):
    """ Count Leading Signs starting from bit disp.
        disp: 15 or 31
    """
    mask = 0x1
    ctr = 0
    sign_bit = disp  # bit: 31 or 15
    disp -= 1        # first bit is the sign bit
    while disp >= 0:
        cond = (val[sign_bit] ^ (((val & (mask << disp)) >> disp) & 0x1) == 0)
        ctr += (1 & cond)
        disp -= 1

    return ctr


def clz16(val):
    """ Count Leading Zeros starting from bit 16. """
    # pylint: disable=line-too-long
    first_bit = val[15] ^ 0x1
    ctr = (1 & (val[15]^1)) + \
          (1 & (val[14]^1)) + \
          (1 & (val[13]^1) & (val[14]^1)) + \
          (1 & (val[12]^1) & (val[14]^1) & (val[13]^1)) + \
          (1 & (val[11]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1)) + \
          (1 & (val[10]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1)) + \
          (1 & (val[9] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1)) + \
          (1 & (val[8] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1)) + \
          (1 & (val[7] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1)) + \
          (1 & (val[6] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1)) + \
          (1 & (val[5] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1)) + \
          (1 & (val[4] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1)) + \
          (1 & (val[3] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1)) + \
          (1 & (val[2] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1)) + \
          (1 & (val[1] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1) & (val[2]^1)) + \
          (1 & (val[0] ^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1) & (val[2]^1) & (val[1]^1))

    return ctr * first_bit


def clz32(val):
    """ Count Leading Zeros starting from bit 32. """
    # pylint: disable=line-too-long
    first_bit = val[31] ^ 0x1
    ctr = (1 & (val[31]^1)) + \
          (1 & (val[30]^1)) + \
          (1 & (val[29]^1) & (val[30]^1)) + \
          (1 & (val[28]^1) & (val[30]^1) & (val[29]^1)) + \
          (1 & (val[27]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1)) + \
          (1 & (val[26]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1)) + \
          (1 & (val[25]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1)) + \
          (1 & (val[24]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1)) + \
          (1 & (val[23]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1)) + \
          (1 & (val[22]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1)) + \
          (1 & (val[21]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1)) + \
          (1 & (val[20]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1)) + \
          (1 & (val[19]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1)) + \
          (1 & (val[18]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1)) + \
          (1 & (val[17]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1)) + \
          (1 & (val[16]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1)) + \
          (1 & (val[15]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1)) + \
          (1 & (val[14]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1)) + \
          (1 & (val[13]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1)) + \
          (1 & (val[12]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1)) + \
          (1 & (val[11]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1)) + \
          (1 & (val[10]^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1)) + \
          (1 & (val[9] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1)) + \
          (1 & (val[8] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1)) + \
          (1 & (val[7] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1)) + \
          (1 & (val[6] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1)) + \
          (1 & (val[5] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1)) + \
          (1 & (val[4] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1)) + \
          (1 & (val[3] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1)) + \
          (1 & (val[2] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1)) + \
          (1 & (val[1] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1) & (val[2]^1)) + \
          (1 & (val[0] ^1) & (val[30]^1) & (val[29]^1) & (val[28]^1) & (val[27]^1) & (val[26]^1) & (val[25]^1) & (val[24]^1) & (val[23]^1) & (val[22]^1) & (val[21]^1) & (val[20]^1) & (val[19]^1) & (val[18]^1) & (val[17]^1) & (val[16]^1) & (val[15]^1) & (val[14]^1) & (val[13]^1) & (val[12]^1) & (val[11]^1) & (val[10]^1) & (val[9]^1) & (val[8]^1) & (val[7]^1) & (val[6]^1) & (val[5]^1) & (val[4]^1) & (val[3]^1) & (val[2]^1) & (val[1]^1))

    return ctr * first_bit


def reverse16(n):
    result = n[0] << 15 | n[1] << 14 | \
             n[2] << 13 | n[3] << 12 | \
             n[4] << 11 | n[5] << 10 | \
             n[6] << 9  | n[7] << 8  | \
             n[8] << 7  | n[9] << 6  | \
             n[10]<< 5  | n[11] << 4 | \
             n[12]<< 3  | n[13] << 2 | \
             n[14]<< 1  | n[15]
    return result
