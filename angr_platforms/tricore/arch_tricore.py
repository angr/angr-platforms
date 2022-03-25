#!/usr/bin/env python3
""" arch_tricore.py
Implementation of tricore architecture class.
"""
from archinfo.arch import Arch
from archinfo.arch import Register
from archinfo.arch import Endness
from archinfo.tls import TLSArchInfo
from archinfo import register_arch


class ArchTRICORE(Arch):
    """ Tricore architecture class. """

    name = "TRICORE"
    bits = 32
    byte_width = 8
    max_inst_bytes = 4
    instruction_alignment = 1
    vex_arch = None
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)
    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    memory_endness = Endness.LE
    register_endness = Endness.LE

    register_list = [
        Register(name="a0", size=32, vex_offset=0),
        Register(name="a1", size=32, vex_offset=32),
        Register(name="a2", size=32, vex_offset=64),
        Register(name="a3", size=32, vex_offset=96),
        Register(name="a4", size=32, vex_offset=128),
        Register(name="a5", size=32, vex_offset=160),
        Register(name="a6", size=32, vex_offset=192),
        Register(name="a7", size=32, vex_offset=224),
        Register(name="a8", size=32, vex_offset=256),
        Register(name="a9", size=32, vex_offset=288),
        Register(name="a10", size=32, vex_offset=320, alias_names=('sp',)),
        Register(name="a11", size=32, vex_offset=352, alias_names=('ra','lr',)),
        Register(name="a12", size=32, vex_offset=384),
        Register(name="a13", size=32, vex_offset=416),
        Register(name="a14", size=32, vex_offset=448),
        Register(name="a15", size=32, vex_offset=480),

        Register(name="d0", size=32, vex_offset=512),
        Register(name="d1", size=32, vex_offset=544),
        Register(name="d2", size=32, vex_offset=576),
        Register(name="d3", size=32, vex_offset=608),
        Register(name="d4", size=32, vex_offset=640),
        Register(name="d5", size=32, vex_offset=672),
        Register(name="d6", size=32, vex_offset=704),
        Register(name="d7", size=32, vex_offset=736),
        Register(name="d8", size=32, vex_offset=768),
        Register(name="d9", size=32, vex_offset=800),
        Register(name="d10", size=32, vex_offset=832),
        Register(name="d11", size=32, vex_offset=864),
        Register(name="d12", size=32, vex_offset=896),
        Register(name="d13", size=32, vex_offset=928),
        Register(name="d14", size=32, vex_offset=960),
        Register(name="d15", size=32, vex_offset=992),

        Register(name="psw", size=32, vex_offset=1024),
        Register(name="pc", size=32, vex_offset=1056, alias_names=('ip',)),
        Register(name="pcxi", size=32, vex_offset=1088),
        Register(name="fcx", size=32, vex_offset=1120),
        Register(name="lcx", size=32, vex_offset=1152),
        Register(name="isp", size=32, vex_offset=1184),
        Register(name="icr", size=32, vex_offset=1216),
        Register(name="pipn", size=32, vex_offset=1248),
        Register(name="biv", size=32, vex_offset=1280),
        Register(name="btv", size=32, vex_offset=1312),

        Register(name="ip_at_syscall", size=8, vex_offset=1344),
    ]

    def __init__(self, endness=Endness.LE):
        super().__init__(endness)


register_arch([r'tc|tricore'], 32, 'Iend_LE', ArchTRICORE)
