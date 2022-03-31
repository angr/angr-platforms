#!/usr/bin/env python3
""" simos_tricore.py
Define OS simulator for tricore architecture.
"""
from angr.calling_conventions import SimCC, register_default_cc, SimRegArg
from .arch_tricore import ArchTRICORE

class SimCCTricore(SimCC):
    """ Calling convertion simulator for tricore architecture. """
    ARG_REGS = ['d4', 'd5', 'd6', 'd7', 'a4', 'a5', 'a6', 'a7']
    FP_ARG_REGS = []
    CALLER_SAVED_REGS = ['d8', 'd9', 'd10', 'd11', 'd12', 'd13', 'd14',
                         'd15', 'a10', 'a11', 'a12', 'a13', 'a14', 'a15']
    RETURN_ADDR = SimRegArg('ra', 4)
    RETURN_VAL = SimRegArg('d2', 4)  # scalar value
    #RETURN_VAL = SimRegArg('a2', 4) # pointer value  TODO
    ARCH = ArchTRICORE

register_default_cc('TRICORE', SimCCTricore)
