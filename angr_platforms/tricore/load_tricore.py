#!/usr/bin/env python3
""" load_tricore.py
Define tricore backend to load ELF files and register it in angr's backends list.
"""
import logging
from cle.backends import Blob, register_backend
from archinfo import arch_from_id

# pylint: disable=super-with-arguments

l = logging.getLogger("cle.tc")
__all__ = ('TRICORE',)

class TRICORE(Blob):
    """" Tricore architecture class. """

    is_default = True

    def __init__(self, *args, offset=0, **kwargs):
        super(TRICORE, self).__init__(*args,
                arch=arch_from_id("tricore"),
                offset=offset,
                entry_point=0,
                **kwargs)
        self.os = "tc"


    @staticmethod
    def is_compatible(stream):
        #TODO: check compatibility here
        return True

register_backend(r"tc|tricore", TRICORE)
