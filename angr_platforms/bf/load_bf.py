from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import re
import logging

from .engine_bf import bf_engine_preset

l = logging.getLogger("cle.blob")

__all__ = ('BF',)

class BF(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, path, offset=0, *args, **kwargs):
        """
        Loader backend for BF programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(BF, self).__init__(path, *args,
                arch=arch_from_id("bf"),
                offset=offset,
                entry_point=0,
                **kwargs)
        self.os = "bf"
        self.engine_preset = bf_engine_preset

    @staticmethod
    def is_compatible(stream):
        bf_re = re.compile(b'[+\-<>.,\[\]\n]+')
        stream.seek(0)
        stuff = stream.read(0x1000)
        if bf_re.match(stuff):
            return True
        return False

"""
    def _load(self, offset, size=None):
        """"""
        Load a segment into memory.
        """"""

        self.binary_stream.seek(offset)
        if size is None:
            string = self.binary_stream.read()
        else:
            string = self.binary_stream.read(size)
        self.memory.add_backer(0, string)
        self._max_addr = len(string)
"""

register_backend("bf", BF)
