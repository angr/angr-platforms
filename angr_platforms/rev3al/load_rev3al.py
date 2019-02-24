from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import re
import logging

l = logging.getLogger("cle.blob")

__all__ = ('Rev3al',)

class Rev3al(Blob):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """
    is_default = True

    def __init__(self, path, offset=0, *args, **kwargs):
        """
        Loader backend for hell86 programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(Rev3al, self).__init__(path, *args,
                                 arch=arch_from_id("rev3al"),
                                 offset=offset,
                                 **kwargs)
        self.os = 'rev3al'

    @staticmethod
    def is_compatible(stream):
        #stream.seek(0)
        #for i in range(10):
        #    r = stream.read(14)
        #    if len(r) != 14:
        #        break
        #    if r[12:14] != '\x0f\x0b':
        #        return False
        return True

register_backend("rev3al", Rev3al)