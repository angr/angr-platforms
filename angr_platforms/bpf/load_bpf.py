
import logging

from cle.backends import Blob, register_backend
from archinfo import arch_from_id

l = logging.getLogger("load_Bpf")


class BPF(Blob):
    is_default = False

    def __init__(self, *args, offset=0, **kwargs):
        """
        Loader backend for BF programs
        :param path: The file path
        :param offset: Skip this many bytes from the beginning of the file.
        """
        super(BPF, self).__init__(*args,
                                  arch=arch_from_id("bpf"),
                                  offset=offset,
                                  entry_point=0,
                                  **kwargs)
        self.os = "bpf"

    @staticmethod
    def is_compatible(stream):
        """
        A BPF file is simply a binary blob. So it is compatible with anything.

        :param stream:
        :return:
        """
        return True


register_backend("bpf", BPF)
