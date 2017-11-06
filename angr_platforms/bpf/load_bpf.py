
import logging

from cle.backends import Blob, register_backend
from archinfo import arch_from_id

l = logging.getLogger("load_Bpf")


class BPF(Blob):
    def __init__(self, path, custom_offset=0, *args, **kwargs):
        """
        Loader backend for BF programs
        :param path: The file path
        :param custom_offset: Skip this many bytes from the beginning of the file.
        """
        super(BPF, self).__init__(path, *args,
                                  custom_arch=arch_from_id("bpf"),
                                  custom_offset=custom_offset,
                                  custom_entry_point=0,
                                  **kwargs)
        self.os = "bpf"

    @staticmethod
    def is_compatible(stream):
        # FIXME
        return True


register_backend("bpf", BPF)
