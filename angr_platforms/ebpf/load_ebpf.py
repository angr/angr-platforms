import logging

from archinfo import arch_from_id
from cle.backends import ELF, register_backend

l = logging.getLogger(__name__)


class ExtendedBPF(ELF):
    """Mark extended BPF as loadable via ELF"""

    is_default = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, arch=arch_from_id("bpf"), **kwargs)
        self.os = "UNIX - System V"


register_backend("UNIX - System V", ExtendedBPF)
