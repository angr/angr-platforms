import logging

from cle.backends import ELF, register_backend

l = logging.getLogger(__name__)


class Ebpf(ELF):
    is_default = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.os = "UNIX - System V"


register_backend("UNIX - System V", Ebpf)
