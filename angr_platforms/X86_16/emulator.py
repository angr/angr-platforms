from .interrupt import Interrupt


class Emulator(Interrupt):  #DataAccess,

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

