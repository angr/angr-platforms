from .arch_hell86 import ArchHell86
from . import instrs_hell86 as instrs
#from . import instrs_hell86 as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter
import sys


class LifterHell86(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterHell86, 'hell86')

if __name__ == '__main__':
    fname = sys.argv[1]
    with open(fname, 'rb') as f:
        data = f.read()
    #data = '\x02' + '\x00' * 7 + '\x09\x0d\x00\x00\x0f\x0b'
    print(len(data))
    l = LifterHell86(ArchHell86(), 0x401192)
    #l = LifterHell86(ArchHell86(), 0x0)
    l._lift(data)
    l.pp_disas()
