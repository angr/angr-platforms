from .arch_rev3al import ArchRev3al
from . import instrs_rev3al as instrs
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter
import sys


class LifterRev3al(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [instrs.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs.__dict__.keys())]

register(LifterRev3al, 'rev3al')

if __name__ == '__main__':
    fname = sys.argv[1]
    with open(fname, 'rb') as f:
        data = f.read()
    #data = '\x02' + '\x00' * 7 + '\x09\x0d\x00\x00\x0f\x0b'
    print(len(data))
    l = LifterRev3al(ArchRev3al(), 0x401192)
    #l = LifterHell86(ArchHell86(), 0x0)
    l._lift(data)
    l.pp_disas()
