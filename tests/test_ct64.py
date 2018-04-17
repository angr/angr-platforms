import logging
import os

from angr_platforms import ct64

def deinterlace(s):
    return ''.join(x for i, x in enumerate(s) if i % 2 == 1)

def test_crackme():
    p = ct64.load_rom(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/ct64/distribute.rom'))

    @p.hook(0x1303, length=2)
    def bug_fix(s):
        s.regs.sc3 = 14

    simgr = p.factory.simulation_manager()
    simgr.explore(
        find=lambda s: 'flag{' in deinterlace(s.posix.dumps(1)),
        )#step_func=lambda lsm: lsm.drop(stash='deadended'))

    if not simgr.found:
        assert False, "Failed to find any path containing the flag"
    out = deinterlace(simgr.one_found.posix.dumps(0))
    print repr(out)

if __name__ == '__main__':
    logging.getLogger('angr.manager').setLevel('DEBUG')
    test_crackme()
