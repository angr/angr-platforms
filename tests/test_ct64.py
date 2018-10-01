import logging
import os

from nose.plugins.attrib import attr
from angr_platforms import ct64

def deinterlace(s):
    t = b''
    for n, x in enumerate(s):
        if n % 2 == 1:
            t += bytes([x])
    return t
def test_quick_ct64():
    p = ct64.load_rom(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/ct64/distribute.rom'))
    simgr = p.factory.simulation_manager()
    simgr.run(n=100)
    assert len(simgr.active) == 6
    for active in simgr.active:
        assert active.posix.dumps(0) != b''
        assert deinterlace(active.posix.dumps(1)) == b'PASSWORD: '

@attr(speed='slow')
def test_crackme():
    p = ct64.load_rom(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/ct64/distribute.rom'))

    @p.hook(0x1303, length=2)
    def bug_fix(s):
        s.regs.sc3 = 14

    simgr = p.factory.simulation_manager()
    simgr.explore(
        avoid=[0x12cc, 0x1316, 0x1338, 0x14c9],
        find=0x1608,
        step_func=lambda lsm: lsm.drop(stash='deadended'))

    if not simgr.found:
        assert False, "Failed to find any path containing the flag"
    out = deinterlace(simgr.one_found.posix.dumps(0))
    print(repr(out))

if __name__ == '__main__':
    logging.getLogger('angr.sim_manager').setLevel('DEBUG')
    test_quick_ct64()
    test_crackme()
