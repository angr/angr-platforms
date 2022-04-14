import os
import logging
import pyvex
import angr

from angr_platforms.bf.engine_bf import UberEngineWithBF

def test_hello():
    lifters = pyvex.lifting.lifters['BF']
    pyvex.lifting.lifters['BF'] = []
    try:
        hellobf = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../test_programs/bf/hello.bf'))
        p = angr.Project(hellobf, engine=UberEngineWithBF)
        entry = p.factory.entry_state()
        smgr = p.factory.simulation_manager(entry)
        smgr.explore()
        assert smgr.deadended[0].posix.dumps(1) == b'Hello World!\n'
    finally:
        pyvex.lifting.lifters['BF'] = lifters

def test_1bytecrackme_good():
    lifters = pyvex.lifting.lifters['BF']
    pyvex.lifting.lifters['BF'] = []
    try:
        crackme = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
            '../test_programs/bf/1bytecrackme-good.bf'))
        bad_states = lambda state: b"-" in state.posix.dumps(1)
        p = angr.Project(crackme, engine=UberEngineWithBF)
        p.arch.vex_arch = None  # force test with engine
        entry = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
        smgr = p.factory.simulation_manager(entry)
        smgr.run(until=lambda lsmgr: len(lsmgr.active) == 0)
        smgr.stash(from_stash="deadended", to_stash="bad", filter_func=bad_states)
        assert b"\n" == smgr.deadended[0].posix.dumps(0)
    finally:
        pyvex.lifting.lifters['BF'] = lifters


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_hello()
    test_1bytecrackme_good()
