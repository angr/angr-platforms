import logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430
import angr
p = angr.Project("test_programs/msp430/switchLeds.elf")
simgr = p.factory.simgr()
simgr.step()
simgr.step()
simgr.step()
simgr.step()
cfg = p.analyses.CFGAccurate()
