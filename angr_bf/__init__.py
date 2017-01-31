from arch_bf import ArchBF
from lift_bf import LifterBF
from load_bf import BF
from engine_bf import SimEngineBF

from angr import register_default_engine

register_default_engine(BF, SimEngineBF, arch='any')
