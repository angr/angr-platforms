from pyvex.lifting.util import Type
from bitstring import Bits
import logging


from .b_instr import *
from .cb_instr import *
from .ci_instr import *
from .cj_instr import *
from .cr_instr import *
from .cs_instr import *
from .i_instr import *
from .j_instr import *
from .misc_instr import *
from .r_instr import *
from .s_instr import *
from .u_instr import *

l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_32
BYTE_TYPE = Type.int_8
INDEX_TYPE = Type.int_16


# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int
