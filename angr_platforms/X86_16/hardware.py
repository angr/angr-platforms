from .cr import CR
from .io import IO
from .memory import Memory
from .processor import Processor


class Hardware(Processor, Memory, IO):
    def __init__(self, size: int = 0):
        super(Hardware, self).__init__()  # Processor
        super(CR, self).__init__(size)  # Memory
        super(Memory, self).__init__(self)  # IO
