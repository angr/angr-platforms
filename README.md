# angr-bf: Demo on extending angr
This is a repo demonstrating how to extend angr to analyze the BrainFuck esoteric programming language.

This includes:
* `load_bf`: A loader for BF using CLE's new modular backends
* `arch_bf`: An architecture description implementing a 64-bit BF-compatible machine using Archinfo's new modular architectures
* `lift_bf`: A lifter from BrainFuck instructions to the VEX IR angr uses, which can then be executed with SimuVEX and analyzed statically.  Uses pyvex's new modular lifters system, and a new suite of helpers for writing your own VEX lifters
* `simos_bf`: A SimOS for a BF environment, implementing the two syscalls ('.' and ',')
* `engine_bf`: A completely custom SimEngine, for executing BF code without using VEX at all

Example usage (with engine_bf):
```python
from angr_bf import *
import angr
p = angr.Project("test_programs/hello.bf")
pg = p.factory.path_group()
pg.explore()
pg.deadended[0].state.posix.dumps(0)
>>> 'Hello World!\n'
```

Example usage (with the VEX lifter):
```python
from angr_bf import arch_bf, load_bf, simos_bf, lift_bf
# The modules automatically register themselves with angr! Magic!
import angr
p = angr.Project("test_programs/hello.bf")
pg = p.factory.path_group()
pg.explore()
pg.deadended[0].state.posix.dumps(0)
>>> 'Hello World!\n'
```

A tutorial describing how to write your own angr components, using this one as an example, can be found in `tutorial`