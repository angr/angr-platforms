# angr-bf: Extending angr to new architectures, VMs, and more!

angr now supports creating your own architectures, lifters, engines, and more, without modifying angr itself!
You simply create classes that implement the correct interface, register them with angr, and you can use angr as normal!
The various components are designed to integrate seamlessly with the rest of angr, such that they are used automatically
when needed.

In this repository, we show off these new features by extending angr to support the BrainFuck esoteric programming language.

Yep.  Not joking.

This includes:
* `load_bf`: A loader for BF using CLE's new modular backends
* `arch_bf`: An architecture description implementing a 64-bit BF-compatible machine using Archinfo's new modular architectures
* `lift_bf`: A lifter from BrainFuck instructions to the VEX IR angr uses, which can then be executed and analyzed.  Uses pyvex's new modular lifters system, and a new suite of helpers for writing your own VEX lifters
* `simos_bf`: A SimOS for a BF environment, implementing the two syscalls ('.' and ',')
* `engine_bf`: A completely custom SimEngine, for executing BF code without using VEX at all


By default, angr relies on VEX as its intermediate representation; all binary code gets converted into a set of
VEX instructions, which get interpreted symbolically by our SimEngineVEX engine.
When adding a new language or architecture to angr, we have two options: "lift" the code to VEX, or use a custom engine
which operates on this code directly.
Whether it's easy to do one or the other really depends on how similar your target is to something VEX already supports.
Here, we provide an example of both.

Our lifter, demoed here, directly converts the `<>+-[].,` of BF into multiple VEX instructions.
In addition to making lifters modular, we also provide a set of helper functions for those writing even very
complex lifters, which can be found in `pyvex.lifting.util.vex_helper`

Example usage (with the VEX lifter):
```python
from angr_bf import arch_bf, load_bf, simos_bf, lift_bf
# The modules automatically register themselves with angr! Magic!
import angr
p = angr.Project("test_programs/hello.bf")
pg = p.factory.path_group()
pg.explore()
pg.deadended[0].state.posix.dumps(1)
>>> 'Hello World!\n'
```

The loader, when registered will put the BF program into memory, and tag it with the architecture and OS `BF`.
The lifter declares that any code passed to pyvex using the 'BF' architecture should be directed to it.
This produces regular VEX code, which is interpreted by angr the same way as if it originated with a regular
binary program.

However, this may not always be desirable.  VEX's instructions are geared towards certain kinds of
instrumentation on binaries.  Higher-level languages and VMs may not fit cleanly into VEX.
We can now remove VEX from the equation entirely, and execute the BF program itself symbolically,
by creating our own SimEngine.

Example usage (with engine_bf):
```python
from angr_bf import arch_bf, load_bf, simos_bf, engine_bf
import angr
p = angr.Project("test_programs/hello.bf")
pg = p.factory.path_group()
pg.explore()
pg.deadended[0].state.posix.dumps(1)
>>> 'Hello World!\n'
```

The loader knows when it is presented with a BF program, and will be automatically selected.
The engine, when registered, declares that it will execute anything the BF loader can handle, and will be used
instead of the VEX engine, using the BF architecture's register(s) and the correct system calls.

This is good for more than just straight execution;
You can even solve crackmes with it! Here's a silly one-byte example (provided in `test_programs`):
```python
# We're wrong if we print a '-'
bad_paths = lambda path: "-" in path.state.posix.dumps(1)
p = angr.Project(crackme)
entry = p.factory.entry_state(remove_options={angr.o.LAZY_SOLVES})
pg = p.factory.path_group(entry)
pg.step(until=lambda lpg: len(lpg.active) == 0)
pg.stash(from_stash="deadended", to_stash="bad", filter_func=bad_paths)
print pg.deadended[0].posix.dumps(0)
>>> '\n'
```

Amazing! It slices, it dices, it fucks your brain!

### Current limitations
Right now, angr cannot be trivially extended to perform complex CFG-based static analyses in a general way.
This is being worked on! Soon, you'll be able to make CFGs of your BF programs (and everything else) too!

## Extend angr to your architecture, VM, or language!!

A tutorial describing how to write your own angr components, using this one as an example, can be found in `tutorial`
