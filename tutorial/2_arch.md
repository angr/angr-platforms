# Throwing a Tantrum: Extending angr with new architectures, engines, loaders, and more

# Part 2: Architectures

Since this is a tutorial about extending the core parts of angr, we should start by focusing on how to extend the core-est of core parts: the architecture support!
Pretty much every piece of angr's suite involves, in some way, specific information about the architecture of the program you're analyzing.  Dealing with all this low-level architecture stuff is part of what makes binaries a pain in the rear to analyze, but angr abstracts most of it away for you in the `archinfo` class, which is used by everything else to make the code flexible and platform-independent!

Before we can talk about how to add a new architecture, let's talk about our target:

## Our Arch: BrainFuck.

We're going to implement BrainFuck in angr, because it's one of the simplest architectures that exists, but yet is far enough from the "real" architectures angr already supports to show off its flexibility.

BrainFuck is an esoteric programming language created by Urban Muller to be simple in concept, but really painful to actually use.

BrainFuck implements a Turing machine-like abstraction, in which a infinite(ish) tape of symbols contains the program, and another tape of "cells", holds the program's state (memory).
Each cell is an unsigned byte, and the cell being referred to by instructions is chosen by the current value of a "pointer".
BrainFuck's instruction pointer starts at 0, and the program ends when it moves past the last symbols.
The data pointer starts at cell 0.

BrainFuck has only 8 instructions:

`>`: Move the pointer to the right (increment)
`<`: Move the pointer to the left (decrement)
`+`: Increment the cell under the pointer
`-`: Decrement the cell under the pointer
`[`: If the value at the pointer is zero, skip forward to the matching `]`
`]`: If the value at the pointer is non-zero, skip backward to the matching `[`
`.`: Output (print to stdout) the cell at the pointer
`,`: Input (get character at stdin) to the cell at ptr

## Defining our architecture

From the description above, we notice a few things:
* This is a "Harvard" architecture, data and memory are separate.
* We have two real registers here: A pointer `ptr`, and the usual instruction pointer `ip`.
* Memory accesses in BF are all in terms of a single byte.  There's no endianness to worry about.  However, the width of `ip` and `ptr` are not defined.
* We have to do something about input and output.

This last point is worth some discussion.
In traditional architectures, this is handled by GPIOs, or some complicated mess of peripherals driven by the OS.  We have none of that, we just want bytes in and bytes out.  We'll need to help angr out a bit with this one; there are a few possible ways to implement this, but we're going to explore one that pretends there are mythical system calls to get our bytes in and out.  In a "normal" architecture, this means there's a syscall number in a register somewhere.  We're going to pretend that exists too.

## `archinfo`

archinfo is the class in the angr suite that holds all of this information.
To create a new arch, you simply make a subclass of `archinfo.Arch`, and define your registers, their aliases, some info about bit widths and endianess, and so on.

Now, let's lay down some code.

First, some simple metadata:

```python
from archinfo.arch import Arch
from archinfo import register_arch

class ArchBF(Arch):
    bits = 64
    vex_arch = None
    name = "BF"
```
Names are usually all-caps.  As I mentioned above, the bit-width here corresponds to the address space and register widths, and we don't have one defined, so I picked 64.
VEX doesn't support this arch, so `vex_arch` is None.


Now here's the register file:

```python
    register_list = [
        Register(name="ip", size=8, vex_offset=0), alias_names=('pc',),
        Register(name="ptr", size=8, vex_offset=8),
        Register(name="inout", size=1, vex_offset=16),
        Register(name="ip_at_syscall", size=8, vex_offset=24),
    ]
```
I mentioned the 'inout' register, which is our syscall number when picking input vs output.
However, we have another fake register `ip_at_syscall`, which is used by angr to track syscall-related return behavior.  Don't worry about it, just put it here.
As you can see, you can also assign aliases, like `pc` for `ip`.


```python
    def __init__(self, endness="Iend_LE"):
        super(ArchBF, self).__init__('Iend_LE')
        ip_offset = self.registers["ip"][0]
```
Finally we add the initializer. We'll call this arch little endian, since we have to say something, and in this case it doesn't matter.
Various kinds of reasoning need to know where the ip is rather explicitly.  We set that here too.


Finally, we need to tell archinfo about our new arch:

```python
register_arch(['bf|brainfuck'], 64, 'any', ArchBF)
```
The first argument is a list of regular expressions that match the name of our architecture.  (Note, as of this writing, you can assume input is lowercase).  Next, the bit-width of our arch, which is 64.
The third argument is the `endness`, which can either be "Iend_LE", "Iend_BE", or "any".  (_these constants come from VEX, if you're curious_) 'any' means this Arch will match for either endness.

This is used by `archinfo.arch_from_id()` to look up the Arch for a given set of parameters.  Given the various circumstances under which this is needed, we deliberately make this super flexible, and encourage you to make your mappings flexible too.

That's it!

This doesn't do a whole lot yet, but it's an important first step.

We'll build on this in the next part, where we get angr to load BF programs into its simulated memory.
