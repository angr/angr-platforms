# Part 4: Lifting Code to VEX with Gymrat

In order for angr to perform any sort of analysis on binary code, we need to first translate, or lift, this code into an intermediate representation (IR) that angr uses, called VEX.

VEX is the IR used by the Valgrind analysis tools. angr uses the libvex library also used by Valgrind, etc. to lift code, and uses its `pyvex` package to provide a pythonic interface to the resulting IR objects.

However, libvex and Valgrind were tailor-made for doing what they do best: analyzing lots of desktop-ish programs.  What if we want to do something super non-traditional? Like Brainfuck? Or even something a bit more reasonable like MSP430.

That's where the `gymrat` framework included with newer versions of pyvex comes in. Gymrat's goal is to make lifting just about anything easy, by moving the focus from messing with parsing and bits and what not, to simply and quickly specifying what the instructions actually _do_, which is magically translated into VEX.

## Building your workout plan

Before you jump into lifting, you're going to need some sort of plan on how to structure your lifter, to make the process easier, and to make auditing the result less painful.

## Know your body

The most important part of this planning process is becoming familiar with your chosen architecture, and particularly its instructions. We touched on `archinfo` in a previous part of this tutorial, and we assume you have already built the `archinfo` class for your architecture, with all of the register maps, and so on. In this section, we will be using the BF and MSP430 examples introduced earlier to demonstrate how we designed the lifters, and why.

Your first step should be to find an Instruction Set Architecture (ISA) document, containing, at least, the binary formats for the instructions, and hopefully a precise description of their effects of the processor.

A few questions to ask yourself while reading:

* How are the instructions formatted? Are there a few formats that cover all possible instructions? Or is each instruction different? Is there the notion of an "opcode"?
* How are arguments to the instructions specified? registers, memory address, intermediats, offsets, etc
* What are the primary side-effects of instructions? (e.g., flags)

Let's consider our example of MSP430.  See (https://www.ti.com/sc/docs/products/micro/msp430/userguid/as_5.pdf) for one of many references.
MSP430 instructions take one of three types, having zero, one or two operands.
One operand instructions take the form src = src (op) src. Two-operand instructions take the form dst = src (op) dst. Zero-operand instructions are conditional jumps, and merely have a condition code, and a 10-bit immediate destination address offset. Each format has its own notion of "opcode".

MSP430 supports a wide variety of possible sources and destinations, based on addressing mode bits, and special register values, contained in each instruction. Operands can be the usual register contents, or can be combined with an immediate 16-bit extension word.
Instructions also support handling data of different sizes, either an 8-bit byte, or a 16-bit word, based on a flag.
Instructions can set one of four flags (Carry, Negative, Zero, and Overflow), although the behavior of these is far from unifrom.

This means, in summary, that there is some logic that's common to all instructions, and some common to each type.  There are, of course edge cases, but all of this can be specified neatly using `gymrat`.

## Know your equipment

Here we will introduce briefly the primary classes used to write a lifter using `gymrat`.
All of the following are contained in `pyvex.util`:

### GymratLifter
This is the actual lifter class used by `pyvex`.
You will need to make a subclass of this, and provide a property `instrs` containing a list of possible instruction classes.
`GymratLifter`s are provided with a block of code to lift in their constructor, and when `lift()` is called, will iterate through the code, matching instruction classes to the bytes, and populating an IRSB object (IR Super Block) with the appropriate VEX instructions. This IRSB gets returned eventually to angr, and used for its analyses.
By default, GymratLifter will try using every instruction contained in `instrs` until one succeeds.
Don't forget to call `pyvex.lifting.register()` to tell pyvex that your new lifter exists.

### Type
In the binary world, a "type" here merely denodes how many bits wide a value is, and how it is interpreted (int, float, etc)
This class uses "type imagination", don't worry about what sizes it supports, it will make them up for you.
Simply use `Type.int_16` for a 16-bit integer, or even `Type.int_9` if you really want to (cLEMENCy you say? Yeah, we can do that.)
You'll see these mentioned around as the argument named `ty`.

### Instruction
You should create a class for every instruction in your architecture, which should be subclasses of `Instruction`.  Instructions receive the bitstream given to the lifter, and attempt to match it with a format string (`self.bin_format`), which both identifies that this is the correct instruction, and parses the various operands and flags.  Format strings are specified similar to how many ISA documents will; for example, a 2-operand instruction, with fixed bits of 1101, and 2x2 bits of mode flags, could look like `1101ssssmmddddMM`.  The instruction would only match if it started with 1101, and each similarly-lettered bit would be extracted into a dictionary keyed by the letter.

The Instruction class has a number of methods designed by overriden by its subclasses, to modify behavior for each instruction or instruction type.
Here's a brief summary:
* `parse`: Called by the lifter to try and match the instruction.  Returns a dictionary of parsed bits on success, or does something else (raise) on failure
You may want to extend this to implement changes in how data is parsed, based on previous parsed values (e.g., get an extra word if a flag is set)
* `match_instruction`: Optionally implement this to match the instruction based on a bit format symbol; for example, you could use `o` as your opcode, and match it here.  Return something on success, raise on failure.
* `lift`: Called by the lifter after the instruction is matched. By default, it simply calls all of the following functions in order, but you can override this to change this or add your own.
* `mark_instruction_start`: Should be called at the beginning of lifting, creates the VEX `IMark` instruction of the correct length.
* `fetch_operands`: Implement this to specify how operands are fetched.  You'll probably want to use `get()` and `load()` below.
* `compute_result`: This is where the meat of your instruction goes. Compute the actual result, and return a VexValue of the result. You will make heavy use of the `VexValue` syntax helpers here; for example, a normal add could simply be `return src + dst` You should also commit your result using `put` or `store, unless you chose to do that somewhere else.
* `compute_flags`: Compute and store the flags affected by the instruction. Gets the same arguments as `compute_result`, plus the addition of the computed result, to make flag expressions easier.

Instruction also contains a few important methods meant to be called by its subclasses to implement the above methods.
* `get(reg_num, ty)` Get register from a physical machine register into a temporary value we can do operations on.
* `load(addr, ty)`: Similar to the above, but loads from a given address in memory
* `put(val, reg_num)`: Puts a given temporary value into a physical register.
* `store(val, addr)`: Store a given value at an address in memory
* `jump(when, where)`: Conditionally jump to a given location
* `constant(int_val, ty)`: Creates a temporary values from an integer constant.
(Note: there is also `ccall()`; If you have something really messed up you don't think you can express correctly, such as something that needs extensive runtime information, you may need a ccall, but try to avoid it if you can.  See the python docs for info.)

### VexValue
What are all these 'temprary values'? How do I actually specify what instructions do? That's the magic of `VexValue`.
In VEX, you cannot do operations directly on registers or memory.  They must be first loaded into a temporary variable, operated on, and then written back to the registers or memory.  We wanted the lifter author to think as little about this as possible, so VexValue makes this whole process a snap.

A VexValue can be created in two different ways: by loading it out of the machine's state using `get()` or `put()`, or by creating a constant value with `constant()`.  You can then do normal python operations to them like any other value!
VexValues have a set `Type` when they are created; you can cast to a new type using the `cast_to(ty)` method.
You can even fetch bits using python's slice and index notation!

Here's an example, the xor instruction from our MSP430 lifter.
Of course you have to xor, but what about the types? What's the VEX operation for xor? Weird expressions for the flags?

Nah.

```

    def compute_result(self, src, dst):
        return src ^ dst
```

Or something boolean:
```
    def carry(self, src, dst, ret):
        return ret != 0
```

It's pretty magic.

## Use the proper form

As in exercise, using the proper form when lifting is better for your health, and just makes things work better.
Its time to put the two sections above together and make your lifter's design. A good lifter design, like any other piece of software, must minimize the amount of repetative code, while still being readable.  In particular, we'd like to make the structure of our lifter as close to that of the documentation, to allow for better manual auditing.

Let's walk through the design of our MSP430 lifter.  We'll come back to the BF example later; it's too simple for this discussion.

As mentioned above, there are a lot of common tasks all MSP430 instructions must do, such as resolving the operands and addressing modes, grabbing the immediate extension words, and the write-back of the results of operations. These are defined in `MSP430Instruction`, a direct subclass of `Instruction`.
We'll also define how the Status Register (flags, in `compute_flags`) works, and how the four flags are packed inside when it is updated.
Because the three types have their own opcode, we define `match_instruction` to check the `o` symbol here. As a final step, how values are committed to the machine's state is dependant on the addressing mode (writing to a register, vs indexing into memory, etc), and is handled in this class as well; we expect `compute_result` to return the value to be written out, or None if that instruction doesn't commit.

We will then define a class for each of the three types. These will set the `bin_format` property, as well as overriding `fetch_operands` to resolve the source and/or destination registers/immediates/etc, and simply return `src` and `dst`, which are passed to the instructions` `compute_result` methods.

Finally, we will create a class for each instruction, subclassing the appropriate type, and providing only the `opcode` (to be matched in `match_instruction`), the `compute_result` function, which returns the value to be committed, and the computation of any flags the instruction modifies.

## Time to get swole!

While we aimed these features to spare the user from thinking about an IR as much as possible (did you notice we told you almost nothing about how the IR actually works?), there's no magical formula for getting totally shredded, or for lifting every architecture.  CPU architecutres, like human bodies, are different, and have their own quirks, so the best thing we can do is give you really in-depth examples.

Our fully commented example, which lifts MSP430 binary code into VEX, can be found [here](https://github.com/angr/angr-platforms/blob/master/angr_platforms/msp430/instrs_msp430.py). You can also find the, much simpler, BF lifter [here](https://github.com/angr/angr-platforms/blob/master/angr_platforms/bf/lift_bf.py).

Built a really rad lifter? [Let us know on Slack](http://angr.io/invite.html)

Next time, we get to talk about execution engines! Better get fueled up.
