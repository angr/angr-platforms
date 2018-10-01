# Throwing a Tantrum: Extending angr with new architectures, engines, loaders, and more

# Part 3: The Loader

Now we're going to focus on the first actual step in the process of analyzing a program: Figuring out what it even is, and loading it into our system's memory somehow.

## CLE: CLE Loads Everything

The angr suite uses `CLE` to load binaries.
It serves as a logical implementation of the Linux loader first and foremost, but supports other OSes and formats through a series of "backends".

CLE is given, by angr, a path to the "main binary".  This is the argument to angr.Project().
It's CLE's job to open it, figure out what it is, figure out what architecture it is (unless the user overrides), figure out where in memory it's supposed to go, and load any dependencies, such as shared libraries, that it may depend on.

## Shortcut: What if my architecture uses ELF files?

You don't need to do anything; CLE will load your binary just fine.  However, you will need to tell angr which sorts of ELF files map to the correct SimOS environment model, described in section 6.  These are tracked by the content of their EI_OSABI field.

If you have pyelftools installed, you can identify this simply like this:
```
% readelf.py -h switchLeds.elf
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 ff 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            Standalone App
  ABI Version:                       0
```

To register this with our MSP430 environment model, we would simply do:
```
from angr.simos import register_simos
register_simos('Standalone App', SimMSP430)
```

Were your binaries made by orcs instead? Read on.

## Defining the BF backend

For BrainFuck, we really just need to read the program in, and put it in memory, rather straight-up, at address 0.
You could get away with using the `Blob` loader backend directly to do this, but we're going to make it a little more explicit and demonstrative and define our own based on it.

First, the boring stuff:

```python
from cle.backends import Blob, register_backend
from archinfo import arch_from_id
import re
import logging
l = logging.getLogger("cle.bf")
__all__ = ('BF',)

class BF(Blob):
    def __init__(self, path, offset=0, *args, **kwargs):

        super(BF, self).__init__(path, *args,
                arch=arch_from_id("bf"),
                offset=offset,
                entry_point=0,
                **kwargs)

```
Normally, to use the Blob loader, you must specify an entry point and arch *manually*.
We want to be able to just use angr.Project() on a BF program and have it work, so we subclass the Blob loader, and give it this information.

Next, we need to tell CLE when this loader will work on the given file, so that it can pick the right backend.
Technically, by many definitions of BF, you can have other non-instruction characters in a file and still have it be valid.  For the ease of demonstration, let's keep it simple and support the "non-compatible" BF syntax of only the instructions and newlines.

```python
    @staticmethod
    def is_compatible(stream):
        bf_re = re.compile('[+\-<>.,\[\]\n]+')
        stream.seek(0)
        stuff = stream.read(0x1000)
        if bf_re.match(stuff):
            return True
        return False
```

Don't forget to seek the stream to 0!! Some other `is_compatible`, or the rest of CLE, is going to use it later.  As they used to say when I was a kid, "Be kind, rewind" :)

Last but not least, we need to tell CLE about our backend.

```python
register_backend("bf", BF)
```

That's it?? That's it.

If you want to see a more complex, but not too-complex example on something a bit less contrived, check out CLE's CGC backend.  CGC binaries are deliberately simplified ELF-like files, that were designed to make analysis easy, so they make a nice template for crazier formats.

Next time, we get to talk about lifters! Get that protein powder ready.
