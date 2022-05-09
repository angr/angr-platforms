# The angr Platforms collection

This is a collection of extensions to angr to handle new platforms!

Here you can find the following:

* ```BrainFuck support (yes, really)``` (by @subwire) Includes a arch description, loader, VEX lifter, native symexec engine, SimOS

* ```TI MSP430 Support``` (by @subwire and @nilocunger) Arch, VEX lifter, SimOS; Uses ELF or Blob to load binaries

* ```Berkeley Packet Filter (BPF)``` (by @ltfish) 

* ```CyberTronix64k support``` (by @rhelmot) Demonstrates how to support arches with odd byte-widths (16-bits), and uses memory-mapped registers and mmio.

* ```[WIP] Atmel AVR support``` (by @subwire, and maybe you!) WIP branch at https://github.com/angr/angr-platforms/tree/wip/avr

* ```[WIP] Hitachi SH4 support``` (by @pwnslinger) https://github.com/angr/angr-platforms/tree/wip/ikaruga

* ```Tricore support``` (by @shahinsba) 

The core idea here is that angr and its components are extensible through _registration_ -- a method, such as `pyvex.lifting.register()` can be used to include your out-of-tree code into angr's automatic consideration.
Through these mechanisms, you can write new architectural descriptions, laoders for new binary formats, lifters for new instruction sets, new simulated execution environments (SimOSes).  You can even create entirely new execution engines that operate on instructions other than the VEX IR.

A set of tutorials, providing a walkthrough of these components, how they interact, and how to write them, can be found here: https://github.com/angr/angr-platforms/tree/master/tutorial

