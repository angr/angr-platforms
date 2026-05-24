# x86-16 DOS and BIOS API Lowering Plan

This plan covers one specific decompiler-quality goal:

- detect DOS and BIOS API usage in real-mode x86 code
- recover arguments from registers, stack, and compiler-built `REGS`/`SREGS`
  wrappers
- render the result as natural C calls
- prefer modern/standard C calls when the mapping is truly equivalent
- otherwise render MS C specific calls or explicit interrupt-wrapper calls

This is not a transpiler feature. It is a decompiler recovery layer for API
intent.

The architecture rule remains:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

API lowering must follow that order. It must not hide storage recovery problems
inside late text rewrites.

## Current State

The current code already has a useful first slice for DOS/BIOS interrupt
recovery.

### What already exists

- A generic `InterruptCall` model and vector-aware collection in:
  - [`../angr_platforms/X86_16/analysis_helpers.py`](../angr_platforms/X86_16/analysis_helpers.py)
- Service-specific naming for DOS `int 21h` and common BIOS vectors:
  - `0x09`, `0x0E`, `0x30`, `0x39`-`0x3F`, `0x40`, `0x41`, `0x42`, `0x47`,
    `0x4A`, `0x4C`
  - `0x10`, `0x11`, `0x12`, `0x13`, `0x14`, `0x15`, `0x16`, `0x17`, `0x1A`
- Three output styles for recovered calls:
  - `pseudo`
  - `dos`
  - `modern`
- Wrapper-call classification and attachment for:
  - `int86(...)`
  - `int86x(...)`
  - `intdos(...)`
  - `intdosx(...)`
- Wrapper field-path recovery for `REGS` / `SREGS` object accesses:
  - `inregs`
  - `outregs`
  - `sregs`
- CLI and sample-matrix coverage for DOS interrupt replacements and wrapper
  lowering:
  - [`../tests/test_x86_16_cli.py`](../tests/test_x86_16_cli.py)
  - [`../tests/test_x86_16_sample_matrix.py`](../tests/test_x86_16_sample_matrix.py)
- Milestone reporting now exposes interrupt/API surface and debt counts:
  - [`../angr_platforms/X86_16/milestone_report.py`](../angr_platforms/X86_16/milestone_report.py)
- Synthetic interrupt hooks and names for BIOS/DOS vectors in:
  - [`../angr_platforms/X86_16/simos_86_16.py`](../angr_platforms/X86_16/simos_86_16.py)

### What is missing

- Wrapper results are still not fully propagated into downstream natural
  expressions such as:
  - `g_info.bios_kb = outregs.x.ax;`
  - `g_info.int21_segment = sregs.es;`
  - `g_info.int21_offset = outregs.x.bx;`
- BIOS services are still mostly conservative, wrapper-oriented recoveries:
  - `int10h` stays intentionally broad
  - `int13h` / `int14h` / `int15h` / `int16h` / `int17h` / `int1Ah` still need
    stronger service-specific lowering where evidence exists
- `REGS` / `SREGS` reconstruction is present, but it still needs better
  propagation into result-visible local variables and output fields
- Milestone reporting now shows interrupt/API lowering surface and debt counts,
  but the corpus still needs more focused BIOS/wrapper examples to keep that
  summary honest

In other words, the project already has a good `int 21h` seed, but it does not
yet have a fully complete interrupt/API lowering pipeline.

## External Surface To Match

The Microsoft C v6 headers at:

- [`/home/xor/inertia_player/dos_compilers/Microsoft C v6ax/INCLUDE/BIOS.H`](/home/xor/inertia_player/dos_compilers/Microsoft%20C%20v6ax/INCLUDE/BIOS.H)
- [`/home/xor/inertia_player/dos_compilers/Microsoft C v6ax/INCLUDE/DOS.H`](/home/xor/inertia_player/dos_compilers/Microsoft%20C%20v6ax/INCLUDE/DOS.H)

define the most important user-facing API surface we should target.

### MS C BIOS surface

- `_bios_disk(unsigned, struct diskinfo_t *)`
- `_bios_equiplist(void)`
- `_bios_keybrd(unsigned)`
- `_bios_memsize(void)`
- `_bios_printer(unsigned, unsigned, unsigned)`
- `_bios_serialcom(unsigned, unsigned, unsigned)`
- `_bios_timeofday(unsigned, long *)`
- `int86(...)`
- `int86x(...)`

### MS C DOS surface

- `bdos(...)`
- `_dos_allocmem(...)`
- `_dos_close(...)`
- `_dos_creat(...)`
- `_dos_creatnew(...)`
- `_dos_findfirst(...)`
- `_dos_findnext(...)`
- `_dos_freemem(...)`
- `_dos_getdate(...)`
- `_dos_getdrive(...)`
- `_dos_getdiskfree(...)`
- `_dos_getfileattr(...)`
- `_dos_getftime(...)`
- `_dos_gettime(...)`
- `_dos_getvect(...)`
- `_dos_keep(...)`
- `_dos_open(...)`
- `_dos_read(...)`
- `_dos_setblock(...)`
- `_dos_setdate(...)`
- `_dos_setdrive(...)`
- `_dos_setfileattr(...)`
- `_dos_setftime(...)`
- `_dos_settime(...)`
- `_dos_setvect(...)`
- `_dos_write(...)`
- `intdos(...)`
- `intdosx(...)`
- `int86(...)`
- `int86x(...)`

## Rendering Policy

### Preferred output order

1. Use a modern/standard C function when the recovered semantics are genuinely
   equivalent.
2. Otherwise use the MS C specific function if the call matches the header
   surface cleanly.
3. Otherwise render `int86(...)`, `int86x(...)`, `intdos(...)`, or
   `intdosx(...)` with reconstructed `REGS` / `SREGS`.
4. Otherwise fall back to a typed pseudo helper like `bios_int10_video(...)`
   or `dos_int21(...)`.
5. If evidence is still weak, keep explicit interrupt-shaped code instead of
   guessing.

### Safe modern mappings

These are already partly implemented on the DOS side and should remain
preferred when argument recovery is strong:

- `open`
- `creat`
- `close`
- `read`
- `write`
- `lseek`
- `mkdir`
- `rmdir`
- `chdir`
- `unlink`
- `exit`

### Cases that should stay MS C specific

- `_bios_disk`
- `_bios_equiplist`
- `_bios_keybrd`
- `_bios_memsize`
- `_bios_printer`
- `_bios_serialcom`
- `_bios_timeofday`
- `int86`
- `int86x`
- `intdos`
- `intdosx`
- DOS APIs with no strong modern equivalent in the local recovery context

### Cases that should usually not be guessed into modern libc

- `int 10h` video services
- `int 13h` disk services unless they clearly match `_bios_disk(...)`
- `int 15h` mixed system services
- vector-management paths that should stay `_dos_getvect` / `_dos_setvect`
- services whose original C surface is naturally `int86/int86x`

## Main Recovery Problem

There are really two input forms, and they need different treatment.

### A. Direct interrupt form

Examples:

- `int 21h`
- `int 10h`
- `int 12h`
- `int 16h`

Recovery problem:

- collect pre-interrupt register state
- determine service identity from `AH`, `AL`, `AX`, and other regs
- map input/output registers to C arguments/results

### B. Compiler wrapper form

Examples:

- `call _int86`
- `call _int86x`
- `call _intdos`
- `call _intdosx`

Recovery problem:

- recover stack arguments to the wrapper call
- recover `inregs`, `outregs`, `sregs` object shapes
- understand stores into those objects before the call
- understand reads from those objects after the call
- render a natural wrapper call or a stronger `_bios_*` / `_dos_*` call

The wrapper form matters a lot because real MS C code often expresses BIOS and
DOS APIs through `int86` / `int86x` rather than raw `int` instructions.

## Remaining Work

### 1. Propagate wrapper results into natural expressions

- `Priority`: `P0`
- `What remains`:
  - turn post-call reads like `outregs.x.ax`, `outregs.x.bx`, and
    `sregs.es` into output-visible result flow instead of only cached wrapper
    metadata
  - preserve the return/result meaning of `int86x` / `intdosx` callsites in
    the final C
- `Why it still matters`:
  - the lowering layer should explain both the call and the result, not just
    the callsite name
- `Current code basis`:
  - wrapper field-path collection already exists in
    [`../decompile.py`](/home/xor/vextest/decompile.py)
  - result-flow propagation still needs stronger use of that evidence

### 2. Make BIOS-specific lowering stronger where evidence is clear

- `Priority`: `P1`
- `What remains`:
  - keep `int10h` conservative by default, but add stronger lowering when the
    service and arguments are clearly known
  - expand direct BIOS handling where the output is still too wrapper-oriented
  - avoid pretending all BIOS calls are just `int86(0x10, ...)`
- `Why it still matters`:
  - BIOS calls are common in real DOS code and need readable, evidence-driven
    output
- `Current code basis`:
  - the service table and helper naming already exist in
    [`../angr_platforms/X86_16/analysis_helpers.py`](../angr_platforms/X86_16/analysis_helpers.py)

### 3. Add explicit corpus tests for BIOS and wrapper lowering

- `Priority`: `P1`
- `What remains`:
  - add focused tests for the remaining BIOS/wrapper output shapes
  - keep result-flow regressions stable for the new lowering work
- `Why it still matters`:
  - this path is only useful if the corpus keeps it honest
- `Current code basis`:
  - existing coverage already validates `int21h`, `int86`, `int86x`, and some
    BIOS service naming

### 4. Keep wrapper/service lowering layered

- `Priority`: `P0`
- `What remains`:
  - keep detection, rendering, and result propagation separate
  - do not move service recovery into final text rewrites
  - keep alias/type/object facts as the source of truth
- `Why it still matters`:
  - this is the main guardrail that keeps API lowering from turning into a bag
    of hacks

## Testing Plan

### Unit-level

- service-table tests for DOS and BIOS mappings
- allowed/forbidden register-field reconstruction tests
- `REGS` / `SREGS` field extraction tests
- wrapper argument recovery tests

### Focused corpus tests

- existing `int 21h` sample-matrix cases stay green
- add explicit `int 10h`, `int 12h`, and `int 86x` focused cases from:
  - [`../x16_samples/ISOD.COD`](../x16_samples/ISOD.COD)
  - [`../x16_samples/IMOD.COD`](../x16_samples/IMOD.COD)
  - [`../x16_samples/intdemo.c`](../x16_samples/intdemo.c)
- add `.COD` and CLI anchors for:
  - wrapper-call rendering
  - BIOS helper rendering
  - output-field propagation

### Scan-safe / corpus visibility

- reports should count:
  - recovered DOS helper calls
  - recovered BIOS helper calls
  - recovered wrapper calls
  - unresolved interrupt-wrapper sites

## Suggested Execution Order

1. Generalize `collect_dos_int21_calls(...)` into generic interrupt-call
   recovery.
2. Add declarative DOS and BIOS service metadata tables.
3. Build wrapper-call classification for `int86/int86x/intdos/intdosx`.
4. Recover `REGS` / `SREGS` arguments and field writes.
5. Recover post-call `outregs` / `sregs` reads.
6. Add MS C BIOS mappings for the low-ambiguity services.
7. Add conservative `int 10h` wrapper-oriented rendering.
8. Integrate all of the above into milestone reporting and CLI coverage.

## Short Success Criterion

This work is going in the right direction when:

- more DOS and BIOS sites become natural C calls
- wrapper-built interrupt calls become readable instead of anonymous stack
  traffic
- `int 10h` and similar BIOS families become understandable without unsafe
  guessing
- fewer interrupt-related wins depend on one-off source rescues

This work is going in the wrong direction when:

- every new interrupt service needs another hardcoded final-text rewrite
- wrapper-call arguments are guessed without object recovery
- BIOS services are forced into fake modern APIs with weak evidence
- the decompiler hides unresolved interrupt sites instead of classifying them
