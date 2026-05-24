# Dream Decompiler Execution Plan

This document is the live execution roadmap for the remaining "dream
decompiler" work.

Completed baseline and recovery milestones are intentionally omitted. Finished
work belongs in tests, milestone artifacts, and narrower execution plans, not
in this rolling roadmap.

The target architecture stays:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

For x86-16, the ownership boundary stays:

- `angr`: loader, CFG, VEX lift, fallback/reference decompiler
- `Inertia IR`: typed semantic reasoning layer

That means future quality work should prefer:

- richer Inertia-owned `Value` / `Address` / `Condition` objects
- an explicit distinction between:
  - block-local typed IR
  - CFG-level typed IR with merge/phi nodes
- alias and widening on typed storage
- explicit segmented-memory state
- explicit condition/flag meaning
- explicit string-instruction memory effects and repeat semantics in typed IR when they affect readable C recovery
- obfuscation-tolerant semantic recovery from typed effects and CFG facts rather than compiler-pattern assumptions

And should avoid:

- leaning on AIL as the long-term reasoning substrate
- leaving segmented memory or conditions as hidden VEX-temp trivia
- leaving string-instruction semantics as timeout-only fallback debt when they can be expressed in typed IR
- depending on compiler-shaped idioms when the same behavior can be recovered from typed semantics for hand-written or obfuscated code
- blurring block-local typed IR and CFG-level merged IR into one vague layer

For the narrower whole-corpus operational plan focused on:

- whole `.COD` traversal
- no crashes
- no blind spots
- steadily improving readability

see:

- [`x86_16_cod_corpus_completion_plan.md`](./x86_16_cod_corpus_completion_plan.md)

## Priority Scale

- `P0`: foundation work that unlocks multiple later steps
- `P1`: high-impact quality work for the current target corpus
- `P2`: important follow-up work after the recovery foundation is stable
- `P3`: polish, breadth, or extension work

## Complexity Scale

- `Low`: small and bounded change, low architecture risk
- `Medium`: multi-file change or pipeline boundary change
- `High`: changes core recovery logic or cross-pass interaction
- `Very High`: architecture-shaping work with serious regression risk

## Phase A. Stable Platform

This phase stays live because scan stability and instruction-core hygiene are
continuous prerequisites for all later recovery work.

### A1. Close Real Corpus Blocking Opcode Gaps

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - prevents decompilation from failing before recovery even starts
  - reduces time wasted debugging "quality" issues that are really lift/runtime
    issues
- `Low-level steps`:
  - keep mining `.COD` and sample-matrix binaries for blocking mnemonics
  - add compare-style semantics tests for instructions that still block real
    code
  - add focused lift/decompile regressions for each newly unblocked sample
  - use MartyPC as a reference when an instruction family still needs clearer
    semantic factoring or flag/stack/control-transfer organization
- `Exit signal`:
  - new real-sample failures are more often readability/recovery failures than
    missing opcode failures
- `Deterministic goal`:
  - each newly blocked mnemonic is tied to one focused regression and one named
    semantic family
  - the remaining blocking gap list shrinks only when the associated compare or
    corpus test is green

### A2. Keep Loader, Runtime, and Interrupt Baseline Stable

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps `.EXE` / `.COM` analysis viable
  - stops execution or CFG issues from polluting decompilation work
- `Low-level steps`:
  - keep DOS MZ loader regressions green
  - preserve DOS/BIOS interrupt behavior needed by the current sample corpus
  - extend bounded far-call and whole-binary recovery helpers only when a real
    sample needs it
- `Exit signal`:
  - loader/runtime changes are mostly maintenance, not the main blocker for new
    corpus cases
- `Deterministic goal`:
  - DOS MZ, far-call, and interrupt baseline regressions stay green across
    sample-matrix and corpus runs
  - loader/runtime changes must not increase crash or unknown-failure counts

### A3. MartyPC-Style Instruction-Core Factoring

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps instruction semantics easier to reason about and test
  - reduces the chance that future 386 real-mode additions will be bolted onto
    16-bit handlers as special cases
  - improves scan stability and semantic readability for hot paths such as
    string ops, stack ops, ALU flags, and control transfer
- `Low-level steps`:
  - keep instruction families split into small semantic helpers instead of one
    large handler
  - keep ALU flag updates centralized and width-parametric
  - keep string, stack, and near/far control-transfer helpers separate
  - make instruction semantics width-extensible so 32-bit operand-size support
    can be added later without rewriting the 16-bit baseline
  - treat future 386 real-mode instructions with 16-bit addressing as a
    mixed-width extension of the same instruction-core, not a separate
    architecture
- `Dependencies`:
  - `A1`
  - `A2`
- `Exit signal`:
  - new instruction support can be added with small, width-aware helpers rather
    than ad hoc branching in existing 16-bit handlers
- `Deterministic goal`:
  - every new instruction-family fix lands in a small helper or shared family
    module
  - address-size, operand-size, stack, string, ALU, and branch semantics remain
    separable in code and tests

## Reference Implementation Notes: MartyPC

MartyPC is not a decompiler, but it is a useful reference implementation for
the instruction-core side of the x86-16 stack. The most useful patterns to
borrow are:

- split instruction families into small semantic modules instead of one
  monolithic executor
- keep string operations explicit, with side effects and direction-flag updates
  localized
- centralize ALU flag updates instead of scattering flag logic across
  instruction handlers
- keep near/far jump, call, return, and interrupt paths separate and explicit
- make stack push/pop semantics simple and reusable
- keep operand width and address width as separate concepts so future 386
  real-mode instructions with 16-bit addressing do not contaminate the current
  16-bit baseline
- make mixed-width instruction semantics width-extensible from the start,
  especially for ALU, shifts/rotates, and stack/control-transfer helpers

For Inertia, these ideas are low-level guidance for x86-16 maintenance work,
not a replacement for the alias/widening/type pipeline. The practical order is:

1. keep instruction handlers in small semantic groups
2. prefer shared helpers for repeated flag, stack, and control-transfer
   behavior
3. use MartyPC-style clarity when cleaning up handlers that still affect scan
   stability or real-sample correctness
4. keep operand-size and address-size concerns explicit so the future 386
   real-mode path can remain a bounded extension of the same helpers
5. keep these instruction-level patterns downstream of the architecture
   boundary already fixed in `IR -> Alias model -> Widening -> Traits -> Types
   -> Rewrite`

For a more concrete comparison between Inertia and MartyPC, with file-level
gaps and a priority-ordered practical improvement plan, see:

- [`x86_16_martypc_improvement_plan.md`](./x86_16_martypc_improvement_plan.md)

## Remaining Roadmap

## Remaining Working Order

If we compress the remaining roadmap into the next major execution sequence, the
best order is:

1. keep the scan lane and baseline stable
2. keep instruction-core factoring clean as new blockers appear

## Stop Rules

Pause and reassess if:

- widening starts producing more wrong code than it removes
- object/type recovery becomes prettier but less honest
- alias work adds complexity without reducing local special cases
- new wins keep requiring one-off rescues instead of becoming reusable

## Success Signal

This plan is working if each major layer:

- explains multiple older wins with one architectural idea
- reduces the number of local hacks needed for new corpus cases
- improves both correctness and readability together
- leaves the test discipline stronger than before
