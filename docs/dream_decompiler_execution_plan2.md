# Dream Decompiler Execution Plan 2

This document is the current execution roadmap for Inertia's x86-16 decompiler
work.

It is a more operational follow-up to
[`dream_decompiler_execution_plan.md`](dream_decompiler_execution_plan.md).
The original plan describes the architectural intent; this document turns that
intent into a concrete order of work, status tracking, and exit criteria.

The architecture invariant stays the same:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

The decompiler should keep improving readability and correctness by pushing
recovery earlier in that pipeline, not by growing the late rewrite layer.

## Current State Snapshot

The source tree already contains the following stable surfaces:

- alias storage facts and join checks in `angr_platforms/X86_16/alias_model.py`
- alias state and register/stack transfer helpers in
  `alias_state.py` and `alias_transfer.py`
- explicit widening candidate/proof logic in `widening_model.py`
- recovery layer metadata in `recovery_manifest.py`
- validation tiers in `validation_manifest.py`
- milestone reporting in `milestone_report.py`
- bounded late postprocess passes in `decompiler_postprocess*.py`
- source-backed rewrite registry and status reporting in
  `cod_source_rewrites.py`

The current roadmap gap is narrower than the original document suggests:

- `A1` is still open
- `A2` is still open
- `A3` is still open

Everything else in the checked-off recovery backlog is either implemented,
test-covered, or represented by explicit registry/report layers.

## Priority Rules

Use the same priority scale as the original plan:

- `P0`: foundation work that unlocks multiple later steps
- `P1`: high-impact quality work for the current target corpus
- `P2`: important follow-up work after the recovery foundation is stable
- `P3`: polish, breadth, or extension work

Planning guidance:

- do not introduce new special cases when an existing recovery layer can absorb
  the case
- prefer evidence objects and explicit policy gates over local heuristics
- keep late rewrite thin
- keep tests close to the layer they validate
- do not broaden the alias model unless corpus evidence forces it

## Working Order

If the team is choosing the next feature or fix, do the work in this order:

1. keep the scan lane stable
2. close remaining instruction and loader/runtime blockers
3. strengthen segmented-memory association policy
4. finish object and type recovery on stable evidence
5. finish prototype and calling-convention recovery
6. keep late rewrite honest and narrow
7. retire guarded rescues into tests or the general pipeline

This order is intentionally conservative. The goal is to improve output quality
without making the recovery stack harder to reason about.

## Phase 0. Baseline And Guard Rails

Status: mostly done, must be preserved.

Purpose:

- keep the decompiler usable while recovery work continues
- ensure regressions are visible quickly
- keep the architecture boundaries explicit

Existing implementation anchors:

- alias API and join logic: `alias_model.py`
- widening pipeline and proof layer: `widening_model.py`
- recovery registry: `recovery_manifest.py`
- validation tiers: `validation_manifest.py`
- milestone summary: `milestone_report.py`
- package exports and bootstrap wiring: `__init__.py`

Exit criteria:

- the recovery surfaces remain importable and stable
- the report/validation layers continue to describe the current system
- new work does not bypass the alias/widening boundary

## Phase 1. Close The Remaining Platform Gaps

Status: active.

### 1.1 Close Real Corpus Blocking Opcode Gaps

Priority: `P1`

What to do:

- keep mining `.COD`, `.COM`, and `.EXE` samples for blocking mnemonics
- add compare-style semantics tests for instructions that still block real
  corpus code
- add focused lift/decompile regressions for each newly unblocked sample
- keep instruction semantics factored into small helpers when a family gets
  complicated

Implementation focus:

- reduce the number of cases where analysis fails before recovery starts
- keep flag, stack, string, and control-transfer logic easy to inspect
- keep width handling explicit

Exit criteria:

- real-sample failures are mostly recovery/readability failures, not missing
  opcodes
- new instruction support lands in bounded helpers instead of ad hoc branches

### 1.2 Keep Loader, Runtime, And Interrupt Baseline Stable

Priority: `P1`

What to do:

- keep DOS MZ loader regressions green
- preserve DOS/BIOS interrupt behavior needed by the current corpus
- extend far-call and whole-binary helpers only when a real sample needs it
- keep runtime changes from leaking into decompiler recovery logic

Implementation focus:

- `.EXE` and `.COM` analysis must remain reliable
- loader/runtime bugs should not be mistaken for decompiler quality bugs

Exit criteria:

- loader/runtime changes are maintenance work, not the main cause of new
  corpus failures

### 1.3 Finish Instruction-Core Factoring

Priority: `P2`

What to do:

- keep instruction families split into small semantic helpers
- centralize ALU flag updates where width-parametric logic belongs
- keep string, stack, near-call, far-call, and interrupt helpers separate
- make mixed-width instruction semantics extensible without rewriting the
  16-bit baseline

Implementation focus:

- remove accidental coupling between unrelated instruction semantics
- keep future 386 real-mode additions as a bounded extension of the same core

Exit criteria:

- new instruction support can be added with small width-aware helpers
- hot-path semantics remain readable and testable

## Phase 2. Strengthen Alias And Widening

Status: implemented in core form, but still a maintenance and correctness area.

### 2.1 Keep The Alias API Stable

Priority: `P1`

Current state:

- `same_alias_storage_domain`
- `compatible_alias_storage_views`
- `needs_alias_synthesis`
- `can_join_alias_storage`

Next work:

- keep register, stack-slot, and segmented-memory cases on the same API shape
- remove any remaining direct shape-guessing callers
- extend the API only when corpus evidence needs it

Exit criteria:

- downstream passes use alias helpers instead of their own storage heuristics

### 2.2 Keep Widening Explicit And Debugeable

Priority: `P1`

Current state:

- candidate extraction
- explicit proof layer
- join decision layer

Next work:

- keep register pair widening, stack pair widening, segmented-load widening,
  and projection-style shapes all routed through the same widening vocabulary
- keep proof failures visible in tests and debug reports
- keep widening decisions separate from the final rewrite choice

Exit criteria:

- widening always starts from an explicit candidate list
- widening is accepted or rejected by a proof object, not by hidden ad hoc
  branching

### 2.3 Keep Store-Side Widening Conservative

Priority: `P2`

What to do:

- start with stable stack-slot store pairs
- extend to segmented-memory store pairs only when association is strong
- preserve widths and reject mixed/overlapping unsafe cases
- verify on corpus cases where adjacent byte stores still survive into C

Exit criteria:

- adjacent byte stores are widened only when safety is proven

## Phase 3. Finish Object Recovery

Status: partially implemented, still being strengthened by evidence policy.

### 3.1 Segmented Memory Association

Priority: `P1`

What to do:

- keep `ss`, `ds`, and `es` distinct as storage spaces
- classify base association as `single`, `const`, or `over-associated`
- make object-lowering conditional on stable association
- extend association checks from local shape matching toward function-level
  reasoning

Exit criteria:

- pointer-like lowering in segmented code is driven by explicit association
  state

### 3.2 Segment-Aware Object Roots

Priority: `P2`

What to do:

- define stable roots for `ss:frameoff`, `ds:const/global`, and helper-produced
  stable bases
- keep segment identity attached to the root
- let object candidates form only from stable roots that survive association
  policy gates

Exit criteria:

- field and array recovery operate on segment-aware roots instead of raw
  arithmetic alone

### 3.3 Stable Stack Object Recovery

Priority: `P1`

What to do:

- preserve stable stack objects as explicit locals and arguments
- keep byte and word subviews attached to one stack family
- reject early overmerge across distinct stack regions
- keep stack annotations and typed stack evidence flowing into the object layer

Exit criteria:

- stack code looks object-like and width-stable instead of byte-slice-heavy

### 3.4 Stable Global Object Recovery

Priority: `P2`

What to do:

- distinguish scalar globals from object roots
- preserve widths in declarations and uses
- carry typed global annotation evidence into final declarations
- stop at scalar/global-root presentation when stronger object evidence is
  missing

Exit criteria:

- globals are consistently typed and only become objects when base evidence is
  strong enough

### 3.5 Member And Array Recovery

Priority: `P2`

What to do:

- map repeated offsets to field candidates
- map stride and induction patterns to array candidates
- keep mixed evidence conservative
- prefer no rewrite over guessed pretty output when evidence conflicts

Exit criteria:

- object-like code increasingly shows members and arrays instead of raw
  `*(base + k)` arithmetic

## Phase 4. Finish Traits, Types, And Prototypes

Status: the handoff exists, but the quality bar still depends on corpus
coverage.

### 4.1 Trait-To-Type Handoff

Priority: `P1`

What to do:

- keep one formal handoff shape from trait evidence profiles to the type layer
- keep object and type decisions downstream of that handoff only
- include evidence category, width stability, address-space origin, base
  identity, and ambiguity flags

Exit criteria:

- trait logic emits evidence objects and downstream layers consume them
  explicitly

### 4.2 Prototype And Calling Convention Recovery

Priority: `P1`

What to do:

- improve stack-argument recovery on top of stack alias identity
- improve near/far-call aware signature handling
- preserve multiword return handling and keep explicit wide-return prototypes
  width-stable
- promote explicit prototypes only with strong evidence

Exit criteria:

- function signatures are a strength of the output instead of a readability
  weakness

### 4.3 Prototype Evidence Layer

Priority: `P1`

What to do:

- define explicit prototype evidence for stack-argument windows, register
  returns, multiword returns, far/near call class, helper metadata, and callsite
  agreement
- keep typed annotations and wide-return handling as inputs to the layer

Exit criteria:

- prototype decisions can be described as evidence composition rather than
  one-off heuristics

### 4.4 Stack-Argument Recovery

Priority: `P1`

What to do:

- recover argument windows from stack-slot identity
- distinguish argument slots from local stack objects
- preserve widths and partial views
- keep prototype promotion conservative when stack identity is mixed

Exit criteria:

- common functions stop inventing bogus locals and args around the frame

### 4.5 Far/Near Prototype Recovery

Priority: `P2`

What to do:

- preserve far/near call class as output-visible prototype evidence
- connect bounded far-call target recovery and calling-convention seeding to
  function signature recovery
- keep helper signatures stable when the callee model is known, conservative
  otherwise

Exit criteria:

- DOS helper/startup code shows fewer weak or misleading call signatures

## Phase 5. Keep Late Rewrite Thin

Status: implemented, but should stay narrow.

### 5.1 Thin Late-Rewrite Boundary

Priority: `P1`

What to do:

- keep late rewrite limited to boolean cleanup, algebraic cleanup, declaration
  cleanup, and final pretty-print normalization
- move any lingering storage or evidence reasoning upstream

Exit criteria:

- late rewrite no longer hides recovery logic that belongs upstream

### 5.2 Boolean And Condition Cleanup

Priority: `P2`

What to do:

- keep improving the bounded late-cleanup helpers in
  `decompiler_postprocess_simplify.py`
- keep flag-condition pairing and impossible interval-guard repair explicit
- add new simplifiers only when they are semantics-preserving and stay
  downstream of stable evidence

Exit criteria:

- common conditions get shorter and clearer without reopening alias or type
  decisions

### 5.3 Control-Flow Readability Polishing

Priority: `P3`

What to do:

- clean up loops and switch recovery only where safe
- avoid broad structural rewrites that destabilize honest recovery

Exit criteria:

- selected bodies look like decompiled source instead of recovered IR

### 5.4 Naming Polish Over Object Recovery

Priority: `P3`

What to do:

- let naming follow recovered structure
- fall back conservatively when evidence is weak

Exit criteria:

- final naming is driven by recovered structure, not ad hoc hints

## Phase 6. Retire Special Cases

Status: active and ongoing.

### 6.1 Source-Backed Rewrite Audit

Priority: `P2`

What to do:

- keep `cod_source_rewrites.py` as the explicit registry for source-backed
  rewrites
- annotate each rewrite spec as temporary rescue, permanent guarded oracle, or
  already subsumed by general recovery
- keep a summary/report helper visible in milestone output

Exit criteria:

- every source-backed rewrite has an explicit status and the active rescue set
  is small and explainable

### 6.2 Promote Rescues Into Regression Oracles

Priority: `P2`

What to do:

- when the general recovery pipeline covers a case, move the old behavior into
  a focused test anchor
- keep sample-matrix and `.COD` cases as the main acceptance layer
- prefer registry-level downgrade from active rewrite to oracle rather than
  ad hoc deletion

Exit criteria:

- more former rescue cases are enforced by tests than by active rewrite code

### 6.3 Special-Case Debt Tracker

Priority: `P2`

What to do:

- track the number of active source-backed rewrite specs
- track how many golden cases still require explicit rescue
- track how many now pass through the general alias/widening/type/prototype
  path
- include this in milestone notes alongside scan-safe and validation summaries

Exit criteria:

- the special-case surface trends down over time instead of drifting upward

## Validation Strategy

Validation should be layered, not monolithic.

### Unit Layer

Use this layer for:

- alias API behavior
- widening candidate and proof behavior
- global word store helpers
- milestone report generation
- readability set helpers

Representative files:

- `tests/test_x86_16_alias_register_mvp.py`
- `tests/test_x86_16_storage_domain_alias.py`
- `tests/test_x86_16_widening_model.py`
- `tests/test_x86_16_word_global_helpers.py`
- `tests/test_x86_16_milestone_report.py`
- `tests/test_x86_16_readability_set.py`

### Focused Corpus Layer

Use this layer for:

- real sample regressions
- compare semantics
- sample matrix coverage
- stack prototype promotion
- word-global widening

Representative files:

- `tests/test_x86_16_smoketest.py`
- `tests/test_x86_16_compare_semantics.py`
- `tests/test_x86_16_sample_matrix.py`
- `tests/test_x86_16_stack_prototype_promotion.py`
- `tests/test_x86_16_word_global_store_widening.py`

### Whole-Program Layer

Use this layer for:

- bounded scan-safe corpus runs
- runtime samples
- sample matrix end-to-end stability

Representative commands:

```bash
../.venv/bin/python -m pytest -q \
  tests/test_x86_16_smoketest.py \
  tests/test_x86_16_cod_samples.py \
  tests/test_x86_16_dos_mz_loader.py \
  tests/test_x86_16_sample_matrix.py \
  tests/test_x86_16_runtime_samples.py
```

```bash
../.venv/bin/python scripts/scan_cod_dir.py /path/to/cod_dir \
  --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
```

## Success Criteria

This plan is working if:

- each major layer explains multiple older wins with one architectural idea
- the number of local hacks needed for new corpus cases trends down
- correctness and readability improve together
- the tests get stronger as the architecture gets cleaner
- late rewrite stays narrow
- special-case rescues keep shrinking

## Near-Term Goals

The next concrete milestones should be:

1. close `A1`
2. close `A2`
3. close `A3`
4. strengthen segmented-memory association policy gates
5. finish the remaining object-recovery edge cases
6. keep prototype recovery conservative but stronger on real DOS samples
7. continue moving guarded rescues into tests and the general pipeline

## Stop Rules

Pause and reassess if:

- widening starts producing more wrong code than it removes
- object/type recovery becomes prettier but less honest
- alias work adds complexity without reducing local special cases
- new wins keep requiring one-off rescues instead of becoming reusable

## Summary

The architecture is already in place. The remaining work is mostly about:

- closing the last platform gaps
- tightening evidence-based recovery
- finishing object and prototype quality
- reducing the need for special-case rewrites

That is the right order for the current corpus and the current codebase.
