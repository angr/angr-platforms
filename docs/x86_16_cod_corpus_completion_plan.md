# x86-16 `.COD` Corpus Completion Plan

This plan is narrower than the full dream-decompiler roadmap.

Its purpose is to drive Inertia to a practical corpus-grade state where the
whole `.COD` corpus is:

- scannable without crashes
- free of silent blind spots
- steadily more readable

The target is not "pretty output at any cost". The target is:

1. no process-level failures on the corpus
2. no unknown or invisible failure regions
3. readability work driven by explicit evidence and real corpus pain

The architecture rule remains:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

This plan does not replace that rule. It applies it to the specific operational
goal of finishing the `.COD` corpus.

## Success Criteria

The corpus is considered "complete enough" only when all three conditions are
true at the same time.

### 1. No Crashes

- `scan-safe` can traverse the whole `.COD` tree without the driver dying
- no file causes process abort, uncontrolled exception escape, or cleanup-time
  traceback noise
- timeouts and skips are allowed only when they are bounded and classified

### 2. No Blind Spots

- every function ends in one of:
  - `decompile`
  - `cfg_only`
  - `lift_only`
  - `block_lift`
  - classified failure
- every failure has a stage and a failure class
- every conservative skip has an explicit reason
- there are no "unknown" buckets left in milestone reports except during
  short-lived investigation

### 3. Readable Progress

- the golden readability set stays green
- milestone reports show the top ugly clusters, not just top crashes
- new readability wins come from general recovery layers, not only local rescue
  rewrites

## Three Separate Tracks

The work should run on three tracks in parallel. Do not collapse them into one
"quality" bucket.

### Track A. Corpus Stability

Goal: traverse all `.COD` inputs safely.

This track owns:

- driver robustness
- timeout discipline
- memory limits
- cleanup safety
- bounded fallback policy

Primary entry points:

- [`corpus_scan.py`](../angr_platforms/X86_16/corpus_scan.py)
- [`scan_cod_dir.py`](../scripts/scan_cod_dir.py)

### Track B. Blind-Spot Elimination

Goal: remove invisible analysis gaps.

This track owns:

- failure taxonomy
- stage boundaries
- hotspot ranking
- fallback visibility
- baseline and milestone reporting

Primary entry points:

- [`corpus_scan.py`](../angr_platforms/X86_16/corpus_scan.py)
- [`milestone_report.py`](../angr_platforms/X86_16/milestone_report.py)
- [`validation_manifest.py`](../angr_platforms/X86_16/validation_manifest.py)

### Track C. Readability Uplift

Goal: make more of the corpus readable without weakening correctness.

This track owns:

- alias-first cleanup
- widening-driven byte-pair elimination
- segmented association quality
- trait/type/object recovery
- boolean/control-flow cleanup

Primary references:

- [`dream_decompiler_execution_plan.md`](./dream_decompiler_execution_plan.md)
- [`x86_16_decompiler_readability.md`](./x86_16_decompiler_readability.md)

## Phase 1. Finish Corpus Visibility

This phase is about knowing exactly what happens for every function.

## TODO — updated COD/x86-16 decompilation plan

### -1. Optimize:

benchmark in this order:

CPython 3.14
CPython 3.14 + experimental JIT
PyPy 7.3.21

                        try on cod/EGAME2.COD or similar

### 0. Stabilize current pipeline first

* [ ] Wrap `dec.codegen.regenerate_text()` in a safe fallback
* [ ] Log the **last rewrite pass that changed AST/text**
* [ ] Return degraded output instead of crashing when regeneration fails
* [ ] Add a per-function flag: `regeneration_failed`
* [ ] Make CLI/report distinguish:

  * [ ] decompiler timeout
  * [ ] rewrite failure
  * [ ] regeneration failure
  * [ ] empty codegen
* [ ] Add test: `test_cod_regenerate_text_failure_does_not_abort_cli`
* [ ] Add test: `test_cod_rewrite_failure_reports_last_pass`

**Done when**

* [ ] No run aborts on `regenerate_text()` failures like `_my_itoa`

---

### 1. Actually activate early helper signatures

* [ ] Call `_apply_known_helper_signatures(project, cod_metadata)` inside `_decompile_function()` **before** `seed_calling_conventions(cfg)` and before `Decompiler(...)`
* [ ] Expand `known_helper_signature_decl()` coverage for:

  * [ ] `_intdos`
  * [ ] `_intdosx`
  * [ ] `_fprintf`
  * [ ] `_fflush`
  * [ ] `_abort`
  * [ ] `_ERROR`
  * [ ] `_INFO`
  * [ ] `_DEBUG`
  * [ ] common corpus helpers like `_joyOrKey`, `_inp`, `clearRect`, `exit`
* [ ] Ensure helper signatures affect **callsites**, not just callee declarations
* [ ] Add test: `test_cod_known_helper_signatures_applied_before_decompilation`
* [ ] Add test: `test_cod_known_helper_calls_render_without_numeric_sub_targets`

**Done when**

* [ ] known helpers stop rendering as anonymous/numeric callees where metadata exists
* [ ] helper calls render with correct arg counts and return shapes

---

### 2. Restore early binary-specific annotations

* [ ] Replace `_apply_binary_specific_annotations(...): return None` with real early-safe annotations
* [ ] Re-enable early attachment of:

  * [ ] binary-local wrapper declarations
  * [ ] known globals from `.COD` / `.LST`
  * [ ] safe object names/types
  * [ ] known arg/return shapes for tiny wrappers
* [ ] Do **not** put text hacks back into this stage
* [ ] Add test: `test_binary_specific_annotations_restore_known_cod_globals`
* [ ] Add test: `test_binary_specific_annotations_do_not_require_text_rewrite`

**Done when**

* [ ] early stage carries facts; rewrite stage only polishes

---

### 3. Reduce rewrite-chain responsibility for COD object semantics

* [ ] Audit these passes and mark each as:

  * [ ] semantic recovery
  * [ ] late polish only
* [ ] Review:

  * [ ] `_coalesce_cod_word_global_loads`
  * [ ] `_coalesce_cod_word_global_statements`
  * [ ] `_attach_cod_global_names`
  * [ ] `_attach_cod_global_declaration_names`
  * [ ] `_attach_cod_global_declaration_types`
  * [ ] `_collect_access_traits`
  * [ ] `_attach_access_trait_field_names`
  * [ ] `_attach_pointer_member_names`
* [ ] Move any semantic logic from those passes into alias/type recovery
* [ ] Keep only declaration cleanup / naming cleanup late
* [ ] Add test: `test_cod_known_object_fields_recover_before_codegen_text_cleanup`

**Done when**

* [ ] known object fields do not depend primarily on late rewrite to exist

---

### 4. Strengthen known COD object recovery

* [ ] Extend `cod_known_objects.py` specs to include:

  * [ ] full type name
  * [ ] field offsets
  * [ ] field widths
  * [ ] packed-struct info
  * [ ] allowed byte/word views
  * [ ] expected segment/domain
* [ ] Feed object spec facts into early recovery via `_apply_known_cod_object_annotations()`
* [ ] Add direct support for:

  * [ ] `rin`
  * [ ] `rout`
  * [ ] `sreg`
  * [ ] `_exeLoadParams`
  * [ ] `_ovlLoadParams`
  * [ ] `_commData`-like far/global objects where stable
* [ ] Add test: `test_cod_regs_union_recovers_field_accesses_without_late_source_rewrite`

**Done when**

* [ ] COD-known objects recover as typed fields, not mainly as raw offsets or post-hoc names

---

### 5. Improve stack-slot classification for wrappers

* [ ] Distinguish stack slots as:

  * [ ] incoming arg
  * [ ] real local
  * [ ] outgoing call staging
  * [ ] dead synthetic spill
* [ ] Teach tiny-wrapper handling to drop dead staging locals
* [ ] Add structural wrapper simplifier for:

  * [ ] one-call wrappers
  * [ ] one-call-and-return wrappers
* [ ] Prefer wrapper simplification on tiny functions after signatures are known
* [ ] Add test: `test_cod_waitjoykey_strips_fake_stack_local`
* [ ] Add test: `test_cod_openfilewrapper_direct_forwarding`
* [ ] Add test: `test_cod_direct_wrapper_return_preserved`

**Done when**

* [ ] wrappers like `_waitJoyKey()` no longer emit fake `s_*` locals around a direct helper call

---

### 6. Fix return-shape correctness

* [ ] Add a pre-text pass to classify final return shape:

  * [ ] `void`
  * [ ] scalar `AX`
  * [ ] wide `DX:AX` only if proven
* [ ] Penalize synthetic `DX:AX` returns in tiny functions
* [ ] Add store-then-return cleanup for helpers currently rendered as bogus `long`
* [ ] Add test: `test_cod_small_function_does_not_invent_dxax_return`
* [ ] Add test: `test_cod_getreturncode_returns_scalar`
* [ ] Add test: `test_cod_store_helper_not_emitted_as_long_without_proof`

**Done when**

* [ ] functions like `_sub_19E44` stop inventing `return v7 << 16 | v6;` without proof 

---

### 7. Move segmented-memory correctness earlier

* [ ] Add alias/storage domains for:

  * [ ] `DS:DGROUP`
  * [ ] `SS:stack`
  * [ ] `ES:far object`
  * [ ] absolute `0:offset` low memory
* [ ] Move segmented word-store/load correctness earlier than rewrite
* [ ] Add LES/global far-object attachment
* [ ] Keep late passes only for normalization:

  * [ ] `_coalesce_segmented_word_store_statements`
  * [ ] `_coalesce_segmented_word_load_expressions`
  * [ ] `_elide_redundant_segment_pointer_dereferences`
* [ ] Add test: `test_cod_segmented_word_store_recovers_single_word_assignment`
* [ ] Add test: `test_cod_les_global_pointer_recovers_object_access`

**Done when**

* [ ] LES/global pointer patterns recover as object access, not raw segmented arithmetic

---

### 8. Tighten tiny-function path

* [ ] Review `small_function = block_count <= 4 and byte_count <= 32`
* [ ] Make tiny-function path depend on:

  * [ ] helper signature availability
  * [ ] wrapper shape
  * [ ] proven return shape
* [ ] Ensure tiny-function optimization does not skip necessary correctness passes
* [ ] Add test: `test_tiny_wrapper_path_preserves_call_and_return_semantics`

**Done when**

* [ ] tiny wrappers get simpler output without losing semantics

---

### 9. Add timeout-stage classification and scan-safe mode

* [ ] Record timeout stage as one of:

  * [ ] CFG
  * [ ] normalization
  * [ ] decompiler
  * [ ] rewrite
  * [ ] regeneration
* [ ] Add large-function scan-safe mode:

  * [ ] disable risky recursive simplification
  * [ ] cap expensive rewrites
  * [ ] allow partial output fallback
* [ ] Report per-function:

  * [ ] block count
  * [ ] byte count
  * [ ] elapsed time
  * [ ] timeout stage
  * [ ] regeneration status
* [ ] Add test: `test_cod_timeout_report_includes_stage`

**Done when**

* [ ] timeout-heavy COD files produce classified failures or partial output, not unstable behavior

---

### 10. Add anti-regression anchors

* [ ] For wrapper targets, fail if final C contains:

  * [ ] `s_2 = &`
  * [ ] `s_4 =`
  * [ ] `s_6 =`
* [ ] For helper targets, fail if final C contains:

  * [ ] `sub_` numeric callee for a known helper
* [ ] For tiny setters/helpers, fail if final C contains:

  * [ ] synthetic `DX:AX` long return without proof
* [ ] For segmented object targets, fail if final C contains:

  * [ ] raw segmented arithmetic where known object lowering is expected

---

## Suggested commit order

* [ ] Commit 1: pipeline stability + regeneration fallback
* [ ] Commit 2: activate early helper signatures
* [ ] Commit 3: restore binary-specific early annotations
* [ ] Commit 4: known COD object recovery earlier
* [ ] Commit 5: wrapper cleanup / stack-slot classification
* [ ] Commit 6: return-shape correctness
* [ ] Commit 7: segmented-memory early recovery
* [ ] Commit 8: timeout-stage reporting + scan-safe large-function mode

---

## Definition of done for this phase

* [ ] no `regenerate_text()` crash aborts a COD run
* [ ] `_waitJoyKey()`-style wrappers become direct calls without fake locals
* [ ] tiny helpers stop inventing bogus wide returns
* [ ] LES/global pointer patterns start recovering as object access
* [ ] known helper calls and known COD objects are recovered mostly **before** late rewrite
* [ ] timeout-heavy COD files produce classified failures or partial output instead of unstable exits


## The Simple Human Version

The `.COD` corpus is only really "done" when:

- nothing crashes
- nothing important is invisible
- the ugly parts are ranked and shrinking
- readable wins come from architecture, not miracles

That is the operational meaning of:

"whole COD readable and not crashes and no blind spots"
