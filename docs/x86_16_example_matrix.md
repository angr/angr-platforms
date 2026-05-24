# x86-16 Example Matrix

This table tracks the real `.COD` / `.COM` / `.EXE` examples we are actively
using as decompiler-quality and logic-correctness oracles for Inertia
decompiler.

The intent is practical:
- keep a small set of named examples visible
- show which ones are tiny and cheap versus large and noisy
- record what each example is currently useful for

## Focused Examples

| Example | Proc | Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | --- | ---: | --- | --- |
| `cod/default/MAX.COD` | `_max` | near | `2771` B | `if (x > y) return x; return y;` | Smallest branch/return correctness case. Also checks `.COD --proc` skipping of leading `__chkstk`. |
| `cod/f14/NHORZ.COD` | `_ChangeWeather` | near | `108285` B | direct truth-test plus split-word stores for `8150`, `500`, `125`, `1000` | Good for direct-memory compare recovery, `if/else` shape, and distinct synthetic global materialization for `_CLOUDHEIGHT` / `_CLOUDTHICK`. |
| `cod/f14/MONOPRIN.COD` | `_mset_pos` | near | `20309` B | `% 80`, `% 25` | Good for simple arithmetic and frame-wrapper normalization. |
| `cod/f14/BILLASM.COD` | `_MousePOS` | near | `5689` B | `if (!MOUSE) return 0;`, `x * 2` | Good for byte compare recovery and tiny early-return logic. |
| `cod/f14/BILLASM.COD` | `_rotate_pt` | near | `5689` B | indexed word loads, `a1 * -1`, trig-call setup | Good for small arithmetic/setup logic before call-heavy code. |
| `cod/f14/PLANES3.COD` | `_Ready5` | near | `637819` B | `planecnt`, `droll`, `pdest`, `* 46`, `+ 18` | Large source file, but the chosen procedure is still small and now useful for named-global plus struct-stride anchoring. |
| `cod/f14/COCKPIT.COD` | `_LookDown` | near | `354631` B | `if (!(BackSeat))`, `Rp3D`, `RpCRT1`, `RpCRT2`, `RpCRT4`, `50`, `27`, `25`, `39` | Good for constant-heavy branch bodies and repeated field updates with recovered global names. |
| `cod/f14/COCKPIT.COD` | `_LookUp` | near | `354631` B | `if (!(BackSeat))`, `Rp3D`, `RpCRT1`, `RpCRT2`, `RpCRT4`, `150`, `138`, `136`, `139` | Pairs with `_LookDown`; same shape, different constants and else-path. |
| `cod/f14/COCKPIT.COD` | `_ConfigCrts` | near | `354631` B | counted copy loop, `flag * 2`, `546 + v5`, `flag < 8` | Good for simple loop/copy correctness on a real large `.COD` source file. |
| `cod/f14/CARR.COD` | `_InBox` | near | `254653` B | block-lift bounds logic is good; decompiled C now recovers the source-like guard chain | Good bounds-logic oracle for the `x/z` box test; still useful as a canonical interval-guard case. |
| `cod/f14/CARR.COD` | `_InBoxLng` | near | `254653` B | long compare chain, source-like `x/z` bounds guard | Good 32-bit-style bounds logic benchmark and a useful long-compare guard case. |
| `cod/f14/CARR.COD` | `_SetHook` | near | `254653` B | `return 1;`, hook state store, `93` / `106` message branches | Good for small state-toggle logic with an early-return path. |
| `cod/f14/CARR.COD` | `_SetGear` | near | `254653` B | guard threshold `350`, message branches `73` / `52`, distinct direct globals/tables | Good for guarded state-update logic with multiple early-return branches and separated synthetic globals for `_Status`, `_Knots`, `_Alt`, `_MinAlt`, and `_Damaged`. |
| `cod/f14/CARR.COD` | `_SetDLC` | near | `254653` B | state store plus `return a1;` | Tiny state-write helper; good cheap oracle for direct global stores and return-value preservation. |
| `cod/f14/COCKPIT.COD` | `_TIDShowRange` | near | `354631` B | `146`, `21`, `29`, `9`, `782`, `* 2`, distinct synthetic globals | Good for constant-heavy UI/layout logic plus indexed table access, `_Tscale`-style synthetic globals, and final helper call setup. |
| `cod/f14/COCKPIT.COD` | `_DrawRadarAlt` | near | `354631` B | direct truth-test, `v2 = 0` / `112`, final state write and helper call | Good for another small branch-heavy cockpit helper with a simple boolean split and call tail. |
| `angr_platforms/x16_samples/ICOMDO.COM` | `_start` | tiny `.COM` | n/a in this table | `get_dos_version(); print_dos_string(...); exit(0);` | Best user-facing tiny runtime sample. More about helper-call quality than arithmetic logic. |
| `angr_platforms/x16_samples/ISOD.EXE` | `_start` | small-model `.EXE` | paired with `ISOD.COD` | named DOS helpers plus startup constants | Useful bridge from tiny examples to real startup code. Still noisier than the small `.COD` set. |

## `fold_values` Matrix

These are the same source-level arithmetic helper across different memory-model
and optimization variants from the sample matrix.

Today it is useful in two ways:
- decompiled-C consistency for the recovered arithmetic body
- block-lift consistency for the two stable body families:
  - unoptimized `/Od`-style entry
  - optimized `/Ot`/`/Ox`-style entry

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | `123`, `return` | Small model, `/Od` style baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | `123`, `return` | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | `123`, `return` | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | `123`, `return` | Medium model baseline; useful for far-model decompilation correctness. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | `123`, `return` | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | `123`, `return` | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `123`, `return` | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `123`, `return` | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `123`, `return` | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `123`, `return` | Large model optimized variant. |

## `show_summary` Matrix

These are the same source-level summary-print wrapper across the 10 sample
matrix variants. Today it is useful in two ways:
- decompiled-C consistency for split word-load reconstruction
- block-lift consistency for near/far `cprintf` call setup

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | three `g_info` pushes + format push before `_cprintf` | Small model `/Od` baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | three `g_info` pushes + format push before `_cprintf` | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | three `g_info` pushes + format push before `_cprintf` | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | three `g_info` pushes + format push before far `_cprintf` | Medium model baseline. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | three `g_info` pushes + format push before far `_cprintf` | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | three `g_info` pushes + format push before far `_cprintf` | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `push ds` + format pointer + far `_cprintf` setup | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `push ds` + format pointer + far `_cprintf` setup | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `push ds` + format pointer + far `_cprintf` setup | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `push ds` + format pointer + far `_cprintf` setup | Large model optimized variant. |

## `_main` Matrix

These are the same source-level `main` wrapper across the 10 sample matrix
variants. Today it is useful in two ways:
- decompiled-C consistency for call-sequence stability
- block-lift consistency for `fold_values(g_info.video_mode, g_info.bios_kb & 0xFF)` argument setup

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Small model `/Od` baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Medium model baseline. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `_main`, helper calls, `& 0xff00 |`, `fold_values` arg pushes | Large model optimized variant. |

## Current Use

- The focused example set is the main small-to-medium logic correctness ladder.
- The `fold_values` matrix is the current model/optimization consistency ladder.
- The `show_summary` matrix is the current decompiled-C consistency ladder for
  split word-load reconstruction across memory models and optimization levels.
- The `show_summary` matrix also now has a block-lift ladder for the `_cprintf`
  call-setup prefix, which is a cleaner oracle for near/far ABI differences.
- The `_main` matrix is the current decompiled-C consistency ladder for helper
  call ordering and folded byte/word flow across the same 10 variants.
- The `_main` matrix now also has a block-lift ladder for the
  `query_interrupts(); show_summary();` call prefix, which cleanly exposes the
  near/far call setup split across the matrix variants.
- The `_main` matrix now also has a block-lift ladder for the final
  `fold_values(g_info.video_mode, g_info.bios_kb & 0xFF)` argument setup, which
  is a cleaner oracle for byte-to-word reconstruction plus stack argument
  stores before the final call.
- The `query_interrupts` setup prefix is now also locked across all 10 sample-matrix variants at block-lift level:
  - `ISOD`, `ISOT`, `ISOX`
  - `IMOD`, `IMOT`, `IMOX`
  - `IHOD`, `IHOT`
  - `ILOD`, `ILOT`
- A second `query_interrupts` matrix now also locks the `int86x(0x21)` / `g_info.int21_segment` / `g_info.int21_offset` tail across those same 10 variants.
- That matrix is intentionally block-level today because it is a cleaner correctness oracle than the current full decompiled C for those startup/helper-heavy routines.
- `examples/snake.lst` is a useful future oracle candidate, but the current listing does not byte-match the checked-in `snake.exe`, so it should not yet be used as a direct correctness source for that binary without a matching rebuild.
- When adding new examples, prefer:
  - one small, source-obvious procedure
  - one clear logic anchor
  - one reason the example is distinct from the ones already here
