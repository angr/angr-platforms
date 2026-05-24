# x86-16 Decompiler Readability Snapshot

This note tracks small real `.COM`, `.EXE`, and `.COD` examples that currently
show where the decompiler is already readable and where the next quality work
should go.

## Good Now

### `x16_samples/ICOMDO.COM` `_start`

Current pseudo-style output:

```c
int dos_get_version(void);
void dos_print_dollar_string(const char *s);
void dos_exit(int status);

int _start(void)
{
    dos_get_version();
    dos_print_dollar_string("DOS sample");
    dos_exit(0);
}
```

Why it is good:
- helper calls are readable
- the string literal is recovered
- control flow is simple and human-facing

## Mixed But Promising

### `cod/f14/MONOPRIN.COD` `_mset_pos`

Current strengths:
- `% 80` is visible
- `/ 25` and `% 25` are visible
- the basic calculation shape is recoverable

Current weaknesses:
- frame setup still shows as raw segmented stores
- locals and arguments are not named well yet
- signed divide/mod lowering is still too literal

### `cod/f14/NHORZ.COD` `_ChangeWeather`

Current strengths:
- an `if/else` shape is present
- the main constants survive clearly: `8150`, `500`, `125`, `1000`
- return structure is stable

Current weaknesses:
- the branch condition is still opaque as `...`
- global word updates are still split into byte stores
- globals are still rendered as `g_*` instead of meaningful variables

## Still Ugly

### `x16_samples/ISOD.EXE` `_start`

Current strengths:
- startup DOS helpers are visible as named pseudo-callees:
  - `dos_get_version()`
  - `dos_setblock()`
  - `dos_exit(255)`
- major startup constants like `520` are still visible

Current weaknesses:
- stack/frame state is still noisy
- many global updates are rendered as bytewise segmented stores
- some conditions still collapse to `...`
- unresolved or weakly recovered calls still hurt readability

## Best Next Step

The best next decompiler-quality step is not wider DOS API coverage.

The highest-value work now is:

1. Coalesce 16-bit segmented byte stores and loads into word-level variables.
2. Clean up stack/frame noise for small MSC functions.
3. Improve branch-condition recovery on small `.COD` arithmetic/logic samples.

## Golden Readability Set

The current named readability set is:

- `cod/f14/MONOPRIN.COD` `_mset_pos`
- `cod/f14/NHORZ.COD` `_ChangeWeather`
- `angr_platforms/x16_samples/ICOMDO.COM` `_start`
- `cod/f14/MAX.COD` `_max`
- `angr_platforms/x16_samples/COCKPIT.COD` `_ConfigCrts`

Each case is tracked with a small anchor list in
[`readability_set.py`](../angr_platforms/X86_16/readability_set.py) and in the
sample-backed tests that exercise the decompiler output.

That should make outputs like `_mset_pos`, `_ChangeWeather`, and the small
`ISOD.EXE` startup function look materially more human-readable without needing
much broader semantic coverage.
