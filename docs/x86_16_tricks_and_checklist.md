# x86-16 Tricks and Decompiler Checklist

This note is a compact working reference for 16-bit x86 code patterns that are
useful both for hand-written assembly and for decompiler recovery work.

## Practical Tricks

### Zeroing Registers

- `xor ax, ax` / `sub ax, ax` are still the standard size-efficient zeroing idioms.
- `cwd` is useful when `AX >= 0` and you want `DX = 0` via sign-extension.
- `xor bx, bx ; mul bx` can zero `DX:AX` in one short idiom when that side
  effect is acceptable.

### Small Constants

- On 8086, `mov reg, imm16` is usually the safest baseline.
- On 80186+, `push imm8 ; pop reg` is a compact way to materialize signed
  8-bit values.
- `xor ax, ax ; dec ax` is a small `-1` pattern.

### Register Moves and Swaps

- `push reg1 ; pop reg2` is often a compact move.
- `xchg ax, reg` is the 1-byte king when `AX` participates.

### Arithmetic and Addressing

- `add ax, ax` and `shl ax, 1` are the usual `*2` idioms.
- `lea` is still useful in 16-bit mode for base/index/displacement forms, but
  there are no scaled-index forms.
- `sub ax, -5` is a size-neutral alternative to `add ax, 5` when flag shape
  matters.

### Comparisons and Flags

- `test ax, ax` is usually shorter than `cmp ax, 0`.
- `jcxz` is a useful short zero-branch.
- `salc` exists and is tiny, but it is undocumented and not universally safe to
  depend on.

### Loops and String Ops

- `loop`, `loope`, and `loopne` are very compact for `CX`-based loops.
- `lodsw`, `stosw`, and `rep stosw` are especially useful in real-mode code.
- `do/while`-style control flow often decompiles more cleanly than an initial
  forward jump.

### Segment Setup

- `push cs ; pop ds` is the classic 2-byte segment-copy idiom.
- Real-mode output becomes easier to read when segment-aware access is
  normalized early instead of printed as raw `seg * 16 + off`.

## Decompiler Checklist

- Look for `xor reg, reg`, `sub reg, reg`, `cwd`, and `mul reg` as zeroing
  candidates.
- Normalize `test ax, ax` and `jcxz`-style guards before trying broader control
  flow rewrites.
- Treat `lodsw`, `stosw`, `rep stosw`, and `loop` as high-value patterns for
  source-like recovery.
- Prefer segment-aware rewrites for `ss`, `ds`, and `es` before naming or type
  inference.
- Collapse small additive chains like `x + 1 + 1` only when the tree is short
  and clearly local.
- Collapse byte-pair patterns only when the low/high byte pair is proven to be
  adjacent and safe.
- Keep `snake`-style helpers and `.COD` samples as the main visible oracle set
  for readability work.
- Avoid broad alias inlining unless the block is tiny and the gain is obvious.
- If a rewrite starts affecting whole-binary stability, split it back into a
  focused `--addr` path.

## Notes

- `cwd` is not a general zeroing instruction.
- `salc` is useful but should stay behind a compatibility guard.
- `push imm8 ; pop reg` is 80186+, not 8086.
- `lea` in 16-bit mode is still limited to base/index/displacement forms.
