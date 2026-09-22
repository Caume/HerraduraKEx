# BitArray — the reference specification

**Status: NORMATIVE for TODO #314.  No port implements all of it yet.**

This document specifies one variable-width bit-string type, to be implemented as the
*same algorithm over the same representation* in C, Go, Python and Java, replacing the
three embedded bignum types the suite currently delegates to.  It exists because
"the four ports agree" is presently a property of four people's care at one width rather
than a property of the code — see `TODO.md` #314 for the argument, and TODO #313
(closed v9.0.0) for the defect that made it concrete.

Assembly and Arduino targets are **out of scope**: they stay at their current fixed
32-bit widths by design.  This document governs the four major-language ports only.

Conformance vectors: `KAT/bitarray.json`, generated and checked by
`KAT/generate_bitarray_kat.py`.  The generator carries the reference implementation.

---

## 1. Representation

A BitArray is a pair **(nbits, b)**:

| field | meaning |
|---|---|
| `nbits` | the width, a positive multiple of 8, `16 <= nbits <= BA_MAX_BITS` |
| `b` | `nbits/8` octets, **big-endian**: `b[0]` is the most significant octet |

The width is carried **with** the value, always, in every port.  It is never passed
alongside the value as a separate argument and never inferred from context.  That rule is
the whole point of the type: TODO #313's four-way divergence begins with two ports that
were handed a declared width and ignored it, which is only possible when the width and
the value can be separated.

`BA_MAX_BITS` is a per-port capacity, **at least 256**.  A port MAY allocate exactly
`nbits/8` octets (Go, Python, Java) or a fixed `BA_MAX_BITS/8` buffer with `nbits` active
(C, so that value semantics, stack allocation, arrays-of-BitArray and the AVR/ARM targets
survive).  Capacity is not observable: an operation's result depends on `nbits` and the
active octets only.

**The octet string is the canonical form.**  `to_bytes` is the identity on `b`, and it is
also the suite's wire encoding — PEM/DER INTEGERs are big-endian — so no endianness
conversion happens at any I/O boundary.

**Limb width is implementation-private.**  A port MAY operate on 32- or 64-bit limbs
internally for speed, provided it reproduces `KAT/bitarray.json` octet for octet.  The
specification is defined on octets; nothing observable may depend on limb size.

### 1.1 Why big-endian octets and not an integer

Three of the four ports today delegate to an integer type (`math/big`, Python `int`,
`java.math.BigInteger`).  Each of those normalises away leading zero octets, which is
precisely the information `nbits` exists to carry, and each then needs a re-widening step
on the way out.  Go's `Bytes()` is where that goes wrong today (§6.1).  An octet string
has no normalisation step to get wrong.

---

## 2. Widths

- `nbits` MUST be a positive multiple of 8.  Bit-granular widths are not representable
  and MUST be rejected at construction.
- `nbits >= 16`.  This is not arbitrary: `fscx` (§4.6) reads the octet on both sides of
  every position and degenerates below two octets.  C has carried
  `#if KEYBYTES < 2 / #error` since v1.3 for the same reason.
- `nbits <= BA_MAX_BITS`, which every port MUST set to at least 256.

The suite's deployed widths are 256 (the classical quartet, HSKE, HSKE-NL, HPKS, HPKE,
HFSCX-256) and 1024 (HKEX-RNL's ring dimension, which is **not** a key width — see
`SPEC.md` §9.2 and TODO #228).  32, 64 and 128 appear in `GF_POLY` and in tests.

---

## 3. The mixed-width rule

> **Every binary operation REQUIRES both operands to have the same `nbits`.
> A mismatch is a protocol error.  It is reported.  It is never coerced.**

No implicit zero-extension, no implicit truncation, no silent adoption of either
operand's width.  Changing a width is an explicit operation (§4.4) and can itself fail.

This is the single most important clause in this document, because it is the one all four
ports currently get wrong in four different ways — two by coercing and two by being unable
to pose the question at all.  §6 records what they do today, measured.

---

## 4. Operations

Throughout: `n` is the common width, `nb = n/8`.  Every operation listed as
**CT** must be constant-time in its operands' *values* (branch-free, no data-dependent
indexing); it may branch on `n`, which is public.

### 4.1 Construction and conversion

| op | semantics | errors |
|---|---|---|
| `zero(n)` | all octets 0 | `E_WIDTH` if `n` invalid (§2) |
| `from_bytes(data, n)` | `b = data`, requires `len(data) == n/8` **exactly** | `E_WIDTH`, `E_LENGTH` |
| `from_uint(v, n)` | big-endian encoding of `v` | `E_WIDTH`, `E_RANGE` if `v >= 2^n` |
| `from_hex(s, n)` | requires `len(s) == n/4` exactly, lowercase on output | `E_WIDTH`, `E_LENGTH`, `E_HEXDIGIT` |
| `random(n, src)` | `n/8` octets from `src` | `E_WIDTH`, `E_ENTROPY` on a short read |
| `to_bytes(a)` | the `nb` octets, identity on `b` | — |
| `to_hex(a)` | exactly `n/4` lowercase hex digits, zero-padded | — |
| `to_uint(a)` | the big-endian integer value | — |
| `copy(a)` | a value-distinct equal BitArray | — |

`from_uint` rejecting `v >= 2^n` rather than masking is deliberate and is a change from
every current port.  Masking is how an out-of-range intermediate becomes a plausible-looking
in-range value with nothing recording that it happened.

`random` MUST fail on a short read rather than proceeding with partial entropy.  C's
existing `ba_rand` already does (`herradura.h`); the rule is stated here so the other three
cannot drift.

### 4.2 Bitwise

| op | semantics | CT | errors |
|---|---|---|---|
| `xor(a, b)` | octetwise `^` | CT | `E_MIXED_WIDTH` |
| `and(a, b)` | octetwise `&` | CT | `E_MIXED_WIDTH` |
| `or(a, b)` | octetwise `\|` | CT | `E_MIXED_WIDTH` |
| `not(a)` | octetwise `~` over all `nb` octets | CT | — |

Aliasing (`dst == a`, `dst == b`) is safe in every port that has an explicit destination.

### 4.3 Rotation and shift

`rot_left(a, s)` and `rot_right(a, s)` rotate within the width.  **`s` is reduced modulo
`n` first**, and the reduction is the mathematical one: `s` may be negative, and
`rot_left(a, -s) == rot_right(a, s)`.  A port MUST NOT use a language `%` that returns a
negative remainder without correcting it.

`shl(a, k)` and `shr(a, k)` are numeric shifts within the width: bits shifted past either
end are **discarded**, vacated positions are **zero**.  `k` is any integer `>= 0`;
`k >= n` yields zero.  `k < 0` is `E_RANGE`.

> A shift by a distance `>= the operand's own width` is undefined behaviour in C, a panic
> in Go, `0` in Python and a *rotation of the distance* in Java (`<<` uses `k & 63`).  That
> is four answers to one expression, which is why this clause exists and why `k >= n`
> returning zero is stated rather than assumed.  C's current `ba_shl_k`/`ba_shr_k` accept
> only `0 <= k < 8` and short-circuit `k == 0` specifically to dodge a `>> 8` on a
> `uint8_t`; the reference has no such restriction and ports must handle the general case.

All four are CT in the operand; `s`/`k` are public.

### 4.4 Width change

| op | semantics | errors |
|---|---|---|
| `truncate(a, m)` | keep the **high** `m` bits: the big-endian **prefix** `b[0 .. m/8-1]` | `E_WIDTH` if `m` invalid or `m > n` |
| `extend(a, m)` | append `(m-n)/8` zero octets on the **low** side | `E_WIDTH` if `m` invalid or `m < n` |
| `resize_exact(a, m)` | `m <= n`: as `truncate`, but `E_LOSSY` if any discarded bit is 1.  `m >= n`: as `extend` | `E_WIDTH`, `E_LOSSY` |

**`truncate` takes the HIGH bits.**  This is the clause that settles TODO #313's split, and
it is not a coin toss:

1. It is the big-endian-natural rule.  Truncating a big-endian octet string is taking a
   prefix — a slice.  Low-bit truncation is a suffix, which on this representation is
   arithmetic rather than slicing, and arithmetic is where the ports diverged.
2. Two of the four already say high bits.  Python's `rnl_kdf_seed` does
   `_RNL_KDF_DC_256 >> (256 - n)`, and C's own declared narrow constants
   `_RNL_KDF_DC_32 = 0x6A09E667` and `_RNL_KDF_DC_64 = 0x6A09E667BB67AE85` are the high 32
   and high 64 bits of the same 256-bit value.  Go's `RnlKdfDC[32-n/8:]` — the low octets —
   is the outlier.
3. There is then exactly **one** truncation, in one place, which is #314's reason 1
   realised.  Every width-taking constant derives from its 256-bit form by this one call.

`resize_exact` is the operation protocol code should reach for.  A silent narrowing that
drops a set bit is the shape of the defect this type exists to remove, so the lossy case is
an error and not a result.

### 4.5 Comparison and inspection

| op | semantics | CT | errors |
|---|---|---|---|
| `equal(a, b)` | width **and** value | CT — accumulate all octets, no early exit | — |
| `compare(a, b)` | `-1/0/+1`, unsigned big-endian lexicographic | CT | `E_MIXED_WIDTH` |
| `is_zero(a)` | all octets zero | CT | — |
| `popcount(a)` | number of set bits over all `nb` octets | CT | — |
| `bit(a, i)` | bit `i` counted from the **LSB** (`i = 0` is the low bit of `b[nb-1]`) | CT | `E_RANGE` if `i >= n` |

`equal` compares widths as well as values and returns false on a mismatch rather than
raising: an equality test is a question, not an operation on a shared width.  Go's `Equal`
already does this; it is the one mixed-width case any current port handles correctly.

### 4.6 Suite primitives built on the above

These are specified here because they are where width enters the protocol, and because
three of them are the sites TODO #313 found.

**`fscx(a, b)`** — `a ^ b ^ ROL(a,1) ^ ROL(b,1) ^ ROR(a,1) ^ ROR(b,1)`, at the common
width.  `E_MIXED_WIDTH`.  Requires `n >= 16` (§2).

**`fscx_revolve(a, b, i)`** — `fscx` applied `i` times, `b` held constant.  `i >= 0`;
`i == 0` is the identity.

**`gf_mul(a, b)`**, **`gf_pow(a, e)`** — GF(2^n) multiply and power modulo the primitive
polynomial for that width.  The polynomial is looked up by width, and a width with no
entry is `E_NO_POLY` — never a default.  The table is the one Python already carries:

| n | primitive polynomial (low coefficients, hex) |
|---|---|
| 32 | `0x00400007` |
| 64 | `0x0000001B` |
| 128 | `0x00000087` |
| 256 | `0x00000425` — `x^256 + x^10 + x^5 + x^2 + 1` |

Both CT.  `E_MIXED_WIDTH` for `gf_mul`.

> C currently carries `#if KEYBITS != 256 / #error "GF polynomial constants are only
> defined for KEYBITS=256 in this build"`.  Under this specification that `#error`
> becomes a run-time `E_NO_POLY` on an unlisted width, and the table above is compiled in.

**`rnl_kdf_seed(k)`** — `ROL(k, n/8) XOR truncate(RNL_KDF_DC_256, n)`, where
`RNL_KDF_DC_256 = 0x6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19`.
The truncation is §4.4's, high bits, one call.  This is the TODO #313 site.

---

## 5. Errors

Every port reports in its own idiom — C by return code, Go by `error`, Python and Java by
exception — but the **set** is identical and closed:

| code | raised when |
|---|---|
| `E_WIDTH` | width not a multiple of 8, `< 16`, `> BA_MAX_BITS`, or otherwise invalid |
| `E_MIXED_WIDTH` | a binary operation's operands disagree on width |
| `E_LENGTH` | input octet/hex-digit count does not match the declared width |
| `E_RANGE` | value `>= 2^n`, negative shift, or bit index `>= n` |
| `E_LOSSY` | `resize_exact` would discard a set bit |
| `E_HEXDIGIT` | non-hex character in `from_hex` |
| `E_NO_POLY` | no primitive polynomial for this width |
| `E_ENTROPY` | short read from the entropy source |

No operation in this specification has a silent failure mode.  An operation either returns
a correct result at a stated width or reports one of the above.

---

## 6. What the four ports do today

Measured on the tree at v9.0.0, not read off the source.  This is the gap the ports are
being converted to close.

| | representation | width | mixed-width `xor` |
|---|---|---|---|
| C | `uint8_t b[KEYBYTES]`, big-endian | fixed at compile time | not expressible |
| Go | `BitArray{ Val big.Int; size int }` | variable | **silently returns all zeros** |
| Python | `int` + `_size` + `_mask` | variable | **silently discards the other operand** |
| Java | bare `BigInteger` vs. static `N = 256` | fixed at 256 | not expressible |

### 6.1 Go returns zeros

`Xor` builds `&BitArray{size: ba.size}` and sets `Val` **without masking**, so XOR against
a wider operand leaves `Val` wider than `size` claims.  `Bytes()` then does

```go
b := ba.Val.Bytes()
out := make([]byte, ba.size/8)
if len(b) <= len(out) { copy(out[len(out)-len(b):], b) }
return out            // <-- unchanged, i.e. all zeros, when the value overflows
```

so the over-wide value copies nothing and reads back as zeros.  Measured: a 64-bit array
XORed with a 256-bit one yields `size = 64`, `Val.BitLen() = 201`, and
`Bytes() = 0000000000000000`.  No error, no panic.  Under §3 this is `E_MIXED_WIDTH`.

### 6.2 Python discards

`__xor__` returns `BitArray(self._size, self._val ^ other._val)`, and the constructor masks
to `self._size`.  The same expression returns the left operand **unchanged**, the right one
having been masked away entirely.  Under §3 this is `E_MIXED_WIDTH`.

Two variable-width ports, one operation, two different silent wrong answers.  That is
TODO #313's shape one layer down, and it is the argument for this document.

---

## 7. Conformance

`KAT/bitarray.json` pins every operation in §4 at widths 32, 64, 128 and 256, including
the error cases, which are pinned as *expected error codes* rather than as values.

`python3 KAT/generate_bitarray_kat.py --check` verifies currency and is gating.
`--report` prints per-port, per-operation conformance for the ports converted so far; it
is a **report, not a gate**, because a port not yet converted is expected to differ and
`CLAUDE.md`'s Testing section allows no failing test.  A port joins the gating set when it
is converted — one port, one release.

A vector generated by the reference and checked only by the reference proves only that
nobody edited the file.  It becomes load-bearing at the first port and decisive at the
second: two independent implementations against one pinned answer is what no round-trip or
interop test can supply, because those compare a port against another port's opinion.

---

## 8. Sequencing

| pass | scope |
|---|---|
| 1 | this document, `KAT/bitarray.json`, the reference implementation in the generator, and the C type decision (§9) |
| 2 | C — the constraint, and the only port that cannot represent a narrow value at all |
| 3-5 | Go, Python, Java, one per release, each joining the gating set |
| 6 | relax TODO #313's refusal: `MIGRATING.md` §19 and `CliTest/test_narrow_width_matrix.sh` go from "all four refuse" to "all four agree" |

Every pass MUST be behaviour-preserving at 256 bits, and 256 is where everything is
pinned — `KAT/` entire, the 518-assertion `test_cross_lang_matrix.sh`, and the numbered
tests in all four languages.  A port that moves one octet at 256 fails immediately.

## 9. The C type, and why this is not a MAJOR change

The C form is

```c
#define BA_MAX_BITS 256           /* per-port capacity, >= 256 */
typedef struct {
    uint16_t nbits;
    uint8_t  b[BA_MAX_BITS / 8];  /* big-endian; b[0] most significant */
} BitArray;
```

which keeps value semantics, stack allocation, arrays-of-`BitArray`, embedding in other
structs, and the AVR/ARM footprint.

`sizeof(BitArray)` changes, so the question TODO #314 said to settle in the item is
whether that breaks the public C API.  **Measured: it does not.**

- `bindings/ffi/herradura_shim.h` mentions `BitArray` **zero times**.  The FFI ABI is flat
  `uint8_t[KEYBYTES]` buffers by design — the shim's own header says so — so the type is
  not on it.  The shim's `.c` body converts with `memcpy(ba.b, src, KEYBYTES)` and becomes
  `ba_from_bytes(&ba, src, KEYBITS)`: mechanical, one file, no exported signature moves.
- `docs/examples/c/hello_herradura.c` declares `BitArray` values and calls `ba_*` only.  It
  never touches `.b[]` or `KEYBYTES`, so it compiles unchanged.
- All 95 direct-internals accesses outside `herradura.h` are in three in-tree files: the
  CLI, the tests, and the suite walkthrough.
- `herradura.h` is header-only, so every consumer recompiles from the same header and there
  is no ABI boundary for the type to break.

So the change is **source-compatible on the public surface**, and MAJOR is not forced on
the C-API ground.  Passes 2-5 are behaviour-preserving at every width the ports currently
agree on, which is MINOR at most.  Pass 6 relaxes a refusal, which breaks nothing.  The one
place a MAJOR could still arise is if a later pass changes what an existing `--algo`
produces or accepts; none of passes 1-5 does.
