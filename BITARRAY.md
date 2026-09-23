# BitArray — the reference specification

**Status: NORMATIVE for TODO #314.  ALL SIX PASSES ARE DONE — C (pass 2, v9.1.0), Go
(pass 3, v9.2.0), Python (pass 4, v9.3.0), Java (pass 5, v9.4.0), and pass 6 (v9.5.0),
which relaxed TODO #313's refusal: `hske-nla1` is accepted at every width §2 permits and
all four CLIs agree octet for octet at 32, 64, 128 and 256 bits.  §8.4 records what pass 6
found — two ports that passed the 376-case vector and still produced the wrong keystream
below 256, because conforming to the type is not the same as consuming it at the value's
width.**

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
| `from_uint(v, n)` | big-endian encoding of `v`; **defined for `n <= 64` only** | `E_WIDTH`, `E_RANGE` if `v >= 2^n` or `n > 64` |
| `from_hex(s, n)` | requires `len(s) == n/4` exactly, lowercase on output | `E_WIDTH`, `E_LENGTH`, `E_HEXDIGIT` |
| `random(n, src)` | `n/8` octets from `src` | `E_WIDTH`, `E_ENTROPY` on a short read |
| `to_bytes(a)` | the `nb` octets, identity on `b` | — |
| `to_hex(a)` | exactly `n/4` lowercase hex digits, zero-padded | — |
| `to_uint(a)` | the big-endian integer value; **defined for `n <= 64` only** | `E_RANGE` if `n > 64` |
| `copy(a)` | a value-distinct equal BitArray | — |

`from_uint` rejecting `v >= 2^n` rather than masking is deliberate and is a change from
every current port.  Masking is how an out-of-range intermediate becomes a plausible-looking
in-range value with nothing recording that it happened.

**The `n <= 64` bound on the integer conversions was found by the first port and is a
correction to this document, not a concession to C.**  An earlier draft specified
`to_uint` at every width, which the Python reference satisfies trivially because its
integers are arbitrary-precision — and that is precisely the property this type exists to
stop depending on.  A port with no bignum cannot return a 256-bit integer, and requiring
it would force back in the `math/big` / `BigInteger` / Python-`int` dependency that
§1.1 removes.  The canonical form is the octet string (§1); `to_uint` is a convenience for
widths that fit a machine integer, and `E_RANGE` above that is the honest answer rather
than a silent truncation.

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
| **C (converted, v9.1.0)** | **`uint16_t nbits` + `uint8_t b[BA_MAX_BYTES]`, big-endian** | **variable, 16..256** | **`E_MIXED_WIDTH`** |
| **Go (converted, v9.2.0)** | **`nbits int` + `b []byte`, big-endian, both unexported** | **variable, 16..256** | **`E_MIXED_WIDTH`** |
| **Python (converted, v9.3.0)** | **`_nbits int` + `_b bytes`, big-endian** | **variable, 16..256** | **`E_MIXED_WIDTH`** |
| **Java (converted, v9.4.0)** | **`int nbits` + `byte[] b`, big-endian, immutable** | **variable, 16..256** | **`E_MIXED_WIDTH`** |

C's row before pass 2 read "`uint8_t b[KEYBYTES]`, fixed at compile time, not
expressible".  Go's before pass 3 read "`BitArray{ Val big.Int; size int }`, variable,
**silently returns all zeros**".  Python's before pass 4 read "`int` + `_size` + `_mask`,
variable, **silently discards the other operand**".  Java's read "bare `BigInteger` vs. a
static `N = 256`, fixed at 256, not expressible" — it could not pose the mixed-width
question at all, because a width was not a property of a value there but of the whole
port.  §6.1 and §6.2 are kept because the defects are the argument for this document, and
a fixed defect that nobody can still read about is a fixed defect nobody learns from.

### 6.1 Go returned zeros (fixed in pass 3)

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
`Bytes() = 0000000000000000`.  No error, no panic.  Under §3 this is `E_MIXED_WIDTH`,
and since pass 3 it is: `TryXor` returns it and `Xor` panics on it.

### 6.2 Python discarded (fixed in pass 4)

`__xor__` returned `BitArray(self._size, self._val ^ other._val)`, and the constructor
masked to `self._size`.  The same expression returned the left operand **unchanged**, the
right one having been masked away entirely.  Under §3 this is `E_MIXED_WIDTH`, and since
pass 4 it is: `_same_width` raises `BaError(E_MIXED_WIDTH)` before any operand is read.

Two variable-width ports, one operation, two different silent wrong answers.  That is
TODO #313's shape one layer down, and it is the argument for this document.

---

## 7. Conformance

`KAT/bitarray.json` pins every operation in §4 at widths 32, 64, 128 and 256, including
the error cases, which are pinned as *expected error codes* rather than as values.

`python3 KAT/generate_bitarray_kat.py --check` verifies currency — of the JSON **and** of
`KAT/bitarray_vector.h`, the C-array transposition the dependency-free C tree consumes in
place of a JSON parser (`KAT/hcred_kkw_vector.h`'s precedent, TODO #266) — and is gating.
`--report` prints per-port, per-operation conformance for the ports **not** yet converted;
it is a **report, not a gate**, because a port not yet converted is expected to differ and
`CLAUDE.md`'s Testing section allows no failing test.  A port joins the gating set when it
is converted — one port, one release.

**All four ports are in the gating set**, via `KAT/verify_bitarray_c.c`,
`KAT/verify_bitarray_go.go`, `KAT/verify_bitarray_py.py` and
`herradurakex.VerifyBitArray`, run by `CliTest/test_kat_vectors.sh` (the first three) and
`CliTest/test_java_bindings.sh` (the fourth, which is where the Java toolchain is already
set up): **376/376 each**.

A vector generated by the reference and checked only by the reference proves only that
nobody edited the file.  It became load-bearing at the first port and decisive at the
second: independent implementations against one pinned answer is what no round-trip or
interop test can supply, because those compare a port against another port's opinion.  C
reads the generated header while Go and Python read the JSON, so the three do not share a
single input file.

**Is a Python consumer checking a Python-generated vector circular?**  No, and the
distinction is worth stating because it is the obvious objection.  The reference is
`Ref` in `KAT/generate_bitarray_kat.py` — a separate class written against this document,
storing its own octets and keeping its own private `_int()`, sharing no code with the
suite.  The consumer loads the SHIPPED suite through `importlib`, exactly as the twenty
`SecurityProofsCode/` scripts do, and never touches `Ref`.  The two agree because both
satisfy this document, and the case goes red when they stop.  What a Python consumer
cannot do is prove the VECTOR right — three ports agreeing is what does that, which is
the whole reason the third one is worth having.

The Go consumer decodes with `json.Number`, and the reason belongs here rather than only
in its source: two cases carry integers above 2^53 — `to_uint`'s 7025791060798414911 at
n = 64, and `from_uint`'s 2^32 boundary — and a float64 decode rounds the first.  Go is
the first consumer to read this JSON at all, so it is the first that could meet the
hazard `CLAUDE.md` records for `nl_fscx_v3.json`.  It is **not** silent here: the pinned
answer disagrees and the case fails, which is the vector doing its job, and is why the
fix was an exact decode rather than a change to the file.

---

## 8. Sequencing

| pass | scope | state |
|---|---|---|
| 1 | this document, `KAT/bitarray.json`, the reference implementation in the generator, and the C type decision (§9) | **done, v9.0.1** |
| 2 | C — the constraint, and the only port that could not represent a narrow value at all | **done, v9.1.0** |
| 3 | Go — the port whose silent mixed-width answer (§6.1) is this document's argument, and the outlier §4.4 settles against | **done, v9.2.0** |
| 4 | Python — the other silent answer (§6.2), and the port whose integers make over-specification easy to miss | **done, v9.3.0** |
| 5 | Java — the last, and the one whose own header conceded constant-time away *because of* `BigInteger` | **done, v9.4.0** |
| 6 | relax TODO #313's refusal: `MIGRATING.md` §19 and `CliTest/test_narrow_width_matrix.sh` go from "all four refuse" to "all four agree" | **done, v9.5.0** |

Pass 6 needed **all four** ports, not three: a refusal may only be relaxed once every port
agrees, and two of four agreeing with the reference is not the four agreeing with each
other.  It is done: `hske-nla1` is accepted at every width §2 permits, in all four CLIs,
and `CliTest/test_narrow_width_matrix.sh` measures the full 4 × 4 matrix at 256, 128, 64
and 32 bits — 48 narrow cells, all agreeing.

Every pass MUST be behaviour-preserving at 256 bits, and 256 is where everything is
pinned — `KAT/` entire, the 518-assertion `test_cross_lang_matrix.sh`, and the numbered
tests in all four languages.  A port that moves one octet at 256 fails immediately.

### 8.1 What pass 3 cost outside the type (recorded, not argued)

§9 measured that the C change was source-compatible on the public surface.  The Go
change is **not**, and the difference is worth stating rather than discovering: `Val`
was an EXPORTED field and `GfMul`/`GfPow`/`GfPoly` were exported functions taking a
`poly *big.Int` and a width.  Making the fields unexported is what turned the compiler
into pass 2's poisoned build — it enumerated all 237 reach-ins rather than a grep doing
it — and it necessarily moves the package's API.

The blast radius was measured, not assumed: every consumer is in this tree
(`HerraduraCli`, `CryptosuiteTests`, the suite walkthrough, `KAT/verify_kat.go`,
`docs/examples/go`, `bindings/ffi/go`'s native cross-check), and all six are updated in
the same commit.  This is a Go PACKAGE API change and not a CLI/PEM/wire one, so under
`CLAUDE.md`'s rule it is MINOR, not MAJOR: no `--algo` changes what it produces or
accepts, and no stored artifact becomes unreadable.

`math/big` does not leave the Go tree with this pass and was never going to.  It stops
implementing the BitArray, and it keeps representing the objects this document does not
govern — QC-MDPC dense polynomials at r = 12323 bits, Stern and HCRED syndromes,
HCRED's Z_q coefficients, the OPRF and threshold scalars, and the PEM/DER codec's
INTEGERs.  What changed is that the boundary is now a door with a name on it
(`NewBitArray` and `BitArray.BigInt`) instead of 237 reach-ins, so it can be counted.

### 8.2 What pass 4 cost, and the one thing it measured that the others could not

Python's conversion is the cheapest of the three and the most easily mistaken for a
no-op, so what it actually settles is worth stating.

**The stored form is octets** (`_b: bytes`), for §1.1's reason: an integer normalises away
leading zero octets and needs a re-widening step on the way out.  **Python's private limb
is the interpreter's int**, which §1 explicitly permits — and that choice was measured
rather than argued.  A pure byte-loop rotation at n = 256 costs **7.60 µs against 0.35 µs**
for the int form, 21×, in a suite that already runs for half an hour.  Storing octets
costs **nothing** when a composite primitive converts once at its boundary and iterates in
the limb domain: `fscx_revolve(256, 64)` measures **100.9 µs either way**, and **+32%**
when the conversion is paid per step.  That is why `fscx` and the revolve loops take
`.uint` once and return one `BitArray`, and why the per-operation methods do not need to.

**`uint` is the bignum boundary, `to_uint` is the specified operation, and they are
deliberately different names.**  `to_uint` carries §4.1's `n <= 64` bound.  `uint` does
not, because Python's protocol layers — Z_q coefficients, QC-MDPC dense polynomials,
Stern and HCRED syndromes, OPRF and threshold scalars, DER INTEGERs — are integers by
their own definitions, as they are in Go, where the same crossing is spelled
`NewBitArray` / `BigInt`.  Keeping the two spellings apart is what stops "the value fits
in a machine word" and "give me the integer" from being one call.

**Constant time is marked, not claimed.**  §4 marks `equal`, `compare`, `is_zero`,
`popcount` and `bit` CT, and C and Go implement that literally — accumulate every octet,
no early exit.  Python cannot: its arbitrary-precision int is not constant-time and
neither is `bytes.__eq__`, which short-circuits.  The port says so in the class rather
than implementing a form that would look CT and not be, and the suite keeps using
`hmac.compare_digest` where constant time is load-bearing.  The marking is a statement
about the specified operation; whether a port can honour it is a property of the port.

**The public accessor surface did not move, and that is why the blast radius was 89 sites
and not 380.**  `.uint`, `.bytes`, `.hex`, `.copy()`, `.rotated()`, `^`, `==` and
`BitArray(size, value)` all keep their meaning, so the twenty `SecurityProofsCode/`
scripts that load the suite through `importlib` — sixteen of which touch `BitArray`, and
most of which gate a finding — needed no edit at all.  Only `._size`, `._val` and
`._mask`, which are private by name, had to move.  A representation change that leaves
the published surface alone is a different-sized job from one that does not: Go's `Val`
was exported, and that is the whole difference between §8.1 and this section.

### 8.3 What pass 5 bought that the other three could not

Java is the port TODO #314's **third reason** was written for, and the evidence is in the
port's own header.  `Herradura.java` said it mirrored the Python source "rather than
herradura.h's constant-time C implementation: java.math.BigInteger gives no constant-time
guarantee regardless, **so there is nothing to gain from porting the C branchless
tricks**".  That sentence is a security property conceded *because of a dependency
choice*, written down by the person who made it — which is exactly what reason 3 says the
BigInteger dependency costs.

Over a `byte[]` there is something to gain, so `equals`, `compare`, `isZero`, `popcount`
and the bitwise operations are now implemented the way C and Go implement them: every
octet touched, results folded with masks rather than branches, no early exit on a
data-dependent condition.  **What that buys is a branch-free structure, not a claim about
what a JIT emits** — the distinction §4 draws — and the suite still uses
`MessageDigest.isEqual` where constant time is load-bearing.  The header has been
rewritten to say so rather than left asserting a decision that no longer holds.

Two other things only this port had.

**It had no `rnl_kdf_seed` at all.**  The derivation was transcribed at **six** call sites
— two in `Hfscx256`, two in `HerraduraNl`, one in `Hpake`, one in `KatVerify` — each
against the 256-bit constant with a comment explaining that the shift is zero at n = 256.
That is TODO #312's finding in a fourth port, and it is why "exactly one truncation, in
one place" (#314's reason 1) was not available here however carefully each copy was
written.  There is now one.

**Its CLI passed the width beside the value.**  `loadKey` returned
`BigInteger[] { value, nbits }` — the width as a separate array element, read back as
`key[1]` at nineteen sites.  That is TODO #313's defect shape stated in a type: "two ports
that were handed a declared width and ignored it, which is only possible when the width
and the value can be separated" (§1).  It returns a `BitArray`, and the separation is no
longer expressible.

**The hazard of the conversion itself is worth recording, because it is this document's
own subject.**  Java's `equals(Object)` returns **false** for a different type rather than
failing to compile, so every place the conversion left a `BitArray` compared against a
`BigInteger` became a silently wrong answer — a round-trip check that always fails, or a
difference check that always passes.  Four separate instances survived three successive
audits, and **every one of them was caught by an existing oracle**: `SelfTest` (the A3
round-trip), `Demo` (masked HSKE), `CodecTest` (the key round-trips) and `KatVerify`
(three vector sets).  A conversion that changes a type cannot rely on the compiler where
the language's equality is untyped; it has to rely on the tests, which is an argument for
having them rather than a reason to be uneasy about the method.

### 8.4 What pass 6 found, which is the reason a conformance vector is not enough

Pass 6 is the payoff and it was not a paperwork exercise.  Every port passed
`KAT/bitarray.json` 376/376 before it started, and **two of the four still produced the
wrong `hske-nla1` keystream below 256 bits** — because conforming to the type is not the
same as *consuming it at the value's width*.

**Java's NL-FSCX v1 round rotated by a static `N / 4`.**  `Hfscx256.NL_V1_SHIFT` was
`Herradura.N / 4` = 64, correct at 256 and at no other width, sitting one line below a
`BitArray` that carries its width faithfully.  The measurement is what found it: the
four-port probe agreed on `rnl_kdf_seed` at 32, 64, 128 and 256 — the site TODO #313 was
*about* — and disagreed on the keystream in Java alone.  A conformance vector pins the
TYPE's operations; a constant in a consumer of the type is invisible to it.

**C's A1 path ran at `I_VALUE` and on fixed-`KEYBYTES` arithmetic.**  `ba_add256`,
`ba_sub256`, `ba_mul256` and `ba_rol64_256` looped `KEYBYTES` and rotated a fixed eight
octets; they are `ba_add_mod2n`, `ba_sub_mod2n`, `ba_mul_mod2n` and `ba_rol_quarter` now,
and **the names were the tell** — a function whose name contains its width is a function
that cannot take another one.  `hske_nla1_encrypt` takes `base.nbits / 4` steps.

**The result, measured rather than argued.**  The shipped suites of all four ports now
produce byte-identical A1 ciphertext at 32, 64, 128 and 256 bits from identical inputs,
and all 16 (writer × reader) CLI pairs round-trip at each of those widths.  Both fixes
were verified by reverting them: each one alone turns the matrix from 85/0 to 19 failures.

**What was NOT relaxed, and why the distinction matters.**  `encfile`/`decfile` still
refuse a narrow key.  The `.hkx` container has no width field — a 32-octet nonce, 32-octet
blocks, a 256-bit HFSCX-256 MAC — so that refusal is about a FORMAT that cannot describe
another width, not about ports that disagree, and Python, Go and Java enforced it long
before TODO #313 existed.  Two refusals also remain at `dec` and they are the specification
speaking: a declared width that is not a legal BitArray width is §2, and a ciphertext whose
declared width disagrees with the key's is §3's **mixed width, never coerced**.  That last
one is load-bearing rather than tidy: this CLI layer used to resolve the disagreement by
preferring one side — Go built the key at the *ciphertext's* width, C stamped 256 on
everything it wrote — and a reader that silently prefers either would pass the whole matrix
above and mis-decrypt a foreign artifact.

**The standing lesson, restated because pass 6 is where it paid.**  TODO #313's divergence
survived a green 518-assertion cross-language matrix because nothing in the repo ever ran
the algorithm at a second width.  Neither did a 376-case conformance vector for the type
underneath it.  What found both defects was one probe asking four shipped suites the same
question at four widths, which is the cheapest test in this item and the last one written.

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
