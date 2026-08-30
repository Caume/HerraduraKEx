# Migration Guide

This document consolidates every breaking change in the Herradura Cryptographic Suite's
history into one place. Individual `CHANGELOG.md` entries flagged each of these at the
time (search for "BREAKING" or "wire-format breaking" there for full technical detail);
this file exists so a reader doesn't have to reconstruct the list by scanning years of
changelog entries.

**Migrating to 2.0.0 itself introduces no new protocol or wire-format changes.** The
2.0.0 tag marks the CLI/PEM surface as a stable baseline going forward — see
[Migrating to 2.0.0](#migrating-to-200) below. Read the sections below for whichever of
these five breaks fall between your current version and the version you're upgrading to.
Three of them (1–3) predate 2.0.0. Of the two after it, the HKEX-RNL ring-dimension
move in v2.7.19 is the only one that leaves affected keys insecure rather than merely
incompatible — if you are on any version before v2.7.19 and use HKEX-RNL, start at
[section 4](#4-hkex-rnl-ring-dimension-256--1024-v2719).

The fifth is the reason the version is **3.0.0**. It is narrow in reach — it touches only
HKEX-RNL at a non-default `--bits N` below 256, and n = 1024 output is byte-for-byte
unchanged — but it changes what an existing `--algo` value produces, which is exactly
the surface the 2.0.0 tag froze. A break of that surface is a MAJOR bump regardless of
how few artifacts it reaches, so it gets one.

The seventh, in v3.3.0, is the only one on this list that leaves every stored artifact
readable and still breaks interoperation: `hpke-stern-kem` keys and ciphertexts are
unchanged byte-for-byte, but the *shared secret* derived from them is not. Nothing needs
regenerating; both ends simply have to be on the same side of the upgrade.

The ninth, in v5.0.0, is the widest on this list: it changes the NL-FSCX v2 round
function itself, so **five** constructions break together — `hske-nla2`, `hpke-nl`,
`hske-duplex`, `fpe` and `twk`. For the two unauthenticated ones the failure is silent,
as in section 8.
See [section 9](#9-nl-fscx-v2-round-constants-v500).

The eighth is the reason the version is **4.0.0**, and it is the one on this list most
likely to lose data if it is ignored. `fpe` and `twk` ciphertexts written by any earlier
build cannot be decrypted by 4.0.0+, and because both subcommands are unauthenticated
permutations the failure is **silent** — you get plaintext-shaped garbage, not an error.
If you have stored any, decrypt them with a pre-4.0.0 build first. See
[section 8](#8-fpe-and-twk-subkey-derivation-v400).

---

## Summary table

| Break | Introduced in | Affects | Action required |
|---|---|---|---|
| [HKEX → HKEX-GF; HPKS/HPKE → Schnorr/El Gamal](#1-hkex--hkex-gf-hpkshpke--schnorrel-gamal-v140) | v1.4.0 | Library API only (predates the CLI/PEM format) | None — no PEM artifacts from this era exist |
| [HFSCX-256 → HFSCX-256-DM](#2-hfscx-256--hfscx-256-dm-v190) | v1.9.0 | Hash digests, pre-hashed signatures, AEAD tags | Regenerate on v1.9.0+ |
| [Stern parity-matrix (H) finalization](#3-stern-parity-matrix-h-finalization-v1935) | v1.9.35 | HPKS-Stern-F keys/signatures, HPKE-Stern-F ciphertexts | Regenerate on v1.9.35+ |
| [HKEX-RNL ring dimension 256 → 1024](#4-hkex-rnl-ring-dimension-256--1024-v2719) | v2.7.19 | HKEX-RNL private/public keys, kex responses, ZKP-RNL proofs | Regenerate on v2.7.19+ — the old keys are not just incompatible, they are insecure |
| [HKEX-RNL small-ring session-key width](#5-hkex-rnl-small-ring-session-key-width-v300) | v3.0.0 | `HERRADURA SESSION KEY` PEMs from `kex --algo hkex-rnl --bits N` with N < 256 | Redo the handshake on v3.0.0+; nothing to do at the default ring |
| [`SternSig` is heap-backed and carries its own round count](#6-sternsig-is-heap-backed-and-carries-its-own-round-count-v310) | v3.1.0 | C code using `herradura.h` directly (`SternSig`, `hpks_stern_f_sign`/`-verify`, `hcred_issue`) | Add `stern_sig_alloc`/`stern_sig_free` around each `SternSig`. **No PEM, wire-format or CLI break** — existing signatures still verify byte-for-byte |
| [HPKE-Stern-KEM session-key derivation](#7-hpke-stern-kem-session-key-derivation-v330) | v3.3.0 | Shared secrets from `--algo hpke-stern-kem` and `--algo hybrid-rnl-stern`; anything encrypted under one | Both peers must be on v3.3.0+. **No key or ciphertext format change** — existing keys and ciphertexts are still read; only the derived secret differs |
| [`fpe` and `twk` subkey derivation](#8-fpe-and-twk-subkey-derivation-v400) | v4.0.0 | Every `fpe` and `twk` ciphertext written by any earlier build | **Decrypt with a pre-4.0.0 build before upgrading.** Old ciphertexts cannot be recovered by 4.0.0+, and the failure is silent |
| [NL-FSCX v2 round constants](#9-nl-fscx-v2-round-constants-v500) | v5.0.0 | Every `hske-nla2`, `hpke-nl`, `hske-duplex`, `fpe` and `twk` ciphertext written by any earlier build | **Decrypt with a pre-5.0.0 build before upgrading.** Five constructions at once; for `fpe`/`twk` the failure is silent |

---

## 1. HKEX → HKEX-GF; HPKS/HPKE → Schnorr/El Gamal (v1.4.0)

**What changed:** The original HKEX key exchange was proven broken — its shared secret
`sk = S_{r+1}·(C⊕C2)` is directly computable from the two public wire values alone, with
no private key needed (see `SecurityProofs.md` history, Theorem 7). v1.4.0 replaced it
with HKEX-GF (standard Diffie-Hellman over `GF(2^n)*`), and replaced the equally
trivially-reversible XOR-based HPKS/HPKE constructions with a Schnorr signature and El
Gamal encryption respectively.

**What's incompatible:** Nothing you need to act on. This break happened at the library
API level, years before `HerraduraCli/` (the PEM-producing CLI) existed — see TODO #25
in `TODO_DONE.md`. No PEM file was ever produced under the old HKEX/HPKS/HPKE
constructions, so there is nothing to regenerate.

**Action required:** None.

---

## 2. HFSCX-256 → HFSCX-256-DM (v1.9.0)

**What changed:** The HFSCX-256 hash's compression function was upgraded to a
Davies-Meyer construction (renamed HFSCX-256-DM): every compression step now feeds the
pre-compression state back in, `C_DM(s, m) = F_1^{64}(s, m) ⊕ s` instead of
`C(s, m) = F_1^{64}(s, m)`. This closes a fixed-point weakness — see
`SecurityProofs-6.md` §11.9.8.

> **Correction (v2.7.12, TODO #215):** this entry originally also claimed the change
> "aligns the construction with one of the 12 provably-secure PGV compression
> functions". That claim is withdrawn: the PGV results hold in the ideal-*cipher*
> model and require a per-block permutation, which `nl_fscx_v1` is not. The
> fixed-point benefit above is unaffected, and the bounds are re-derived in the
> ideal-random-function model in `SecurityProofs-6.md` §11.9.12 — where every
> previously published figure still holds. Nothing about the v1.9.0 wire-format
> change or the action required below is altered.

**What's incompatible:** Any HFSCX-256 digest, `--kdf hfscx-256` derived key,
pre-hash-signed message digest, or HSKE-NL-AEAD authentication tag computed before
v1.9.0. Because HFSCX-256(-DM) is used as the KDF on `kex --kdf hfscx-256`, as the
pre-hash for `sign`/`verify --digest hfscx-256`, and inside HSKE-NL-AEAD's tag
computation, all three of those outputs change.

**Action required:** If any of your stored digests, KDF-derived session keys,
pre-hash-signed signatures, or AEAD ciphertexts/tags were produced before v1.9.0,
regenerate them on v1.9.0 or later. Ordinary HKEX-GF/HKEX-RNL key exchange (without
`--kdf hfscx-256`) and non-AEAD HSKE encryption are unaffected — they don't invoke the
hash at all.

---

## 3. Stern parity-matrix (H) finalization (v1.9.35)

**What changed:** The HPKS-Stern-F / HPKE-Stern-F public parity-check matrix H is
generated by hashing row seeds through NL-FSCX v1. Before v1.9.35, that raw output was
truncated to n bits directly; v1.9.35 routes it through HFSCX-256-DM first (matching
what `_stern_hash` had already done since v1.6.0), fixing a range-compression weakness
that made H distinguishable from a uniform random binary matrix (~21–28% distinct rows
at n=32, predicted far worse at n=256) — see `SecurityProofs-5.md` §11.8.4.

**What's incompatible:** H changes, so **every** HPKS-Stern-F public key, syndrome, and
signature, and every HPKE-Stern-F KEM ciphertext, generated before v1.9.35 is
incompatible with v1.9.35+. This is unrelated to and independent of item 2 above —
regenerating for the HFSCX-256-DM break does not also fix this one, and vice versa.

**Also relevant:** v1.9.36 (the very next release) fixed two *separate* bugs that broke
cross-language HPKS-Stern-F signature interop (Python-signed signatures failing C/Go
verification and vice versa) — a challenge-derivation mismatch and a syndrome
byte-ordering mismatch, unrelated to the H-matrix change itself. If you're regenerating
Stern-F artifacts anyway, use v1.9.36+ rather than stopping at v1.9.35, so
cross-language verification works correctly too (`CliTest/test_stern_interop.sh`
exercises all 9 Python/C/Go sign→verify combinations).

**Action required:** If any HPKS-Stern-F or HPKE-Stern-F key material was generated
before v1.9.35, regenerate it on v1.9.36 or later.

---

## Migrating to 2.0.0

If you are already on v1.9.36 or later, **2.0.0 requires no action** — it introduces no
protocol, CLI, or wire-format changes of its own. It marks the point at which the
CLI/PEM surface (subcommands, flags, PEM boundary labels) is treated as a stable
baseline: from 2.0.0 forward, a change of this kind will bump the MAJOR version and get
its own entry in this file, rather than being buried in a PATCH-level `CHANGELOG.md`
entry as the three breaks above were.

If you're upgrading from before v1.9.35, read all three sections above in order, since
your artifacts may be affected by more than one of them.

---

## 4. HKEX-RNL ring dimension 256 → 1024 (v2.7.19)

**What changed:** The HKEX-RNL ring dimension moved from `n = 256` to `n = 1024`.
`q = 65537`, `p = 4096`, `eta = 1`, and `pp = 4` are all unchanged.

**Why:** TODO #216 computed the deployed parameters directly instead of citing them and
found HKEX-RNL was worth about **32 classical / 29 quantum Core-SVP bits**, not the
~105/~100 previously documented — and that HKEX-RNL-128 at `n = 512`, which the docs
promoted as the production-track answer, reached only ~87/~79. Neither met the 128-bit
claim. TODO #223 selected `n = 1024`, which reaches ~206 classical / ~187 quantum.

`n = 768` was considered and **rejected as unsound**: `x^768 + 1` factors over the
integers as `(x^256 + 1)(x^512 - x^256 + 1)`, so the ring CRT-splits and a short secret
stays short under projection into the 256-dimensional component — worth only ~39/~36
bits. `x^1024 + 1` is the 2048th cyclotomic polynomial, irreducible over Q, so no such
projection exists.

**What's incompatible:**

- `HERRADURA HKEX-RNL PRIVATE KEY` and `HERRADURA HKEX-RNL PUBLIC KEY` PEM files —
  the ring elements are four times as long, and the encoded `n` field changes.
- `HERRADURA HKEX-RNL RESPONSE` PEM files — both the public element and the
  reconciliation hint grow with `n`.
- ZKP-RNL (`rnl-sigma`) proofs, which are statements about an HKEX-RNL key.
- `hybrid-rnl-stern` key exchange, whose Ring-LWR half is HKEX-RNL.

A new build rejects an old key with a ring-size mismatch rather than misinterpreting it,
because `n` is carried explicitly in every RNL PEM.

**Action required:** regenerate HKEX-RNL keypairs on v2.7.19 or later:

```
herradura genpkey --algo hkex-rnl --out alice.pem
herradura pkey --in alice.pem --pubout --out alice_pub.pem
```

Unlike the earlier breaks in this document, this one is not merely a format change.
Keys generated before v2.7.19 are at ~32-bit security and any HKEX-RNL session
established with them should be treated as compromised, not merely stale. There is no
migration path that preserves an old key, and there should not be one.

**Costs of the move:** public keys grow from 384 to 1536 bytes, and a handshake costs
roughly 5x what it did (the NTT is O(n log n), so 4x the dimension is about 5x the
work). The derived session key is unchanged at 256 bits — the ring dimension and the key
width are now separate quantities, where before they were the same number.

**Small rings still work.** `--bits N` still overrides the ring dimension for interop
and testing. They were never at 128-bit security and still are not; `--bits` is not a
supported way to opt out of this migration.

> **Correction (v3.0.0, TODO #228):** this paragraph originally added that rings below
> 256 "keep deriving an N-bit key as they always did". That was never true of all four
> CLIs — they disagreed four ways — and as of v3.0.0 it is true of none of them. The
> derived session key is 256 bits at every ring dimension; see
> [section 5](#5-hkex-rnl-small-ring-session-key-width-v300).

**Not affected:** HCRED keeps its own ring at `n = 256`. It shares HKEX-RNL's ring
arithmetic but its remaining parameters are tuned for that dimension, and its security is
tracked separately; its PEM files are unchanged. The assembly, NASM, and Arduino targets
run `RNL_N = 32` and are unchanged — they were demo-only before this migration and remain
so.
---

## 5. HKEX-RNL small-ring session-key width (v3.0.0)

**What changed:** For HKEX-RNL, the derived session key is now **256 bits at every ring
dimension**. Before v3.0.0 the CLIs labelled it with the ring-dependent reconciliation
width, so at `--bits N` for N < 256 the wire format claimed an N-bit key.

**Why:** The two are different quantities and only coincide at n >= 256. Reconciliation
extracts 2 bits from each of `key_bits/2` coefficients, so an n-coefficient ring bounds
how much *raw* entropy the handshake can yield — that is genuinely n bits at a small
ring. But the contributory KDF that turns that raw value into the session key is
`HFSCX-256(K_raw || n_A || n_B)`, whose output is 256 bits regardless. Labelling the
output with the input's width made the two numbers disagree, and each CLI reconciled the
disagreement differently: Python wrote the full 256-bit digest under an `nbits=64`
label, Go truncated the digest to 64 bits to match the label, Java did a third thing, and
C — which had only ever encoded 256 here — could not read a small ring at all. Fixing it
in C's direction is the only choice that changes nothing at the deployed ring.

**What's incompatible:**

- `HERRADURA SESSION KEY` PEM files produced by `kex --algo hkex-rnl --bits N` with
  N < 256, and any HSKE ciphertext encrypted under such a key. The HSKE block width at a
  small ring goes from N bits to 256.

Nothing else. `HERRADURA HKEX-RNL PRIVATE KEY`, `PUBLIC KEY`, and `RESPONSE` PEMs are
unchanged at every ring dimension, small rings included — a RESPONSE PEM already stored
the full 256-bit derived key; only the width the reader *ascribed* to it was wrong.

**Action required:** none at the default ring. `n = 1024` output is byte-for-byte
identical before and after, and `KAT/pem/`'s n=1024 artifacts are unchanged across this
release to demonstrate it. If you kept a small-ring session key or a ciphertext under
one, redo the handshake on v3.0.0 or later:

```
herradura kex --algo hkex-rnl --our bob.pem --their alice_pub.pem --out bob_resp.pem
herradura kex --algo hkex-rnl --our alice.pem --their bob_resp.pem --out alice_sk.pem
```

**Scope note:** `--bits N` below 256 is a demo and interop facility and was never at a
security claim, so this is a correctness and interoperability fix, not a vulnerability.
No two CLIs previously agreed on the old behaviour, so there was no interoperable format
to preserve here — but it does change what an existing `--algo` value produces, and that
is a break of the surface 2.0.0 froze whether or not anything depended on it. Hence
3.0.0 rather than a patch release.

---

## 6. `SternSig` is heap-backed and carries its own round count (v3.1.0)

**This is a C source-compatibility break only.** No PEM changes, no wire-format change, no
CLI flag removed or repurposed. Signatures and HCRED credentials produced by any earlier
version still verify byte-for-byte, and the DER encoding of an existing 32-round signature
is unchanged down to the byte (`02 01 20`). If you only use the CLIs, there is nothing to
do — this release strictly *widens* what they accept.

**What changed:** `SternSig` was a fixed-size struct whose arrays were dimensioned by the
compile-time `SDF_ROUNDS`:

```c
typedef struct {
    BitArray c0[SDF_ROUNDS], c1[SDF_ROUNDS], c2[SDF_ROUNDS];
    int      b[SDF_ROUNDS];
    BitArray resp_a[SDF_ROUNDS], resp_b[SDF_ROUNDS];
} SternSig;
```

It now carries the round count as data, with heap-allocated arrays:

```c
typedef struct {
    int       rounds;
    BitArray *c0, *c1, *c2;
    int      *b;
    BitArray *resp_a, *resp_b;
} SternSig;
```

**Why:** the round count has always been on the wire — item[1] of the DER SEQUENCE — but
the C reader compared it against its own `SDF_ROUNDS` and rejected any mismatch. Two C
builds with different `SDF_ROUNDS` were therefore mutually unreadable in both directions,
and the `SDF_ROUNDS=32 -> 219` upgrade path documented for 128-bit Fiat-Shamir soundness
was unreachable from C without recompiling every peer in lockstep. It also meant
cross-language HCRED interop was only ever exercised at 32 rounds, because CI asked the
Python and Go issuers for `--rounds 32` to match C. See TODO #236.

**What's incompatible:** C code that includes `herradura.h` and declares a `SternSig`
directly. The dangerous part is that such code **still compiles**: the struct is smaller
now, and the members are pointers rather than arrays, so a bare

```c
SternSig sig;
hpks_stern_f_sign(&sig, &msg, &e, &seed, urnd);   /* undefined behaviour */
```

passes the compiler and then writes through uninitialized pointers at run time. There is
no diagnostic. Audit for `SternSig` declarations rather than relying on the build to find
them.

**Action required:**

```c
SternSig sig;
stern_sig_alloc(&sig, SDF_ROUNDS);            /* or SDF_PRODUCTION_ROUNDS (219) */
hpks_stern_f_sign(&sig, &msg, &e, &seed, urnd);
int ok = hpks_stern_f_verify(&sig, &msg, &seed, syndr);
stern_sig_free(&sig);
```

`stern_sig_load` / `stern_sig_load_label` allocate the signature themselves, from the
round count in the PEM — call `stern_sig_free` when done, and do not `stern_sig_alloc`
beforehand. `hpks_stern_f_sign` and `hpks_stern_f_verify` both follow `sig->rounds`;
`SDF_ROUNDS` is now only the default a caller passes to `stern_sig_alloc`, never a
constraint on what can be read. Decoded round counts are bounded to
`[1, SDF_MAX_ROUNDS]` (4096) so a hostile PEM cannot drive an unbounded allocation.

**Also new:** `sign --algo hpks-stern --rounds N` and `cred-issue --rounds N` in the C
CLI, matching the Go and Python CLIs. This is what makes the version bump a MINOR rather
than a PATCH; the C CLI previously took the round count only at compile time via
`-DSDF_ROUNDS=219`, which remains supported and still sets the *signing* default.

---

## 7. HPKE-Stern-KEM session-key derivation (v3.3.0)

**What changed:** `hpke-stern-kem` decapsulation gained a Fujisaki-Okamoto transform with
implicit rejection (TODO #235 Part 2), and the session key it derives changed with it:

| | before v3.3.0 | v3.3.0 onward |
|---|---|---|
| success | `HFSCX-256(e0 \|\| e1)` | `HFSCX-256-DS(0x10, e0 \|\| e1 \|\| C)` |
| failure | *error: no key* | `HFSCX-256-DS(0x11, z \|\| C)`, `z = HFSCX-256-DS(0x12, h0 \|\| h1)` |

**Why:** decapsulation used to report failure — a distinct return value in the library and
a distinct exit status plus stderr message at all four CLIs. That signal was the oracle the
GJS reaction attack consumes to recover the private key (`SecurityProofs-5.md` §11.8.7,
TODO #218 §5–§6). Removing it means decapsulation must return *something* on failure, and
the standard construction returns a pseudorandom key bound to the ciphertext. The success
path was domain-separated and bound to the ciphertext in the same change: HFSCX-256 is
Merkle-Damgard, so length extension applies, and an FO transform hashes attacker-influenced
data.

**What's incompatible:** the derived shared secret, and only that. Specifically:

- A v3.3.0 peer and a pre-v3.3.0 peer running `enc`/`dec --algo hpke-stern-kem` against
  each other will each derive a *different* 32-byte key, and — because the failure path is
  now silent — **neither will report an error.** The decryption simply produces garbage.
  The same applies to `kex --algo hybrid-rnl-stern`, whose KEM half feeds the combiner.
- Anything encrypted under a session key derived before v3.3.0 cannot be decrypted by
  re-running decapsulation on v3.3.0+. If you have stored such a ciphertext and still need
  it, decrypt it with a pre-v3.3.0 build first.

**What is *not* incompatible:** `HERRADURA QC-MDPC` private keys, public keys and
ciphertext PEMs are all unchanged byte-for-byte and are still read by both sides. The
implicit-rejection secret `z` is *derived* from `h0 || h1` rather than stored, precisely so
that no PEM field had to be added and existing private keys keep working. The CLI surface
— subcommands, flags, `--algo` values — is unchanged.

**Action required:** upgrade both ends together. There is nothing to regenerate: keep your
existing keys, and redo any handshake that spans the upgrade.

**Why this is a MINOR and not a MAJOR.** No PEM boundary label changed, no CLI flag was
renamed or removed, and no existing key, ciphertext or signature file became unreadable —
the surface the 2.0.0 tag froze is intact. What changed is a derived secret, in a protocol
classified **demo-only** in `SECURITY.md` for reasons this change does not alter. It is
recorded here anyway, because a silent wrong-key outcome is exactly the kind of break a
reader should not have to discover from a garbled plaintext.

**One further behavioural change to be aware of**, not a wire-format matter but the reason
a passing test can now be meaningless: a decoding failure (measured DFR ~0.225% per
encapsulation at the deployed toy parameters) no longer surfaces as an error. It surfaces
as a shared secret the two parties disagree on. Any script or application that treated
`dec --algo hpke-stern-kem` exiting 0 as proof of success is no longer testing the KEM —
it must compare output bytes. `CliTest/lib_dfr.sh` documents the retry policy this
implies.

---

## 8. `fpe` and `twk` subkey derivation (v4.0.0)

**What changed:** both subcommands derive their 256-bit subkey differently, and both run
more rounds.

| | before v4.0.0 | v4.0.0 onward |
|---|---|---|
| `fpe` subkey | `HFSCX-256(key ‖ ctx)` | `HFSCX-256-DS(0x20, len(key)_be8 ‖ key ‖ ctx)` |
| `twk` subkey | `HFSCX-256(key ‖ sector_be64 ‖ bidx_be32)` | `HFSCX-256-DS(0x21, len(key)_be8 ‖ key ‖ sector_be64 ‖ bidx_be32)` |
| step count | `I_VALUE` = 64 | `R_VALUE` = 192 |

Both derivations additionally reject the subkey and rehash if it lands in NL-FSCX v2's
degenerate affine class — a backstop that is effectively never taken, since the class is
about `2^-129` of the space and the subkey is a hash output.

**Why:** three defects, all found by TODO #241 and measured in `SecurityProofs-7.md`
§11.24.

1. *The two subcommands were the same function.* Neither derivation carried a
   domain-separation tag, so a 12-byte `fpe --context` equal to `twk`'s
   `sector_be64 ‖ bidx_be32` produced the identical subkey. `twk --decrypt` recovered
   what `fpe --encrypt` produced, byte-identically in the C, Go and Python CLIs. Two
   separately-advertised primitives reachable under one key were not independent.
2. *The key/tweak boundary was unencoded.* `key ‖ tweak` does not record where the key
   ends, so `(key=AB, ctx=C)` and `(key=A, ctx=BC)` collided — and the CLI takes key
   width from the session-key PEM, so key length was never fixed by the interface.
3. *The round count was a third of its parent's.* Both run HSKE-NL-A2's
   `nl_fscx_revolve_v2`, which A2 uses at 192 steps; these used 64. TODO #214's trail
   projection puts 64 rounds at `2^-119` against the 137 rounds it estimates for
   `2^-256`. Folded into this break rather than spent as a second one.

**What's incompatible:** every `fpe` and `twk` ciphertext ever written. There is no
format or length change — the files are the same 32 bytes they always were — but the
permutation that produced them is different, so a 4.0.0 build decrypts them to garbage.

**This failure is silent.** Both subcommands are unauthenticated permutations with no
tag, no checksum and no structure in the output. A 4.0.0 build handed a 3.x ciphertext
exits 0 and writes 32 plausible-looking bytes. Nothing will tell you the decryption was
wrong except comparing against the original plaintext. This is the single most important
line in this section.

**Action required — do this before upgrading:**

1. Find any stored `fpe` or `twk` output. If you have none, there is nothing to do; keys
   are unaffected, and `HERRADURA SESSION KEY` PEMs are read unchanged.
2. Decrypt it with a **pre-4.0.0** build, under the same key and tweak you encrypted it
   with.
3. Upgrade, then re-encrypt with 4.0.0+ if you still need it stored.

There is no conversion tool and no dual-read mode: the old derivation was removed rather
than kept behind a flag, because a flag that silently selects between two subkey
derivations is the same hazard in a different shape.

**What is *not* affected:** every other subcommand and protocol. `rand` is untouched.
Keys, public keys and all other PEM types are unchanged. The CLI surface — subcommands,
flags, `--algo` values — is unchanged; `fpe --context`, `twk --sector` and `twk --bidx`
all still mean exactly what they meant.

**Why this is MAJOR rather than MINOR.** It changes what an existing CLI surface
produces and makes existing files unreadable by a newer build, which is precisely what
CLAUDE.md reserves MAJOR for. That the affected protocols are classified `broken` and
`demo-only` in `SECURITY.md` does not downgrade it: the version number describes the
compatibility break, not the maturity of what broke.

**Still open after this change.** `fpe` is still not format-preserving encryption in the
SP 800-38G sense — no radix, no domain, 32 bytes in and 32 raw bytes out. TODO #242
scoped that out deliberately: renaming it, re-scoping it, or implementing a real
FF1/FF3-1 domain is a different decision from a wire-format fix, and bundling them would
have forced both at once. `SECURITY.md`'s `fpe` row records it meanwhile.

---

## 9. NL-FSCX v2 round constants (v5.0.0)

**What changed:** `nl_fscx_revolve_v2` and its inverse now XOR the 1-based round index
into the state before each step. One XOR per round.

```
before v5.0.0   for i in 1..r:   x = M(x ⊕ B) + δ(B)          every round identical
v5.0.0 onward   for i in 1..r:   x = M(x ⊕ i ⊕ B) + δ(B)      rounds differ
```

The single-step `nl_fscx_v2` is unchanged; only the revolve loops carry the constant.
`R_VALUE` stays at 192.

**Why:** without a round constant the cipher was `F_B^r` — one unvaried map iterated —
which `SecurityProofs-7.md` §11.25 and §11.26 found two consequences of. A slid pair very
nearly determines the key, and the ~`2^128` cost of finding one does not depend on the
round count, so adding rounds could never help. And `E_B` deviated measurably from an
ideal cipher on fixed points: at `n = 16` the median key had 4 where an ideal cipher has
1, and 76% of keys exceeded 1 against an ideal 37%. At some widths — 38/300 keys at
`n = 8`, 1/300 at `n = 16` — `F_B^r` was the **identity map**, though `256 ∤ 192` kept
that away from the deployed parameters.

Round constants remove all of it, and cost nothing measurable: `xdp+` is *exactly*
invariant under an XOR constant (§11.27.1), so TODO #214's differential trail bounds carry
over verbatim.

**What's incompatible — five constructions, not one:**

| affected | what breaks |
|---|---|
| `enc`/`dec --algo hske-nla2` | every ciphertext |
| `enc`/`dec --algo hpke-nl` | every ciphertext (El Gamal layer unchanged; the v2 envelope is not) |
| `enc`/`dec --algo hske-duplex` | every ciphertext |
| `fpe --encrypt`/`--decrypt` | every ciphertext |
| `twk --encrypt`/`--decrypt` | every ciphertext |

No key format changes. No PEM label changes. No CLI flag or `--algo` value changes.
`HERRADURA SESSION KEY` PEMs and every other key type are read exactly as before.

**The `fpe` and `twk` failures are silent**, for the same reason as section 8: both are
unauthenticated permutations with no tag and no structure in the output, so a v5.0.0 build
handed a 4.x ciphertext exits 0 and writes 32 plausible-looking bytes. `hske-nla2` and
`hske-duplex` go through the AEAD/PEM layer and will fail visibly.

**Action required — before upgrading:**

1. Identify any stored `hske-nla2`, `hske-duplex`, `fpe` or `twk` output.
2. Decrypt it with a **pre-5.0.0** build, under the same key and tweak.
3. Upgrade, then re-encrypt if you still need it stored.

There is no conversion tool and no dual-read mode: the constant-free path was removed
rather than kept behind a flag, because a flag selecting between two round functions is
the same hazard in a different shape.

**Not affected:** NL-FSCX **v1** and everything built on it — HSKE-NL-A1, HFSCX-256 and
every hash, signature and KEM that uses them — plus HKEX-GF, HKEX-RNL, the Stern family,
`rand`, and all classical constructions. The change is confined to the v2 revolve. The
Arduino and assembly ports were also left unchanged: their v2 is a separate 32-bit
construction with no wire compatibility to anything.

**Why this is MAJOR.** It makes existing ciphertexts unreadable by a newer build, which is
what CLAUDE.md reserves MAJOR for. That the four affected protocols are all rated
`demo-only`, `research` or `broken` in `SECURITY.md` does not downgrade it: the version
number describes the compatibility break, not the maturity of what broke.

**What it does *not* change: any rating.** `hske-nla2` and `twk` remain demo-only. The fix
removes the structural objections §11.25 and §11.26 raised, which puts the differential
trail bounds back in the binding position — and those are still key-averaged and
explicitly order-of-magnitude, with no PRP/SPRP reduction behind them. Removing an
objection is not supplying a proof.
