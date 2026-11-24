# HerraduraKEx Protocol Specification

Version: 1.0.0 (tracks `spec/herradura-protocol-spec.json` schema version 1.0.0)
Status: Informational — describes the classical quartet and its NL/PQC and
code-based (Stern) variants as implemented in this repository. This is not
an IETF RFC; it borrows RFC conventions (MUST/SHOULD/MAY per RFC 2119,
numbered algorithm steps) to make independent reimplementation possible
from this document alone, in the style of the Noise Protocol Framework
and the `age` specification.

This document is prose and self-contained: it does not require reading
the suite source to reimplement a protocol. For a machine-readable
summary of PEM labels, CLI `--algo` tags, and security classification,
see `spec/herradura-protocol-spec.json`. For proofs and cryptanalysis
behind the design choices below, see `SecurityProofs.md` (index) and its
parts. For fixed test vectors to check a new implementation against, see
`KAT/classical_quartet.json` and `KAT/generate_kat.py --check`.

## 1. Notational Conventions

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are
to be interpreted as described in RFC 2119.

- `n` — the bit width of the working group/ring (`KEYBITS`; 256 in the
  C/Go/Python suite and CLI; 32 in the assembly/Arduino targets).
- `A ⊕ B` — bitwise XOR of two `n`-bit values.
- `A ‖ B` — concatenation of byte strings.
- `ROL(A)`, `ROR(A)` — left/right rotation of the `n`-bit value `A` by
  one bit position.
- `A + B`, `A − B` — addition/subtraction of `n`-bit values modulo `2^n`
  (unsigned wraparound), distinct from GF(2^n) addition (which is XOR).
- `g^x mod P(z)` — exponentiation in GF(2^n)*, the multiplicative group
  of the finite field GF(2^n) defined by a fixed irreducible polynomial
  `P(z)` of degree `n` (§3).
- All integers are unsigned and represented as `n`-bit (or otherwise
  stated width) big-endian byte strings when serialized, unless noted.
- `i = n/4`, `r = 3n/4` — the fixed FSCX-REVOLVE step counts used
  throughout the classical and NL protocol suite (§4.2, §5).

## 2. Design Goals and Non-Goals

HerraduraKEx is built from two primitives — FSCX (§3.1) and Diffie-Hellman
over GF(2^n)* (§3.2) — combined into four protocols: a key exchange
(HKEX-GF), a symmetric cipher (HSKE), a Schnorr-style signature (HPKS),
and an El Gamal-style asymmetric cipher (HPKE). §6–§8 describe non-linear
(NL-FSCX) and lattice-based (Ring-LWR) variants intended to resist
quantum adversaries, and §9 describes a code-based (Stern ZKID)
signature and KEM family with an independent, better-studied hardness
assumption.

**Non-goals of the classical quartet (§4–§5):** HKEX-GF, HPKS and HPKE
rely on the discrete-log problem in GF(2^n)*, a group family NIST SP
800-57 Rev.5 (2020) and ENISA (2022) deprecate for new designs regardless
of `n`, because of the existence of sub-exponential index-calculus attacks
specific to extension-field groups. The binding attack is cheaper still:
the group order is `2^n − 1`, whose largest prime factor is 73 bits at
`n = 256`, so Pohlig-Hellman recovers a private key in about `2^36.5`
group operations (`SecurityProofs-3.md` §9.2.4). HSKE is pedagogical for
an unrelated reason of its own — see §5.1. **The classical quartet MUST NOT be
used for anything requiring real confidentiality or authenticity
guarantees; it exists for pedagogy, cross-language testing, and as the
substrate the NL/PQC variants build on.** Deployments SHOULD use
HKEX-RNL / HSKE-NL / HPKS-Stern-F / HPKE-Stern-KEM (§6–§9) instead. This
distinction is also recorded in `security.status` per protocol in
`spec/herradura-protocol-spec.json`.

## 3. Core Primitives

### 3.1. FSCX (Full Surroundings Cyclic XOR)

FSCX combines two `n`-bit values using XOR and single-bit rotation:

```
FSCX(A, B) = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
```

Viewed as a function of `A` alone (`B` fixed), FSCX is affine: define the
linear map `M = I ⊕ ROL ⊕ ROR` (composition of the identity and the two
rotation operators, XORed together as `n×n` GF(2) matrices). Then

```
FSCX(A, B) = M(A) ⊕ M(B)
```

`M` has multiplicative order `n/2` over GF(2) (i.e. `M^(n/2) = I`), which
determines the period structure of the iteration below.

**FSCX-REVOLVE(A, B, steps)** iterates FSCX `steps` times, holding `B`
fixed and re-feeding the result as the new first argument:

```
FSCX_REVOLVE(A, B, 0)     = A
FSCX_REVOLVE(A, B, k+1)   = FSCX(FSCX_REVOLVE(A, B, k), B)
```

Because `M` has order `n/2`, orbits under repeated FSCX-with-fixed-`B`
have length dividing `n/2` (equivalently `n` for the affine map with the
`M(B)` offset); the specific step counts `i = n/4` and `r = n − i = 3n/4`
used by HSKE (§5) and HPKE (§5.4) are chosen so that encryption and
decryption are each other's inverse — see §5.1 for the correctness
argument, and `SecurityProofs-2.md` §2–3 for the full period analysis.

### 3.2. GF(2^n)* Arithmetic

The suite fixes one irreducible polynomial `P(z)` of degree `n` over
GF(2) per supported width (`n = 256` is the default; 32-bit is used in
the assembly/Arduino targets). Field elements are `n`-bit values;
addition is XOR; multiplication `gf_mul(A, B)` is carryless (polynomial)
multiplication of `A` and `B` reduced modulo `P(z)`. `gf_pow(g, x)`
computes `g^x mod P(z)` by square-and-multiply. The multiplicative group
GF(2^n)* has order `2^n − 1` and a fixed generator `g = 3` (chosen for
having, at `n = 256`, multiplicative order equal to the full group
order `2^256 − 1`, i.e. it generates the whole group — verify by
confirming `3^((2^256-1)/q) ≠ 1` for every prime factor `q` of `2^256-1`
before reusing this generator at a different `n`).

## 4. HKEX-GF — Diffie-Hellman Key Exchange over GF(2^n)*

**PEM labels:** `HERRADURA HKEX-GF PRIVATE KEY` / `HERRADURA HKEX-GF PUBLIC
KEY`. **CLI:** `genpkey --algo hkex-gf`, `kex --algo hkex-gf`.

### 4.1. Key Generation

1. Sample a private scalar `a` uniformly from `[1, 2^n − 2]` (`n` random
   bits, discarding `0` and `2^n − 1`, which trivially reveal or fix the
   shared secret).
2. Compute the public value `C = g^a mod P(z)` (§3.2).
3. The key pair is `(a, C)`.

### 4.2. Key Agreement

Given a local private scalar `a` and a peer's public value `C_peer`:

```
shared_secret = C_peer^a mod P(z)
```

Both parties compute the same value: if Alice holds `(a, C_A = g^a)` and
Bob holds `(b, C_B = g^b)`, then `C_B^a = g^{ba} = g^{ab} = C_A^b`. The
raw `shared_secret` MAY be passed through a KDF before use (the CLI's
`kex --kdf hfscx-256` and `--kdf sp800227` options; `--kdf none` uses the
raw field element, NOT RECOMMENDED for anything but interop testing).

`kex --algo hkex-gf --kdf hfscx-256` works the same way at every width n
(32, 64, 128 or 256; TODO #389):

```
raw  = shared_secret as exactly n/8 big-endian bytes (leading zeros kept)
sk   = HFSCX-256(raw)                       -- always 256 bits
SESSION KEY = SEQUENCE { INTEGER sk, INTEGER 256 }
```

The session key is the whole digest and declares `n_bits = 256`, its own
width, whatever n the key exchange ran at, so it can key HSKE (`enc --algo
hske --key`) like any 256-bit session key; HKEX-RNL's session key is
labelled the same way (TODO #228).  Without `--kdf` the SESSION KEY holds
the raw n-bit `shared_secret` and declares `n_bits = n`.  No CLI truncates
the digest.  A 256-bit digest of a 64-bit secret still carries at most 64
bits of entropy (and the demonstration widths far less security, see the
`genpkey` warnings); the KDF fixes the key's FORMAT, not its strength.

### 4.3. Wire Format

Private key: DER `SEQUENCE { INTEGER a, INTEGER n_bits }`, PEM-wrapped
under the private-key label above. Public key: DER `SEQUENCE { INTEGER
C, INTEGER n_bits }`, PEM-wrapped under the public-key label. See
`HerraduraCli/herradura_codec.h` for the exact DER INTEGER/SEQUENCE
subset (0x02/0x30 tags, long-form length 0x81–0x84) — the encoding rules
themselves are shared verbatim across all four classical-quartet
protocols and are summarized in §10.

## 5. HSKE — Symmetric Encryption via FSCX-REVOLVE

**CLI:** `enc --algo hske` / `dec --algo hske` (also `encfile`/`decfile`).
HSKE requires a pre-shared `n`-bit symmetric key (e.g. an HKEX-GF or
HKEX-RNL shared secret, optionally KDF'd).

### 5.1. Encryption / Decryption

Given plaintext block `P` (`n` bits) and key `K`:

```
E = FSCX_REVOLVE(P, K, i)      i = n/4
D = FSCX_REVOLVE(E, K, r)      r = 3n/4  =  n − i
```

`D = P` because FSCX-REVOLVE-with-fixed-`B` is the affine map `M`
composed with itself `i` times plus an offset that telescopes; running it
a further `r = n − i` times completes the map's period (§3.1) back to the
identity on `P`, canceling the `K`-dependent offset. See
`SecurityProofs-2.md` §3 for the full derivation and `SecurityProofsCode/
hkex_gf_test.py` for a runnable check.

Multi-block messages MUST use a mode of operation on top of this
primitive (the CLI's `enc --algo hske` runs one block; see
`HSKE-Duplex`/`HSKE-NL-A1` in §7 for authenticated multi-block streaming
modes — HSKE itself provides no authentication and MUST NOT be used
without a separate MAC in any setting where an active adversary is in
scope).

**Confidentiality note.** The key reaches `E` only through the linear map
`M · S_i`, and at `i = n/4` that map is singular with co-rank 126 out of
256: the ciphertext alone discloses 126 independent linear functionals of
the plaintext, for every key and with no known plaintext
(`SecurityProofs-1.md` §1.3.1). HSKE therefore offers no confidentiality
claim at any key size and MUST NOT be used to protect data; implement it
for cross-language conformance, and use `HSKE-NL-A1`/`HSKE-NL-A2` (§9.2)
where encryption is actually required.

## 6. HPKS — Schnorr Signature over GF(2^n)*

**PEM labels:** `HERRADURA HPKS PRIVATE KEY` / `HERRADURA HPKS PUBLIC KEY`.
**CLI:** `genpkey --algo hpks`, `sign --algo hpks`, `verify --algo hpks`.

### 6.1. Key Generation

Identical to HKEX-GF §4.1: private scalar `a`, public value `C = g^a`.

### 6.2. Signing

Given a private key `a`, message `msg`:

1. Sample a nonce `k` uniformly from `[1, 2^n − 2]` (fresh per signature
   — nonce reuse across two different messages under the same key
   MUST NOT happen; it leaks `a` via the standard Schnorr linear-equation
   attack, since `s` is an affine function of `k`, `a`, and `e`).
2. Compute the commitment `R = g^k mod P(z)`.
3. Compute the challenge `e = FSCX_REVOLVE(R, msg_digest, i)` where
   `msg_digest` is `msg` reduced/padded to `n` bits (`i = n/4` as in §3.1)
   — this is the suite's Fiat-Shamir hash-substitute, binding the
   challenge to both the commitment and the message.
4. Compute the response `s = (k − a·e) mod (2^n − 1)` (arithmetic mod the
   group order, not mod `2^n`).
5. The signature is `(s, e)` (equivalently `(s, R)`, since `e` is
   recomputable from `R` and `msg`; the CLI stores `(s, e)`).

### 6.3. Verification

Given public key `C`, message `msg`, signature `(s, e)`:

1. Recompute `R' = g^s · C^e mod P(z)`.
2. Recompute `e' = FSCX_REVOLVE(R', msg_digest, i)`.
3. Accept iff `e' = e`.

Correctness: `g^s · C^e = g^{k-ae} · g^{ae} = g^k = R`, so `R' = R` for a
genuine signature, making `e'` recompute to the same value as step 6.2.3.

## 7. HPKE — El Gamal Encryption over GF(2^n)*

**PEM labels:** same key format as HKEX-GF (§4.3) — HPKE reuses HKEX-GF
key pairs. **CLI:** `enc --algo hpke`, `dec --algo hpke`.

### 7.1. Encryption

Given recipient public key `C = g^a`, plaintext block `P`:

1. Sample an ephemeral scalar `r` uniformly from `[1, 2^n − 2]`, fresh
   per message (reuse leaks equality of plaintexts to an eavesdropper
   who sees two ciphertexts under the same `r`, as in classical El
   Gamal).
2. Compute the ephemeral public value `R = g^r mod P(z)` (sent alongside
   the ciphertext).
3. Compute the shared encryption key `enc_key = C^r = g^{ar}`.
4. Compute the ciphertext `E = FSCX_REVOLVE(P, enc_key, i)` (§5.1,
   `i = n/4`).
5. Transmit `(R, E)`.

### 7.2. Decryption

Given private key `a`, received `(R, E)`:

1. Compute `dec_key = R^a = g^{ra} = g^{ar} = enc_key`.
2. Compute `D = FSCX_REVOLVE(E, dec_key, r)` (`r = 3n/4`, §5.1) `= P`.

## 8. NL-FSCX — Non-Linear Hardening Primitive

FSCX (§3.1) is GF(2)-affine, which the classical protocols above do not
try to hide — the "classical" quartet's security rests entirely on the
GF(2^n)* discrete-log assumption, not on FSCX's non-linearity. NL-FSCX
replaces the affine step with two deliberately non-linear constructions,
each used by a different family of "-NL" protocols (§9).

### 8.1. NL-FSCX v1 (used by HSKE-NL-A1 and HFSCX-256; HPKS-NL's challenge hash through HFSCX-256)

```
NL_FSCX_v1(A, B) = FSCX(A, B) ⊕ ROL64((A + B) mod 2^n)
```

i.e. the affine FSCX combiner XORed with a 64-bit rotation of the
*modular* (not GF(2)) sum of `A` and `B` — the modular addition's carry
chain is what breaks GF(2)-linearity. `NL_FSCX_REVOLVE_v1(A, B, steps)`
iterates this the same way FSCX-REVOLVE does (§3.1). NL-FSCX v1 is
one-way but not proven invertible in general; see
`SecurityProofs-4.md` §11 for the non-linearity argument and
`SecurityProofsCode/hkex_nl_verification.py` for a runnable check.

### 8.2. NL-FSCX v2 (used by HSKE-NL-A2, HPKE-NL)

```
delta(B)          = ROL64( B · ((B + 1) / 2) mod 2^n )     (all arithmetic mod 2^n;
                                                             "/" is a 1-bit right shift,
                                                             i.e. floor division by 2)
NL_FSCX_v2(A, B)  = (FSCX(A, B) + delta(B)) mod 2^n
```

Unlike v1, v2 is constructed to be **invertible** for a fixed `B` (this is
required — HSKE-NL-A2 and HPKE-NL decrypt by running the inverse rather
than by re-revolving forward):

```
NL_FSCX_v2_inv(Y, B) = B ⊕ M^{-1}((Y − delta(B)) mod 2^n)
```

where `M^{-1}` is the inverse of the linear map from §3.1 (well-defined
since `M` is invertible — it has finite multiplicative order `n/2`).
`NL_FSCX_REVOLVE_v2(A, B, steps)` / `..._inv(Y, B, steps)` iterate the
forward/inverse map `steps` times.  v2 is a bijection in `A` for every
`B`; what `nl_v2_key_is_valid` (see `herradura.h`) refuses is a WEAK key.
Write `arc(d)` for `n` minus the longest cyclic run of zero bits in `d`
(`arc(0) = 0`): the shortest cyclic window holding every set bit.  Since
v14.0.0 (TODO #354) a key is valid iff

```
arc(delta(B)) > n/4
```

which contains the affine class `delta(B) ∈ {0, 2^(n−1)}` refused until
then (for those keys `NL_FSCX_v2` is GF(2)-affine), and refuses about
`2^(−3n/8)` of uniform keys, `2^−96` at `n = 256`.  Implementations
**MUST** perform this check before use.  See `SecurityProofs-4.md` §11.8
for the bijectivity proof and `SecurityProofs-10.md` §11.81 for the screen.

## 9. NL/PQC Protocol Variants

### 9.1. HKEX-RNL — Ring Learning-With-Rounding Key Exchange

**PEM labels:** `HERRADURA HKEX-RNL PRIVATE KEY` / `HERRADURA HKEX-RNL
PUBLIC KEY`. **CLI:** `genpkey --algo hkex-rnl`, two-round `kex --algo
hkex-rnl` (Bob responds first, then Alice completes). **Conjectured
quantum-resistant** (lattice-based; no known efficient quantum attack, as
opposed to HKEX-GF's Shor's-algorithm-breakable discrete log), at ring
dimension n=1024 since v2.7.19 — ~206 classical / ~187 quantum Core-SVP bits.
Keys generated before v2.7.19 used n=256 and are worth only ~32/~29; see
`MIGRATING.md` §4 and SecurityProofs-4.md §11.4.3.

**Parameters** (ring degree `n`, defaults to the CLI's `--bits`, 256):
modulus `q = 65537` (`2^16 + 1`), public-key rounding modulus `p = 4096`,
reconciliation modulus `pp = 4` (extracts 2 bits/coefficient), secret
noise distribution `CBD(b)` with `b = 1` (each secret coefficient drawn
from the centered binomial distribution on `{−1, 0, 1}`). Polynomials
are elements of `Z_q[x]/(x^n + 1)`.

1. **Public parameter.** Both parties derive the same public polynomial
   `m` deterministically (`m_base`, a fixed function of `n`), then each
   party additionally blinds it with a fresh random polynomial before
   using it as their own base — i.e. each party's `m_blind = m_base +
   a_rand` for an independently sampled `a_rand`, so the two parties do
   *not* share one base polynomial; correctness instead relies on the
   reconciliation step (§9.1 step 5) tolerating the resulting small
   rounding-noise mismatch. Implementers MUST reproduce `_rnl_m_poly(n)`
   exactly (`HerraduraCli/primitives.py`) bit-for-bit, since any
   deviation desynchronizes both parties' rounding.
2. **Key generation** (each party independently): sample private
   polynomial `s ← CBD(b)`; compute `C = round_p(m_blind · s mod q)`
   (`round_p` maps `Z_q → Z_p` by scaling, the "rounding" step that gives
   Learning-*With-Rounding* its name and avoids sampling encryption
   noise explicitly). Public key is `C`; private key is `s`.
3. **Round 1 (Bob):** Bob computes his own `(s_B, C_B)` per step 2, and
   additionally a reconciliation *hint* over `C_B` (`_rnl_hint`) that
   lets Alice correct for asymmetric rounding error without leaking `s_B`.
   Bob sends `(C_B, hint)`.
4. **Round 2 (Alice):** Alice computes her own `(s_A, C_A)`, then the raw
   shared value `k_raw = round_pp(C_B · s_A mod q)` using Bob's hint to
   pick the reconciliation bucket (`_rnl_reconcile_bits`), and sends
   `C_A` back.
5. **Completion (Bob):** Bob computes his side of the same raw value
   from `(C_A, s_B)` and the same reconciliation function (without
   needing a hint, since he already knows his own rounding).
6. **KDF.** Both parties pass `k_raw` through the contributory KDF
   `_rnl_contributory_kdf(k_raw, n, N_a, N_b)` — binding in each party's
   nonce `N_a`/`N_b` (exchanged alongside the public keys) to make the
   final key contributory (neither party can unilaterally force the
   final shared secret, unlike a bare `k_raw`).

Implementers **MUST** reproduce the CBD sampler, rounding functions, and
reconciliation bucket boundaries exactly — Ring-LWR key exchange is only
correct (both parties derive the same final key) with overwhelming
probability, not always; see `SecurityProofsCode/hkex_rnl_failure_rate.py`
for the measured decryption-failure rate and `SecurityProofs-4.md` §11.5
for the reconciliation proof.

### 9.2. HSKE-NL — Symmetric Encryption with NL-FSCX

Two independent constructions, both requiring a pre-shared `n`-bit key
`K` (e.g. from HKEX-RNL):

- **HSKE-NL-A1 (counter mode).** For a message split into `n`-bit blocks
  `P_0, P_1, …`: `ks_j = NL_FSCX_REVOLVE_v1(K, K ⊕ ctr_j, i)` (§8.1,
  `i = n/4`); `E_j = P_j ⊕ ks_j`. Decryption recomputes the same
  keystream and XORs again. `ctr_j` MUST be unique per block per key (a
  reused counter under the same key is a two-time-pad break, as with any
  stream cipher). The CLI's `--aead` flag additionally wraps this in an
  authenticated construction (HFSCX-256-based MAC over ciphertext +
  associated data) — HSKE-NL-A1 without `--aead` provides confidentiality
  only, MUST NOT be used without separate authentication.
  **`n` MUST be 256.** The construction is defined at any `n`, but the
  seed derivation truncates a 256-bit domain constant and conforming
  implementations disagreed about which end to truncate, producing
  different keystreams below 256 bits; since v9.0.0 every CLI REFUSES
  any other width, on the key and on the ciphertext's declared `nbits`
  alike. Because A1 without `--aead` has no tag, a divergence here is
  not detectable by the recipient — which is why this is a MUST and not
  a SHOULD. See `MIGRATING.md` §19.
- **HSKE-NL-A2 (revolve mode).** `E = NL_FSCX_REVOLVE_v2(P, K, r)`
  (§8.2, `r = 3n/4`); decryption is `D = NL_FSCX_REVOLVE_v2_inv(E, K, r)
  = P` by the invertibility property of NL-FSCX v2 (§8.2), not by
  re-revolving forward as HSKE (§5.1) does. `K` MUST pass
  `nl_v2_key_is_valid` (§8.2) before use.

### 9.3. HPKS-NL — Schnorr Signature with NL-FSCX Challenge

**PEM labels:** `HERRADURA HPKS-NL PRIVATE KEY` / `HERRADURA HPKS-NL
PUBLIC KEY`. Identical to HPKS (§6) except the challenge hash in signing
step 3 / verification step 2 is `e = HFSCX-256-DS(0x30, R ‖ msg_digest)`,
truncated to the key width n (its high n bits), instead of plain
FSCX-REVOLVE. `R` and `msg_digest` are each n/8 big-endian octets, and
HFSCX-256-DS(t, d) = HFSCX-256(t ‖ d). Until v11.x the challenge was
`NL_FSCX_REVOLVE_v1(R, msg_digest, i)` (§8.1). That put the signer's
message in v1's B, which TODO #348 (v12.0.0) removed: for B in
{0, 2^(n−1)} v1 ignores A after n/2 rounds. HPKS-T (threshold) uses
the same challenge. **Classical only** — the
underlying key pair is still a GF(2^n)* discrete-log key pair (§4.1), so
this variant is not quantum-resistant; NL-FSCX only strengthens the
challenge-derivation step against classical algebraic attacks that
exploit FSCX's linearity, per `spec/herradura-protocol-spec.json`'s
`hpks-nl` entry.

### 9.4. HPKE-NL — El Gamal Encryption with NL-FSCX

**PEM labels:** same as HPKE (§7) — HPKE-NL reuses HKEX-GF/HPKE key
pairs. Identical to HPKE (§7) except step 4 uses
`E = NL_FSCX_REVOLVE_v2(P, enc_key, i)` (§8.2) and decryption uses
`D = NL_FSCX_REVOLVE_v2_inv(E, dec_key, i)`. **Classical only, deprecated
PQC claim** — like HPKS-NL, the key pair's security rests on GF(2^n)*
discrete log (§4.1), so HPKE-NL is not quantum-resistant despite the
non-linear ciphertext step; `spec/herradura-protocol-spec.json` marks
`hpke-nl` `security.status: "deprecated"` with no lattice-based
replacement planned (use HKEX-RNL + HSKE-NL for an actually
quantum-resistant encryption path instead).

## 10. Wire Format (Classical Quartet)

All four classical-quartet protocols (§4, §5 lacks a standalone key
format since HSKE consumes a raw symmetric key, §6, §7) and their -NL
variants (§9.3, §9.4, which reuse §4's key format) share one PEM/DER
convention, implemented identically in `HerraduraCli/herradura_codec.h`
(C), `HerraduraCli/codec.py` (Python), `herradura/codec.go` (Go), and
`bindings/java/herradurakex.Codec` (Java):

- **DER subset:** `INTEGER` (tag `0x02`) and `SEQUENCE` (tag `0x30`)
  only, with short-form length encoding for lengths `< 128` and
  long-form (`0x81`–`0x84` prefix + big-endian length bytes) above that.
  `INTEGER` values follow standard DER sign-byte rules (a leading `0x00`
  is prepended when the high bit of the first content byte would
  otherwise be misread as a sign bit).
- **PEM wrapping:** standard `-----BEGIN <LABEL>-----` /
  `-----END <LABEL>-----` armor around the Base64 encoding (76-character
  lines) of the DER bytes; `<LABEL>` is the protocol- and key-type-
  specific string given in each section above and enumerated in full in
  `spec/herradura-protocol-spec.json`'s `pem_labels` field per protocol.
- **Private-key encryption:** `genpkey --passphrase` wraps the DER
  payload in a PBKDF2-HFSCX256-derived-key encryption layer before PEM
  armor (see `_encrypt_pem`/`_decrypt_pem` in `HerraduraCli/herradura.py`
  for the exact format — out of scope for this document's protocol-level
  focus, since it is a key-storage convention rather than part of any of
  the four protocols themselves).

A conformance suite implementing this section can cross-check
byte-for-byte compatibility against `KAT/classical_quartet.json`
(fixed test vectors covering HKEX-GF/HSKE/HPKS/HPKE at `n = 256`,
NIST-CAVP-`.rsp`-style) and against any of the four PEM-producing CLIs
directly (`CliTest/test_c_interop.sh`, `test_go_interop.sh` exercise
exactly this).

### 10.1 Reading a PEM file (TODO #398, #400)

The bullet above is the WRITER's format: LF line ends, 76-character base64
lines, nothing before the BEGIN line, one LF after the END line.  A READER
accepts a little more than that and refuses everything else.  These rules
apply to every PEM file every CLI reads, whatever its label and whichever
section of this document defines it.  All four readers (`pem_unwrap` in C
and Python, `PemUnwrap` in Go, `Codec.pemUnwrap` in Java) scan in the order
below, so the refusal a file gets is specified as well as the fact of one.
Whitespace means space, tab, CR or LF, and nothing else (a vertical tab, a
form feed or a non-ASCII byte is not whitespace).

1. **Before the block:** only whitespace.  If the first non-whitespace
   characters are not `-----BEGIN ` (with its space), the file is refused:
   `PEM: text before the BEGIN line` when `-----BEGIN ` appears later in
   the file, `PEM: missing BEGIN marker` when it never does.
2. **The BEGIN line:** `-----BEGIN `, then the label, then `-----`, then
   only spaces or tabs up to a CR or LF.  The label runs to the first
   `-----` on the line and is 1 to 79 characters, each printable ASCII
   (0x20 to 0x7E, so a space is allowed inside it).  Any other shape,
   including an empty or 80-character label, a control character in it, a
   missing closing `-----`, other text after it, or a file that ends on
   this line, is `PEM: malformed BEGIN line`.
3. **The END line:** the first `-----END ` after the BEGIN line.  None at
   all is `PEM: missing END marker`.  It must start a line (the character
   before it is CR or LF; an indented END line is refused) and be followed
   on the same line by `-----`; otherwise `PEM: malformed END line`.
4. **The labels match**, byte for byte; otherwise
   `PEM: END label 'E' does not match BEGIN label 'B'`, with E cut to 79
   characters and each character of it outside 0x20 to 0x7E shown as `?`
   (the END label is not screened the way the BEGIN label is, so its bytes
   are never echoed raw; TODO #403).
5. **After the block:** only whitespace to the end of the file, so a file
   holds exactly one block; anything else, including a second block, is
   `PEM: text after the END line`.  A final line ending is optional.
6. **The body**, everything between the BEGIN line's line end and the END
   line, is base64: the alphabet `A-Z a-z 0-9 + /`, with whitespace allowed
   anywhere between characters (so CRLF files, any line length, one long
   line and blank lines all read).  The reader scans it once, and the
   first of these two it meets is the refusal:
   - a character outside the alphabet, `=` and whitespace (`-`, `_`, a
     vertical tab, a non-ASCII byte) is
     `PEM body is not valid base64: invalid character`;
   - a `=` in the first or second place of a group of four, a third `=`,
     or an alphabet character after a `=` is
     `PEM body is not valid base64: misplaced padding`;
   - after the scan, if the characters (`=` included, whitespace not) do not number
     a multiple of 4, `PEM body is not valid base64: length is not a
     multiple of 4` (padding is required, never implied);
   - then, if the bits the padding leaves over are not all zero,
     `PEM body is not valid base64: non-zero bits after the last byte`, so
     one DER encoding has exactly one body.
7. **The body is not empty:** a body that decodes to no bytes (nothing, or
   only whitespace) is `PEM: empty body`.

Only then is the DER parsed, under each label's own rules.  The quoted
texts are the reasons, identical in all four CLIs; each CLI may put its own
prefix before one (the C CLI, and `pkey --decrypt` in every CLI, print
`cannot parse PEM from: PATH: ` and then the reason).  The conformance cases
are `CliTest/test_malformed_pem_matrix.sh`: the accepted layouts (CRLF, CR
only, spaces and tabs inside and after body lines, 64-character and
single-line bodies, a blank line,
whitespace around the block, no final line ending, blanks after the BEGIN
line) each decode to the same bytes, and every refusal above is checked by
its text in all four CLIs, with the 79/80-character label boundary.
`CliTest/test_pem_reader_diff.sh` adds volume: 60,000 generated inputs, each
read by all four readers in process, which must give identical results.

### 10.2 Reading the DER SEQUENCE (TODO #405)

Every DER-bodied PEM (a key, a ciphertext, a signature, an envelope) is one
SEQUENCE of INTEGERs.  Every CLI reads it with one walk, left to right
(`der_seq_check` in C and Python, `DerSeqCheck` in Go, `Codec.derSeqCheck`
in Java), and the first of these faults the walk meets is the refusal.  Each
text below follows `malformed PEM 'LABEL': `, where LABEL is the PEM's.

1. **The tag:** the first byte is not 0x30: `not a DER SEQUENCE`.
2. **The SEQUENCE length**, then each INTEGER's length below, is read as it
   is met:
   - its first byte, or one of the bytes that byte announces, is past the
     end (for an INTEGER, past the end of the SEQUENCE body):
     `DER length field truncated`;
   - it announces more than four length bytes:
     `DER length field longer than 4 bytes`;
   - it is not in its shortest form (long form for a length under 0x80,
     a leading 0x00 length byte, or BER's indefinite 0x80):
     `DER length not in its shortest form`.
3. **The body** is longer than what follows the length:
   `DER SEQUENCE body truncated`; shorter, with N bytes left over:
   `N bytes after the DER SEQUENCE`.
4. **Each item** in turn, numbered from 0 as field N:
   - its tag is not 0x02: `field N is not an INTEGER (tag 0xTT)`, with TT the
     tag in two lowercase hex digits;
   - its length (rule 2), then: the content runs past the body,
     `field N runs past the DER SEQUENCE`; there is none,
     `field N is an empty INTEGER`; its first bit is set with no 0x00 sign
     byte, `field N is a negative INTEGER`.

Only a SEQUENCE passing all of these is counted and its fields checked, in
the texts §10's generated tables give: the item count
(`N DER items, expected M`, TODO #367), then each field's width, encoding
and value (TODO #372, #373).  A file breaking several rules is refused for
the first in this order, and the order and texts are the same in all four
CLIs, `pkey --decrypt`'s envelope included.  The conformance test is
`CliTest/test_der_reader_diff.sh`: 60,000 generated inputs read by all four
parsers in process, which must give identical results, refusal texts
included, and each refusal above checked by its text through the four real
CLIs.

### 10.3 Raw-body PEMs (TODO #406, #407, #408)

Eight labels carry packed bytes instead of DER: ZKP-RNL PROOF, ZKP-NL
PRIVATE KEY / PUBLIC KEY / PROOF, ZKP-NL-PP SIGNATURE and HCRED PRIVATE
KEY / PUBLIC KEY / PROOF.  A 4-byte big-endian `n` leads (then the round
count, and for an HCRED proof `W` before it), and every block after it is
sized from those.  A reader accepts exactly the encoding its writer
produces.  Besides the header bounds and the trailing-byte rule
(`malformed PEM 'LABEL': N bytes after its last field`, TODO #372), it
refuses, each with one text, the same in all four CLIs:

- a per-round length byte other than the size `n` fixes, at the length
  byte and before any truncation check:
  `malformed PEM 'LABEL': round J FIELD is L bytes, n=N needs M`, where
  FIELD is `view_p1` or `view_p2` (ZKBoo, M = 2*ceil(n/8) + 32 + n - 1) or
  `gates_p2` (ZKB++, M = ceil(max(n - 1, 1)/8));
- a ZKB++ `has_share2` other than 1 for e != 2 and 0 for e = 2:
  `malformed PEM 'LABEL': round J has_share2 is V, e=E needs W`;
- a bit above `n` in an n-bit field (ZKP-NL key A, B, y; a ZKBoo view's
  share and output; ZKB++ `out_e` and `share2`):
  `malformed PEM 'LABEL': [round J ]FIELD has bits above n=N`;
- an HCRED Z_q value (3 bytes) not below q = 65537 or Z_p value (2 bytes)
  not below p = 4096, in a key or a proof, the first in wire order:
  `malformed PEM 'LABEL': value V at byte OFF is not below Q`;
- an HCRED proof `has_aux` other than 0 or 1:
  `malformed PEM 'LABEL': round J has_aux is V, expected 0 or 1`;
- an HCRED proof `W` outside 1..256: `HCRED proof: W out of range (W)`.

`verify` compares a ZKP-NL proof's `n` with the public key's before reading
the rest: `verify: proof n mismatch with pubkey n (P vs K)`.  An HCRED
verifier fails a round whose aux block the challenge does not open, as it
fails one that lacks a needed block.  `CliTest/test_raw_body_diff.sh` sends
seeded mutations of each artifact through the four real CLIs and fails on
any crash or any case they answer differently, and checks every refusal
above by its text.  Not yet covered: the ZKBoo view's gate-byte bits and
share bit n - 1, which the verifier does not read (TODO #409).

## 11. Code-Based (Stern ZKID) Variants

HPKS-Stern-F and HPKE-Stern-F/-KEM (§9, `hpks-stern`/`hpke-stern`/
`hpke-stern-kem` in `spec/herradura-protocol-spec.json`) are a separate
family built on the Stern identification protocol (zero-knowledge proof
of knowledge of a bounded-weight syndrome-decoding solution) rather than
on FSCX/NL-FSCX or GF(2^n)* — this is intentional diversification: Stern
ZKID's hardness rests on syndrome decoding, a much longer-studied
code-based assumption than the suite's own Ring-LWR construction (§9.1),
giving deployments choosing between HKEX-RNL/HSKE-NL and HPKS-Stern-F/
HPKE-Stern-KEM two structurally independent quantum-resistance bets
rather than one. Their algorithm-level description (commit/challenge/
response over a random `[N, N/2]` linear code, Fiat-Shamir transform for
signing, Niederreiter framing for the KEM) is intricate enough to warrant
its own document rather than a condensed section here; see
`SecurityProofs-5.md` §11.8.3–11.9 for the full construction and
`SecurityProofs-7.md` for the accompanying Σ-protocol/ZKBoo analysis.
One step is stated here because the four CLIs once disagreed on it
(TODO #390): the Fiat-Shamir challenges of hpks-stern, hpks-ring and the
HCRED credential signature are derived from `ch_st = stern_hash(msg ‖
commitments)` by `ch_st = nl_fscx_v1(ch_st, i)` for round `i = 0, 1, …`,
where `i` is the WHOLE round index as an n-bit integer (not its low byte),
and round `i`'s challenge is `(ch_st mod 2^32) mod 3`.

### 11.1 The long form: N = 2304, the 128-bit set (TODO #382)

`genpkey --algo hpks-stern --level 128` (and `hpke-stern`) makes a key at
N = 2304, k = N/2 = 1152 parity rows, error weight t = N/16 = 144: about
2^137 classical by BJMM and 2^106 by Grover-over-Prange
(`SecurityProofsCode/stern_f_parameter_selection.py`). Its vectors are
wider than the 256-bit BitArray, so every value is an N-bit string, N/8
octets big-endian, integer bit `i` at octet `N/8 - 1 - i/8`, bit `i mod 8`.
The protocol is the short form's (same commitments, challenge rule,
responses, weight check and ds tags); these rules apply above N = 256:

- **Hash.** `H_ds(x_0, x_1, …) = HFSCX-256-DS(0x31, ds ‖ x_0 ‖ x_1 ‖ …)`,
  all 256 bits (the short form keeps the high N bits). Commitments
  `c0 = H_1(π-seed, H·rᵀ)`, `c1 = H_2(σ(r))`, `c2 = H_3(σ(y))` are 256 bits;
  the syndrome is hashed as an N-bit string (bit `i` = row `i`, the high
  half zero).
- **Matrix.** `sk = H_6(seed)`. Row `i` (0 ≤ i < N/2) is the concatenation
  `chunk(i, 0) ‖ … ‖ chunk(i, N/256 − 1)` read as an N-bit string, where
  `chunk(i, c) = HFSCX-256(i_hi ‖ i_lo ‖ c)` — a 3-octet message — with
  `sk` as HFSCX-256's initial chaining value.
- **Permutation.** σ is the short form's Fisher–Yates generator over N
  positions with its NL-FSCX v1 PRNG keyed by the 256-bit
  `k = H_5(π-seed)`: state `k`, key `ROL(k, 32)`, eight 32-bit draws per
  state, `j = (v · (i + 1)) >> 32`.
- **Message and challenges.** The signed message is 256 bits (the whole
  HFSCX-256 pre-hash, or the input's first 32 octets). `ch_st =
  H_0(msg ‖ c0_0 ‖ c1_0 ‖ c2_0 ‖ …)` and advances by `nl_fscx_v1(ch_st, i)`
  at 256 bits, exactly as above; a ring signature hashes every member's
  commitments, member-major.
- **Demo KEM (`hpke-stern`).** `K = H_4(seed, e′)`; the payload is one
  32-octet block, `E = fscx_revolve(P, K, 64)`.
- **Wire.** The short form's PEM layouts with `n = 2304`: keys
  `(e or syndrome, seed, n)`, each N/8 octets; a signature
  `(n, rounds, commitments, challenges, responses)` with 3 × 32 commitment
  octets and 2 × N/8 response octets a round (147,249 DER octets at 219
  rounds); the HPKE-Stern ciphertext's `K` and `E` are 32 octets.

Random draws keep the short form's order (seed, then the error; per round
`r`, then the π-seed), and `KAT/operation_replay.json` pins keygen,
signing and ring signing at N = 2304 in all four ports.

This SPEC.md's §9 NL/PQC coverage and this pointer satisfy TODO #193's
scope (HKEX-GF, HSKE, HPKS, HPKE, and the NL/PQC/Stern variants); a
follow-up TODO MAY expand §11 into full Stern-F/Niederreiter algorithm
steps at the same level of detail as §9 if that becomes the higher-value
next increment.

## 12. Security Considerations

This document describes *what* each protocol computes, not whether doing
so is safe for a given deployment — read `SecurityProofs.md` (index) and
its parts before deploying any of these protocols, and note in
particular:

- The classical quartet (§4–§7) is pedagogical only (§2). Pohlig-Hellman
  recovers a GF(2^n)* private key in about `2^36.5` group operations at
  `n = 256` — cheaper than the index-calculus attacks that also apply —
  and HSKE leaks 126 of 256 plaintext functionals independently of any of
  that (§5.1).
- HPKE-NL's PQC framing is deprecated (§9.4) — it is not quantum-
  resistant despite using NL-FSCX.
- HKEX-RNL (§9.1) has a non-zero probabilistic decryption-failure rate;
  implementers MUST reproduce the CBD/rounding/reconciliation functions
  exactly and SHOULD consult `SecurityProofsCode/hkex_rnl_failure_rate.py`
  for the measured rate at their chosen `n`.
- Nonce/counter reuse breaks HPKS (§6.2 step 1), HPKE (§7.1 step 1), and
  HSKE-NL-A1 (§9.2) — each MUST use a fresh, non-repeating value per
  operation under a given key.
