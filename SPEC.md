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

### 8.1. NL-FSCX v1 (used by HSKE-NL-A1, HPKS-NL's challenge hash, HFSCX-256)

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
forward/inverse map `steps` times; a key `B` for which `A + delta(B)`
would overflow the top bit is rejected by `nl_v2_key_is_valid` (see
`herradura.h`) to keep the construction bijective — implementations
**MUST** perform this check before use. See `SecurityProofs-4.md` §11.8
for the bijectivity proof (v2 replaces v1's one-wayness with an explicit
invertibility argument, at the cost of the extra validity check).

## 9. NL/PQC Protocol Variants

### 9.1. HKEX-RNL — Ring Learning-With-Rounding Key Exchange

**PEM labels:** `HERRADURA HKEX-RNL PRIVATE KEY` / `HERRADURA HKEX-RNL
PUBLIC KEY`. **CLI:** `genpkey --algo hkex-rnl`, two-round `kex --algo
hkex-rnl` (Bob responds first, then Alice completes). **Conjectured
quantum-resistant** (lattice-based; no known efficient quantum attack, as
opposed to HKEX-GF's Shor's-algorithm-breakable discrete log).

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
- **HSKE-NL-A2 (revolve mode).** `E = NL_FSCX_REVOLVE_v2(P, K, r)`
  (§8.2, `r = 3n/4`); decryption is `D = NL_FSCX_REVOLVE_v2_inv(E, K, r)
  = P` by the invertibility property of NL-FSCX v2 (§8.2), not by
  re-revolving forward as HSKE (§5.1) does. `K` MUST pass
  `nl_v2_key_is_valid` (§8.2) before use.

### 9.3. HPKS-NL — Schnorr Signature with NL-FSCX Challenge

**PEM labels:** `HERRADURA HPKS-NL PRIVATE KEY` / `HERRADURA HPKS-NL
PUBLIC KEY`. Identical to HPKS (§6) except the challenge hash in signing
step 3 / verification step 2 is `e = NL_FSCX_REVOLVE_v1(R, msg_digest,
i)` (§8.1) instead of plain FSCX-REVOLVE. **Classical only** — the
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
