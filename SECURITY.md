# Security Policy

## Protocol Status

HerraduraKEx implements several protocols that span a wide range of maturity, from
production-suitable to strictly pedagogical. Use this table to decide whether a protocol
is appropriate for your use case. Each row links to the authoritative analysis instead of
restating it here, so consult the linked section for the full argument before relying on
any of these classifications.

| Protocol | Status | Why | Details |
|---|---|---|---|
| **HKEX-GF** | Demo-only / pedagogical | Pohlig–Hellman solves the DLP in ~2^36.5 group operations at n=256 (the group order 2^256−1 has a 73-bit largest prime factor) — days on one core; DLP in GF(2^n)* is also deprecated by NIST SP 800-57 Rev. 5 (2020) and ENISA (2022) | SecurityProofs-3.md §9.2.4 |
| **HPKS** | Demo-only / pedagogical | Same ~2^36.5 Pohlig–Hellman key recovery as HKEX-GF, which yields arbitrary signature forgery | SecurityProofs-3.md §9.2.4, §9.2.6 (ristretto255 migration path) |
| **HPKE** | Demo-only / pedagogical | Same ~2^36.5 Pohlig–Hellman recovery as HKEX-GF, which yields the decryption key; independently, the FSCX encryption layer leaks 126 of 256 plaintext functionals from the ciphertext alone — concretely, `E[0]^E[2]^E[128]^E[130]` equals the same XOR of plaintext bits under every key (TODO #232) | SecurityProofs-3.md §9.2.4, SecurityProofs-1.md §1.3.1, SecurityProofs-7.md §11.23.5 |
| **HPKS-NL / HPKE-NL** | Demo-only / pedagogical | NL-FSCX challenge/encryption layered on the same GF(2^n)* group, so the ~2^36.5 Pohlig–Hellman key recovery applies unchanged | SecurityProofs-4.md §11.7 |
| **HSKE** (key-only) | Not suitable for production | The ciphertext alone leaks 126 of 256 linear functionals of the plaintext at the deployed i = n/4 — no known plaintext required; the lightest has weight 4, so `E[0]^E[2]^E[128]^E[130]` equals the same XOR of plaintext bits under every key. The n/2-bit post-quantum bound covers key search only. The 126 is also a **floor** for any rotation-based step admitting agreement (TODO #232), so it is not fixable within the FSCX design | SecurityProofs-1.md §1.3.1 (Thm. 4.1), §4.2 W9, SecurityProofs-7.md §11.23 |
| **HSKE** (known-plaintext) | Not suitable for production | A single known-plaintext pair recovers `T_i·K` and with it *every other* message under the same key — the map is GF(2)-affine in both the plaintext and the key | SecurityProofs-4.md §11.7 |
| **HSKE-NL-A1** | Production-track (conjectured) | **Corrected under TODO #237** — this row previously shared classical HSKE's known-plaintext verdict, which does not apply. The carry non-linearity makes the keystream non-affine in `base` (measured: 200/200 affinity violations vs. 0/200 for classical HSKE), so the 1-pair attack above has no analogue: a known-plaintext pair yields that block's keystream and nothing else, exactly as in AES-CTR. The binding assumption is instead the **conjecture** that NL-FSCX v1 is a PRF — treat it as a conjecture, not a proof | SecurityProofs-4.md §11.3.1, §11.7 (TODO #237 correction) |
| **HSKE-NL-A2** | Production-track (conjectured), with two constraints | Same correction as A1: A2 is a keyed bijection, so there is no keystream for a pair to recover. But **(1)** it is deterministic — identical `(P, K)` always gives identical `E`, so it is not IND-CPA across multiple messages unless you embed a nonce or sequence number in the plaintext; prefer HSKE-NL-A1 when messages share a key. **(2)** Keys with `delta(K) ∈ {0, 2^(n-1)}` degenerate to a GF(2)-affine permutation and fall to linear algebra from a handful of known plaintexts; the class is ~2^-129 of the key space and all three CLIs reject it via `nl_v2_key_is_valid` | SecurityProofs-4.md §11.3.2, §11.7; SecurityProofs-7.md §11.19.2 |
| **HSKE-Duplex** (`hske-duplex`) | Research — do not deploy | Single-pass MonkeyDuplex sponge over NL-FSCX v2. Bijectivity of the permutation is proven, but its differential/linear profile as a standalone sponge permutation has never been characterised (TODO #99), which is precisely what a sponge's security rests on. `herradura.h`'s own banner says "RESEARCH CONSTRUCTION — not for production use without further cryptanalysis"; `spec/` said `production` until TODO #237. Use `enc --aead` (HSKE-NL-A1 encrypt-then-MAC) instead | SecurityProofs-6.md §11.9 |
| **OPRF** (`oprf-blind`/`-eval`/`-unblind`) | Demo-only / pedagogical | `oprf_eval` is `gf_pow(alpha, k)` — the same GF(2^n)* exponentiation as HKEX-GF, so the same Pohlig–Hellman attack recovers the **server key** `k` from a single observed `(alpha, beta)` transcript pair in ~2^36.5 group operations at n=256. Verified end to end at n=32 and n=64 (TODO #237). The base is the client's blinded `alpha` rather than the fixed `g = 3`; `alpha` is primitive with density 0.4992, and where it is not, `k` returns modulo `ord(alpha)`. That is no mitigation — `ord(alpha)` is publicly computable, so an attacker picks one of the ~50% of transcripts whose `alpha` is primitive and recovers `k` outright. Obliviousness is unaffected — what falls is `k`'s secrecy, and with it the ability to stop anyone who has seen one transcript from evaluating `F(k, ·)` offline on chosen inputs | SecurityProofs-3.md §9.2.4; `SecurityProofsCode/hkex_gf_pohlig_hellman.py` §6 |
| **aPAKE** (`pake-register`/`pake-demo`) | Demo-only / pedagogical | Builds on the OPRF row above, and its stated purpose is the property that row breaks: the server record stores `F(oprf_key, password)` specifically so that a stolen database cannot be attacked offline. Since `oprf_key` is recoverable in ~2^36.5, a compromised database **is** offline-guessable at the deployed n. Independently, the shipped ZKBoo parameters are demo-grade (`_HPAKE_ZKP_N = 32`, `_HPAKE_ROUNDS = 16`, soundness error ≈ 0.15%; production needs 219 rounds) | This row; SecurityProofs-3.md §9.2.4 |
| **HKEX-RNL** (n=1024, since v2.7.19) | Production-track (conjectured PQ-resistant) | ~206 classical / ~187 quantum Core-SVP bits at the ring dimension adopted in TODO #223, computed directly rather than cited (primal uSVP binding at β=704). Reconciliation measures 0 failures in 6000 trials. **Keys generated before v2.7.19 used n=256 and are worth ~32/~29 bits — regenerate them; see `MIGRATING.md` §4.** Two protocol-level caveats are unchanged and independent of the parameter move: the reconciliation hint is transmitted unauthenticated, so the caller must authenticate the transcript, and `m_blind`'s uniformity rests entirely on the initiator's RNG (TODO #89) | SecurityProofs-4.md §11.4.3, §11.7; `SecurityProofsCode/hkex_rnl_lattice_2026.py`, `rnl_parameter_selection.py` |
| **HKEX-RNL-128** (n=512) | Withdrawn — do not use | ~87 classical / ~79 quantum Core-SVP bits, so it never met the ≥128-bit claim made for it; the ~220/~200 previously documented was a linear extrapolation off an n=256 figure that was itself wrong. Superseded entirely by the n=1024 row above rather than repaired: no (p, η) retune brings n=512 to target. **n=768 is unsound and must not be substituted** — x^768+1 factors over Z, so the ring CRT-splits and the instance projects down to ~39/~36 bits | SecurityProofs-4.md §11.4.3; `SecurityProofsCode/rnl_parameter_selection.py` §2 |
| **HPKS-Stern-F / HPKE-Stern-F** | Demo-only | ~30–40 bits at deployed N=256; 128-bit classical security needs N ≥ 17000; decapsulation at production parameters needs the QC-MDPC decoder from TODO #126. Separately, the Fiat–Shamir round count for 128-bit soundness is **r = 219** = ⌈128 / log₂(3/2)⌉, giving 128.107 bits; measurement over 3,000,000 seeds bounds any challenge-expansion bias at 0.0588 bits, supporting a 128.048-bit floor (TODO #217, #222). Round count and instance hardness are separate axes — 219 rounds over a 30–40-bit instance is still demo-only | SecurityProofs-4.md §11.7, SecurityProofs-5.md §11.8.5, §11.8.8 |
| **HPKE-Stern-KEM** | Demo-only | Measured DFR 0.264% = 2^-8.6 at the deployed toy parameters (r=523, d=15, t=18), where IND-CCA2 needs 2^-128; decapsulation signals failure explicitly with no Fujisaki–Okamoto transform and no implicit rejection, so the GJS reaction attack recovers the private key in ~10^6 chosen-ciphertext queries; keygen applies no weak-key screen (~1 key in 3400 has ~10x the average DFR). Do not reuse a keypair across decapsulations you do not control | SecurityProofs-5.md §11.8.7 |

**HYBRID-RNL-STERN note.** The hybrid combines HKEX-RNL with HPKE-Stern-KEM, so it
inherits the KEM row's reaction-attack exposure on its KEM half: `kex --algo
hybrid-rnl-stern` reports decapsulation failure with its own distinct message, which
is the same oracle. The Ring-LWR half is unaffected, and an attacker who recovers the
QC-MDPC private key still faces the HKEX-RNL contribution — but treat the hybrid's
KEM half as demo-only for the same reasons.  Since v2.7.19 the RNL contribution is
worth ~206 Core-SVP bits at n=1024; hybrid keys generated before that version carry the
~32-bit n=256 ring and must be regenerated along with the plain HKEX-RNL ones.

**Rule of thumb:** if a protocol's status above is anything other than "production-track,"
treat it as a proof-of-concept for the underlying math, not a component to deploy where
real confidentiality or authenticity guarantees are required.

## Supported Versions

The project follows `MAJOR.MINOR.PATCH` versioning (see `CLAUDE.md`). Security fixes are
released as `PATCH` bumps against the current `MAJOR.MINOR` line and documented in
`CHANGELOG.md`. Only the latest released version is supported — there are no maintained
backport branches. Upgrade to the latest tag to receive a fix.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately using
[GitHub's private vulnerability reporting](https://github.com/Caume/HerraduraKEx/security/advisories/new)
(repository **Security** tab → **Report a vulnerability**), rather than opening a public
issue. This applies to implementation bugs (e.g. missing input validation, timing leaks,
memory-safety issues) as well as cryptographic weaknesses not already documented in
`SecurityProofs-1.md` through `-7.md`.

Please include:

- Affected protocol(s) and language implementation(s) (C / Go / Python / assembly / Arduino).
- Steps to reproduce, or a minimal proof-of-concept.
- Your assessment of impact, if known.

**Response time:** we aim to acknowledge reports within 5 business days and to provide an
initial assessment (confirmed, not applicable, or needs more information) within 14 days.
Fix timelines depend on severity and are communicated once triage is complete.

If you believe a weakness is already covered by the protocol status table above or by an
existing `TODO.md` entry, feel free to reference it — that doesn't disqualify a report, but
it helps us triage faster.

## Out of Scope

- Findings against protocols already labeled demo-only/pedagogical above, when the finding
  merely reconfirms the documented weakness (e.g. "HKEX-GF's DLP is sub-128-bit", or its
  ~2^36.5 Pohlig–Hellman cost — both already tracked in SecurityProofs-3.md §9.2.4). Novel
  attacks that go beyond the documented analysis are still in scope.
- The `SecurityProofsCode/` analysis scripts and `CliTest/`/`CryptosuiteTests/` test
  harnesses are not part of the trust boundary; issues there can be filed as normal public
  GitHub issues.
