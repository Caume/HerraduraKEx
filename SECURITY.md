# Security Policy

## Protocol Status

HerraduraKEx implements several protocols that span a wide range of maturity, from
production-suitable to strictly pedagogical. Use this table to decide whether a protocol
is appropriate for your use case. Each row links to the authoritative analysis instead of
restating it here, so consult the linked section for the full argument before relying on
any of these classifications.

| Protocol | Status | Why | Details |
|---|---|---|---|
| **HKEX-GF** | Demo-only / pedagogical | Pohlig–Hellman solves the DLP in ~2^36.5 group operations at n=256 (the group order 2^256−1 has a 73-bit largest prime factor) — days on one core; DLP in GF(2^n)* is also deprecated by NIST SP 800-57 Rev. 5 (2020) and ENISA (2022) | SecurityProofs-2.md §9.2.4 |
| **HPKS** | Demo-only / pedagogical | Same ~2^36.5 Pohlig–Hellman key recovery as HKEX-GF, which yields arbitrary signature forgery | SecurityProofs-2.md §9.2.4, §9.2.6 (ristretto255 migration path) |
| **HPKE** | Demo-only / pedagogical | Same ~2^36.5 Pohlig–Hellman recovery as HKEX-GF, which yields the decryption key; independently, the FSCX encryption layer leaks 126 of 256 plaintext functionals from the ciphertext alone | SecurityProofs-2.md §9.2.4, SecurityProofs-1.md §1.3.1 |
| **HPKS-NL / HPKE-NL** | Demo-only / pedagogical | NL-FSCX challenge/encryption layered on the same GF(2^n)* group, so the ~2^36.5 Pohlig–Hellman key recovery applies unchanged | SecurityProofs-3.md §11.7 |
| **HSKE** (key-only) | Not suitable for production | The ciphertext alone leaks 126 of 256 linear functionals of the plaintext at the deployed i = n/4 — no known plaintext required; the n/2-bit post-quantum bound covers key search only | SecurityProofs-1.md §1.3.1 (Thm. 4.1), §4.2 W9 |
| **HSKE** (known-plaintext) / **HSKE-NL-A1/A2** | Not suitable for production | A single known-plaintext pair recovers the keystream | SecurityProofs-3.md §11.7 |
| **HKEX-RNL** (n=256) | Below target, use HKEX-RNL-128 | ~105 classical / ~100 quantum Core-SVP bits — below the 128-bit target | SecurityProofs-3.md §11.4.3, §11.7 |
| **HKEX-RNL-128** (n=512) | Production-track (conjectured PQ-resistant) | ≥128-bit classical and quantum Core-SVP bits; cross-checked against ML-KEM-512 | SecurityProofs-3.md §11.4.3 |
| **HPKS-Stern-F / HPKE-Stern-F** | Demo-only | ~30–40 bits at deployed N=256; 128-bit classical security needs N ≥ 17000; decapsulation at production parameters needs the QC-MDPC decoder from TODO #126 | SecurityProofs-3.md §11.7, SecurityProofs-4.md §11.8.5 |
| **HPKE-Stern-KEM** | Demo-only | Measured DFR 0.264% = 2^-8.6 at the deployed toy parameters (r=523, d=15, t=18), where IND-CCA2 needs 2^-128; decapsulation signals failure explicitly with no Fujisaki–Okamoto transform and no implicit rejection, so the GJS reaction attack recovers the private key in ~10^6 chosen-ciphertext queries; keygen applies no weak-key screen (~1 key in 3400 has ~10x the average DFR). Do not reuse a keypair across decapsulations you do not control | SecurityProofs-4.md §11.8.7 |

**HYBRID-RNL-STERN note.** The hybrid combines HKEX-RNL with HPKE-Stern-KEM, so it
inherits the KEM row's reaction-attack exposure on its KEM half: `kex --algo
hybrid-rnl-stern` reports decapsulation failure with its own distinct message, which
is the same oracle. The Ring-LWR half is unaffected, and an attacker who recovers the
QC-MDPC private key still faces the HKEX-RNL contribution — but treat the hybrid's
KEM half as demo-only for the same reasons.

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
`SecurityProofs-1.md` through `-5.md`.

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
  ~2^36.5 Pohlig–Hellman cost — both already tracked in SecurityProofs-2.md §9.2.4). Novel
  attacks that go beyond the documented analysis are still in scope.
- The `SecurityProofsCode/` analysis scripts and `CliTest/`/`CryptosuiteTests/` test
  harnesses are not part of the trust boundary; issues there can be filed as normal public
  GitHub issues.
