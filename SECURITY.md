# Security Policy

## Protocol Status

HerraduraKEx implements several protocols that span a wide range of maturity, from
production-suitable to strictly pedagogical. Use this table to decide whether a protocol
is appropriate for your use case. Each row links to the authoritative analysis instead of
restating it here, so consult the linked section for the full argument before relying on
any of these classifications.

| Protocol | Status | Why | Details |
|---|---|---|---|
| **HKEX-GF** | Demo-only / pedagogical | DLP in GF(2^n)* is deprecated by NIST SP 800-57 Rev. 5 (2020) and ENISA (2022); ~80–90 bits at n=256, not 128 | SecurityProofs-1.md §9.2.4 |
| **HPKS** | Demo-only / pedagogical | Same GF(2^n)* deprecation as HKEX-GF | SecurityProofs-1.md §9.2.4, §9.2.6 (ristretto255 migration path) |
| **HPKE** | Demo-only / pedagogical | Same GF(2^n)* deprecation as HKEX-GF | SecurityProofs-1.md §9.2.4 |
| **HPKS-NL / HPKE-NL** | Demo-only / pedagogical | NL-FSCX challenge/encryption layered on the same deprecated GF(2^n)* group | SecurityProofs-2.md §11.7 |
| **HSKE** (key-only) | Conditionally usable | n/2-bit post-quantum security only if no plaintext is ever observed; not realistic in most deployments | SecurityProofs-2.md §11.7 |
| **HSKE** (known-plaintext) / **HSKE-NL-A1/A2** | Not suitable for production | A single known-plaintext pair recovers the keystream | SecurityProofs-2.md §11.7 |
| **HKEX-RNL** (n=256) | Below target, use HKEX-RNL-128 | ~105 classical / ~100 quantum Core-SVP bits — below the 128-bit target | SecurityProofs-2.md §11.4.3, §11.7 |
| **HKEX-RNL-128** (n=512) | Production-track (conjectured PQ-resistant) | ≥128-bit classical and quantum Core-SVP bits; cross-checked against ML-KEM-512 | SecurityProofs-2.md §11.4.3 |
| **HPKS-Stern-F / HPKE-Stern-F** | Demo-only | ~30–40 bits at deployed N=256; 128-bit classical security needs N ≥ 17000; decapsulation at production parameters needs the QC-MDPC decoder from TODO #126 | SecurityProofs-2.md §11.7, §11.8.5 |

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
`SecurityProofs-1.md`/`-2.md`/`-3.md`.

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
  merely reconfirms the documented weakness (e.g. "HKEX-GF's DLP is sub-128-bit" — already
  tracked in SecurityProofs-1.md §9.2.4). Novel attacks that go beyond the documented
  analysis are still in scope.
- The `SecurityProofsCode/` analysis scripts and `CliTest/`/`CryptosuiteTests/` test
  harnesses are not part of the trust boundary; issues there can be filed as normal public
  GitHub issues.
