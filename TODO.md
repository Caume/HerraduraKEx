# HerraduraKEx — Open TODO Items

> **Completed, deprecated, and acknowledged items have moved to [`TODO_DONE.md`](TODO_DONE.md) (TODO #154).** This file holds only entries with `Status: **OPEN**`. Item numbers are global and preserved across both files — when an item here is completed, move its whole entry to the end of `TODO_DONE.md` and update its Status line, per CLAUDE.md's TODO policy.

---

## Research review — 2025-2026 cryptanalysis and primitive developments

The following items (#156-#163) were opened from a literature review of cryptanalysis
and cryptographic-primitive research published in roughly the 12 months prior to
2026-07-31, cross-checked against this repo's existing TODO/SecurityProofs coverage so
only genuinely new angles are recorded here (constant-time auditing, rotational
differential analysis of NL-FSCX, QC-MDPC decoder trapdoors, and hybrid Ring-LWR+Stern-F
credentials were already tracked as #41/#75/#83/#123/#125/#126/#128/#129 and are not
re-opened).

### 156. Re-derive Stern-F/QC-MDPC security margins against 2025-2026 information-set-decoding improvements (Research/Security, Medium)

**Background:** Two ISD advances published in the review window potentially shift the
parameter margins TODO #91 and #126 already track:

- An improved Both-May algorithm with more efficient time-memory trade-offs than prior
  ISD variants (Both-May-style ISD, 2025;
  https://link.springer.com/content/pdf/10.1007/978-3-031-86599-2_4.pdf?pdf=inline+link).
- 2026 research on whether extension-field structure can further speed up ISD solvers for
  the syndrome decoding problem underlying most code-based schemes
  (https://link.springer.com/article/10.1007/s12095-025-00857-9).

`HPKS-Stern-F`/`HPKE-Stern-F`'s $N=256$ demo parameters are already documented (README,
TODO #91) as providing only ~30-40 bits of security, with $N \geq 17000$ named as the
128-bit-security production target. That $N \geq 17000$ figure was derived against the
ISD state of the art at the time it was set; if either 2025-2026 ISD improvement reduces
the bit-security of a fixed $(N, t)$ pair, the production-target $N$ named in TODO #91/
`SecurityProofs-2.md` may now be understated, and `SDF_PRODUCTION_ROUNDS`'s soundness
target (referenced by `herradura.h`'s own build-time `#pragma message` in TODO #142)
should be re-checked against it too.

**Work items:**

1. Read both papers in full and extract their concrete complexity-exponent improvements
   over classical Prange/Stern/Dumer ISD (not just the abstract's headline numbers).
2. Re-run or adapt `SecurityProofsCode`'s existing Stern-F parameter-selection reasoning
   (wherever $N \geq 17000$ was derived — check `SecurityProofs-2.md` §11.x and TODO #91)
   with the improved ISD cost model plugged in, for both the classical bit-security
   estimate and any assumed quantum speedup.
3. If the required $N$ for 128-bit security changes materially, update
   `SecurityProofs-2.md`, TODO #91's own text, README's parameter table, and
   `spec/herradura-protocol-spec.json`'s security-level classification for the Stern-F
   protocols accordingly.
4. Cross-check whether the same ISD improvements affect TODO #126's QC-MDPC/Niederreiter
   decoding-trapdoor scoping (HPKE-Stern-F's KEM side uses the same underlying SD
   assumption family).

**Progress (2026-07-31):** `SecurityProofs-2.md` §11.8.4 now documents both papers.
The Elbro-Weger extension-field paper (eprint 2025/1402, fully reviewed) is a clean
negative result — extension-field structure does not speed up ISD, and doesn't apply
to HPKS-Stern-F/HPKE-Stern-F's plain-$\mathrm{GF}(2)$ construction anyway, so it does
not move the $N \geq 17000$ target. The Furue-Aikawa Both-May paper (PQCrypto 2025) sits
behind a Springer paywall; only its abstract-level framing ("more efficient
time-memory trade-offs", not a lower time exponent) could be confirmed, so work items
1–2 remain unresolved for that paper specifically — the concrete exponent improvement
was never extracted or plugged into the SDE worksheet. TODO #126's QC-MDPC parameters
are unaffected by either finding (item 4 is otherwise complete). Re-open work items 1–2
if full-text access to the Both-May paper becomes available.

Status: **OPEN**

### 157. Re-evaluate HKEX-RNL's CBD($\eta=1$) secret distribution against the 2026 sparse-secret hybrid-decoding attack on Ring-LWE/Ring-LWR (Research/Security, Medium)

**Background:** "Careful with the Ring: Enhanced Hybrid Decoding Attacks against
Module/Ring-LWE" (2026; https://eprint.iacr.org/2026/366) presents a hybrid
meet-in-the-middle/lattice-decoding attack that exploits the polynomial ring structure of
$\mathbb{Z}_q[X]/(x^N+1)$ to accelerate guessing and decoding for **sparse-secret**
instances, reporting a complexity improvement by a factor of $O(N)$ over prior hybrid
decoding attacks and 17x-114x speedups on previously-broken sparse instances (mostly
demonstrated against FHE parameter sets from 2022-2025 deployments, not HKEX-RNL's own
parameters).

TODO #1 (`RNLB=1 — sparse secrets`, now `DEPRECATED` in `TODO_DONE.md`) already flagged
sparse-secret risk for an earlier, cruder uniform-small-Hamming-weight secret sampler and
recorded that it was superseded by the CBD($\eta=1$) sampler (`SecurityProofs-2.md`
§11.4.2/§11.6). CBD($\eta=1$) secrets are *small* (each coefficient in
$\{-1,0,1\}$-ish range, per the centered binomial distribution) but not necessarily
*sparse* in the specific structural sense this new hybrid attack exploits — the two
properties are related but distinct, and TODO #1's deprecation reasoning predates this
2026 paper. This item is to determine whether "small" (CBD) and "sparse" (attacked here)
coincide closely enough at HKEX-RNL's own $(q=65537, n=256)$ parameters for the new
attack's complexity bound to apply, or whether they're distinct enough that the existing
deprecation stands unaffected.

**Work items:**

1. Read the paper's precise definition of "sparse" (e.g. Hamming weight / hint-supported
   sparsity assumption) and compare it against HKEX-RNL's actual CBD($\eta=1$) secret
   distribution at $n=256$ — are CBD-sampled secrets sparse under that definition, or only
   "small"?
2. If applicable, estimate the concrete complexity of the enhanced hybrid attack against
   HKEX-RNL's deployed parameters (not just the FHE parameter sets the paper
   demonstrates), following the same style of concrete-complexity worksheet already used
   in `SecurityProofsCode/hkex_rnl_failure_rate.py`/§11.4-§11.6.
3. Document the conclusion in `SecurityProofs-2.md` regardless of outcome (either "attack
   does not apply because X" or "attack reduces estimated security margin by Y bits") so
   the reasoning is traceable, and update TODO #1's `DEPRECATED` note in `TODO_DONE.md`
   with a forward-reference if the conclusion revises it.

**Progress (2026-07-31):** `SecurityProofs-2.md` §11.6 (just before §11.7) now documents
the finding: the paper's own PDF is Cloudflare-gated and couldn't be read directly, but
its abstract names five target FHE papers ([JM22]/[CCKS23]/[BCKS24]/[CHKS25]/[AKP25])
that are all classical sparse-secret-bootstrapping proposals with published Hamming
weights $h \approx 64$–$192$ against $N=2^{15}$ (density $\lesssim 0.6\%$). HKEX-RNL's
deployed CBD($\eta=1$) sampler has $\approx 50\%$ nonzero density at $n=256$ — over two
orders of magnitude denser — so by the density-gap argument the attack's speedup
mechanism (reduced guessing space over sparse nonzero positions) should not transfer,
and TODO #1's deprecation stands unaffected. Note in passing: TODO #1's own status line
in `TODO_DONE.md` reads `DONE (v1.5.x)`, not `DEPRECATED` as this item's background
section (written before this review) stated — a small cross-reference slip, not a
finding that needs its own action. Work item 3's forward-reference-to-TODO#1 is therefore
not needed since no revision resulted. This item stays **OPEN** because the conclusion
rests on indirect evidence (target-paper parameters), not the paper's own formal
sparsity definition — re-close only after a direct read confirms it.

Status: **OPEN**

### 158. Apply the 2025 automated rotational-XOR differential search framework to FSCX/NL-FSCX (Research, Medium)

**Background:** A 2025 paper proposes an automatic search framework for
rotational-XOR (RX) differential characteristics in ARX ciphers
(https://link.springer.com/article/10.1007/s10623-025-01571-6), reporting characteristics
covering more rounds than previously known for SPECK, CHAM, SPARX, and Ballet (e.g.
17-24 round RX-differentials for SPECK variants, versus a prior best of 13 rounds).

TODO #75 (`Formal rotational differential analysis of NL-FSCX v1`) and TODO #125
(`Sparse-input rotational differential characterization of NL-FSCX v1 at large n`) are
already `DONE`/tracked in `TODO_DONE.md` and cover rotational analysis of FSCX/NL-FSCX,
but both predate this specific 2025 automated-search tool. FSCX's core operator
$M = I \oplus \text{ROL} \oplus \text{ROR}$ is XOR-and-rotation (not full ARX — it has no
modular addition), so the framework's addition-centric technique doesn't transfer
directly, but its automated RX-characteristic-search *methodology* (as opposed to the
addition-specific propagation rules) may still surface longer characteristics than the
manual/semi-automated analysis TODO #75/#125 used, especially for NL-FSCX v1/v2 where the
non-linear step reintroduces addition-like mixing.

**Work items:**

1. Read the paper closely to separate its ARX-modular-addition-specific propagation
   rules from its general RX-characteristic search methodology (SAT/SMT or MILP-based
   search, if that's what it uses).
2. Determine whether the general search methodology can be adapted to FSCX's pure
   XOR-rotation operator and to NL-FSCX v1/v2's added non-linear step, reusing
   `SecurityProofsCode/fscx_periodicity_z3.py`'s existing Z3-based approach as a starting
   point if the tooling is compatible.
3. If adaptable, run the search against FSCX_N and NL-FSCX v1/v2 at the suite's actual
   parameter sizes and compare any newly found characteristics against TODO #75/#125's
   prior bounds.
4. Document results in `SecurityProofs-2.md` regardless of outcome, and add a
   `SecurityProofsCode/` script if new characteristics are found (following the existing
   naming convention, e.g. `nl_fscx_rx_differential_2025.py`).

**Progress (2026-07-31):** paper's full text is paywalled beyond its abstract, so its
exact CNF/SAT encoding couldn't be reproduced. Added
`SecurityProofsCode/nl_fscx_rx_differential_2025.py`: a bounded, non-exhaustive
hill-climbing stand-in that searches over nonzero-XOR RX-differences $(da,db)$ (not just
the pure-rotation $da=db=0$ slice TODO #75/#125 already covered) for NL-FSCX v1's
modular-addition step, since FSCX's XOR-rotation linear part transmits every RX-difference
with probability 1 and contributes no search surface. Found no configuration with a
materially higher single-round transition probability than the existing pure-rotational
baseline at $n \in \{16,32\}$. Documented in `SecurityProofs-2.md` (end of the sparse-$B$
subsection) with explicit caveats: this is local search, not exhaustive SAT, and only
covers single-round (not chained multi-round) transitions. Stays **OPEN** — reproducing
the paper's actual automated search is future work, deferred due to paywalled access.

Status: **OPEN**

### 159. LLM/AI-assisted cryptanalysis stress-testing pass across HerraduraKEx's primitives (Research/Security, Medium)

**Background:** In the review window, LLM-driven cryptanalysis moved from a research
curiosity to a credible, NIST-adjacent methodology: Anthropic's Claude discovered a real
vulnerability in HAWK, a lattice-based signature scheme that was under active
consideration for NIST standardization, leading the HAWK team to withdraw it from
consideration entirely (2026-07-28;
https://www.govinfosecurity.com/claude-mythos-finds-new-cryptographic-algorithm-attacks-a-32360).
Separately, `CryptanalysisBench` (2026; https://arxiv.org/html/2607.18538v1) benchmarks
LLMs across 191 cryptanalysis tasks spanning six primitive families drawn from four NIST
standardization competitions, and other 2025-2026 work evaluates LLM-assisted
side-channel vulnerability discovery (https://arxiv.org/html/2505.24621) and automated
cryptographic exploitation agents (https://arxiv.org/pdf/2601.09129). This is a
meaningfully different validation channel from this repo's existing
`SecurityProofsCode/` manual/scripted proofs — it found a real flaw in a scheme that had
already passed multiple rounds of expert human review.

**Work items:**

1. Scope a bounded, well-defined stress-testing pass: pick 2-3 of HerraduraKEx's less
   battle-tested constructions as targets (e.g. NL-FSCX v2's CSP-based construction,
   HPKS-Stern-Ring's OR-composition, the HFSCX-256-DM finalizer) rather than attempting
   to cover the whole suite at once.
2. Define what "stress-testing" means concretely here given available tooling — this
   could be as simple as posing the same kind of structured cryptanalysis prompts used in
   `CryptanalysisBench`/the HAWK finding against this suite's own primitive definitions
   and existing `SecurityProofsCode/` proof scripts, to see whether an LLM surfaces gaps
   the existing manual proofs missed.
3. Treat any finding as a lead requiring the same manual verification standard as any
   other TODO in this file (a `SecurityProofsCode/` script reproducing it, not just an
   LLM's claim) before it's considered confirmed — mirroring how CryptanalysisBench's own
   authors note LLMs "fail comprehensively at algorithm-level cryptanalysis" in the
   general case, so a hit rate of zero is an expected, valid outcome here too.
4. Document the pass and its outcome (findings or a clean bill of health) in
   `SecurityProofs-2.md` or a new `SecurityProofsCode/` note, so this doesn't need
   re-justifying from scratch next time it comes up.

**Progress (2026-07-31) — first pass complete, one real finding.** Scoped the pass to
HPKS-Stern-Ring's OR-composition (herradura.h `stern_ring_sign`, the Python/Go suite
equivalents) as the target — the "less battle-tested" construction named in work item 1.
Reading `stern_ring_sign`'s non-signer challenge simulation against the joint
Fiat-Shamir challenge derivation surfaced a genuine, previously-undocumented modulo-3
bias: the C and Python implementations draw a single random byte and reduce mod 3 to
pick each non-signer's per-round challenge (256 is not divisible by 3, so residue 0 is
~0.39% overrepresented), while the real signer's own displayed challenge is forced by
subtraction from a hash-derived, effectively-uniform joint challenge — meaning the
signer's slot has an exactly-uniform marginal while every non-signer's slot carries the
skew. This is a statistical anonymity leak under repeated use of the same ring (not a
one-shot break): `SecurityProofsCode/stern_ring_challenge_bias.py` (added this pass)
verifies the exact 86/85/85-out-of-256 distribution, confirms it by Monte Carlo, and
estimates ~9,000+ same-ring signatures needed before the skew is statistically
distinguishable per slot at 3-sigma confidence. Per work item 3, this is filed as its own
actionable item — **TODO #164** — rather than treated as fixed here, since #159 is a
process/tracking item, not a fix ticket. Go's own implementation already reduces a wide
32-bit value mod 3 (bias ~2^-32, negligible), so this is a C/Python-specific gap, not a
protocol-level design flaw.

The other two candidate targets from work item 1 (NL-FSCX v2's CSP-based construction,
HFSCX-256-DM's finalizer) have not yet been passed over — stays **OPEN** for those two.

Status: **OPEN**





### 165. Bind ciphertext/encapsulation-key/context into HKEX-RNL's KDF, per SP 800-227's key-derivation recommendations (Security, Medium)

**Background:** Found during TODO #161's NIST SP 800-227 audit (`SecurityProofs-2.md`
§11.15, item 7). SP 800-227 §4.5–§4.6 recommends that a KEM's key-derivation `OtherInput`/
`FixedInfo` include not just a domain separator but also the ciphertext, either party's
encapsulation key, and/or a context string — its example combiner is
`H(K1, K2, c1, c2, ek1, ek2, domain_sep)` — both for cross-protocol domain separation and
for "binding the final shared secret to the identities of the participating parties."

HKEX-RNL's `ba_rnl_kdf_seed` (`herradura.h`, TODO #38) already XORs a fixed domain
constant `_RNL_KDF_DC` into the KDF input, which correctly separates HKEX-RNL's KDF output
from other suite call sites reusing the same underlying primitive. It does **not**
additionally bind the ciphertext/public polynomial exchanged that session, either party's
encapsulation key, or any other per-session context beyond what's already implicitly
carried inside the raw shared secret itself. This is not a known attack against the
current construction — HKEX-RNL is a direct DH-style NIKE, not a composite/hybrid KEM
where SP 800-227 §4.6.3 shows this matters for IND-CCA preservation — but it falls short
of the standard's recommended practice, and TODO #162's planned hybrid HKEX+Stern-F
combiner will need exactly this kind of binding to satisfy §4.6.3's IND-CCA-preservation
requirement regardless.

**Work items:**

1. Extend `ba_rnl_kdf_seed`'s input (or add a new KDF entry point) to additionally mix in
   the session's public polynomials (`C_A`/`C_B` or equivalent ciphertext/encapsulation-key
   material) and, if available, a caller-supplied context string — following SP 800-227's
   example combiner shape rather than inventing a new one.
2. Apply consistently across all three language targets (C/Go/Python) and, if reachable
   from the CLI, the CLI's own `kex` KDF invocation.
3. Update `SecurityProofs-1.md`'s KDF domain-constant discussion (§11.6-adjacent) and
   `SecurityProofs-2.md` §11.15 to reflect the stronger binding once implemented.
4. Re-run `CliTest/test_vectors.sh`/`test_go_keygen.sh` equivalents to confirm Alice/Bob
   still derive the same session key after the change (both sides must feed identical
   ciphertext/ek material into the KDF, not just their own).
5. Coordinate with TODO #162: if that item's combiner design is done first, this item may
   be substantially satisfied by it rather than needing separate implementation — check
   before duplicating work.

Status: **OPEN**

### 166. Optional passphrase-based encryption for exported private-key PEM files (Security/Feature, Low)

**Background:** Found during TODO #161's NIST SP 800-227 audit (`SecurityProofs-2.md`
§11.15, item 4). SP 800-227 §3.2 ("Data at rest") requires that private data (seeds,
decapsulation/private keys) be "stored within the cryptographic module in a manner that
is secure against both leakage and unauthorized modification," and that "the import and
export of private data...needs to be performed in a secure manner." All three CLIs
(`genpkey --out priv.pem`) always write private-key PEM files in cleartext with no
passphrase-based encryption option, unlike OpenSSL's traditional `-aes256`/`-des3`
PEM-encryption flags or PKCS#8 encrypted private-key format. Anyone who copies, backs up,
or transmits an exported `.pem` file without independent OS-level protection (file
permissions, disk encryption) has no cryptographic protection on the key material itself.

**Work items:**

1. Decide an encryption format: either a simple password-based scheme reusing this
   suite's own primitives (e.g. HSKE-NL-A1 keystream over the PEM payload, keyed by a
   password-derived key via a suite KDF with a random salt) or a more conventional
   PBKDF2/scrypt-wrapped-AES approach if the goal is broader tooling compatibility —
   document the tradeoff before picking one, since this suite doesn't currently implement
   a password-based KDF (PBKDF2/Argon2-class) anywhere.
2. Add a `--passphrase`/`--passin`/`--passout`-style flag to `genpkey` (and `pkey` for
   re-encryption/decryption round-trips) across all three CLI language targets, mirroring
   OpenSSL's flag naming where reasonable for user familiarity.
3. Extend the PEM wire format with an encrypted-private-key variant label/header
   (distinguishable from the existing cleartext label so old tooling fails closed rather
   than silently misinterpreting encrypted bytes as a raw key).
4. Add `CliTest/` coverage: round-trip encrypt/decrypt with correct passphrase, and
   confirm a wrong passphrase is rejected cleanly (not a crash or silent garbage key).
5. Document in `docs/TUTORIAL.md` and `SecurityProofs-2.md` §11.15.

Status: **OPEN**

### 167. Port the `hybrid-rnl-stern` combiner (TODO #162) to the Go and C CLIs (Feature/Interop, Medium)

**Background:** TODO #162 implemented a hybrid HKEX-RNL + HPKE-Stern-KEM combiner mode
(`kex --algo hybrid-rnl-stern`) and its SP 800-227 §4.6-style key-combiner construction
(`SecurityProofs-2.md` §11.16), matching this repo's own precedent for large CLI features
(TODO #25's "Python only (initial version)" scoping, later followed by separate C/Go
items #27/#28). Only the Python CLI (`HerraduraCli/herradura.py`) and
`CliTest/test_hybrid_kex.sh` exist so far; the Go (`herradura_cli.go`) and C
(`herradura_cli.c`/`herradura.h`) CLIs have no equivalent, so this feature is not yet
interop-complete across the three language targets this repo's other KEM/KEX modes
maintain parity across.

**Work items:**

1. Port `_hybrid_rnl_stern_combine`'s exact byte layout (§11.16's formula: `HFSCX-256-DS`
   with tag `0x05` over `K1 || K2 || C_A || m_A || C_B || hint || h_pub || syn ||
   "HERRADURA-HYBRID-RNL-STERN-v1"`) to Go and C — bit-for-bit identical serialization is
   required for cross-language interop, not just cross-language correctness.
2. Add the `hybrid-rnl-stern` `kex` mode (with `--their-kem`/`--our-kem` flags mirroring
   Python's) to both `herradura_cli.go` and `herradura_cli.c`, reusing each language's
   existing `hkex-rnl` and `hpke-stern-kem`/QC-MDPC implementations exactly as the Python
   version reuses `_rnl_agree`/`qcmdpc_encap`/`qcmdpc_decap_bgf` unmodified.
3. Add a new `HYBRID-RNL-STERN RESPONSE` PEM label/encode/decode to each language's codec,
   matching Python's DER field order exactly (`K, C_B, hint, n, hint_len, n_B, syn, r`).
4. Extend `CliTest/test_hybrid_kex.sh` (or add a cross-language sibling matching the
   `test_stern_kem.sh`/`test_vectors.sh` 3x3 interop-matrix convention) so Bob (any
   language) and Alice (any language) derive the same session key regardless of which
   CLI each party runs.
5. Update `SecurityProofs-2.md` §11.16's "Implementation status" note once complete.

Status: **OPEN**

