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


### 161. Audit HKEX-RNL/HKEX-GF/Stern-F KEM usage against NIST SP 800-227 (September 2025) (Security/Docs, Medium)

**Background:** NIST finalized SP 800-227 in September 2025, providing guidance on how
KEMs should actually be used in protocols — covering protocol composition, input
validation, key derivation, failure behavior, randomness requirements, side-channel
resistance, and key lifecycle controls, on the premise that a mathematically sound KEM
primitive can still be broken by misuse at these layers
(https://postquantum.com/post-quantum/cryptography-pqc-nist/, referencing SP 800-227).
This repo already has related but narrower items — TODO #141 hardens the CLI against
degenerate peer public keys, and TODO #144 covers weak-key rejection parity across
language targets — but neither was scoped against this specific, now-finalized NIST
guidance document, which is broader (implicit rejection semantics, KDF domain separation
requirements, decapsulation failure handling) than either existing item.

**Work items:**

1. Read SP 800-227 in full and produce a checklist of its concrete requirements/
   recommendations relevant to a KEM implementation and its calling protocol.
2. Walk HKEX-RNL (the suite's actual KEM), and HKEX-GF/HPKE-Stern-F as the closest
   analogues (DH-based and Niederreiter-KEM-based respectively), against that checklist:
   implicit vs. explicit rejection on decapsulation failure, KDF domain separation
   (`SecurityProofs-1.md`/§11.6's existing KDF domain constant work may already satisfy
   some of this — verify rather than assume), randomness source requirements, and
   failure-mode information leakage.
3. File any gaps found as their own follow-up TODOs rather than fixing inline here, since
   this item is scoped to the audit/checklist, not remediation.
4. Cross-reference the result against TODO #141/#144 so overlapping scope is merged
   rather than duplicated.

Status: **OPEN**

### 162. Hybrid classical+PQC combiner mode for HKEX, beyond the existing hybrid Ring-LWR+Stern-F credential work (Feature/Research, Medium)

**Background:** "Hybrid-by-default" is now the mainstream industry deployment pattern
for the post-quantum transition: run a classical algorithm and a PQC algorithm in
parallel so an attacker must break both (IETF/NIST-adjacent guidance per 2025-2026
sources, e.g. https://postquantum.com/post-quantum/hybrid-cryptography-pqc/,
https://neuraparse.com/blog/hybrid-post-quantum-tls-ml-kem-2026/). NIST's own March 2025
selection of HQC specifically to diversify the KEM portfolio away from a single
lattice-based assumption follows the same logic. TODO #123/#128 already scope a hybrid
**Ring-LWR + Stern-F credential** (a specific compound proof/verifier construction), but
that is narrower than a general-purpose hybrid **key exchange** combiner mode — this item
is about combining HKEX-GF (or HKEX-RNL) with HPKE-Stern-F's Niederreiter KEM as parallel
KEMs feeding one combined session key, independent of the credential/ZKP work in #123/#128.

**Work items:**

1. Decide a concrete combiner construction (e.g. concatenate-then-KDF vs. one of the
   combiner constructions surveyed in current hybrid-PQC literature) and confirm it
   satisfies the property that the combined key is secure if *either* input KEM is
   secure (the standard hybrid-combiner security requirement).
2. Add a `kex --algo hybrid-...` (or similar) CLI mode pairing HKEX-RNL (lattice-based)
   with HPKE-Stern-F's KEM (code-based) as the two independent post-quantum assumptions,
   matching the "diversify away from a single PQC assumption family" rationale NIST used
   for HQC.
3. Extend to all three CLI language targets per this repo's existing interop-parity
   standard, with `CliTest/` coverage.
4. Document the construction and its security argument in `SecurityProofs-2.md`,
   distinguishing it clearly from TODO #123/#128's credential-specific hybrid work.

Status: **OPEN**

### 163. Refresh SecurityProofs-1.md §6's quantum resource-estimate numbers with 2026 discrete-log qubit-count improvements (Documentation/Research, Low)

**Background:** A paper scheduled for EUROCRYPT 2026 (Chevignard, Fouque, Schrottenloher)
reduces the logical-qubit requirement for solving a 256-bit-curve discrete log via Shor's
algorithm from a prior estimate of 2,124 logical qubits down to 1,098, via a
space-optimized circuit (space complexity $3.12n$ for an $n$-bit curve) and output
compression using a Legendre-symbol-based single-bit hash
(https://quantumcomputingreport.com/resource-estimates-for-quantum-discrete-logarithm-computations-on-256-bit-elliptic-curves/).
A follow-up distributed-quantum variant reportedly pushes the single-node requirement to
1,080-1,140 qubits with no quantum communication between nodes
(https://eprint.iacr.org/2026/1244). These figures are specifically for elliptic-curve
DLP, not directly for HKEX-GF's $\mathbb{GF}(2^n)^\ast$ discrete log, but
`SecurityProofs-1.md` §6's existing quantum attack analysis for HKEX-GF discusses Shor's
algorithm's applicability in the same qubit-resource-estimate style, and citing stale
qubit-count figures there undersells (or oversells) how close a practical quantum attack
actually is by 2026 standards.

**Work items:**

1. Read `SecurityProofs-1.md` §6 and identify exactly which qubit-count/resource-estimate
   figures it currently cites for Shor's-algorithm attacks relevant to HKEX-GF.
2. Determine whether the Legendre-symbol output-compression technique (developed for
   ECDLP) has a natural analogue for $\mathbb{GF}(2^n)^\ast$ discrete log, or whether the
   qubit savings are ECDLP-specific and only useful here as a general "quantum resource
   estimates keep improving" data point.
3. Update §6 with the current-as-of-2026 qubit-count figures (citing both papers above),
   making clear which apply directly to HKEX-GF's actual group and which are cited only
   for context (e.g. RSA-3072 comparison point).
4. No code changes expected — this is a documentation freshness item, distinct from
   TODO #145's build/test doc staleness scope.

Status: **OPEN**

