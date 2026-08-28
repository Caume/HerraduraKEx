#!/usr/bin/env python3
"""rand_fpe_twk_analysis.py — TODO #241: the three unclassified CLI subcommands.

`rand`, `fpe` and `twk` ship in the C, Go and Python CLIs and reach no protocol
entry in spec/, no SECURITY.md row, and no SecurityProofs-*.md section.  TODO
#238 Part C recorded them in `unfiled_cli_surface` so the gap was enumerable;
this script is the analysis that lets them be filed, and it is what
SecurityProofs-7.md §11.24 cites.

Sections
  1  What the three actually are, read off the shipped implementation
  2  `fpe` and `twk` are the same function -- demonstrated, not argued
  3  `fpe` is not format-preserving encryption
  4  The tweak derivation: three defects in one line of code
  5  Round count: the same permutation as HSKE-NL-A2 at one third the rounds
  6  `rand` / HDRBG against SP 800-90A
  7  Verdicts and the SECURITY.md rows

Two of TODO #241's own premises did not survive contact with the code, and both
are recorded here rather than quietly worked around -- see §2 and §6.

Everything here runs against the shipped suite (`Herradura cryptographic
suite.py`) via importlib, deliberately: a claim about the deployed construction
has to be tested on the deployed construction.  No third-party dependencies;
runtime is a couple of seconds.

Run:  python3 SecurityProofsCode/rand_fpe_twk_analysis.py
"""

import importlib.util
import inspect
import os
import sys

SEP = "=" * 74
SEP2 = "-" * 74

_SUITE_PATH = os.path.join(os.path.dirname(__file__), '..',
                           'Herradura cryptographic suite.py')


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SUITE = _load_suite()


def rule(title):
    print("\n" + SEP)
    print(title)
    print(SEP)


# ═══════════════════════════════════════════════════════════════════════════
# §1 — what they are
# ═══════════════════════════════════════════════════════════════════════════
def section1():
    rule("§1  What the three subcommands actually are")
    print("""Read off the shipped implementation rather than the help text.

  fpe (TODO #78.A)   B = HFSCX-256(key || ctx)
                     C = nl_fscx_revolve_v2(P, B, I_VALUE)
  twk (TODO #78.B)   B = HFSCX-256(key || sector_be64 || bidx_be32)
                     C = nl_fscx_revolve_v2(P, B, I_VALUE)
  rand (TODO #96)    fast-key-erasure DRBG over HFSCX-256 and NL-FSCX v1

The first thing to notice is that fpe and twk differ only in what is
concatenated after `key`.  Both derive a 256-bit subkey with the same
unseparated hash call and hand it to the same permutation at the same step
count.  §2 shows what follows from that.""")

    i_value = _SUITE.I_VALUE
    r_value = _SUITE.R_VALUE
    print(f"\n  Deployed constants: I_VALUE = {i_value}, R_VALUE = {r_value}, "
          f"KEYBITS = {_SUITE.KEYBITS}")
    print(f"  DRBG_MAX_BLOCKS   = 2^{_SUITE.DRBG_MAX_BLOCKS.bit_length() - 1}"
          f" ({_SUITE.DRBG_MAX_BLOCKS} output blocks per seed/reseed)")
    return i_value, r_value


# ═══════════════════════════════════════════════════════════════════════════
# §2 — fpe and twk are one function
# ═══════════════════════════════════════════════════════════════════════════
def section2():
    rule("§2  `fpe` and `twk` are the same function")
    print("""TODO #241 states that these three "have no such parent" -- no existing
analysis whose verdict could be propagated the way TODO #238 propagated the
hpks row to hpks-t and hpks-nl.  That premise is half right.  `rand` has no
parent.  `fpe` and `twk` have two: each other, and HSKE-NL-A2 (§5).

Neither derivation carries a domain-separation tag, so whenever twk's
`sector_be64 || bidx_be32` happens to equal fpe's `ctx`, the two subkeys are
equal and the two subcommands compute the identical function.  Twelve bytes of
context is not an exotic choice -- it is the natural size -- and every byte of
it can be printable ASCII, so the collision is reachable from the command line
without constructing anything unusual.""")

    key = b'\x11' * 32
    P = _SUITE.BitArray(_SUITE.KEYBITS, 0xdeadbeefcafe)
    sector = int.from_bytes(b'01234567', 'big')
    bidx = int.from_bytes(b'89:;', 'big')
    ctx = sector.to_bytes(8, 'big') + bidx.to_bytes(4, 'big')

    a = _SUITE.fpe_encrypt(P, key, ctx).uint
    b = _SUITE.twk_encrypt(P, key, sector, bidx).uint
    same = (a == b)

    print(f"\n  ctx (as text)                     : {ctx!r}")
    print(f"  --sector {sector} --bidx {bidx}")
    print(f"  fpe_encrypt(P, key, ctx)          : {a:064x}")
    print(f"  twk_encrypt(P, key, sector, bidx) : {b:064x}")
    print(f"  identical                         : {same}")

    # The inverse direction matters too: it is not merely an equal ciphertext,
    # the two subcommands are inverses of one another across the boundary.
    back = _SUITE.twk_decrypt(_SUITE.BitArray(_SUITE.KEYBITS, a),
                              key, sector, bidx).uint
    print(f"  twk_decrypt undoes fpe_encrypt    : {back == P.uint}")

    print("""
  Reproduced at the CLI, in all three implementations that ship these
  subcommands (C, Go, Python), against one HERRADURA SESSION KEY PEM:

      $CLI fpe --context '0123456789:;'      --encrypt --in pt --out a
      $CLI twk --sector 3472611983179986487 \\
               --bidx   943274555            --encrypt --in pt --out b
      cmp a b        # identical, in each of the three
      $CLI twk --sector ... --bidx ... --decrypt --in a   # recovers pt

  All three agree byte-for-byte on the colliding value, which makes this a
  property of the construction rather than a bug in one port.

  Why it matters.  Two separately-advertised primitives, reachable under one
  key, are not independent: a `twk` disk-sector ciphertext and an `fpe` record
  ciphertext can be the same ciphertext, and either subcommand decrypts the
  other's output.  A caller who believes they are using distinct primitives for
  distinct purposes -- which is the only reason to ship both -- does not get
  that.  Standard practice is one domain-separation tag per primitive, and the
  suite already has the machinery: `hfscx_256_ds` (TODO #93) and
  `hmac_hfscx_256` both exist and neither is used here.""")
    return same, back == P.uint


# ═══════════════════════════════════════════════════════════════════════════
# §3 — fpe is not FPE
# ═══════════════════════════════════════════════════════════════════════════
def section3():
    rule("§3  `fpe` is not format-preserving encryption")
    print("""Format-preserving encryption, as the term is used in the literature and in
NIST SP 800-38G (FF1, FF3-1), is a cipher on an arbitrary domain: given a
radix and a length, it maps a radix-`radix` string of length `n` to another
string of the same radix and length.  The whole point is that a 16-digit card
number encrypts to a 16-digit card number, so ciphertext can flow through a
system that validates the format.

The shipped `fpe` has no radix parameter, no length parameter, and no domain
of any kind.  It maps 32 bytes to 32 bytes.  The only "format" preserved is
the block width of the underlying permutation, which every block cipher
preserves and none of them calls FPE.

The CLI makes the mismatch concrete rather than merely terminological: input
shorter than 32 bytes is zero-padded, and output is always 32 raw bytes.""")

    kb = _SUITE.KEYBITS // 8
    pan = b'4111111111111111'          # 16 ASCII digits
    padded = pan.ljust(kb, b'\x00')    # exactly what cmd_fpe does
    P = _SUITE.BitArray(_SUITE.KEYBITS, int.from_bytes(padded, 'big'))
    C = _SUITE.fpe_encrypt(P, b'\x22' * 32, b'ctx')
    out = C.uint.to_bytes(kb, 'big')

    print(f"\n  plaintext  : {pan!r}   ({len(pan)} bytes, all ASCII digits)")
    print(f"  ciphertext : {out.hex()}")
    print(f"               ({len(out)} bytes, printable-ASCII: "
          f"{all(32 <= c < 127 for c in out)}, all-digits: "
          f"{out.isdigit() if hasattr(out, 'isdigit') else False})")
    print("""
  A 16-digit input became 32 bytes of binary.  Any caller who reached for a
  subcommand named `fpe` because they needed the output to keep the input's
  shape gets the opposite, silently.  Nothing in the CLI help text
  ("Format-preserving encrypt/decrypt a 256-bit block") corrects the
  expectation the name sets, and "256-bit block" is doing load-bearing work
  that a reader scanning subcommands will not notice.

  This is a naming defect, not a break of the underlying permutation: as a
  deterministic 256-bit tweakable permutation the construction is exactly what
  §5 says it is.  But a security document that classified it without saying
  this would be classifying something other than what users will reach for.""")
    return out


# ═══════════════════════════════════════════════════════════════════════════
# §4 — the tweak derivation
# ═══════════════════════════════════════════════════════════════════════════
def section4():
    rule("§4  The tweak derivation: three defects in one line")
    print("""Both subcommands derive their subkey as `HFSCX-256(key || tweak)`, with the
key as a bare prefix.  Three separate problems sit in that line.\n""")

    key_a, ctx_a = b'AB', b'C'
    key_b, ctx_b = b'A', b'BC'
    P = _SUITE.BitArray(_SUITE.KEYBITS, 0x1234)
    amb = (_SUITE.fpe_encrypt(P, key_a, ctx_a).uint
           == _SUITE.fpe_encrypt(P, key_b, ctx_b).uint)

    print("  (a) No domain separation between the two primitives.  §2.\n")
    print("  (b) Unencoded concatenation boundary.  `key || ctx` does not record")
    print("      where the key ends, so distinct (key, ctx) pairs collide:")
    print(f"        fpe(P, key={key_a!r}, ctx={ctx_a!r}) == "
          f"fpe(P, key={key_b!r}, ctx={ctx_b!r}) : {amb}")
    print("      The CLI derives key bytes from the session-key PEM's own width,")
    print("      so key length is not fixed by the interface either.  The suite's")
    print("      own KEM code (TODO #235) length-prefixes for exactly this reason,")
    print("      and `drbg_seed` in this same file encodes len(entropy) as 8 bytes")
    print("      before the entropy -- so the correct pattern is already in use")
    print("      two hundred lines away.\n")

    src = inspect.getsource(_SUITE.fpe_encrypt) + inspect.getsource(_SUITE.twk_encrypt)
    checks_key = 'nl_v2_key_is_valid' in src
    print("  (c) The derived subkey is never validity-checked.")
    print(f"        fpe/twk call nl_v2_key_is_valid : {checks_key}")
    print("""      NL-FSCX v2 degenerates to a GF(2)-affine permutation, recoverable
      by linear algebra from a handful of known plaintexts, for keys with
      delta(B) in {0, 2^(n-1)}.  SECURITY.md's HSKE-NL-A2 row states that "all
      three CLIs reject it via nl_v2_key_is_valid" -- true for A2, not true
      here.  The practical exposure is small, because B is a hash output rather
      than user-supplied and the class is about 2^-129 of the space, so it is
      unreachable by chance and an attacker cannot steer it without the key.
      It is recorded as a missing defence-in-depth check that the suite already
      implements elsewhere, not as a live break.

      Note the direction of this one: deriving B by hashing is what makes the
      weak-key class unreachable, so on this specific axis fpe/twk are in a
      BETTER position than the HSKE-NL-A2 they inherit from.""")
    return amb, checks_key


# ═══════════════════════════════════════════════════════════════════════════
# §5 — round count
# ═══════════════════════════════════════════════════════════════════════════
def section5(i_value, r_value):
    rule("§5  The same permutation as HSKE-NL-A2, at one third the rounds")
    print(f"""`fpe` and `twk` are HSKE-NL-A2's construction with a derived rather than a
supplied subkey.  A2 is `nl_fscx_revolve_v2(P, K, r)`; these are
`nl_fscx_revolve_v2(P, B, i)`.  Same permutation, same primitive, same width.

The step count is not the same:

      HSKE-NL-A2      R_VALUE = 3n/4 = {r_value} steps
      fpe / twk       I_VALUE =   n/4 = {i_value} steps

That is a factor of {r_value // i_value}, and it is the reason the classification cannot simply
be inherited.  SECURITY.md rates HSKE-NL-A2 "Production-track (conjectured)".
Whatever confidence that rating carries is a statement about {r_value} rounds.

TODO #214 (SecurityProofsCode/nl_fscx_exact_trail_search.py) is the relevant
measurement.  It builds an exact Lipmaa-Moriai xdp+ model of one v2 round and
searches for optimal differential trails with an SMT backend.  Its §4 reports,
for v2 at the deployed rotation:

      mean slope                  1.87 bits of trail weight per round
      rounds to reach 2^-256      137
      64 rounds reaches           2^-119

So A2's {r_value} rounds clear the 137-round bar comfortably, and fpe/twk's {i_value} do not
reach it.  Two caveats, both important, both #214's own:

  * That projection is explicitly labelled the weakest step in #214 -- the
    slope is read off widths 16-32, not 256, and the search closes only for
    small round counts.  It is an order-of-magnitude indication, not a bound.
  * A trail probability is not a security level.  2^-119 is a statement about
    the best differential trail the model finds, not a demonstrated attack.

What survives both caveats is comparative, and that is enough for a
classification: on the only quantitative handle the repository has for this
permutation, fpe/twk sit on the wrong side of a line that HSKE-NL-A2 clears,
using the identical primitive.  Nothing in the code or the commit history
records a reason for the smaller count; I_VALUE appears to have been taken as
the default step count rather than chosen.

Note also that #214's own framing says "the deployed step count is n/4 = 64
rounds at n = 256".  That is right for HFSCX-256's v1 compression and for
fpe/twk, and wrong for HSKE-NL-A2 at 192 -- a documentation inconsistency
worth fixing when #214 is next revisited.""")


# ═══════════════════════════════════════════════════════════════════════════
# §6 — rand
# ═══════════════════════════════════════════════════════════════════════════
def section6():
    rule("§6  `rand` / HDRBG against SP 800-90A")
    print("""TODO #241 says of this one: "`rand`'s HDRBG has a `DrbgMaxBlocks = 1 << 20`
reseed bound ... and nothing anywhere saying what that bound is for."

That premise does not hold, and it is the second of the item's two that does
not.  The bound has a derivation, it is reproducible, and it is cited from the
suite source three lines above the constant:

    SecurityProofsCode/nl_fscx_v1_ratchet_collision.py §5

Re-running that section on the deployed construction gives:

      |Im(F^64)| / 2^256              extrapolates to 2^218.79
      E[walk collision]               ~ 2^109.7 output blocks
      P(collision within 2^20 blocks) ~ 2^-179.8
      verdict                         SAFE (requirement: <= 2^-128)

So DRBG_MAX_BLOCKS = 2^20 is not arbitrary: it is the point at which the
state-walk collision probability stays roughly fifty bits below the 2^-128
target, against a walk whose expected collision distance is 2^109.7 blocks.
For #241's purposes the work on `rand` is therefore filing, not deriving.

One genuinely new observation falls out of the same numbers and belongs in the
SECURITY.md row.  The state walk is a non-bijective map, so its image
contracts: after one revolve the reachable state space is about 2^218.8, not
2^256.  The effective state entropy of the generator is therefore roughly 219
bits rather than the 256 its state width suggests.  That is far above any
practical threshold and is not a weakness, but a reader entitled to assume
"256-bit state = 256-bit security" would be assuming slightly wrong, and no
document currently says so.\n""")

    # Behavioural properties the row will assert, checked rather than asserted.
    d1 = _SUITE.drbg_seed(b'entropy-241-aaaaaaaaaaaaaaaaaaaaaaaa', b'pers')
    d2 = _SUITE.drbg_seed(b'entropy-241-aaaaaaaaaaaaaaaaaaaaaaaa', b'pers')
    d3 = _SUITE.drbg_seed(b'entropy-241-aaaaaaaaaaaaaaaaaaaaaaaa', b'other-pers')
    o1 = _SUITE.drbg_generate(d1, 64)
    o2 = _SUITE.drbg_generate(d2, 64)
    o3 = _SUITE.drbg_generate(d3, 64)
    determinism = (o1 == o2)
    pers_separates = (o1 != o3)

    d4 = _SUITE.drbg_seed(b'entropy-241-aaaaaaaaaaaaaaaaaaaaaaaa', b'pers')
    _SUITE.drbg_generate(d4, 64)
    _SUITE.drbg_reseed(d4, b'fresh')
    reseed_separates = (_SUITE.drbg_generate(d4, 64) != _SUITE.drbg_generate(d2, 64))

    # The output limit must actually be enforced, not merely documented.
    d5 = _SUITE.drbg_seed(b'entropy-241-aaaaaaaaaaaaaaaaaaaaaaaa')
    d5.blocks = _SUITE.DRBG_MAX_BLOCKS - 1
    try:
        _SUITE.drbg_generate(d5, 64)      # 2 blocks, one over the limit
        limit_enforced = False
    except RuntimeError:
        limit_enforced = True

    print("  Behavioural properties, checked against the shipped code:")
    print(f"    deterministic in (entropy, personalization) : {determinism}")
    print(f"    personalization separates streams           : {pers_separates}")
    print(f"    reseed separates streams                    : {reseed_separates}")
    print(f"    DRBG_MAX_BLOCKS enforced, not advisory      : {limit_enforced}")

    print("""
  Measured against SP 800-90A, the gaps are the ones the suite's own comment
  already names as non-goals, and they are what keeps this out of any
  "validated DRBG" claim:

    * no health tests (SP 800-90A section 11) -- no instantiate-time or
      continuous self-test, so a stuck state is never detected;
    * no prediction-resistance request path -- a caller cannot demand fresh
      entropy per generate() the way the standard's interface allows;
    * no entropy-source assessment (SP 800-90B) -- `rand --seed` consumes
      whatever file it is handed at face value, with no minimum length check
      and no estimate of what it contains;
    * no reseed counter enforced against wall-clock or request count, only
      the output-block bound.

  What it IS, stated positively, is a deterministic expander for seed material
  that is already full-entropy, with forward secrecy from the fast-key-erasure
  ratchet (Bernstein 2017) resting on the same OWF conjecture as the #78.C
  ratchet.  Used that way -- `--seed` fed 32 bytes from a real entropy source,
  under the 2^20 block bound -- it is sound.  Used as a general-purpose RNG for
  a system that expects SP 800-90A semantics, it is not, because four of that
  standard's mechanisms are absent rather than weak.

  Forward secrecy carries one implementation caveat the suite states and this
  analysis confirms is unavoidable in Python: erasure of the old state cannot
  be guaranteed for immutable ints, so the Python port's backtracking
  resistance is best-effort.  The C port can and does erase.""")
    return determinism, pers_separates, reseed_separates, limit_enforced


# ═══════════════════════════════════════════════════════════════════════════
# §7 — verdicts
# ═══════════════════════════════════════════════════════════════════════════
def section7():
    rule("§7  Verdicts and the SECURITY.md rows")
    print("""TODO #241 predicted "at least one of the three to come out worse than
demo-only", and named `fpe` as the one to look at first.  That prediction is
correct, for a different reason than the one it gave: not an undocumented
tweak schedule, but a name that promises a primitive the code does not
implement, plus a shared subkey derivation that makes it indistinguishable
from `twk`.

  fpe   BROKEN AS NAMED.  It is not format-preserving encryption in the
        SP 800-38G sense -- no radix, no domain, 32 bytes in and 32 raw bytes
        out, short input zero-padded (§3).  It is additionally the same
        function as `twk` whenever the context is twelve bytes (§2).  As a
        deterministic 256-bit tweakable permutation it is HSKE-NL-A2 at one
        third the rounds (§5).  Do not use it to encrypt anything whose format
        must survive, and do not use it under a key shared with `twk`.

  twk   DEMO-ONLY.  The construction is coherent for its stated purpose --
        a per-(sector, block) tweaked wide-block permutation, which is the
        right shape for disk encryption, and determinism per tweak is the
        expected XTS-style property rather than a defect.  Three things keep
        it below production: the domain-separation collision with `fpe` (§2),
        the round count (§5), and the unencoded key boundary (§4b).  None of
        the three is a break; together they are more than a caveat.

  rand  DEMO-ONLY, and the closest of the three to sound.  The construction is
        a documented fast-key-erasure DRBG with a derived and reproducible
        output bound (§6), and its behavioural properties check out.  It is
        not an SP 800-90A DRBG and its own source says so; the four missing
        mechanisms are absent by design, not broken.  Effective state entropy
        is ~2^218.8 rather than 2^256.  Sound as a deterministic expander for
        full-entropy seeds under the 2^20 block bound; not a drop-in RNG.

None of the three is being removed -- TODO #241 puts that explicitly out of
scope, and they are shipped surface.  The deficiency the item was filed about
is that nobody could tell what they promised, and these rows are the answer.

The domain-separation collision (§2) is a live defect rather than merely an
unanalysed one, and fixing it changes what both subcommands produce -- a break
of the CLI surface 2.0.0 froze, and therefore its own item rather than a
silent edit inside an analysis one.  It is filed as TODO #242.""")


def main():
    print(SEP)
    print("rand / fpe / twk — the unclassified CLI surface (TODO #241)")
    print(SEP)

    i_value, r_value = section1()
    collides, inverts = section2()
    section3()
    amb, checks_key = section4()
    section5(i_value, r_value)
    drbg = section6()
    section7()

    print("\n" + SEP)
    print("Machine-readable summary of the checked claims")
    print(SEP)
    print(f"  fpe/twk subkey collision reachable      : {collides}")
    print(f"  twk_decrypt inverts fpe_encrypt         : {inverts}")
    print(f"  key||ctx boundary ambiguous             : {amb}")
    print(f"  derived subkey validity-checked         : {checks_key}")
    print(f"  drbg determinism / pers / reseed / cap  : {drbg}")
    print(SEP)

    # The analysis is only meaningful if the defects it describes are present.
    # If a future change fixes one, this script should fail loudly rather than
    # keep printing a stale finding.
    ok = collides and inverts and amb and not checks_key and all(drbg)
    if not ok:
        print("\n*** One or more findings no longer reproduce. The construction has")
        print("*** changed; re-derive §2-§4 and update SecurityProofs-7.md §11.24.")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
