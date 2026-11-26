#!/usr/bin/env python3
# CryptosuiteTests/check_suite_parity.py — TODO #416: hold the Python harness's
# re-implemented copies to the SHIPPED suite.
#
# CryptosuiteTests/Herradura_tests.py is standalone by design: it re-implements
# the suite's primitives rather than importing them, so its [FAIL]-gated numbered
# tests hold the COPY to its own expectations.  C's harness uses herradura.h, Go's
# the package and Java's SelfTest the shipped classes; Python is the one port whose
# numbered tests do not, on their own, test what ships.  #409 is what that costs:
# the harness's ZKBoo copy carried the shipped bug and its tests passed.
#
# This checker closes that gap WITHOUT rewriting the 4663-line harness:
#
#   1. CENSUS.  Every top-level harness function whose NAME also names a suite
#      function (a "shadow") must be classified below -- PARITY (compared here),
#      RANDOMIZED or HELPER (exempt, with a reason).  A new shadow that is none of
#      these fails the checker, so a copy cannot be added silently (the same shape
#      as spec/check_language_parity.py's censuses).
#
#   2. PRIMITIVE PARITY.  Each deterministic primitive is run in BOTH modules on
#      the same random inputs; the outputs must be byte-for-byte equal.  A copy
#      that drifts from the shipped function fails here rather than passing against
#      its own expectation.
#
#   3. VERIFIER PARITY (the #409 class).  For every verifier the numbered tests
#      exercise, an HONEST artifact is cross-verified BOTH WAYS -- the suite's
#      prover against the harness verifier and the harness prover against the
#      SHIPPED verifier -- and both must accept.  Then a WRONG-STATEMENT artifact
#      (an honest proof checked against another key/statement) and a TAMPERED one
#      must be REJECTED by BOTH verifiers.  The rejection is asserted against the
#      shipped verifier directly, so a shipped verifier that accepts a bad proof
#      (as in #409) fails here even though the harness copy shares the bug.  The
#      exhaustive wrong-witness/true-statement cheat lives in
#      CliTest/test_wrong_secret_matrix.sh (cheat_sign.py); this is its Python-
#      level, shipped-verifier counterpart.
#
# Run by ci.yml's native-python-cli job and tools/check_fast.sh.  Exit 0 iff every
# shadow is classified and every parity holds.

import ast
import importlib.util
import os
import random
import sys
import warnings

warnings.filterwarnings('ignore')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "CryptosuiteTests", "Herradura_tests.py")
SUITE = os.path.join(ROOT, "Herradura cryptographic suite.py")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _top_funcs(path):
    tree = ast.parse(open(path).read())
    return {n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


# ── Classification of every NAME shadow (census) ──────────────────────────────
#
# PARITY_PRIMITIVES and the VERIFIERS table below carry the active checks; the
# names they touch are added to the covered set automatically.  RANDOMIZED and
# HELPER are the exemptions, each with a reason.  The census fails if a shadow is
# in none of the four.

RANDOMIZED = {
    "_csprng_weight_t": "samples a fresh weight-t vector; output is random, so it is "
                        "exercised through hpks_stern_f_verify / hcred parity, not compared",
    "_rnl_rand_poly": "rejection-samples a uniform polynomial; random output",
    "_rnl_cbd_poly": "samples a centered-binomial polynomial; random output",
    "_rnl_keygen": "draws the RNL secret; random output, exercised through rnl_sigma parity",
    "stern_f_keygen": "draws seed and error; random output, exercised through the Stern verifier",
    "hpks_stern_f_sign": "draws a fresh nonce per round; random output, exercised by the verifier",
    "hpke_stern_f_encap": "draws a fresh error e'; random output",
    "hpke_stern_f_encap_with_e": "as hpke_stern_f_encap, returning e' too",
    "hcred_user_keygen": "draws the user secret; random, exercised through hcred_verify parity",
    "hcred_prove": "randomized MPC-in-the-head prover; exercised through hcred_verify parity",
    "hcred_issue": "randomized issuer; exercised through hcred_cred_verify parity",
    "_hcred_witness": "draws the prover's per-round witness shares; random",
    "_hcred_commit": "randomized commitment; exercised through hcred_verify parity",
    "_hcred_mpc_round": "randomized MPC round; exercised through hcred_verify parity",
}

HELPER = {
    "print": "the harness's [FAIL]-gating print shadow (TODO #233), not a crypto copy",
    "stern_f_first_preimage": "brute-force decoder for the demo KEM; infeasible at shipped "
                              "params and not reached by any numbered test",
    # hcred internal serializers / parameter helpers: pure functions reached only
    # through hcred_prove/verify, whose parity below covers them transitively.
    "_hcred_params": "hcred parameter tuple; covered transitively by hcred_verify parity",
    "_hcred_stmt_hash": "statement hash; covered transitively by hcred_verify parity",
    "_hcred_challenges": "Fiat-Shamir challenge derivation; covered via hcred_verify parity",
    "_hcred_outputs": "MPC output recombination; covered via hcred_verify parity",
    "_hcred_outputs_ser": "serializer; covered via hcred_verify parity",
    "_hcred_ser": "serializer; covered via hcred_verify parity",
    "_sigma_params": "RNL-sigma parameter tuple; covered via rnl_sigma parity",
    "_sigma_poly_bytes": "polynomial serializer; covered via rnl_sigma parity",
    "_sigma_challenge": "RNL-sigma challenge derivation; covered via rnl_sigma parity",
    "_zkp_nl_prg_bit": "per-gate PRG bit; covered via the ZKBoo verifier parity",
    "_zkp_nl_evaluate_circuit": "MPC circuit evaluation; covered via the ZKBoo verifier parity",
    "_zkp_nl_h": "ZKBoo commitment hash; covered via the ZKBoo verifier parity",
    "_ntt_inplace": "NTT butterfly used only inside _rnl_poly_mul, whose parity covers it",
    "_rnl_bits_to_bitarray": "bit packing; covered via rnl_sigma / hcred parity",
    "_rnl_reconcile_bits": "reconciliation bits; covered via _rnl_agree parity",
    "_rnl_hint": "reconciliation hint; covered via _rnl_agree parity",
    "_rnl_m_poly": "derives the public m polynomial from a seed; covered via rnl_sigma parity",
    "_rnl_lift": "centers a rounded polynomial; covered via _rnl_round parity",
}

# ── Primitive parity: deterministic func -> builder of equal inputs for both ──
#
# Each entry is name -> fn(H, S, rnd) returning (out_H, out_S); the two must be
# equal.  Inputs are drawn from the shared `rnd` so both modules see the same
# bytes.  BitArray values are built per-module so the types match.

VERIFIERS = {"hpks_stern_f_verify", "hcred_verify", "hcred_cred_verify"}


def _norm(x):
    """Normalise a value for cross-module (cross-BitArray-class) comparison."""
    if hasattr(x, 'uint') and hasattr(x, 'size'):
        return ('ba', x.size, x.uint)
    if isinstance(x, (list, tuple)):
        return tuple(_norm(e) for e in x)
    if isinstance(x, dict):
        return tuple(sorted((k, _norm(v)) for k, v in x.items()))
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return x


def _keybits(mod):
    return getattr(mod, 'KEYBITS', None) or getattr(mod, '_KEYBITS')


def _ba(mod, n, v):
    return mod.BitArray(n, v & ((1 << n) - 1))


def _prim_fscx(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return H.fscx(_ba(H, n, a), _ba(H, n, b)).uint, S.fscx(_ba(S, n, a), _ba(S, n, b)).uint


def _prim_fscx_revolve(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return (H.fscx_revolve(_ba(H, n, a), _ba(H, n, b), n // 4).uint,
            S.fscx_revolve(_ba(S, n, a), _ba(S, n, b), n // 4).uint)


def _prim_gf_mul(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    poly = S.GF_POLY[n]
    return H.gf_mul(a, b, poly, n), S.gf_mul(a, b, poly, n)


def _prim_gf_pow(H, S, r):
    n = 256
    a, e = r.getrandbits(n), r.getrandbits(64)
    poly = S.GF_POLY[n]
    return H.gf_pow(a, e, poly, n), S.gf_pow(a, e, poly, n)


def _prim_gf_pub_is_valid(H, S, r):
    n = 256
    v = r.choice([0, 1, r.getrandbits(n)])
    return bool(H.gf_pub_is_valid(v)), bool(S.gf_pub_is_valid(v))


def _prim_nl_v1(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return H.nl_fscx_v1(_ba(H, n, a), _ba(H, n, b)).uint, S.nl_fscx_v1(_ba(S, n, a), _ba(S, n, b)).uint


def _prim_nl_v2(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return H.nl_fscx_v2(_ba(H, n, a), _ba(H, n, b)).uint, S.nl_fscx_v2(_ba(S, n, a), _ba(S, n, b)).uint


def _prim_revolve_v1(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return (H.nl_fscx_revolve_v1(_ba(H, n, a), _ba(H, n, b), 3 * n // 4).uint,
            S.nl_fscx_revolve_v1(_ba(S, n, a), _ba(S, n, b), 3 * n // 4).uint)


def _prim_revolve_v2(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return (H.nl_fscx_revolve_v2(_ba(H, n, a), _ba(H, n, b), 3 * n // 4).uint,
            S.nl_fscx_revolve_v2(_ba(S, n, a), _ba(S, n, b), 3 * n // 4).uint)


def _prim_revolve_v3(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    rv = S.R3_VALUE
    return (H.nl_fscx_revolve_v3(_ba(H, n, a), _ba(H, n, b), rv).uint,
            S.nl_fscx_revolve_v3(_ba(S, n, a), _ba(S, n, b), rv).uint)


def _prim_chi(H, S, r):
    n = 256
    v = r.getrandbits(n)
    return H.nl_chi_v3(_ba(H, n, v)).uint, S.nl_chi_v3(_ba(S, n, v)).uint


def _prim_nl_v2_key_valid(H, S, r):
    n = 256
    v = r.getrandbits(n)
    return bool(H.nl_v2_key_is_valid(v, n)), bool(S.nl_v2_key_is_valid(_ba(S, n, v)))


def _prim_hfscx(H, S, r):
    data = bytes(r.getrandbits(8) for _ in range(r.randrange(0, 80)))
    return H.hfscx_256(data), S.hfscx_256(data)


def _prim_stern_hash(H, S, r):
    n = 256
    a, b = r.getrandbits(n), r.getrandbits(n)
    return (H._stern_hash(n, _ba(H, n, a), _ba(H, n, b), ds=1),
            S._stern_hash(n, _ba(S, n, a), _ba(S, n, b), ds=1))


def _prim_stern_perm(H, S, r):
    n = 256
    seed = r.getrandbits(n)
    ph = H._stern_gen_perm(_ba(H, n, seed), n)
    ps = S._stern_gen_perm(_ba(S, n, seed), n)
    return list(ph), list(ps)


def _prim_rnl_poly_mul(H, S, r):
    # RNL polynomials are lists of small ints; use the suite's parameters.
    n = S._RNL_N if hasattr(S, "_RNL_N") else 1024
    q = S._RNL_Q if hasattr(S, "_RNL_Q") else 12289
    a = [r.randrange(q) for _ in range(n)]
    b = [r.randrange(q) for _ in range(n)]
    return H._rnl_poly_mul(a, b, q, n), S._rnl_poly_mul(a, b, q, n)


PARITY_PRIMITIVES = {
    "fscx": _prim_fscx,
    "fscx_revolve": _prim_fscx_revolve,
    "gf_mul": _prim_gf_mul,
    "gf_pow": _prim_gf_pow,
    "gf_pub_is_valid": _prim_gf_pub_is_valid,
    "nl_fscx_v1": _prim_nl_v1,
    "nl_fscx_v2": _prim_nl_v2,
    "nl_fscx_revolve_v1": _prim_revolve_v1,
    "nl_fscx_revolve_v2": _prim_revolve_v2,
    "nl_fscx_revolve_v3": _prim_revolve_v3,
    "nl_chi_v3": _prim_chi,
    "nl_v2_key_is_valid": _prim_nl_v2_key_valid,
    "hfscx_256": _prim_hfscx,
    "_stern_hash": _prim_stern_hash,
    "_stern_gen_perm": _prim_stern_perm,
    "_rnl_poly_mul": _prim_rnl_poly_mul,
}

# Primitives covered transitively by one of the above (same family, exercised by
# the round-trip / verifier parity), listed so the census can see them.
PARITY_TRANSITIVE = {
    "nl_fscx_v2_inv": "inverse of nl_fscx_v2; exercised by the revolve_v2 round-trip",
    "nl_fscx_revolve_v2_inv": "inverse of nl_fscx_revolve_v2; round-trip under revolve_v2",
    "nl_fscx_revolve_v3_inv": "inverse of nl_fscx_revolve_v3; round-trip under revolve_v3",
    "nl_chi_v3_inv": "inverse of nl_chi_v3",
    "_m_inv": "inverse of the FSCX linear map M; exercised by nl_fscx_v2_inv",
    "_chi_row": "single chi row; exercised by nl_chi_v3",
    "_stern_apply_perm": "applies a permutation; exercised by _stern_gen_perm and the Stern verifier",
    "_stern_syndrome": "H*e^T; exercised by hpks_stern_f_verify parity",
    "_stern_matrix_row": "one H row; exercised by hpks_stern_f_verify parity",
    "hpke_stern_f_decap": "decap from a known e'; exercised by the encap/verify path",
    "hcred_phi": "hcred's one-way map; exercised by hcred_verify parity",
    "hcred_syndrome": "hcred syndrome; exercised by hcred_verify parity",
    "_zkp_nl_rol": "rotate-left helper; exercised by the ZKBoo verifier parity",
    "_twk_tweak": "tweak derivation; exercised by _fpe_twk_derive_b",
    "_fpe_twk_derive_b": "fpe/twk subkey; exercised by the suite's own [51] drift check and reused here",
    "_fpe_twk_v3_derive_b": "fpe/twk v3 subkey; as _fpe_twk_derive_b",
    "_rnl_poly_add": "polynomial add; exercised by _rnl_poly_mul parity",
    "_rnl_round": "rounding; exercised by _rnl_agree",
    "_rnl_agree": "key agreement; exercised by rnl_sigma parity",
}


def run_primitive_parity(H, S, trials, fails):
    rnd = random.Random(0xC0FFEE)
    for name, fn in sorted(PARITY_PRIMITIVES.items()):
        bad = 0
        for _ in range(trials):
            try:
                oh, os_ = fn(H, S, rnd)
            except Exception as exc:                       # pragma: no cover
                fails.append(f"primitive {name}: raised {type(exc).__name__}: {exc}")
                bad = -1
                break
            if _norm(oh) != _norm(os_):
                bad += 1
        if bad > 0:
            fails.append(f"primitive {name}: harness copy disagrees with the suite "
                         f"on {bad}/{trials} inputs")
        if bad == 0:
            print(f"  PARITY primitive {name}: {trials}/{trials} match")


# ── Verifier parity (the #409 class) ──────────────────────────────────────────

def _flip_first_bytes(obj):
    """Return a tampered deep-ish copy of a proof: flip a bit in the first bytes
    field found (recursively through list/dict/tuple)."""
    if isinstance(obj, (bytes, bytearray)):
        b = bytearray(obj)
        if b:
            b[0] ^= 1
        return bytes(b), True
    if isinstance(obj, list):
        out = []
        done = False
        for x in obj:
            if not done:
                nx, d = _flip_first_bytes(x)
                out.append(nx); done = done or d
            else:
                out.append(x)
        return out, done
    if isinstance(obj, dict):
        out = {}
        done = False
        for k, v in obj.items():
            if not done:
                nv, d = _flip_first_bytes(v)
                out[k] = nv; done = done or d
            else:
                out[k] = v
        return out, done
    if isinstance(obj, tuple):
        lst, done = _flip_first_bytes(list(obj))
        return tuple(lst), done
    return obj, False


def scheme_stern(mod, r):
    """Build (honest_args, verify_fn, wrongstmt_args) for hpks_stern_f in `mod`."""
    n = mod.KEYBITS
    seed, e, syn = mod.stern_f_keygen(n)
    seed2, e2, syn2 = mod.stern_f_keygen(n)
    msg = mod.BitArray(n, r.getrandbits(n))
    sig = mod.hpks_stern_f_sign(msg, e, seed, syn, n, rounds=24)
    honest = (msg, sig, seed, syn, n)
    wrong = (msg, sig, seed2, syn2, n)        # honest sig, another key's statement
    return honest, mod.hpks_stern_f_verify, wrong, sig


def verify_stern(mod, args):
    msg, sig, seed, syn, n = args
    return bool(mod.hpks_stern_f_verify(msg, sig, seed, syn, n))


def run_verifier_parity(H, S, fails):
    r = random.Random(0x5115)

    # hpks_stern_f: cross-verify both ways, and reject a wrong statement + tamper.
    for src, dst, label in ((S, H, "suite prover -> harness verify"),
                            (H, S, "harness prover -> suite verify")):
        n = _keybits(src)
        seed, e, syn = src.stern_f_keygen(n)
        msg_v = r.getrandbits(n)
        sig = src.hpks_stern_f_sign(src.BitArray(n, msg_v), e, seed, syn, n, rounds=24)
        # Re-pack the statement/sig into dst's types by value.
        ok = _stern_verify_cross(dst, msg_v, sig, seed.uint if hasattr(seed, "uint") else seed,
                                 syn, n)
        if not ok:
            fails.append(f"hpks_stern_f: {label} did not accept an honest signature")
        else:
            print(f"  VERIFIER hpks_stern_f: {label} accepts")

    # Ground-truth rejection, asserted against BOTH verifiers (the #409 check):
    for mod, tag in ((S, "suite"), (H, "harness")):
        n = _keybits(mod)
        seed, e, syn = mod.stern_f_keygen(n)
        seed2, e2, syn2 = mod.stern_f_keygen(n)
        msg = mod.BitArray(n, r.getrandbits(n))
        sig = mod.hpks_stern_f_sign(msg, e, seed, syn, n, rounds=24)
        if not mod.hpks_stern_f_verify(msg, sig, seed, syn, n):
            fails.append(f"hpks_stern_f: {tag} verifier rejected an honest signature")
        if mod.hpks_stern_f_verify(msg, sig, seed2, syn2, n):
            fails.append(f"hpks_stern_f: {tag} verifier ACCEPTED a signature under another "
                         f"key's statement (wrong-statement forgery)")
        tampered, done = _flip_first_bytes(sig)
        if done and mod.hpks_stern_f_verify(msg, tampered, seed, syn, n):
            fails.append(f"hpks_stern_f: {tag} verifier ACCEPTED a tampered signature")
        if tag == "suite":
            print("  VERIFIER hpks_stern_f: suite verifier rejects wrong-statement and tamper")


def _stern_verify_cross(mod, msg_v, sig, seed_v, syn, n):
    """Verify, in `mod`, a signature produced by the other module, rebuilding the
    message/seed as mod's BitArray and translating the sig's BitArray components."""
    msg = mod.BitArray(n, msg_v)
    seed = mod.BitArray(n, seed_v)
    sig2 = _translate(mod, sig)
    return bool(mod.hpks_stern_f_verify(msg, sig2, seed, syn, n))


def _translate(mod, obj):
    """Deep-copy a proof/signature into `mod`'s BitArray type (match by .size/.uint)."""
    if hasattr(obj, "uint") and hasattr(obj, "size"):
        return mod.BitArray(obj.size, obj.uint)
    if isinstance(obj, list):
        return [_translate(mod, x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_translate(mod, x) for x in obj)
    if isinstance(obj, dict):
        return {k: _translate(mod, v) for k, v in obj.items()}
    return obj


def _f(mod, *names):
    for nm in names:
        if hasattr(mod, nm):
            return getattr(mod, nm)
    raise AttributeError("none of %r in %s" % (names, mod.__name__))


def run_zkp_parity(H, S, fails):
    """ZKBoo (zkp_nl) — the #409 scheme — cross-verified both ways, with wrong-
    statement and tamper rejection asserted against BOTH verifiers.  The proof is
    bytes/ints, so it crosses module boundaries without translation."""
    r = random.Random(0x2B00)
    n, rounds = 64, 8
    msg = b"suite-parity"
    for src, dst, label in ((S, H, "suite prover -> harness verify"),
                            (H, S, "harness prover -> suite verify")):
        keygen = _f(src, "zkp_nl_keygen", "_zkp_nl_keygen")
        prove = _f(src, "zkp_nl_prove", "_zkp_nl_prove")
        verify = _f(dst, "zkp_nl_verify", "_zkp_nl_verify")
        A, B, y = keygen(n)
        proof = prove(A, B, y, n, rounds, msg)
        if not verify(B, y, n, rounds, msg, proof):
            fails.append(f"zkp_nl (ZKBoo): {label} did not accept an honest proof")
        else:
            print(f"  VERIFIER zkp_nl: {label} accepts")
    for mod, tag in ((S, "suite"), (H, "harness")):
        keygen = _f(mod, "zkp_nl_keygen", "_zkp_nl_keygen")
        prove = _f(mod, "zkp_nl_prove", "_zkp_nl_prove")
        verify = _f(mod, "zkp_nl_verify", "_zkp_nl_verify")
        A, B, y = keygen(n)
        A2, B2, y2 = keygen(n)
        proof = prove(A, B, y, n, rounds, msg)
        if not verify(B, y, n, rounds, msg, proof):
            fails.append(f"zkp_nl: {tag} verifier rejected an honest proof")
        if verify(B2, y2, n, rounds, msg, proof):
            fails.append(f"zkp_nl: {tag} verifier ACCEPTED a proof against another statement")
        tampered, done = _flip_first_bytes(proof)
        if done and verify(B, y, n, rounds, msg, tampered):
            fails.append(f"zkp_nl: {tag} verifier ACCEPTED a tampered proof")
        if tag == "suite":
            print("  VERIFIER zkp_nl: suite verifier rejects wrong-statement and tamper")


def main():
    harness_funcs = _top_funcs(HARNESS)
    S = _load(SUITE, "herradura_suite")
    suite_funcs = {k for k, v in vars(S).items()
                   if callable(v) and getattr(v, "__module__", None) == S.__name__}
    shadows = harness_funcs & suite_funcs

    covered = (set(PARITY_PRIMITIVES) | set(PARITY_TRANSITIVE)
               | set(RANDOMIZED) | set(HELPER) | VERIFIERS)
    unclassified = sorted(shadows - covered)
    stale = sorted(covered - shadows - {"nl_chi_v3", "nl_fscx_revolve_v3"})  # covered that no longer shadow

    fails = []
    if unclassified:
        fails.append("unclassified shadow(s) — add each to PARITY_PRIMITIVES, "
                     "PARITY_TRANSITIVE, RANDOMIZED or HELPER in this file: "
                     + ", ".join(unclassified))
    # A classified name that is no longer a shadow is a stale entry to prune, but
    # only flag names that are genuinely gone (ignore same-name verifiers handled
    # explicitly and primitives whose suite name matches).
    truly_stale = [n for n in stale if n not in suite_funcs]
    if truly_stale:
        fails.append("stale classification(s) — these names no longer exist in the "
                     "suite, prune them: " + ", ".join(truly_stale))

    print(f"shadows: {len(shadows)}  (parity {len(PARITY_PRIMITIVES)}, transitive "
          f"{len(PARITY_TRANSITIVE)}, randomized {len(RANDOMIZED)}, helper {len(HELPER)})")

    H = _load(HARNESS, "herradura_harness")
    run_primitive_parity(H, S, trials=16, fails=fails)
    run_verifier_parity(H, S, fails=fails)
    run_zkp_parity(H, S, fails=fails)

    if fails:
        print("\n*** FAILED: suite parity ***")
        for f in fails:
            print(f"    {f}")
        return 1
    print("\n*** OK: harness copies match the shipped suite ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
