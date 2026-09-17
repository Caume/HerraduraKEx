#!/usr/bin/env python3
"""TODO #190: generate fixed Known-Answer-Test vectors for the classical
(v1.4.0) HerraduraKEx quartet — HKEX-GF, HSKE, HPKS, HPKE — at n=256 bits,
in a style similar to NIST CAVP .rsp files: fixed inputs, deterministic
outputs, checked into the repo so a third-party reimplementation can
cross-validate against this suite's reference (Python) output without
depending on this repo's own test harness.

All inputs below are arbitrary fixed constants (not secrets) chosen only to
exercise the math; nobody should use them as real keys. Re-running this
script must reproduce KAT/classical_quartet.json byte-for-byte — there is
no randomness anywhere in this file.

Usage:
    python3 KAT/generate_kat.py            # regenerate KAT/classical_quartet.json
    python3 KAT/generate_kat.py --check     # regenerate to a temp file and diff
"""
import contextlib
import importlib.util
import json
import os
import sys
import warnings

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SUITE_PATH = os.path.join(_ROOT, "Herradura cryptographic suite.py")
_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "classical_quartet.json")

spec = importlib.util.spec_from_file_location("herradura_suite", _SUITE_PATH)
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)

BitArray = suite.BitArray
fscx_revolve = suite.fscx_revolve
gf_pow = suite.gf_pow
gf_mul = suite.gf_mul
GF_POLY = suite.GF_POLY
GF_GEN = suite.GF_GEN

# HKEX-RNL (TODO #226).  RNLN is the ring dimension (1024 since TODO #223) and is
# deliberately distinct from KEYBITS, the derived session-key width.
hfscx_256 = suite.hfscx_256
nl_fscx_revolve_v1 = suite.nl_fscx_revolve_v1
RNLN, RNLQ, RNLP, RNLPP, RNLB = suite.RNLN, suite.RNLQ, suite.RNLP, suite.RNLPP, suite.RNLB
KEYBITS = suite.KEYBITS
_RNL_KDF_DC_256 = suite._RNL_KDF_DC_256
_RNL_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hkex_rnl.json")

# NL-FSCX v3 and its five consumers (TODO #255).  Pins the primitive AND every
# construction built on it, because the family's ports are byte-identical by
# design and nothing else in KAT/ covers the NL side of the suite.
_V3_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nl_fscx_v3.json")
nl_chi_v3 = suite.nl_chi_v3
nl_fscx_v3 = suite.nl_fscx_v3
nl_fscx_revolve_v3 = suite.nl_fscx_revolve_v3
nl_fscx_revolve_v3_inv = suite.nl_fscx_revolve_v3_inv
hske_nl_v3_duplex_encrypt = suite.hske_nl_v3_duplex_encrypt
fpe_v3_encrypt = suite.fpe_v3_encrypt
twk_v3_encrypt = suite.twk_v3_encrypt
R3_VALUE, I3_VALUE = suite.R3_VALUE, suite.I3_VALUE

N = 256
POLY = GF_POLY[N]
I_STEPS = N // 4        # 64
R_STEPS = 3 * N // 4     # 192


def h(x: int) -> str:
    return f"{x:0{N // 4}x}"


def gen_hkex_gf() -> dict:
    """HKEX-GF: C = g^a; C2 = g^b; sk = C2^a = C^b = g^{ab}."""
    a = 0x1A2B3C4D5E6F708192A3B4C5D6E7F809_1A2B3C4D5E6F708192A3B4C5D6E7F809 & ((1 << N) - 1)
    b = 0x0FEDCBA9876543210FEDCBA987654321_0FEDCBA9876543210FEDCBA987654321 & ((1 << N) - 1)
    C = gf_pow(GF_GEN, a, POLY, N)
    C2 = gf_pow(GF_GEN, b, POLY, N)
    sk_alice = gf_pow(C2, a, POLY, N)
    sk_bob = gf_pow(C, b, POLY, N)
    assert sk_alice == sk_bob
    return {
        "description": "HKEX-GF Diffie-Hellman key agreement over GF(2^256)*",
        "n": N, "poly": h(POLY), "g": GF_GEN,
        "alice_priv": h(a), "bob_priv": h(b),
        "alice_pub": h(C), "bob_pub": h(C2),
        "shared_secret": h(sk_alice),
    }


def gen_hske() -> dict:
    """HSKE: E = fscx_revolve(P, key, i); D = fscx_revolve(E, key, r) == P."""
    key = BitArray(N, 0xCAFEBABEDEADBEEF0123456789ABCDEF_CAFEBABEDEADBEEF0123456789ABCDEF & ((1 << N) - 1))
    pt = BitArray(N, int.from_bytes(b"HerraduraKEx TODO #190 KAT test", "big"))
    ct = fscx_revolve(pt, key, I_STEPS)
    recovered = fscx_revolve(ct, key, R_STEPS)
    assert recovered.uint == pt.uint
    return {
        "description": "HSKE symmetric encryption via fscx_revolve",
        "n": N, "i_steps": I_STEPS, "r_steps": R_STEPS,
        "key": h(key.uint), "plaintext": h(pt.uint), "ciphertext": h(ct.uint),
    }


def gen_hpks() -> dict:
    """HPKS: R = g^k; e = fscx_revolve(R, msg, i); s = (k - a*e) mod (2^n - 1);
    verify: g^s * C^e == R."""
    a = 0x777788889999AAAABBBBCCCCDDDDEEEE_777788889999AAAABBBBCCCCDDDDEEEE & ((1 << N) - 1)
    k = 0x1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF & ((1 << N) - 1)
    msg = BitArray(N, int.from_bytes(b"HerraduraKEx TODO #190 HPKS msg", "big"))
    C = gf_pow(GF_GEN, a, POLY, N)
    R = BitArray(N, gf_pow(GF_GEN, k, POLY, N))
    e = fscx_revolve(R, msg, I_STEPS).uint
    order = (1 << N) - 1
    s = (k - a * e) % order
    ok = suite.hpks_verify(msg, C, R, s, POLY, N)
    assert ok
    return {
        "description": "HPKS Schnorr signature over GF(2^256)*",
        "n": N, "priv": h(a), "pub": h(C),
        "ephemeral_k": h(k), "message": h(msg.uint),
        "R": h(R.uint), "s": h(s), "verifies": True,
    }


def gen_hpke() -> dict:
    """HPKE: enc_key = C^r; E = fscx_revolve(P, enc_key, i);
    dec_key = R^a; D = fscx_revolve(E, dec_key, r) == P."""
    a = 0x2468ACE02468ACE02468ACE02468ACE0_2468ACE02468ACE02468ACE02468ACE0 & ((1 << N) - 1)
    r = 0x13579BDF13579BDF13579BDF13579BDF_13579BDF13579BDF13579BDF13579BDF & ((1 << N) - 1)
    pt = BitArray(N, int.from_bytes(b"HerraduraKEx TODO #190 HPKE msg", "big"))
    C = gf_pow(GF_GEN, a, POLY, N)
    R = gf_pow(GF_GEN, r, POLY, N)
    enc_key = gf_pow(C, r, POLY, N)
    ct = fscx_revolve(pt, BitArray(N, enc_key), I_STEPS)
    dec_key = gf_pow(R, a, POLY, N)
    recovered = fscx_revolve(ct, BitArray(N, dec_key), R_STEPS)
    assert recovered.uint == pt.uint
    return {
        "description": "HPKE El Gamal + fscx_revolve hybrid encryption over GF(2^256)*",
        "n": N, "recipient_priv": h(a), "recipient_pub": h(C),
        "ephemeral_r": h(r), "R": h(R), "plaintext": h(pt.uint),
        "ciphertext": h(ct.uint),
    }


# ---------------------------------------------------------------------------
# HKEX-RNL (TODO #226)
#
# The deployed samplers draw from os.urandom, so the secrets here are produced by
# a deterministic expansion instead: a KAT fixes the randomness as an *input* and
# tests the deterministic parts — ring arithmetic, rounding, reconciliation and
# the KDF.  The expansion mirrors each sampler's bit layout exactly so a
# reimplementation can follow `_rnl_cbd_poly` / `_rnl_rand_poly` in the suite and
# get the same polynomials from the same label.
# ---------------------------------------------------------------------------

def det_bytes(label: bytes, nbytes: int) -> bytes:
    """HFSCX-256 in counter mode: the reproducible stand-in for os.urandom."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hfscx_256(label + ctr.to_bytes(4, "big"))
        ctr += 1
    return bytes(out[:nbytes])


def det_cbd_poly(label: bytes, n: int, eta: int, q: int) -> list:
    """CBD(eta) from a fixed label.  Mirrors `_rnl_cbd_poly`'s eta=1 bit layout:
    4 coefficients per byte, bit pairs (0,1) (2,3) (4,5) (6,7), coeff = a - b."""
    assert eta == 1, "KAT vectors are generated at the deployed eta = 1"
    raw = det_bytes(label, (n + 3) // 4)
    out = []
    for i in range(n):
        shift = (i & 3) * 2
        a = (raw[i >> 2] >> shift) & 1
        b = (raw[i >> 2] >> (shift + 1)) & 1
        out.append((a - b) % q)
    return out


def det_rand_poly(label: bytes, n: int, q: int) -> list:
    """Uniform in Z_q^n from a fixed label.  Mirrors `_rnl_rand_poly`'s 3-byte
    rejection sampling, so the rejection threshold is part of the vector."""
    threshold = (1 << 24) - (1 << 24) % q
    out = []
    stream = det_bytes(label, 8 * n + 64)
    pos = 0
    while len(out) < n:
        if pos + 3 > len(stream):
            stream += det_bytes(label + b"-ext" + pos.to_bytes(4, "big"), 4 * n)
        v = int.from_bytes(stream[pos:pos + 3], "big")
        pos += 3
        if v < threshold:
            out.append(v % q)
    return out


def poly_hex(coeffs: list, bytes_per_coeff: int) -> str:
    """Big-endian, fixed width per coefficient — the same packing the PEM codec
    uses (`pack_poly`), so a vector can be compared against wire bytes directly."""
    return "".join(f"{c:0{bytes_per_coeff * 2}x}" for c in coeffs)


def hint_hex(hint: list, used: int) -> str:
    """The transmitted hint: `used` two-bit values, 4 per byte, LSB-first within
    each byte — matching C's rnl_hint packing and Python's hint[:n//2] slice."""
    raw = bytearray((used + 3) // 4)
    for i in range(used):
        raw[i >> 2] |= (hint[i] & 3) << ((i & 3) * 2)
    return raw.hex()


def rnl_kdf(k_raw: 'BitArray') -> str:
    """Suite-level HKEX-RNL session KDF:
    sk = NL-FSCX-v1(ROL(K_raw, KEYBITS/8) XOR _RNL_KDF_DC_256, K_raw, KEYBITS/4)."""
    sk = nl_fscx_revolve_v1(
        BitArray(KEYBITS, k_raw.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
        k_raw, KEYBITS // 4)
    return f"{sk.uint:0{KEYBITS // 4}x}"


def gen_hkex_rnl(n: int, tag: str) -> dict:
    """One full two-party HKEX-RNL handshake at ring dimension n.

    `key_bits` is the RAW reconciliation width — how many bits an n-coefficient
    ring can yield — matching the CLI's `_rnl_key_bits`.  It is not the width of
    a derived session key; that is always 256 (TODO #228), which is why the
    suite-level `session_key` below is only defined when the two coincide.
    """
    key_bits = KEYBITS if n >= KEYBITS else n
    m_base = suite._rnl_m_poly(n)
    a_rand = det_rand_poly(b"HerraduraKEx-TODO226-a_rand-" + tag.encode(), n, RNLQ)
    m_blind = suite._rnl_poly_add(m_base, a_rand, RNLQ)

    s_a = det_cbd_poly(b"HerraduraKEx-TODO226-alice-s-" + tag.encode(), n, RNLB, RNLQ)
    s_b = det_cbd_poly(b"HerraduraKEx-TODO226-bob-s-" + tag.encode(), n, RNLB, RNLQ)
    c_a = suite._rnl_round(suite._rnl_poly_mul(m_blind, s_a, RNLQ, n), RNLQ, RNLP)
    c_b = suite._rnl_round(suite._rnl_poly_mul(m_blind, s_b, RNLQ, n), RNLQ, RNLP)

    # Bob reconciles and publishes the hint; Alice consumes it.
    k_bob, hint = suite._rnl_agree(s_b, c_a, RNLQ, RNLP, RNLPP, n, key_bits)
    k_alice = suite._rnl_agree(s_a, c_b, RNLQ, RNLP, RNLPP, n, key_bits, hint)
    assert k_alice.uint == k_bob.uint, f"HKEX-RNL KAT: reconciliation disagreed at n={n}"

    used = n // 2
    return {
        "description": f"HKEX-RNL Ring-LWR key agreement at ring dimension {n}",
        "n": n, "q": RNLQ, "p": RNLP, "pp": RNLPP, "eta": RNLB,
        "key_bits": key_bits,
        "hint_coefficients": used,
        "m_blind": poly_hex(m_blind, 4),
        "alice_s": poly_hex(s_a, 4), "alice_C": poly_hex(c_a, 2),
        "bob_s": poly_hex(s_b, 4), "bob_C": poly_hex(c_b, 2),
        "hint": hint_hex(hint, used),
        "k_raw": f"{k_alice.uint:0{key_bits // 4}x}",
        "session_key": rnl_kdf(k_alice) if key_bits == KEYBITS else None,
    }


def generate_rnl() -> dict:
    return {
        "$schema": "HerraduraKEx HKEX-RNL KAT vectors (TODO #226)",
        "suite_reference": "Herradura cryptographic suite.py",
        "note": ("Ring dimension and raw reconciliation width are separate "
                 "quantities (TODO #223): the deployed ring is 1024 while "
                 "reconciliation extracts 256 bits.  The n=64 set exercises the "
                 "small-ring path, where they coincide and k_raw is n bits.  "
                 "key_bits here is that RAW width, not the width of a derived "
                 "session key: the CLI's contributory KDF returns an HFSCX-256 "
                 "digest and so derives 256 bits at either ring (TODO #228)."),
        "deployed": gen_hkex_rnl(RNLN, "n1024"),
        "small_ring": gen_hkex_rnl(64, "n64"),
    }


# ── NL-FSCX v3 (TODO #255) ──────────────────────────────────────────────────

# Fixed non-secret constants, chosen only to exercise the math.
_V3_KEY = 0xCAFEBABEDEADBEEF0123456789ABCDEF_CAFEBABEDEADBEEF0123456789ABCDEF
_V3_PT  = 0x004E4C2D46534358207633204B41542D_544F444F2032353520766563746F72
_V3_NONCE = 0x0102030405060708090A0B0C0D0E0F10_1112131415161718191A1B1C1D1E1F20
_V3_HPKE_PRIV = 0x33445566778899AABBCCDDEEFF001122_33445566778899AABBCCDDEEFF001122
_V3_HPKE_R    = 0x0BADC0FFEE0DDF00D0BADC0FFEE0DDF0_0BADC0FFEE0DDF00D0BADC0FFEE0DDF0


def gen_nl_fscx_v3() -> dict:
    """The v3 primitive itself: the chi layer, one round, and the full revolve."""
    key = BitArray(N, _V3_KEY & ((1 << N) - 1))
    pt  = BitArray(N, _V3_PT  & ((1 << N) - 1))
    ct  = nl_fscx_revolve_v3(pt, key, R3_VALUE)
    assert nl_fscx_revolve_v3_inv(ct, key, R3_VALUE).uint == pt.uint
    return {
        "description": "NL-FSCX v3 primitive: chi layer, one round, and the "
                       "R3_VALUE-round revolve with its inverse",
        "n": N,
        "rows": list(suite.v3_rows(N)),
        "r3_steps": R3_VALUE,
        "i3_steps": I3_VALUE,
        "key": h(key.uint),
        "plaintext": h(pt.uint),
        "chi_of_plaintext": h(nl_chi_v3(pt).uint),
        "one_round": h(nl_fscx_v3(pt, key).uint),
        "revolve": h(ct.uint),
    }


def gen_hske_nla3() -> dict:
    key = BitArray(N, _V3_KEY & ((1 << N) - 1))
    pt  = BitArray(N, _V3_PT  & ((1 << N) - 1))
    return {
        "description": "HSKE-NL-A3: E = nl_fscx_revolve_v3(P, K, R3_VALUE).  No "
                       "key check — v3 has no weak class (SecurityProofs-8.md 11.34.4)",
        "n": N, "r3_steps": R3_VALUE,
        "key": h(key.uint), "plaintext": h(pt.uint),
        "ciphertext": h(nl_fscx_revolve_v3(pt, key, R3_VALUE).uint),
    }


def gen_hpke_nl3() -> dict:
    priv = _V3_HPKE_PRIV & ((1 << N) - 1)
    r    = _V3_HPKE_R    & ((1 << N) - 1)
    pub  = gf_pow(GF_GEN, priv, POLY, N)
    R    = gf_pow(GF_GEN, r, POLY, N)
    enc_key = BitArray(N, gf_pow(pub, r, POLY, N))
    dec_key = BitArray(N, gf_pow(R, priv, POLY, N))
    assert enc_key.uint == dec_key.uint
    pt = BitArray(N, _V3_PT & ((1 << N) - 1))
    ct = nl_fscx_revolve_v3(pt, enc_key, R3_VALUE)
    assert nl_fscx_revolve_v3_inv(ct, dec_key, R3_VALUE).uint == pt.uint
    return {
        "description": "HPKE-NL3: El Gamal over GF(2^256)* with the v3 round.  The "
                       "ephemeral scalar is fixed here; the CLI draws it at random "
                       "and, unlike hpke-nl, never resamples",
        "n": N, "r3_steps": R3_VALUE,
        "priv": h(priv), "pub": h(pub), "ephemeral_r": h(r), "R": h(R),
        "enc_key": h(enc_key.uint),
        "plaintext": h(pt.uint), "ciphertext": h(ct.uint),
    }


def gen_hske_duplex3() -> dict:
    key   = BitArray(N, _V3_KEY & ((1 << N) - 1))
    nonce = BitArray(N, _V3_NONCE & ((1 << N) - 1))
    pt = b"HerraduraKEx TODO #255 duplex-v3 KAT vector"
    ad = b"nl-v3-duplex-associated-data"
    _, ct, tag = hske_nl_v3_duplex_encrypt(key, pt, ad, nonce=nonce)
    return {
        "description": "HSKE-NL-V3-Duplex AEAD at I3_VALUE = 5n/16 sponge rounds, "
                       "rate 16 bytes.  Ciphertext format tag 4 on the wire",
        "n": N, "i3_steps": I3_VALUE, "rate_bytes": 16,
        "key": h(key.uint), "nonce": h(nonce.uint),
        "ad": ad.hex(), "plaintext": pt.hex(),
        "ciphertext": ct.hex(), "tag": tag.hex(),
    }


def gen_fpe_twk_v3() -> dict:
    key = (_V3_KEY & ((1 << N) - 1)).to_bytes(N // 8, "big")
    pt  = BitArray(N, _V3_PT & ((1 << N) - 1))
    ctx = b"herradura-v3-kat-context"
    sector, bidx = 0x0123456789ABCDEF, 0x00C0FFEE
    return {
        "description": "fpe --v3 and twk --v3: subkey = HFSCX-256-DS(0x22 / 0x23, "
                       "len(key)_be8 || key || tweak), single hash, NO rejection loop",
        "n": N, "r3_steps": R3_VALUE,
        "key": h(int.from_bytes(key, "big")),
        "plaintext": h(pt.uint),
        "fpe_context": ctx.hex(),
        "fpe_ciphertext": h(fpe_v3_encrypt(pt, key, ctx).uint),
        # Hex strings, not JSON numbers: a 64-bit sector does not survive a
        # round trip through the float64 every JSON parser defaults to, and the
        # loss is silent (0x0123456789ABCDEF reads back off by 1).
        "twk_sector": f"{sector:016x}", "twk_bidx": f"{bidx:08x}",
        "twk_ciphertext": h(twk_v3_encrypt(pt, key, sector, bidx).uint),
    }


def generate_v3() -> dict:
    return {
        "$schema": "HerraduraKEx NL-FSCX v3 KAT vectors (TODO #255)",
        "suite_reference": "Herradura cryptographic suite.py",
        "note": ("R3_VALUE = 5n/8 = 160 is DERIVED, not inherited from v2's 3n/4, "
                 "and I3_VALUE = 5n/16 = 80 is the duplex sponge count, likewise "
                 "derived (SecurityProofs-8.md 11.34.8).  The chi row partition is "
                 "47 fives then 3 sevens: every row odd and >= 5, which is a hard "
                 "constraint and not a preference -- a 3-bit row is a complete "
                 "break at any round count (11.34.2)."),
        "nl_fscx_v3": gen_nl_fscx_v3(),
        "hske_nla3": gen_hske_nla3(),
        "hpke_nl3": gen_hpke_nl3(),
        "hske_duplex3": gen_hske_duplex3(),
        "fpe_twk_v3": gen_fpe_twk_v3(),
    }


def generate() -> dict:
    return {
        "$schema": "HerraduraKEx classical-quartet KAT vectors (TODO #190)",
        "suite_reference": "Herradura cryptographic suite.py",
        "hkex_gf": gen_hkex_gf(),
        "hske": gen_hske(),
        "hpks": gen_hpks(),
        "hpke": gen_hpke(),
    }


# ── HCRED-KKW (TODO #266) ───────────────────────────────────────────────────
#
# This file is PINNED, not regenerated, and that is a deliberate difference from
# the other three.  hcred_prove_kkw draws one os.urandom(32) root per emulation,
# so a proof is not a function of its statement and "regenerate and diff" cannot
# work here.  TODO #266 settles the shape: this is a VERIFY-SIDE vector.  One
# reference transcript is captured once, checked in, and every language must
# CONSUME it and accept -- the same discipline KAT/pem/ uses, and the one that
# would have caught all three bugs the C/Go ports actually had (an inverted
# aux-reveal condition, an under-allocated commitment buffer and a flipped bit
# convention are all READER disagreements about a byte layout).
#
#   python3 KAT/generate_kat.py --capture-kkw   # re-capture a fresh transcript
#   python3 KAT/generate_kat.py --check         # verify the checked-in one
#
# --check does not diff bytes here; it runs hcred_verify_kkw over the pinned
# transcript and asserts True, then applies each tamper case and asserts False.
# That is strictly stronger than a diff: a byte-identical file whose verifier
# has drifted still fails.
_KKW_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "hcred_kkw.json")

hcred_prove_kkw = suite.hcred_prove_kkw
hcred_verify_kkw = suite.hcred_verify_kkw
_hcred_ser = suite._hcred_ser
RNLQ_ = suite.RNLQ

# Demo parameters.  Production KKW is (N, M, tau) = (64, 343, 27) for 2^-128;
# a vector at those parameters would be ~0.9 MB and minutes to verify, so the
# vector is demo-sized and records the production triple as metadata.
_KKW_N_PAR, _KKW_M, _KKW_TAU = 4, 8, 4
_KKW_MSG = b"HCRED-KKW KAT vector (TODO #266)"

# TWO SETS, and the reason is a four-language finding rather than a convenience
# (TODO #266).  HCRED's bit width is a RUNTIME argument in Python and Go, whose
# demos both use n = 32, but a COMPILE-TIME constant fixed at 256 in C
# (herradura.h's HCRED_N) and in Java (Hcred.N = Herradura.N).  So the four
# implementations have never proved the same statement size, and two of them
# cannot run the size the other two demo at.  A vector every language can
# consume must therefore be at n = 256; the n = 32 set is kept because it is
# cheap enough to tamper-check exhaustively in the Python reference.
#
# Cost is why the two sets are checked differently.  One n = 256 verification is
# ~70 s in Python, so a full accept-plus-six-rejections pass would add ~8 min to
# CI's slowest job.  The split: Python checks n32 exhaustively and n256 for
# ACCEPT only, while the compiled consumers (Go, C, Java) run the full tamper
# matrix on n256 in well under a second.  Nothing is unchecked -- the expensive
# matrix simply runs where it is cheap.
_KKW_SETS = (("n256", 256), ("n32", 32))


def _vec_hex(vec) -> str:
    """Z_q vector as hex of the protocol's own 3-bytes-per-coefficient wire
    encoding (_hcred_ser).  Not JSON numbers: KAT/nl_fscx_v3.json records why
    -- a wide value does not survive the float64 a JSON parser defaults to, and
    the loss is silent."""
    return _hcred_ser(vec).hex()


def _vec_unhex(s: str) -> list:
    b = bytes.fromhex(s)
    return [int.from_bytes(b[i:i + 3], "big") for i in range(0, len(b), 3)]


def _kkw_proof_to_json(p: dict) -> dict:
    return {
        "W": p["W"],
        "params": list(p["params"]),
        "pre": {str(e): root.hex() for e, root in sorted(p["pre"].items())},
        "online": {str(e): {
            "pbar": od["pbar"],
            "path": [[lvl, idx, node.hex()] for (lvl, idx), node in od["path"]],
            "com_h": od["com_h"].hex(),
            # aux is a Z_q VECTOR, not a byte string: it is the correction the
            # last party carries, revealed only when that party is not the
            # hidden one.  Getting this wrong is what the Go port's inverted
            # reveal condition did.
            "aux": None if od["aux"] is None else _vec_hex(od["aux"]),
            "zin": _vec_hex(od["zin"]),
            "t": _vec_hex(od["t"]),
            "u": od["u"],
        } for e, od in sorted(p["online"].items())},
    }


def _kkw_proof_from_json(j: dict) -> dict:
    return {
        "W": j["W"],
        "params": tuple(j["params"]),
        "pre": {int(e): bytes.fromhex(r) for e, r in j["pre"].items()},
        "online": {int(e): {
            "pbar": od["pbar"],
            "path": [((lvl, idx), bytes.fromhex(node))
                     for lvl, idx, node in od["path"]],
            "com_h": bytes.fromhex(od["com_h"]),
            "aux": None if od["aux"] is None else _vec_unhex(od["aux"]),
            "zin": _vec_unhex(od["zin"]),
            "t": _vec_unhex(od["t"]),
            "u": od["u"],
        } for e, od in j["online"].items()},
    }


def _capture_kkw_set(n: int) -> dict:
    """Capture one fresh reference transcript at width n."""
    m = suite._rnl_poly_add(suite._rnl_m_poly(n),
                            suite._rnl_rand_poly(n, RNLQ_), RNLQ_)
    seed_H = suite.BitArray.random(n)
    s, C, e_int = suite.hcred_user_keygen(m, n)
    y = suite.hcred_syndrome(seed_H, e_int, n)
    proof = hcred_prove_kkw(s, m, C, seed_H, y, n, N_par=_KKW_N_PAR,
                            M=_KKW_M, tau=_KKW_TAU, msg_bytes=_KKW_MSG)
    assert hcred_verify_kkw(m, C, seed_H, y, proof, n, _KKW_MSG), \
        f"captured n={n} transcript does not verify"
    rows, row_bits, w_max = suite._hcred_params(n)
    return {
        "params": {
            "n": n, "rows": rows, "row_bits": row_bits, "w_max": w_max,
            "N_par": _KKW_N_PAR, "M": _KKW_M, "tau": _KKW_TAU,
            "production": {"N_par": 64, "M": 343, "tau": 27},
        },
        "statement": {
            "m_poly": _vec_hex(m),
            "C_poly": _vec_hex(C),
            "s_poly": _vec_hex(s),
            "seed_H": f"{seed_H.uint:0{n // 4}x}",
            "y": f"{y:0{(rows + 3) // 4}x}",
            "msg": _KKW_MSG.hex(),
        },
        "proof": _kkw_proof_to_json(proof),
        "expect_verify": True,
        # The six axes each port was independently debugged against.  Declared
        # as mutations rather than as six more full transcripts: a consumer
        # applies one to a copy of `proof` and asserts verification FAILS.
        "tamper": [
            {"name": "wrong_msg", "apply": "msg", "note": "verify under a different msg"},
            {"name": "flip_W", "apply": "W"},
            {"name": "flip_u", "apply": "online[0].u"},
            {"name": "flip_t", "apply": "online[0].t[0]"},
            {"name": "flip_pre_root", "apply": "pre[0][0]"},
            {"name": "relabel_pbar", "apply": "online[0].pbar"},
        ],
    }


def capture_kkw() -> dict:
    """Capture both reference transcripts.  Uses os.urandom, so this is the one
    generator here whose output legitimately differs run to run."""
    return {
        "$schema": "HerraduraKEx HCRED-KKW KAT vectors (TODO #266)",
        "suite_reference": "Herradura cryptographic suite.py",
        "note": ("VERIFY-SIDE vectors: hcred_prove_kkw is not deterministic "
                 "(one os.urandom root per emulation), so these transcripts are "
                 "PINNED rather than regenerated, and every language must "
                 "CONSUME them and accept.  Coefficient vectors are hex of the "
                 "protocol's own 3-bytes-per-coefficient encoding, never JSON "
                 "numbers.  Demo-sized: production KKW is (N, M, tau) = "
                 "(64, 343, 27) for 2^-128 soundness."),
        "width_note": ("n256 is the FOUR-LANGUAGE set.  HCRED's width is a "
                       "runtime argument in Python and Go (both demo at n=32) "
                       "but a compile-time constant fixed at 256 in C "
                       "(HCRED_N) and Java (Hcred.N), so only n=256 is a width "
                       "every implementation can run.  n32 is kept because it "
                       "is cheap enough for the Python reference to "
                       "tamper-check exhaustively: one n=256 verification is "
                       "~70 s in Python, so the full accept-plus-six-rejections "
                       "matrix runs there on n32 and in the compiled consumers "
                       "on n256."),
        "sets": {name: _capture_kkw_set(n) for name, n in _KKW_SETS},
    }


def _kkw_apply_tamper(vec: dict, proof: dict, msg: bytes, which: str):
    """Apply one tamper case, returning (proof, msg).  Mirrored by every
    language's consumer, so keep the mutations arithmetically trivial."""
    import copy
    p = copy.deepcopy(proof)
    e0 = sorted(p["online"])[0]
    r0 = sorted(p["pre"])[0]
    if which == "msg":
        return p, msg + b"!"
    if which == "W":
        p["W"] += 1
    elif which == "online[0].u":
        p["online"][e0]["u"] = (p["online"][e0]["u"] + 1) % RNLQ_
    elif which == "online[0].t[0]":
        p["online"][e0]["t"][0] = (p["online"][e0]["t"][0] + 1) % RNLQ_
    elif which == "pre[0][0]":
        b = bytearray(p["pre"][r0]); b[0] ^= 1
        p["pre"][r0] = bytes(b)
    elif which == "online[0].pbar":
        p["online"][e0]["pbar"] = (p["online"][e0]["pbar"] + 1) % p["params"][0]
    else:
        raise ValueError(f"unknown tamper case {which}")
    return p, msg


def _check_kkw_set(name: str, vec: dict, tamper: bool) -> int:
    """Verify one pinned transcript instead of diffing a regeneration."""
    n = vec["params"]["n"]
    st = vec["statement"]
    m = _vec_unhex(st["m_poly"])
    C = _vec_unhex(st["C_poly"])
    seed_H = suite.BitArray(n, int(st["seed_H"], 16))
    y = int(st["y"], 16)
    msg = bytes.fromhex(st["msg"])
    proof = _kkw_proof_from_json(vec["proof"])

    if not hcred_verify_kkw(m, C, seed_H, y, proof, n, msg):
        sys.stderr.write(f"{name}: pinned transcript FAILS verification — the "
                         "vector is stale or the verifier has drifted\n")
        return 1
    if not tamper:
        print(f"{name} verifies (accept only; the tamper matrix for this set "
              "runs in the compiled consumers — see width_note).")
        return 0
    rc = 0
    for case in vec["tamper"]:
        tp, tmsg = _kkw_apply_tamper(vec, proof, msg, case["apply"])
        if hcred_verify_kkw(m, C, seed_H, y, tp, n, tmsg):
            sys.stderr.write(f"{name}: tamper case '{case['name']}' was "
                             "ACCEPTED — verification is not binding here\n")
            rc = 1
    if rc == 0:
        print(f"{name} verifies (1 accept + {len(vec['tamper'])} rejections).")
    return rc


# ── The C consumer's generated header (TODO #266) ───────────────────────────
#
# C is the one language with no KAT verifier of any kind, and it is where two of
# the three KKW port bugs were (an under-allocated commitment buffer and a
# flipped bit convention).  Rather than put a JSON parser in a dependency-free
# C tree, the pinned vector is transposed into C arrays here.
#
# The header is a DERIVED artifact -- a pure, deterministic transform of the
# pinned JSON -- so unlike the JSON itself it can be regenerate-and-diff checked,
# and `--check` does exactly that.  Editing the JSON without re-emitting the
# header is therefore a failure, not a silent drift.
#
# Only the n256 set is emitted: herradura.h fixes HCRED_N at 256, so the n32 set
# is not a width this build can represent at all.
_KKW_HDR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "hcred_kkw_vector.h")


def _c_i32_array(name: str, vals, per_line: int = 12) -> str:
    out = [f"static const int32_t {name}[{len(vals)}] = {{"]
    for i in range(0, len(vals), per_line):
        out.append("    " + " ".join(f"{v}," for v in vals[i:i + per_line]))
    out.append("};")
    return "\n".join(out)


def _c_bytes(name: str, data: bytes, per_line: int = 16) -> str:
    out = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), per_line):
        out.append("    " + " ".join(f"0x{b:02x}," for b in data[i:i + per_line]))
    out.append("};")
    return "\n".join(out)


def emit_kkw_header(vec: dict) -> str:
    s = vec["sets"]["n256"]
    p = s["proof"]
    st = s["statement"]
    n = s["params"]["n"]
    n_par, m_cnt, tau = p["params"]
    pre_e = sorted(int(e) for e in p["pre"])
    on_e = sorted(int(e) for e in p["online"])
    ons = [p["online"][str(e)] for e in on_e]
    ilen = len(_vec_unhex(ons[0]["zin"]))
    glen = len(_vec_unhex(ons[0]["t"]))
    maxpath = max(len(o["path"]) for o in ons)

    L = ["/* KAT/hcred_kkw_vector.h — GENERATED, do not edit.",
         " *",
         " * The n=256 HCRED-KKW reference transcript from KAT/hcred_kkw.json,",
         " * transposed into C arrays (TODO #266).  Regenerate with:",
         " *",
         " *     python3 KAT/generate_kat.py --emit-kkw-header",
         " *",
         " * `python3 KAT/generate_kat.py --check` diffs this against the JSON,",
         " * so editing one without the other fails rather than drifting.",
         " */",
         "#ifndef HCRED_KKW_VECTOR_H",
         "#define HCRED_KKW_VECTOR_H",
         "",
         f"#define KKW_KAT_N       {n}",
         f"#define KKW_KAT_N_PAR   {n_par}",
         f"#define KKW_KAT_M       {m_cnt}",
         f"#define KKW_KAT_TAU     {tau}",
         f"#define KKW_KAT_I       {ilen}",
         f"#define KKW_KAT_G       {glen}",
         f"#define KKW_KAT_MAXPATH {maxpath}",
         f"#define KKW_KAT_W       {p['W']}",
         ""]

    L.append(_c_i32_array("kkw_kat_m_poly", _vec_unhex(st["m_poly"])))
    L.append(_c_i32_array("kkw_kat_c_poly", _vec_unhex(st["C_poly"])))
    L.append(_c_bytes("kkw_kat_seed_H", bytes.fromhex(st["seed_H"])))
    # The syndrome is emitted in herradura.h's INTERNAL byte order, which is the
    # reverse of the big-endian integer Python and Go use: hcred_stmt_hash
    # reverses it back on the way into the hash (its own comment says so).  The
    # conversion belongs here, once, rather than in every C consumer -- feeding
    # it in Python's order makes the statement hash differ and every proof
    # rejected, with nothing pointing at the byte order.  This is the same class
    # of bug that TODO #261's C KKW port hit in hcred_kkw_outmap.
    L.append("/* NOTE: herradura.h's internal syndrome order (reverse of the "
             "big-endian\n * integer Python/Go use); pass straight to "
             "hcred_verify_kkw. */")
    L.append(_c_bytes("kkw_kat_syndrome", bytes.fromhex(st["y"])[::-1]))
    L.append(_c_bytes("kkw_kat_msg", bytes.fromhex(st["msg"])))
    L.append(f"#define KKW_KAT_MSG_LEN {len(bytes.fromhex(st['msg']))}")
    L.append("")

    L.append(_c_i32_array("kkw_kat_pre_e", pre_e))
    L.append(f"static const uint8_t kkw_kat_pre_root[{len(pre_e)}][32] = {{")
    for e in pre_e:
        raw = bytes.fromhex(p["pre"][str(e)])
        L.append("    { " + " ".join(f"0x{b:02x}," for b in raw) + " },")
    L.append("};")
    L.append("")

    L.append(_c_i32_array("kkw_kat_online_e", on_e))
    L.append(_c_i32_array("kkw_kat_pbar", [o["pbar"] for o in ons]))
    L.append(_c_i32_array("kkw_kat_u", [o["u"] for o in ons]))
    L.append(_c_i32_array("kkw_kat_path_len", [len(o["path"]) for o in ons]))
    L.append(_c_i32_array("kkw_kat_has_aux",
                          [0 if o["aux"] is None else 1 for o in ons]))
    L.append("")

    # Path entries: (level, index, node) per online emulation.
    L.append(f"static const int32_t kkw_kat_path_l[{tau}][KKW_KAT_MAXPATH] = {{")
    for o in ons:
        vals = [pe[0] for pe in o["path"]] + [0] * (maxpath - len(o["path"]))
        L.append("    { " + " ".join(f"{v}," for v in vals) + " },")
    L.append("};")
    L.append(f"static const int32_t kkw_kat_path_i[{tau}][KKW_KAT_MAXPATH] = {{")
    for o in ons:
        vals = [pe[1] for pe in o["path"]] + [0] * (maxpath - len(o["path"]))
        L.append("    { " + " ".join(f"{v}," for v in vals) + " },")
    L.append("};")
    L.append(f"static const uint8_t kkw_kat_path_node[{tau}][KKW_KAT_MAXPATH][32] = {{")
    for o in ons:
        L.append("    {")
        for k in range(maxpath):
            raw = bytes.fromhex(o["path"][k][2]) if k < len(o["path"]) else b"\0" * 32
            L.append("        { " + " ".join(f"0x{b:02x}," for b in raw) + " },")
        L.append("    },")
    L.append("};")
    L.append("")

    L.append(f"static const uint8_t kkw_kat_com_h[{tau}][32] = {{")
    for o in ons:
        raw = bytes.fromhex(o["com_h"])
        L.append("    { " + " ".join(f"0x{b:02x}," for b in raw) + " },")
    L.append("};")
    L.append("")

    for label, key, width in (("zin", "zin", ilen), ("t", "t", glen),
                              ("aux", "aux", glen)):
        L.append(f"static const int32_t kkw_kat_{label}[{tau}][{width}] = {{")
        for o in ons:
            vals = ([0] * width if o[key] is None else _vec_unhex(o[key]))
            L.append("    {")
            for i in range(0, width, 12):
                L.append("        " + " ".join(f"{v}," for v in vals[i:i + 12]))
            L.append("    },")
        L.append("};")
        L.append("")

    # The tamper table, so C runs the same six cases as every other consumer
    # rather than a set someone chose independently.
    L.append(f"#define KKW_KAT_TAMPER_COUNT {len(s['tamper'])}")
    L.append("static const char *const kkw_kat_tamper_name[] = {")
    for tc in s["tamper"]:
        L.append(f"    \"{tc['name']}\",")
    L.append("};")
    L.append("static const char *const kkw_kat_tamper_apply[] = {")
    for tc in s["tamper"]:
        L.append(f"    \"{tc['apply']}\",")
    L.append("};")
    L.append("")
    L.append("#endif /* HCRED_KKW_VECTOR_H */")
    return "\n".join(L) + "\n"


def check_kkw_header(vec: dict) -> int:
    name = os.path.basename(_KKW_HDR_PATH)
    want = emit_kkw_header(vec)
    if not os.path.exists(_KKW_HDR_PATH):
        sys.stderr.write(f"{name} is missing — run "
                         "python3 KAT/generate_kat.py --emit-kkw-header\n")
        return 1
    with open(_KKW_HDR_PATH) as f:
        got = f.read()
    if got != want:
        sys.stderr.write(f"{name} is stale — it no longer matches "
                         "hcred_kkw.json; rerun "
                         "python3 KAT/generate_kat.py --emit-kkw-header\n")
        return 1
    print(f"{name} matches hcred_kkw.json[n256].")
    return 0


def check_kkw(path: str) -> int:
    name = os.path.basename(path)
    if not os.path.exists(path):
        sys.stderr.write(f"{name} is missing — run "
                         "python3 KAT/generate_kat.py --capture-kkw\n")
        return 1
    with open(path) as f:
        vec = json.load(f)
    rc = check_kkw_header(vec)
    for set_name, sv in vec["sets"].items():
        # n=256 is accept-only HERE and fully tamper-checked in Go/C/Java; see
        # _KKW_SETS' comment for why the split is by cost, not by coverage.
        rc |= _check_kkw_set(f"{name}[{set_name}]", sv,
                             tamper=(sv["params"]["n"] != 256))
    return rc



# ---------------------------------------------------------------------------
# TODO #296: the fixed-stream sampler replay.
#
# WHY THIS VECTOR EXISTS.  TODO #294 found rnl_sigma_sign drawing its ZK mask by
# rejection sampling in C and by raw modulo in the other three -- a 3-vs-1 split
# that had shipped, because local randomness reaches no artifact: no KAT pins it
# and none can (a signature is randomised per call), and no round-trip or interop
# pair compares two samplers.  #294 recorded that the ONLY check available for
# that class is a fixed-stream replay, which makes a randomised primitive
# deterministic by replacing its entropy source, and then pins the four
# consumption orders against each other.  It verified its own fix that way and
# threw the harness away, leaving the claim in CLAUDE.md with nothing enforcing
# it.  This is that harness, kept.
#
# WHAT IS PINNED.  Per row: the sampler's OUTPUT given a fixed input stream, and
# -- where all four ports read the stream at the same granularity -- the number
# of bytes consumed.  Output pins the byte order, the rejection threshold, the
# modular reduction and the order the stream is consumed in; byte count pins
# that no port reads ahead of or behind the others.
#
# WHY consumed IS null ON ONE ROW.  rnl_rand_poly is block-buffered in Go,
# Python and Java (TODO #293) and unbuffered in C, which reads 3 bytes per draw
# through a buffered FILE *.  The byte-to-draw MAPPING is identical -- draw i
# takes stream[3i:3i+3] in all four -- so the output is pinnable and is pinned.
# The TOTAL is not: the three buffered ports read 3*(n + n/64 + 8) bytes whatever
# they use, and on a refill they discard the 0-2 byte remainder that C would have
# used.  The slack is ~1.6% against a 0.39% rejection rate at q = 65537, so a
# refill is about ten standard deviations out and no run will see one; the
# divergence is recorded rather than asserted away, and closing it would mean
# buffering C for a test's benefit, which #293 deliberately did not do.
#
# THE STREAMS are HFSCX-256 in counter mode (det_bytes), but nothing downstream
# needs that: the bytes are stored literally as hex, so a consumer reads them and
# needs no derivation and no hash.  They are arbitrary fixed constants.
# ---------------------------------------------------------------------------

_REPLAY_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sampler_replay.json")


class _ReplayStream:
    """A fixed byte stream standing in for os.urandom, counting what it serves."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def urandom(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise RuntimeError(
                "sampler replay: stream exhausted (%d asked, %d left) — the "
                "vector's stream is too short for this sampler"
                % (n, len(self.data) - self.pos))
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk


@contextlib.contextmanager
def _replay(data: bytes):
    """Run the SHIPPED sampler against `data` instead of the CSPRNG.

    Patches the suite module's own `os` reference, which is the process-wide
    module object — hence the finally.  Driving the shipped function rather than
    a transcription is the point: a transcription would pin this file's opinion
    of the sampler, which is the very thing the vector exists to check.
    """
    st = _ReplayStream(data)
    real = suite.os.urandom
    suite.os.urandom = st.urandom
    try:
        yield st
    finally:
        suite.os.urandom = real


def gen_sampler_replay() -> dict:
    rows = []

    # --- CBD(1) polynomial: one read of (n+3)/4, four coefficients per byte ---
    stream = det_bytes(b"replay-cbd", (RNLN + 3) // 4)
    with _replay(stream) as st:
        coeffs = suite._rnl_cbd_poly(RNLN, RNLB, RNLQ)
    rows.append({
        "name": "rnl_cbd_poly",
        "calls": {"c": "rnl_cbd_poly_dim", "go": "RnlCBDPoly",
                  "python": "_rnl_cbd_poly", "java": "HerraduraNl.rnlCbdPoly"},
        "params": {"n": RNLN, "q": RNLQ, "eta": RNLB},
        "stream": stream.hex(),
        "expect_poly": poly_hex(coeffs, 3),
        "consumed": st.pos,
    })

    # --- uniform in Z_q^n: 3-byte big-endian rejection sampling ---
    stream = det_bytes(b"replay-randpoly", 3 * (RNLN + (RNLN >> 6) + 8))
    with _replay(stream) as st:
        coeffs = suite._rnl_rand_poly(RNLN, RNLQ)
    rows.append({
        "name": "rnl_rand_poly",
        "calls": {"c": "rnl_rand_poly", "go": "RnlRandPoly",
                  "python": "_rnl_rand_poly", "java": "HerraduraNl.rnlRandPoly"},
        "params": {"n": RNLN, "q": RNLQ,
                   "threshold": (1 << 24) - (1 << 24) % RNLQ},
        "stream": stream.hex(),
        "expect_poly": poly_hex(coeffs, 3),
        # Deliberately null — see the header: C is unbuffered, the other three
        # are block-buffered (TODO #293), so only the MAPPING is common.
        "consumed": None,
        "consumed_note": ("C reads 3 bytes per draw; Go, Python and Java read "
                          "3*(n + n/64 + 8) in one block (TODO #293).  The "
                          "byte-to-draw mapping is identical, the total is not."),
    })

    # --- weight-t error vector: 4-byte big-endian rejection into a set ---
    # The label is chosen, not arbitrary: it is the first one whose stream makes
    # the sampler draw a position it has ALREADY taken -- twice -- so the
    # duplicate-skip path is exercised rather than merely present.  The first
    # label tried consumed exactly 4t bytes, i.e. sixteen distinct draws, and a
    # port that dropped the duplicate check would have passed it.
    # The OTHER branch, v >= threshold, is UNREACHABLE at this width and that is
    # arithmetic rather than luck: 256 divides 2^32, so threshold is exactly
    # 2^32 and a 4-byte draw is always below it.  Worth knowing before widening
    # the type -- a threshold held in a uint32 would wrap to 0 here and reject
    # every draw forever.  All four ports compute it in 64 bits.
    stream = det_bytes(b"replay-weightt-2", 256)
    with _replay(stream) as st:
        e_int = suite._csprng_weight_t(KEYBITS, suite.SDFT)
    rows.append({
        "name": "stern_weight_t",
        "calls": {"c": "stern_rand_error", "go": "SternRandError",
                  "python": "_csprng_weight_t", "java": "Stern.csprngWeightT"},
        "params": {"n": KEYBITS, "t": suite.SDFT,
                   "threshold": (1 << 32) - (1 << 32) % KEYBITS},
        "stream": stream.hex(),
        "expect_value": f"{e_int:0{KEYBITS // 4}x}",
        "expect_weight": bin(e_int).count("1"),
        "consumed": st.pos,
    })

    # --- OPRF blinding scalar: 32 raw bytes, reject r <= 1 or gcd(r, ORD) != 1 ---
    # The FIRST draw is r = 1 exactly, and that is the point of this row rather
    # than a decoration.  C rejected r <= 1 with a `continue` inside a do/while,
    # which jumps to the CONDITION and not to the top of the body, so a rejected
    # draw re-tested the previous iteration's verdict -- uninitialised on the
    # first (TODO #296).  A stream of random-looking bytes never enters that
    # branch (it needs a 256-bit draw of 0 or 1, p = 2^-255), so a vector built
    # only from det_bytes leaves the repaired code unguarded: deleting the
    # rejection again would still pass.  With r = 1 leading, it does not.
    # The gcd rejection is exercised too, by the det_bytes tail: the accepted
    # scalar is the third draw, so two are refused for gcd(r, ORD) != 1.
    stream = (b"\x00" * 31 + b"\x01") + det_bytes(b"replay-oprf", 32 * 16)
    oprf_input = b"HerraduraKEx sampler replay"
    with _replay(stream) as st:
        r_val, alpha_val = suite.oprf_blind(oprf_input)
    rows.append({
        "name": "oprf_blind_scalar",
        "calls": {"c": "oprf_blind", "go": "OprfBlind",
                  "python": "oprf_blind", "java": "Oprf.blind"},
        "params": {"bits": KEYBITS, "input_hex": oprf_input.hex()},
        "stream": stream.hex(),
        "expect_r": f"{r_val:0{KEYBITS // 4}x}",
        "expect_alpha": f"{alpha_val:0{KEYBITS // 4}x}",
        "consumed": st.pos,
    })

    return {
        "description": ("TODO #296: fixed-stream replay of the suite's leaf "
                        "CSPRNG samplers.  Each row replaces the entropy source "
                        "with `stream` and pins what the SHIPPED sampler "
                        "produces, so four ports that agree on a distribution "
                        "but not on a consumption order cannot stay that way "
                        "unnoticed."),
        "note": ("`consumed` is the number of stream bytes the sampler reads.  "
                 "A null means the four ports read at different granularities "
                 "and only the output is common — see consumed_note on that row."),
        "samplers": rows,
    }


_REPLAY_HDR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "sampler_replay_vector.h")


def emit_replay_header(vec: dict) -> str:
    """Transpose sampler_replay.json into C arrays.

    Same reason as emit_kkw_header's: the shipped C tree has no JSON parser and
    that property is worth more than the convenience of one.  A pure
    deterministic transform of the JSON, so --check diffs it and a vector
    regenerated without re-emitting the header fails rather than drifting.
    """
    rows = {r["name"]: r for r in vec["samplers"]}

    L = ["/* KAT/sampler_replay_vector.h — GENERATED, do not edit.",
         " *",
         " * KAT/sampler_replay.json transposed into C arrays (TODO #296), so",
         " * the dependency-free C tree can replay the suite's leaf CSPRNG",
         " * samplers against a fixed stream.  Regenerate with:",
         " *",
         " *     python3 KAT/generate_kat.py",
         " *",
         " * `python3 KAT/generate_kat.py --check` diffs this against the JSON.",
         " */",
         "#ifndef SAMPLER_REPLAY_VECTOR_H",
         "#define SAMPLER_REPLAY_VECTOR_H",
         ""]

    r = rows["rnl_cbd_poly"]
    L += [f"#define RPL_CBD_N         {r['params']['n']}",
          f"#define RPL_CBD_Q         {r['params']['q']}",
          f"#define RPL_CBD_ETA       {r['params']['eta']}",
          f"#define RPL_CBD_CONSUMED  {r['consumed']}",
          _c_bytes("rpl_cbd_stream", bytes.fromhex(r["stream"])),
          _c_i32_array("rpl_cbd_expect", _vec_unhex(r["expect_poly"])), ""]

    r = rows["rnl_rand_poly"]
    # consumed is null on this row by design: C reads 3 bytes per draw, the
    # other three ports read one block (TODO #293).  No CONSUMED macro is
    # emitted, so the C consumer cannot accidentally assert a total that is
    # only true of the buffered ports.
    L += [f"#define RPL_RAND_N        {r['params']['n']}",
          f"#define RPL_RAND_Q        {r['params']['q']}",
          f"#define RPL_RAND_THRESH   {r['params']['threshold']}",
          _c_bytes("rpl_rand_stream", bytes.fromhex(r["stream"])),
          _c_i32_array("rpl_rand_expect", _vec_unhex(r["expect_poly"])), ""]

    r = rows["stern_weight_t"]
    L += [f"#define RPL_WT_N          {r['params']['n']}",
          f"#define RPL_WT_T          {r['params']['t']}",
          f"#define RPL_WT_WEIGHT     {r['expect_weight']}",
          f"#define RPL_WT_CONSUMED   {r['consumed']}",
          _c_bytes("rpl_wt_stream", bytes.fromhex(r["stream"])),
          _c_bytes("rpl_wt_expect", bytes.fromhex(r["expect_value"])), ""]

    r = rows["oprf_blind_scalar"]
    L += [f"#define RPL_OPRF_BITS     {r['params']['bits']}",
          f"#define RPL_OPRF_CONSUMED {r['consumed']}",
          _c_bytes("rpl_oprf_input", bytes.fromhex(r["params"]["input_hex"])),
          _c_bytes("rpl_oprf_stream", bytes.fromhex(r["stream"])),
          _c_bytes("rpl_oprf_expect_r", bytes.fromhex(r["expect_r"])),
          _c_bytes("rpl_oprf_expect_alpha", bytes.fromhex(r["expect_alpha"])), ""]

    L += ["#endif /* SAMPLER_REPLAY_VECTOR_H */", ""]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# TODO #297: the fixed-stream OPERATION replay.
#
# WHAT THIS ADDS OVER sampler_replay.json.  TODO #296 pinned four LEAF samplers:
# each is separately callable, so a fixed stream reaches it directly and one row
# is one call with scalar arguments.  The raw-entropy census counts 105 functions
# that read the CSPRNG, so 101 were left recorded-but-unpinned, and they are not
# leaves -- they are protocol operations whose draw loops are INLINE.  What a
# leaf row cannot see is the ORDER in which an operation visits its samplers, or
# an inline loop that is not a named sampler at all.  #294's own defect was of
# exactly that kind: rnl_sigma_sign's mask draw is written out inside the
# signing loop and is not a function anyone can call.
#
# WHY IT IS POSSIBLE AT ALL, restated because it is the whole insight: a
# signature is randomised per call, so no KAT can pin one and none could.  Under
# a fixed stream it is deterministic.  That is #294's observation, applied to
# whole operations rather than to the leaves #296 stopped at.
#
# WHAT A ROW CARRIES, and the new part is `statement`.  An operation is a
# function of its stream AND its statement -- a key, a message, parameters -- so
# every row states its inputs explicitly in hex rather than deriving them from
# another row.  A derived statement would make one row's failure cascade into
# the next and would hide which of the two actually diverged.
#
# INJECTION NEEDS NOTHING NEW, in any of the four.  Every operation here takes
# its entropy as a parameter in C (`FILE *`) and in Java (`SecureRandom`);
# Python patches os.urandom and Go swaps rand.Reader exactly as #296 does.  That
# was checked before the vector was designed, and it is why this item is a
# vector plus four drivers rather than a new mechanism.
#
# THE ONE THING THAT DOES NOT CARRY, and it is a limit rather than a defect.
# rnl_sigma_sign RETRIES: it draws a fresh mask and re-tests a norm bound, and
# at the deployed ring it accepts about one attempt in three or four.  Python,
# Go and Java buffer the draw (TODO #293) and C does not, so the two agree
# byte-for-byte only until the first retry -- at an attempt boundary the
# buffered ports discard the tail of a block that C would have gone on to use,
# and every attempt after the first reads from a different offset in the three
# than in C.  So the sigma row's stream is CHOSEN to accept on the first
# attempt, `attempts` records that, and the generator asserts it: regenerating
# with a stream that happens to retry would silently produce a vector only three
# of the four ports can reproduce.  Note what this means honestly -- the row
# pins the MINORITY path, since most real signatures retry.  Pinning the retry
# path would mean buffering C for a test's benefit, which #293 declined.
# ---------------------------------------------------------------------------

_OPREPLAY_OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "operation_replay.json")
_OPREPLAY_HDR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "operation_replay_vector.h")


def i32_hex(vals) -> str:
    """Centered integer coefficients as 4-byte big-endian two's complement.

    Two's complement rather than an offset encoding because that is what C's
    int32_t already holds: the consumer compares against the array verbatim and
    no port has to agree with any other about where the zero point sits.
    """
    return "".join(f"{v & 0xFFFFFFFF:08x}" for v in vals)


def _unhex_i32(s: str) -> list:
    out = []
    for i in range(0, len(s), 8):
        v = int(s[i:i + 8], 16)
        out.append(v - (1 << 32) if v >= (1 << 31) else v)
    return out


def _nbit_hex(x, n: int) -> str:
    """A BitArray or an int as n bits of big-endian hex."""
    v = x.uint if hasattr(x, "uint") else int(x)
    return f"{v:0{(n + 3) // 4}x}"


def gen_operation_replay() -> dict:
    rows = []
    n = KEYBITS

    # --- Stern-F keygen: BitArray.random(n), THEN the weight-t error vector ---
    # No statement at all, which is what makes this the cheapest possible
    # operation row and still a real one: it pins the ORDER of two samplers both
    # of which #296 already pins individually.  Swapping the two lines leaves
    # every distribution correct, every round-trip passing and every leaf row
    # green, and changes both outputs here.
    # Slack above the 100 bytes consumed: the weight-t draw rejects and
    # retries, so the total is data-dependent and cannot be computed here.
    stream = det_bytes(b"op-stern-keygen", 256)
    with _replay(stream) as st:
        seed, e_int, syndrome = suite.stern_f_keygen(n)
    sf_t = max(2, n // 16)
    rows.append({
        "name": "stern_f_keygen",
        "calls": {"c": "stern_f_keygen", "go": "SternFKeygen",
                  "python": "stern_f_keygen", "java": "Stern.sternFKeygen"},
        "params": {"n": n, "t": sf_t, "n_rows": n // 2},
        "statement": {},
        "stream": stream.hex(),
        "expect": {"seed": _nbit_hex(seed, n),
                   "e": _nbit_hex(e_int, n),
                   "syndrome": _nbit_hex(syndrome, n // 2)},
        "consumed": st.pos,
    })

    # --- Stern-F signing: per round a weight-t draw, THEN a permutation seed ---
    # The keypair comes from the row above for convenience, but the ROW writes it
    # out in full: a consumer reads this row's own `statement` and never row 0's
    # output, so a keygen divergence cannot masquerade as a signing one.
    sign_msg = BitArray(n, int.from_bytes(det_bytes(b"op-stern-msg", n // 8), "big"))
    sign_e = int.from_bytes(bytes.fromhex(rows[0]["expect"]["e"]), "big")
    sign_seed = BitArray(n, int.from_bytes(bytes.fromhex(rows[0]["expect"]["seed"]), "big"))
    sign_syn = int.from_bytes(bytes.fromhex(rows[0]["expect"]["syndrome"]), "big")
    rounds = 6
    # The label is chosen: the first one tried gave challenges {0, 2}
    # only, leaving the b = 1 response branch unpinned.
    stream = det_bytes(b"op-stern-sign-1", 1024)
    with _replay(stream) as st:
        with warnings.catch_warnings():
            # rounds < 219 warns by design (production soundness).  A vector is
            # not a deployment; the round count is small so the row stays small.
            warnings.simplefilter("ignore", RuntimeWarning)
            commits, challenges, responses = suite.hpks_stern_f_sign(
                sign_msg, sign_e, sign_seed, sign_syn, n, rounds)
    # The three challenge branches reveal three DIFFERENT pairs, so a stream
    # whose challenges miss a value leaves that branch unpinned.  Asserted, not
    # hoped for -- this is #296's chosen-stream rule carried forward.
    assert set(challenges) == {0, 1, 2}, \
        ("operation replay: the stern_f_sign stream must produce all three "
         "challenge values; got %r" % (sorted(set(challenges)),))
    rows.append({
        "name": "hpks_stern_f_sign",
        "calls": {"c": "hpks_stern_f_sign", "go": "HpksSternFSign",
                  "python": "hpks_stern_f_sign", "java": "Stern.hpksSternFSign"},
        "params": {"n": n, "t": sf_t, "n_rows": n // 2, "rounds": rounds},
        "statement": {"msg": _nbit_hex(sign_msg, n),
                      "e": _nbit_hex(sign_e, n),
                      "seed": _nbit_hex(sign_seed, n),
                      "syndrome": _nbit_hex(sign_syn, n // 2)},
        "stream": stream.hex(),
        "expect": {
            "commits": [[c0.hex() if isinstance(c0, bytes) else _nbit_hex(c0, 256),
                         c1.hex() if isinstance(c1, bytes) else _nbit_hex(c1, 256),
                         c2.hex() if isinstance(c2, bytes) else _nbit_hex(c2, 256)]
                        for c0, c1, c2 in commits],
            "challenges": list(challenges),
            # Every response is a pair of n-bit values whichever branch produced
            # it, so one uniform shape serves all three.
            "responses": [[_nbit_hex(a, n), _nbit_hex(b, n)] for a, b in responses],
        },
        "consumed": st.pos,
    })

    # --- ZKBoo prover: per round two n-bit shares, then three 32-byte tapes ---
    zn, zrounds = 16, 4
    zA = int.from_bytes(det_bytes(b"op-zkboo-a", (zn + 7) // 8), "big") & ((1 << zn) - 1)
    zB = int.from_bytes(det_bytes(b"op-zkboo-b", (zn + 7) // 8), "big") & ((1 << zn) - 1)
    zy = suite.nl_fscx_v1(BitArray(zn, zA), BitArray(zn, zB)).uint
    zmsg = b"HerraduraKEx operation replay"
    # Exactly what the operation must consume -- there is no rejection
    # anywhere in ZKBoo's draws -- so a port that reads one byte more
    # exhausts the stream and says so, rather than diverging quietly.
    stream = det_bytes(b"op-zkboo", zrounds * (2 * ((zn + 7) // 8) + 96))
    with _replay(stream) as st:
        proof = suite.zkp_nl_prove(zA, zB, zy, zn, zrounds, zmsg)
    rows.append({
        "name": "zkp_nl_prove",
        "calls": {"c": "zkp_nl_prove", "go": "ZkpNlProve",
                  "python": "zkp_nl_prove", "java": "ZkpNl.prove"},
        "params": {"n": zn, "rounds": zrounds, "nb": (zn + 7) // 8},
        "statement": {"a": _nbit_hex(zA, zn), "b": _nbit_hex(zB, zn),
                      "y": _nbit_hex(zy, zn), "msg_hex": zmsg.hex()},
        "stream": stream.hex(),
        "expect": {"rounds": [{"com_0": r["com_0"].hex(),
                               "com_1": r["com_1"].hex(),
                               "com_2": r["com_2"].hex(),
                               "e": r["e"],
                               "view_p1": r["view_p1"].hex(),
                               "view_p2": r["view_p2"].hex()} for r in proof]},
        "consumed": st.pos,
    })

    # --- Stern-F ring signing: the operation that had the DEFECT (TODO #297) ---
    # k-1 simulated members, each round of each drawing a challenge trit and then
    # one of three branch-specific draw sequences, followed by the real signer's
    # rounds.  That shape is why this row earns its size: no leaf sampler is
    # involved in choosing the trit, the branch taken decides what is drawn next,
    # and the whole thing reaches the wire through commitments a verifier accepts
    # whatever they contain.
    #
    # Two divergences lived here, both invisible to every other check because a
    # simulated member's randomness reaches no artifact a verifier examines:
    #   - the trit had THREE schemes (C/Python one byte rejecting 255, Go a
    #     whole n-bit draw modulo 3, Java Random.nextInt(3));
    #   - and the b = 0 dummy commitment was hash(ZERO, ZERO) in C and Go, a
    #     CONSTANT marking every simulated b = 0 round, so the signer was the
    #     member whose rounds never carried it.  That is an anonymity break, and
    #     the row below is what stops it coming back.
    ring_k, ring_rounds, ring_j = 3, 4, 1
    ring_keys, ring_e = [], None
    for idx in range(ring_k):
        with _replay(det_bytes(b"op-ring-key-%d" % idx, 256)):
            rseed, re_int, rsyn = suite.stern_f_keygen(n)
        ring_keys.append((rseed, rsyn))
        if idx == ring_j:
            ring_e = re_int
    ring_msg = BitArray(n, int.from_bytes(det_bytes(b"op-ring-msg", n // 8), "big"))
    stream = det_bytes(b"op-ring-sign", 8192)
    with _replay(stream) as st:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            r_commits, r_challenges, r_responses = suite.hpks_stern_ring_sign(
                ring_msg, ring_e, ring_j, ring_keys, n, ring_rounds)
    # The b = 0 branch is the one that carried the defect, so a stream whose
    # simulated members never draw it would pin the fix and prove nothing.
    sim_b = [r_challenges[i][r] for i in range(ring_k) for r in range(ring_rounds)
             if i != ring_j]
    assert 0 in sim_b, \
        ("operation replay: the ring stream must make a SIMULATED member draw "
         "b = 0 -- that is the branch whose dummy commitment was a constant in "
         "C and Go; got %r" % (sorted(set(sim_b)),))
    rows.append({
        "name": "hpks_stern_ring_sign",
        "calls": {"c": "stern_ring_sign", "go": "HpksSternRingSign",
                  "python": "hpks_stern_ring_sign", "java": "SternRing.sign"},
        "params": {"n": n, "t": sf_t, "n_rows": n // 2, "rounds": ring_rounds,
                   "k": ring_k, "j": ring_j},
        "statement": {
            "msg": _nbit_hex(ring_msg, n),
            "e": _nbit_hex(ring_e, n),
            "seeds": [_nbit_hex(sd, n) for sd, _ in ring_keys],
            "syndromes": [_nbit_hex(sy, n // 2) for _, sy in ring_keys],
        },
        "stream": stream.hex(),
        "expect": {
            "commits": [[[_nbit_hex(c, n) for c in r_commits[i][r]]
                         for r in range(ring_rounds)] for i in range(ring_k)],
            "challenges": [[r_challenges[i][r] for r in range(ring_rounds)]
                           for i in range(ring_k)],
            "responses": [[[_nbit_hex(a, n), _nbit_hex(b, n)]
                           for a, b in (r_responses[i][r] for r in range(ring_rounds))]
                          for i in range(ring_k)],
        },
        "consumed": st.pos,
    })

    # --- Ring-LWR Sigma signing: the inline mask draw TODO #294 was about ---
    # The statement is an HKEX-RNL keypair plus C = round_p(m*s), derived here
    # under its own fixed stream and then written out in full, so the row is
    # self-contained.
    sig_stream_stmt = det_bytes(b"op-sigma-stmt", 3 * (RNLN + (RNLN >> 6) + 8) + 4096)
    with _replay(sig_stream_stmt):
        m_poly = suite._rnl_rand_poly(RNLN, RNLQ)
        s_poly = suite._rnl_cbd_poly(RNLN, RNLB, RNLQ)
    C_poly = suite._rnl_round(suite._rnl_poly_mul(m_poly, s_poly, RNLQ, RNLN),
                              RNLQ, RNLP)
    gamma, sig_t = suite._sigma_params(RNLN)
    sig_msg = (b"HerraduraKEx operation replay" + b"\x00" * 32)[:32]
    # v24 is the first label whose FIRST attempt clears the norm bound; see
    # the header on why any other label would produce a three-port vector.
    # The stream is exactly one block long, so a retry cannot silently pass
    # either: it exhausts the stream before the assertion is reached.
    blk = 3 * (RNLN + (RNLN >> 6) + 8)
    stream = det_bytes(b"op-sigma-v24", blk)
    with _replay(stream) as st:
        w, c, z = suite.rnl_sigma_sign(s_poly, m_poly, C_poly, RNLN, sig_msg)
    assert st.pos == blk, \
        ("operation replay: the rnl_sigma_sign stream must accept on the FIRST "
         "attempt (consumed %d, one block is %d) -- a retry makes the row "
         "reproducible in the three buffered ports only" % (st.pos, blk))
    assert suite.rnl_sigma_verify(m_poly, C_poly, RNLN, sig_msg, w, c, z), \
        "operation replay: the pinned rnl_sigma proof does not verify"
    rows.append({
        "name": "rnl_sigma_sign",
        "calls": {"c": "rnl_sigma_sign", "go": "RnlSigmaSign",
                  "python": "rnl_sigma_sign", "java": "HerraduraNl.rnlSigmaSign"},
        "params": {"n": RNLN, "q": RNLQ, "p": RNLP, "gamma": gamma, "t": sig_t,
                   "threshold": (1 << 24) - (1 << 24) % (2 * gamma + 1),
                   "attempts": 1},
        "statement": {"s_poly": poly_hex(s_poly, 3), "m_poly": poly_hex(m_poly, 3),
                      "c_poly": poly_hex(C_poly, 3), "msg_hex": sig_msg.hex()},
        "stream": stream.hex(),
        "expect": {"w": i32_hex(w), "c": i32_hex(c), "z": i32_hex(z)},
        # Null by design: C is unbuffered, the other three read one block
        # (TODO #293).  Only the byte-to-draw MAPPING is common, and it is
        # common only because `attempts` is 1 -- see the header.
        "consumed": None,
        "consumed_note": ("C reads 3 bytes per draw; Go, Python and Java read "
                          "3*(n + n/64 + 8) in one block (TODO #293).  Equal "
                          "only up to the first retry, which is why this row's "
                          "stream accepts on attempt 1."),
    })

    return {
        "description": ("TODO #297: fixed-stream replay of whole randomised "
                        "OPERATIONS, one level above KAT/sampler_replay.json's "
                        "leaf samplers.  Each row supplies a fixed statement and "
                        "a fixed stream and pins what the SHIPPED operation "
                        "produces, so the ORDER in which it visits its samplers "
                        "-- and any inline draw loop that is not a callable "
                        "sampler at all -- is pinned across the four ports."),
        "note": ("`statement` is stated in full rather than derived from another "
                 "row, so a divergence is attributed to the operation that has "
                 "it.  `consumed` is null where the ports read at different "
                 "granularities; see consumed_note on that row."),
        "operations": rows,
    }


def _c_bytes2(name: str, rows: list, per_line: int = 16) -> str:
    """A [rows][len] uint8_t table, every row the same length."""
    ln = len(rows[0])
    out = [f"static const uint8_t {name}[{len(rows)}][{ln}] = {{"]
    for data in rows:
        assert len(data) == ln, f"{name}: ragged row"
        out.append("    {")
        for i in range(0, ln, per_line):
            out.append("        " + " ".join(f"0x{b:02x}," for b in data[i:i + per_line]))
        out.append("    },")
    out.append("};")
    return "\n".join(out)


def _c_int_list(name: str, vals, per_line: int = 16) -> str:
    out = [f"static const int {name}[{len(vals)}] = {{"]
    for i in range(0, len(vals), per_line):
        out.append("    " + " ".join(f"{v}," for v in vals[i:i + per_line]))
    out.append("};")
    return "\n".join(out)


def emit_operation_header(vec: dict) -> str:
    """Transpose operation_replay.json into C arrays.

    Same reason as emit_replay_header's: the shipped C tree has no JSON parser.
    A pure deterministic transform, so --check diffs it and a vector regenerated
    without re-emitting the header fails rather than drifting.
    """
    rows = {r["name"]: r for r in vec["operations"]}
    hx = bytes.fromhex

    L = ["/* KAT/operation_replay_vector.h — GENERATED, do not edit.",
         " *",
         " * KAT/operation_replay.json transposed into C arrays (TODO #297), so",
         " * the dependency-free C tree can replay whole randomised OPERATIONS",
         " * against a fixed statement and a fixed stream.  Regenerate with:",
         " *",
         " *     python3 KAT/generate_kat.py",
         " *",
         " * `python3 KAT/generate_kat.py --check` diffs this against the JSON.",
         " */",
         "#ifndef OPERATION_REPLAY_VECTOR_H",
         "#define OPERATION_REPLAY_VECTOR_H",
         ""]

    r = rows["stern_f_keygen"]
    L += ["/* Stern-F keygen: seed first, then the weight-t error vector. */",
          f"#define OPR_SFK_N         {r['params']['n']}",
          f"#define OPR_SFK_T         {r['params']['t']}",
          f"#define OPR_SFK_CONSUMED  {r['consumed']}",
          _c_bytes("opr_sfk_stream", hx(r["stream"])),
          _c_bytes("opr_sfk_seed", hx(r["expect"]["seed"])),
          _c_bytes("opr_sfk_e", hx(r["expect"]["e"])),
          # BYTE ORDER, and it is the trap TODO #266 recorded: the JSON holds
          # the syndrome as a big-endian INTEGER (row i is bit i), which is what
          # Python, Go and Java compute, while herradura.h packs row i into
          # syndr[i/8] bit i%8.  That is the same integer written
          # little-endian, so the transposition happens HERE, once, rather than
          # in the C consumer where a reader would have to infer it.
          _c_bytes("opr_sfk_syndrome",
                   int(r["expect"]["syndrome"], 16).to_bytes(
                       r["params"]["n_rows"] // 8, "little")), ""]

    r = rows["hpks_stern_f_sign"]
    e = r["expect"]
    L += ["/* Stern-F signing: per round a weight-t draw, then a permutation seed. */",
          f"#define OPR_SFS_N         {r['params']['n']}",
          f"#define OPR_SFS_ROUNDS    {r['params']['rounds']}",
          f"#define OPR_SFS_CONSUMED  {r['consumed']}",
          _c_bytes("opr_sfs_stream", hx(r["stream"])),
          _c_bytes("opr_sfs_msg", hx(r["statement"]["msg"])),
          _c_bytes("opr_sfs_e", hx(r["statement"]["e"])),
          _c_bytes("opr_sfs_seed", hx(r["statement"]["seed"])),
          _c_bytes("opr_sfs_syndrome", hx(r["statement"]["syndrome"])),
          _c_bytes2("opr_sfs_c0", [hx(c[0]) for c in e["commits"]]),
          _c_bytes2("opr_sfs_c1", [hx(c[1]) for c in e["commits"]]),
          _c_bytes2("opr_sfs_c2", [hx(c[2]) for c in e["commits"]]),
          _c_int_list("opr_sfs_challenge", e["challenges"]),
          _c_bytes2("opr_sfs_resp_a", [hx(p[0]) for p in e["responses"]]),
          _c_bytes2("opr_sfs_resp_b", [hx(p[1]) for p in e["responses"]]), ""]

    r = rows["zkp_nl_prove"]
    e = r["expect"]["rounds"]
    L += ["/* ZKBoo prover: per round two n-bit shares, then three 32-byte tapes. */",
          f"#define OPR_ZK_N          {r['params']['n']}",
          f"#define OPR_ZK_ROUNDS     {r['params']['rounds']}",
          f"#define OPR_ZK_VIEWLEN    {len(hx(e[0]['view_p1']))}",
          f"#define OPR_ZK_CONSUMED   {r['consumed']}",
          f"#define OPR_ZK_A          0x{r['statement']['a']}ULL",
          f"#define OPR_ZK_B          0x{r['statement']['b']}ULL",
          f"#define OPR_ZK_Y          0x{r['statement']['y']}ULL",
          _c_bytes("opr_zk_msg", hx(r["statement"]["msg_hex"])),
          _c_bytes("opr_zk_stream", hx(r["stream"])),
          _c_bytes2("opr_zk_com0", [hx(x["com_0"]) for x in e]),
          _c_bytes2("opr_zk_com1", [hx(x["com_1"]) for x in e]),
          _c_bytes2("opr_zk_com2", [hx(x["com_2"]) for x in e]),
          _c_int_list("opr_zk_e", [x["e"] for x in e]),
          _c_bytes2("opr_zk_view1", [hx(x["view_p1"]) for x in e]),
          _c_bytes2("opr_zk_view2", [hx(x["view_p2"]) for x in e]), ""]

    r = rows["hpks_stern_ring_sign"]
    e, st = r["expect"], r["statement"]
    k, rr = r["params"]["k"], r["params"]["rounds"]
    # Flattened to [k * rounds] in member-major order, which is exactly how
    # SternRingSig indexes its own arrays (i * rounds + r) -- so the consumer
    # compares element for element with no reshaping to get wrong.
    flat = [(i, j) for i in range(k) for j in range(rr)]
    L += ["/* Stern-F ring signing: the operation TODO #297 found a defect in.",
          " * Flat [k * rounds] arrays, member-major, matching SternRingSig.",
          " */",
          f"#define OPR_RING_N        {r['params']['n']}",
          f"#define OPR_RING_K        {k}",
          f"#define OPR_RING_ROUNDS   {rr}",
          f"#define OPR_RING_J        {r['params']['j']}",
          f"#define OPR_RING_CONSUMED {r['consumed']}",
          _c_bytes("opr_ring_stream", hx(r["stream"])),
          _c_bytes("opr_ring_msg", hx(st["msg"])),
          _c_bytes("opr_ring_e", hx(st["e"])),
          _c_bytes2("opr_ring_seeds", [hx(x) for x in st["seeds"]]),
          # Same little-endian transposition as opr_sfk_syndrome, and for the
          # same reason -- herradura.h packs row i into byte i/8.
          _c_bytes2("opr_ring_syndromes",
                    [int(x, 16).to_bytes(r["params"]["n_rows"] // 8, "little")
                     for x in st["syndromes"]]),
          _c_bytes2("opr_ring_c0", [hx(e["commits"][i][j][0]) for i, j in flat]),
          _c_bytes2("opr_ring_c1", [hx(e["commits"][i][j][1]) for i, j in flat]),
          _c_bytes2("opr_ring_c2", [hx(e["commits"][i][j][2]) for i, j in flat]),
          _c_int_list("opr_ring_challenge", [e["challenges"][i][j] for i, j in flat]),
          _c_bytes2("opr_ring_resp_a", [hx(e["responses"][i][j][0]) for i, j in flat]),
          _c_bytes2("opr_ring_resp_b", [hx(e["responses"][i][j][1]) for i, j in flat]), ""]

    r = rows["rnl_sigma_sign"]
    st, e = r["statement"], r["expect"]
    # No OPR_SIGMA_CONSUMED macro: `consumed` is null on this row by design
    # (C unbuffered, the other three block-buffered, TODO #293), so the C
    # consumer must not be able to assert a total that is only true of them.
    L += ["/* Ring-LWR Sigma signing: the inline mask draw TODO #294 was about.",
          " * The stream accepts on the FIRST attempt -- see operation_replay.json.",
          " */",
          f"#define OPR_SIGMA_N       {r['params']['n']}",
          f"#define OPR_SIGMA_Q       {r['params']['q']}",
          f"#define OPR_SIGMA_GAMMA   {r['params']['gamma']}",
          f"#define OPR_SIGMA_T       {r['params']['t']}",
          f"#define OPR_SIGMA_THRESH  {r['params']['threshold']}",
          _c_bytes("opr_sigma_msg", hx(st["msg_hex"])),
          _c_bytes("opr_sigma_stream", hx(r["stream"])),
          _c_i32_array("opr_sigma_s", _vec_unhex(st["s_poly"])),
          _c_i32_array("opr_sigma_m", _vec_unhex(st["m_poly"])),
          _c_i32_array("opr_sigma_cpub", _vec_unhex(st["c_poly"])),
          _c_i32_array("opr_sigma_w", _unhex_i32(e["w"])),
          _c_i32_array("opr_sigma_c", _unhex_i32(e["c"])),
          _c_i32_array("opr_sigma_z", _unhex_i32(e["z"])), ""]

    L += ["#endif /* OPERATION_REPLAY_VECTOR_H */", ""]
    return "\n".join(L)

def main() -> int:
    if "--capture-kkw" in sys.argv:
        vec = capture_kkw()
        with open(_KKW_OUT_PATH, "w") as f:
            f.write(json.dumps(vec, indent=2, sort_keys=False) + "\n")
        print(f"captured {os.path.basename(_KKW_OUT_PATH)} "
              f"(N={_KKW_N_PAR}, M={_KKW_M}, tau={_KKW_TAU})")
        # The C header is derived from the vector, so a re-capture must
        # re-emit it or --check would immediately go red.
        with open(_KKW_HDR_PATH, "w") as f:
            f.write(emit_kkw_header(vec))
        print(f"emitted {os.path.basename(_KKW_HDR_PATH)}")
        return check_kkw(_KKW_OUT_PATH)

    if "--emit-kkw-header" in sys.argv:
        with open(_KKW_OUT_PATH) as f:
            vec = json.load(f)
        with open(_KKW_HDR_PATH, "w") as f:
            f.write(emit_kkw_header(vec))
        print(f"emitted {os.path.basename(_KKW_HDR_PATH)} from "
              f"{os.path.basename(_KKW_OUT_PATH)}[n256]")
        return 0

    outputs = [(_OUT_PATH, generate()), (_RNL_OUT_PATH, generate_rnl()),
               (_V3_OUT_PATH, generate_v3()),
               (_REPLAY_OUT_PATH, gen_sampler_replay()),
               (_OPREPLAY_OUT_PATH, gen_operation_replay())]
    # (generated C view, its JSON source, the emitter).  Each is a pure
    # deterministic transform of its JSON, so unlike the JSON's other consumers
    # these ARE diffed -- regenerating one without the other fails rather than
    # drifting (TODO #296, #297).
    headers = [(_REPLAY_HDR_PATH, _REPLAY_OUT_PATH, emit_replay_header),
               (_OPREPLAY_HDR_PATH, _OPREPLAY_OUT_PATH, emit_operation_header)]
    if "--check" in sys.argv:
        rc = 0
        for path, vectors in outputs:
            text = json.dumps(vectors, indent=2, sort_keys=False) + "\n"
            with open(path) as f:
                existing = f.read()
            if existing != text:
                sys.stderr.write(f"{os.path.basename(path)} is stale — rerun "
                                  "python3 KAT/generate_kat.py\n")
                rc = 1
            else:
                print(f"{os.path.basename(path)} is up to date.")
        for hdr_path, src_path, emit in headers:
            hdr = emit(dict(outputs)[src_path])
            with open(hdr_path) as f:
                if f.read() != hdr:
                    sys.stderr.write(f"{os.path.basename(hdr_path)} is stale "
                                     "— rerun python3 KAT/generate_kat.py\n")
                    rc = 1
                else:
                    print(f"{os.path.basename(hdr_path)} matches "
                          f"{os.path.basename(src_path)}.")
        # The KKW vector is pinned, so it is CHECKED here, never diffed.
        rc |= check_kkw(_KKW_OUT_PATH)
        return rc
    for path, vectors in outputs:
        with open(path, "w") as f:
            f.write(json.dumps(vectors, indent=2, sort_keys=False) + "\n")
        print(f"Wrote {path}")
    for hdr_path, src_path, emit in headers:
        with open(hdr_path, "w") as f:
            f.write(emit(dict(outputs)[src_path]))
        print(f"Wrote {hdr_path}")
    # A plain run must not silently leave the pinned vector unexamined: it is
    # the one output this mode cannot rewrite, so say so and check it instead.
    print(f"NOTE: {os.path.basename(_KKW_OUT_PATH)} is pinned, not regenerated "
          "(hcred_prove_kkw is randomised) — use --capture-kkw to replace it.")
    return check_kkw(_KKW_OUT_PATH)


if __name__ == "__main__":
    sys.exit(main())
