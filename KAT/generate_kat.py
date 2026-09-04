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
import importlib.util
import json
import os
import sys

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


def capture_kkw() -> dict:
    """Capture one fresh reference transcript.  Uses os.urandom, so this is the
    one generator here whose output legitimately differs run to run."""
    n = suite._HCRED_DEFAULT_N
    m = suite._rnl_poly_add(suite._rnl_m_poly(n),
                            suite._rnl_rand_poly(n, RNLQ_), RNLQ_)
    seed_H = suite.BitArray.random(n)
    s, C, e_int = suite.hcred_user_keygen(m, n)
    y = suite.hcred_syndrome(seed_H, e_int, n)
    proof = hcred_prove_kkw(s, m, C, seed_H, y, n, N_par=_KKW_N_PAR,
                            M=_KKW_M, tau=_KKW_TAU, msg_bytes=_KKW_MSG)
    assert hcred_verify_kkw(m, C, seed_H, y, proof, n, _KKW_MSG), \
        "captured transcript does not verify"
    rows, row_bits, w_max = suite._hcred_params(n)
    return {
        "$schema": "HerraduraKEx HCRED-KKW KAT vector (TODO #266)",
        "suite_reference": "Herradura cryptographic suite.py",
        "note": ("VERIFY-SIDE vector: hcred_prove_kkw is not deterministic (one "
                 "os.urandom root per emulation), so this transcript is PINNED "
                 "rather than regenerated, and every language must CONSUME it "
                 "and accept.  Coefficient vectors are hex of the protocol's own "
                 "3-bytes-per-coefficient encoding, never JSON numbers.  "
                 "Demo-sized: production KKW is (N, M, tau) = (64, 343, 27) for "
                 "2^-128 soundness."),
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


def check_kkw(path: str) -> int:
    """Verify the pinned transcript instead of diffing a regeneration."""
    name = os.path.basename(path)
    if not os.path.exists(path):
        sys.stderr.write(f"{name} is missing — run "
                         "python3 KAT/generate_kat.py --capture-kkw\n")
        return 1
    with open(path) as f:
        vec = json.load(f)
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


def main() -> int:
    if "--capture-kkw" in sys.argv:
        vec = capture_kkw()
        with open(_KKW_OUT_PATH, "w") as f:
            f.write(json.dumps(vec, indent=2, sort_keys=False) + "\n")
        print(f"captured {os.path.basename(_KKW_OUT_PATH)} "
              f"(N={_KKW_N_PAR}, M={_KKW_M}, tau={_KKW_TAU})")
        return check_kkw(_KKW_OUT_PATH)

    outputs = [(_OUT_PATH, generate()), (_RNL_OUT_PATH, generate_rnl()),
               (_V3_OUT_PATH, generate_v3())]
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
        # The KKW vector is pinned, so it is CHECKED here, never diffed.
        rc |= check_kkw(_KKW_OUT_PATH)
        return rc
    for path, vectors in outputs:
        with open(path, "w") as f:
            f.write(json.dumps(vectors, indent=2, sort_keys=False) + "\n")
        print(f"Wrote {path}")
    # A plain run must not silently leave the pinned vector unexamined: it is
    # the one output this mode cannot rewrite, so say so and check it instead.
    print(f"NOTE: {os.path.basename(_KKW_OUT_PATH)} is pinned, not regenerated "
          "(hcred_prove_kkw is randomised) — use --capture-kkw to replace it.")
    return check_kkw(_KKW_OUT_PATH)


if __name__ == "__main__":
    sys.exit(main())
