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
    """One full two-party HKEX-RNL handshake at ring dimension n."""
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
        "note": ("Ring dimension and derived key width are separate quantities "
                 "(TODO #223): the deployed ring is 1024 while the session key "
                 "stays 256 bits.  The n=64 set exercises the small-ring path, "
                 "where they coincide and the key is n bits."),
        "deployed": gen_hkex_rnl(RNLN, "n1024"),
        "small_ring": gen_hkex_rnl(64, "n64"),
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


def main() -> int:
    outputs = [(_OUT_PATH, generate()), (_RNL_OUT_PATH, generate_rnl())]
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
        return rc
    for path, vectors in outputs:
        with open(path, "w") as f:
            f.write(json.dumps(vectors, indent=2, sort_keys=False) + "\n")
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
