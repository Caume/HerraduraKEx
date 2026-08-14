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
    vectors = generate()
    text = json.dumps(vectors, indent=2, sort_keys=False) + "\n"
    if "--check" in sys.argv:
        with open(_OUT_PATH) as f:
            existing = f.read()
        if existing != text:
            sys.stderr.write("KAT/classical_quartet.json is stale — rerun "
                              "python3 KAT/generate_kat.py\n")
            return 1
        print("KAT/classical_quartet.json is up to date.")
        return 0
    with open(_OUT_PATH, "w") as f:
        f.write(text)
    print(f"Wrote {_OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
