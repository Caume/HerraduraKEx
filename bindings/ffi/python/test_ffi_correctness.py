"""Correctness test: bindings/ffi/python/herradura_ffi.py (C via ctypes) must
produce byte-identical output to the native Python suite for the same
inputs, across the classical v1.4.0 quartet (HKEX-GF, HSKE, HPKS, HPKE).

Requires bindings/ffi/libherradura_ffi.so built (bash bindings/ffi/build.sh).

Run: python3 bindings/ffi/python/test_ffi_correctness.py
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "..", "..", "HerraduraCli"))

from herradura_ffi import Herradura, KEYBYTES  # noqa: E402
import primitives as P  # noqa: E402

KEYBITS = P.KEYBITS
POLY = P.GF_POLY.get(KEYBITS, 0x00000425)


def ba_from_bytes(data):
    return P.BitArray(KEYBITS, int.from_bytes(data, "big"))


def bytes_from_ba(ba):
    return ba.uint.to_bytes(KEYBYTES, "big")


def native_hkex_gf_pubkey(priv_bytes):
    priv = ba_from_bytes(priv_bytes).uint
    return P.gf_pow(P.GF_GEN, priv, POLY, KEYBITS).to_bytes(KEYBYTES, "big")


def native_hkex_gf_agree(my_priv_bytes, their_pub_bytes):
    priv = ba_from_bytes(my_priv_bytes).uint
    pub = ba_from_bytes(their_pub_bytes).uint
    return P.gf_pow(pub, priv, POLY, KEYBITS).to_bytes(KEYBYTES, "big")


def native_hske_encrypt(pt_bytes, key_bytes):
    pt = ba_from_bytes(pt_bytes)
    key = ba_from_bytes(key_bytes)
    return bytes_from_ba(P.fscx_revolve(pt, key, P.I_VALUE))


def native_hske_decrypt(ct_bytes, key_bytes):
    ct = ba_from_bytes(ct_bytes)
    key = ba_from_bytes(key_bytes)
    return bytes_from_ba(P.fscx_revolve(ct, key, P.R_VALUE))


def native_hpks_verify(msg_bytes, pub_bytes, R_bytes, s_bytes):
    msg = ba_from_bytes(msg_bytes)
    pub = ba_from_bytes(pub_bytes).uint
    R = ba_from_bytes(R_bytes)
    s = ba_from_bytes(s_bytes).uint
    e = P.fscx_revolve(R, msg, P.I_VALUE)
    lhs = P.gf_mul(P.gf_pow(P.GF_GEN, s, POLY, KEYBITS),
                    P.gf_pow(pub, e.uint, POLY, KEYBITS), POLY, KEYBITS)
    return lhs == R.uint


def native_hpke_encrypt(pt_bytes, r_bytes, C_bytes):
    """Mirrors the suite's inline El Gamal step, with r supplied (not random)
    so the FFI's internally-random r can be fed back in for comparison."""
    pt = ba_from_bytes(pt_bytes)
    r = ba_from_bytes(r_bytes).uint
    C = ba_from_bytes(C_bytes).uint
    R = P.gf_pow(P.GF_GEN, r, POLY, KEYBITS)
    enc_key = ba_from_bytes(P.gf_pow(C, r, POLY, KEYBITS).to_bytes(KEYBYTES, "big"))
    E = P.fscx_revolve(pt, enc_key, P.I_VALUE)
    return bytes_from_ba(P.BitArray(KEYBITS, R)), bytes_from_ba(E)


def native_hpke_decrypt(ct_bytes, R_bytes, priv_bytes):
    ct = ba_from_bytes(ct_bytes)
    R = ba_from_bytes(R_bytes).uint
    priv = ba_from_bytes(priv_bytes).uint
    dec_key = ba_from_bytes(P.gf_pow(R, priv, POLY, KEYBITS).to_bytes(KEYBYTES, "big"))
    return bytes_from_ba(P.fscx_revolve(ct, dec_key, P.R_VALUE))


def main():
    h = Herradura()
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(name)
            print(f"FAIL {name}: ffi={got.hex()} native={want.hex()}")
        else:
            print(f"ok   {name}")

    a_priv = h.random_bytes()
    b_priv = h.random_bytes()

    a_pub_ffi = h.hkex_gf_pubkey(a_priv)
    check("hkex_gf_pubkey", a_pub_ffi, native_hkex_gf_pubkey(a_priv))

    b_pub_ffi = h.hkex_gf_pubkey(b_priv)
    shared_ffi = h.hkex_gf_agree(a_priv, b_pub_ffi)
    check("hkex_gf_agree", shared_ffi, native_hkex_gf_agree(a_priv, b_pub_ffi))

    pt = h.random_bytes()
    key = h.random_bytes()
    ct_ffi = h.hske_encrypt(pt, key)
    check("hske_encrypt", ct_ffi, native_hske_encrypt(pt, key))
    dec_ffi = h.hske_decrypt(ct_ffi, key)
    check("hske_decrypt", dec_ffi, native_hske_decrypt(ct_ffi, key))

    msg = h.random_bytes()
    R_ffi, s_ffi = h.hpks_sign(msg, a_priv)
    # k is drawn randomly on both sides, so R/s can't be compared directly;
    # instead confirm the FFI signature verifies against a native verifier
    # fed the exact same (msg, pub, R, s), proving verify-side equivalence.
    ok_native_verify = native_hpks_verify(msg, a_pub_ffi, R_ffi, s_ffi)
    check("hpks_sign->native_verify", b"1" if ok_native_verify else b"0", b"1")
    ok_ffi_verify = h.hpks_verify(msg, a_pub_ffi, R_ffi, s_ffi)
    check("hpks_verify_self_consistent", b"1" if ok_ffi_verify else b"0", b"1")

    # HPKE: use a native r fed through hffi's own encrypt path is impossible
    # (r is drawn internally by the FFI), so instead verify the *decrypt*
    # side against a native encryption with a known r.
    r = h.random_bytes()
    R_native, ct_native = native_hpke_encrypt(pt, r, a_pub_ffi)
    dec_ffi_of_native = h.hpke_decrypt(ct_native, R_native, a_priv)
    check("hpke_decrypt(native_ct)", dec_ffi_of_native, pt)

    R_ffi_enc, ct_ffi_enc = h.hpke_encrypt(pt, a_pub_ffi)
    dec_native_of_ffi = native_hpke_decrypt(ct_ffi_enc, R_ffi_enc, a_priv)
    check("native_decrypt(hpke_ffi_ct)", dec_native_of_ffi, pt)

    if failures:
        print(f"\n{len(failures)} FAILURES: {failures}")
        sys.exit(1)
    print("\nAll FFI vs. native correctness checks passed.")


if __name__ == "__main__":
    main()
