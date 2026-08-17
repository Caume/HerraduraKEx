"""TODO #194: benchmark HKEX-GF (this suite's DH-style key exchange over
GF(2^n)*) against libsodium's X25519 (Curve25519 ECDH), on the same
hardware, so a reader has a reference point for whether the FSCX/GF-based
construction is in the right ballpark against the standard, widely-deployed
elliptic-curve equivalent.

Uses the FFI-bound C implementation (bindings/ffi/) for HKEX-GF, and
libsodium via ctypes (no libsodium-dev headers required — only the runtime
.so, which is what most systems already have installed).

*** Read the caveats below before drawing conclusions from these numbers. ***

Run:
    bash bindings/ffi/build.sh   # once, if not already built
    python3 benchmarks/compare_hkex_x25519.py
"""

import ctypes
import ctypes.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "bindings", "ffi", "python"))

from herradura_ffi import Herradura  # noqa: E402

N = 500

CAVEATS = """
Caveats (apples-to-oranges — see TODO #127 on this suite's proof-of-concept status):
  - libsodium's X25519 is a production-hardened, constant-time, heavily optimized
    implementation with over a decade of scrutiny. HerraduraKEx is a research/pedagogical
    suite; HKEX-GF's security rests on the discrete-log problem over GF(2^n)*, which is
    classical (broken by Shor's algorithm, and the specific group/parameters here have not
    received anywhere near the cryptanalytic attention Curve25519 has).
  - HKEX-GF here runs through this repo's C FFI shim, not hand-tuned assembly like
    libsodium's ref10 backend — the comparison is "this suite's best current C path" vs.
    "a widely deployed reference library", not two implementations optimized to the same
    degree.
  - Absolute numbers vary a lot by CPU; treat the *ratio* as the useful signal, not the
    microsecond values, and re-run on your own hardware before citing this.
  - This script measures wall-clock latency for single-threaded keypair generation and
    shared-secret agreement only; it says nothing about maturity, side-channel resistance,
    or protocol-level security properties. See TODO #186's methodology note (same caveat
    class, for HPKS-Stern-F vs. ML-DSA-65) for how these comparisons are meant to be read.
"""


def load_libsodium():
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    lib = ctypes.CDLL(name)
    if lib.sodium_init() < 0:
        raise RuntimeError("sodium_init failed")
    return lib


def bench_hkex_gf(h):
    t0 = time.perf_counter()
    keys = []
    for _ in range(N):
        priv = h.random_bytes()
        pub = h.hkex_gf_pubkey(priv)
        keys.append((priv, pub))
    t1 = time.perf_counter()
    keygen_us = (t1 - t0) / N * 1e6

    # Pair up consecutive keypairs to perform agreement (Alice/Bob roles).
    pairs = list(zip(keys[0::2], keys[1::2]))
    t0 = time.perf_counter()
    for (a_priv, a_pub), (b_priv, b_pub) in pairs:
        sk_a = h.hkex_gf_agree(a_priv, b_pub)
        sk_b = h.hkex_gf_agree(b_priv, a_pub)
        assert sk_a == sk_b
    t1 = time.perf_counter()
    agree_us = (t1 - t0) / len(pairs) * 1e6

    return keygen_us, agree_us


X25519_BYTES = 32
X25519_BASEPOINT = bytes([9] + [0] * 31)


def bench_x25519(lib):
    lib.crypto_scalarmult_curve25519_base.restype = ctypes.c_int
    lib.crypto_scalarmult_curve25519.restype = ctypes.c_int

    t0 = time.perf_counter()
    keys = []
    for _ in range(N):
        priv = os.urandom(X25519_BYTES)
        priv_buf = ctypes.create_string_buffer(priv, X25519_BYTES)
        pub_buf = ctypes.create_string_buffer(X25519_BYTES)
        rc = lib.crypto_scalarmult_curve25519_base(pub_buf, priv_buf)
        assert rc == 0
        keys.append((priv, pub_buf.raw[:X25519_BYTES]))
    t1 = time.perf_counter()
    keygen_us = (t1 - t0) / N * 1e6

    pairs = list(zip(keys[0::2], keys[1::2]))
    t0 = time.perf_counter()
    for (a_priv, a_pub), (b_priv, b_pub) in pairs:
        a_priv_buf = ctypes.create_string_buffer(a_priv, X25519_BYTES)
        b_pub_buf = ctypes.create_string_buffer(b_pub, X25519_BYTES)
        sk_a = ctypes.create_string_buffer(X25519_BYTES)
        rc = lib.crypto_scalarmult_curve25519(sk_a, a_priv_buf, b_pub_buf)
        assert rc == 0

        b_priv_buf = ctypes.create_string_buffer(b_priv, X25519_BYTES)
        a_pub_buf = ctypes.create_string_buffer(a_pub, X25519_BYTES)
        sk_b = ctypes.create_string_buffer(X25519_BYTES)
        rc = lib.crypto_scalarmult_curve25519(sk_b, b_priv_buf, a_pub_buf)
        assert rc == 0
        assert sk_a.raw == sk_b.raw
    t1 = time.perf_counter()
    agree_us = (t1 - t0) / len(pairs) * 1e6

    return keygen_us, agree_us


def main():
    h = Herradura()
    hkex_keygen_us, hkex_agree_us = bench_hkex_gf(h)

    try:
        lib = load_libsodium()
        x25519_keygen_us, x25519_agree_us = bench_x25519(lib)
        have_x25519 = True
    except OSError:
        have_x25519 = False

    print(f"N = {N} operations per measurement\n")
    print(f"{'':22s}{'keygen (us/op)':>18s}{'agree (us/op)':>18s}")
    print(f"{'HKEX-GF (FFI/C)':22s}{hkex_keygen_us:18.2f}{hkex_agree_us:18.2f}")
    if have_x25519:
        print(f"{'X25519 (libsodium)':22s}{x25519_keygen_us:18.2f}{x25519_agree_us:18.2f}")
        print(f"\nHKEX-GF is {hkex_keygen_us / x25519_keygen_us:.1f}x slower to generate a "
              f"keypair, {hkex_agree_us / x25519_agree_us:.1f}x slower to agree, than X25519.")
    else:
        print("libsodium not found — skipped X25519 comparison.")

    print(CAVEATS)


if __name__ == "__main__":
    main()
