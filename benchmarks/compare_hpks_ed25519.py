"""TODO #138: benchmark HPKS (HerraduraKEx's Schnorr-style signature) against
libsodium's Ed25519, on the same hardware, so a reader has a reference point
for whether the FSCX-based approach is in the right ballpark.

Uses the FFI-bound C implementation (bindings/ffi/) for HPKS, and libsodium
via ctypes (no libsodium-dev headers required — only the runtime .so, which
is what most systems already have installed).

*** Read the caveats below before drawing conclusions from these numbers. ***

Run:
    bash bindings/ffi/build.sh   # once, if not already built
    python3 benchmarks/compare_hpks_ed25519.py
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
  - libsodium's Ed25519 is a production-hardened, constant-time, heavily optimized
    implementation with over a decade of scrutiny. HerraduraKEx is a research/pedagogical
    suite; HPKS's DLP-based security is classical (broken by Shor's algorithm) and its
    constant-time posture has not received the same audit depth as libsodium.
  - HPKS here runs through this repo's C FFI shim, not hand-tuned assembly like libsodium's
    ref10 backend — the comparison is "this suite's best current C path" vs. "a widely
    deployed reference library", not two implementations optimized to the same degree.
  - Absolute numbers vary a lot by CPU; treat the *ratio* as the useful signal, not the
    microsecond values, and re-run on your own hardware before citing this.
  - This script measures wall-clock latency for single-threaded sign/verify only; it says
    nothing about maturity, side-channel resistance, or protocol-level security properties.
"""


def load_libsodium():
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    lib = ctypes.CDLL(name)
    if lib.sodium_init() < 0:
        raise RuntimeError("sodium_init failed")
    return lib


def bench_hpks(h):
    priv = h.random_bytes()
    pub = h.hkex_gf_pubkey(priv)
    msg = h.random_bytes()

    t0 = time.perf_counter()
    sigs = [h.hpks_sign(msg, priv) for _ in range(N)]
    t1 = time.perf_counter()
    sign_us = (t1 - t0) / N * 1e6

    t0 = time.perf_counter()
    for R, s in sigs:
        ok = h.hpks_verify(msg, pub, R, s)
        assert ok
    t1 = time.perf_counter()
    verify_us = (t1 - t0) / N * 1e6

    return sign_us, verify_us


def bench_ed25519(lib):
    SEEDBYTES = 32
    PKBYTES = 32
    SKBYTES = 64
    SIGBYTES = 64

    seed = os.urandom(SEEDBYTES)
    pk = ctypes.create_string_buffer(PKBYTES)
    sk = ctypes.create_string_buffer(SKBYTES)
    lib.crypto_sign_ed25519_seed_keypair(pk, sk, seed)

    msg = os.urandom(32)
    msg_buf = ctypes.create_string_buffer(msg, len(msg))

    sig = ctypes.create_string_buffer(SIGBYTES)
    siglen = ctypes.c_ulonglong(0)

    t0 = time.perf_counter()
    sigs = []
    for _ in range(N):
        lib.crypto_sign_ed25519_detached(sig, ctypes.byref(siglen), msg_buf,
                                          ctypes.c_ulonglong(len(msg)), sk)
        sigs.append(sig.raw[:SIGBYTES])
    t1 = time.perf_counter()
    sign_us = (t1 - t0) / N * 1e6

    t0 = time.perf_counter()
    for s in sigs:
        s_buf = ctypes.create_string_buffer(s, len(s))
        rc = lib.crypto_sign_ed25519_verify_detached(s_buf, msg_buf,
                                                       ctypes.c_ulonglong(len(msg)), pk)
        assert rc == 0
    t1 = time.perf_counter()
    verify_us = (t1 - t0) / N * 1e6

    return sign_us, verify_us


def main():
    h = Herradura()
    hpks_sign_us, hpks_verify_us = bench_hpks(h)

    try:
        lib = load_libsodium()
        ed_sign_us, ed_verify_us = bench_ed25519(lib)
        have_ed25519 = True
    except OSError:
        have_ed25519 = False

    print(f"N = {N} operations per measurement\n")
    print(f"{'':20s}{'sign (us/op)':>16s}{'verify (us/op)':>18s}")
    print(f"{'HPKS (FFI/C)':20s}{hpks_sign_us:16.2f}{hpks_verify_us:18.2f}")
    if have_ed25519:
        print(f"{'Ed25519 (libsodium)':20s}{ed_sign_us:16.2f}{ed_verify_us:18.2f}")
        print(f"\nHPKS is {hpks_sign_us / ed_sign_us:.1f}x slower to sign, "
              f"{hpks_verify_us / ed_verify_us:.1f}x slower to verify, than Ed25519.")
    else:
        print("libsodium not found — skipped Ed25519 comparison.")

    print(CAVEATS)


if __name__ == "__main__":
    main()
