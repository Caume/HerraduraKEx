"""TODO #194: benchmark HSKE (this suite's FSCX_REVOLVE-based symmetric
encryption) against libsodium's AES-256-GCM and ChaCha20-Poly1305, on the
same hardware, so a reader has a reference point for whether the FSCX-based
construction is in the right ballpark against standard, widely-deployed
authenticated symmetric ciphers.

Uses the FFI-bound C implementation (bindings/ffi/) for HSKE, and libsodium
via ctypes (no libsodium-dev headers required — only the runtime .so, which
is what most systems already have installed).

*** Read the caveats below before drawing conclusions from these numbers. ***

Run:
    bash bindings/ffi/build.sh   # once, if not already built
    python3 benchmarks/compare_hske_aead.py
"""

import ctypes
import ctypes.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "bindings", "ffi", "python"))

from herradura_ffi import Herradura  # noqa: E402

N = 2000
BLOCK = 32  # HSKE's fixed block size (KEYBYTES); see herradura_ffi.py

CAVEATS = """
Caveats (apples-to-oranges — see TODO #127 on this suite's proof-of-concept status):
  - AES-256-GCM and ChaCha20-Poly1305 are production-hardened, constant-time (with AES-NI/
    dedicated instructions on most modern CPUs), AEAD ciphers with built-in integrity/
    authentication and over a decade (AES-GCM) or comparable (ChaCha20-Poly1305) scrutiny.
    HSKE is a research/pedagogical, un-authenticated stream-like construction built on
    FSCX_REVOLVE — it provides confidentiality only, with none of AEAD's tag/associated-data
    machinery, so this is not an apples-to-apples security comparison, only a raw-throughput
    reference point for the underlying transform.
  - HSKE here operates on a single fixed 32-byte block per call (this suite's KEYBYTES),
    while the AEAD ciphers below are benchmarked on the same 32-byte payload for a like-for-
    like per-call comparison; note real-world AEAD usage typically amortizes setup cost over
    much larger messages, which this micro-benchmark does not capture.
  - HSKE here runs through this repo's C FFI shim, not hand-tuned assembly/AES-NI-dispatched
    code like libsodium's backends — the comparison is "this suite's best current C path" vs.
    "a widely deployed reference library", not two implementations optimized to the same
    degree.
  - Absolute numbers vary a lot by CPU (esp. AES-NI availability); treat the *ratio* as the
    useful signal, not the microsecond values, and re-run on your own hardware before citing
    this.
"""


def load_libsodium():
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    lib = ctypes.CDLL(name)
    if lib.sodium_init() < 0:
        raise RuntimeError("sodium_init failed")
    return lib


def bench_hske(h):
    pt = h.random_bytes()
    key = h.random_bytes()

    t0 = time.perf_counter()
    cts = []
    for _ in range(N):
        ct = h.hske_encrypt(pt, key)
        cts.append(ct)
    t1 = time.perf_counter()
    enc_us = (t1 - t0) / N * 1e6

    t0 = time.perf_counter()
    for ct in cts:
        pt2 = h.hske_decrypt(ct, key)
        assert pt2 == pt
    t1 = time.perf_counter()
    dec_us = (t1 - t0) / N * 1e6

    return enc_us, dec_us


def _bench_aead(encrypt_fn, decrypt_fn, key_bytes, nonce_bytes):
    key = os.urandom(key_bytes)
    nonce = os.urandom(nonce_bytes)
    pt = os.urandom(BLOCK)

    t0 = time.perf_counter()
    cts = [encrypt_fn(pt, nonce, key) for _ in range(N)]
    t1 = time.perf_counter()
    enc_us = (t1 - t0) / N * 1e6

    t0 = time.perf_counter()
    for ct in cts:
        pt2 = decrypt_fn(ct, nonce, key)
        assert pt2 == pt
    t1 = time.perf_counter()
    dec_us = (t1 - t0) / N * 1e6

    return enc_us, dec_us


def bench_aes256gcm(lib):
    KEYBYTES, NPUBBYTES, ABYTES = 32, 12, 16

    if not lib.crypto_aead_aes256gcm_is_available():
        return None

    lib.crypto_aead_aes256gcm_encrypt.restype = ctypes.c_int
    lib.crypto_aead_aes256gcm_decrypt.restype = ctypes.c_int

    def encrypt_fn(pt, nonce, key):
        ct = ctypes.create_string_buffer(BLOCK + ABYTES)
        ct_len = ctypes.c_ulonglong(0)
        pt_buf = ctypes.create_string_buffer(pt, len(pt))
        rc = lib.crypto_aead_aes256gcm_encrypt(
            ct, ctypes.byref(ct_len), pt_buf, ctypes.c_ulonglong(len(pt)),
            None, ctypes.c_ulonglong(0), None,
            ctypes.create_string_buffer(nonce, NPUBBYTES),
            ctypes.create_string_buffer(key, KEYBYTES))
        assert rc == 0
        return ct.raw[:ct_len.value]

    def decrypt_fn(ct, nonce, key):
        pt = ctypes.create_string_buffer(len(ct) - ABYTES)
        pt_len = ctypes.c_ulonglong(0)
        ct_buf = ctypes.create_string_buffer(ct, len(ct))
        rc = lib.crypto_aead_aes256gcm_decrypt(
            pt, ctypes.byref(pt_len), None, ct_buf, ctypes.c_ulonglong(len(ct)),
            None, ctypes.c_ulonglong(0),
            ctypes.create_string_buffer(nonce, NPUBBYTES),
            ctypes.create_string_buffer(key, KEYBYTES))
        assert rc == 0
        return pt.raw[:pt_len.value]

    return _bench_aead(encrypt_fn, decrypt_fn, KEYBYTES, NPUBBYTES)


def bench_chacha20poly1305(lib):
    KEYBYTES, NPUBBYTES, ABYTES = 32, 8, 16

    lib.crypto_aead_chacha20poly1305_encrypt.restype = ctypes.c_int
    lib.crypto_aead_chacha20poly1305_decrypt.restype = ctypes.c_int

    def encrypt_fn(pt, nonce, key):
        ct = ctypes.create_string_buffer(BLOCK + ABYTES)
        ct_len = ctypes.c_ulonglong(0)
        pt_buf = ctypes.create_string_buffer(pt, len(pt))
        rc = lib.crypto_aead_chacha20poly1305_encrypt(
            ct, ctypes.byref(ct_len), pt_buf, ctypes.c_ulonglong(len(pt)),
            None, ctypes.c_ulonglong(0), None,
            ctypes.create_string_buffer(nonce, NPUBBYTES),
            ctypes.create_string_buffer(key, KEYBYTES))
        assert rc == 0
        return ct.raw[:ct_len.value]

    def decrypt_fn(ct, nonce, key):
        pt = ctypes.create_string_buffer(len(ct) - ABYTES)
        pt_len = ctypes.c_ulonglong(0)
        ct_buf = ctypes.create_string_buffer(ct, len(ct))
        rc = lib.crypto_aead_chacha20poly1305_decrypt(
            pt, ctypes.byref(pt_len), None, ct_buf, ctypes.c_ulonglong(len(ct)),
            None, ctypes.c_ulonglong(0),
            ctypes.create_string_buffer(nonce, NPUBBYTES),
            ctypes.create_string_buffer(key, KEYBYTES))
        assert rc == 0
        return pt.raw[:pt_len.value]

    return _bench_aead(encrypt_fn, decrypt_fn, KEYBYTES, NPUBBYTES)


def main():
    h = Herradura()
    hske_enc_us, hske_dec_us = bench_hske(h)

    rows = [("HSKE (FFI/C)", hske_enc_us, hske_dec_us)]

    try:
        lib = load_libsodium()
        have_libsodium = True
    except OSError:
        have_libsodium = False

    if have_libsodium:
        gcm = bench_aes256gcm(lib)
        if gcm is not None:
            rows.append(("AES-256-GCM (libsodium)", gcm[0], gcm[1]))
        else:
            print("AES-NI not available on this CPU — skipped AES-256-GCM.")

        chacha = bench_chacha20poly1305(lib)
        rows.append(("ChaCha20-Poly1305 (libsodium)", chacha[0], chacha[1]))

    print(f"N = {N} operations per measurement, {BLOCK}-byte payload\n")
    print(f"{'':32s}{'encrypt (us/op)':>18s}{'decrypt (us/op)':>18s}")
    for name, enc_us, dec_us in rows:
        print(f"{name:32s}{enc_us:18.2f}{dec_us:18.2f}")

    if len(rows) > 1:
        print()
        for name, enc_us, dec_us in rows[1:]:
            print(f"HSKE is {hske_enc_us / enc_us:.1f}x slower to encrypt, "
                  f"{hske_dec_us / dec_us:.1f}x slower to decrypt, than {name}.")
    else:
        print("libsodium not found — skipped AEAD comparison.")

    print(CAVEATS)


if __name__ == "__main__":
    main()
