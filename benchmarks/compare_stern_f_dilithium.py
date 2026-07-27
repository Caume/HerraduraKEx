"""TODO #138: benchmark HPKS-Stern-F (this suite's code-based PQC signature)
against liboqs's Dilithium, on the same hardware.

Drives the C CLI (HerraduraCli/herradura_cli, build with build_c.sh) for
HPKS-Stern-F rather than the FFI shim, since bindings/ffi/ intentionally
scopes out the Stern-F protocols (TODO #137).

liboqs is loaded via ctypes against its stable C API (OQS_SIG_*) if present;
this environment does not have liboqs installed, so this path is
*best-effort and has not been exercised end-to-end here* — if liboqs is
missing, the script reports the HPKS-Stern-F numbers alone and explains how
to install liboqs to complete the comparison.

Run:
    ./build_c.sh                                   # once
    python3 benchmarks/compare_stern_f_dilithium.py
"""

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(_ROOT, "HerraduraCli", "herradura_cli")
N = 30  # Stern-F sign/verify are much slower than the classical quartet


def bench_hpks_stern_f(tmp):
    if not os.path.exists(CLI):
        print(f"error: {CLI} not built — run ./build_c.sh first", file=sys.stderr)
        sys.exit(1)

    priv = os.path.join(tmp, "hs.pem")
    pub = os.path.join(tmp, "hs_pub.pem")
    msg = os.path.join(tmp, "msg.txt")
    sig = os.path.join(tmp, "sig.bin")

    with open(msg, "wb") as f:
        f.write(os.urandom(64))

    subprocess.run([CLI, "genpkey", "--algo", "hpks-stern", "--out", priv],
                    check=True, capture_output=True)
    subprocess.run([CLI, "pkey", "--in", priv, "--pubout", "--out", pub],
                    check=True, capture_output=True)

    t0 = time.perf_counter()
    for _ in range(N):
        subprocess.run([CLI, "sign", "--algo", "hpks-stern", "--key", priv,
                         "--in", msg, "--out", sig], check=True, capture_output=True)
    t1 = time.perf_counter()
    sign_ms = (t1 - t0) / N * 1e3

    t0 = time.perf_counter()
    for _ in range(N):
        r = subprocess.run([CLI, "verify", "--algo", "hpks-stern", "--pubkey", pub,
                             "--in", msg, "--sig", sig], check=True, capture_output=True)
        assert b"Signature OK" in r.stdout
    t1 = time.perf_counter()
    verify_ms = (t1 - t0) / N * 1e3

    return sign_ms, verify_ms


def try_load_liboqs():
    name = ctypes.util.find_library("oqs")
    if not name:
        return None
    try:
        return ctypes.CDLL(name)
    except OSError:
        return None


def bench_dilithium(lib, alg=b"Dilithium3"):
    """Best-effort OQS_SIG C API usage; not exercised in this environment
    since liboqs is not installed here. Verify against your local liboqs
    docs/headers if results look wrong."""

    class OQS_SIG(ctypes.Structure):
        _fields_ = [
            ("method_name", ctypes.c_char_p),
            ("alg_version", ctypes.c_char_p),
            ("claimed_nist_level", ctypes.c_ubyte),
            ("euf_cma", ctypes.c_ubyte),
            ("length_public_key", ctypes.c_size_t),
            ("length_secret_key", ctypes.c_size_t),
            ("length_signature", ctypes.c_size_t),
        ]

    lib.OQS_SIG_new.restype = ctypes.POINTER(OQS_SIG)
    lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
    sig_obj = lib.OQS_SIG_new(alg)
    if not sig_obj:
        return None

    s = sig_obj.contents
    pk = ctypes.create_string_buffer(s.length_public_key)
    sk = ctypes.create_string_buffer(s.length_secret_key)
    lib.OQS_SIG_keypair(sig_obj, pk, sk)

    msg = os.urandom(64)
    msg_buf = ctypes.create_string_buffer(msg, len(msg))
    sigbuf = ctypes.create_string_buffer(s.length_signature)
    siglen = ctypes.c_size_t(0)

    t0 = time.perf_counter()
    sigs = []
    for _ in range(N):
        lib.OQS_SIG_sign(sig_obj, sigbuf, ctypes.byref(siglen), msg_buf,
                          ctypes.c_size_t(len(msg)), sk)
        sigs.append(sigbuf.raw[:siglen.value])
    t1 = time.perf_counter()
    sign_ms = (t1 - t0) / N * 1e3

    t0 = time.perf_counter()
    for sd in sigs:
        sd_buf = ctypes.create_string_buffer(sd, len(sd))
        rc = lib.OQS_SIG_verify(sig_obj, msg_buf, ctypes.c_size_t(len(msg)),
                                 sd_buf, ctypes.c_size_t(len(sd)), pk)
        assert rc == 0
    t1 = time.perf_counter()
    verify_ms = (t1 - t0) / N * 1e3

    lib.OQS_SIG_free(sig_obj)
    return sign_ms, verify_ms


CAVEATS = """
Caveats (apples-to-oranges — see TODO #127 on this suite's proof-of-concept status):
  - HPKS-Stern-F here runs at demo parameters (N=256, t=16, 32 rounds, ~30-40 bit security
    per the CLI's own warning) rather than the production parameters the code documents
    (N>=17000 for ~128-bit security); Dilithium is a NIST-standardized, 128+ bit-secure
    scheme run through its reference/optimized implementation.
  - HPKS-Stern-F is driven through CLI process spawns (PEM parsing, file I/O) rather than a
    direct library call, which adds fixed overhead Dilithium's library-call path doesn't pay.
  - Treat the *ratio*, not the absolute numbers, as the signal, and re-run on your own
    hardware. Dilithium's numbers above were not validated end-to-end in the environment
    this script was written in (liboqs was not installed there) — sanity-check them against
    liboqs's own benchmark suite before citing this comparison.
"""


def main():
    with tempfile.TemporaryDirectory() as tmp:
        hpks_sign_ms, hpks_verify_ms = bench_hpks_stern_f(tmp)

    print(f"N = {N} operations per measurement\n")
    print(f"{'':24s}{'sign (ms/op)':>16s}{'verify (ms/op)':>18s}")
    print(f"{'HPKS-Stern-F (CLI/C)':24s}{hpks_sign_ms:16.2f}{hpks_verify_ms:18.2f}")

    lib = try_load_liboqs()
    if lib is None:
        print(f"{'Dilithium3 (liboqs)':24s}{'n/a':>16s}{'n/a':>18s}")
        print("\nliboqs not found on this system — install it to complete this comparison:")
        print("  https://github.com/open-quantum-safe/liboqs  (cmake build, or your")
        print("  distro's liboqs-dev / liboqs package if available).")
    else:
        result = bench_dilithium(lib)
        if result is None:
            print("liboqs loaded but OQS_SIG_new(\"Dilithium3\") failed "
                  "(algorithm not enabled in this build).")
        else:
            ed_sign_ms, ed_verify_ms = result
            print(f"{'Dilithium3 (liboqs)':24s}{ed_sign_ms:16.2f}{ed_verify_ms:18.2f}")
            print(f"\nHPKS-Stern-F is {hpks_sign_ms / ed_sign_ms:.1f}x slower to sign, "
                  f"{hpks_verify_ms / ed_verify_ms:.1f}x slower to verify, than Dilithium3.")

    print(CAVEATS)


if __name__ == "__main__":
    main()
