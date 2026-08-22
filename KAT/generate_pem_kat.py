#!/usr/bin/env python3
"""TODO #227: fixed wire-format (PEM) Known-Answer-Test artifacts for the CLI layer.

TODO #226 pinned the *suite* layer — ring multiplication, rounding, reconciliation,
hint packing, the KDF.  It did not pin the CLI layer, and that is where every bug
TODO #223 shipped actually lived:

  * `loadKey` (Go) and `_decode_session_key` (Python) read an HKEX-RNL RESPONSE
    PEM's ring-dimension field as the derived key width.
  * C's hybrid response encoder wrote a hardcoded n=256 into that field.
  * Python's and Go's hybrid combiners serialised K1 at the ring dimension.

None of those touch the suite primitives, so #226's vectors are blind to them.
The existing CLI tests were blind too: `test_encrypt.sh` pins `--bits 64`, where
the ring dimension and the key width are the same number, so nothing there could
distinguish the two.

This script emits byte-exact PEM artifacts under `KAT/pem/`.  The point is that
each CLI must **consume** them and reproduce an expected output — consumption is
the direction the bugs broke.  Producing a keypair cannot be pinned this way at
all, because `genpkey` draws its secrets and nonces from os.urandom; here those
are fixed inputs, derived by the same deterministic expansion TODO #226 uses.

Artifacts per ring size:

    <tag>_alice_priv.pem     HKEX-RNL PRIVATE KEY  (s_A, m_blind, n, n_A)
    <tag>_alice_pub.pem      HKEX-RNL PUBLIC KEY   (C_A, m_blind, n, n_A)
    <tag>_bob_priv.pem       HKEX-RNL PRIVATE KEY  (s_B, m_blind, n, n_A)
    <tag>_bob_response.pem   HKEX-RNL RESPONSE     (K_B, C_B, hint, n, len, n_B)
    <tag>_alice_session.pem  HERRADURA SESSION KEY  — what Alice must derive
    <tag>_hske_ct.pem        HSKE ciphertext under the key read from the RESPONSE

The last one is the direct regression test for the `loadKey` width bug: a CLI that
reads the RESPONSE PEM's ring dimension as the key width encrypts at the wrong
width and produces a different ciphertext.

Usage:
    python3 KAT/generate_pem_kat.py            # (re)write KAT/pem/
    python3 KAT/generate_pem_kat.py --check     # verify the checked-in files
"""
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_PEM_DIR = os.path.join(_HERE, "pem")
_CLI_DIR = os.path.join(_ROOT, "HerraduraCli")

sys.path.insert(0, _CLI_DIR)
_cwd = os.getcwd()
os.chdir(_CLI_DIR)          # primitives.py resolves the suite relative to itself
try:
    import herradura as cli
finally:
    os.chdir(_cwd)

suite = cli._suite_mod

# The same deterministic expansion TODO #226 uses, so both KATs describe the same
# handshake and a mismatch between them is itself a signal.
_gen_spec = importlib.util.spec_from_file_location(
    "generate_kat", os.path.join(_HERE, "generate_kat.py"))
_gen = importlib.util.module_from_spec(_gen_spec)
_gen_spec.loader.exec_module(_gen)

RNLQ, RNLP, RNLPP, RNLB = suite.RNLQ, suite.RNLP, suite.RNLPP, suite.RNLB

# Fixed nonces. Real ones come from os.urandom; a KAT supplies them as inputs.
N_A = bytes(range(0x40, 0x60))          # 32 bytes: 40 41 .. 5f
N_B = bytes(range(0xA0, 0xC0))          # 32 bytes: a0 a1 .. bf
MESSAGE = b"HerraduraKEx TODO #227 wire-format KAT message!!"


def build(n: int, tag: str) -> dict:
    """One full handshake, rendered as the PEMs the CLIs exchange."""
    key_bits = cli._rnl_key_bits(n)

    m_base = suite._rnl_m_poly(n)
    a_rand = _gen.det_rand_poly(b"HerraduraKEx-TODO226-a_rand-" + tag.encode(), n, RNLQ)
    m_blind = suite._rnl_poly_add(m_base, a_rand, RNLQ)
    s_a = _gen.det_cbd_poly(b"HerraduraKEx-TODO226-alice-s-" + tag.encode(), n, RNLB, RNLQ)
    s_b = _gen.det_cbd_poly(b"HerraduraKEx-TODO226-bob-s-" + tag.encode(), n, RNLB, RNLQ)

    c_a = cli._rnl_derive_C(m_blind, s_a, n)
    c_b = cli._rnl_derive_C(m_blind, s_b, n)

    # Bob's step: reconcile against Alice's C, publish K_B and the hint.
    k_bob, hint = suite._rnl_agree(s_b, c_a, RNLQ, RNLP, RNLPP, n, key_bits)
    k_bob_int = cli._rnl_contributory_kdf(k_bob.uint, key_bits, N_A, N_B)
    # `--kdf none` is the default and applies no post-hash, so this is the raw
    # contributory output; a CLI defaulting differently would diverge here.

    # Alice's step: same reconciliation from the other side, same KDF inputs.
    k_alice = suite._rnl_agree(s_a, c_b, RNLQ, RNLP, RNLPP, n, key_bits, hint)
    k_alice_int = cli._rnl_contributory_kdf(k_alice.uint, key_bits, N_A, N_B)
    assert k_alice_int == k_bob_int, f"TODO #227: session keys disagree at n={n}"

    # HSKE under the key as read from the RESPONSE PEM — the loadKey width probe.
    key_ba = suite.BitArray(key_bits, k_bob_int)
    pt_int = int.from_bytes(MESSAGE[: key_bits // 8].ljust(key_bits // 8, b"\0"), "big")
    ct = suite.fscx_revolve(suite.BitArray(key_bits, pt_int), key_ba, key_bits // 4)

    return {
        f"{tag}_alice_priv.pem": cli._encode_rnl_privkey(s_a, m_blind, n, N_A),
        f"{tag}_alice_pub.pem": cli._encode_rnl_pubkey(c_a, m_blind, n, N_A),
        f"{tag}_bob_priv.pem": cli._encode_rnl_privkey(s_b, m_blind, n, N_A),
        f"{tag}_bob_response.pem": cli._encode_rnl_response(k_bob_int, c_b, hint, n, N_B),
        f"{tag}_alice_session.pem": cli._encode_session_key(k_alice_int, key_bits),
        f"{tag}_hske_ct.pem": cli._encode_sym_ct("hske", ct.uint, key_bits),
    }


def build_all() -> dict:
    out = {}
    out.update(build(suite.RNLN, "n1024"))
    out.update(build(64, "n64"))
    # The plaintext the ciphertext decrypts to, as a file the tests can diff.
    kb = cli._rnl_key_bits(suite.RNLN) // 8
    out["message_n1024.bin"] = MESSAGE[:kb].ljust(kb, b"\0")
    kb64 = cli._rnl_key_bits(64) // 8
    out["message_n64.bin"] = MESSAGE[:kb64].ljust(kb64, b"\0")
    return out


def main() -> int:
    artifacts = build_all()
    check = "--check" in sys.argv
    if not check:
        os.makedirs(_PEM_DIR, exist_ok=True)
    rc = 0
    for name, body in sorted(artifacts.items()):
        path = os.path.join(_PEM_DIR, name)
        data = body if isinstance(body, bytes) else body.encode()
        if check:
            if not os.path.exists(path):
                sys.stderr.write(f"KAT/pem/{name} is missing — rerun "
                                  "python3 KAT/generate_pem_kat.py\n")
                rc = 1
                continue
            with open(path, "rb") as f:
                if f.read() != data:
                    sys.stderr.write(f"KAT/pem/{name} is stale — rerun "
                                      "python3 KAT/generate_pem_kat.py\n")
                    rc = 1
        else:
            with open(path, "wb") as f:
                f.write(data)
    if check:
        if rc == 0:
            print(f"KAT/pem/ is up to date ({len(artifacts)} artifacts).")
        return rc
    print(f"Wrote {len(artifacts)} artifacts to {_PEM_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
