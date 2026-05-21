"""
hello_herradura.py — Minimal Python integration example for the Herradura suite.

Run from the repo root:
    python3 docs/examples/python/hello_herradura.py

The suite file has spaces in its name, so it must be loaded via importlib.
The pattern shown below works from any directory as long as you set SUITE_PATH.
"""

import importlib.util
import pathlib

# ── Load the Herradura module ─────────────────────────────────────────────────
SUITE_PATH = pathlib.Path(__file__).parent.parent.parent.parent / "Herradura cryptographic suite.py"
_spec = importlib.util.spec_from_file_location("herradura", SUITE_PATH)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)


# ── HKEX-GF: Diffie-Hellman over GF(2^256)* ─────────────────────────────────
print("=== HKEX-GF key exchange ===")

n    = h.KEYBITS          # 256
poly = h.GF_POLY[n]
g    = h.GF_GEN           # 3

alice_priv = h.BitArray.random(n)
bob_priv   = h.BitArray.random(n)

alice_pub = h.BitArray(n, h.gf_pow(g, alice_priv.uint, poly, n))
bob_pub   = h.BitArray(n, h.gf_pow(g, bob_priv.uint,   poly, n))

alice_shared = h.BitArray(n, h.gf_pow(bob_pub.uint,   alice_priv.uint, poly, n))
bob_shared   = h.BitArray(n, h.gf_pow(alice_pub.uint, bob_priv.uint,   poly, n))

print(f"Alice shared: {alice_shared.hex}")
print(f"Bob   shared: {bob_shared.hex}")
print("✓ shared secrets agree" if alice_shared == bob_shared else "✗ shared secrets differ!")


# ── HSKE: symmetric encryption with the derived shared key ────────────────────
print("\n=== HSKE symmetric encryption ===")

plaintext  = h.BitArray.random(n)
ciphertext = h.fscx_revolve(plaintext, alice_shared, h.I_VALUE)
recovered  = h.fscx_revolve(ciphertext, alice_shared, h.R_VALUE)

print(f"Plaintext : {plaintext.hex}")
print(f"Ciphertext: {ciphertext.hex}")
print(f"Recovered : {recovered.hex}")
print("✓ decryption correct" if plaintext == recovered else "✗ decryption failed!")


# ── HKEX-RNL: Ring-LWR key exchange (PQC-hardened) ───────────────────────────
print(f"\n=== HKEX-RNL (Ring-LWR, n={n}, q={h.RNLQ}) ===")

m_base  = h._rnl_m_poly(n)
a_rand  = h._rnl_rand_poly(n, h.RNLQ)
m_blind = h._rnl_poly_add(m_base, a_rand, h.RNLQ)

# Use the public aliases added in v1.7.4
sA, CA = h.hkex_rnl_keygen(m_blind, n, h.RNLQ, h.RNLP, h.RNLB)
sB, CB = h.hkex_rnl_keygen(m_blind, n, h.RNLQ, h.RNLP, h.RNLB)

kA, hint_A = h.hkex_rnl_agree(sA, CB, h.RNLQ, h.RNLP, h.RNLPP, n, n)
kB         = h.hkex_rnl_agree(sB, CA, h.RNLQ, h.RNLP, h.RNLPP, n, n, hint=hint_A)

# KDF: seed = ROL(K, n/8); sk = NL-FSCX-v1(seed, K, n/4)
skA = h.nl_fscx_revolve_v1(kA.rotated(n // 8), kA, n // 4)
skB = h.nl_fscx_revolve_v1(kB.rotated(n // 8), kB, n // 4)

print(f"sk (Alice): {skA.hex}")
print(f"sk (Bob)  : {skB.hex}")
print("✓ Ring-LWR keys agree" if kA == kB else "✗ Ring-LWR key disagreement!")


# ── HPKS-Stern-F: code-based signature (PQC) ─────────────────────────────────
print(f"\n=== HPKS-Stern-F (N={n}, t={h.SDFT}, rounds={h.SDFR}) ===")

seed, e_int, syndrome = h.stern_f_keygen(n)
msg = h.BitArray.random(n)
sig = h.hpks_stern_f_sign(msg, e_int, seed, syndrome, n)

result = h.hpks_stern_f_verify(msg, sig, seed, syndrome, n)
print("✓ Stern-F signature verified" if result else "✗ Stern-F signature invalid!")
