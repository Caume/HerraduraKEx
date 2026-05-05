# HerraduraCli/primitives.py — loads the Herradura suite and re-exports symbols (v1.5.23)
# Uses importlib.util to load a file with spaces in its name without renaming it.
import importlib.util
import os

_SUITE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', 'Herradura cryptographic suite.py')
)


def _load_suite():
    spec = importlib.util.spec_from_file_location('herradura_suite', _SUITE_PATH)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_s = _load_suite()

# ── Primitive functions ──────────────────────────────────────────────────────
BitArray               = _s.BitArray
fscx_revolve           = _s.fscx_revolve
nl_fscx_revolve_v1     = _s.nl_fscx_revolve_v1
nl_fscx_revolve_v2     = _s.nl_fscx_revolve_v2
nl_fscx_revolve_v2_inv = _s.nl_fscx_revolve_v2_inv
gf_mul                 = _s.gf_mul
gf_pow                 = _s.gf_pow
hfscx_256              = _s.hfscx_256
_HFSCX256_IV_BYTES     = _s._HFSCX256_IV_BYTES

# ── Ring-LWR / HKEX-RNL ─────────────────────────────────────────────────────
_rnl_keygen         = _s._rnl_keygen
_rnl_agree          = _s._rnl_agree
_rnl_hint           = _s._rnl_hint
_rnl_reconcile_bits = _s._rnl_reconcile_bits
_rnl_m_poly         = _s._rnl_m_poly
_rnl_rand_poly      = _s._rnl_rand_poly
_rnl_poly_add       = _s._rnl_poly_add
_rnl_lift           = _s._rnl_lift
_rnl_poly_mul       = _s._rnl_poly_mul

# ── Stern-F (code-based PQC) ─────────────────────────────────────────────────
stern_f_keygen            = _s.stern_f_keygen
hpks_stern_f_sign         = _s.hpks_stern_f_sign
hpks_stern_f_verify       = _s.hpks_stern_f_verify
hpke_stern_f_encap_with_e = _s.hpke_stern_f_encap_with_e
hpke_stern_f_decap        = _s.hpke_stern_f_decap

# ── Module-level constants ───────────────────────────────────────────────────
KEYBITS = _s.KEYBITS          # default key width (256)
GF_POLY = _s.GF_POLY          # irreducible poly dict keyed by bit width
GF_GEN  = _s.GF_GEN           # DH generator (3)
ORD     = _s.ORD               # group order = 2^KEYBITS − 1
RNLQ   = _s.RNLQ              # Ring-LWR prime modulus (65537)
RNLP   = _s.RNLP              # Ring-LWR public-key rounding modulus (4096)
RNLPP  = _s.RNLPP             # Ring-LWR reconciliation modulus (2)
RNLB   = _s.RNLB              # Ring-LWR CBD eta (1)
I_VALUE = _s.I_VALUE          # FSCX encrypt steps (KEYBITS/4 = 64)
R_VALUE = _s.R_VALUE          # FSCX decrypt steps (3*KEYBITS/4 = 192)
SDFT   = _s.SDFT              # Stern-F error weight t
SDFNR  = _s.SDFNR             # Stern-F parity-check rows
SDFR   = _s.SDFR              # Stern-F Fiat-Shamir rounds
