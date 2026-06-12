# HerraduraCli/primitives.py — loads the Herradura suite and re-exports symbols (v1.9.15)
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
hske_nl_aead_encrypt   = _s.hske_nl_aead_encrypt
hske_nl_aead_decrypt   = _s.hske_nl_aead_decrypt
_HFSCX256_IV_BYTES     = _s._HFSCX256_IV_BYTES
_RNL_KDF_DC_256        = _s._RNL_KDF_DC_256

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

# ── ZKP-RNL: Ring-LWR Σ-protocol ─────────────────────────────────────────────
rnl_sigma_sign   = _s.rnl_sigma_sign
rnl_sigma_verify = _s.rnl_sigma_verify

# ── ZKP-NL: NL-FSCX ZKBoo ────────────────────────────────────────────────────
zkp_nl_keygen = _s.zkp_nl_keygen
zkp_nl_prove  = _s.zkp_nl_prove
zkp_nl_verify = _s.zkp_nl_verify

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
_ZKP_NL_DEFAULT_N   = _s._ZKP_NL_DEFAULT_N    # ZKBoo CLI default bit width (8)
_ZKP_NL_PROD_ROUNDS = _s._ZKP_NL_PROD_ROUNDS  # ZKBoo production rounds (219)

# ── 78.A FPE / 78.B Tweakable / 78.J Accumulator ───────────────────────────
fpe_encrypt   = _s.fpe_encrypt
fpe_decrypt   = _s.fpe_decrypt
twk_encrypt   = _s.twk_encrypt
twk_decrypt   = _s.twk_decrypt
haccum_leaf   = _s.haccum_leaf
haccum_node   = _s.haccum_node
haccum_root   = _s.haccum_root
haccum_prove  = _s.haccum_prove
haccum_verify = _s.haccum_verify

# ── 78.H Masking / 78.C Ratchet ─────────────────────────────────────────────
fscx_revolve_masked  = _s.fscx_revolve_masked
hske_encrypt_masked  = _s.hske_encrypt_masked
hske_decrypt_masked  = _s.hske_decrypt_masked
ratchet_init         = _s.ratchet_init
ratchet_advance      = _s.ratchet_advance

# ── 80 OPRF ──────────────────────────────────────────────────────────────────
oprf_keygen          = _s.oprf_keygen
oprf_blind           = _s.oprf_blind
oprf_eval            = _s.oprf_eval
oprf_unblind         = _s.oprf_unblind
oprf_direct          = _s.oprf_direct

# ── 80 aPAKE ─────────────────────────────────────────────────────────────────
hpake_register       = _s.hpake_register
hpake_login_demo     = _s.hpake_login_demo
