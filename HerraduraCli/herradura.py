#!/usr/bin/env python3
# HerraduraCli/herradura.py — OpenSSL-style CLI for the Herradura Cryptographic Suite (v1.9.79)
#
# Usage examples:
#   python3 herradura.py genpkey --algo hkex-gf  --bits 256 --out alice.pem
#   python3 herradura.py pkey    --in alice.pem --pubout --out alice_pub.pem
#   python3 herradura.py kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --out sk.pem
#   python3 herradura.py kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --kdf hfscx-256 --out sk.pem
#   python3 herradura.py enc     --algo hske      --key sk.pem --in msg.bin --out cipher.pem
#   python3 herradura.py dec     --algo hske      --key sk.pem --in cipher.pem --out plain.bin
#   python3 herradura.py enc     --algo hske-duplex --key sk.pem --in msg.bin --ad hdr --out cipher.pem
#   python3 herradura.py dec     --algo hske-duplex --key sk.pem --in cipher.pem --ad hdr --out plain.bin
#   python3 herradura.py sign    --algo hpks      --key sig.pem --in msg.bin --out s.pem
#   python3 herradura.py sign    --algo hpks-nl   --key sig.pem --in large.bin --digest hfscx-256 --out s.pem
#   python3 herradura.py genpkey --algo hpks-wots --out otk.pem            # ONE-TIME key
#   python3 herradura.py sign    --algo hpks-wots --key otk.pem --in msg.bin --out s.pem  # signs once
#   python3 herradura.py sign    --algo hpks-ring --key m1.pem --ring m0_pub.pem,m1_pub.pem,m2_pub.pem --in msg.bin --out s.pem
#   python3 herradura.py verify  --algo hpks-ring --ring m0_pub.pem,m1_pub.pem,m2_pub.pem --in msg.bin --sig s.pem
#   python3 herradura.py verify  --algo hpks      --pubkey sig.pem --in msg.bin --sig s.pem
#   python3 herradura.py verify  --algo hpks-nl   --pubkey pub.pem --in large.bin --digest hfscx-256 --sig s.pem
#   python3 herradura.py dgst                     --in file.bin               # hex to stdout
#   python3 herradura.py dgst    --algo hfscx-256 --in file.bin --out d.pem   # PEM digest file
#   python3 herradura.py rand    --seed seed.bin  --bytes 64 --hex            # deterministic bytes
#   python3 herradura.py rand    --state st.pem   --bytes 64 --out r.bin      # resume DRBG stream
#   python3 herradura.py encfile --algo hske-nla1 --key sk.pem --in large.bin --out cipher.hkx
#   python3 herradura.py decfile --algo hske-nla1 --key sk.pem --in cipher.hkx --out plain.bin
#
# HKEX-RNL key exchange (2-round — Bob responds first, then Alice completes):
#   # Step 1: Bob responds to Alice's public key
#   python3 herradura.py kex --algo hkex-rnl --our bob.pem --their alice_pub.pem \
#                            --out bob_session.pem
#   # Step 2: Alice completes using Bob's response
#   python3 herradura.py kex --algo hkex-rnl --our alice.pem --their bob_session.pem \
#                            --out alice_session.pem
#
# HPKE-Stern-F is a KEM demo: e' is embedded in ciphertext (brute-force decap).
# Production use requires a QC-MDPC decoder (N=256, t=16).

import argparse
import hmac as _hmac
import sys
import os

# Add parent directory to path so relative imports work when run directly
sys.path.insert(0, os.path.dirname(__file__))

from codec import (der_int, der_seq, der_parse_seq, pem_wrap, pem_unwrap,
                   pack_poly, unpack_poly,
                   encode_zkp_rnl_proof, decode_zkp_rnl_proof,
                   encode_zkp_nl_privkey, decode_zkp_nl_privkey,
                   encode_zkp_nl_pubkey, decode_zkp_nl_pubkey,
                   encode_zkp_nl_proof, decode_zkp_nl_proof,
                   encode_zkp_nl_pp_proof, decode_zkp_nl_pp_proof,
                   encode_hpkst_commit, decode_hpkst_commit,
                   encode_hpkst_nonce, decode_hpkst_nonce,
                   encode_hpkst_aggregate, decode_hpkst_aggregate,
                   encode_hpkst_partial, decode_hpkst_partial,
                   encode_hpkst_sig, decode_hpkst_sig,
                   encode_hcred_privkey, decode_hcred_privkey,
                   encode_hcred_pubkey, decode_hcred_pubkey,
                   encode_hcred_credential, decode_hcred_credential,
                   encode_hcred_proof, decode_hcred_proof)
from primitives import (
    BitArray, fscx_revolve, nl_fscx_revolve_v1, nl_fscx_revolve_v2,
    nl_fscx_revolve_v2_inv, nl_v2_key_is_valid, gf_mul, gf_pow,
    hfscx_256, hfscx_256_ds, hmac_hfscx_256, _HFSCX256_IV_BYTES, _RNL_KDF_DC_256,
    hske_nl_aead_encrypt, hske_nl_aead_decrypt,
    hske_nl_v2_duplex_encrypt, hske_nl_v2_duplex_decrypt,
    HDrbg, drbg_seed, drbg_generate, drbg_reseed,
    _rnl_keygen, _rnl_agree, _rnl_m_poly, _rnl_rand_poly, _rnl_poly_add,
    _rnl_lift, _rnl_poly_mul,
    stern_f_keygen, hpks_stern_f_sign, hpks_stern_f_verify,
    hpks_stern_ring_sign, hpks_stern_ring_verify,
    hpke_stern_f_encap_with_e, hpke_stern_f_decap,
    qcmdpc_keygen, qcmdpc_encap, qcmdpc_decap_bgf, qcmdpc_bgf_decode,
    _QCMDPC_R, _QCMDPC_D, _QCMDPC_T,
    _qcp_inv, _qcp_mul,
    rnl_sigma_sign, rnl_sigma_verify,
    zkp_nl_keygen, zkp_nl_prove, zkp_nl_verify,
    zkp_nl_prove_pp, zkp_nl_verify_pp,
    KEYBITS, GF_POLY, GF_GEN, ORD,
    RNLN, RNLQ, RNLP, RNLPP, RNLB,
    I_VALUE, R_VALUE, SDFT, SDFNR, SDFR,
    _ZKP_NL_DEFAULT_N, _ZKP_NL_PROD_ROUNDS,
    fpe_encrypt, fpe_decrypt, twk_encrypt, twk_decrypt,
    haccum_leaf, haccum_node, haccum_root, haccum_prove, haccum_verify,
    oprf_keygen, oprf_blind, oprf_eval, oprf_unblind, oprf_direct,
    hpake_register, hpake_login_demo,
    hpks_wots_keygen, hpks_wots_sign, hpks_wots_verify,
    hpks_xmss_keygen, hpks_xmss_sign, hpks_xmss_verify,
    _WOTS_L, _wots_pk_bytes,
    hpkst_aggregate_pubkeys, hpkst_sign, hpkst_verify,
    hcred_phi, hcred_user_keygen, hcred_syndrome,
    hcred_prove, hcred_verify, hcred_issue, hcred_cred_verify,
    _HCRED_DEFAULT_N, _HCRED_DEMO_ROUNDS,
)
from primitives import _s as _suite_mod

# ---------------------------------------------------------------------------
# Label constants
# ---------------------------------------------------------------------------

_PRIV_ALGOS = {
    'hkex-gf':     'HERRADURA HKEX-GF PRIVATE KEY',
    'hkex-rnl':    'HERRADURA HKEX-RNL PRIVATE KEY',
    'hpks':        'HERRADURA HPKS PRIVATE KEY',
    'hpks-nl':     'HERRADURA HPKS-NL PRIVATE KEY',
    'hpke':        'HERRADURA HPKE PRIVATE KEY',
    'hpke-nl':     'HERRADURA HPKE-NL PRIVATE KEY',
    'hpks-stern':  'HERRADURA HPKS-STERN PRIVATE KEY',
    'hpke-stern':     'HERRADURA HPKE-STERN PRIVATE KEY',
    'hpke-stern-kem': 'HERRADURA HPKE-STERN-KEM PRIVATE KEY',
    'hpks-zkp-nl': 'HERRADURA ZKP-NL PRIVATE KEY',
    'oprf':        'HERRADURA OPRF PRIVATE KEY',
    'hpks-xmss':   'HERRADURA HPKS-XMSS PRIVATE KEY',
    'hpks-wots':   'HERRADURA HPKS-WOTS PRIVATE KEY',
}

_PUB_ALGOS = {k: v.replace('PRIVATE', 'PUBLIC') for k, v in _PRIV_ALGOS.items()}

_LABEL_TO_ALGO = {v: k for k, v in _PRIV_ALGOS.items()}
_LABEL_TO_ALGO.update({v: k for k, v in _PUB_ALGOS.items()})

_LABEL_SESSION     = 'HERRADURA SESSION KEY'
_LABEL_RNL_RESP    = 'HERRADURA HKEX-RNL RESPONSE'
_LABEL_SIG         = 'HERRADURA SIGNATURE'
_LABEL_CT          = 'HERRADURA CIPHERTEXT'
_LABEL_DIGEST      = 'HERRADURA DIGEST'
_LABEL_ZKP_RNL     = 'HERRADURA ZKP-RNL PROOF'
_LABEL_ZKP_NL      = 'HERRADURA ZKP-NL PROOF'
_LABEL_ZKP_NL_PP   = 'HERRADURA ZKP-NL-PP SIGNATURE'
_LABEL_OPRF_STATE  = 'HERRADURA OPRF CLIENT STATE'   # (r, alpha, nbits) — client keeps this
_LABEL_OPRF_EVAL   = 'HERRADURA OPRF EVALUATION'     # (beta, nbits) — server response
_LABEL_PAKE_RECORD = 'HERRADURA PAKE RECORD'         # (salt, B, y) — server-side aPAKE record
_LABEL_HDRBG_STATE = 'HERRADURA HDRBG STATE'         # (state[32], blocks) — DRBG checkpoint (TODO #119)
_LABEL_RING_SIG    = 'HERRADURA HPKS-RING SIGNATURE'  # (k, rounds, n, blob) — ring signature (TODO #121)
_LABEL_HCRED_PRIV  = 'HERRADURA HCRED PRIVATE KEY'
_LABEL_HCRED_PUB   = 'HERRADURA HCRED PUBLIC KEY'
_LABEL_HCRED_CRED  = 'HERRADURA HCRED CREDENTIAL'
_LABEL_HCRED_PROOF = 'HERRADURA HCRED PROOF'
_HCRED_CLI_ROUNDS  = 219   # production rounds (128-bit soundness); demo=4

# TODO #162: hybrid HKEX-RNL + HPKE-Stern-KEM combiner
_LABEL_HYBRID_RESP  = 'HERRADURA HYBRID-RNL-STERN RESPONSE'
_HYBRID_COMBINE_DS  = 0x05   # hfscx_256_ds tag for the hybrid key combiner (§11.9.7 tags)

# TODO #165: SP 800-227-style context-bound KDF for plain (non-hybrid) HKEX-RNL
_RNL_SP800227_DS    = 0x06   # hfscx_256_ds tag for --kdf sp800227

# TODO #166: optional passphrase-based encryption for exported private-key PEM files
_LABEL_ENC_PRIV       = 'HERRADURA ENCRYPTED PRIVATE KEY'
_PBKDF2_SALT_BYTES    = 16
# NIST SP 800-132 guidance recommends >=200,000 PBKDF2 iterations as of 2026 — but a
# pure-Python HFSCX-256 call runs at only ~300/sec (~3ms each), so 200,000 would take
# roughly 10-12 minutes per genpkey/decrypt call. Demo default is deliberately much
# lower for CLI responsiveness; --kdf-iterations lets a caller opt into the SP 800-132
# floor (or higher) at the cost of a multi-minute wait, matching this repo's existing
# demo-vs-production-parameter pattern (e.g. Stern-F rounds=32 demo / 219 production).
_PBKDF2_HFSCX256_ITER_DEMO = 1_000
_PBKDF2_HFSCX256_ITER_PROD = 200_000

_ZKP_NL_ALGOS      = {'hpks-zkp-nl'}
_ZKP_CLI_ROUNDS    = _ZKP_NL_PROD_ROUNDS   # CLI default: full 128-bit soundness

# Binary container format for encfile / decfile (.hkx files)
_HKX_MAGIC     = b'HKX1'   # 4-byte magic
_HKX_ALGO_NLA1 = 0x01      # algo byte: HSKE-NL-A1 CTR-mode AEAD
_HKX_BLOCK     = 32        # cipher block = 256 bits

# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _read_file(path):
    if path == '-':
        return sys.stdin.buffer.read()
    with open(path, 'rb') as f:
        return f.read()


def _write_file(path, data):
    if path == '-':
        if isinstance(data, str):
            sys.stdout.write(data)
        else:
            sys.stdout.buffer.write(data)
        return
    mode = 'w' if isinstance(data, str) else 'wb'
    with open(path, mode) as f:
        f.write(data)


def _read_pem(path):
    raw = _read_file(path)
    return pem_unwrap(raw.decode('ascii') if isinstance(raw, bytes) else raw)


def _read_pem_ints(path):
    label, der = _read_pem(path)
    return label, der_parse_seq(der)


# ---------------------------------------------------------------------------
# TODO #240: bound the PEM fields that size an allocation.
#
# TODO #239 did this for the C CLI and stopped there, so every reader below was
# still multiplying counts straight off the wire into a to_bytes() length.  A
# four-byte edit to a signature turned into a MemoryError traceback rather than
# a diagnostic, and — because these are the same wire fields the C reader now
# refuses — into a disagreement between the two CLIs about what a valid
# artifact is.  The bounds are C's: RING_MAX_K, SDF_MAX_ROUNDS, QCMDPC_D and
# the XMSS height cap genpkey already enforced.
#
# Reject rather than clamp, and reject inside the reader: a check applied after
# the reader returns (hpks-ring verify's `sig_n != n` and `k != len(ring_keys)`
# are both of that kind) runs after the allocation it was meant to guard.
# ---------------------------------------------------------------------------

_RING_MAX_K     = 64      # herradura_cli.c RING_MAX_K
_SDF_MAX_ROUNDS = 4096    # herradura.h SDF_MAX_ROUNDS (TODO #236)
_XMSS_MAX_H     = 20      # herradura_cli.c XMSS_MAX_H; genpkey's --xmss-height cap
_STERN_MAX_N    = KEYBITS # no implementation here emits a wider Stern instance


def _bounded(value, lo, hi, what, where):
    """Return int(value), or exit(1) if it falls outside [lo, hi].

    `what` names the field as the wire calls it; `where` is the subcommand, so
    the message shape matches the C CLI's.
    """
    v = int(value)
    if v < lo or v > hi:
        sys.exit(f"{where}: {what} is {v} (expected {lo}..{hi})")
    return v


def _int_nbytes(v) -> int:
    """Byte width of a parsed DER INTEGER's value, as it will be re-serialised."""
    v = int(v)
    return (v.bit_length() + 7) // 8


def _bounded_n(value, where, what='n'):
    """Bound a wire-supplied bit width: a multiple of 8 no wider than the suite's."""
    v = _bounded(value, 8, _STERN_MAX_N, what, where)
    if v % 8:
        sys.exit(f"{where}: {what} is {v} (expected a multiple of 8)")
    return v


# ---------------------------------------------------------------------------
# TODO #166: optional passphrase-based encryption for exported private keys
# ---------------------------------------------------------------------------

def _pbkdf2_hfscx256(password: bytes, salt: bytes, iterations: int,
                     dklen: int = 32) -> bytes:
    """PBKDF2 (RFC 8018) using HMAC-HFSCX-256-DM as the underlying PRF.

    This suite has no PBKDF2/Argon2-class password KDF, so rather than invent an
    unreviewed bespoke construction, this follows PBKDF2's well-studied iterated-PRF
    structure exactly, swapping in the suite's own already-implemented HMAC-HFSCX-256
    (§11.9.6) in place of HMAC-SHA256 — self-contained (no external dependency) while
    keeping the KDF itself a standard, analyzed shape. Only single-block output
    (dklen == 32, the PRF's native output size) is needed here.
    """
    if dklen != 32:
        raise ValueError("_pbkdf2_hfscx256 only supports dklen=32 (single PRF block)")
    # HMAC-HFSCX-256 requires an exactly-32-byte key; hash an arbitrary-length
    # password down first, matching standard HMAC over-length-key handling.
    key = hfscx_256(password)
    u = hmac_hfscx_256(key, salt + (1).to_bytes(4, 'big'))
    t = bytearray(u)
    for _ in range(iterations - 1):
        u = hmac_hfscx_256(key, u)
        for j in range(32):
            t[j] ^= u[j]
    return bytes(t)


def _encrypt_pem(pem_text: str, passphrase: str,
                 iterations: int = _PBKDF2_HFSCX256_ITER_DEMO) -> str:
    """Wrap an existing (cleartext) PEM's exact bytes in an AEAD-encrypted envelope.

    Encrypts the whole PEM text (any algorithm) as opaque bytes under a
    PBKDF2-HFSCX256-derived key, using the existing HSKE-NL-AEAD construction
    (already implemented and tested for encfile/decfile). Recovering the passphrase
    yields the byte-for-byte original PEM, so this composes with every existing
    command that consumes a private-key PEM — decrypt first, then feed the result
    to any other subcommand unmodified.
    """
    salt = os.urandom(_PBKDF2_SALT_BYTES)
    key_bytes = _pbkdf2_hfscx256(passphrase.encode('utf-8'), salt, iterations)
    key = BitArray(KEYBITS, int.from_bytes(key_bytes, 'big'))
    pt = pem_text.encode('utf-8')
    nonce, ct, tag = hske_nl_aead_encrypt(key, pt)
    der = der_seq(der_int(int.from_bytes(salt, 'big'), _PBKDF2_SALT_BYTES),
                  der_int(iterations),
                  der_int(nonce.uint, KEYBITS // 8),
                  der_int(int.from_bytes(ct, 'big'), max(1, len(ct))),
                  der_int(int.from_bytes(tag, 'big'), 32),
                  der_int(len(pt)))
    return pem_wrap(_LABEL_ENC_PRIV, der)


def _decrypt_pem(enc_pem_text: str, passphrase: str) -> str:
    """Inverse of `_encrypt_pem`. Raises ValueError on a wrong passphrase or a
    corrupted/tampered envelope (AEAD tag mismatch) — never returns garbage."""
    label, der = pem_unwrap(enc_pem_text)
    if label != _LABEL_ENC_PRIV:
        raise ValueError(f"Expected {_LABEL_ENC_PRIV!r} PEM, got {label!r}")
    salt_int, iterations, nonce_int, ct_int, tag_int, pt_len = der_parse_seq(der)
    salt = salt_int.to_bytes(_PBKDF2_SALT_BYTES, 'big')
    ct   = ct_int.to_bytes(pt_len, 'big') if pt_len else b''
    tag  = tag_int.to_bytes(32, 'big')
    key_bytes = _pbkdf2_hfscx256(passphrase.encode('utf-8'), salt, iterations)
    key = BitArray(KEYBITS, int.from_bytes(key_bytes, 'big'))
    nonce = BitArray(KEYBITS, nonce_int)
    pt = hske_nl_aead_decrypt(key, nonce, ct, tag)
    if pt is None:
        raise ValueError("wrong passphrase or corrupted/tampered file")
    return pt.decode('utf-8')


# ---------------------------------------------------------------------------
# Key serialization helpers
# ---------------------------------------------------------------------------

_WEAK_V2_KEY_MSG = (
    "NL-FSCX v2 affine weak key — delta(K) is 0 or 2^(n-1), which makes the "
    "permutation GF(2)-affine and the ciphertext recoverable by linear algebra "
    "(SecurityProofs-7.md \u00a711.19.2, TODO #168)")

_CLASSICAL_GF_ALGOS = {'hkex-gf', 'hpks', 'hpks-nl', 'hpke', 'hpke-nl'}
_STERN_ALGOS        = {'hpks-stern', 'hpke-stern'}

_STERN_DEMO_WARNING = (
    "WARNING: Stern-F at N=256 provides only ~30-40 bits of security "
    "(demo parameters). 128-bit security requires N>=17000. "
    "Do not use for production."
)


def _encode_classical_privkey(priv_int, pub_int, nbits, algo):
    der = der_seq(der_int(priv_int, nbits // 8),
                  der_int(pub_int,  nbits // 8),
                  der_int(nbits))
    return pem_wrap(_PRIV_ALGOS[algo], der)


def _encode_classical_pubkey(pub_int, nbits, algo):
    der = der_seq(der_int(pub_int, nbits // 8), der_int(nbits))
    return pem_wrap(_PUB_ALGOS[algo], der)


def _rnl_privkey_fields(n, s_poly, m_poly):
    s_packed, s_nb = pack_poly(s_poly, 4)   # Z_q coeff → 4 bytes (q = 65537 ≤ 3 bytes; padded)
    m_packed, m_nb = pack_poly(m_poly, 4)   # m_blind in Z_q → 4 bytes per coeff
    return s_packed, s_nb, m_packed, m_nb


def _encode_rnl_privkey(s_poly, m_poly, n, n_a: bytes = None):
    """Encode HKEX-RNL private key with optional Alice nonce n_a (32 bytes)."""
    s_packed, s_nb, m_packed, m_nb = _rnl_privkey_fields(n, s_poly, m_poly)
    if n_a is None:
        der = der_seq(der_int(s_packed, s_nb), der_int(m_packed, m_nb), der_int(n))
    else:
        na_int = int.from_bytes(n_a, 'big')
        der = der_seq(der_int(s_packed, s_nb), der_int(m_packed, m_nb),
                      der_int(n), der_int(na_int, len(n_a)))
    return pem_wrap(_PRIV_ALGOS['hkex-rnl'], der)


def _encode_rnl_pubkey(C_poly, m_poly, n, n_a: bytes = None):
    """Encode HKEX-RNL public key with optional Alice nonce n_a (32 bytes)."""
    C_packed, C_nb = pack_poly(C_poly, 2)   # Z_p coeff → 2 bytes (p = 4096)
    m_packed, m_nb = pack_poly(m_poly, 4)
    if n_a is None:
        der = der_seq(der_int(C_packed, C_nb), der_int(m_packed, m_nb), der_int(n))
    else:
        na_int = int.from_bytes(n_a, 'big')
        der = der_seq(der_int(C_packed, C_nb), der_int(m_packed, m_nb),
                      der_int(n), der_int(na_int, len(n_a)))
    return pem_wrap(_PUB_ALGOS['hkex-rnl'], der)


def _decode_rnl_privkey(ints):
    """Return (s_poly, m_poly, n, n_a_bytes) from parsed private key integers."""
    if len(ints) >= 4:
        s_packed, m_packed, n, na_int = ints[0], ints[1], ints[2], ints[3]
        n_a = na_int.to_bytes(32, 'big')
    else:
        s_packed, m_packed, n = ints[0], ints[1], ints[2]
        n_a = bytes(32)
    s_poly = unpack_poly(s_packed, n, 4)
    m_poly = unpack_poly(m_packed, n, 4)
    return s_poly, m_poly, n, n_a


def _decode_rnl_pubkey(ints):
    """Return (C_poly, m_poly, n, n_a_bytes) from parsed public key integers."""
    if len(ints) >= 4:
        C_packed, m_packed, n, na_int = ints[0], ints[1], ints[2], ints[3]
        n_a = na_int.to_bytes(32, 'big')
    else:
        C_packed, m_packed, n = ints[0], ints[1], ints[2]
        n_a = bytes(32)
    C_poly = unpack_poly(C_packed, n, 2)
    m_poly = unpack_poly(m_packed, n, 4)
    return C_poly, m_poly, n, n_a


def _rnl_key_bits(n):
    """RAW reconciliation width for an HKEX-RNL ring of dimension n (TODO #223).

    Reconciliation extracts 2 bits from each of key_bits//2 coefficients, so a
    ring of n coefficients can supply at most 2n key bits.  Since TODO #223 the
    ring dimension (RNLN = 1024) and the key width (KEYBITS = 256) are separate:
    a production ring is far larger than the key needs, so the raw agreement is
    capped at KEYBITS.  Small demo/test rings (--bits 32/64) can only supply n
    raw bits, so that is what reconciliation extracts there.

    This is the width of `K_raw` — the input to the contributory KDF, and the
    width at which `K_raw` is serialised inside it.  It is NOT the width of the
    session key that comes out; see `_rnl_session_bits` (TODO #228).
    """
    return KEYBITS if n >= KEYBITS else n


def _rnl_session_bits(n=None):
    """DERIVED session-key width for HKEX-RNL — always KEYBITS (TODO #228).

    `_rnl_contributory_kdf` returns an HFSCX-256 digest, so the session key is
    256 bits wide whatever the ring dimension is; the ring only bounds how much
    raw entropy reconciliation can extract into the KDF's input.  Labelling the
    session key with `_rnl_key_bits(n)` made the two numbers disagree below
    n=256, where the CLIs then diverged four ways: Python stored a full 256-bit
    digest under an `nbits=64` label, Go truncated the digest to match the
    label, Java did a third thing, and C — which has only ever encoded KEYBITS
    here — could not read a small ring at all.  All four now agree that the
    answer is 256.  At n >= 256 the two functions coincide, so the deployed
    n=1024 wire format is unchanged.

    `n` is accepted and ignored so call sites read symmetrically with
    `_rnl_key_bits(n)`.  HKEX-GF is genuinely nbits-wide and must not use this.
    """
    return KEYBITS


def _rnl_derive_C(m_poly, s_poly, n):
    """Compute C = round_p(m_blind * s) given m_blind and s (both as Z_q polys)."""
    ms = _rnl_poly_mul(m_poly, s_poly, RNLQ, n)
    return _suite_mod._rnl_round(ms, RNLQ, RNLP)


def _rnl_contributory_kdf(k_raw_int: int, n_bits: int, n_a: bytes, n_b: bytes) -> int:
    """Derive final HKEX-RNL session key via contributory KDF.

    Returns int: HFSCX-256(K_raw_bytes || n_A || n_B)
    n_a and n_b must each be 32 bytes; use bytes(32) for old-format peers.
    """
    k_bytes = k_raw_int.to_bytes(n_bits // 8, 'big')
    payload = k_bytes + n_a + n_b
    return int.from_bytes(hfscx_256(payload), 'big')


def _rnl_validate_m_blind(poly, q=RNLQ):
    """Return True if poly looks like a uniform-random element of Z_q^n.
    Rejects sparse polys (nz < n/4) and clustered polys (range < q/4)."""
    n = len(poly)
    nz = sum(1 for c in poly if c != 0)
    if nz < n // 4:
        return False
    span = max(poly) - min(poly)
    if span < q // 4:
        return False
    return True


def _encode_stern_privkey(e_int, seed, n, algo):
    nbytes = n // 8
    der = der_seq(der_int(e_int, nbytes), der_int(seed.uint, nbytes), der_int(n))
    return pem_wrap(_PRIV_ALGOS[algo], der)


def _encode_stern_pubkey(syn_int, seed, n, algo):
    nbytes = n // 8
    der = der_seq(der_int(syn_int, nbytes), der_int(seed.uint, nbytes), der_int(n))
    return pem_wrap(_PUB_ALGOS[algo], der)


def _encode_xmss_privkey(master_seed: bytes, h: int, next_idx: int,
                         leaf_hashes: list) -> str:
    """
    XMSS private key PEM.
    DER: SEQUENCE { seed(32B), h(int), next_idx(int), leaf_hashes_blob(bytes) }
    leaf_hashes_blob = 32 * 2^h bytes (concatenated 32-byte leaf hashes).
    """
    blob = b''.join(leaf_hashes)
    der = der_seq(
        der_int(int.from_bytes(master_seed, 'big'), 32),
        der_int(h),
        der_int(next_idx),
        der_int(int.from_bytes(blob, 'big'), len(blob)),
    )
    return pem_wrap(_PRIV_ALGOS['hpks-xmss'], der)


def _decode_xmss_privkey(path):
    """Returns (master_seed, h, next_idx, leaf_hashes, root)."""
    label, der = _read_pem(path)
    ints = der_parse_seq(der)
    seed_int, h_int, next_idx, blob_int = ints
    master_seed = seed_int.to_bytes(32, 'big')
    # h sizes `1 << h` leaves and the 32-bytes-per-leaf blob behind them.
    h = _bounded(h_int, 1, _XMSS_MAX_H, 'XMSS height', 'pkey')
    num_leaves = 1 << h
    blob = blob_int.to_bytes(32 * num_leaves, 'big')
    leaf_hashes = [blob[i*32:(i+1)*32] for i in range(num_leaves)]
    from primitives import haccum_root as _haccum_root
    root = _haccum_root(leaf_hashes)
    return master_seed, h, int(next_idx), leaf_hashes, root


def _encode_xmss_pubkey(root: bytes, h: int) -> str:
    """XMSS public key PEM: just the 32-byte Merkle root + h."""
    der = der_seq(der_int(int.from_bytes(root, 'big'), 32), der_int(h))
    return pem_wrap(_PUB_ALGOS['hpks-xmss'], der)


def _decode_xmss_pubkey(path):
    """Returns (root, h)."""
    label, der = _read_pem(path)
    root_int, h_int = der_parse_seq(der)
    return root_int.to_bytes(32, 'big'), int(h_int)


def _pack_xmss_sig(sig: dict, n: int) -> str:
    """
    PEM-encode an XMSS signature.
    DER: SEQUENCE { leaf_idx, wots_sig_blob, auth_path_blob }
    wots_sig_blob = ℓ × (n//8) bytes; auth_path_blob = h × 32 bytes.
    """
    leaf_idx  = sig['leaf_idx']
    sig_blob  = b''.join(v.uint.to_bytes(n // 8, 'big') for v in sig['wots_sig'])
    path_blob = b''.join(sig['auth_path'])
    h         = len(sig['auth_path'])
    der = der_seq(
        der_int(leaf_idx),
        der_int(int.from_bytes(sig_blob, 'big'), len(sig_blob)),
        der_int(int.from_bytes(path_blob, 'big'), len(path_blob)),
        der_int(h),
        der_int(n),
    )
    return pem_wrap('HERRADURA HPKS-XMSS SIGNATURE', der)


def _unpack_xmss_sig(path: str):
    """Returns sig dict for hpks_xmss_verify (pk is recovered during verify)."""
    label, der = _read_pem(path)
    leaf_idx, sig_int, path_int, h_int, n_int = der_parse_seq(der)
    leaf_idx  = int(leaf_idx)
    n         = _bounded_n(n_int, 'verify')
    h         = _bounded(h_int, 1, _XMSS_MAX_H, 'XMSS signature depth', 'verify')
    nbytes    = n // 8
    sig_blob  = sig_int.to_bytes(_WOTS_L * nbytes, 'big')
    path_blob = path_int.to_bytes(h * 32, 'big')
    wots_sig  = [BitArray(n, int.from_bytes(sig_blob[i*nbytes:(i+1)*nbytes], 'big'))
                 for i in range(_WOTS_L)]
    auth_path = [path_blob[i*32:(i+1)*32] for i in range(h)]
    return {'leaf_idx': leaf_idx, 'wots_sig': wots_sig, 'auth_path': auth_path}


def _xmss_state_path(key_path: str) -> str:
    """State file path: <key>.idx — stores next leaf index (one integer per line)."""
    return key_path + '.idx'


def _xmss_read_idx(key_path: str, h: int) -> int:
    sp = _xmss_state_path(key_path)
    if os.path.exists(sp):
        try:
            return int(open(sp).read().strip())
        except Exception:
            pass
    return 0


def _xmss_write_idx(key_path: str, next_idx: int):
    open(_xmss_state_path(key_path), 'w').write(str(next_idx) + '\n')


# ---------------------------------------------------------------------------
# HPKS-WOTS-F one-time signature codec (TODO #120)
#
# A WOTS-F key signs EXACTLY ONCE.  The private key is (master_seed, leaf_idx);
# the public key is the list of ℓ=67 chain endpoints.  One-time use is enforced
# via a `.idx` state file alongside the private key (0 = unused, 1 = burned).
# ---------------------------------------------------------------------------

_LABEL_WOTS_SIG = 'HERRADURA HPKS-WOTS SIGNATURE'


def _encode_wots_privkey(master_seed: bytes, leaf_idx: int) -> str:
    der = der_seq(der_int(int.from_bytes(master_seed, 'big'), 32),
                  der_int(leaf_idx))
    return pem_wrap(_PRIV_ALGOS['hpks-wots'], der)


def _decode_wots_privkey(path):
    """Returns (master_seed, leaf_idx)."""
    label, der = _read_pem(path)
    if label != _PRIV_ALGOS['hpks-wots']:
        raise ValueError(f"Expected HPKS-WOTS private key, got {label!r}")
    seed_int, leaf_idx = der_parse_seq(der)
    return seed_int.to_bytes(32, 'big'), int(leaf_idx)


def _encode_wots_pubkey(pk: list) -> str:
    """Public key PEM: the ℓ chain endpoints (ℓ × 32 bytes) + ℓ."""
    nbytes = KEYBITS // 8
    blob = b''.join(v.uint.to_bytes(nbytes, 'big') for v in pk)
    der = der_seq(der_int(int.from_bytes(blob, 'big'), len(blob)),
                  der_int(len(pk)))
    return pem_wrap(_PUB_ALGOS['hpks-wots'], der)


def _decode_wots_pubkey(path):
    """Returns pk as a list of ℓ BitArrays."""
    label, der = _read_pem(path)
    if label != _PUB_ALGOS['hpks-wots']:
        raise ValueError(f"Expected HPKS-WOTS public key, got {label!r}")
    blob_int, ell = der_parse_seq(der)
    # The shipped parameters fix the chain count, so anything else is malformed
    # rather than merely large.
    ell = _bounded(ell, _WOTS_L, _WOTS_L, 'WOTS chain count', 'verify')
    nbytes = KEYBITS // 8
    blob = blob_int.to_bytes(ell * nbytes, 'big')
    return [BitArray(KEYBITS, int.from_bytes(blob[i*nbytes:(i+1)*nbytes], 'big'))
            for i in range(ell)]


def _pack_wots_sig(sig: list) -> str:
    """Signature PEM: the ℓ chain values (ℓ × 32 bytes) + ℓ."""
    nbytes = KEYBITS // 8
    blob = b''.join(v.uint.to_bytes(nbytes, 'big') for v in sig)
    der = der_seq(der_int(int.from_bytes(blob, 'big'), len(blob)),
                  der_int(len(sig)))
    return pem_wrap(_LABEL_WOTS_SIG, der)


def _unpack_wots_sig(path: str):
    """Returns the signature as a list of ℓ BitArrays."""
    label, der = _read_pem(path)
    if label != _LABEL_WOTS_SIG:
        raise ValueError(f"Expected HPKS-WOTS signature, got {label!r}")
    blob_int, ell = der_parse_seq(der)
    # The shipped parameters fix the chain count, so anything else is malformed
    # rather than merely large.
    ell = _bounded(ell, _WOTS_L, _WOTS_L, 'WOTS chain count', 'verify')
    nbytes = KEYBITS // 8
    blob = blob_int.to_bytes(ell * nbytes, 'big')
    return [BitArray(KEYBITS, int.from_bytes(blob[i*nbytes:(i+1)*nbytes], 'big'))
            for i in range(ell)]


def _wots_is_used(key_path: str) -> bool:
    sp = _xmss_state_path(key_path)   # reuse <key>.idx convention
    if os.path.exists(sp):
        try:
            return int(open(sp).read().strip()) != 0
        except Exception:
            pass
    return False


def _wots_mark_used(key_path: str):
    open(_xmss_state_path(key_path), 'w').write('1\n')


def _load_zkp_nl_privkey(path):
    """Load a ZKP-NL private key PEM; return (A, B, y, n)."""
    pem_text = _read_file(path).decode('ascii')
    return decode_zkp_nl_privkey(pem_text)


def _load_zkp_nl_pubkey(path):
    """Load a ZKP-NL public key PEM; return (B, y, n)."""
    pem_text = _read_file(path).decode('ascii')
    return decode_zkp_nl_pubkey(pem_text)


def _decode_privkey(path):
    """Load a private key PEM; return (algo, fields_list).

    For ZKP-NL keys the fields_list contains raw bytes (not DER integers);
    use _load_zkp_nl_privkey() directly when algo is known to be hpks-zkp-nl.
    """
    raw = _read_file(path).decode('ascii')
    label, _ = pem_unwrap(raw)
    if label == _LABEL_ENC_PRIV:
        raise ValueError(
            f"{path!r} is a passphrase-encrypted private key (TODO #166) — "
            f"decrypt it first with: pkey --decrypt --in {path} --passphrase ... --out plain.pem"
        )
    if label == _PRIV_ALGOS.get('hpks-zkp-nl'):
        A, B, y, n = decode_zkp_nl_privkey(raw)
        return 'hpks-zkp-nl', (A, B, y, n)
    if label == _LABEL_HCRED_PRIV:
        return 'hcred', decode_hcred_privkey(raw)
    label2, ints = _read_pem_ints(path)
    algo = _LABEL_TO_ALGO.get(label2)
    if algo is None:
        raise ValueError(f"Unrecognised PEM label: {label2!r}")
    return algo, ints


def _decode_pubkey(path):
    """Load a public key PEM; return (algo, fields_list)."""
    raw = _read_file(path).decode('ascii')
    label, _ = pem_unwrap(raw)
    if label == _PUB_ALGOS.get('hpks-zkp-nl'):
        B, y, n = decode_zkp_nl_pubkey(raw)
        return 'hpks-zkp-nl', (B, y, n)
    if label == _LABEL_HCRED_PUB:
        return 'hcred', decode_hcred_pubkey(raw)
    label2, ints = _read_pem_ints(path)
    algo = _LABEL_TO_ALGO.get(label2)
    if algo is None:
        raise ValueError(f"Unrecognised PEM label: {label2!r}")
    return algo, ints


# ---------------------------------------------------------------------------
# Session key serialization
# ---------------------------------------------------------------------------

def _encode_session_key(key_int, nbits):
    """Encode a plain session key (HKEX-GF or completed HKEX-RNL)."""
    nbytes = max(1, (key_int.bit_length() + 7) // 8)
    der = der_seq(der_int(key_int, nbytes), der_int(nbits))
    return pem_wrap(_LABEL_SESSION, der)


def _encode_rnl_response(K_int, C_B_poly, hint, n, n_b: bytes = None):
    """Encode Bob's HKEX-RNL response: (K_B, C_B, hint, n, hint_len[, n_B]).

    K_B is Bob's session key (stored so enc/dec can use this file directly).
    C_B and hint are the public parts Alice uses to complete the handshake.
    n_b (32 bytes) is Bob's contributory nonce; omitted for old-format output.
    """
    K_nb    = max(1, (K_int.bit_length() + 7) // 8)
    C_packed, C_nb = pack_poly(C_B_poly, 2)
    # Only the first n//2 coefficients are used in reconciliation; cap to match
    # C's hint[RNL_N/8] buffer (n//4 bytes = n//2 coefficients × 2 bits).
    hint_used = hint[:n // 2]
    hint_int = 0
    for i, b in enumerate(hint_used):
        hint_int |= (b & 3) << (2 * i)
    hint_nb = max(1, (2 * len(hint_used) + 7) // 8)
    fields = [der_int(K_int,    K_nb),
              der_int(C_packed, C_nb),
              der_int(hint_int, hint_nb),
              der_int(n),
              der_int(len(hint_used))]
    if n_b is not None:
        nb_int = int.from_bytes(n_b, 'big')
        fields.append(der_int(nb_int, len(n_b)))
    der = der_seq(*fields)
    return pem_wrap(_LABEL_RNL_RESP, der)


def _decode_session_key(path):
    """Return (key_int, nbits) from either SESSION KEY or RNL RESPONSE PEM."""
    label, ints = _read_pem_ints(path)
    if label == _LABEL_SESSION:
        key_int, nbits = ints
        return key_int, nbits
    elif label == _LABEL_RNL_RESP:
        # K_B (already contributory-KDF-derived) is the first field.  ints[3] is
        # the RING dimension, which since TODO #223 is no longer the key width —
        # the ring is 1024 while the derived key stays 256 bits.  Returning it
        # raw makes `enc` use a 1024-bit width against a SESSION KEY PEM's 256,
        # breaking the cross-party round trip.
        K_int = ints[0]
        return K_int, _rnl_session_bits(ints[3])
    elif label == _LABEL_HYBRID_RESP:
        # K (already combined) is the first field; ints[3] is the ring dimension,
        # not the key width — see the RNL RESPONSE case above.
        K_int = ints[0]
        return K_int, _rnl_session_bits(ints[3])
    else:
        raise ValueError(f"Expected SESSION KEY or RNL RESPONSE PEM, got {label!r}")


def _decode_rnl_response(path):
    """Return (K_int, C_B_poly, hint, n, n_b_bytes) from a HKEX-RNL RESPONSE PEM."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_RNL_RESP:
        raise ValueError(f"Expected HKEX-RNL RESPONSE PEM, got {label!r}")
    K_int, C_packed, hint_int, n, hint_len = ints[0], ints[1], ints[2], ints[3], ints[4]
    C_B_poly = unpack_poly(C_packed, n, 2)
    hint = [(hint_int >> (2 * i)) & 3 for i in range(hint_len)]
    n_b = ints[5].to_bytes(32, 'big') if len(ints) >= 6 else bytes(32)
    return K_int, C_B_poly, hint, n, n_b


# ---------------------------------------------------------------------------
# TODO #162: hybrid HKEX-RNL + HPKE-Stern-KEM combiner
# ---------------------------------------------------------------------------

def _hybrid_rnl_stern_combine(K1_int, K2_int, C_A, m_A, C_B, hint_used, h_pub, syn,
                              n, r_qc):
    """SP 800-227 §4.6-style IND-CCA-preserving key combiner (TODO #162, #165).

    K = HFSCX-256-DS(0x05, K1 || K2 || C_A || m_A || C_B || hint || h_pub || syn || v1)

    Binds both component shared secrets (K1 from HKEX-RNL, K2 from HPKE-Stern-KEM) to
    the full public transcript — both parties' public polynomials, the reconciliation
    hint, the KEM public key, and the KEM ciphertext — rather than naively hashing just
    K1||K2. Per SP 800-227 §4.6.2 (citing Giacon et al.), the naive combiner does not
    generically preserve IND-CCA security if only one component KEM is IND-CCA; this
    shape (matching SP 800-227's own worked example) does.
    """
    C_A_packed, C_A_nb = pack_poly(C_A, 2)
    m_A_packed, m_A_nb = pack_poly(m_A, 4)
    C_B_packed, C_B_nb = pack_poly(C_B, 2)
    rb = (r_qc + 7) // 8
    # K1 is serialised at the KEY width, not the ring dimension.  Those were the
    # same number until TODO #223 moved the ring to 1024 while the derived key
    # stayed 256 bits; using n here writes 128 zero-padded bytes where C's
    # combiner writes KEYBYTES (32), so the two sides derive different keys.
    data = (K1_int.to_bytes(_rnl_session_bits(n) // 8, 'big')
            + K2_int.to_bytes(KEYBITS // 8, 'big')
            + C_A_packed.to_bytes(C_A_nb, 'big')
            + m_A_packed.to_bytes(m_A_nb, 'big')
            + C_B_packed.to_bytes(C_B_nb, 'big')
            + bytes(hint_used)
            + h_pub.to_bytes(rb, 'big')
            + syn.to_bytes(rb, 'big')
            + b'HERRADURA-HYBRID-RNL-STERN-v1')
    return int.from_bytes(hfscx_256_ds(_HYBRID_COMBINE_DS, data), 'big')


def _hkex_rnl_sp800227_kdf(K_int, n, C_A, m_A, C_B, hint_used):
    """SP 800-227 §4.5-style context-bound KDF for plain (non-hybrid) HKEX-RNL
    (TODO #165, `--kdf sp800227`).

    K' = HFSCX-256-DS(0x06, K || C_A || m_A || C_B || hint || v1)

    The contributory KDF (`_rnl_contributory_kdf`) already binds K to both parties'
    per-session nonces, but not to the public polynomials/ciphertext exchanged that
    session. This opt-in KDF variant additionally binds the full public transcript,
    matching SP 800-227's own worked combiner example (§4.6) and TODO #162's hybrid
    combiner's approach (§11.16) — applied here to the plain, non-hybrid case. Not the
    default (`--kdf none`/`hfscx-256` are unaffected) to avoid a breaking wire-format
    change to existing HKEX-RNL sessions; both sides must opt in with the same flag.
    """
    C_A_packed, C_A_nb = pack_poly(C_A, 2)
    m_A_packed, m_A_nb = pack_poly(m_A, 4)
    C_B_packed, C_B_nb = pack_poly(C_B, 2)
    data = (K_int.to_bytes(n // 8, 'big')
            + C_A_packed.to_bytes(C_A_nb, 'big')
            + m_A_packed.to_bytes(m_A_nb, 'big')
            + C_B_packed.to_bytes(C_B_nb, 'big')
            + bytes(hint_used)
            + b'HERRADURA-HKEX-RNL-SP800227-v1')
    return int.from_bytes(hfscx_256_ds(_RNL_SP800227_DS, data), 'big')


def _encode_hybrid_response(K_int, C_B_poly, hint_used, n, n_b, syn, r_qc):
    """Encode Bob's hybrid-rnl-stern response: (K, C_B, hint, n, hint_len, n_B, syn, r)."""
    C_packed, C_nb = pack_poly(C_B_poly, 2)
    hint_int = 0
    for i, b in enumerate(hint_used):
        hint_int |= (b & 3) << (2 * i)
    hint_nb = max(1, (2 * len(hint_used) + 7) // 8)
    K_nb    = max(1, (K_int.bit_length() + 7) // 8)
    nb_int  = int.from_bytes(n_b, 'big')
    rb      = (r_qc + 7) // 8
    der = der_seq(der_int(K_int,    K_nb),
                  der_int(C_packed, C_nb),
                  der_int(hint_int, hint_nb),
                  der_int(n),
                  der_int(len(hint_used)),
                  der_int(nb_int, len(n_b)),
                  der_int(syn, rb),
                  der_int(r_qc))
    return pem_wrap(_LABEL_HYBRID_RESP, der)


def _decode_hybrid_response(path):
    """Return (K_int, C_B_poly, hint, n, n_b_bytes, syn, r_qc) from a HYBRID RESPONSE PEM."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_HYBRID_RESP:
        raise ValueError(f"Expected HYBRID-RNL-STERN RESPONSE PEM, got {label!r}")
    (K_int, C_packed, hint_int, n, hint_len,
     nb_int, syn, r_qc) = ints
    C_B_poly = unpack_poly(C_packed, n, 2)
    hint = [(hint_int >> (2 * i)) & 3 for i in range(hint_len)]
    n_b = nb_int.to_bytes(32, 'big')
    return K_int, C_B_poly, hint, n, n_b, syn, r_qc


# ---------------------------------------------------------------------------
# Ciphertext serialization (symmetric)
# ---------------------------------------------------------------------------

def _encode_sym_ct(algo, E_int, nbits, nonce_int=None, tag_int=None):
    nbytes = nbits // 8
    if algo == 'hske-nla1' and nonce_int is not None and tag_int is not None:
        der = der_seq(der_int(2),               # format tag 2: NLA1 AEAD (TODO #95)
                      der_int(nonce_int, nbytes),
                      der_int(E_int, nbytes),
                      der_int(tag_int, 32),
                      der_int(nbits))
    elif algo == 'hske-nla1' and nonce_int is not None:
        der = der_seq(der_int(1),               # format tag 1: NLA1 with nonce
                      der_int(nonce_int, nbytes),
                      der_int(E_int, nbytes),
                      der_int(nbits))
    else:
        der = der_seq(der_int(0),               # format tag 0: no nonce
                      der_int(E_int, nbytes),
                      der_int(nbits))
    return pem_wrap(_LABEL_CT, der)


def _decode_sym_ct(path):
    """Return (E_int, nbits, nonce_int_or_None, tag_int_or_None)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    fmt = ints[0]
    if fmt == 2:
        _, nonce_int, E_int, tag_int, nbits = ints
        return E_int, nbits, nonce_int, tag_int
    elif fmt == 1:
        _, nonce_int, E_int, nbits = ints
        return E_int, nbits, nonce_int, None
    else:
        _, E_int, nbits = ints
        return E_int, nbits, None, None


# ---------------------------------------------------------------------------
# Ciphertext serialization (HSKE-NL-V2-Duplex AEAD — TODO #118)
#
# Unlike the single-block sym formats above, the duplex AEAD handles
# arbitrary-length plaintext, so the ciphertext is stored length-prefixed:
#   format tag 3, nonce (KEYBYTES), ct_len, ct (ct_len bytes), tag (32), nbits.
# ---------------------------------------------------------------------------

def _encode_duplex_ct(nonce_int, ct_bytes, tag_int, nbits):
    nbytes = nbits // 8
    ct_len = len(ct_bytes)
    der = der_seq(der_int(3),                       # format tag 3: V2-Duplex AEAD
                  der_int(nonce_int, nbytes),
                  der_int(ct_len),
                  der_int(int.from_bytes(ct_bytes, 'big'), max(1, ct_len)),
                  der_int(tag_int, 32),
                  der_int(nbits))
    return pem_wrap(_LABEL_CT, der)


def _decode_duplex_ct(path):
    """Return (nonce_int, ct_bytes, tag_int, nbits)."""
    label, der = _read_pem(path)
    ints = der_parse_seq(der)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    if ints[0] != 3:
        raise ValueError(f"Expected V2-Duplex ciphertext (format 3), got {ints[0]}")
    _, nonce_int, ct_len, ct_int, tag_int, nbits = ints
    # The declared length sizes the buffer.  It cannot exceed the DER actually
    # read, and the payload cannot be longer than the length claiming to
    # describe it; shorter is legal (DER strips leading zero bytes) and is
    # zero-padded by to_bytes.
    ct_len = _bounded(ct_len, 0, len(der), 'declared ciphertext length', 'dec')
    if _int_nbytes(ct_int) > ct_len:
        sys.exit(f"dec: V2-Duplex ciphertext declares {ct_len} bytes but "
                 f"carries {_int_nbytes(ct_int)}")
    ct_bytes = ct_int.to_bytes(ct_len, 'big') if ct_len else b''
    return nonce_int, ct_bytes, tag_int, nbits


# ---------------------------------------------------------------------------
# Ciphertext serialization (asymmetric HPKE / HPKE-NL)
# ---------------------------------------------------------------------------

def _encode_asym_ct(R_int, E_int, nbits):
    nbytes = nbits // 8
    der = der_seq(der_int(R_int, nbytes), der_int(E_int, nbytes), der_int(nbits))
    return pem_wrap(_LABEL_CT, der)


def _decode_asym_ct(path):
    label, ints = _read_pem_ints(path)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    R_int, E_int, nbits = ints
    return R_int, E_int, nbits


# ---------------------------------------------------------------------------
# Ciphertext serialization (HPKE-Stern-F KEM)
# ---------------------------------------------------------------------------

def _encode_stern_ct(ct_syn, e_p, K_int, E_int, n):
    """HPKE-Stern-F demo ciphertext: syndrome + plaintext error (demo) + HSKE payload."""
    nbytes = n // 8
    der = der_seq(der_int(ct_syn, nbytes),
                  der_int(e_p,    nbytes),   # demo: e' transmitted for brute-force decap
                  der_int(K_int,  nbytes),
                  der_int(E_int,  nbytes),
                  der_int(n))
    return pem_wrap(_LABEL_CT, der)


def _decode_stern_ct(path):
    label, ints = _read_pem_ints(path)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    ct_syn, e_p, K_int, E_int, n = ints
    return ct_syn, e_p, K_int, E_int, n


_LABEL_KEM_PRIV = 'HERRADURA HPKE-STERN-KEM PRIVATE KEY'
_LABEL_KEM_PUB  = 'HERRADURA HPKE-STERN-KEM PUBLIC KEY'
_QCMDPC_RBYTES  = (_QCMDPC_R + 7) // 8  # 66


def _encode_kem_privkey(sup0, sup1, h0, h1):
    """HPKE-Stern-KEM private key: SEQUENCE(h0, h1, sup0_bytes, sup1_bytes, r, d)."""
    rb = _QCMDPC_RBYTES
    d  = _QCMDPC_D
    h0b = h0.to_bytes(rb, 'little')
    h1b = h1.to_bytes(rb, 'little')
    s0b = b''.join(int(p).to_bytes(2, 'big') for p in sorted(sup0))
    s1b = b''.join(int(p).to_bytes(2, 'big') for p in sorted(sup1))
    der = der_seq(der_int(int.from_bytes(h0b, 'big'), rb),
                  der_int(int.from_bytes(h1b, 'big'), rb),
                  der_int(int.from_bytes(s0b, 'big'), d * 2),
                  der_int(int.from_bytes(s1b, 'big'), d * 2),
                  der_int(_QCMDPC_R),
                  der_int(d))
    return pem_wrap(_LABEL_KEM_PRIV, der)


def _decode_kem_privkey(path):
    """Returns (sup0 set, sup1 set, h0 int, h1 int)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_KEM_PRIV:
        raise ValueError(f"Expected HPKE-Stern-KEM private key, got {label!r}")
    h0_int, h1_int, s0_int, s1_int, r, d = ints
    # r and d each size a to_bytes() below.  d additionally indexes the support
    # arrays, and in the C reader it sized a fixed stack buffer (TODO #239).
    r  = _bounded(r, 1, _QCMDPC_R, 'QC-MDPC block length r', 'pkey')
    d  = _bounded(d, 1, _QCMDPC_D, 'QC-MDPC row weight d',   'pkey')
    rb = (r + 7) // 8
    h0 = int.from_bytes(h0_int.to_bytes(rb, 'big'), 'little')
    h1 = int.from_bytes(h1_int.to_bytes(rb, 'big'), 'little')
    s0b = s0_int.to_bytes(d * 2, 'big')
    s1b = s1_int.to_bytes(d * 2, 'big')
    sup0 = {int.from_bytes(s0b[k*2:k*2+2], 'big') for k in range(d)}
    sup1 = {int.from_bytes(s1b[k*2:k*2+2], 'big') for k in range(d)}
    return sup0, sup1, h0, h1


def _encode_kem_pubkey(h_pub):
    """HPKE-Stern-KEM public key: SEQUENCE(h_pub, r)."""
    rb = _QCMDPC_RBYTES
    hpb = int.from_bytes(h_pub.to_bytes(rb, 'little'), 'big')
    der = der_seq(der_int(hpb, rb), der_int(_QCMDPC_R))
    return pem_wrap(_LABEL_KEM_PUB, der)


def _decode_kem_pubkey(path):
    """Returns (h_pub int, r int)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_KEM_PUB:
        raise ValueError(f"Expected HPKE-Stern-KEM public key, got {label!r}")
    hpb_int, r = ints
    rb = (r + 7) // 8
    h_pub = int.from_bytes(hpb_int.to_bytes(rb, 'big'), 'little')
    return h_pub, r


def _encode_kem_ct(syn, E_int):
    """HPKE-Stern-KEM ciphertext: SEQUENCE(syn, E, r).  No e' — BGF decodes."""
    rb = _QCMDPC_RBYTES
    syn_int = int.from_bytes(syn.to_bytes(rb, 'little'), 'big')
    der = der_seq(der_int(syn_int, rb),
                  der_int(E_int, KEYBITS // 8),
                  der_int(_QCMDPC_R))
    return pem_wrap(_LABEL_CT, der)


def _decode_kem_ct(path):
    """Returns (syn int, E_int int, r int)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    syn_int, E_int, r = ints
    rb = (r + 7) // 8
    syn = int.from_bytes(syn_int.to_bytes(rb, 'big'), 'little')
    return syn, E_int, r


# ---------------------------------------------------------------------------
# Signature serialization (HPKS / HPKS-NL — Schnorr)
# ---------------------------------------------------------------------------

def _encode_schnorr_sig(s_int, R_int, e_int, nbits):
    nbytes = nbits // 8
    der = der_seq(der_int(s_int, nbytes),
                  der_int(R_int, nbytes),
                  der_int(e_int, nbytes),
                  der_int(nbits))
    return pem_wrap(_LABEL_SIG, der)


def _decode_schnorr_sig(path):
    label, ints = _read_pem_ints(path)
    if label != _LABEL_SIG:
        raise ValueError(f"Expected SIGNATURE PEM, got {label!r}")
    s_int, R_int, e_int, nbits = ints
    return s_int, R_int, e_int, nbits


# ---------------------------------------------------------------------------
# Signature serialization (HPKS-Stern-F)
# Stores: n, rounds, packed commits (3×rounds×n bits), packed challenges
# (2 bits each), packed responses (2×n bits per round).
# ---------------------------------------------------------------------------

def _pack_stern_sig(sig, n):
    commits, challenges, responses = sig
    rounds  = len(commits)
    nbytes  = n // 8

    commits_ba = bytearray()
    for c0, c1, c2 in commits:
        commits_ba += c0.uint.to_bytes(nbytes, 'big')
        commits_ba += c1.uint.to_bytes(nbytes, 'big')
        commits_ba += c2.uint.to_bytes(nbytes, 'big')

    chal_bytes = bytearray((rounds + 3) // 4)
    for i, b in enumerate(challenges):
        chal_bytes[i // 4] |= (b & 3) << ((i % 4) * 2)

    resp_ba = bytearray()
    for resp in responses:
        v0 = resp[0].uint if isinstance(resp[0], BitArray) else resp[0]
        v1 = resp[1].uint if isinstance(resp[1], BitArray) else resp[1]
        resp_ba += v0.to_bytes(nbytes, 'big')
        resp_ba += v1.to_bytes(nbytes, 'big')

    c_int  = int.from_bytes(commits_ba, 'big')
    ch_int = int.from_bytes(chal_bytes, 'big')
    r_int  = int.from_bytes(resp_ba,   'big')

    der = der_seq(der_int(n),
                  der_int(rounds),
                  der_int(c_int,  len(commits_ba)),
                  der_int(ch_int, len(chal_bytes)),
                  der_int(r_int,  len(resp_ba)))
    return pem_wrap(_LABEL_SIG, der)


def _unpack_stern_sig(path):
    """Return (commits, challenges, responses, n) from a Stern-F signature PEM."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_SIG:
        raise ValueError(f"Expected SIGNATURE PEM, got {label!r}")
    n, rounds, c_int, ch_int, r_int = ints
    n      = _bounded_n(n, 'verify')
    rounds = _bounded(rounds, 1, _SDF_MAX_ROUNDS, 'round count', 'verify')
    nbytes = n // 8

    commits_ba = c_int.to_bytes(3 * rounds * nbytes, 'big')
    commits = []
    for i in range(rounds):
        off = i * 3 * nbytes
        c0 = BitArray(n, int.from_bytes(commits_ba[off           :off + nbytes],     'big'))
        c1 = BitArray(n, int.from_bytes(commits_ba[off + nbytes  :off + 2 * nbytes], 'big'))
        c2 = BitArray(n, int.from_bytes(commits_ba[off + 2*nbytes:off + 3 * nbytes], 'big'))
        commits.append((c0, c1, c2))

    chal_nb    = (rounds + 3) // 4
    chal_bytes = ch_int.to_bytes(chal_nb, 'big')
    challenges = [(chal_bytes[i // 4] >> ((i % 4) * 2)) & 3 for i in range(rounds)]

    resp_ba   = r_int.to_bytes(2 * rounds * nbytes, 'big')
    responses = []
    for i in range(rounds):
        off = i * 2 * nbytes
        v0  = int.from_bytes(resp_ba[off:off + nbytes],          'big')
        v1  = int.from_bytes(resp_ba[off + nbytes:off + 2*nbytes], 'big')
        b   = challenges[i]
        if b == 0:
            responses.append((v0, v1))
        else:
            responses.append((BitArray(n, v0), v1))

    return commits, challenges, responses, n


# ---------------------------------------------------------------------------
# HPKS-Stern-Ring signature codec (TODO #121)
#
# Member-major, round-major flat blob; per (member, round) entry:
#   c0 || c1 || c2 || b(1 byte) || resp_a || resp_b   (each n-bit value = n/8 B).
# resp_a is a BitArray when b != 0 (pi_seed), else an integer (sr); resp_b is
# always an integer.  PEM: SEQ(k, rounds, n, blob).
# ---------------------------------------------------------------------------

def _pack_ring_sig(sig, n):
    all_commits, all_challenges, all_responses = sig
    k      = len(all_challenges)
    rounds = len(all_challenges[0])
    nbytes = n // 8

    def _vb(v):
        iv = v.uint if isinstance(v, BitArray) else int(v)
        return iv.to_bytes(nbytes, 'big')

    blob = bytearray()
    for i in range(k):
        for r in range(rounds):
            c0, c1, c2 = all_commits[i][r]
            ra, rb     = all_responses[i][r]
            blob += _vb(c0) + _vb(c1) + _vb(c2)
            blob += bytes([all_challenges[i][r] & 0xFF])
            blob += _vb(ra) + _vb(rb)

    der = der_seq(der_int(k), der_int(rounds), der_int(n),
                  der_int(int.from_bytes(blob, 'big'), len(blob)))
    return pem_wrap(_LABEL_RING_SIG, der)


def _unpack_ring_sig(path):
    """Return (sig, k, rounds, n) — sig = (all_commits, all_challenges, all_responses)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_RING_SIG:
        raise ValueError(f"Expected HPKS-RING SIGNATURE PEM, got {label!r}")
    # Bounded before use: k, rounds and n each multiply into the blob length
    # below, and `verify`'s own k/n cross-checks only run after this returns.
    k      = _bounded(ints[0], 2, _RING_MAX_K,     'ring member count', 'verify')
    rounds = _bounded(ints[1], 1, _SDF_MAX_ROUNDS, 'round count',       'verify')
    n      = _bounded_n(ints[2], 'verify')
    blob_int = ints[3]
    nbytes = n // 8
    entry  = 5 * nbytes + 1
    blen   = k * rounds * entry
    if _int_nbytes(blob_int) > blen:
        sys.exit(f"verify: HPKS-RING signature payload is "
                 f"{_int_nbytes(blob_int)} bytes, but k={k} rounds={rounds} "
                 f"n={n} describe {blen}")
    blob   = blob_int.to_bytes(blen, 'big')

    all_commits    = [[None] * rounds for _ in range(k)]
    all_challenges = [[0]    * rounds for _ in range(k)]
    all_responses  = [[None] * rounds for _ in range(k)]
    off = 0
    for i in range(k):
        for r in range(rounds):
            c0 = BitArray(n, int.from_bytes(blob[off:off+nbytes], 'big')); off += nbytes
            c1 = BitArray(n, int.from_bytes(blob[off:off+nbytes], 'big')); off += nbytes
            c2 = BitArray(n, int.from_bytes(blob[off:off+nbytes], 'big')); off += nbytes
            b  = blob[off]; off += 1
            ra = int.from_bytes(blob[off:off+nbytes], 'big'); off += nbytes
            rb = int.from_bytes(blob[off:off+nbytes], 'big'); off += nbytes
            all_commits[i][r]    = (c0, c1, c2)
            all_challenges[i][r] = b
            all_responses[i][r]  = ((ra if b == 0 else BitArray(n, ra)), rb)
    return (all_commits, all_challenges, all_responses), k, rounds, n


def _load_ring_pubkeys(ring_arg):
    """Parse a comma-separated list of hpks-stern public-key PEM paths.

    Returns (ring_keys, n) where ring_keys[i] = (seed BitArray, syndrome int)."""
    paths = [p for p in ring_arg.split(',') if p]
    if len(paths) < 2:
        sys.exit("hpks-ring: --ring needs at least 2 member public keys")
    ring_keys, ring_n = [], None
    for p in paths:
        algo_i, ints_i = _decode_pubkey(p)
        if algo_i != 'hpks-stern':
            sys.exit(f"hpks-ring: ring member {p!r} is {algo_i!r}, expected hpks-stern")
        syn_i, seed_i, n_i = ints_i
        if ring_n is None:
            ring_n = n_i
        elif n_i != ring_n:
            sys.exit("hpks-ring: all ring members must share the same n")
        ring_keys.append((BitArray(n_i, seed_i), syn_i))
    return ring_keys, ring_n


# ---------------------------------------------------------------------------
# Key-loading helper for enc/dec (accepts both SESSION KEY and RNL RESPONSE)
# ---------------------------------------------------------------------------

def _load_key(path):
    """Return (key_int, nbits) from a session key PEM or hex string."""
    raw = _read_file(path)
    key_str = raw.decode('ascii', errors='replace').strip()
    if key_str.startswith('0x') or key_str.startswith('0X'):
        key_int = int(key_str, 16)
        nbits   = max(32, ((key_int.bit_length() + 31) // 32) * 32)
        return key_int, nbits
    return _decode_session_key(path)


# ---------------------------------------------------------------------------
# Sub-command: genpkey
# ---------------------------------------------------------------------------

def cmd_genpkey(args):
    algo = args.algo
    bits = args.bits or KEYBITS

    if algo in _CLASSICAL_GF_ALGOS:
        poly    = GF_POLY.get(bits, GF_POLY[256])
        a       = BitArray.random(bits)
        C       = BitArray(bits, gf_pow(GF_GEN, a.uint, poly, bits))
        pem_out = _encode_classical_privkey(a.uint, C.uint, bits, algo)

    elif algo == 'hkex-rnl':
        # Ring dimension is independent of the derived key width (TODO #223):
        # the ring must be 1024 for 128-bit security, the session key stays
        # KEYBITS.  --bits still overrides, for interop with older/other sizes.
        n       = args.bits or RNLN
        m_base  = _rnl_m_poly(n)
        a_rand  = _rnl_rand_poly(n, RNLQ)
        m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)   # randomised m_blind
        s, C    = _rnl_keygen(m_blind, n, RNLQ, RNLP, RNLB)
        n_a     = os.urandom(32)                          # Alice's contributory nonce
        pem_out = _encode_rnl_privkey(s, m_blind, n, n_a)

    elif algo in _STERN_ALGOS:
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        seed, e_int, syn = stern_f_keygen(bits)
        pem_out = _encode_stern_privkey(e_int, seed, bits, algo)

    elif algo in _ZKP_NL_ALGOS:
        n = bits if bits != KEYBITS else _ZKP_NL_DEFAULT_N
        A, B, y = zkp_nl_keygen(n)
        pem_out = encode_zkp_nl_privkey(A, B, y, n)

    elif algo == 'oprf':
        k   = oprf_keygen()
        der = der_seq(der_int(k, bits // 8), der_int(bits))
        pem_out = pem_wrap(_PRIV_ALGOS['oprf'], der)

    elif algo == 'hpks-xmss':
        import secrets as _sec
        h_val = getattr(args, 'xmss_height', None) or 10
        master_seed = _sec.token_bytes(32)
        print(f"Generating XMSS tree (h={h_val}, {1<<h_val} leaves) — may take a moment…",
              file=sys.stderr)
        sk_seed, root, leaf_hashes = hpks_xmss_keygen(master_seed, h_val)
        pem_out = _encode_xmss_privkey(master_seed, h_val, 0, leaf_hashes)
        # Write state file alongside output if output is a named file
        out_path = args.out
        if out_path and out_path != '-':
            _xmss_write_idx(out_path, 0)

    elif algo == 'hpks-wots':
        import secrets as _sec
        master_seed = _sec.token_bytes(32)
        pem_out = _encode_wots_privkey(master_seed, 0)
        out_path = args.out
        if out_path and out_path != '-':
            _xmss_write_idx(out_path, 0)   # 0 = unused (one-time key)
        print("HPKS-WOTS: ONE-TIME key — it may sign exactly one message.",
              file=sys.stderr)

    elif algo == 'hcred':
        # args.bits is None when --bits is omitted → use _HCRED_DEFAULT_N (32, demo speed).
        # --bits N uses N directly, including --bits 256 for C interop.
        n = args.bits if args.bits is not None else _HCRED_DEFAULT_N
        m_base  = _suite_mod._rnl_m_poly(n)
        a_rand  = _suite_mod._rnl_rand_poly(n, RNLQ)
        m_blind = [(m_base[i] + a_rand[i]) % RNLQ for i in range(n)]
        s, C, e_int = hcred_user_keygen(m_blind, n)
        seed_H = BitArray.random(n)
        syndr  = hcred_syndrome(seed_H, e_int, n)
        pem_out = encode_hcred_privkey(s, C, m_blind, seed_H.uint, syndr, n)

    elif algo == 'hpke-stern-kem':
        sup0, sup1, h0, h1, h_pub = qcmdpc_keygen()
        pem_out = _encode_kem_privkey(sup0, sup1, h0, h1)

    else:
        sys.exit(f"Unknown algorithm: {algo!r}")

    passphrase = getattr(args, 'passphrase', None)
    if passphrase:
        iterations = getattr(args, 'kdf_iterations', _PBKDF2_HFSCX256_ITER_DEMO)
        pem_out = _encrypt_pem(pem_out, passphrase, iterations)

    _write_file(args.out or '-', pem_out)


# ---------------------------------------------------------------------------
# Sub-command: pkey
# ---------------------------------------------------------------------------

def cmd_pkey(args):
    in_path = getattr(args, 'in')

    if getattr(args, 'decrypt', False):
        # TODO #166: recover the original cleartext PEM (any algorithm) from a
        # passphrase-encrypted envelope. The result is byte-for-byte the original
        # PEM, so it can be fed to any other subcommand unmodified.
        passphrase = args.passphrase
        if not passphrase:
            sys.exit("pkey --decrypt: --passphrase required")
        enc_text = _read_file(in_path).decode('ascii')
        try:
            plain_pem = _decrypt_pem(enc_text, passphrase)
        except ValueError as e:
            sys.exit(f"pkey --decrypt: {e}")
        _write_file(args.out or '-', plain_pem)
        return

    algo, ints = _decode_privkey(in_path)

    if args.pubout:
        if algo in _CLASSICAL_GF_ALGOS:
            priv_int, pub_int, nbits = ints
            pem_out = _encode_classical_pubkey(pub_int, nbits, algo)
        elif algo == 'hkex-rnl':
            s_poly, m_poly, n, n_a = _decode_rnl_privkey(ints)
            C_poly  = _rnl_derive_C(m_poly, s_poly, n)
            pem_out = _encode_rnl_pubkey(C_poly, m_poly, n, n_a)
        elif algo in _STERN_ALGOS:
            e_int, seed_int, n = ints
            syn   = _suite_mod._stern_syndrome(seed_int, e_int, n, n // 2)
            seed  = BitArray(n, seed_int)
            pem_out = _encode_stern_pubkey(syn, seed, n, algo)
        elif algo in _ZKP_NL_ALGOS:
            A, B, y, n = ints
            pem_out = encode_zkp_nl_pubkey(B, y, n)
        elif algo == 'hpks-xmss':
            master_seed, h, _, leaf_hashes, root = _decode_xmss_privkey(in_path)
            pem_out = _encode_xmss_pubkey(root, h)
        elif algo == 'hpks-wots':
            master_seed, leaf_idx = _decode_wots_privkey(in_path)
            _sk, pk = hpks_wots_keygen(master_seed, leaf_idx)
            pem_out = _encode_wots_pubkey(pk)
        elif algo == 'hcred':
            s, C, m, seed_H_int, syndr, n = ints
            pem_out = encode_hcred_pubkey(C, m, seed_H_int, syndr, n)
        elif algo == 'hpke-stern-kem':
            sup0, sup1, h0, h1 = _decode_kem_privkey(in_path)
            h0_inv = _qcp_inv(h0, _QCMDPC_R)
            h_pub  = _qcp_mul(h1, h0_inv, _QCMDPC_R)
            pem_out = _encode_kem_pubkey(h_pub)
        else:
            sys.exit(f"Unknown algorithm: {algo!r}")
        _write_file(args.out or '-', pem_out)

    elif args.text:
        if algo in _CLASSICAL_GF_ALGOS:
            priv_int, pub_int, nbits = ints
            print(f"algorithm : {algo}")
            print(f"bits      : {nbits}")
            print(f"private   : {priv_int:0{nbits//4}x}")
            print(f"public    : {pub_int:0{nbits//4}x}")
        elif algo == 'hkex-rnl':
            s_poly, m_poly, n, n_a = _decode_rnl_privkey(ints)
            C_poly = _rnl_derive_C(m_poly, s_poly, n)
            C_packed, _ = pack_poly(C_poly, 2)
            s_packed, _ = pack_poly(s_poly, 4)
            print(f"algorithm : {algo}")
            print(f"n         : {n}")
            print(f"s_packed  : {s_packed:0{n}x}")
            print(f"C_packed  : {C_packed:0{n//2}x}")
            print(f"n_A       : {n_a.hex()}")
        elif algo in _STERN_ALGOS:
            e_int, seed_int, n = ints
            print(f"algorithm : {algo}")
            print(f"n         : {n}")
            print(f"e_int     : {e_int:0{n//4}x}")
            print(f"seed      : {seed_int:0{n//4}x}")
        elif algo == 'hcred':
            s, C, m, seed_H_int, syndr, n = ints
            print(f"algorithm : hcred")
            print(f"n         : {n}")
            print(f"seed_H    : {seed_H_int:0{n//4}x}")
            print(f"syndr     : {syndr:0{n//8}x}")
            print(f"W (weight): {bin(hcred_phi(s)).count('1')}")
    else:
        sys.exit("Specify --pubout or --text")


# ---------------------------------------------------------------------------
# Sub-command: kex
# ---------------------------------------------------------------------------

def cmd_kex(args):
    algo     = args.algo
    our_path = args.our
    their_path = args.their
    kdf_mode = getattr(args, 'kdf', 'none')
    if kdf_mode == 'sp800227' and algo != 'hkex-rnl':
        sys.exit("kex: --kdf sp800227 is only defined for --algo hkex-rnl (TODO #165)")

    def _apply_kdf(k_int, nbits):
        if kdf_mode != 'hfscx-256':
            return k_int
        raw = k_int.to_bytes(nbits // 8, 'big')
        return int.from_bytes(hfscx_256(raw), 'big')

    if algo == 'hkex-gf':
        our_algo,   our_ints   = _decode_privkey(our_path)
        their_algo, their_ints = _decode_pubkey(their_path)
        priv_int, _, nbits = our_ints
        pub_int = their_ints[0]
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        sk_int  = _apply_kdf(gf_pow(pub_int, priv_int, poly, nbits), nbits)
        _write_file(args.out, _encode_session_key(sk_int, nbits))

    elif algo == 'hkex-rnl':
        # Detect protocol step from the type of --their file
        their_label, their_ints = _read_pem_ints(their_path)

        if their_label == _PUB_ALGOS['hkex-rnl']:
            # ── STEP 1: Bob responds to Alice's public key ──────────────────
            # Bob has: s_B (private), reads C_A and m_A from Alice's pubkey.
            # Re-derives C_B = round_p(m_A * s_B) using Alice's m_blind.
            # Generates n_B, applies contributory KDF, writes RESPONSE PEM.
            our_algo, our_ints = _decode_privkey(our_path)
            s_B, _, n, _ = _decode_rnl_privkey(our_ints)
            C_A, m_A, n_their, n_a = _decode_rnl_pubkey(their_ints)
            if n != n_their:
                sys.exit(f"Ring size mismatch: ours n={n}, theirs n={n_their}")
            if not _rnl_validate_m_blind(m_A):
                sys.exit("kex hkex-rnl: peer m_blind failed entropy check — possible substitution attack")
            C_B       = _rnl_derive_C(m_A, s_B, n)
            K_B, hint = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n, _rnl_key_bits(n))
            n_b       = os.urandom(32)
            K_B_int   = _rnl_contributory_kdf(K_B.uint, _rnl_key_bits(n), n_a, n_b)
            if kdf_mode == 'sp800227':
                K_B_int = _hkex_rnl_sp800227_kdf(K_B_int, _rnl_session_bits(n), C_A, m_A, C_B, hint[:n // 2])
            else:
                K_B_int = _apply_kdf(K_B_int, _rnl_session_bits(n))
            _write_file(args.out, _encode_rnl_response(K_B_int, C_B, hint, n, n_b))

        elif their_label == _LABEL_RNL_RESP:
            # ── STEP 2: Alice completes the handshake ───────────────────────
            # Alice has: s_A (private), reads C_B, hint, n_B from Bob's response.
            # Applies contributory KDF with her n_A and Bob's n_B.
            our_algo, our_ints = _decode_privkey(our_path)
            s_A, m_A, n, n_a = _decode_rnl_privkey(our_ints)
            _, C_B, hint, n_resp, n_b = _decode_rnl_response(their_path)
            if n != n_resp:
                sys.exit(f"Ring size mismatch: ours n={n}, response n={n_resp}")
            K_A     = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n, _rnl_key_bits(n), hint)
            K_A_int = _rnl_contributory_kdf(K_A.uint, _rnl_key_bits(n), n_a, n_b)
            if kdf_mode == 'sp800227':
                C_A     = _rnl_derive_C(m_A, s_A, n)
                K_A_int = _hkex_rnl_sp800227_kdf(K_A_int, _rnl_session_bits(n), C_A, m_A, C_B, hint[:n // 2])
            else:
                K_A_int = _apply_kdf(K_A_int, _rnl_session_bits(n))
            _write_file(args.out, _encode_session_key(K_A_int, _rnl_session_bits(n)))

        else:
            sys.exit(
                f"kex hkex-rnl: --their must be an HKEX-RNL PUBLIC KEY or RESPONSE PEM "
                f"(got label {their_label!r})"
            )

    elif algo == 'hybrid-rnl-stern':
        # TODO #162: hybrid classical-PQC-diversity combiner — HKEX-RNL (lattice-based)
        # + HPKE-Stern-KEM/QC-MDPC (code-based) as two independent PQC assumptions,
        # combined per SP 800-227 §4.6's IND-CCA-preserving shape (TODO #165's finding).
        their_label, their_ints = _read_pem_ints(their_path)

        if their_label == _PUB_ALGOS['hkex-rnl']:
            # ── STEP 1: Bob responds — encapsulator for both components ──────
            if not args.their_kem:
                sys.exit("kex hybrid-rnl-stern: --their-kem required "
                         "(Alice's HPKE-Stern-KEM public key)")
            our_algo, our_ints = _decode_privkey(our_path)
            s_B, _, n, _ = _decode_rnl_privkey(our_ints)
            C_A, m_A, n_their, n_a = _decode_rnl_pubkey(their_ints)
            if n != n_their:
                sys.exit(f"Ring size mismatch: ours n={n}, theirs n={n_their}")
            if not _rnl_validate_m_blind(m_A):
                sys.exit("kex hybrid-rnl-stern: peer m_blind failed entropy "
                         "check — possible substitution attack")
            h_pub, r_qc = _decode_kem_pubkey(args.their_kem)

            C_B         = _rnl_derive_C(m_A, s_B, n)
            K1, hint    = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n, _rnl_key_bits(n))
            n_b         = os.urandom(32)
            K1_int      = _rnl_contributory_kdf(K1.uint, _rnl_key_bits(n), n_a, n_b)
            K1_int      = _apply_kdf(K1_int, _rnl_session_bits(n))

            syn, K2_int = qcmdpc_encap(h_pub)

            hint_used = hint[:n // 2]
            K_int = _hybrid_rnl_stern_combine(K1_int, K2_int, C_A, m_A, C_B,
                                              hint_used, h_pub, syn, n, r_qc)
            _write_file(args.out, _encode_hybrid_response(
                K_int, C_B, hint_used, n, n_b, syn, r_qc))

        elif their_label == _LABEL_HYBRID_RESP:
            # ── STEP 2: Alice completes — decapsulator for the KEM component ─
            if not args.our_kem:
                sys.exit("kex hybrid-rnl-stern: --our-kem required "
                         "(Alice's own HPKE-Stern-KEM private key)")
            our_algo, our_ints = _decode_privkey(our_path)
            s_A, m_A, n, n_a = _decode_rnl_privkey(our_ints)
            (_, C_B, hint_used, n_resp, n_b,
             syn, r_qc) = _decode_hybrid_response(their_path)
            if n != n_resp:
                sys.exit(f"Ring size mismatch: ours n={n}, response n={n_resp}")
            sup0, sup1, h0, h1 = _decode_kem_privkey(args.our_kem)
            h0_inv = _qcp_inv(h0, r_qc)
            h_pub  = _qcp_mul(h1, h0_inv, r_qc)
            C_A    = _rnl_derive_C(m_A, s_A, n)

            K1     = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n, _rnl_key_bits(n), hint_used)
            K1_int = _rnl_contributory_kdf(K1.uint, _rnl_key_bits(n), n_a, n_b)
            K1_int = _apply_kdf(K1_int, _rnl_session_bits(n))

            K2_int = qcmdpc_decap_bgf(syn, sup0, sup1, h0)
            if K2_int is None:
                sys.exit("kex hybrid-rnl-stern: HPKE-Stern-KEM decapsulation "
                         "failed (DFR event or corrupt ciphertext)")

            K_int = _hybrid_rnl_stern_combine(K1_int, K2_int, C_A, m_A, C_B,
                                              hint_used, h_pub, syn, n, r_qc)
            _write_file(args.out, _encode_session_key(K_int, _rnl_session_bits(n)))

        else:
            sys.exit(
                f"kex hybrid-rnl-stern: --their must be an HKEX-RNL PUBLIC KEY or "
                f"HYBRID-RNL-STERN RESPONSE PEM (got label {their_label!r})"
            )

    else:
        sys.exit(f"kex: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: enc
# ---------------------------------------------------------------------------

def cmd_enc(args):
    algo     = args.algo
    in_bytes = _read_file(getattr(args, 'in'))
    out_path = args.out

    # ── HSKE-NL-V2-Duplex AEAD (arbitrary-length, single-pass) ──────────────
    if algo == 'hske-duplex':
        key_path = args.key
        if not key_path:
            sys.exit(f"--key required for {algo}")
        key_int, nbits = _load_key(key_path)
        if nbits != 256:
            sys.exit("enc: hske-duplex requires a 256-bit key")
        K = BitArray(nbits, key_int)
        ad = (args.ad or '').encode()
        nonce, ct, tag = hske_nl_v2_duplex_encrypt(K, in_bytes, ad)
        _write_file(out_path, _encode_duplex_ct(
            nonce.uint, ct, int.from_bytes(tag, 'big'), nbits))
        return

    # ── Symmetric algos ─────────────────────────────────────────────────────
    if algo in ('hske', 'hske-nla1', 'hske-nla2'):
        key_path = args.key
        if not key_path:
            sys.exit(f"--key required for {algo}")
        key_int, nbits = _load_key(key_path)
        nbytes  = nbits // 8
        in_padded = in_bytes[:nbytes].ljust(nbytes, b'\x00')
        P = BitArray(nbits, int.from_bytes(in_padded, 'big'))
        K = BitArray(nbits, key_int)

        if algo == 'hske':
            E = fscx_revolve(P, K, nbits // 4)
            _write_file(out_path, _encode_sym_ct('hske', E.uint, nbits))

        elif algo == 'hske-nla1':
            N_nonce = BitArray.random(nbits)
            if getattr(args, 'aead', False):
                # HSKE-NL-AEAD (TODO #95): format tag 2 with auth tag
                if nbits != 256:
                    sys.exit("enc: --aead requires a 256-bit key")
                ad = (args.ad or '').encode()
                _, ct, tag = hske_nl_aead_encrypt(K, in_padded, ad, nonce=N_nonce)
                _write_file(out_path, _encode_sym_ct(
                    'hske-nla1', int.from_bytes(ct, 'big'), nbits,
                    nonce_int=N_nonce.uint, tag_int=int.from_bytes(tag, 'big')))
                return
            if args.ad:
                sys.exit("enc: --ad requires --aead")
            base    = BitArray(nbits, K.uint ^ N_nonce.uint)
            seed    = BitArray(nbits, base.rotated(nbits // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - nbits)))
            ks      = nl_fscx_revolve_v1(seed, BitArray(nbits, base.uint ^ 0), nbits // 4)
            E       = BitArray(nbits, P.uint ^ ks.uint)
            _write_file(out_path, _encode_sym_ct('hske-nla1', E.uint, nbits, nonce_int=N_nonce.uint))

        else:  # hske-nla2
            if not nl_v2_key_is_valid(K):
                sys.exit("enc hske-nla2: %s" % _WEAK_V2_KEY_MSG)
            E = nl_fscx_revolve_v2(P, K, 3 * nbits // 4)
            _write_file(out_path, _encode_sym_ct('hske-nla2', E.uint, nbits))
        return

    # ── Asymmetric algos ────────────────────────────────────────────────────
    pubkey_path = args.pubkey
    if not pubkey_path:
        sys.exit(f"--pubkey required for {algo}")
    their_algo, their_ints = _decode_pubkey(pubkey_path)

    if algo == 'hpke':
        pub_int, nbits = their_ints
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        nbytes  = nbits // 8
        P       = BitArray(nbits, int.from_bytes(in_bytes[:nbytes].ljust(nbytes, b'\x00'), 'big'))
        r       = BitArray.random(nbits)
        R       = BitArray(nbits, gf_pow(GF_GEN, r.uint, poly, nbits))
        enc_key = BitArray(nbits, gf_pow(pub_int, r.uint, poly, nbits))
        E       = fscx_revolve(P, enc_key, nbits // 4)
        _write_file(out_path, _encode_asym_ct(R.uint, E.uint, nbits))

    elif algo == 'hpke-nl':
        pub_int, nbits = their_ints
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        nbytes  = nbits // 8
        P       = BitArray(nbits, int.from_bytes(in_bytes[:nbytes].ljust(nbytes, b'\x00'), 'big'))
        # r is ours to choose, so resample past the ~2^-129 affine-weak-key class
        # (TODO #168) rather than failing an honest encryption.
        for _ in range(64):
            r       = BitArray.random(nbits)
            R       = BitArray(nbits, gf_pow(GF_GEN, r.uint, poly, nbits))
            enc_key = BitArray(nbits, gf_pow(pub_int, r.uint, poly, nbits))
            if nl_v2_key_is_valid(enc_key):
                break
        else:
            sys.exit("enc hpke-nl: could not sample a non-degenerate ephemeral key")
        E       = nl_fscx_revolve_v2(P, enc_key, nbits // 4)
        _write_file(out_path, _encode_asym_ct(R.uint, E.uint, nbits))

    elif algo == 'hpke-stern':
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        syn_int, seed_int, n = their_ints
        seed    = BitArray(n, seed_int)
        nbytes  = n // 8
        P       = BitArray(n, int.from_bytes(in_bytes[:nbytes].ljust(nbytes, b'\x00'), 'big'))
        K, ct_syn, e_p = hpke_stern_f_encap_with_e(seed, n)
        E       = fscx_revolve(P, K, n // 4)
        _write_file(out_path, _encode_stern_ct(ct_syn, e_p, K.uint, E.uint, n))

    elif algo == 'hpke-stern-kem':
        h_pub, r = _decode_kem_pubkey(pubkey_path)
        nbytes = KEYBITS // 8
        P = BitArray(KEYBITS, int.from_bytes(in_bytes[:nbytes].ljust(nbytes, b'\x00'), 'big'))
        syn, K_int = qcmdpc_encap(h_pub)
        K = BitArray(KEYBITS, K_int)
        E = fscx_revolve(P, K, I_VALUE)
        _write_file(out_path, _encode_kem_ct(syn, E.uint))

    else:
        sys.exit(f"enc: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: dec
# ---------------------------------------------------------------------------

def cmd_dec(args):
    algo     = args.algo
    out_path = args.out

    # ── HSKE-NL-V2-Duplex AEAD (arbitrary-length, single-pass) ──────────────
    if algo == 'hske-duplex':
        key_path = args.key
        if not key_path:
            sys.exit(f"--key required for {algo}")
        key_int, nbits = _load_key(key_path)
        if nbits != 256:
            sys.exit("dec: hske-duplex requires a 256-bit key")
        K = BitArray(nbits, key_int)
        nonce_int, ct_bytes, tag_int, _nb = _decode_duplex_ct(getattr(args, 'in'))
        ad = (getattr(args, 'ad', None) or '').encode()
        pt = hske_nl_v2_duplex_decrypt(K, BitArray(nbits, nonce_int), ct_bytes,
                                       tag_int.to_bytes(32, 'big'), ad)
        if pt is None:
            sys.exit("dec: authentication tag mismatch — "
                     "ciphertext corrupt, wrong key, or wrong --ad")
        _write_file(out_path, pt)
        return

    # ── Symmetric algos ─────────────────────────────────────────────────────
    if algo in ('hske', 'hske-nla1', 'hske-nla2'):
        key_path = args.key
        if not key_path:
            sys.exit(f"--key required for {algo}")
        key_int, nbits = _load_key(key_path)
        K = BitArray(nbits, key_int)

        E_int, _nbits, nonce_int, tag_int = _decode_sym_ct(getattr(args, 'in'))
        E = BitArray(nbits, E_int)

        if algo == 'hske-nla1' and tag_int is not None:
            # HSKE-NL-AEAD (TODO #95): verify-then-decrypt
            ad = (getattr(args, 'ad', None) or '').encode()
            pt = hske_nl_aead_decrypt(K, BitArray(nbits, nonce_int),
                                      E_int.to_bytes(nbits // 8, 'big'),
                                      tag_int.to_bytes(32, 'big'), ad)
            if pt is None:
                sys.exit("dec: authentication tag mismatch — "
                         "ciphertext corrupt, wrong key, or wrong --ad")
            _write_file(out_path, pt)
            return

        if algo == 'hske':
            D = fscx_revolve(E, K, 3 * nbits // 4)
        elif algo == 'hske-nla1':
            if nonce_int is None:
                sys.exit("hske-nla1 ciphertext missing nonce")
            N_nonce = BitArray(nbits, nonce_int)
            base    = BitArray(nbits, K.uint ^ N_nonce.uint)
            seed    = BitArray(nbits, base.rotated(nbits // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - nbits)))
            ks      = nl_fscx_revolve_v1(seed, BitArray(nbits, base.uint ^ 0), nbits // 4)
            D       = BitArray(nbits, E.uint ^ ks.uint)
        else:  # hske-nla2
            if not nl_v2_key_is_valid(K):
                sys.exit("dec hske-nla2: %s" % _WEAK_V2_KEY_MSG)
            D = nl_fscx_revolve_v2_inv(E, K, 3 * nbits // 4)

        _write_file(out_path, D.uint.to_bytes(nbits // 8, 'big'))
        return

    # ── Asymmetric algos ────────────────────────────────────────────────────
    key_path = args.key
    if not key_path:
        sys.exit(f"--key required for {algo}")
    our_algo, our_ints = _decode_privkey(key_path)

    if algo == 'hpke':
        priv_int, _, nbits = our_ints
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        R_int, E_int, _nb = _decode_asym_ct(getattr(args, 'in'))
        E       = BitArray(nbits, E_int)
        dec_key = BitArray(nbits, gf_pow(R_int, priv_int, poly, nbits))
        D       = fscx_revolve(E, dec_key, 3 * nbits // 4)
        _write_file(out_path, D.uint.to_bytes(nbits // 8, 'big'))

    elif algo == 'hpke-nl':
        priv_int, _, nbits = our_ints
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        R_int, E_int, _nb = _decode_asym_ct(getattr(args, 'in'))
        E       = BitArray(nbits, E_int)
        dec_key = BitArray(nbits, gf_pow(R_int, priv_int, poly, nbits))
        if not nl_v2_key_is_valid(dec_key):
            sys.exit("dec hpke-nl: %s" % _WEAK_V2_KEY_MSG)
        D       = nl_fscx_revolve_v2_inv(E, dec_key, nbits // 4)
        _write_file(out_path, D.uint.to_bytes(nbits // 8, 'big'))

    elif algo == 'hpke-stern':
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        e_int, seed_int, n = our_ints
        ct_syn, e_p, K_int, E_int, _n = _decode_stern_ct(getattr(args, 'in'))
        seed    = BitArray(n, seed_int)
        K_dec   = hpke_stern_f_decap(ct_syn, e_p, seed, n)
        if K_dec is None:
            sys.exit("HPKE-Stern-F decap failed (brute-force exhausted)")
        E       = BitArray(n, E_int)
        D       = fscx_revolve(E, K_dec, 3 * n // 4)
        _write_file(out_path, D.uint.to_bytes(n // 8, 'big'))

    elif algo == 'hpke-stern-kem':
        key_path = args.key
        sup0, sup1, h0, h1 = _decode_kem_privkey(key_path)
        syn, E_int, r = _decode_kem_ct(getattr(args, 'in'))
        K_int = qcmdpc_decap_bgf(syn, sup0, sup1, h0)
        if K_int is None:
            sys.exit("dec: HPKE-Stern-KEM BGF decoding failed (DFR event or corrupt ciphertext)")
        K = BitArray(KEYBITS, K_int)
        E = BitArray(KEYBITS, E_int)
        D = fscx_revolve(E, K, R_VALUE)
        _write_file(out_path, D.uint.to_bytes(KEYBITS // 8, 'big'))

    else:
        sys.exit(f"dec: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: sign
# ---------------------------------------------------------------------------

def cmd_sign(args):
    algo     = args.algo
    key_path = args.key
    in_bytes = _read_file(getattr(args, 'in'))
    if args.digest == 'hfscx-256':
        in_bytes = hfscx_256(in_bytes)   # pre-hash: sign the 32-byte digest

    our_algo, our_ints = _decode_privkey(key_path)

    if algo in ('hpks', 'hpks-nl'):
        priv_int, pub_int, nbits = our_ints
        poly = GF_POLY.get(nbits, GF_POLY[256])
        msg  = BitArray(nbits, int.from_bytes(in_bytes[:nbits // 8].ljust(nbits // 8, b'\x00'), 'big'))
        k    = BitArray.random(nbits)
        R    = BitArray(nbits, gf_pow(GF_GEN, k.uint, poly, nbits))
        if algo == 'hpks':
            e = fscx_revolve(R, msg, nbits // 4)
        else:
            e = nl_fscx_revolve_v1(R, msg, nbits // 4)
        ord_n = (1 << nbits) - 1
        s     = (k.uint - priv_int * e.uint) % ord_n
        _write_file(args.out, _encode_schnorr_sig(s, R.uint, e.uint, nbits))

    elif algo == 'hpks-stern':
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        e_int, seed_int, n = our_ints
        seed   = BitArray(n, seed_int)
        syn    = _suite_mod._stern_syndrome(seed_int, e_int, n, n // 2)
        msg    = BitArray(n, int.from_bytes(in_bytes[:n // 8].ljust(n // 8, b'\x00'), 'big'))
        rounds = getattr(args, 'rounds', None) or SDFR
        sig    = hpks_stern_f_sign(msg, e_int, seed, syn, n, rounds)
        _write_file(args.out, _pack_stern_sig(sig, n))

    elif algo == 'hpks-ring':
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        if our_algo != 'hpks-stern':
            sys.exit(f"hpks-ring sign: signer key must be hpks-stern, got {our_algo!r}")
        if not getattr(args, 'ring', None):
            sys.exit("hpks-ring sign: --ring (comma-separated member public keys) required")
        e_int, seed_int, n = our_ints
        ring_keys, ring_n = _load_ring_pubkeys(args.ring)
        if ring_n != n:
            sys.exit(f"hpks-ring sign: signer n={n} != ring n={ring_n}")
        # Locate the signer's own index in the ring (matched by seed).
        j = next((idx for idx, (sd, _sy) in enumerate(ring_keys)
                  if sd.uint == seed_int), None)
        if j is None:
            sys.exit("hpks-ring sign: signer's public key is not in --ring "
                     "(run pkey --pubout on the signer key and include it)")
        msg    = BitArray(n, int.from_bytes(in_bytes[:n // 8].ljust(n // 8, b'\x00'), 'big'))
        rounds = getattr(args, 'rounds', None) or SDFR
        sig    = hpks_stern_ring_sign(msg, e_int, j, ring_keys, n, rounds)
        _write_file(args.out, _pack_ring_sig(sig, n))
        print(f"Ring signature created (k={len(ring_keys)}); signer index is hidden.",
              file=sys.stderr)

    elif algo == 'rnl-sigma':
        # Sign using an HKEX-RNL private key: proves knowledge of s s.t. C = round_p(m·s)
        if our_algo != 'hkex-rnl':
            sys.exit(f"rnl-sigma sign: expected hkex-rnl key, got {our_algo!r}")
        s_poly, m_poly, n, _ = _decode_rnl_privkey(our_ints)
        C_poly = _rnl_derive_C(m_poly, s_poly, n)
        w, c, z = rnl_sigma_sign(s_poly, m_poly, C_poly, n, in_bytes)
        pem_out = encode_zkp_rnl_proof(w, c, z, n)
        _write_file(args.out, pem_out)

    elif algo == 'nl-zkboo':
        # Sign using a ZKP-NL private key: proves knowledge of A s.t. nl_fscx_v1(A,B)=y
        if our_algo != 'hpks-zkp-nl':
            sys.exit(f"nl-zkboo sign: expected hpks-zkp-nl key, got {our_algo!r}")
        A, B, y, n = our_ints
        rounds = getattr(args, 'rounds', None) or _ZKP_CLI_ROUNDS
        proof_rounds = zkp_nl_prove(A, B, y, n, rounds, in_bytes)
        pem_out = encode_zkp_nl_proof(proof_rounds, n)
        _write_file(args.out, pem_out)

    elif algo == 'nl-zkbpp':
        # ZKB++ compact encoding (Chase et al. 2017) of the same statement
        if our_algo != 'hpks-zkp-nl':
            sys.exit(f"nl-zkbpp sign: expected hpks-zkp-nl key, got {our_algo!r}")
        A, B, y, n = our_ints
        rounds = getattr(args, 'rounds', None) or _ZKP_CLI_ROUNDS
        # Pad/truncate to 32 bytes to match C/Go behavior
        msg = (in_bytes + b'\x00' * 32)[:32]
        proof_rounds = zkp_nl_prove_pp(A, B, y, n, rounds, msg)
        pem_out = encode_zkp_nl_pp_proof(proof_rounds, n)
        _write_file(args.out, pem_out)

    elif algo == 'hpks-xmss':
        master_seed, h, stored_idx, leaf_hashes, root = _decode_xmss_privkey(key_path)
        leaf_idx = _xmss_read_idx(key_path, h)
        num_leaves = 1 << h
        if leaf_idx >= num_leaves:
            sys.exit(f"sign: XMSS key exhausted ({num_leaves} leaves used). Generate a new key.")
        sig  = hpks_xmss_sign(in_bytes, master_seed, leaf_hashes, leaf_idx)
        pem_out = _pack_xmss_sig(sig, KEYBITS)
        _write_file(args.out, pem_out)
        _xmss_write_idx(key_path, leaf_idx + 1)
        print(f"XMSS leaf {leaf_idx} used; {num_leaves - leaf_idx - 1} leaves remaining.",
              file=sys.stderr)

    elif algo == 'hpks-wots':
        if our_algo != 'hpks-wots':
            sys.exit(f"hpks-wots sign: expected hpks-wots key, got {our_algo!r}")
        if _wots_is_used(key_path):
            sys.exit("sign: this HPKS-WOTS key was already used — WOTS keys are "
                     "ONE-TIME. Generate a fresh key (genpkey --algo hpks-wots).")
        master_seed, leaf_idx = _decode_wots_privkey(key_path)
        sig, _pk = hpks_wots_sign(in_bytes, master_seed, leaf_idx)
        _write_file(args.out, _pack_wots_sig(sig))
        _wots_mark_used(key_path)
        print("HPKS-WOTS key burned (one-time use); do not sign again with it.",
              file=sys.stderr)

    else:
        sys.exit(f"sign: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-commands: threshold signing phases (TODO #106)
# ---------------------------------------------------------------------------

def _load_hpks_privkey_for_threshold(key_path):
    """Load an hpks or hpks-nl private key; return (priv_int, pub_int, nbits)."""
    algo, ints = _decode_privkey(key_path)
    if algo not in ('hpks', 'hpks-nl'):
        sys.exit(f"threshold: expected hpks or hpks-nl key, got {algo!r}")
    return ints  # (priv_int, pub_int, nbits)


def cmd_threshold_commit(args):
    """Phase 1: generate nonce k_j, write commitment PEM and nonce PEM."""
    priv_int, pub_int, nbits = _load_hpks_privkey_for_threshold(args.key)
    poly = GF_POLY.get(nbits, GF_POLY[256])
    k_j  = BitArray.random(nbits)
    R_j  = BitArray(nbits, gf_pow(GF_GEN, k_j.uint, poly, nbits))
    _write_file(args.commit_out, encode_hpkst_commit(R_j.uint, pub_int, nbits).encode())
    _write_file(args.nonce_out,  encode_hpkst_nonce(k_j.uint, nbits).encode())


def cmd_threshold_aggregate(args):
    """Phase 2 (coordinator): read all commitment PEMs + message, write aggregate PEM."""
    commit_paths = args.commits
    R_parts = []
    pubkeys  = []
    nbits    = None
    for cp in commit_paths:
        text = _read_file(cp).decode('ascii')
        R_j, C_j, n = decode_hpkst_commit(text)
        if nbits is None:
            nbits = n
        elif nbits != n:
            sys.exit("aggregate: commitment n mismatch")
        R_parts.append(BitArray(n, R_j))
        pubkeys.append(BitArray(n, C_j))

    in_bytes = _read_file(getattr(args, 'in'))
    if args.digest == 'hfscx-256':
        in_bytes = hfscx_256(in_bytes)

    poly  = GF_POLY.get(nbits, GF_POLY[256])
    R_val = 1
    for Rj in R_parts:
        R_val = gf_mul(R_val, Rj.uint, poly, nbits)

    R     = BitArray(nbits, R_val)
    msg   = BitArray(nbits, int.from_bytes(in_bytes[:nbits // 8].ljust(nbits // 8, b'\x00'), 'big'))
    e     = nl_fscx_revolve_v1(R, msg, nbits // 4)

    C_agg, _coeffs = hpkst_aggregate_pubkeys(pubkeys)
    _write_file(args.out, encode_hpkst_aggregate(R.uint, C_agg.uint, e.uint, nbits).encode())


def cmd_threshold_respond(args):
    """Phase 3: each signer reads aggregate PEM + nonce PEM, writes partial sig PEM."""
    priv_int, pub_int, nbits = _load_hpks_privkey_for_threshold(args.key)

    # Load all commit PEMs to recompute mu_j
    commit_paths = args.commits
    pubkeys      = []
    for cp in commit_paths:
        text = _read_file(cp).decode('ascii')
        _R_j, C_j, n = decode_hpkst_commit(text)
        pubkeys.append(BitArray(n, C_j))

    # Load aggregate PEM
    agg_text       = _read_file(args.aggregate).decode('ascii')
    R_val, C_agg_val, e_val, n2 = decode_hpkst_aggregate(agg_text)
    if n2 != nbits:
        sys.exit("respond: aggregate n mismatch with key")

    # Load nonce PEM
    nonce_text     = _read_file(args.nonce).decode('ascii')
    k_j_val, n3   = decode_hpkst_nonce(nonce_text)
    if n3 != nbits:
        sys.exit("respond: nonce n mismatch with key")

    # Compute mu_j for this signer
    _C_agg_computed, coeffs = hpkst_aggregate_pubkeys(pubkeys)
    # Find our pubkey index
    our_pub = BitArray(nbits, pub_int)
    try:
        idx = next(i for i, pk in enumerate(pubkeys) if pk.uint == our_pub.uint)
    except StopIteration:
        sys.exit("respond: our public key not found in commit list")
    mu_j = coeffs[idx]

    ord_n = (1 << nbits) - 1
    e_ba  = BitArray(nbits, e_val)
    s_j   = (k_j_val - priv_int * mu_j * e_val) % ord_n
    _write_file(args.out, encode_hpkst_partial(s_j, nbits).encode())


def cmd_threshold_combine(args):
    """Phase 4 (coordinator): read all partial PEMs, write final HPKST SIGNATURE PEM."""
    # Load aggregate PEM for R and C_agg
    agg_text           = _read_file(args.aggregate).decode('ascii')
    R_val, C_agg_val, _e_val, nbits = decode_hpkst_aggregate(agg_text)

    ord_n  = (1 << nbits) - 1
    s_acc  = 0
    for pp in args.partials:
        text = _read_file(pp).decode('ascii')
        s_j, n = decode_hpkst_partial(text)
        if n != nbits:
            sys.exit("combine: partial n mismatch")
        s_acc = (s_acc + s_j) % ord_n

    _write_file(args.out, encode_hpkst_sig(C_agg_val, R_val, s_acc, nbits).encode())


# ---------------------------------------------------------------------------
# Sub-command: verify
# ---------------------------------------------------------------------------

def cmd_verify(args):
    algo        = args.algo
    pubkey_path = args.pubkey
    in_bytes    = _read_file(getattr(args, 'in'))
    if args.digest == 'hfscx-256':
        in_bytes = hfscx_256(in_bytes)   # pre-hash: verify against 32-byte digest
    sig_path    = args.sig

    if algo == 'hpks-t':
        sig_text       = _read_file(sig_path).decode('ascii')
        C_agg_val, R_val, s_val, nbits = decode_hpkst_sig(sig_text)
        msg   = BitArray(nbits, int.from_bytes(in_bytes[:nbits // 8].ljust(nbits // 8, b'\x00'), 'big'))
        C_agg = BitArray(nbits, C_agg_val)
        R     = BitArray(nbits, R_val)
        s     = BitArray(nbits, s_val)
        ok    = hpkst_verify(C_agg, R, s, msg)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    if algo == 'hpks-ring':
        if not getattr(args, 'ring', None):
            sys.exit("hpks-ring verify: --ring (comma-separated member public keys) required")
        ring_keys, n = _load_ring_pubkeys(args.ring)
        sig, k, rounds, sig_n = _unpack_ring_sig(sig_path)
        if sig_n != n:
            sys.exit(f"hpks-ring verify: signature n={sig_n} != ring n={n}")
        if k != len(ring_keys):
            sys.exit(f"hpks-ring verify: signature ring size {k} != "
                     f"{len(ring_keys)} provided members")
        msg = BitArray(n, int.from_bytes(in_bytes[:n // 8].ljust(n // 8, b'\x00'), 'big'))
        ok  = hpks_stern_ring_verify(msg, sig, ring_keys, n)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    if not pubkey_path:
        sys.exit("verify: --pubkey required for this algorithm")
    their_algo, their_ints = _decode_pubkey(pubkey_path)

    if algo in ('hpks', 'hpks-nl'):
        pub_int, nbits = their_ints
        poly = GF_POLY.get(nbits, GF_POLY[256])
        msg  = BitArray(nbits, int.from_bytes(in_bytes[:nbits // 8].ljust(nbits // 8, b'\x00'), 'big'))
        s_int, R_int, e_int, _nb = _decode_schnorr_sig(sig_path)
        R    = BitArray(nbits, R_int)
        e_v  = (fscx_revolve(R, msg, nbits // 4)
                if algo == 'hpks'
                else nl_fscx_revolve_v1(R, msg, nbits // 4))
        lhs  = gf_mul(gf_pow(GF_GEN, s_int, poly, nbits),
                      gf_pow(pub_int, e_v.uint, poly, nbits), poly, nbits)
        if lhs == R_int:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'hpks-stern':
        print(_STERN_DEMO_WARNING, file=sys.stderr)
        syn_int, seed_int, n = their_ints
        seed = BitArray(n, seed_int)
        msg  = BitArray(n, int.from_bytes(in_bytes[:n // 8].ljust(n // 8, b'\x00'), 'big'))
        commits, challenges, responses, _n = _unpack_stern_sig(sig_path)
        sig  = (commits, challenges, responses)
        ok   = hpks_stern_f_verify(msg, sig, seed, syn_int, n)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'rnl-sigma':
        # Verify using an HKEX-RNL public key
        if their_algo != 'hkex-rnl':
            sys.exit(f"rnl-sigma verify: expected hkex-rnl pubkey, got {their_algo!r}")
        C_poly, m_poly, n, _ = _decode_rnl_pubkey(their_ints)
        sig_pem = _read_file(sig_path).decode('ascii')
        w, c, z, _n = decode_zkp_rnl_proof(sig_pem)
        ok = rnl_sigma_verify(m_poly, C_poly, n, in_bytes, w, c, z)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'nl-zkboo':
        # Verify using a ZKP-NL public key
        if their_algo != 'hpks-zkp-nl':
            sys.exit(f"nl-zkboo verify: expected hpks-zkp-nl pubkey, got {their_algo!r}")
        B, y, n = their_ints
        sig_pem = _read_file(sig_path).decode('ascii')
        proof_rounds, _n = decode_zkp_nl_proof(sig_pem)
        rounds = len(proof_rounds)
        ok = zkp_nl_verify(B, y, n, rounds, in_bytes, proof_rounds)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'nl-zkbpp':
        # ZKB++ verify
        if their_algo != 'hpks-zkp-nl':
            sys.exit(f"nl-zkbpp verify: expected hpks-zkp-nl pubkey, got {their_algo!r}")
        B, y, n = their_ints
        sig_pem = _read_file(sig_path).decode('ascii')
        proof_rounds, _n = decode_zkp_nl_pp_proof(sig_pem)
        rounds = len(proof_rounds)
        # Pad/truncate to 32 bytes to match C/Go behavior
        msg = (in_bytes + b'\x00' * 32)[:32]
        ok = zkp_nl_verify_pp(B, y, n, rounds, msg, proof_rounds)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'hpks-xmss':
        root, h = _decode_xmss_pubkey(pubkey_path)
        sig = _unpack_xmss_sig(sig_path)
        ok  = hpks_xmss_verify(in_bytes, sig, root)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    elif algo == 'hpks-wots':
        pk  = _decode_wots_pubkey(pubkey_path)
        sig = _unpack_wots_sig(sig_path)
        ok  = hpks_wots_verify(in_bytes, sig, pk)
        if ok:
            print("Signature OK")
            sys.exit(0)
        else:
            print("Verification FAILED")
            sys.exit(1)

    else:
        sys.exit(f"verify: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: encfile   (HSKE-NL-A1 CTR-mode AEAD for arbitrary-size files)
# ---------------------------------------------------------------------------
#
# Binary output format (.hkx):
#   [0:4]        Magic b'HKX1'
#   [4]          Algo byte: 0x01 = hske-nla1
#   [5:13]       Plaintext length (big-endian uint64)
#   [13:45]      Nonce N_nonce (32 bytes)
#   [45:45+m*32] Ciphertext blocks (m = ceil(len/32); last block zero-padded)
#   [45+m*32:]   Auth tag — HFSCX-256-MAC(mac_key, nonce||len||ciphertext)
#
# Keystream:  ks_i = nl_fscx_revolve_v1(seed, base XOR i, n/4)
# MAC key:    nl_fscx_revolve_v1(ROL(seed, n/4), base, n/4)  [domain-separated]

def cmd_encfile(args):
    algo = args.algo
    if algo != 'hske-nla1':
        sys.exit(f"encfile: unsupported algorithm {algo!r}")

    key_int, nbits = _load_key(args.key)
    if nbits != 256:
        sys.exit(f"encfile: key must be 256-bit; got {nbits}-bit")

    plaintext     = _read_file(getattr(args, 'in'))
    plaintext_len = len(plaintext)

    n        = 256
    blen     = _HKX_BLOCK          # 32 bytes
    steps    = n // 4              # 64 NL-FSCX v1 steps per block
    iv_const = int.from_bytes(_HFSCX256_IV_BYTES, 'big')

    K       = BitArray(n, key_int)
    N_nonce = BitArray.random(n)
    base    = BitArray(n, K.uint ^ N_nonce.uint)
    seed    = BitArray(n, base.rotated(n // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - n)))

    # Encrypt: ks_i = nl_fscx_revolve_v1(seed, base XOR i, 64); C_i = P_i XOR ks_i
    n_blocks  = (plaintext_len + blen - 1) // blen   # 0 for empty plaintext
    ct_blocks = bytearray()
    for i in range(n_blocks):
        chunk = plaintext[i * blen:(i + 1) * blen]
        p_blk = chunk + b'\x00' * (blen - len(chunk))   # zero-pad final block
        ks    = nl_fscx_revolve_v1(seed, BitArray(n, base.uint ^ i), steps)
        ct_blocks += bytes(p ^ k for p, k in zip(p_blk, ks.uint.to_bytes(blen, 'big')))

    # MAC key: domain-separated from encryption (second ROL shift)
    mac_key = nl_fscx_revolve_v1(seed.rotated(n // 4), base, steps)
    mac_iv  = BitArray(n, mac_key.uint ^ iv_const)

    # Auth tag: HFSCX-256-MAC over nonce || plaintext_len || ciphertext
    mac_data = (N_nonce.uint.to_bytes(blen, 'big')
                + plaintext_len.to_bytes(8, 'big')
                + bytes(ct_blocks))
    tag = hfscx_256(mac_data, iv=mac_iv)

    header = (_HKX_MAGIC
              + bytes([_HKX_ALGO_NLA1])
              + plaintext_len.to_bytes(8, 'big')
              + N_nonce.uint.to_bytes(blen, 'big'))
    _write_file(args.out, header + bytes(ct_blocks) + tag)


# ---------------------------------------------------------------------------
# Sub-command: decfile
# ---------------------------------------------------------------------------

def cmd_decfile(args):
    algo = args.algo
    if algo != 'hske-nla1':
        sys.exit(f"decfile: unsupported algorithm {algo!r}")

    key_int, nbits = _load_key(args.key)
    if nbits != 256:
        sys.exit(f"decfile: key must be 256-bit; got {nbits}-bit")

    raw = _read_file(getattr(args, 'in'))

    # Parse and validate header
    if len(raw) < 77:   # 4+1+8+32+32 minimum (empty plaintext + tag)
        sys.exit("decfile: file too short to be a valid .hkx container")
    if raw[:4] != _HKX_MAGIC:
        sys.exit(f"decfile: invalid magic {raw[:4]!r} (expected {_HKX_MAGIC!r})")
    if raw[4] != _HKX_ALGO_NLA1:
        sys.exit(f"decfile: unsupported algo byte 0x{raw[4]:02x}")

    plaintext_len = int.from_bytes(raw[5:13], 'big')
    nonce_bytes   = raw[13:45]
    n_blocks      = (plaintext_len + _HKX_BLOCK - 1) // _HKX_BLOCK
    ct_end        = 45 + n_blocks * _HKX_BLOCK

    if len(raw) < ct_end + 32:
        sys.exit("decfile: file truncated (ciphertext blocks or auth tag missing)")

    ct_bytes   = raw[45:ct_end]
    tag_stored = bytes(raw[ct_end:ct_end + 32])

    n        = 256
    blen     = _HKX_BLOCK
    steps    = n // 4
    iv_const = int.from_bytes(_HFSCX256_IV_BYTES, 'big')

    K       = BitArray(n, key_int)
    N_nonce = BitArray(n, int.from_bytes(nonce_bytes, 'big'))
    base    = BitArray(n, K.uint ^ N_nonce.uint)
    seed    = BitArray(n, base.rotated(n // 8).uint ^ (_RNL_KDF_DC_256 >> (256 - n)))

    # Recompute auth tag and compare before decrypting (verify-then-decrypt)
    mac_key = nl_fscx_revolve_v1(seed.rotated(n // 4), base, steps)
    mac_iv  = BitArray(n, mac_key.uint ^ iv_const)
    mac_data = (nonce_bytes
                + plaintext_len.to_bytes(8, 'big')
                + bytes(ct_bytes))
    tag_computed = hfscx_256(mac_data, iv=mac_iv)

    if not _hmac.compare_digest(tag_stored, tag_computed):
        sys.exit("decfile: authentication tag mismatch — file corrupt or wrong key")

    # Decrypt and trim to exact plaintext length
    plaintext = bytearray()
    for i in range(n_blocks):
        c_blk = ct_bytes[i * blen:(i + 1) * blen]
        ks    = nl_fscx_revolve_v1(seed, BitArray(n, base.uint ^ i), steps)
        plaintext += bytes(c ^ k for c, k in zip(c_blk, ks.uint.to_bytes(blen, 'big')))

    _write_file(args.out, bytes(plaintext[:plaintext_len]))


# ---------------------------------------------------------------------------
# Sub-command: dgst
# ---------------------------------------------------------------------------

def cmd_dgst(args):
    algo     = args.algo
    in_bytes = _read_file(getattr(args, 'in'))
    out_path = args.out

    if algo == 'hfscx-256':
        digest = hfscx_256(in_bytes)
    elif algo == 'hfscx-256-ds':
        digest = hfscx_256_ds(0x01, in_bytes)
    else:
        sys.exit(f"dgst: unsupported algorithm {algo!r}")

    digest_int = int.from_bytes(digest, 'big')

    if out_path == '-':
        sys.stdout.write(digest.hex() + '\n')
    else:
        der = der_seq(der_int(digest_int, 32))
        _write_file(out_path, pem_wrap(_LABEL_DIGEST, der))


# ---------------------------------------------------------------------------
# Sub-command: rand — HDRBG deterministic byte generation (TODO #119)
#
# Deterministic DRBG (NOT an OS entropy source): identical seed +
# personalization + byte count yield byte-identical output across the
# Python, C, and Go CLIs.  A DRBG state can be checkpointed to a
# 'HERRADURA HDRBG STATE' PEM (state[32], blocks) and resumed later.
# ---------------------------------------------------------------------------

def _encode_hdrbg_state(drbg):
    der = der_seq(der_int(drbg.state.uint, KEYBITS // 8),
                  der_int(drbg.blocks))
    return pem_wrap(_LABEL_HDRBG_STATE, der)


def _decode_hdrbg_state(path):
    label, ints = _read_pem_ints(path)
    if label != _LABEL_HDRBG_STATE:
        raise ValueError(f"Expected HDRBG STATE PEM, got {label!r}")
    state_int, blocks = ints
    return HDrbg(BitArray(KEYBITS, state_int), blocks)


def cmd_rand(args):
    # Obtain the DRBG: fresh from --seed, or resumed from --state.
    if args.seed:
        pers = (args.personalization or '').encode()
        drbg = drbg_seed(_read_file(args.seed), pers)
    elif args.state:
        drbg = _decode_hdrbg_state(args.state)
    else:
        sys.exit("rand: one of --seed or --state is required")

    if getattr(args, 'reseed', None):
        drbg_reseed(drbg, _read_file(args.reseed))

    if args.bytes is not None:
        if args.bytes < 0:
            sys.exit("rand: --bytes must be non-negative")
        try:
            out = drbg_generate(drbg, args.bytes)
        except RuntimeError as e:
            sys.exit(f"rand: {e}")
        if args.hex:
            data = (out.hex() + '\n').encode()
        else:
            data = out
        if args.out == '-':
            sys.stdout.buffer.write(data)
        else:
            _write_file(args.out, data)
    elif not getattr(args, 'reseed', None):
        sys.exit("rand: nothing to do (specify --bytes and/or --reseed)")

    # Persist the (advanced/reseeded) state if a state file was given.
    if args.state:
        _write_file(args.state, _encode_hdrbg_state(drbg))


# ---------------------------------------------------------------------------
# Sub-command: fpe (78.A)
# ---------------------------------------------------------------------------

def cmd_fpe(args):
    key_int, nbits = _load_key(args.key)
    key_bytes = key_int.to_bytes(nbits // 8, 'big')
    ctx_bytes = args.context.encode() if args.context else b''
    in_bytes  = _read_file(getattr(args, 'in'))
    if len(in_bytes) < 32:
        in_bytes = in_bytes.ljust(32, b'\x00')
    P = BitArray(KEYBITS, int.from_bytes(in_bytes[:32], 'big'))
    if args.encrypt:
        R = fpe_encrypt(P, key_bytes, ctx_bytes)
    else:
        R = fpe_decrypt(P, key_bytes, ctx_bytes)
    out_bytes = R.uint.to_bytes(KEYBITS // 8, 'big')
    if args.out == '-':
        sys.stdout.buffer.write(out_bytes)
    else:
        with open(args.out, 'wb') as f:
            f.write(out_bytes)


# ---------------------------------------------------------------------------
# Sub-command: twk (78.B)
# ---------------------------------------------------------------------------

def cmd_twk(args):
    key_int, nbits = _load_key(args.key)
    key_bytes = key_int.to_bytes(nbits // 8, 'big')
    in_bytes  = _read_file(getattr(args, 'in'))
    if len(in_bytes) < 32:
        in_bytes = in_bytes.ljust(32, b'\x00')
    P = BitArray(KEYBITS, int.from_bytes(in_bytes[:32], 'big'))
    if args.encrypt:
        R = twk_encrypt(P, key_bytes, args.sector, args.bidx)
    else:
        R = twk_decrypt(P, key_bytes, args.sector, args.bidx)
    out_bytes = R.uint.to_bytes(KEYBITS // 8, 'big')
    if args.out == '-':
        sys.stdout.buffer.write(out_bytes)
    else:
        with open(args.out, 'wb') as f:
            f.write(out_bytes)


# ---------------------------------------------------------------------------
# Sub-commands: oprf-blind, oprf-eval, oprf-unblind  (TODO #80)
# ---------------------------------------------------------------------------

def _load_oprf_key(path):
    """Return (k_int, nbits) from an OPRF PRIVATE KEY PEM."""
    label, ints = _read_pem_ints(path)
    if label != _PRIV_ALGOS['oprf']:
        sys.exit(f"Expected OPRF PRIVATE KEY PEM, got {label!r}")
    k_int, nbits = ints
    return k_int, nbits


def cmd_oprf_blind(args):
    """Client step 1: hash input and blind with random scalar r.
    Writes OPRF CLIENT STATE PEM (r + alpha) to --out; alpha is sent to server."""
    in_bytes = _read_file(getattr(args, 'in'))
    r, alpha = oprf_blind(in_bytes)
    nbits    = KEYBITS
    der      = der_seq(der_int(r,     nbits // 8),
                       der_int(alpha, nbits // 8),
                       der_int(nbits))
    pem_out  = pem_wrap(_LABEL_OPRF_STATE, der)
    _write_file(args.out, pem_out)


def cmd_oprf_eval(args):
    """Server step: evaluate alpha^k and write OPRF EVALUATION PEM to --out."""
    k_int, nbits = _load_oprf_key(args.key)
    label, ints  = _read_pem_ints(getattr(args, 'in'))
    if label != _LABEL_OPRF_STATE:
        sys.exit(f"Expected OPRF CLIENT STATE PEM, got {label!r}")
    _r, alpha, _nb = ints
    beta  = oprf_eval(alpha, k_int)
    der   = der_seq(der_int(beta, nbits // 8), der_int(nbits))
    _write_file(args.out, pem_wrap(_LABEL_OPRF_EVAL, der))


def cmd_oprf_unblind(args):
    """Client step 2: recover F(k, x) = H(x)^k and print hex to stdout (or --out)."""
    label_s, ints_s = _read_pem_ints(args.state)
    if label_s != _LABEL_OPRF_STATE:
        sys.exit(f"Expected OPRF CLIENT STATE PEM, got {label_s!r}")
    r, alpha, nbits = ints_s

    label_e, ints_e = _read_pem_ints(getattr(args, 'eval'))
    if label_e != _LABEL_OPRF_EVAL:
        sys.exit(f"Expected OPRF EVALUATION PEM, got {label_e!r}")
    beta, _nb = ints_e

    F      = oprf_unblind(beta, r)
    F_hex  = F.to_bytes(nbits // 8, 'big').hex()
    _write_file(args.out, F_hex + '\n')


# ---------------------------------------------------------------------------
# Sub-commands: pake-register, pake-demo  (TODO #80 Batch 4)
# ---------------------------------------------------------------------------

def cmd_pake_register(args):
    """Register a new user for aPAKE.  Outputs HERRADURA PAKE RECORD PEM."""
    oprf_key, _nbits = _load_oprf_key(args.key)
    username = args.username or "user"
    if args.password:
        password = args.password.encode()
    else:
        import getpass
        password = getpass.getpass(f"Password for {username!r}: ").encode()
    record  = hpake_register(username, password, oprf_key)
    salt_b  = record['salt']
    B_int   = record['B']
    y_int   = record['y']
    # Encode: SEQUENCE(INTEGER(salt), INTEGER(B), INTEGER(y))
    # salt as 32-byte big-endian integer; B and y as 4-byte (32-bit demo params)
    der = der_seq(
        der_int(int.from_bytes(salt_b, 'big'), 32),
        der_int(B_int, 4),
        der_int(y_int, 4),
    )
    _write_file(args.out, pem_wrap(_LABEL_PAKE_RECORD, der))


def _load_pake_record(path):
    """Return a record dict {'username', 'salt', 'B', 'y'} from PAKE RECORD PEM."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_PAKE_RECORD:
        sys.exit(f"Expected PAKE RECORD PEM, got {label!r}")
    salt_int, B_int, y_int = ints
    return {
        'username': '',            # not stored in the PEM for simplicity
        'salt':     salt_int.to_bytes(32, 'big'),
        'B':        B_int,
        'y':        y_int,
    }


def cmd_pake_demo(args):
    """aPAKE demo: run full registration + login on both sides and show session key."""
    oprf_key, _nbits = _load_oprf_key(args.key)
    username  = args.username or "demo-user"
    password  = (args.password or "demo-password").encode()
    record    = hpake_register(username, password, oprf_key)
    sk        = hpake_login_demo(record, password, oprf_key)
    if sk is not None:
        print(f"- aPAKE login succeeded; session key: {sk.hex()}")
    else:
        print("+ aPAKE login failed!")
        sys.exit(1)
    # Also test wrong password
    wrong_sk  = hpake_login_demo(record, b"wrong-password", oprf_key)
    if wrong_sk is None:
        print("- aPAKE correctly rejects wrong password")
    else:
        print("+ aPAKE accepted wrong password! (security failure)")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Sub-commands: cred-issue, cred-prove, cred-verify (TODO #128 Batch 5)
# ---------------------------------------------------------------------------

_HCRED_SIGN_ROUNDS = 219   # Stern-F rounds for issuer credential (prod soundness)


def _load_hcred_pubkey(path):
    """Return (C_poly, m_poly, seed_H_BitArray, syndr_int, n) from HCRED PUBLIC KEY PEM."""
    raw = _read_file(path).decode('ascii')
    label, _ = pem_unwrap(raw)
    if label == _LABEL_HCRED_PRIV:
        s, C, m, seed_H_int, syndr, n = decode_hcred_privkey(raw)
        return C, m, BitArray(n, seed_H_int), syndr, n
    if label != _LABEL_HCRED_PUB:
        sys.exit(f"Expected HCRED PUBLIC KEY (or PRIVATE KEY), got {label!r}")
    C, m, seed_H_int, syndr, n = decode_hcred_pubkey(raw)
    return C, m, BitArray(n, seed_H_int), syndr, n


def cmd_cred_issue(args):
    """Issue an HCRED credential: Stern-F signature over (m, C, seed_H, y)."""
    # Load user's HCRED public key
    C, m, seed_H, syndr, n = _load_hcred_pubkey(getattr(args, 'in'))
    # Load issuer's hpks-stern private key
    our_algo, ints = _decode_privkey(args.our)
    if our_algo not in ('hpks-stern', 'hpke-stern'):
        sys.exit(f"cred-issue: --our must be an hpks-stern private key, got {our_algo!r}")
    e_int, seed_int, issuer_n = ints
    issuer_seed = BitArray(issuer_n, seed_int)
    issuer_syn  = _suite_mod._stern_syndrome(seed_int, e_int, issuer_n, issuer_n // 2)

    rounds = getattr(args, 'rounds', None) or _HCRED_SIGN_ROUNDS
    print(_STERN_DEMO_WARNING, file=sys.stderr)
    cred_sig = hcred_issue(m, C, seed_H, syndr, n,
                           e_int, issuer_seed, issuer_syn,
                           issuer_n=issuer_n, rounds=rounds)
    pem_out = encode_hcred_credential(cred_sig, issuer_n)
    _write_file(args.out or '-', pem_out)


def cmd_cred_prove(args):
    """Generate an HCRED presentation proof (ZKBoo MPCitH)."""
    raw = _read_file(getattr(args, 'in')).decode('ascii')
    label, _ = pem_unwrap(raw)
    if label != _LABEL_HCRED_PRIV:
        sys.exit(f"cred-prove: --in must be an HCRED PRIVATE KEY PEM, got {label!r}")
    s, C, m, seed_H_int, syndr, n = decode_hcred_privkey(raw)
    seed_H  = BitArray(n, seed_H_int)
    msg     = (args.msg or '').encode()
    rounds  = getattr(args, 'rounds', None) or _HCRED_CLI_ROUNDS
    try:
        proof = hcred_prove(s, m, C, seed_H, syndr, n=n, rounds=rounds,
                            msg_bytes=msg)
    except ValueError as exc:
        sys.exit(f"cred-prove: {exc}")
    pem_out = encode_hcred_proof(proof, n)
    _write_file(args.out or '-', pem_out)


def cmd_cred_verify(args):
    """Verify an HCRED presentation proof and optionally the issuer credential."""
    # Load proof
    raw_proof = _read_file(args.proof).decode('ascii')
    proof, proof_n = decode_hcred_proof(raw_proof)

    # Load user's public key
    C, m, seed_H, syndr, pub_n = _load_hcred_pubkey(args.pubkey)
    if proof_n != pub_n:
        sys.exit(f"cred-verify: proof n={proof_n} does not match public key n={pub_n}")

    msg    = (args.msg or '').encode()
    rounds = len(proof['rounds'])

    ok_proof = hcred_verify(m, C, seed_H, syndr, proof, n=pub_n,
                            rounds=rounds, msg_bytes=msg)
    if not ok_proof:
        print("Verification FAILED (proof)")
        sys.exit(1)

    # Optional issuer credential check
    if args.cred:
        raw_cred = _read_file(args.cred).decode('ascii')
        commits_raw, challenges, responses, issuer_n = decode_hcred_credential(raw_cred)
        # Wrap commit integers as BitArrays for hpks_stern_f_verify
        commits = [(BitArray(issuer_n, c0), BitArray(issuer_n, c1), BitArray(issuer_n, c2))
                   for c0, c1, c2 in commits_raw]
        responses2 = []
        for i, (v0, v1) in enumerate(responses):
            b = challenges[i]
            responses2.append((v0 if b == 0 else BitArray(issuer_n, v0), v1))
        cred_sig = (commits, challenges, responses2)

        # Load issuer's public key (hpks-stern pub)
        issuer_algo, issuer_ints = _decode_pubkey(args.issuer)
        if issuer_algo not in ('hpks-stern', 'hpke-stern'):
            sys.exit(f"cred-verify: --issuer must be an hpks-stern public key, got {issuer_algo!r}")
        issuer_syn_int, issuer_seed_int, _ = issuer_ints
        issuer_seed = BitArray(issuer_n, issuer_seed_int)

        ok_cred = hcred_cred_verify(m, C, seed_H, syndr, pub_n,
                                    cred_sig, issuer_seed, issuer_syn_int,
                                    issuer_n=issuer_n)
        if not ok_cred:
            print("Verification FAILED (credential)")
            sys.exit(1)
        print("Credential OK")

    print("Proof OK")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog='herradura',
        description='Herradura Cryptographic Suite CLI v1.9.79',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    # genpkey
    gp = sub.add_parser('genpkey', help='Generate a private key')
    gp.add_argument('--algo', required=True, choices=list(_PRIV_ALGOS) + ['hcred'])
    gp.add_argument('--bits', type=int, default=None,
                    help='Key size in bits (default 256; Stern: matrix dimension N)')
    gp.add_argument('--xmss-height', type=int, default=10, dest='xmss_height',
                    help='XMSS tree height (default 10 → 1024 leaves)')
    gp.add_argument('--out', default='-')
    gp.add_argument('--passphrase', default=None,
                    help='Encrypt the exported private key PEM under this passphrase '
                         '(TODO #166; PBKDF2-HFSCX256 + HSKE-NL-AEAD). Omit for the '
                         'existing cleartext behavior.')
    gp.add_argument('--kdf-iterations', type=int, default=_PBKDF2_HFSCX256_ITER_DEMO,
                    help=f'PBKDF2-HFSCX256 iteration count for --passphrase (default '
                         f'{_PBKDF2_HFSCX256_ITER_DEMO}, demo-speed; NIST SP 800-132 '
                         f'recommends >={_PBKDF2_HFSCX256_ITER_PROD}, which takes '
                         f'several minutes in this pure-Python CLI).')

    # pkey
    pk = sub.add_parser('pkey', help='Display or extract a key')
    pk.add_argument('--in', required=True, dest='in')
    pk.add_argument('--pubout', action='store_true')
    pk.add_argument('--text',   action='store_true')
    pk.add_argument('--decrypt', action='store_true',
                    help='Decrypt a --passphrase-protected private key PEM (TODO #166) '
                         'back to cleartext; requires --passphrase.')
    pk.add_argument('--passphrase', default=None,
                    help='Passphrase for --decrypt.')
    pk.add_argument('--out', default='-')

    # kex
    kx = sub.add_parser('kex', help='Key exchange')
    kx.add_argument('--algo', required=True,
                    choices=['hkex-gf', 'hkex-rnl', 'hybrid-rnl-stern'])
    kx.add_argument('--our',   required=True)
    kx.add_argument('--their', required=True)
    kx.add_argument('--out',   required=True)
    kx.add_argument('--kdf', default='none',
                    choices=['none', 'hfscx-256', 'sp800227'],
                    help='Post-hash raw shared secret (default: none). "hfscx-256" '
                         'plain-hashes the raw key; "sp800227" (hkex-rnl only) '
                         'additionally binds the full public transcript (both '
                         'parties\' public polynomials and reconciliation hint) per '
                         'SP 800-227 Sec 4.5-4.6 (TODO #165). Both sides must use '
                         'the same --kdf flag.')
    kx.add_argument('--their-kem', default=None,
                    help='hybrid-rnl-stern only: Bob step — Alice\'s HPKE-Stern-KEM '
                         'public key (--their remains her HKEX-RNL public key).')
    kx.add_argument('--our-kem', default=None,
                    help='hybrid-rnl-stern only: Alice step — her own HPKE-Stern-KEM '
                         'private key (--our remains her HKEX-RNL private key).')

    # enc
    en = sub.add_parser('enc', help='Encrypt')
    en.add_argument('--algo', required=True,
                    choices=['hske', 'hske-nla1', 'hske-nla2', 'hske-duplex',
                             'hpke', 'hpke-nl', 'hpke-stern', 'hpke-stern-kem'])
    en.add_argument('--key',    default=None)
    en.add_argument('--pubkey', default=None)
    en.add_argument('--in',  required=True, dest='in')
    en.add_argument('--out', required=True)
    en.add_argument('--aead', action='store_true',
                    help='HSKE-NL-AEAD authenticated encryption (hske-nla1 only)')
    en.add_argument('--ad', default=None,
                    help='associated data bound into the AEAD tag (requires --aead)')

    # dec
    de = sub.add_parser('dec', help='Decrypt')
    de.add_argument('--algo', required=True,
                    choices=['hske', 'hske-nla1', 'hske-nla2', 'hske-duplex',
                             'hpke', 'hpke-nl', 'hpke-stern', 'hpke-stern-kem'])
    de.add_argument('--key',    default=None)
    de.add_argument('--in',  required=True, dest='in')
    de.add_argument('--out', required=True)
    de.add_argument('--ad', default=None,
                    help='associated data for AEAD ciphertexts (must match enc --ad)')

    # sign
    sg = sub.add_parser('sign', help='Sign a message or generate a ZKP')
    sg.add_argument('--algo', required=True,
                    choices=['hpks', 'hpks-nl', 'hpks-stern', 'rnl-sigma', 'nl-zkboo',
                             'nl-zkbpp', 'hpks-xmss', 'hpks-wots', 'hpks-ring'])
    sg.add_argument('--key',  required=True)
    sg.add_argument('--ring', default=None,
                    help='hpks-ring: comma-separated member public-key PEM paths')
    sg.add_argument('--in',  required=True, dest='in')
    sg.add_argument('--out', required=True)
    sg.add_argument('--digest', default='none', choices=['none', 'hfscx-256'],
                    help='Pre-hash: none=truncate input to block size (default), '
                         'hfscx-256=hash full input then sign the 32-byte digest')
    sg.add_argument('--rounds', type=int, default=None,
                    help='ZKP/Stern-F rounds (nl-zkboo, hpks-stern, hpks-ring; '
                         'default: 32 demo for hpks-stern/hpks-ring, 219 for nl-zkboo; '
                         'production soundness needs >= 219 for all three)')

    # verify
    vf = sub.add_parser('verify', help='Verify a signature or ZKP proof')
    vf.add_argument('--algo', required=True,
                    choices=['hpks', 'hpks-nl', 'hpks-stern', 'rnl-sigma', 'nl-zkboo',
                             'nl-zkbpp', 'hpks-xmss', 'hpks-wots', 'hpks-ring', 'hpks-t'])
    vf.add_argument('--pubkey', default=None)
    vf.add_argument('--ring', default=None,
                    help='hpks-ring: comma-separated member public-key PEM paths')
    vf.add_argument('--in',  required=True, dest='in')
    vf.add_argument('--sig', required=True)
    vf.add_argument('--digest', default='none', choices=['none', 'hfscx-256'],
                    help='Pre-hash algorithm: must match the value used during signing')

    # threshold-commit
    tc = sub.add_parser('threshold-commit',
                        help='HPKS-T phase 1: generate nonce and commitment PEMs')
    tc.add_argument('--key',        required=True, help='hpks or hpks-nl private key PEM')
    tc.add_argument('--commit-out', required=True, dest='commit_out',
                    help='Output commitment PEM (share with coordinator)')
    tc.add_argument('--nonce-out',  required=True, dest='nonce_out',
                    help='Output nonce PEM (keep secret; delete after phase 3)')

    # threshold-aggregate
    ta = sub.add_parser('threshold-aggregate',
                        help='HPKS-T phase 2 (coordinator): build aggregate PEM from commitments')
    ta.add_argument('--commits', required=True, nargs='+',
                    help='One or more commitment PEM files (one per signer)')
    ta.add_argument('--in',  required=True, dest='in', help='Message file to sign')
    ta.add_argument('--out', required=True, help='Output aggregate PEM (broadcast to all signers)')
    ta.add_argument('--digest', default='none', choices=['none', 'hfscx-256'],
                    help='Pre-hash: must match the value used during combine/verify')

    # threshold-respond
    tr = sub.add_parser('threshold-respond',
                        help='HPKS-T phase 3: produce partial signature PEM')
    tr.add_argument('--key',       required=True, help='hpks or hpks-nl private key PEM')
    tr.add_argument('--commits',   required=True, nargs='+',
                    help='All commitment PEMs (same list used in threshold-aggregate)')
    tr.add_argument('--aggregate', required=True, help='Aggregate PEM from coordinator')
    tr.add_argument('--nonce',     required=True, help='Nonce PEM from threshold-commit')
    tr.add_argument('--out',       required=True, help='Output partial signature PEM')

    # threshold-combine
    tb = sub.add_parser('threshold-combine',
                        help='HPKS-T phase 4 (coordinator): combine partial sigs into final sig')
    tb.add_argument('--aggregate', required=True, help='Aggregate PEM from threshold-aggregate')
    tb.add_argument('--partials',  required=True, nargs='+',
                    help='One or more partial signature PEM files (one per signer)')
    tb.add_argument('--out', required=True, help='Output HPKST SIGNATURE PEM')

    # encfile
    ef = sub.add_parser('encfile',
                        help='Encrypt a file of any size (AEAD, binary .hkx output)')
    ef.add_argument('--algo', default='hske-nla1', choices=['hske-nla1'],
                    help='Encryption algorithm (default: hske-nla1 CTR-mode AEAD)')
    ef.add_argument('--key',  required=True,
                    help='Session key PEM (from kex) or hex key file')
    ef.add_argument('--in',  required=True, dest='in',
                    help='Plaintext file to encrypt')
    ef.add_argument('--out', required=True,
                    help='Output .hkx file')

    # decfile
    df = sub.add_parser('decfile',
                        help='Decrypt and authenticate a .hkx file')
    df.add_argument('--algo', default='hske-nla1', choices=['hske-nla1'],
                    help='Encryption algorithm (default: hske-nla1)')
    df.add_argument('--key',  required=True,
                    help='Session key PEM (from kex) or hex key file')
    df.add_argument('--in',  required=True, dest='in',
                    help='Encrypted .hkx file')
    df.add_argument('--out', required=True,
                    help='Output plaintext file')

    # dgst
    dg = sub.add_parser('dgst', help='Compute a digest (default: HFSCX-256, hex to stdout)')
    dg.add_argument('--algo', default='hfscx-256', choices=['hfscx-256', 'hfscx-256-ds'],
                    help='Hash algorithm (default: hfscx-256)')
    dg.add_argument('--in',  required=True, dest='in',
                    help='Input file (use - for stdin)')
    dg.add_argument('--out', default='-',
                    help='Output: - prints hex to stdout (default); file path writes PEM digest')

    # rand (HDRBG — deterministic byte generation, TODO #119)
    rd = sub.add_parser('rand',
                        help='Generate deterministic bytes from an HDRBG seed/state')
    rd.add_argument('--seed', default=None,
                    help='Seed/entropy file to instantiate the DRBG')
    rd.add_argument('--state', default=None,
                    help='HDRBG STATE PEM to resume from and/or update (checkpoint)')
    rd.add_argument('--personalization', default=None,
                    help='Personalization string (with --seed only)')
    rd.add_argument('--reseed', default=None,
                    help='Entropy file to fold into the state before generating')
    rd.add_argument('--bytes', type=int, default=None,
                    help='Number of output bytes to generate')
    rd.add_argument('--hex', action='store_true',
                    help='Hex-encode the output instead of raw bytes')
    rd.add_argument('--out', default='-',
                    help='Output file (default: - = stdout)')

    # fpe (78.A)
    fp = sub.add_parser('fpe',
                        help='Format-preserving encrypt/decrypt a 256-bit block (78.A)')
    fp.add_argument('--key',     required=True,
                    help='Session key PEM')
    fp.add_argument('--context', default='',
                    help='Context/tweak string (optional)')
    fp.add_argument('--in',     required=True, dest='in',
                    help='Input file (32 bytes)')
    fp.add_argument('--out',    default='-',
                    help='Output file (raw 32 bytes); - for stdout')
    fp_mode = fp.add_mutually_exclusive_group(required=True)
    fp_mode.add_argument('--encrypt', action='store_true')
    fp_mode.add_argument('--decrypt', action='store_true')

    # twk (78.B)
    tw = sub.add_parser('twk',
                        help='Tweakable wide-block encrypt/decrypt a 256-bit block (78.B)')
    tw.add_argument('--key',    required=True,
                    help='Session key PEM')
    tw.add_argument('--sector', type=int, default=0,
                    help='Sector number (default 0)')
    tw.add_argument('--bidx',   type=int, default=0,
                    help='Block index within sector (default 0)')
    tw.add_argument('--in',    required=True, dest='in',
                    help='Input file (32 bytes)')
    tw.add_argument('--out',   default='-',
                    help='Output file (raw 32 bytes); - for stdout')
    tw_mode = tw.add_mutually_exclusive_group(required=True)
    tw_mode.add_argument('--encrypt', action='store_true')
    tw_mode.add_argument('--decrypt', action='store_true')

    # oprf-blind (80)
    ob = sub.add_parser('oprf-blind',
                        help='OPRF client step 1: hash input and blind (TODO #80)')
    ob.add_argument('--in',  required=True, dest='in',
                    help='Input bytes to blind (file or - for stdin)')
    ob.add_argument('--out', default='-',
                    help='OPRF CLIENT STATE PEM output (keep secret; contains r + alpha)')

    # oprf-eval (80)
    oe = sub.add_parser('oprf-eval',
                        help='OPRF server step: evaluate blinded input with OPRF key (TODO #80)')
    oe.add_argument('--key', required=True,
                    help='OPRF PRIVATE KEY PEM (server key)')
    oe.add_argument('--in',  required=True, dest='in',
                    help='OPRF CLIENT STATE PEM (from oprf-blind)')
    oe.add_argument('--out', default='-',
                    help='OPRF EVALUATION PEM output')

    # oprf-unblind (80)
    ou = sub.add_parser('oprf-unblind',
                        help='OPRF client step 2: unblind server response to get PRF output (TODO #80)')
    ou.add_argument('--state', required=True,
                    help='OPRF CLIENT STATE PEM (from oprf-blind)')
    ou.add_argument('--eval',  required=True,
                    help='OPRF EVALUATION PEM (from oprf-eval)')
    ou.add_argument('--out', default='-',
                    help='PRF output as hex (default: stdout)')

    # pake-register (80)
    pr = sub.add_parser('pake-register',
                        help='aPAKE: register user and output server record PEM (TODO #80 Batch 4)')
    pr.add_argument('--key',      required=True,
                    help='OPRF PRIVATE KEY PEM (server OPRF key)')
    pr.add_argument('--username', default='user',
                    help='Username to register (default: "user")')
    pr.add_argument('--password', default=None,
                    help='Password (omit to prompt interactively)')
    pr.add_argument('--out', default='-',
                    help='PAKE RECORD PEM output')

    # pake-demo (80)
    pd = sub.add_parser('pake-demo',
                        help='aPAKE: run full register+login demo (both sides) (TODO #80 Batch 4)')
    pd.add_argument('--key',      required=True,
                    help='OPRF PRIVATE KEY PEM')
    pd.add_argument('--username', default='demo-user',
                    help='Demo username (default: "demo-user")')
    pd.add_argument('--password', default='demo-password',
                    help='Demo password (default: "demo-password")')

    # cred-issue (128)
    ci = sub.add_parser('cred-issue',
                        help='HCRED: issue a credential (Stern-F sig over user public key) (TODO #128 Batch 5)')
    ci.add_argument('--our',    required=True,
                    help='Issuer hpks-stern PRIVATE KEY PEM')
    ci.add_argument('--in',     required=True, dest='in',
                    help='User HCRED PUBLIC KEY (or PRIVATE KEY) PEM')
    ci.add_argument('--rounds', type=int, default=None,
                    help=f'Stern-F rounds (default: {_HCRED_SIGN_ROUNDS} for 128-bit soundness)')
    ci.add_argument('--out',    default='-',
                    help='HCRED CREDENTIAL PEM output')

    # cred-prove (128)
    cp = sub.add_parser('cred-prove',
                        help='HCRED: generate a presentation proof (ZKBoo MPCitH) (TODO #128 Batch 5)')
    cp.add_argument('--in',     required=True, dest='in',
                    help='User HCRED PRIVATE KEY PEM')
    cp.add_argument('--msg',    default='',
                    help='Presentation nonce / message (default: empty)')
    cp.add_argument('--rounds', type=int, default=None,
                    help=f'ZKBoo rounds (default: {_HCRED_CLI_ROUNDS} for 128-bit soundness)')
    cp.add_argument('--out',    default='-',
                    help='HCRED PROOF PEM output')

    # cred-verify (128)
    cv = sub.add_parser('cred-verify',
                        help='HCRED: verify a presentation proof (and optional credential) (TODO #128 Batch 5)')
    cv.add_argument('--proof',   required=True,
                    help='HCRED PROOF PEM')
    cv.add_argument('--pubkey',  required=True,
                    help='User HCRED PUBLIC KEY (or PRIVATE KEY) PEM')
    cv.add_argument('--cred',    default=None,
                    help='HCRED CREDENTIAL PEM (optional; verify issuer binding)')
    cv.add_argument('--issuer',  default=None,
                    help='Issuer hpks-stern PUBLIC KEY PEM (required with --cred)')
    cv.add_argument('--msg',     default='',
                    help='Presentation nonce / message (must match cred-prove --msg)')

    return p


_DISPATCH = {
    'genpkey': cmd_genpkey,
    'pkey':    cmd_pkey,
    'kex':     cmd_kex,
    'enc':     cmd_enc,
    'dec':     cmd_dec,
    'sign':    cmd_sign,
    'verify':  cmd_verify,
    'encfile': cmd_encfile,
    'decfile': cmd_decfile,
    'dgst':    cmd_dgst,
    'rand':         cmd_rand,
    'fpe':          cmd_fpe,
    'twk':          cmd_twk,
    'oprf-blind':     cmd_oprf_blind,
    'oprf-eval':      cmd_oprf_eval,
    'oprf-unblind':   cmd_oprf_unblind,
    'pake-register':  cmd_pake_register,
    'pake-demo':      cmd_pake_demo,
    'threshold-commit':    cmd_threshold_commit,
    'threshold-aggregate': cmd_threshold_aggregate,
    'threshold-respond':   cmd_threshold_respond,
    'threshold-combine':   cmd_threshold_combine,
    'cred-issue':  cmd_cred_issue,
    'cred-prove':  cmd_cred_prove,
    'cred-verify': cmd_cred_verify,
}


def main():
    parser = build_parser()
    args   = parser.parse_args()
    _DISPATCH[args.cmd](args)


if __name__ == '__main__':
    main()
