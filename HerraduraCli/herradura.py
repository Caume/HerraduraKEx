#!/usr/bin/env python3
# HerraduraCli/herradura.py — OpenSSL-style CLI for the Herradura Cryptographic Suite (v1.5.23)
#
# Usage examples:
#   python3 herradura.py genpkey --algo hkex-gf  --bits 256 --out alice.pem
#   python3 herradura.py pkey    --in alice.pem --pubout --out alice_pub.pem
#   python3 herradura.py kex     --algo hkex-gf  --our alice.pem --their bob_pub.pem --out sk.pem
#   python3 herradura.py enc     --algo hske      --key sk.pem --in msg.bin --out cipher.pem
#   python3 herradura.py dec     --algo hske      --key sk.pem --in cipher.pem --out plain.bin
#   python3 herradura.py sign    --algo hpks      --key sig.pem --in msg.bin --out s.pem
#   python3 herradura.py verify  --algo hpks      --pubkey sig.pem --in msg.bin --sig s.pem
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
import sys
import os

# Add parent directory to path so relative imports work when run directly
sys.path.insert(0, os.path.dirname(__file__))

from codec import (der_int, der_seq, der_parse_seq, pem_wrap, pem_unwrap,
                   pack_poly, unpack_poly)
from primitives import (
    BitArray, fscx_revolve, nl_fscx_revolve_v1, nl_fscx_revolve_v2,
    nl_fscx_revolve_v2_inv, gf_mul, gf_pow,
    _rnl_keygen, _rnl_agree, _rnl_m_poly, _rnl_rand_poly, _rnl_poly_add,
    _rnl_lift, _rnl_poly_mul,
    stern_f_keygen, hpks_stern_f_sign, hpks_stern_f_verify,
    hpke_stern_f_encap_with_e, hpke_stern_f_decap,
    KEYBITS, GF_POLY, GF_GEN, ORD,
    RNLQ, RNLP, RNLPP, RNLB,
    I_VALUE, R_VALUE, SDFT, SDFNR, SDFR,
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
    'hpke-stern':  'HERRADURA HPKE-STERN PRIVATE KEY',
}

_PUB_ALGOS = {k: v.replace('PRIVATE', 'PUBLIC') for k, v in _PRIV_ALGOS.items()}

_LABEL_TO_ALGO = {v: k for k, v in _PRIV_ALGOS.items()}
_LABEL_TO_ALGO.update({v: k for k, v in _PUB_ALGOS.items()})

_LABEL_SESSION     = 'HERRADURA SESSION KEY'
_LABEL_RNL_RESP    = 'HERRADURA HKEX-RNL RESPONSE'
_LABEL_SIG         = 'HERRADURA SIGNATURE'
_LABEL_CT          = 'HERRADURA CIPHERTEXT'

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
# Key serialization helpers
# ---------------------------------------------------------------------------

_CLASSICAL_GF_ALGOS = {'hkex-gf', 'hpks', 'hpks-nl', 'hpke', 'hpke-nl'}
_STERN_ALGOS        = {'hpks-stern', 'hpke-stern'}


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


def _encode_rnl_privkey(s_poly, m_poly, n):
    s_packed, s_nb, m_packed, m_nb = _rnl_privkey_fields(n, s_poly, m_poly)
    der = der_seq(der_int(s_packed, s_nb), der_int(m_packed, m_nb), der_int(n))
    return pem_wrap(_PRIV_ALGOS['hkex-rnl'], der)


def _encode_rnl_pubkey(C_poly, m_poly, n):
    C_packed, C_nb = pack_poly(C_poly, 2)   # Z_p coeff → 2 bytes (p = 4096)
    m_packed, m_nb = pack_poly(m_poly, 4)
    der = der_seq(der_int(C_packed, C_nb), der_int(m_packed, m_nb), der_int(n))
    return pem_wrap(_PUB_ALGOS['hkex-rnl'], der)


def _decode_rnl_privkey(ints):
    """Return (s_poly, m_poly, n) from parsed private key integers."""
    s_packed, m_packed, n = ints
    s_poly = unpack_poly(s_packed, n, 4)
    m_poly = unpack_poly(m_packed, n, 4)
    return s_poly, m_poly, n


def _decode_rnl_pubkey(ints):
    """Return (C_poly, m_poly, n) from parsed public key integers."""
    C_packed, m_packed, n = ints
    C_poly = unpack_poly(C_packed, n, 2)
    m_poly = unpack_poly(m_packed, n, 4)
    return C_poly, m_poly, n


def _rnl_derive_C(m_poly, s_poly, n):
    """Compute C = round_p(m_blind * s) given m_blind and s (both as Z_q polys)."""
    ms = _rnl_poly_mul(m_poly, s_poly, RNLQ, n)
    return _suite_mod._rnl_round(ms, RNLQ, RNLP)


def _encode_stern_privkey(e_int, seed, n, algo):
    nbytes = n // 8
    der = der_seq(der_int(e_int, nbytes), der_int(seed.uint, nbytes), der_int(n))
    return pem_wrap(_PRIV_ALGOS[algo], der)


def _encode_stern_pubkey(syn_int, seed, n, algo):
    nbytes = n // 8
    der = der_seq(der_int(syn_int, nbytes), der_int(seed.uint, nbytes), der_int(n))
    return pem_wrap(_PUB_ALGOS[algo], der)


def _decode_privkey(path):
    """Load a private key PEM; return (algo, fields_list)."""
    label, ints = _read_pem_ints(path)
    algo = _LABEL_TO_ALGO.get(label)
    if algo is None:
        raise ValueError(f"Unrecognised PEM label: {label!r}")
    return algo, ints


def _decode_pubkey(path):
    """Load a public key PEM; return (algo, fields_list)."""
    label, ints = _read_pem_ints(path)
    algo = _LABEL_TO_ALGO.get(label)
    if algo is None:
        raise ValueError(f"Unrecognised PEM label: {label!r}")
    return algo, ints


# ---------------------------------------------------------------------------
# Session key serialization
# ---------------------------------------------------------------------------

def _encode_session_key(key_int, nbits):
    """Encode a plain session key (HKEX-GF or completed HKEX-RNL)."""
    nbytes = max(1, (key_int.bit_length() + 7) // 8)
    der = der_seq(der_int(key_int, nbytes), der_int(nbits))
    return pem_wrap(_LABEL_SESSION, der)


def _encode_rnl_response(K_int, C_B_poly, hint, n):
    """Encode Bob's HKEX-RNL response: (K_B, C_B, hint, n, hint_len).

    K_B is Bob's session key (stored so enc/dec can use this file directly).
    C_B and hint are the public parts Alice uses to complete the handshake.
    """
    K_nb    = max(1, (K_int.bit_length() + 7) // 8)
    C_packed, C_nb = pack_poly(C_B_poly, 2)
    hint_int = 0
    for i, b in enumerate(hint):
        hint_int |= b << i
    hint_nb = max(1, (len(hint) + 7) // 8)
    der = der_seq(der_int(K_int,    K_nb),
                  der_int(C_packed, C_nb),
                  der_int(hint_int, hint_nb),
                  der_int(n),
                  der_int(len(hint)))
    return pem_wrap(_LABEL_RNL_RESP, der)


def _decode_session_key(path):
    """Return (key_int, nbits) from either SESSION KEY or RNL RESPONSE PEM."""
    label, ints = _read_pem_ints(path)
    if label == _LABEL_SESSION:
        key_int, nbits = ints
        return key_int, nbits
    elif label == _LABEL_RNL_RESP:
        # K_B is the first field — usable directly for enc/dec
        K_int, _, _, n, _ = ints
        return K_int, n
    else:
        raise ValueError(f"Expected SESSION KEY or RNL RESPONSE PEM, got {label!r}")


def _decode_rnl_response(path):
    """Return (K_int, C_B_poly, hint, n) from a HKEX-RNL RESPONSE PEM."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_RNL_RESP:
        raise ValueError(f"Expected HKEX-RNL RESPONSE PEM, got {label!r}")
    K_int, C_packed, hint_int, n, hint_len = ints
    C_B_poly = unpack_poly(C_packed, n, 2)
    hint = [(hint_int >> i) & 1 for i in range(hint_len)]
    return K_int, C_B_poly, hint, n


# ---------------------------------------------------------------------------
# Ciphertext serialization (symmetric)
# ---------------------------------------------------------------------------

def _encode_sym_ct(algo, E_int, nbits, nonce_int=None):
    nbytes = nbits // 8
    if algo == 'hske-nla1' and nonce_int is not None:
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
    """Return (E_int, nbits, nonce_int_or_None)."""
    label, ints = _read_pem_ints(path)
    if label != _LABEL_CT:
        raise ValueError(f"Expected CIPHERTEXT PEM, got {label!r}")
    fmt = ints[0]
    if fmt == 1:
        _, nonce_int, E_int, nbits = ints
        return E_int, nbits, nonce_int
    else:
        _, E_int, nbits = ints
        return E_int, nbits, None


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
        n       = bits
        m_base  = _rnl_m_poly(n)
        a_rand  = _rnl_rand_poly(n, RNLQ)
        m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)   # randomised m_blind
        s, C    = _rnl_keygen(m_blind, n, RNLQ, RNLP, RNLB)
        pem_out = _encode_rnl_privkey(s, m_blind, n)

    elif algo in _STERN_ALGOS:
        seed, e_int, syn = stern_f_keygen(bits)
        pem_out = _encode_stern_privkey(e_int, seed, bits, algo)

    else:
        sys.exit(f"Unknown algorithm: {algo!r}")

    _write_file(args.out or '-', pem_out)


# ---------------------------------------------------------------------------
# Sub-command: pkey
# ---------------------------------------------------------------------------

def cmd_pkey(args):
    in_path = getattr(args, 'in')
    algo, ints = _decode_privkey(in_path)

    if args.pubout:
        if algo in _CLASSICAL_GF_ALGOS:
            priv_int, pub_int, nbits = ints
            pem_out = _encode_classical_pubkey(pub_int, nbits, algo)
        elif algo == 'hkex-rnl':
            s_poly, m_poly, n = _decode_rnl_privkey(ints)
            C_poly  = _rnl_derive_C(m_poly, s_poly, n)
            pem_out = _encode_rnl_pubkey(C_poly, m_poly, n)
        elif algo in _STERN_ALGOS:
            e_int, seed_int, n = ints
            syn   = _suite_mod._stern_syndrome(seed_int, e_int, n, n // 2)
            seed  = BitArray(n, seed_int)
            pem_out = _encode_stern_pubkey(syn, seed, n, algo)
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
            s_poly, m_poly, n = _decode_rnl_privkey(ints)
            C_poly = _rnl_derive_C(m_poly, s_poly, n)
            C_packed, _ = pack_poly(C_poly, 2)
            s_packed, _ = pack_poly(s_poly, 4)
            print(f"algorithm : {algo}")
            print(f"n         : {n}")
            print(f"s_packed  : {s_packed:0{n}x}")
            print(f"C_packed  : {C_packed:0{n//2}x}")
        elif algo in _STERN_ALGOS:
            e_int, seed_int, n = ints
            print(f"algorithm : {algo}")
            print(f"n         : {n}")
            print(f"e_int     : {e_int:0{n//4}x}")
            print(f"seed      : {seed_int:0{n//4}x}")
    else:
        sys.exit("Specify --pubout or --text")


# ---------------------------------------------------------------------------
# Sub-command: kex
# ---------------------------------------------------------------------------

def cmd_kex(args):
    algo      = args.algo
    our_path  = args.our
    their_path = args.their

    if algo == 'hkex-gf':
        our_algo,   our_ints   = _decode_privkey(our_path)
        their_algo, their_ints = _decode_pubkey(their_path)
        priv_int, _, nbits = our_ints
        pub_int = their_ints[0]
        poly    = GF_POLY.get(nbits, GF_POLY[256])
        sk_int  = gf_pow(pub_int, priv_int, poly, nbits)
        _write_file(args.out, _encode_session_key(sk_int, nbits))

    elif algo == 'hkex-rnl':
        # Detect protocol step from the type of --their file
        their_label, their_ints = _read_pem_ints(their_path)

        if their_label == _PUB_ALGOS['hkex-rnl']:
            # ── STEP 1: Bob responds to Alice's public key ──────────────────
            # Bob has: s_B (private), reads C_A and m_A from Alice's pubkey.
            # Re-derives C_B = round_p(m_A * s_B) using Alice's m_blind.
            # Generates (K_B, hint) and writes RESPONSE PEM.
            our_algo, our_ints = _decode_privkey(our_path)
            s_B, _, n = _decode_rnl_privkey(our_ints)
            C_A, m_A, n_their = _decode_rnl_pubkey(their_ints)
            if n != n_their:
                sys.exit(f"Ring size mismatch: ours n={n}, theirs n={n_their}")
            C_B    = _rnl_derive_C(m_A, s_B, n)
            K_B, hint = _rnl_agree(s_B, C_A, RNLQ, RNLP, RNLPP, n, n)
            _write_file(args.out, _encode_rnl_response(K_B.uint, C_B, hint, n))

        elif their_label == _LABEL_RNL_RESP:
            # ── STEP 2: Alice completes the handshake ───────────────────────
            # Alice has: s_A (private), reads K_B, C_B, hint from Bob's response.
            # Computes K_A = _rnl_agree(s_A, C_B, ..., hint).
            our_algo, our_ints = _decode_privkey(our_path)
            s_A, m_A, n = _decode_rnl_privkey(our_ints)
            _, C_B, hint, n_resp = _decode_rnl_response(their_path)
            if n != n_resp:
                sys.exit(f"Ring size mismatch: ours n={n}, response n={n_resp}")
            K_A = _rnl_agree(s_A, C_B, RNLQ, RNLP, RNLPP, n, n, hint)
            _write_file(args.out, _encode_session_key(K_A.uint, n))

        else:
            sys.exit(
                f"kex hkex-rnl: --their must be an HKEX-RNL PUBLIC KEY or RESPONSE PEM "
                f"(got label {their_label!r})"
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
            base    = BitArray(nbits, K.uint ^ N_nonce.uint)
            seed    = base.rotated(nbits // 8)
            ks      = nl_fscx_revolve_v1(seed, BitArray(nbits, base.uint ^ 0), nbits // 4)
            E       = BitArray(nbits, P.uint ^ ks.uint)
            _write_file(out_path, _encode_sym_ct('hske-nla1', E.uint, nbits, nonce_int=N_nonce.uint))

        else:  # hske-nla2
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
        r       = BitArray.random(nbits)
        R       = BitArray(nbits, gf_pow(GF_GEN, r.uint, poly, nbits))
        enc_key = BitArray(nbits, gf_pow(pub_int, r.uint, poly, nbits))
        E       = nl_fscx_revolve_v2(P, enc_key, nbits // 4)
        _write_file(out_path, _encode_asym_ct(R.uint, E.uint, nbits))

    elif algo == 'hpke-stern':
        syn_int, seed_int, n = their_ints
        seed    = BitArray(n, seed_int)
        nbytes  = n // 8
        P       = BitArray(n, int.from_bytes(in_bytes[:nbytes].ljust(nbytes, b'\x00'), 'big'))
        K, ct_syn, e_p = hpke_stern_f_encap_with_e(seed, n)
        E       = fscx_revolve(P, K, n // 4)
        _write_file(out_path, _encode_stern_ct(ct_syn, e_p, K.uint, E.uint, n))

    else:
        sys.exit(f"enc: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: dec
# ---------------------------------------------------------------------------

def cmd_dec(args):
    algo     = args.algo
    out_path = args.out

    # ── Symmetric algos ─────────────────────────────────────────────────────
    if algo in ('hske', 'hske-nla1', 'hske-nla2'):
        key_path = args.key
        if not key_path:
            sys.exit(f"--key required for {algo}")
        key_int, nbits = _load_key(key_path)
        K = BitArray(nbits, key_int)

        E_int, _nbits, nonce_int = _decode_sym_ct(getattr(args, 'in'))
        E = BitArray(nbits, E_int)

        if algo == 'hske':
            D = fscx_revolve(E, K, 3 * nbits // 4)
        elif algo == 'hske-nla1':
            if nonce_int is None:
                sys.exit("hske-nla1 ciphertext missing nonce")
            N_nonce = BitArray(nbits, nonce_int)
            base    = BitArray(nbits, K.uint ^ N_nonce.uint)
            seed    = base.rotated(nbits // 8)
            ks      = nl_fscx_revolve_v1(seed, BitArray(nbits, base.uint ^ 0), nbits // 4)
            D       = BitArray(nbits, E.uint ^ ks.uint)
        else:  # hske-nla2
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
        D       = nl_fscx_revolve_v2_inv(E, dec_key, nbits // 4)
        _write_file(out_path, D.uint.to_bytes(nbits // 8, 'big'))

    elif algo == 'hpke-stern':
        e_int, seed_int, n = our_ints
        ct_syn, e_p, K_int, E_int, _n = _decode_stern_ct(getattr(args, 'in'))
        seed    = BitArray(n, seed_int)
        K_dec   = hpke_stern_f_decap(ct_syn, e_p, seed, n)
        if K_dec is None:
            sys.exit("HPKE-Stern-F decap failed (brute-force exhausted)")
        E       = BitArray(n, E_int)
        D       = fscx_revolve(E, K_dec, 3 * n // 4)
        _write_file(out_path, D.uint.to_bytes(n // 8, 'big'))

    else:
        sys.exit(f"dec: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: sign
# ---------------------------------------------------------------------------

def cmd_sign(args):
    algo     = args.algo
    key_path = args.key
    in_bytes = _read_file(getattr(args, 'in'))

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
        e_int, seed_int, n = our_ints
        seed = BitArray(n, seed_int)
        syn  = _suite_mod._stern_syndrome(seed_int, e_int, n, n // 2)
        msg  = BitArray(n, int.from_bytes(in_bytes[:n // 8].ljust(n // 8, b'\x00'), 'big'))
        sig  = hpks_stern_f_sign(msg, e_int, seed, syn, n)
        _write_file(args.out, _pack_stern_sig(sig, n))

    else:
        sys.exit(f"sign: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Sub-command: verify
# ---------------------------------------------------------------------------

def cmd_verify(args):
    algo        = args.algo
    pubkey_path = args.pubkey
    in_bytes    = _read_file(getattr(args, 'in'))
    sig_path    = args.sig

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

    else:
        sys.exit(f"verify: unsupported algorithm {algo!r}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog='herradura',
        description='Herradura Cryptographic Suite CLI v1.5.23',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    # genpkey
    gp = sub.add_parser('genpkey', help='Generate a private key')
    gp.add_argument('--algo', required=True, choices=list(_PRIV_ALGOS))
    gp.add_argument('--bits', type=int, default=None,
                    help='Key size in bits (default 256; Stern: matrix dimension N)')
    gp.add_argument('--out', default='-')

    # pkey
    pk = sub.add_parser('pkey', help='Display or extract a key')
    pk.add_argument('--in', required=True, dest='in')
    pk.add_argument('--pubout', action='store_true')
    pk.add_argument('--text',   action='store_true')
    pk.add_argument('--out', default='-')

    # kex
    kx = sub.add_parser('kex', help='Key exchange')
    kx.add_argument('--algo', required=True, choices=['hkex-gf', 'hkex-rnl'])
    kx.add_argument('--our',   required=True)
    kx.add_argument('--their', required=True)
    kx.add_argument('--out',   required=True)

    # enc
    en = sub.add_parser('enc', help='Encrypt')
    en.add_argument('--algo', required=True,
                    choices=['hske', 'hske-nla1', 'hske-nla2', 'hpke', 'hpke-nl', 'hpke-stern'])
    en.add_argument('--key',    default=None)
    en.add_argument('--pubkey', default=None)
    en.add_argument('--in',  required=True, dest='in')
    en.add_argument('--out', required=True)

    # dec
    de = sub.add_parser('dec', help='Decrypt')
    de.add_argument('--algo', required=True,
                    choices=['hske', 'hske-nla1', 'hske-nla2', 'hpke', 'hpke-nl', 'hpke-stern'])
    de.add_argument('--key',    default=None)
    de.add_argument('--in',  required=True, dest='in')
    de.add_argument('--out', required=True)

    # sign
    sg = sub.add_parser('sign', help='Sign a message')
    sg.add_argument('--algo', required=True, choices=['hpks', 'hpks-nl', 'hpks-stern'])
    sg.add_argument('--key',  required=True)
    sg.add_argument('--in',  required=True, dest='in')
    sg.add_argument('--out', required=True)

    # verify
    vf = sub.add_parser('verify', help='Verify a signature')
    vf.add_argument('--algo', required=True, choices=['hpks', 'hpks-nl', 'hpks-stern'])
    vf.add_argument('--pubkey', required=True)
    vf.add_argument('--in',  required=True, dest='in')
    vf.add_argument('--sig', required=True)

    return p


_DISPATCH = {
    'genpkey': cmd_genpkey,
    'pkey':    cmd_pkey,
    'kex':     cmd_kex,
    'enc':     cmd_enc,
    'dec':     cmd_dec,
    'sign':    cmd_sign,
    'verify':  cmd_verify,
}


def main():
    parser = build_parser()
    args   = parser.parse_args()
    _DISPATCH[args.cmd](args)


if __name__ == '__main__':
    main()
