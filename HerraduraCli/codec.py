# HerraduraCli/codec.py — PEM and minimal DER codec (v1.9.79)
# No external dependencies; uses only base64 from stdlib.
import base64


# ---------------------------------------------------------------------------
# DER helpers
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xff])
    else:
        raise ValueError(f"Length too large for DER: {n}")


def _read_length(data: bytes, offset: int):
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    n_bytes = b & 0x7f
    val = int.from_bytes(data[offset + 1:offset + 1 + n_bytes], 'big')
    return val, offset + 1 + n_bytes


def der_int(value: int, nbytes: int = None) -> bytes:
    """Encode a non-negative integer as DER INTEGER (tag 0x02).

    nbytes: byte width of the value before adding any sign byte.
    If None, the minimal non-zero byte count is used.
    """
    if value < 0:
        raise ValueError("Negative integers not supported")
    if nbytes is None:
        nbytes = max(1, (value.bit_length() + 7) // 8)
    data = value.to_bytes(nbytes, 'big')
    if data[0] & 0x80:          # high bit set → add leading zero (positive sign)
        data = b'\x00' + data
    return b'\x02' + _encode_length(len(data)) + data


def der_seq(*items: bytes) -> bytes:
    """Wrap DER-encoded items in a SEQUENCE (tag 0x30)."""
    body = b''.join(items)
    return b'\x30' + _encode_length(len(body)) + body


def der_parse_seq(data: bytes) -> list:
    """Decode a DER SEQUENCE of INTEGERs; return list of Python ints."""
    if data[0] != 0x30:
        raise ValueError(f"Expected SEQUENCE tag 0x30, got 0x{data[0]:02x}")
    offset = 1
    length, offset = _read_length(data, offset)
    end = offset + length
    results = []
    while offset < end:
        if data[offset] != 0x02:
            raise ValueError(f"Expected INTEGER tag 0x02, got 0x{data[offset]:02x}")
        offset += 1
        vlen, offset = _read_length(data, offset)
        val_bytes = data[offset:offset + vlen]
        offset += vlen
        # Strip optional leading zero byte used as positive sign indicator
        if val_bytes and val_bytes[0] == 0x00 and len(val_bytes) > 1:
            val_bytes = val_bytes[1:]
        results.append(int.from_bytes(val_bytes, 'big'))
    return results


# ---------------------------------------------------------------------------
# Polynomial packing helpers
# ---------------------------------------------------------------------------

def pack_poly(coeffs: list, bytes_per_coeff: int) -> tuple:
    """Pack a list of integer coefficients into a big integer and byte count.

    Returns (packed_int, total_bytes) so that der_int(packed_int, total_bytes)
    round-trips correctly even when leading coefficients are zero.
    """
    n = len(coeffs)
    total = n * bytes_per_coeff
    raw = bytearray(total)
    for i, c in enumerate(coeffs):
        raw[i * bytes_per_coeff:(i + 1) * bytes_per_coeff] = c.to_bytes(bytes_per_coeff, 'big')
    return int.from_bytes(raw, 'big'), total


def unpack_poly(packed_int: int, n: int, bytes_per_coeff: int) -> list:
    """Unpack a big integer back to a coefficient list (inverse of pack_poly)."""
    total = n * bytes_per_coeff
    raw = packed_int.to_bytes(total, 'big')
    return [int.from_bytes(raw[i * bytes_per_coeff:(i + 1) * bytes_per_coeff], 'big')
            for i in range(n)]


# ---------------------------------------------------------------------------
# PEM helpers
# ---------------------------------------------------------------------------

def pem_wrap(label: str, data: bytes) -> str:
    """Wrap binary data as a PEM block with the given label."""
    b64 = base64.encodebytes(data).decode('ascii').strip()
    return f"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n"


def pem_unwrap(pem_text: str) -> tuple:
    """Unwrap a PEM block; return (label, binary_data)."""
    lines = pem_text.strip().splitlines()
    if not (lines[0].startswith('-----BEGIN ') and lines[-1].startswith('-----END ')):
        raise ValueError("Not a valid PEM block")
    label = lines[0][11:-5]
    b64 = ''.join(lines[1:-1])
    return label, base64.b64decode(b64)


# ---------------------------------------------------------------------------
# ZKP-RNL proof encode/decode
#   Wire format (raw binary, PEM label "HERRADURA ZKP-RNL PROOF"):
#     4B n  |  n×4B w (signed s32-be)  |  n×4B c (unsigned u32-be)  |  n×4B z (signed s32-be)
# ---------------------------------------------------------------------------

def _s32be_pack(coeffs: list) -> bytes:
    """Serialize list of signed integers as n×4-byte big-endian two's complement."""
    return b''.join(c.to_bytes(4, 'big', signed=True) for c in coeffs)


def _u32be_pack(coeffs: list) -> bytes:
    """Serialize list of non-negative integers as n×4-byte big-endian unsigned."""
    return b''.join(c.to_bytes(4, 'big') for c in coeffs)


def _s32be_unpack(data: bytes, n: int, offset: int = 0) -> tuple:
    """Deserialize n signed s32-be values from data[offset:]; return (list, end_offset)."""
    out = []
    for i in range(n):
        val = int.from_bytes(data[offset:offset + 4], 'big', signed=True)
        out.append(val)
        offset += 4
    return out, offset


def _u32be_unpack(data: bytes, n: int, offset: int = 0) -> tuple:
    """Deserialize n unsigned u32-be values from data[offset:]; return (list, end_offset)."""
    out = []
    for i in range(n):
        val = int.from_bytes(data[offset:offset + 4], 'big')
        out.append(val)
        offset += 4
    return out, offset


def encode_zkp_rnl_proof(w_poly: list, c_poly: list, z_poly: list, n: int) -> str:
    """Encode a ZKP-RNL Σ-protocol proof as a PEM block.

    w_poly: centered Z_q coefficients; c_poly: sparse ternary Z_q; z_poly: signed ints.
    """
    body  = n.to_bytes(4, 'big')
    body += _s32be_pack(w_poly)
    body += _u32be_pack(c_poly)
    body += _s32be_pack(z_poly)
    return pem_wrap("HERRADURA ZKP-RNL PROOF", body)


def decode_zkp_rnl_proof(pem_text: str) -> tuple:
    """Decode a ZKP-RNL PEM proof block.

    Returns (w_poly, c_poly, z_poly, n).
    """
    label, body = pem_unwrap(pem_text)
    if label != "HERRADURA ZKP-RNL PROOF":
        raise ValueError(f"Unexpected PEM label: {label!r}")
    n = int.from_bytes(body[:4], 'big')
    off = 4
    w_poly, off = _s32be_unpack(body, n, off)
    c_poly, off = _u32be_unpack(body, n, off)
    z_poly, off = _s32be_unpack(body, n, off)
    return w_poly, c_poly, z_poly, n


# ---------------------------------------------------------------------------
# ZKP-NL keypair and proof encode/decode
#   Private key  (label "HERRADURA ZKP-NL PRIVATE KEY"):
#     4B n  |  nb bytes A  (nb = ceil(n/8))
#   Public key   (label "HERRADURA ZKP-NL PUBLIC KEY"):
#     4B n  |  nb bytes B  |  nb bytes y
#   Proof        (label "HERRADURA ZKP-NL PROOF"):
#     4B n  |  4B rounds  |  for each round:
#       32B com_0  |  32B com_1  |  32B com_2  |  1B e
#       |  2B len_p1  |  view_p1  |  2B len_p2  |  view_p2
# ---------------------------------------------------------------------------

def encode_zkp_nl_privkey(A: int, B: int, y: int, n: int) -> str:
    """Encode a ZKP-NL private key (A, B, y, n) as PEM.

    All three values are stored so that `pkey --pubout` can extract (B, y, n)
    without needing to re-run nl_fscx_v1.
    """
    nb   = (n + 7) // 8
    body = (n.to_bytes(4, 'big')
            + A.to_bytes(nb, 'big')
            + B.to_bytes(nb, 'big')
            + y.to_bytes(nb, 'big'))
    return pem_wrap("HERRADURA ZKP-NL PRIVATE KEY", body)


def decode_zkp_nl_privkey(pem_text: str) -> tuple:
    """Decode a ZKP-NL private key PEM block. Returns (A, B, y, n)."""
    label, body = pem_unwrap(pem_text)
    if label != "HERRADURA ZKP-NL PRIVATE KEY":
        raise ValueError(f"Unexpected PEM label: {label!r}")
    n  = int.from_bytes(body[:4], 'big')
    nb = (n + 7) // 8
    A  = int.from_bytes(body[4:4 + nb], 'big')
    B  = int.from_bytes(body[4 + nb:4 + 2 * nb], 'big')
    y  = int.from_bytes(body[4 + 2 * nb:4 + 3 * nb], 'big')
    return A, B, y, n


def encode_zkp_nl_pubkey(B: int, y: int, n: int) -> str:
    """Encode a ZKP-NL public key (B, y) as PEM."""
    nb   = (n + 7) // 8
    body = n.to_bytes(4, 'big') + B.to_bytes(nb, 'big') + y.to_bytes(nb, 'big')
    return pem_wrap("HERRADURA ZKP-NL PUBLIC KEY", body)


def decode_zkp_nl_pubkey(pem_text: str) -> tuple:
    """Decode a ZKP-NL public key PEM block. Returns (B, y, n)."""
    label, body = pem_unwrap(pem_text)
    if label != "HERRADURA ZKP-NL PUBLIC KEY":
        raise ValueError(f"Unexpected PEM label: {label!r}")
    n  = int.from_bytes(body[:4], 'big')
    nb = (n + 7) // 8
    B  = int.from_bytes(body[4:4 + nb], 'big')
    y  = int.from_bytes(body[4 + nb:4 + 2 * nb], 'big')
    return B, y, n


def encode_zkp_nl_proof(proof_rounds: list, n: int) -> str:
    """Encode a ZKP-NL ZKBoo proof list as PEM.

    proof_rounds: list of dicts with keys com_0, com_1, com_2, e, view_p1, view_p2.
    """
    R    = len(proof_rounds)
    body = n.to_bytes(4, 'big') + R.to_bytes(4, 'big')
    for rnd in proof_rounds:
        body += rnd['com_0'] + rnd['com_1'] + rnd['com_2']
        body += bytes([rnd['e']])
        for vk in ('view_p1', 'view_p2'):
            v = rnd[vk]
            body += len(v).to_bytes(2, 'big') + v
    return pem_wrap("HERRADURA ZKP-NL PROOF", body)


def decode_zkp_nl_proof(pem_text: str) -> tuple:
    """Decode a ZKP-NL PEM proof block. Returns (proof_rounds, n)."""
    label, body = pem_unwrap(pem_text)
    if label != "HERRADURA ZKP-NL PROOF":
        raise ValueError(f"Unexpected PEM label: {label!r}")
    off = 0
    n   = int.from_bytes(body[off:off + 4], 'big'); off += 4
    R   = int.from_bytes(body[off:off + 4], 'big'); off += 4
    rounds = []
    for _ in range(R):
        com_0 = body[off:off + 32]; off += 32
        com_1 = body[off:off + 32]; off += 32
        com_2 = body[off:off + 32]; off += 32
        e     = body[off];          off += 1
        l1    = int.from_bytes(body[off:off + 2], 'big'); off += 2
        vp1   = body[off:off + l1]; off += l1
        l2    = int.from_bytes(body[off:off + 2], 'big'); off += 2
        vp2   = body[off:off + l2]; off += l2
        rounds.append({'com_0': com_0, 'com_1': com_1, 'com_2': com_2,
                       'e': e, 'view_p1': vp1, 'view_p2': vp2})
    return rounds, n


# ---------------------------------------------------------------------------
# HCRED keypair, credential, and proof encode/decode — TODO #128 Batch 5
#
# Wire formats (raw binary, no DER):
#   HCRED PRIVATE KEY  (label "HERRADURA HCRED PRIVATE KEY"):
#     4B n | n×3B s_poly (Z_q) | n×2B C_poly (Z_p) | n×3B m_poly (Z_q)
#     | (n/8)B seed_H | (n/16)B syndr
#   HCRED PUBLIC KEY   (label "HERRADURA HCRED PUBLIC KEY"):
#     4B n | n×2B C_poly (Z_p) | n×3B m_poly (Z_q)
#     | (n/8)B seed_H | (n/16)B syndr
#   HCRED CREDENTIAL   (label "HERRADURA HCRED CREDENTIAL"):
#     Same binary layout as HERRADURA SIGNATURE (Stern-F signature):
#     DER SEQ(n_issuer, rounds, c_int, ch_int, r_int)
#   HCRED PROOF        (label "HERRADURA HCRED PROOF"):
#     4B n | 4B W | 4B rounds |
#     for each round:
#       96B coms (3 × 32B) | outs_bytes (variable, 9 × 3-B/coeff per party)
#       | 32B seed_c | 32B seed_c1
#       | n×3B a1 | n×3B b1 | nb×3B g1 | nd×3B h1
#       | 1B has_aux
#       | if has_aux: n×3B aux_s | nb×3B aux_B | nd×3B aux_D
#   where nb = (n/2) × ⌈log₂(n+1)⌉, nd = n × 5
# ---------------------------------------------------------------------------

_HCRED_PRIV_LBL  = "HERRADURA HCRED PRIVATE KEY"
_HCRED_PUB_LBL   = "HERRADURA HCRED PUBLIC KEY"
_HCRED_CRED_LBL  = "HERRADURA HCRED CREDENTIAL"
_HCRED_PROOF_LBL = "HERRADURA HCRED PROOF"


def _hcred_ser3(vec):
    """Serialize a Z_q vector at 3 bytes/coeff (big-endian)."""
    return b''.join((int(c) % 65537).to_bytes(3, 'big') for c in vec)


def _hcred_deser3(data, off, count):
    """Deserialize `count` Z_q values at 3 bytes/coeff from data[off:]."""
    result = []
    for _ in range(count):
        result.append(int.from_bytes(data[off:off + 3], 'big'))
        off += 3
    return result, off


def _hcred_ser2(vec):
    """Serialize a Z_p vector at 2 bytes/coeff (big-endian)."""
    return b''.join((int(c) % 4096).to_bytes(2, 'big') for c in vec)


def _hcred_deser2(data, off, count):
    """Deserialize `count` Z_p values at 2 bytes/coeff from data[off:]."""
    result = []
    for _ in range(count):
        result.append(int.from_bytes(data[off:off + 2], 'big'))
        off += 2
    return result, off


def _hcred_nb_nd(n):
    """Return (nb, nd, rows, row_bits) for HCRED at n bits."""
    import math
    rows     = n // 2
    row_bits = int(math.ceil(math.log2(n + 1))) if n > 0 else 1
    row_bits = n.bit_length()   # same as ceil(log2(n+1)) for power-of-2 n+1 edge
    nb = rows * row_bits
    nd = n * 5  # HCRED_EPS_BITS = 5
    return nb, nd, rows, row_bits


def _hcred_outs_to_bytes(outs, n):
    """Serialize HcredOuts dict to bytes (3 B/coeff per party per vector)."""
    nb, nd, rows, _ = _hcred_nb_nd(n)
    buf = b''
    for j in range(3):
        buf += _hcred_ser3(outs['ter'][j])
        buf += _hcred_ser3(outs['bit'][j])
        buf += _hcred_ser3(outs['del'][j])
        buf += _hcred_ser3([outs['W'][j]])
        buf += _hcred_ser3(outs['S'][j])
        buf += _hcred_ser3(outs['y'][j])
        buf += _hcred_ser3(outs['rnd'][j])
    return buf


def _hcred_outs_from_bytes(data, off, n):
    """Deserialize HcredOuts dict from data[off:].  Returns (outs, new_off)."""
    nb, nd, rows, _ = _hcred_nb_nd(n)
    outs = {'ter': [], 'bit': [], 'del': [], 'W': [], 'S': [], 'y': [], 'rnd': []}
    for j in range(3):
        ter, off = _hcred_deser3(data, off, n);    outs['ter'].append(ter)
        bit, off = _hcred_deser3(data, off, nb);   outs['bit'].append(bit)
        dl,  off = _hcred_deser3(data, off, nd);   outs['del'].append(dl)
        W,   off = _hcred_deser3(data, off, 1);    outs['W'].append(W[0])
        S,   off = _hcred_deser3(data, off, rows); outs['S'].append(S)
        y,   off = _hcred_deser3(data, off, rows); outs['y'].append(y)
        rnd, off = _hcred_deser3(data, off, n);    outs['rnd'].append(rnd)
    return outs, off


def encode_hcred_privkey(s_poly, C_poly, m_poly, seed_H_int, syndr_int, n):
    """Encode HCRED user private key as PEM."""
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    body = (n.to_bytes(4, 'big')
            + _hcred_ser3(s_poly)
            + _hcred_ser2(C_poly)
            + _hcred_ser3(m_poly)
            + seed_H_int.to_bytes(seed_nb, 'big')
            + syndr_int.to_bytes(syndr_nb, 'little'))
    return pem_wrap(_HCRED_PRIV_LBL, body)


def decode_hcred_privkey(pem_text):
    """Decode HCRED user private key PEM. Returns (s_poly, C_poly, m_poly, seed_H_int, syndr_int, n)."""
    label, body = pem_unwrap(pem_text)
    if label != _HCRED_PRIV_LBL:
        raise ValueError(f"Expected {_HCRED_PRIV_LBL!r}, got {label!r}")
    off  = 0
    n    = int.from_bytes(body[off:off + 4], 'big'); off += 4
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    s,   off = _hcred_deser3(body, off, n)
    C,   off = _hcred_deser2(body, off, n)
    m,   off = _hcred_deser3(body, off, n)
    seed_H   = int.from_bytes(body[off:off + seed_nb], 'big'); off += seed_nb
    # syndr stored little-endian (matches C's LSB-first syndrome byte layout)
    syndr    = int.from_bytes(body[off:off + syndr_nb], 'little')
    return s, C, m, seed_H, syndr, n


def encode_hcred_pubkey(C_poly, m_poly, seed_H_int, syndr_int, n):
    """Encode HCRED user public key as PEM."""
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    body = (n.to_bytes(4, 'big')
            + _hcred_ser2(C_poly)
            + _hcred_ser3(m_poly)
            + seed_H_int.to_bytes(seed_nb, 'big')
            + syndr_int.to_bytes(syndr_nb, 'little'))
    return pem_wrap(_HCRED_PUB_LBL, body)


def decode_hcred_pubkey(pem_text):
    """Decode HCRED user public key PEM. Returns (C_poly, m_poly, seed_H_int, syndr_int, n)."""
    label, body = pem_unwrap(pem_text)
    if label != _HCRED_PUB_LBL:
        raise ValueError(f"Expected {_HCRED_PUB_LBL!r}, got {label!r}")
    off  = 0
    n    = int.from_bytes(body[off:off + 4], 'big'); off += 4
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    C,   off = _hcred_deser2(body, off, n)
    m,   off = _hcred_deser3(body, off, n)
    seed_H   = int.from_bytes(body[off:off + seed_nb], 'big'); off += seed_nb
    # syndr stored little-endian (matches C's LSB-first syndrome byte layout)
    syndr    = int.from_bytes(body[off:off + syndr_nb], 'little')
    return C, m, seed_H, syndr, n


def encode_hcred_credential(sig, issuer_n):
    """Encode HCRED issuer credential (Stern-F sig) as PEM.

    sig = (commits, challenges, responses) as returned by hpks_stern_f_sign.
    Uses same binary layout as encode_stern_sig but with HCRED CREDENTIAL label."""
    commits, challenges, responses = sig
    rounds  = len(commits)
    nbytes  = issuer_n // 8

    def _ba_int(v):
        return v.uint if hasattr(v, 'uint') else int(v)

    commits_ba = bytearray()
    for c0, c1, c2 in commits:
        commits_ba += _ba_int(c0).to_bytes(nbytes, 'big')
        commits_ba += _ba_int(c1).to_bytes(nbytes, 'big')
        commits_ba += _ba_int(c2).to_bytes(nbytes, 'big')

    chal_bytes = bytearray((rounds + 3) // 4)
    for i, b in enumerate(challenges):
        chal_bytes[i // 4] |= (b & 3) << ((i % 4) * 2)

    resp_ba = bytearray()
    for resp in responses:
        v0 = _ba_int(resp[0])
        v1 = _ba_int(resp[1])
        resp_ba += v0.to_bytes(nbytes, 'big')
        resp_ba += v1.to_bytes(nbytes, 'big')

    c_int  = int.from_bytes(commits_ba, 'big')
    ch_int = int.from_bytes(chal_bytes,  'big')
    r_int  = int.from_bytes(resp_ba,    'big')
    der    = der_seq(der_int(issuer_n),
                     der_int(rounds),
                     der_int(c_int,  len(commits_ba)),
                     der_int(ch_int, len(chal_bytes)),
                     der_int(r_int,  len(resp_ba)))
    return pem_wrap(_HCRED_CRED_LBL, der)


def decode_hcred_credential(pem_text):
    """Decode HCRED issuer credential PEM.

    Returns (commits, challenges, responses, issuer_n) — same layout as
    _unpack_stern_sig, compatible with hpks_stern_f_verify."""
    label, data = pem_unwrap(pem_text)
    if label != _HCRED_CRED_LBL:
        raise ValueError(f"Expected {_HCRED_CRED_LBL!r}, got {label!r}")
    ints = der_parse_seq(data)
    issuer_n, rounds, c_int, ch_int, r_int = (int(ints[0]), int(ints[1]),
                                               ints[2], ints[3], ints[4])
    nbytes = issuer_n // 8

    commits_ba = c_int.to_bytes(3 * rounds * nbytes, 'big')
    commits = []
    for i in range(rounds):
        off = i * 3 * nbytes
        c0 = int.from_bytes(commits_ba[off:off + nbytes], 'big')
        c1 = int.from_bytes(commits_ba[off + nbytes:off + 2*nbytes], 'big')
        c2 = int.from_bytes(commits_ba[off + 2*nbytes:off + 3*nbytes], 'big')
        commits.append((c0, c1, c2))

    chal_nb    = (rounds + 3) // 4
    chal_bytes = ch_int.to_bytes(chal_nb, 'big')
    challenges = [(chal_bytes[i // 4] >> ((i % 4) * 2)) & 3 for i in range(rounds)]

    resp_ba   = r_int.to_bytes(2 * rounds * nbytes, 'big')
    responses = []
    for i in range(rounds):
        off = i * 2 * nbytes
        v0  = int.from_bytes(resp_ba[off:off + nbytes], 'big')
        v1  = int.from_bytes(resp_ba[off + nbytes:off + 2*nbytes], 'big')
        # b == 0: (sr:int, sy:int); b != 0: (pi_seed:int, sy:int) — caller wraps
        responses.append((v0, v1))

    # Return commits as plain ints; caller wraps in BitArray as needed.
    return commits, challenges, responses, issuer_n


def encode_hcred_proof(proof, n):
    """Encode an HCRED presentation proof dict as PEM.

    proof = {'W': int, 'rounds': [round_dict, ...]}  as returned by hcred_prove."""
    nb, nd, rows, _ = _hcred_nb_nd(n)
    W      = proof['W']
    rounds = proof['rounds']
    R      = len(rounds)
    body   = n.to_bytes(4, 'big') + W.to_bytes(4, 'big') + R.to_bytes(4, 'big')
    for rd in rounds:
        # commitments: 3 × 32 B
        for com in rd['coms']:
            body += bytes(com) if not isinstance(com, (bytes, bytearray)) else bytes(com)
        # output shares
        body += _hcred_outs_to_bytes(rd['outs'], n)
        # seeds
        body += bytes(rd['seed_c']) + bytes(rd['seed_c1'])
        # linear masks
        body += _hcred_ser3(rd['a1'])
        body += _hcred_ser3(rd['b1'])
        body += _hcred_ser3(rd['g1'])
        body += _hcred_ser3(rd['h1'])
        # optional aux shares
        has_aux = rd['aux_s'] is not None
        body += bytes([1 if has_aux else 0])
        if has_aux:
            body += _hcred_ser3(rd['aux_s'])
            body += _hcred_ser3(rd['aux_B'])
            body += _hcred_ser3(rd['aux_D'])
    return pem_wrap(_HCRED_PROOF_LBL, body)


def decode_hcred_proof(pem_text):
    """Decode an HCRED presentation proof PEM. Returns (proof, n)."""
    label, body = pem_unwrap(pem_text)
    if label != _HCRED_PROOF_LBL:
        raise ValueError(f"Expected {_HCRED_PROOF_LBL!r}, got {label!r}")
    off  = 0
    n    = int.from_bytes(body[off:off + 4], 'big'); off += 4
    W    = int.from_bytes(body[off:off + 4], 'big'); off += 4
    R    = int.from_bytes(body[off:off + 4], 'big'); off += 4
    nb, nd, rows, _ = _hcred_nb_nd(n)
    rounds = []
    for _ in range(R):
        coms = []
        for _ in range(3):
            coms.append(bytes(body[off:off + 32])); off += 32
        outs, off = _hcred_outs_from_bytes(body, off, n)
        seed_c  = bytes(body[off:off + 32]); off += 32
        seed_c1 = bytes(body[off:off + 32]); off += 32
        a1, off = _hcred_deser3(body, off, n)
        b1, off = _hcred_deser3(body, off, n)
        g1, off = _hcred_deser3(body, off, nb)
        h1, off = _hcred_deser3(body, off, nd)
        has_aux = body[off]; off += 1
        if has_aux:
            aux_s, off = _hcred_deser3(body, off, n)
            aux_B, off = _hcred_deser3(body, off, nb)
            aux_D, off = _hcred_deser3(body, off, nd)
        else:
            aux_s = aux_B = aux_D = None
        rounds.append({'coms': coms, 'outs': outs,
                       'seed_c': seed_c, 'seed_c1': seed_c1,
                       'a1': a1, 'b1': b1, 'g1': g1, 'h1': h1,
                       'aux_s': aux_s, 'aux_B': aux_B, 'aux_D': aux_D})
    return {'W': W, 'rounds': rounds}, n


# ---------------------------------------------------------------------------
# HPKS-T (threshold) PEM encode/decode — TODO #106
#
# Wire formats (all DER SEQUENCE of INTEGERs):
#   HPKST COMMITMENT  — [R_j, C_j, n]  (public nonce + signer pubkey)
#   HPKST NONCE       — [k_j, n]        (secret nonce; delete after use)
#   HPKST AGGREGATE   — [R, C_agg, e, n] (broadcast by coordinator)
#   HPKST PARTIAL     — [s_j, n]        (per-signer response)
#   HPKST SIGNATURE   — [C_agg, R, s, n] (final verifiable signature)
# ---------------------------------------------------------------------------

_HPKST_COMMIT_LBL    = "HERRADURA HPKST COMMITMENT"
_HPKST_NONCE_LBL     = "HERRADURA HPKST NONCE"
_HPKST_AGGREGATE_LBL = "HERRADURA HPKST AGGREGATE"
_HPKST_PARTIAL_LBL   = "HERRADURA HPKST PARTIAL"
_HPKST_SIG_LBL       = "HERRADURA HPKST SIGNATURE"


def encode_hpkst_commit(R_j: int, C_j: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(R_j, nb), der_int(C_j, nb), der_int(n, 4))
    return pem_wrap(_HPKST_COMMIT_LBL, der)


def decode_hpkst_commit(pem_text: str) -> tuple:
    """Returns (R_j, C_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_COMMIT_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    R_j, C_j, n = der_parse_seq(data)
    return R_j, C_j, n


def encode_hpkst_nonce(k_j: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(k_j, nb), der_int(n, 4))
    return pem_wrap(_HPKST_NONCE_LBL, der)


def decode_hpkst_nonce(pem_text: str) -> tuple:
    """Returns (k_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_NONCE_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    k_j, n = der_parse_seq(data)
    return k_j, n


def encode_hpkst_aggregate(R: int, C_agg: int, e: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(R, nb), der_int(C_agg, nb), der_int(e, nb), der_int(n, 4))
    return pem_wrap(_HPKST_AGGREGATE_LBL, der)


def decode_hpkst_aggregate(pem_text: str) -> tuple:
    """Returns (R, C_agg, e, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_AGGREGATE_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    R, C_agg, e, n = der_parse_seq(data)
    return R, C_agg, e, n


def encode_hpkst_partial(s_j: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(s_j, nb), der_int(n, 4))
    return pem_wrap(_HPKST_PARTIAL_LBL, der)


def decode_hpkst_partial(pem_text: str) -> tuple:
    """Returns (s_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_PARTIAL_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    s_j, n = der_parse_seq(data)
    return s_j, n


def encode_hpkst_sig(C_agg: int, R: int, s: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(C_agg, nb), der_int(R, nb), der_int(s, nb), der_int(n, 4))
    return pem_wrap(_HPKST_SIG_LBL, der)


def decode_hpkst_sig(pem_text: str) -> tuple:
    """Returns (C_agg, R, s, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_SIG_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    C_agg, R, s, n = der_parse_seq(data)
    return C_agg, R, s, n


# ---------------------------------------------------------------------------
# Self-test (runs when imported as __main__ only)
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    # Round-trip DER INTEGER
    for v in [0, 1, 127, 128, 255, 256, 0xdeadbeef, 2**256 - 1]:
        enc = der_int(v)
        dec = der_parse_seq(der_seq(enc))
        assert dec == [v], f"der_int round-trip failed for {v}: {dec}"
    # Round-trip DER SEQUENCE
    items = [0, 42, 2**64, 2**256 - 1]
    seq = der_seq(*[der_int(x) for x in items])
    assert der_parse_seq(seq) == items
    # Round-trip polynomial packing
    poly = [0, 65537 - 1, 1, 0, 42, 0]
    packed, nb = pack_poly(poly, 4)
    assert unpack_poly(packed, len(poly), 4) == poly
    # Round-trip PEM
    data = bytes(range(64))
    label = "HERRADURA TEST"
    pem = pem_wrap(label, der_seq(der_int(42)))
    lbl, raw = pem_unwrap(pem)
    assert lbl == label
    # Round-trip ZKP-RNL proof
    n_test = 8
    w_test = [100, -200, 300, -400, 500, -600, 700, -800]
    c_test = [0, 1, 65536, 0, 0, 1, 0, 0]
    z_test = [-1000, 2000, -3000, 4000, -5000, 6000, -7000, 8000]
    rnl_pem = encode_zkp_rnl_proof(w_test, c_test, z_test, n_test)
    w2, c2, z2, n2 = decode_zkp_rnl_proof(rnl_pem)
    assert w2 == w_test and c2 == c_test and z2 == z_test and n2 == n_test
    # Round-trip ZKP-NL keys and proof
    A_t, B_t, y_t, n_t = 0xAB, 0xCD, 0xEF, 8
    priv_pem = encode_zkp_nl_privkey(A_t, B_t, y_t, n_t)
    A2, B2, y2, n2 = decode_zkp_nl_privkey(priv_pem)
    assert (A2, B2, y2, n2) == (A_t, B_t, y_t, n_t)
    pub_pem = encode_zkp_nl_pubkey(B_t, y_t, n_t)
    B3, y3, n3 = decode_zkp_nl_pubkey(pub_pem)
    assert (B3, y3, n3) == (B_t, y_t, n_t)
    rnd_t = [{'com_0': b'\x01' * 32, 'com_1': b'\x02' * 32, 'com_2': b'\x03' * 32,
              'e': 1, 'view_p1': b'\xaa\xbb', 'view_p2': b'\xcc\xdd\xee'}]
    proof_pem = encode_zkp_nl_proof(rnd_t, 8)
    rounds2, n4 = decode_zkp_nl_proof(proof_pem)
    assert n4 == 8 and rounds2[0]['e'] == 1 and rounds2[0]['view_p1'] == b'\xaa\xbb'
    print("codec.py self-test OK")
