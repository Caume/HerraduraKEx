# HerraduraCli/codec.py — PEM and minimal DER codec (v1.5.23)
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
