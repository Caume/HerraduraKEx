# HerraduraCli/codec.py — PEM and minimal DER codec
# No external dependencies; uses only base64 from stdlib.
import base64

# ---------------------------------------------------------------------------
# Bounds for the packed (non-DER) wire formats — TODO #275.
#
# Eight PEM labels frame their fields at fixed offsets sized from a 4-byte `n`
# header instead of carrying DER lengths, so nothing in der_parse_seq guards
# them.  Every field below sizes an allocation or a loop; an unchecked one is
# either an unbounded allocation or, when it reaches zero, a verification loop
# that runs no iterations and reports success.
#
# _ZKP_NL_MAX_N matches C's ZKP_NL_MAX_N, Go's ZkpNlMaxN and Java's ZkpNl.MAX_N.
# Go's was 32 until TODO #279 — a representation limit, not policy: its shares
# were uint32 where C's are uint64, so widths 33..64 were read by C, Python and
# Java alone.  Go's shares are uint64 now and all four agree at 64.
# ---------------------------------------------------------------------------
_ZKP_NL_MAX_N      = 64
_ZKP_NL_MAX_ROUNDS = 4096
_ZKP_RNL_MAX_N     = 1024
_HCRED_MAX_N       = 256


def _packed_n(body: bytes, offset: int, limit: int, what: str) -> int:
    """Read a 4-byte big-endian sizing field and bound it, or raise."""
    if len(body) < offset + 4:
        raise ValueError(f"{what}: truncated header")
    v = int.from_bytes(body[offset:offset + 4], 'big')
    if v <= 0 or v > limit:
        raise ValueError(f"{what} out of range ({v})")
    return v


def _packed_take(body: bytes, off: int, size: int, what: str) -> tuple:
    """Slice `size` bytes at `off`, raising rather than returning a short read."""
    if size < 0 or off + size > len(body):
        raise ValueError(f"{what} truncated")
    return body[off:off + size], off + size


def _packed_end(body: bytes, off: int, label: str) -> None:
    """A raw-body PEM must end at its last field (TODO #372): bytes after it
    would give one artifact many encodings.  Same text in all four CLIs."""
    if off < len(body):
        raise ValueError(f"malformed PEM '{label}': {len(body) - off} bytes after its last field")


def _packed_short(label: str, round_: int, field: str, got: int, n: int, need: int) -> None:
    """TODO #407: a per-round length byte shorter than the field n fixes.  The
    verifiers read the full size for n, so a shorter field was read past;
    refuse it at the length byte, before the truncation checks.  Same text in
    all four CLIs."""
    if got < need:
        raise ValueError(f"malformed PEM '{label}': round {round_} {field} is {got} bytes, "
                         f"n={n} needs {need}")


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
    elif n < 0x1000000:
        return bytes([0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    elif n < 0x100000000:
        return bytes([0x84, (n >> 24) & 0xff, (n >> 16) & 0xff,
                      (n >> 8) & 0xff, n & 0xff])
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


# Set by HerraduraCli/herradura.py to its generated field check (TODO #372
# widths, #373 encodings and value rules), so the decoders here hold each
# field to the same rules as the CLI's own loader.  Called as
# FIELD_CAPS_CHECK(label, ints, enc), enc from der_scan.  None when codec is
# used on its own.
FIELD_CAPS_CHECK = None


def _der_len_minimal(data: bytes, offset: int) -> bool:
    b = data[offset]
    if b < 0x80:
        return True
    nb = b & 0x7f
    if nb == 0 or offset + nb >= len(data) or data[offset + 1] == 0:
        return False
    return nb > 1 or data[offset + 1] >= 0x80


def der_scan(data: bytes, label: str) -> list:
    """TODO #373: how each INTEGER of a DER SEQUENCE that der_parse_seq has
    accepted is ENCODED, which its sign-byte strip forgets: one (encoded width,
    lead) pair per item -- the content length less a 0x00 the set top bit
    needs, and lead 1 when it starts with a 0x00 the sign does not need, 2
    when with a sign byte.
    Raises ValueError, in the text every CLI prints, on a length not in its
    shortest form or a negative or empty INTEGER: a SEQUENCE has one encoding
    of its lengths and signs."""
    where = f"malformed PEM '{label}'"
    if not _der_len_minimal(data, 1):
        raise ValueError(f"{where}: DER length not in its shortest form")
    length, offset = _read_length(data, 1)
    end, enc = offset + length, []
    while offset < end:
        offset += 1
        if not _der_len_minimal(data, offset):
            raise ValueError(f"{where}: DER length not in its shortest form")
        vlen, offset = _read_length(data, offset)
        c = data[offset:offset + vlen]
        if not c:
            raise ValueError(f"{where}: field {len(enc)} is an empty INTEGER")
        if c[0] & 0x80:
            raise ValueError(f"{where}: field {len(enc)} is a negative INTEGER")
        sign = len(c) > 1 and c[0] == 0 and c[1] & 0x80
        enc.append((len(c) - (1 if sign else 0), 2 if sign else 1 if len(c) > 1 and c[0] == 0 else 0))
        offset += vlen
    return enc


def _der_count(label: str, data: bytes, want: int, gf_idx: int = None) -> list:
    """der_parse_seq plus the item count TODO #367 checks in every CLI loader;
    the message is the one HerraduraCli's _DER_ITEMS check prints.  gf_idx
    names a GF(2^n) width field, which must be one of the widths with a
    primitive polynomial (BITARRAY.md 4.6), and every other field must then
    fit n bits."""
    ints = der_parse_seq(data, label)
    enc = der_scan(data, label)            # TODO #373
    if len(ints) != want:
        raise ValueError(f"malformed PEM '{label}': {len(ints)} DER items, expected {want}")
    if FIELD_CAPS_CHECK is not None:       # TODO #372, #373: the CLI's generated check
        FIELD_CAPS_CHECK(label, ints, enc)
    if gf_idx is not None:
        n = ints[gf_idx]
        if n not in (32, 64, 128, 256):
            raise ValueError(f"{label}: n is {n} (expected 32, 64, 128 or 256)")
        for i, v in enumerate(ints):
            if i != gf_idx and v.bit_length() > n:
                raise ValueError(f"{label}: field {i} is wider than n = {n} bits")
    return ints


def _der_read_len(d: bytes, p: int, lim: int):
    """TODO #405: the DER length field at d[p], read no further than lim.
    (fault, length, bytes taken): fault 0 well formed and minimal, 1 truncated,
    2 longer than 4 bytes, 3 not in its shortest form."""
    if p >= lim:
        return 1, 0, 0
    b = d[p]
    if b < 0x80:
        return 0, b, 1
    nb = b & 0x7f
    if nb > 4:
        return 2, 0, 0
    if nb > lim - p - 1:
        return 1, 0, 0
    x = int.from_bytes(d[p + 1:p + 1 + nb], 'big')
    if nb == 0 or d[p + 1] == 0 or (nb == 1 and x < 0x80):
        return 3, x, 1 + nb
    return 0, x, 1 + nb


_DER_LEN_TEXT = ('', 'DER length field truncated', 'DER length field longer than 4 bytes',
                 'DER length not in its shortest form')


def der_seq_check(data: bytes, label: str):
    """TODO #405: the DER reader's refusal, specified (SPEC.md section 10.2).
    One left-to-right walk of a SEQUENCE of INTEGERs; the first fault met is
    the refusal, in the text all four CLIs print.  Returns None for a
    well-formed SEQUENCE, else that text; der_parse_seq and der_scan cannot
    fail after it."""
    where = f"malformed PEM '{label}': "
    if not data or data[0] != 0x30:
        return where + 'not a DER SEQUENCE'
    f, v, c = _der_read_len(data, 1, len(data))
    if f:
        return where + _DER_LEN_TEXT[f]
    off = 1 + c
    if v > len(data) - off:
        return where + 'DER SEQUENCE body truncated'
    if v < len(data) - off:
        return where + f'{len(data) - off - v} bytes after the DER SEQUENCE'
    n = 0
    while off < len(data):
        if data[off] != 0x02:
            return where + f'field {n} is not an INTEGER (tag 0x{data[off]:02x})'
        f, v, c = _der_read_len(data, off + 1, len(data))
        if f:
            return where + _DER_LEN_TEXT[f]
        off += 1 + c
        if v > len(data) - off:
            return where + f'field {n} runs past the DER SEQUENCE'
        if v == 0:
            return where + f'field {n} is an empty INTEGER'
        if data[off] & 0x80:
            return where + f'field {n} is a negative INTEGER'
        off += v
        n += 1
    return None


def der_parse_seq(data: bytes, label: str = None) -> list:
    """Decode a DER SEQUENCE of INTEGERs; return list of Python ints.

    Raises ValueError on any malformed input (never lets an IndexError
    escape from an attacker-controlled length field), including bytes after
    the SEQUENCE (TODO #372): every artifact has exactly one encoding.  label,
    when given, runs der_seq_check first (TODO #405), so a malformed SEQUENCE
    is refused in the text every CLI's loader prints."""
    if label is not None:
        msg = der_seq_check(data, label)
        if msg:
            raise ValueError(msg)
    if not data:
        raise ValueError("Empty DER input")
    if data[0] != 0x30:
        raise ValueError(f"Expected SEQUENCE tag 0x30, got 0x{data[0]:02x}")
    offset = 1
    try:
        length, offset = _read_length(data, offset)
    except IndexError:
        raise ValueError("DER: truncated SEQUENCE length field")
    end = offset + length
    if end > len(data):
        raise ValueError("DER: SEQUENCE body truncated")
    if end < len(data):
        where = f"malformed PEM '{label}'" if label else "DER"
        raise ValueError(f"{where}: {len(data) - end} bytes after the DER SEQUENCE")
    results = []
    while offset < end:
        if data[offset] != 0x02:
            raise ValueError(f"Expected INTEGER tag 0x02, got 0x{data[offset]:02x}")
        offset += 1
        try:
            vlen, offset = _read_length(data, offset)
        except IndexError:
            raise ValueError("DER: truncated INTEGER length field")
        if vlen > end - offset:
            raise ValueError("DER: INTEGER length exceeds SEQUENCE body")
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
    # TODO #367: a polynomial longer than its declared n (a key whose n field
    # was edited) raised OverflowError here, i.e. a traceback.
    if packed_int.bit_length() > 8 * total:
        raise ValueError(f"packed polynomial is wider than n = {n} coefficients "
                         f"of {bytes_per_coeff} bytes")
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


PEM_LABEL_MAX = 79
_PEM_WS = ' \t\r\n'


def pem_unwrap(pem_text: str) -> tuple:
    """Unwrap the one PEM block that is the whole of *pem_text*; return
    (label, binary_data).  Raises ValueError on any malformed input.

    One framing for every reader (TODO #400), the same scan in C, Go and Java:
    only whitespace (space, tab, CR, LF) before the BEGIN line and after the
    END line, so a file holds exactly one block; the BEGIN line is
    `-----BEGIN <label>-----`, then only spaces or tabs, the label 1 to 79
    printable ASCII characters;
    the END line starts a line and repeats the label; the body decodes under
    b64_decode_strict's grammar (TODO #398) to at least one byte."""
    t, end = pem_text, len(pem_text)
    p = 0
    while p < end and t[p] in _PEM_WS:
        p += 1
    if not t.startswith('-----BEGIN ', p):
        if t.find('-----BEGIN ', p) >= 0:
            raise ValueError("PEM: text before the BEGIN line")
        raise ValueError("PEM: missing BEGIN marker")
    p += 11
    ls = p
    while p < end and t[p] not in '\r\n' and not t.startswith('-----', p):
        if not ' ' <= t[p] <= '~':
            raise ValueError("PEM: malformed BEGIN line")
        p += 1
    label = t[ls:p]
    if not t.startswith('-----', p) or not 1 <= len(label) <= PEM_LABEL_MAX:
        raise ValueError("PEM: malformed BEGIN line")
    p += 5
    while p < end and t[p] in ' \t':
        p += 1
    if p >= end or t[p] not in '\r\n':
        raise ValueError("PEM: malformed BEGIN line")
    body = p
    foot = t.find('-----END ', body)
    if foot < 0:
        raise ValueError("PEM: missing END marker")
    if t[foot - 1] not in '\r\n':
        raise ValueError("PEM: malformed END line")
    p = es = foot + 9
    while p < end and t[p] not in '\r\n' and not t.startswith('-----', p):
        p += 1
    if not t.startswith('-----', p):
        raise ValueError("PEM: malformed END line")
    if t[es:p] != label:
        # The END label is echoed with every character outside 0x20-0x7E as '?':
        # unlike the BEGIN label it was never screened, and echoed raw it reached
        # stderr differently in each CLI (and could carry control bytes; #403).
        shown = ''.join(c if ' ' <= c <= '~' else '?' for c in t[es:p][:PEM_LABEL_MAX])
        raise ValueError(f"PEM: END label '{shown}' does not match "
                         f"BEGIN label '{label}'")
    p += 5
    while p < end and t[p] in _PEM_WS:
        p += 1
    if p != end:
        raise ValueError("PEM: text after the END line")
    data = b64_decode_strict(t[body:foot])
    if not data:
        raise ValueError("PEM: empty body")
    return label, data


_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_B64_VAL = {c: i for i, c in enumerate(_B64_ALPHABET)}


def b64_decode_strict(text: str) -> bytes:
    """Decode a PEM body under the one base64 grammar every CLI reads (TODO #398).

    The alphabet A-Z a-z 0-9 + /, with space, tab, CR and LF allowed anywhere
    between characters (RFC 7468's lax form).  Padding is REQUIRED: the
    characters number a multiple of 4 and '=' is only the last one or two of
    them.  The bits the padding leaves over must be zero, so one DER has one
    body.  Hand-written rather than base64.b64decode, which skips characters
    outside the alphabet and accepts '=' mid-body; the same loop runs in C, Go
    and Java, so the four refuse the same files with the same words."""
    out = bytearray()
    acc = bits = pad = chars = 0
    for c in text:
        if c in ' \t\r\n':
            continue
        if c == '=':
            pad += 1
            if pad > 2 or chars % 4 < 2:
                raise ValueError("PEM body is not valid base64: misplaced padding")
            chars += 1
            continue
        v = _B64_VAL.get(c)
        if v is None:
            raise ValueError("PEM body is not valid base64: invalid character")
        if pad:
            raise ValueError("PEM body is not valid base64: misplaced padding")
        chars += 1
        acc = ((acc << 6) | v) & 0xFFFF
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if chars % 4:
        raise ValueError("PEM body is not valid base64: length is not a multiple of 4")
    if pad and acc & ((1 << bits) - 1):
        raise ValueError("PEM body is not valid base64: non-zero bits after the last byte")
    return bytes(out)


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
    n = _packed_n(body, 0, _ZKP_RNL_MAX_N, "ZKP-RNL proof: n")
    if len(body) < 4 + n * 12:
        raise ValueError(f"ZKP-RNL proof: truncated (n={n})")
    off = 4
    w_poly, off = _s32be_unpack(body, n, off)
    c_poly, off = _u32be_unpack(body, n, off)
    z_poly, off = _s32be_unpack(body, n, off)
    _packed_end(body, off, label)
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
    n  = _packed_n(body, 0, _ZKP_NL_MAX_N, "ZKP-NL private key: n")
    nb = (n + 7) // 8
    if len(body) < 4 + 3 * nb:
        raise ValueError("ZKP-NL private key: truncated")
    A  = int.from_bytes(body[4:4 + nb], 'big')
    B  = int.from_bytes(body[4 + nb:4 + 2 * nb], 'big')
    y  = int.from_bytes(body[4 + 2 * nb:4 + 3 * nb], 'big')
    _packed_end(body, 4 + 3 * nb, label)
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
    n  = _packed_n(body, 0, _ZKP_NL_MAX_N, "ZKP-NL public key: n")
    nb = (n + 7) // 8
    if len(body) < 4 + 2 * nb:
        raise ValueError("ZKP-NL public key: truncated")
    B  = int.from_bytes(body[4:4 + nb], 'big')
    y  = int.from_bytes(body[4 + nb:4 + 2 * nb], 'big')
    _packed_end(body, 4 + 2 * nb, label)
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
    n   = _packed_n(body, 0, _ZKP_NL_MAX_N, "ZKP-NL proof: n")
    R   = _packed_n(body, 4, _ZKP_NL_MAX_ROUNDS, "ZKP-NL proof: rounds")
    off = 8
    view_need = 2 * ((n + 7) // 8) + 32 + n - 1    # the view the verifier reads
    rounds = []
    for j in range(R):
        w = f"ZKP-NL proof round {j}:"
        com_0, off = _packed_take(body, off, 32, w)
        com_1, off = _packed_take(body, off, 32, w)
        com_2, off = _packed_take(body, off, 32, w)
        eb, off    = _packed_take(body, off, 1, w)
        e     = eb[0]
        lb, off = _packed_take(body, off, 2, w)
        l1    = int.from_bytes(lb, 'big')
        _packed_short(label, j, "view_p1", l1, n, view_need)
        vp1, off = _packed_take(body, off, l1, w + " view1")
        lb, off = _packed_take(body, off, 2, w)
        l2    = int.from_bytes(lb, 'big')
        _packed_short(label, j, "view_p2", l2, n, view_need)
        vp2, off = _packed_take(body, off, l2, w + " view2")
        rounds.append({'com_0': com_0, 'com_1': com_1, 'com_2': com_2,
                       'e': e, 'view_p1': vp1, 'view_p2': vp2})
    _packed_end(body, off, label)
    return rounds, n


# ---------------------------------------------------------------------------
# ZKP-NL-PP (ZKB++) proof encode/decode — TODO #122 Batch 2
#
# Wire format (binary, no DER):
#   4B n | 4B rounds | per-round:
#     32B com_e | 1B e | nb B out_e | 16B seed_p1 | 16B seed_p2
#     | 1B gates_len | gates_p2 | 1B has_share2 | [nb B share2 if has_share2]
# ---------------------------------------------------------------------------

_ZKPP_SEED_BYTES = 16
_ZKPP_LABEL      = "HERRADURA ZKP-NL-PP SIGNATURE"


def encode_zkp_nl_pp_proof(proof_rounds: list, n: int) -> str:
    """Encode a ZKB++ proof list as PEM (label HERRADURA ZKP-NL-PP SIGNATURE).

    proof_rounds: list of dicts with keys:
      com_e, e, out_e, seed_p1, seed_p2, gates_p2, share2 (b'' when e==2).
    """
    nb   = (n + 7) // 8
    R    = len(proof_rounds)
    body = n.to_bytes(4, 'big') + R.to_bytes(4, 'big')
    for rnd in proof_rounds:
        body += rnd['com_e']
        body += bytes([rnd['e']])
        body += rnd['out_e']
        body += rnd['seed_p1']
        body += rnd['seed_p2']
        gl    = len(rnd['gates_p2'])
        body += bytes([gl])
        body += rnd['gates_p2']
        s2    = rnd['share2']
        has   = 1 if s2 else 0
        body += bytes([has])
        if has:
            body += s2
    return pem_wrap(_ZKPP_LABEL, body)


def decode_zkp_nl_pp_proof(pem_text: str) -> tuple:
    """Decode a ZKB++ PEM proof block. Returns (proof_rounds, n)."""
    label, body = pem_unwrap(pem_text)
    if label != _ZKPP_LABEL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    n   = _packed_n(body, 0, _ZKP_NL_MAX_N, "ZKB++ proof: n")
    R   = _packed_n(body, 4, _ZKP_NL_MAX_ROUNDS, "ZKB++ proof: rounds")
    off = 8
    nb  = (n + 7) // 8
    gates_need = (max(n - 1, 1) + 7) // 8     # the gate bytes the verifier reads
    rounds = []
    for j in range(R):
        w = f"ZKB++ proof round {j}:"
        com_e, off   = _packed_take(body, off, 32, w)
        eb, off      = _packed_take(body, off, 1, w)
        e            = eb[0]
        out_e, off   = _packed_take(body, off, nb, w)
        seed_p1, off = _packed_take(body, off, _ZKPP_SEED_BYTES, w)
        seed_p2, off = _packed_take(body, off, _ZKPP_SEED_BYTES, w)
        gb, off      = _packed_take(body, off, 1, w)
        gl           = gb[0]
        _packed_short(label, j, "gates_p2", gl, n, gates_need)
        gates_p2, off = _packed_take(body, off, gl, w + " gates")
        hb, off      = _packed_take(body, off, 1, w)
        has_s2       = hb[0]
        if has_s2:
            share2, off = _packed_take(body, off, nb, w + " share2")
        else:
            share2 = b''
        rounds.append({'com_e': com_e, 'e': e, 'out_e': out_e,
                       'seed_p1': seed_p1, 'seed_p2': seed_p2,
                       'gates_p2': gates_p2, 'share2': share2})
    _packed_end(body, off, label)
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
    # A short slice would otherwise yield silent zeros or an IndexError on the
    # caller's first use; refuse it here instead (TODO #275).
    if count < 0 or off + 3 * count > len(data):
        raise ValueError("HCRED: truncated coefficient vector")
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
    # A short slice would otherwise yield silent zeros or an IndexError on the
    # caller's first use; refuse it here instead (TODO #275).
    if count < 0 or off + 2 * count > len(data):
        raise ValueError("HCRED: truncated coefficient vector")
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
    n    = _packed_n(body, 0, _HCRED_MAX_N, "HCRED private key: n")
    off  = 4
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    # Exact, not ">=": the layout is fixed, so an n SMALLER than the body holds
    # would otherwise parse a prefix and succeed (TODO #275).
    _packed_end(body, 4 + 8 * n + seed_nb + syndr_nb, label)
    if len(body) != 4 + 8 * n + seed_nb + syndr_nb:
        raise ValueError(f"HCRED private key: body length does not match n={n}")
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
    n    = _packed_n(body, 0, _HCRED_MAX_N, "HCRED public key: n")
    off  = 4
    seed_nb  = n // 8
    syndr_nb = (n // 2 + 7) // 8
    # Exact, not ">=": the layout is fixed, so an n SMALLER than the body holds
    # would otherwise parse a prefix and succeed (TODO #275).
    _packed_end(body, 4 + 5 * n + seed_nb + syndr_nb, label)
    if len(body) != 4 + 5 * n + seed_nb + syndr_nb:
        raise ValueError(f"HCRED public key: body length does not match n={n}")
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
    cbytes  = min(issuer_n, 256) // 8   # commitments: 256 bits above N = 256 (TODO #382)

    def _ba_int(v):
        return v.uint if hasattr(v, 'uint') else int(v)

    commits_ba = bytearray()
    for c0, c1, c2 in commits:
        commits_ba += _ba_int(c0).to_bytes(cbytes, 'big')
        commits_ba += _ba_int(c1).to_bytes(cbytes, 'big')
        commits_ba += _ba_int(c2).to_bytes(cbytes, 'big')

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
    ints = _der_count(label, data, 5)
    issuer_n, rounds, c_int, ch_int, r_int = (int(ints[0]), int(ints[1]),
                                               ints[2], ints[3], ints[4])
    # TODO #367: n and rounds size every to_bytes below; an out-of-range one
    # (or a blob wider than they describe) was an OverflowError traceback.
    # 2304: the long-form issuer key (TODO #382)
    if issuer_n != 2304 and (issuer_n % 8 or not 8 <= issuer_n <= 256):
        raise ValueError(f"{label}: n is {issuer_n} (expected a multiple of 8, 8..256)")
    if not 1 <= rounds <= 4096:
        shown = rounds if rounds.bit_length() <= 64 else f"a {rounds.bit_length()}-bit value"
        raise ValueError(f"{label}: round count is {shown} (expected 1..4096)")
    nbytes = issuer_n // 8
    cbytes = min(issuer_n, 256) // 8
    for what, v, nb in (("commitments", c_int, 3 * rounds * cbytes),
                        ("challenges", ch_int, (rounds + 3) // 4),
                        ("responses", r_int, 2 * rounds * nbytes)):
        if v.bit_length() > 8 * nb:
            raise ValueError(f"{label}: {what} field is wider than {nb} bytes")

    commits_ba = c_int.to_bytes(3 * rounds * cbytes, 'big')
    commits = []
    for i in range(rounds):
        off = i * 3 * cbytes
        c0 = int.from_bytes(commits_ba[off:off + cbytes], 'big')
        c1 = int.from_bytes(commits_ba[off + cbytes:off + 2*cbytes], 'big')
        c2 = int.from_bytes(commits_ba[off + 2*cbytes:off + 3*cbytes], 'big')
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
    # n, W and rounds all size allocations below; W additionally indexes into
    # the statement, so an unbounded one is not merely a large read (TODO #275).
    n    = _packed_n(body, 0, _HCRED_MAX_N, "HCRED proof: n")
    W    = _packed_n(body, 4, _HCRED_MAX_N, "HCRED proof: W")
    R    = _packed_n(body, 8, _ZKP_NL_MAX_ROUNDS, "HCRED proof: rounds")
    off  = 12
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
    _packed_end(body, off, label)
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
    der = der_seq(der_int(R_j, nb), der_int(C_j, nb), der_int(n))
    return pem_wrap(_HPKST_COMMIT_LBL, der)


def decode_hpkst_commit(pem_text: str) -> tuple:
    """Returns (R_j, C_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_COMMIT_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    R_j, C_j, n = _der_count(label, data, 3, 2)
    return R_j, C_j, n


def encode_hpkst_nonce(k_j: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(k_j, nb), der_int(n))
    return pem_wrap(_HPKST_NONCE_LBL, der)


def decode_hpkst_nonce(pem_text: str) -> tuple:
    """Returns (k_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_NONCE_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    k_j, n = _der_count(label, data, 2, 1)
    return k_j, n


def encode_hpkst_aggregate(R: int, C_agg: int, e: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(R, nb), der_int(C_agg, nb), der_int(e, nb), der_int(n))
    return pem_wrap(_HPKST_AGGREGATE_LBL, der)


def decode_hpkst_aggregate(pem_text: str) -> tuple:
    """Returns (R, C_agg, e, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_AGGREGATE_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    R, C_agg, e, n = _der_count(label, data, 4, 3)
    return R, C_agg, e, n


def encode_hpkst_partial(s_j: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(s_j, nb), der_int(n))
    return pem_wrap(_HPKST_PARTIAL_LBL, der)


def decode_hpkst_partial(pem_text: str) -> tuple:
    """Returns (s_j, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_PARTIAL_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    s_j, n = _der_count(label, data, 2, 1)
    return s_j, n


def encode_hpkst_sig(C_agg: int, R: int, s: int, n: int) -> str:
    nb = n // 8
    der = der_seq(der_int(C_agg, nb), der_int(R, nb), der_int(s, nb), der_int(n))
    return pem_wrap(_HPKST_SIG_LBL, der)


def decode_hpkst_sig(pem_text: str) -> tuple:
    """Returns (C_agg, R, s, n)."""
    label, data = pem_unwrap(pem_text)
    if label != _HPKST_SIG_LBL:
        raise ValueError(f"Unexpected PEM label: {label!r}")
    C_agg, R, s, n = _der_count(label, data, 4, 3)
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
