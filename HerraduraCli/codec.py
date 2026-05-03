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
    print("codec.py self-test OK")
