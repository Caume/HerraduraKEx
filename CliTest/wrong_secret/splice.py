"""CliTest/wrong_secret/splice.py MODE SRC OUT [DONOR] -- TODO #410.

Write a private key whose PUBLIC fields are SRC's and whose secret is not, so
that whatever it signs or proves claims SRC's statement with a wrong witness:

  der0flip   flip the low bit of DER item 0 (HPKS / HPKS-NL: the secret a)
  der0donor  DER item 0 taken from DONOR (HKEX-RNL s, HPKS-Stern e)
  hcred_s    an HCRED raw body's s block taken from DONOR (same n)
"""
import sys, base64
mode, src, out = sys.argv[1:4]
donor = sys.argv[4] if len(sys.argv) > 4 else None
def raw(path):
    t = open(path).read().split('\n'); lab = t[0][11:-5]
    return lab, bytearray(base64.b64decode(''.join(l for l in t[1:] if l and not l.startswith('-----'))))
def write(lab, b):
    open(out, 'w').write(f'-----BEGIN {lab}-----\n{base64.encodebytes(bytes(b)).decode()}-----END {lab}-----\n')
def der_items(b):
    """(offset, length) of each INTEGER body in a SEQUENCE (short/long lengths)."""
    def ln(p):
        if b[p] < 0x80: return b[p], p + 1
        k = b[p] & 0x7f; return int.from_bytes(b[p+1:p+1+k], 'big'), p + 1 + k
    _, p = ln(1); res = []
    while p < len(b):
        assert b[p] == 2; l, q = ln(p + 1); res.append((q, l)); p = q + l
    return res
lab, b = raw(src)
if mode == 'der0flip':           # flip the low bit of DER item 0 (the secret)
    q, l = der_items(b)[0]; b[q + l - 1] ^= 1
elif mode == 'der0donor':        # item 0 from DONOR; the SEQUENCE is rebuilt
    _, d = raw(donor)
    dq, dl = der_items(d)[0]
    def tl(tag, body):           # DER tag-length-value with a minimal length
        n = len(body)
        ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([tag]) + ln + body
    items = [bytes(b[q:q + l]) for q, l in der_items(b)]
    items[0] = bytes(d[dq:dq + dl])
    b = bytearray(tl(0x30, b''.join(tl(0x02, it) for it in items)))
elif mode == 'hcred_s':          # HCRED raw body: n(4) | s (3 bytes x n) | ...
    _, d = raw(donor); n = int.from_bytes(b[:4], 'big'); b[4:4+3*n] = d[4:4+3*n]
else: sys.exit('mode?')
write(lab, b)
