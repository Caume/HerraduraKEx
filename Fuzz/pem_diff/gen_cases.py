#!/usr/bin/env python3
"""Fuzz/pem_diff/gen_cases.py — PEM-shaped inputs for the PEM reader
differential (TODO #403; CliTest/test_pem_reader_diff.sh drives it).

    gen_cases.py SEED COUNT  >  cases.hex

One case per line, the file's bytes in hex.  Deterministic for a given SEED, so
a disagreement reproduces.  Two generators, alternating:

  * STRUCTURED: a block assembled from parts, each part drawn from a set that
    straddles SPEC.md §10.1's rules -- the text before BEGIN, the label (0, 1,
    78, 79, 80, 81 characters; a control or non-ASCII byte), what follows the
    BEGIN dashes, the body (padding 0/1/2, '=' moved, extra or missing
    characters, non-zero pad bits, whitespace of every kind, line widths), the
    END line (indented, unclosed, another label), and what follows it (nothing,
    whitespace, text, a second block).
  * MUTATED: a valid file (every KAT/pem/*.pem, plus small synthetic blocks)
    with one to four byte-level edits -- insert, delete, replace, duplicate a
    span -- drawing bytes from a set weighted toward the grammar's edges.

Nothing here decides what a reader SHOULD do; the test only asks that the four
readers agree, and that the cases reach every outcome (see the coverage floor
in the test).
"""
import base64
import glob
import os
import random
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

B64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
EDGE = [b'=', b' ', b'\t', b'\r', b'\n', b'\v', b'\f', b'\x00', b'-', b'_', b'.',
        b'\x7f', b'\x80', b'\xe9', b'\xff', b'#', b'"', b"'", b'A', b'z', b'0', b'+', b'/',
        b'-----', b'-----BEGIN ', b'-----END ', b'-----BEGIN X-----\n', b'-----END X-----\n']


def wrap(body: bytes, width: int, eol: bytes) -> bytes:
    if width <= 0:
        return body
    return eol.join(body[i:i + width] for i in range(0, len(body), width))


def label_of(rng: random.Random) -> bytes:
    k = rng.random()
    if k < 0.75:
        return rng.choice([b'L', b'HERRADURA HKEX-GF PRIVATE KEY', b'HERRADURA HPKS PUBLIC KEY',
                           b'A B', b' L', b'L '])
    if k < 0.90:
        n = rng.choice([0, 1, 2, 78, 79, 80, 81])
        return bytes(rng.choice(b'ABCXYZ -') for _ in range(n))
    base = bytearray(rng.choice([b'LABEL', b'HERRADURA KEY', b'X']))
    base.insert(rng.randrange(len(base) + 1), rng.choice(b'\x01\t\x7f\x80\xe9\xff=-'))
    return bytes(base)


def body_of(rng: random.Random, eol: bytes) -> bytes:
    der = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 2, 3, 4, 5, 30, 31, 32, 100])))
    b = bytearray(base64.b64encode(der))
    k = rng.random()
    if b and k < 0.10:                                   # move a '='
        if b'=' in b:
            i = b.index(b'=')
            del b[i]
            b.insert(rng.randrange(len(b) + 1), ord('='))
    elif b and k < 0.20:                                 # non-zero bits under the padding
        if b.endswith(b'=='):
            b[-3] = B64[B64.index(b[-3]) | 1]
        elif b.endswith(b'='):
            b[-2] = B64[B64.index(b[-2]) | 1]
    elif b and k < 0.24:                                 # drop the padding
        b = bytearray(bytes(b).rstrip(b'='))
    elif k < 0.30:                                       # extra '='
        b += b'=' * rng.choice([1, 2, 3])
    elif b and k < 0.36:                                 # one character more or less
        if rng.random() < 0.5:
            del b[rng.randrange(len(b))]
        else:
            b.insert(rng.randrange(len(b) + 1), rng.choice(B64))
    elif b and k < 0.46:                                 # a foreign byte inside
        b.insert(rng.randrange(len(b) + 1), ord(rng.choice(EDGE[:12])[:1]))
    width = rng.choice([0, 4, 7, 64, 76, 76, 76, 80])
    text = wrap(bytes(b), width, eol)
    if rng.random() < 0.15:                              # blank lines or trailing blanks
        lines = text.split(eol)
        lines = [l + rng.choice([b'', b' ', b'\t', b' \t']) for l in lines]
        if rng.random() < 0.5:
            lines.insert(rng.randrange(len(lines) + 1), b'')
        text = eol.join(lines)
    return text


def pick(rng: random.Random, usual, odd: list, p_odd: float):
    """usual, or (with probability p_odd) one of the odd values."""
    return rng.choice(odd) if rng.random() < p_odd else usual


def structured(rng: random.Random) -> bytes:
    # Each part is usually well formed and sometimes not, so most cases break
    # zero or one rule: the region where two readers' edges would differ.
    q = rng.choice([0.03, 0.08, 0.2])
    eol = rng.choice([b'\n', b'\n', b'\n', b'\r\n', b'\r'])
    pre = pick(rng, b'', [b'\n', b' \t\r\n', b'x\n', b'\v', b'\xef\xbb\xbf', b'-----BEGIN ',
                          b'junk -----BEGIN L-----\n'], 2 * q)
    lab = label_of(rng)
    lab2 = pick(rng, lab, [b'', b'L', lab + b' ', lab[:-1], b'\xe9', lab + b'\x00', b'\x1b[0m'], q)
    after_begin = pick(rng, b'-----', [b'----- ', b'-----\t', b'----- \t ', b'----- x',
                                       b'----', b'------', b''], 2 * q)
    begin_eol = pick(rng, eol, [b'', b' ' + eol], q)
    body = body_of(rng, eol)
    pre_end = pick(rng, eol, [b'', b' ', eol + b' ', eol + eol, eol + b'\t'], q)
    end_tail = pick(rng, b'-----', [b'----', b'', b'----- ', b'-----x', b'------'], q)
    post = pick(rng, eol, [b'', eol + eol, b' ', b'\t' + eol, b'x', eol + b'x' + eol,
                           b'\v', b'\x00'], 3 * q)
    out = pre + b'-----BEGIN ' + lab + after_begin + begin_eol + body + pre_end + \
        b'-----END ' + lab2 + end_tail + post
    if rng.random() < 0.05:
        out = out + out                                  # a second block
    if rng.random() < 0.03:
        out = out[:rng.randrange(len(out) + 1)]          # truncated
    return out


def bases() -> list:
    files = sorted(glob.glob(os.path.join(ROOT, 'KAT', 'pem', '*.pem')))
    out = [open(f, 'rb').read() for f in files]
    for der in (b'\x00', b'\x01\x02', b'\x01\x02\x03', b'\x30\x03\x02\x01\x05'):
        out.append(b'-----BEGIN L-----\n' + base64.b64encode(der) + b'\n-----END L-----\n')
    return out


def mutated(rng: random.Random, pool: list) -> bytes:
    b = bytearray(rng.choice(pool))
    for _ in range(rng.choice([1, 1, 2, 3, 4])):
        k = rng.random()
        i = rng.randrange(len(b) + 1)
        if k < 0.35:
            b[i:i] = rng.choice(EDGE)
        elif k < 0.60 and b:
            del b[min(i, len(b) - 1)]
        elif k < 0.85 and b:
            b[min(i, len(b) - 1)] = rng.choice(EDGE)[0]
        elif b:
            j = rng.randrange(len(b))
            b[i:i] = b[j:j + rng.randrange(1, 40)]
    return bytes(b)


def main() -> None:
    seed, count = int(sys.argv[1]), int(sys.argv[2])
    rng = random.Random(seed)
    pool = bases()
    w = sys.stdout.write
    for n in range(count):
        case = structured(rng) if n % 2 == 0 else mutated(rng, pool)
        w(case.hex() + '\n')


if __name__ == '__main__':
    main()
