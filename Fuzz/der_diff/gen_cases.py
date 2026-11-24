#!/usr/bin/env python3
"""Fuzz/der_diff/gen_cases.py — DER inputs for the DER parser differential
(TODO #404; CliTest/test_der_reader_diff.sh drives it).

    gen_cases.py SEED COUNT  >  cases.hex

One case per line, the DER bytes in hex.  Deterministic for a given SEED, so a
disagreement reproduces.  Two generators, alternating:

  * STRUCTURED: a SEQUENCE of INTEGERs built item by item, each part usually
    well formed and sometimes not -- an INTEGER empty, negative, with a needed
    or a needless 0x00; a length in long form when short would do, BER's 0x80,
    five length bytes, a length one off or past 2^31; another tag; 0 to 20
    items (the C CLI stores 16); bytes after the SEQUENCE; a truncation.
  * MUTATED: the DER of every DER-bodied KAT/pem/*.pem with one to three byte
    edits, half of them in the first twelve bytes where the lengths are.

Nothing here decides what a parser SHOULD do; the test only asks that the four
agree, and that the cases reach every outcome (see the coverage floor in the
test).
"""
import glob
import os
import random
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'HerraduraCli'))
import codec  # noqa: E402

EDGE = [0x00, 0x01, 0x02, 0x03, 0x04, 0x30, 0x31, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
        0xff]


def enc_len(n: int) -> bytes:
    return codec._encode_length(n)


def odd_len(rng: random.Random, n: int) -> bytes:
    """A length for content of n bytes: usually right, sometimes not."""
    k = rng.random()
    if k < 0.12:
        return b'\x81' + bytes([n]) if n < 256 else b'\x83' + n.to_bytes(3, 'big')  # long form
    if k < 0.20:
        return b'\x82' + n.to_bytes(2, 'big')
    if k < 0.26:
        return b'\x80'                                            # BER indefinite
    if k < 0.31:
        return b'\x85' + n.to_bytes(5, 'big')                     # five length bytes
    if k < 0.36:
        return b'\x84' + n.to_bytes(4, 'big')
    if k < 0.44:
        return enc_len(max(0, n + rng.choice([-2, -1, 1, 2, 300])))
    if k < 0.48:
        return b'\x84' + rng.choice([b'\xff\xff\xff\xff', b'\x80\x00\x00\x00', b'\x7f\xff\xff\xff'])
    if k < 0.51:
        return rng.choice([b'\x81', b'\x82\x01'])                 # length bytes missing
    return enc_len(n)


def content(rng: random.Random) -> bytes:
    k = rng.random()
    if k < 0.06:
        return b''                                                # empty INTEGER
    if k < 0.12:
        return b'\x00'
    if k < 0.20:
        return b'\x00' + bytes([rng.randrange(0x80, 256)])                     # sign byte
    if k < 0.26:
        return b'\x00' + bytes([rng.randrange(0, 0x80)])                     # needless zero
    if k < 0.32:
        return bytes([rng.randrange(0x80, 256)])                              # negative
    n = rng.choice([1, 1, 2, 4, 31, 32, 33, 127, 128, 129, 200, 300])
    b = bytearray(rng.randrange(256) for _ in range(n))
    if b[0] & 0x80:
        b[0:0] = b'\x00'
    elif len(b) > 1 and b[0] == 0:
        b[0] = 1
    return bytes(b)


def structured(rng: random.Random) -> bytes:
    q = rng.choice([0.0, 0.05, 0.15])          # how often each part goes wrong
    body = b''
    for _ in range(rng.choice([0, 1, 2, 3, 3, 5, 8, 15, 16, 17, 20])):
        c = content(rng) if rng.random() < 2 * q else content_ok(rng)
        tag = b'\x02' if rng.random() >= q / 3 else bytes([rng.choice([0x03, 0x04, 0x30, 0x00, 0x05])])
        body += tag + (odd_len(rng, len(c)) if rng.random() < q else enc_len(len(c))) + c
    out = b'\x30' + (odd_len(rng, len(body)) if rng.random() < 2 * q else enc_len(len(body))) + body
    if rng.random() < q / 2:
        out = rng.choice([b'\x31', b'\x02', b'\x10', b'']) + out[1:]
    if rng.random() < q:
        out += rng.choice([b'\x00', b'\x02\x01\x01', b'\x30\x00', bytes([rng.randrange(256)])])
    if rng.random() < q / 2:
        out = out[:rng.randrange(len(out) + 1)]
    return out


def content_ok(rng: random.Random) -> bytes:
    while True:
        c = content(rng)
        if c and not (c[0] & 0x80) and not (len(c) > 1 and c[0] == 0 and not c[1] & 0x80):
            return c


def bases() -> list:
    out = []
    for f in sorted(glob.glob(os.path.join(ROOT, 'KAT', 'pem', '*.pem'))):
        try:
            _, der = codec.pem_unwrap(open(f, 'rb').read().decode('latin-1'))
        except ValueError:
            continue
        if der[:1] == b'\x30':
            out.append(der)
    return out


def mutated(rng: random.Random, pool: list) -> bytes:
    b = bytearray(rng.choice(pool))
    for _ in range(rng.choice([1, 1, 2, 3])):
        if not b:
            break
        i = rng.randrange(min(len(b), 12)) if rng.random() < 0.5 else rng.randrange(len(b))
        k = rng.random()
        if k < 0.4:
            b[i] = rng.choice(EDGE)
        elif k < 0.6:
            b[i:i] = bytes([rng.choice(EDGE)])
        elif k < 0.8:
            del b[i]
        else:
            del b[i:]
    return bytes(b)


def main() -> None:
    seed, count = int(sys.argv[1]), int(sys.argv[2])
    rng = random.Random(seed)
    pool = bases()
    w = sys.stdout.write
    for n in range(count):
        w((structured(rng) if n % 2 == 0 else mutated(rng, pool)).hex() + '\n')


if __name__ == '__main__':
    main()
