#!/usr/bin/env python3
"""Fuzz/raw_body_diff/gen_cases.py — mutated raw-body PEMs for the raw-body
reader differential (TODO #406; CliTest/test_raw_body_diff.sh drives it).

    gen_cases.py SEED FIXDIR OUTDIR COUNT HCPROOF_COUNT  >  list

Reads the eight fixtures the test writes into FIXDIR (one per raw-body artifact
it can read through a CLI subcommand: the ZKP-NL key pair, a ZKBoo and a ZKB++
signature, a ZKP-RNL proof, the HCRED key pair and an HCRED proof) and writes
COUNT mutations of each (HCPROOF_COUNT of the HCRED proof, whose verification
is the slow one) into OUTDIR, printing one line per case:

    KIND FILE HOW

Deterministic for a given SEED, so a disagreement reproduces.  Each mutation is
one of:

  * SET a structural field -- a 4-byte header (n, rounds, W) or a per-round
    length byte (ZKBoo len_p1 / len_p2, ZKB++ gates_len / has_share2, the
    challenge e) -- to an edge value: 0, 1, the width boundaries, 2^31, ...;
  * CUT one to three bytes, or a random number, off the end;
  * ADD one to four random bytes after the last field;
  * FLIP one byte past the header, so that a case reaches the verifier;
  * EDIT one to three bytes, half of them in the first sixteen.

Nothing here decides what a reader SHOULD do; the test only asks that the four
agree, that none crashes, and that the cases reach every outcome.
"""
import base64
import os
import random
import sys

ART = [('zkpriv', 'zk.pem'), ('zkpub', 'zk_pub.pem'), ('zkboo', 'zkboo.pem'),
       ('zkbpp', 'zkbpp.pem'), ('rnlsig', 'rnlsig.pem'), ('hcpriv', 'hc.pem'),
       ('hcpub', 'hc_pub.pem'), ('hcproof', 'hcproof.pem')]
U32 = [0, 1, 2, 7, 8, 9, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1023, 1024, 1025,
       4095, 4096, 4097, 0x7fffffff, 0x80000000, 0xffffffff]
B8 = [0, 1, 2, 3, 4, 0x7f, 0x80, 0xfe, 0xff]
B16 = [0, 1, 0xff, 0x100, 0xffff]


def read_pem(path):
    lines = open(path).read().split('\n')
    label = lines[0][len('-----BEGIN '):-len('-----')]
    body = base64.b64decode(''.join(l for l in lines[1:] if l and not l.startswith('-----')))
    return label, body


def write_pem(path, label, body):
    b64 = base64.encodebytes(body).decode()
    with open(path, 'w') as f:
        f.write(f'-----BEGIN {label}-----\n{b64}-----END {label}-----\n')


def fields(kind, b):
    """The (offset, width) of every structural field worth setting."""
    out = [(0, 4)]
    if kind in ('zkboo', 'zkbpp', 'hcproof'):
        out.append((4, 4))
    if kind == 'hcproof':
        out.append((8, 4))
    if kind == 'zkboo':             # 96B coms | 1B e | 2B len_p1 | view | 2B len_p2 | view
        p = 8
        while p + 99 <= len(b):
            out += [(p + 96, 1), (p + 97, 2)]
            q = p + 99 + int.from_bytes(b[p + 97:p + 99], 'big')
            if q + 2 > len(b):
                break
            out.append((q, 2))
            p = q + 2 + int.from_bytes(b[q:q + 2], 'big')
    if kind == 'zkbpp':             # 32B com | 1B e | nb out | 32B seeds | gates_len | gates | has_share2
        nb = (int.from_bytes(b[:4], 'big') + 7) // 8
        p = 8
        while p + 32 + 1 + nb + 32 + 1 <= len(b):
            g = p + 33 + nb + 32
            out += [(p + 32, 1), (g, 1)]
            h = g + 1 + b[g]
            if h >= len(b):
                break
            out.append((h, 1))
            p = h + 1 + (nb if b[h] else 0)
    return out


def main():
    seed, fixdir, outdir = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    count, hc_count = int(sys.argv[4]), int(sys.argv[5])
    rng = random.Random(seed)
    for kind, fname in ART:
        label, body = read_pem(os.path.join(fixdir, fname))
        offs = fields(kind, body)
        for i in range(hc_count if kind == 'hcproof' else count):
            d = bytearray(body)
            r = rng.random()
            if r < 0.4:
                off, w = rng.choice(offs)
                v = rng.choice(U32 if w == 4 else B8 if w == 1 else B16) & ((1 << 8 * w) - 1)
                d[off:off + w] = v.to_bytes(w, 'big')
                how = f'set@{off}/{w}={v}'
            elif r < 0.55:
                k = rng.choice([1, 2, 3, rng.randrange(1, len(d))])
                del d[len(d) - k:]
                how = f'cut{k}'
            elif r < 0.65:
                k = rng.choice([1, 2, 3, 4])
                d += bytes(rng.randrange(256) for _ in range(k))
                how = f'add{k}'
            elif r < 0.8:
                hdr = {'zkboo': 8, 'zkbpp': 8, 'hcproof': 12}.get(kind, 4)
                p = rng.randrange(hdr, len(d))
                d[p] ^= rng.randrange(1, 256)
                how = f'flip@{p}'
            else:
                for _ in range(rng.choice([1, 1, 2, 3])):
                    p = rng.randrange(min(len(d), 16)) if rng.random() < 0.5 else rng.randrange(len(d))
                    d[p] = rng.randrange(256)
                how = 'edit'
            name = f's{seed}_{kind}_{i:03d}.pem'
            write_pem(os.path.join(outdir, name), label, bytes(d))
            print(kind, name, how)


if __name__ == '__main__':
    main()
