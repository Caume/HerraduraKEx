#!/usr/bin/env python3
"""Fuzz/der_diff/der_diff_py.py — the Python parser's side of the DER parser
differential (TODO #404; CliTest/test_der_reader_diff.sh drives it).

stdin: one case per line, the DER bytes in hex.  stdout: one line per case,
"OK v/w/z ..." (value in minimal hex, encoded width, lead) or
"ERR <message hex>".  The steps are codec._der_count's for the label "L",
without the item count: der_parse_seq, then der_scan.  An exception other than
ValueError is printed as a refusal named EXC, so the test sees it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', 'HerraduraCli'))
import codec  # noqa: E402

out = []
for line in sys.stdin:
    d = bytes.fromhex(line.strip())
    try:
        ints = codec.der_parse_seq(d, 'L')
        enc = codec.der_scan(d, 'L')
    except ValueError as e:
        out.append('ERR ' + str(e).encode().hex())
    except Exception as e:          # a crash is a finding, not a refusal
        out.append('ERR ' + ('EXC %s: %s' % (type(e).__name__, e)).encode().hex())
    else:
        out.append('OK' + ''.join(' %x/%d/%d' % (v, w, z) for v, (w, z) in zip(ints, enc)))
sys.stdout.write('\n'.join(out) + ('\n' if out else ''))
