#!/usr/bin/env python3
"""Fuzz/pem_diff/pem_diff_py.py — the Python reader's side of the PEM reader
differential (TODO #403; CliTest/test_pem_reader_diff.sh drives it).

stdin: one case per line, the file's bytes in hex.  stdout: one line per case,
"OK <label hex> <der hex>" or "ERR <message hex>".  The bytes go to
codec.pem_unwrap as herradura.py's _read_pem_text reads them (latin-1), and the
message is encoded as the CLI's `error: ...` line reaches stderr (UTF-8).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', '..', 'HerraduraCli'))
import codec  # noqa: E402


def h(b: bytes) -> str:
    return b.hex() if b else '-'


out = []
for line in sys.stdin:
    data = bytes.fromhex(line.strip())
    try:
        label, der = codec.pem_unwrap(data.decode('latin-1'))
    except ValueError as e:
        out.append('ERR ' + h(str(e).encode('utf-8')))
    else:
        out.append('OK %s %s' % (h(label.encode('utf-8')), h(der)))
sys.stdout.write('\n'.join(out) + ('\n' if out else ''))
