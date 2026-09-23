#!/usr/bin/env python3
"""KAT/verify_bitarray_py.py — the Python consumer for KAT/bitarray.json (TODO #314).

BITARRAY.md is the specification; KAT/generate_bitarray_kat.py carries the
reference implementation and pins its output; this runs the SHIPPED Python
BitArray against those pinned answers.

Python is pass 4 and the THIRD port in the gating set, beside C (pass 2) and Go
(pass 3).  Only Java is left, and the report in the generator says so.

WHY THIS IS NOT CIRCULAR, which is the question to ask of a Python consumer
checking a Python-generated vector.  The reference lives in
KAT/generate_bitarray_kat.py as class `Ref`, a SEPARATE implementation written
against the document — it stores octets in its own `b` field, keeps its own
private `_int()` for arithmetic, and shares no code with the suite.  This
consumer imports the SHIPPED suite through importlib, exactly as the twenty
SecurityProofsCode scripts do, and never touches `Ref`.  The two agree because
both satisfy BITARRAY.md, and when they stop agreeing this goes red — which is
the same relationship C and Go's consumers have with it.  What a Python
consumer cannot do is prove the vector is right; three ports agreeing is what
does that, and that is the point of the third one.

Run by CliTest/test_kat_vectors.sh.
"""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_suite():
    """The suite filename contains spaces, so importlib rather than import."""
    path = os.path.join(ROOT, 'Herradura cryptographic suite.py')
    spec = importlib.util.spec_from_file_location('_suite', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


h = _load_suite()
BitArray = h.BitArray
BaError = h.BaError

passes = 0
failures = 0


def ok(cond: bool, case: dict, detail: str) -> None:
    global passes, failures
    if cond:
        passes += 1
        return
    failures += 1
    mixed = ' mixed' if case.get('mixed_with') else ''
    print(f"FAIL [{case['op']} n={case['nbits']}{mixed}] {detail}")


def _run(fn):
    """Return (value, error-code-or-None) for a call that may raise."""
    try:
        return fn(), None
    except BaError as e:
        return None, e.code


def check_bits(case, value, code):
    want_err = case['expect'].get('error')
    if want_err is not None:
        if code is None:
            ok(False, case, f'expected {want_err}, got a value')
        else:
            ok(code == want_err, case, f'expected {want_err}, got {code}')
        return
    if code is not None:
        ok(False, case, f'expected a value, got {code}')
        return
    want_hex, want_nbits = case['expect']['hex'], case['expect']['nbits']
    ok(value.hex == want_hex and value.size == want_nbits, case,
       f'got {value.hex}/{value.size} want {want_hex}/{want_nbits}')


def check_int(case, value, code):
    want_err = case['expect'].get('error')
    if want_err is not None:
        got = 'a value' if code is None else code
        ok(code == want_err, case, f'expected {want_err}, got {got}')
        return
    if code is not None:
        ok(False, case, f'expected a value, got {code}')
        return
    ok(value == case['expect']['int'], case,
       f"got {value} want {case['expect']['int']}")


def main() -> int:
    global failures
    with open(os.path.join(ROOT, 'KAT', 'bitarray.json'), 'rb') as fh:
        vector = json.load(fh)
    cases = vector['cases']
    if vector['case_count'] != len(cases):
        print(f"FAIL: case_count {vector['case_count']} but {len(cases)} cases")
        return 1

    print('=== KAT/bitarray.json against the shipped Python BitArray (TODO #314) ===')
    print(f'    {len(cases)} cases, capacity BA_MAX_BITS = {h.BA_MAX_BITS}')

    for case in cases:
        op = case['op']
        n = case['nbits']
        bw = case.get('mixed_with') or n
        args = case['args']

        # Constructors read their own operand and are scored directly.
        if op == 'zero':
            v, c = _run(lambda: BitArray.zero(n))
            check_bits(case, v, c)
            continue
        if op == 'from_hex':
            v, c = _run(lambda: BitArray.from_hex(args['hex'], n))
            check_bits(case, v, c)
            continue
        if op == 'from_bytes':
            v, c = _run(lambda: BitArray.from_bytes(bytes.fromhex(args['hex']), n))
            check_bits(case, v, c)
            continue
        if op == 'from_uint':
            v, c = _run(lambda: BitArray.from_uint(args['uint'], n))
            check_bits(case, v, c)
            continue

        # Everything below needs its operands to load.  A width this port
        # cannot represent is E_WIDTH, a legitimate answer the vector may pin.
        a = b = None
        if 'a' in args or 'hex' in args:
            a, c = _run(lambda: BitArray.from_hex(args.get('a', args.get('hex')), n))
            if c is not None:
                check_bits(case, None, c)
                continue
        if 'b' in args:
            b, c = _run(lambda: BitArray.from_hex(args['b'], bw))
            if c is not None:
                check_bits(case, None, c)
                continue

        if op == 'to_uint':
            v, c = _run(a.to_uint)
            check_int(case, v, c)
        elif op == 'popcount':
            check_int(case, a.popcount(), None)
        elif op == 'is_zero':
            ok(a.is_zero() == case['expect']['bool'], case, 'is_zero')
        elif op in ('xor', 'and', 'or'):
            fn = {'xor': lambda: a ^ b, 'and': lambda: a & b, 'or': lambda: a | b}[op]
            v, c = _run(fn)
            check_bits(case, v, c)
        elif op == 'not':
            v, c = _run(lambda: ~a)
            check_bits(case, v, c)
        elif op == 'rot_left':
            v, c = _run(lambda: a.rot_left(args['s']))
            check_bits(case, v, c)
        elif op == 'rot_right':
            v, c = _run(lambda: a.rot_right(args['s']))
            check_bits(case, v, c)
        elif op == 'shl':
            v, c = _run(lambda: a.shl(args['k']))
            check_bits(case, v, c)
        elif op == 'shr':
            v, c = _run(lambda: a.shr(args['k']))
            check_bits(case, v, c)
        elif op == 'truncate':
            v, c = _run(lambda: a.truncate(args['m']))
            check_bits(case, v, c)
        elif op == 'extend':
            v, c = _run(lambda: a.extend(args['m']))
            check_bits(case, v, c)
        elif op == 'resize_exact':
            v, c = _run(lambda: a.resize_exact(args['m']))
            check_bits(case, v, c)
        elif op == 'equal':
            ok((a == b) == case['expect']['bool'], case, 'equal')
        elif op == 'compare':
            v, c = _run(lambda: a.compare(b))
            check_int(case, v, c)
        elif op == 'bit':
            v, c = _run(lambda: a.bit(args['i']))
            check_int(case, v, c)
        elif op == 'fscx':
            v, c = _run(lambda: h.fscx(a, b))
            check_bits(case, v, c)
        elif op == 'fscx_revolve':
            def revolve():
                cur = a
                for _ in range(args['i']):
                    cur = h.fscx(cur, b)
                return cur
            v, c = _run(revolve)
            check_bits(case, v, c)
        elif op == 'gf_mul':
            v, c = _run(lambda: h.ba_gf_mul(a, b))
            check_bits(case, v, c)
        elif op == 'gf_pow':
            v, c = _run(lambda: h.ba_gf_pow(a, args['e']))
            check_bits(case, v, c)
        elif op == 'rnl_kdf_seed':
            v, c = _run(lambda: h.rnl_kdf_seed(a))
            check_bits(case, v, c)
        else:
            failures += 1
            print(f'FAIL [{op}] no handler in verify_bitarray_py.py — a case the '
                  'consumer does not implement must not read as a pass')

    print(f'\nResults: {passes} PASS / {failures} FAIL (of {len(cases)} cases)')
    if passes + failures != len(cases):
        print(f'FAIL: {len(cases) - passes - failures} case(s) were neither passed '
              'nor failed — a case that did not run must not be scored (TODO #291)')
        return 1
    if failures:
        print('*** FAILED: the shipped Python BitArray disagrees with BITARRAY.md ***')
        return 1
    print('*** OK: the shipped Python BitArray matches KAT/bitarray.json ***')
    return 0


if __name__ == '__main__':
    sys.exit(main())
