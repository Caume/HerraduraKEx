#!/usr/bin/env python3
"""BitArray conformance vectors (TODO #314) — reference implementation and generator.

`BITARRAY.md` is the normative specification; this file carries the REFERENCE
IMPLEMENTATION of it, and `KAT/bitarray.json` is that implementation's pinned output.
The four shipped ports are converted to match, one per release (BITARRAY.md §8), and
each joins the gating set as it lands.

Why the reference lives in a generator and not in a fifth shipped library: TODO #314's
"what must NOT happen" is a fifth implementation standing beside the four.  A generator
is not shipped and is not linked by anything — it is the same standing as
`generate_kat.py`, which is the deterministic reference for three other vector files.

  --check    verify KAT/bitarray.json is current (gating)
  --report   which ports are converted and which consumer gates each.
             A REPORT, not a gate: a port not yet converted is expected to differ, and
             CLAUDE.md's Testing section allows no failing test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "bitarray.json")

WIDTHS = (32, 64, 128, 256)

RNL_KDF_DC_256 = 0x6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19

# BITARRAY.md 4.6.  A width with no entry is E_NO_POLY, never a default.
GF_POLY = {32: 0x00400007, 64: 0x0000001B, 128: 0x00000087, 256: 0x00000425}

BA_MAX_BITS = 256       # BITARRAY.md 2/9: the per-port capacity, 256 for passes 2-5.
                        # Keeping the reference AT the minimum keeps every vector case
                        # capacity-independent, so a port cannot 'diverge' merely by
                        # having more room.  Widening it is a later decision that
                        # regenerates this file.


# ---------------------------------------------------------------------------
# Errors (BITARRAY.md 5) — a closed set, identical in every port
# ---------------------------------------------------------------------------

ERROR_CODES = (
    "E_WIDTH", "E_MIXED_WIDTH", "E_LENGTH", "E_RANGE",
    "E_LOSSY", "E_HEXDIGIT", "E_NO_POLY", "E_ENTROPY",
)


class BaError(Exception):
    def __init__(self, code: str, detail: str = ""):
        assert code in ERROR_CODES, f"undeclared error code {code!r}"
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _check_width(n: int) -> None:
    if not isinstance(n, int) or n <= 0 or n % 8 != 0:
        raise BaError("E_WIDTH", f"{n} is not a positive multiple of 8")
    if n < 16:
        raise BaError("E_WIDTH", f"{n} < 16 (fscx degenerates below two octets)")
    if n > BA_MAX_BITS:
        raise BaError("E_WIDTH", f"{n} > BA_MAX_BITS ({BA_MAX_BITS})")


# ---------------------------------------------------------------------------
# The reference BitArray (BITARRAY.md 1, 4)
# ---------------------------------------------------------------------------

class Ref:
    """Big-endian octet string with the width carried alongside it.

    Deliberately stores OCTETS, not an int: an integer type normalises leading zero
    octets away, which is exactly the information nbits exists to carry, and the
    re-widening step on the way out is where Go's Bytes() goes wrong (BITARRAY.md 6.1).
    """

    __slots__ = ("nbits", "b")

    def __init__(self, nbits: int, octets: bytes):
        _check_width(nbits)
        if len(octets) != nbits // 8:
            raise BaError("E_LENGTH", f"{len(octets)} octets for a {nbits}-bit value")
        self.nbits = nbits
        self.b = bytes(octets)

    # -- construction ------------------------------------------------------
    @staticmethod
    def zero(n: int) -> "Ref":
        _check_width(n)
        return Ref(n, bytes(n // 8))

    @staticmethod
    def from_bytes(data: bytes, n: int) -> "Ref":
        _check_width(n)
        if len(data) != n // 8:
            raise BaError("E_LENGTH", f"{len(data)} octets for a {n}-bit value")
        return Ref(n, data)

    @staticmethod
    def from_uint(v: int, n: int) -> "Ref":
        _check_width(n)
        if n > 64:
            raise BaError("E_RANGE", "integer conversions are defined for n <= 64")
        if v < 0:
            raise BaError("E_RANGE", "negative value")
        if v >= (1 << n):
            # Masking here is how an out-of-range intermediate becomes a
            # plausible-looking in-range value with nothing recording it.
            raise BaError("E_RANGE", f"value needs {v.bit_length()} bits, width is {n}")
        return Ref(n, v.to_bytes(n // 8, "big"))

    @staticmethod
    def from_hex(s: str, n: int) -> "Ref":
        _check_width(n)
        if len(s) != n // 4:
            raise BaError("E_LENGTH", f"{len(s)} hex digits for a {n}-bit value")
        if any(c not in "0123456789abcdefABCDEF" for c in s):
            raise BaError("E_HEXDIGIT", "non-hex character")
        return Ref(n, bytes.fromhex(s))

    # -- conversion --------------------------------------------------------
    def to_bytes(self) -> bytes:
        return self.b

    def to_hex(self) -> str:
        return self.b.hex()

    def _int(self) -> int:
        """The reference's own arithmetic, at any width.

        PRIVATE on purpose.  The reference may use Python's arbitrary-precision
        integers to COMPUTE a result; the public to_uint may not RETURN one
        above 64 bits, because that is the bignum dependency BITARRAY.md 1.1
        removes.  Keeping the two apart is what lets rot/shl/shr stay specified
        at every width while to_uint is bounded.
        """
        return int.from_bytes(self.b, "big")

    def to_uint(self) -> int:
        # BITARRAY.md 4.1: defined for n <= 64 only.  Specifying it at every
        # width would require an arbitrary-precision integer in every port,
        # which is the dependency this type exists to remove.
        if self.nbits > 64:
            raise BaError("E_RANGE", "integer conversions are defined for n <= 64")
        return self._int()

    def copy(self) -> "Ref":
        return Ref(self.nbits, self.b)

    # -- bitwise (BITARRAY.md 4.2) ----------------------------------------
    def _same(self, other: "Ref") -> None:
        if self.nbits != other.nbits:
            raise BaError("E_MIXED_WIDTH", f"{self.nbits} vs {other.nbits}")

    def xor(self, other: "Ref") -> "Ref":
        self._same(other)
        return Ref(self.nbits, bytes(x ^ y for x, y in zip(self.b, other.b)))

    def and_(self, other: "Ref") -> "Ref":
        self._same(other)
        return Ref(self.nbits, bytes(x & y for x, y in zip(self.b, other.b)))

    def or_(self, other: "Ref") -> "Ref":
        self._same(other)
        return Ref(self.nbits, bytes(x | y for x, y in zip(self.b, other.b)))

    def not_(self) -> "Ref":
        return Ref(self.nbits, bytes(x ^ 0xFF for x in self.b))

    # -- rotation and shift (BITARRAY.md 4.3) ------------------------------
    def rot_left(self, s: int) -> "Ref":
        n = self.nbits
        s %= n                      # Python's % is already the mathematical one;
        if s == 0:                  # a port whose % can go negative must correct it.
            return self.copy()
        v = self._int()
        return Ref(n, (((v << s) | (v >> (n - s))) & ((1 << n) - 1)).to_bytes(n // 8, "big"))

    def rot_right(self, s: int) -> "Ref":
        return self.rot_left(-s)

    def shl(self, k: int) -> "Ref":
        if k < 0:
            raise BaError("E_RANGE", "negative shift")
        n = self.nbits
        if k >= n:                  # stated, not assumed: this expression is UB in C,
            return Ref.zero(n)      # a panic in Go, 0 in Python and a rotation in Java.
        return Ref(n, ((self._int() << k) & ((1 << n) - 1)).to_bytes(n // 8, "big"))

    def shr(self, k: int) -> "Ref":
        if k < 0:
            raise BaError("E_RANGE", "negative shift")
        n = self.nbits
        if k >= n:
            return Ref.zero(n)
        return Ref(n, (self._int() >> k).to_bytes(n // 8, "big"))

    # -- width change (BITARRAY.md 4.4) ------------------------------------
    def truncate(self, m: int) -> "Ref":
        """Keep the HIGH m bits — the big-endian PREFIX.  Settles TODO #313."""
        _check_width(m)
        if m > self.nbits:
            raise BaError("E_WIDTH", f"truncate to {m} from {self.nbits}")
        return Ref(m, self.b[: m // 8])

    def extend(self, m: int) -> "Ref":
        _check_width(m)
        if m < self.nbits:
            raise BaError("E_WIDTH", f"extend to {m} from {self.nbits}")
        return Ref(m, self.b + bytes((m - self.nbits) // 8))

    def resize_exact(self, m: int) -> "Ref":
        _check_width(m)
        if m >= self.nbits:
            return self.extend(m)
        if any(self.b[m // 8:]):
            raise BaError("E_LOSSY", f"narrowing {self.nbits} -> {m} discards a set bit")
        return self.truncate(m)

    # -- comparison and inspection (BITARRAY.md 4.5) -----------------------
    def equal(self, other: "Ref") -> bool:
        # Width AND value, and a mismatch is False rather than an error: an equality
        # test is a question, not an operation on a shared width.
        return self.nbits == other.nbits and self.b == other.b

    def compare(self, other: "Ref") -> int:
        self._same(other)
        a, b = self._int(), other._int()
        return -1 if a < b else (1 if a > b else 0)

    def is_zero(self) -> bool:
        return not any(self.b)

    def popcount(self) -> int:
        return sum(bin(x).count("1") for x in self.b)

    def bit(self, i: int) -> int:
        if i < 0 or i >= self.nbits:
            raise BaError("E_RANGE", f"bit {i} of a {self.nbits}-bit value")
        return (self.b[self.nbits // 8 - 1 - i // 8] >> (i % 8)) & 1

    # -- suite primitives (BITARRAY.md 4.6) --------------------------------
    def fscx(self, other: "Ref") -> "Ref":
        self._same(other)
        a, b = self, other
        return (a.xor(b).xor(a.rot_left(1)).xor(b.rot_left(1))
                 .xor(a.rot_right(1)).xor(b.rot_right(1)))

    def fscx_revolve(self, other: "Ref", i: int) -> "Ref":
        if i < 0:
            raise BaError("E_RANGE", "negative revolve count")
        cur = self
        for _ in range(i):
            cur = cur.fscx(other)
        return cur

    def gf_mul(self, other: "Ref") -> "Ref":
        self._same(other)
        n = self.nbits
        if n not in GF_POLY:
            raise BaError("E_NO_POLY", f"no primitive polynomial for {n} bits")
        poly, mask = GF_POLY[n], (1 << n) - 1
        a, b, r = self._int(), other._int(), 0
        for _ in range(n):
            if b & 1:
                r ^= a
            b >>= 1
            hi = a >> (n - 1)
            a = (a << 1) & mask
            if hi:
                a ^= poly
        return Ref(n, r.to_bytes(n // 8, "big"))

    def gf_pow(self, e: int) -> "Ref":
        if e < 0:
            raise BaError("E_RANGE", "negative exponent")
        n = self.nbits
        if n not in GF_POLY:
            raise BaError("E_NO_POLY", f"no primitive polynomial for {n} bits")
        r, base = Ref(n, (1).to_bytes(n // 8, "big")), self
        while e:
            if e & 1:
                r = r.gf_mul(base)
            base = base.gf_mul(base)
            e >>= 1
        return r

    def rnl_kdf_seed(self) -> "Ref":
        """ROL(k, n/8) XOR truncate(RNL_KDF_DC_256, n).  The TODO #313 site."""
        n = self.nbits
        dc = Ref(256, RNL_KDF_DC_256.to_bytes(32, "big")).truncate(n)
        return self.rot_left(n // 8).xor(dc)


# ---------------------------------------------------------------------------
# Vector generation
# ---------------------------------------------------------------------------

def _operand(n: int, tag: int) -> Ref:
    """Deterministic, structured operands — no RNG anywhere in this file.

    Structured rather than pseudo-random on purpose: a rotation or a truncation that
    loses a byte is invisible against a uniform operand and obvious against a patterned
    one.  Every byte is distinct mod 251 so a misplaced index shows up as a value.
    """
    return Ref(n, bytes((tag * 97 + 31 * i) % 251 for i in range(n // 8)))


def _capture(fn) -> dict:
    """Run fn; record either its value or the error CODE it raised."""
    try:
        v = fn()
    except BaError as e:
        return {"error": e.code}
    if isinstance(v, Ref):
        return {"hex": v.to_hex(), "nbits": v.nbits}
    if isinstance(v, bool):
        return {"bool": v}
    return {"int": v}


def build_vectors() -> dict:
    cases: list[dict] = []

    def add(op: str, n: int, args: dict, fn) -> None:
        cases.append({"op": op, "nbits": n, "args": args, "expect": _capture(fn)})

    for n in WIDTHS:
        a, b = _operand(n, 1), _operand(n, 2)
        ah, bh = a.to_hex(), b.to_hex()

        # construction / conversion
        add("zero", n, {}, lambda n=n: Ref.zero(n))
        add("from_hex", n, {"hex": ah}, lambda n=n, ah=ah: Ref.from_hex(ah, n))
        add("to_uint", n, {"hex": ah}, lambda a=a: a.to_uint())
        add("popcount", n, {"hex": ah}, lambda a=a: a.popcount())
        add("is_zero", n, {"hex": ah}, lambda a=a: a.is_zero())
        add("is_zero", n, {"hex": Ref.zero(n).to_hex()},
            lambda n=n: Ref.zero(n).is_zero())

        # bitwise
        for op, fn in (("xor", Ref.xor), ("and", Ref.and_), ("or", Ref.or_)):
            add(op, n, {"a": ah, "b": bh}, lambda a=a, b=b, f=fn: f(a, b))
        add("not", n, {"a": ah}, lambda a=a: a.not_())

        # rotation and shift, including the edges that differ across languages
        for s in (0, 1, 7, 8, 9, n // 8, n // 2, n - 1, n, n + 1, -1, -n // 4):
            add("rot_left", n, {"a": ah, "s": s}, lambda a=a, s=s: a.rot_left(s))
        for s in (1, 7, 8, n // 4):
            add("rot_right", n, {"a": ah, "s": s}, lambda a=a, s=s: a.rot_right(s))
        for k in (0, 1, 7, 8, 9, n - 1, n, n + 1, 2 * n, -1):
            add("shl", n, {"a": ah, "k": k}, lambda a=a, k=k: a.shl(k))
            add("shr", n, {"a": ah, "k": k}, lambda a=a, k=k: a.shr(k))

        # width change — the TODO #313 clause
        for m in (16, 32, n // 2, n, 2 * n):
            add("truncate", n, {"a": ah, "m": m}, lambda a=a, m=m: a.truncate(m))
            add("extend", n, {"a": ah, "m": m}, lambda a=a, m=m: a.extend(m))
            add("resize_exact", n, {"a": ah, "m": m},
                lambda a=a, m=m: a.resize_exact(m))
        # a value that narrows losslessly, and the same width that does not
        lossless = Ref(n, bytes(n // 8 - 2) + b"\xAB\xCD") if n > 16 else a
        add("resize_exact", n, {"a": lossless.to_hex(), "m": 16},
            lambda v=lossless: v.resize_exact(16))

        # comparison
        add("equal", n, {"a": ah, "b": ah}, lambda a=a: a.equal(a))
        add("equal", n, {"a": ah, "b": bh}, lambda a=a, b=b: a.equal(b))
        add("compare", n, {"a": ah, "b": bh}, lambda a=a, b=b: a.compare(b))
        add("compare", n, {"a": bh, "b": ah}, lambda a=a, b=b: b.compare(a))
        add("compare", n, {"a": ah, "b": ah}, lambda a=a: a.compare(a))
        for i in (0, 1, 7, 8, n - 1, n):
            add("bit", n, {"a": ah, "i": i}, lambda a=a, i=i: a.bit(i))

        # suite primitives
        add("fscx", n, {"a": ah, "b": bh}, lambda a=a, b=b: a.fscx(b))
        for i in (0, 1, 4, n // 4):
            add("fscx_revolve", n, {"a": ah, "b": bh, "i": i},
                lambda a=a, b=b, i=i: a.fscx_revolve(b, i))
        add("gf_mul", n, {"a": ah, "b": bh}, lambda a=a, b=b: a.gf_mul(b))
        for e in (0, 1, 2, 3, 255):
            add("gf_pow", n, {"a": ah, "e": e}, lambda a=a, e=e: a.gf_pow(e))
        add("rnl_kdf_seed", n, {"a": ah}, lambda a=a: a.rnl_kdf_seed())

    # -- the cases that need two widths: every one of these is an error ----
    for n, m in ((64, 256), (256, 64), (32, 128)):
        x, y = _operand(n, 1), _operand(m, 2)
        for op, fn in (("xor", Ref.xor), ("and", Ref.and_), ("or", Ref.or_),
                       ("compare", Ref.compare), ("fscx", Ref.fscx),
                       ("gf_mul", Ref.gf_mul)):
            cases.append({
                "op": op, "nbits": n, "mixed_with": m,
                "args": {"a": x.to_hex(), "b": y.to_hex()},
                "expect": _capture(lambda x=x, y=y, f=fn: f(x, y)),
            })
        cases.append({
            "op": "equal", "nbits": n, "mixed_with": m,
            "args": {"a": x.to_hex(), "b": y.to_hex()},
            "expect": _capture(lambda x=x, y=y: x.equal(y)),
        })

    # -- invalid widths and out-of-range constructions ---------------------
    for n in (0, 7, 8, 12, 255, BA_MAX_BITS + 8, -8):
        cases.append({"op": "zero", "nbits": n, "args": {},
                      "expect": _capture(lambda n=n: Ref.zero(n))})
    cases.append({"op": "from_uint", "nbits": 32, "args": {"uint": 1 << 32},
                  "expect": _capture(lambda: Ref.from_uint(1 << 32, 32))})
    cases.append({"op": "from_uint", "nbits": 32, "args": {"uint": (1 << 32) - 1},
                  "expect": _capture(lambda: Ref.from_uint((1 << 32) - 1, 32))})
    cases.append({"op": "from_uint", "nbits": 32, "args": {"uint": -1},
                  "expect": _capture(lambda: Ref.from_uint(-1, 32))})
    cases.append({"op": "from_hex", "nbits": 32, "args": {"hex": "0011223"},
                  "expect": _capture(lambda: Ref.from_hex("0011223", 32))})
    cases.append({"op": "from_hex", "nbits": 32, "args": {"hex": "001122zz"},
                  "expect": _capture(lambda: Ref.from_hex("001122zz", 32))})
    cases.append({"op": "from_bytes", "nbits": 32, "args": {"hex": "001122"},
                  "expect": _capture(lambda: Ref.from_bytes(b"\x00\x11\x22", 32))})

    # -- a width with no primitive polynomial ------------------------------
    for n in (24, 512):
        try:
            _check_width(n)
        except BaError:
            continue
        v = _operand(n, 1)
        cases.append({"op": "gf_mul", "nbits": n,
                      "args": {"a": v.to_hex(), "b": v.to_hex()},
                      "expect": _capture(lambda v=v: v.gf_mul(v))})
        cases.append({"op": "gf_pow", "nbits": n, "args": {"a": v.to_hex(), "e": 3},
                      "expect": _capture(lambda v=v: v.gf_pow(3))})

    return {
        "$schema": "HerraduraKEx BitArray conformance vectors (TODO #314)",
        "specification": "BITARRAY.md",
        "note": (
            "Pins BITARRAY.md's operation set at widths 32/64/128/256, plus the "
            "mixed-width, invalid-width and no-polynomial cases.  Error cases pin an "
            "expected ERROR CODE, not a value: BITARRAY.md 5 makes the code set closed "
            "and identical in every port, so a port that fails for the right reason is "
            "distinguishable from one that fails for the wrong one.  Operands are "
            "structured rather than pseudo-random -- a rotation or a truncation that "
            "loses an octet is invisible against a uniform operand.  NO PORT IMPLEMENTS "
            "THIS YET: see BITARRAY.md 7 and 8 for how ports join the gating set."
        ),
        "widths": list(WIDTHS),
        "error_codes": list(ERROR_CODES),
        "rnl_kdf_dc_256": f"{RNL_KDF_DC_256:064x}",
        "gf_poly": {str(k): f"0x{v:08x}" for k, v in sorted(GF_POLY.items())},
        "truncation_rule": (
            "HIGH bits -- the big-endian PREFIX (BITARRAY.md 4.4).  This settles the "
            "TODO #313 split: Python and C's declared narrow constants already say high "
            "bits; Go's RnlKdfDC[32-n/8:] is the outlier."
        ),
        "case_count": len(cases),
        "cases": cases,
    }


# ---------------------------------------------------------------------------
# --emit-c-header: bitarray.json transposed into C arrays
#
# The C tree is dependency-free and has no JSON parser, so the C consumer reads
# a GENERATED header instead -- KAT/hcred_kkw_vector.h's precedent (TODO #266).
# A pure deterministic transform of the JSON, so unlike the JSON it IS
# regenerate-and-diff checked: editing one without re-emitting the other fails
# rather than drifting.
# ---------------------------------------------------------------------------

C_HEADER = os.path.join(HERE, "bitarray_vector.h")

_INT_KEYS = ("s", "k", "m", "i", "e", "uint")


def _c_case(c: dict) -> str:
    args = c.get("args", {})
    a = args.get("a") or args.get("hex")
    b = args.get("b")
    ival, has_i = 0, 0
    for key in _INT_KEYS:
        if key in args:
            ival, has_i = int(args[key]), 1
            break
    exp = c["expect"]
    err = exp.get("error")
    def q(x):
        return "NULL" if x is None else '"%s"' % x
    if err:
        res = 'BA_R_ERROR, %s, 0, NULL, 0, 0' % ('"%s"' % err)
    elif "hex" in exp:
        res = 'BA_R_BITS, NULL, %d, %s, 0, 0' % (exp["nbits"], q(exp["hex"]))
    elif "bool" in exp:
        res = 'BA_R_BOOL, NULL, 0, NULL, %d, 0' % (1 if exp["bool"] else 0)
    else:
        res = 'BA_R_INT, NULL, 0, NULL, 0, %d' % int(exp["int"])
    return '    { "%s", %d, %d, %s, %s, %d, %d, %s },' % (
        c["op"], c["nbits"], c.get("mixed_with", 0), q(a), q(b), ival, has_i, res)


def emit_c_header(vectors: dict) -> str:
    out = []
    out.append("/*  KAT/bitarray_vector.h -- GENERATED by KAT/generate_bitarray_kat.py.")
    out.append("    DO NOT EDIT: regenerate with --emit-c-header (or plain generation,")
    out.append("    which emits both).  BITARRAY.md is the specification;")
    out.append("    KAT/bitarray.json is the source this is transposed from, and")
    out.append("    --check verifies the two agree. */")
    out.append("#ifndef HERRADURA_BITARRAY_VECTOR_H")
    out.append("#define HERRADURA_BITARRAY_VECTOR_H")
    out.append("")
    out.append("typedef enum { BA_R_BITS, BA_R_INT, BA_R_BOOL, BA_R_ERROR } BaResultKind;")
    out.append("")
    out.append("typedef struct {")
    out.append("    const char  *op;")
    out.append("    int          nbits;")
    out.append("    int          mixed_with;   /* 0 when the case is single-width */")
    out.append("    const char  *a;            /* hex, or NULL */")
    out.append("    const char  *b;            /* hex, or NULL */")
    out.append("    long long    iarg;")
    out.append("    int          has_iarg;")
    out.append("    BaResultKind kind;")
    out.append("    const char  *want_error;   /* BA_R_ERROR only */")
    out.append("    int          want_nbits;   /* BA_R_BITS only */")
    out.append("    const char  *want_hex;     /* BA_R_BITS only */")
    out.append("    int          want_bool;    /* BA_R_BOOL only */")
    out.append("    long long    want_int;     /* BA_R_INT only */")
    out.append("} BaCase;")
    out.append("")
    out.append("#define BA_VECTOR_CASES %d" % vectors["case_count"])
    out.append("")
    out.append("static const BaCase ba_vector_cases[BA_VECTOR_CASES] = {")
    for c in vectors["cases"]:
        out.append(_c_case(c))
    out.append("};")
    out.append("")
    out.append("#endif /* HERRADURA_BITARRAY_VECTOR_H */")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# --report: which ports are converted, and which gate
#
# _load_python_suite() lived here and is DELETED rather than left: with Python
# converted the report measures nothing in-process, so the loader had no
# caller, and an unreferenced helper beside a check is the shape TODO #305
# deleted from the Go port (a dead rnl_cbd_poly that a manifest row was
# anchored on).
# ---------------------------------------------------------------------------

def report() -> int:
    """Per-port conformance status.  A REPORT, never a gate.

    THIS FLAG HAS RUN OUT OF PORTS TO MEASURE, and saying so is better than
    letting it print rows that duplicate a gate.  Until TODO #314 pass 4 it
    loaded the shipped Python suite and measured it against the contract,
    because Python was unconverted and its divergences were expected and so
    could not be a failing test (CLAUDE.md's Testing section allows none).
    Python is converted now, and its conformance is checked the way C's and
    Go's are: by a consumer that GATES.  Re-measuring it here would assert
    nothing the gate does not already assert, which is #234's vacuous pass
    arriving by way of a report.

    Java is the only port left and this generator cannot introspect it: it is
    a separate toolchain, and running it is what KAT/verify_bitarray_java
    will do when pass 5 lands.  So this prints the gating set and stops.
    """
    print("BitArray conformance status (TODO #314) — BITARRAY.md is the contract.")
    print()
    print("  CONVERTED and GATED, 376/376 each, by their own consumers:")
    print("    c       pass 2, v9.1.0   KAT/verify_bitarray_c.c")
    print("    go      pass 3, v9.2.0   KAT/verify_bitarray_go.go")
    print("    python  pass 4, v9.3.0   KAT/verify_bitarray_py.py")
    print("  All three are run by CliTest/test_kat_vectors.sh.")
    print()
    print("  NOT YET CONVERTED:")
    print("    java    pass 5           BITARRAY.md §8")
    print()
    print("  Three independent implementations against one pinned answer is the")
    print("  cross-implementation check BITARRAY.md §7 describes.  This flag made")
    print("  measurements while an unconverted port could be loaded in-process;")
    print("  Python was the last one, so there is nothing left here to measure and")
    print("  the rows are gone rather than restated.  Java is a separate toolchain")
    print("  and gets a consumer, not a row, at pass 5.")
    return 0


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="verify KAT/bitarray.json is current (gating)")
    ap.add_argument("--report", action="store_true",
                    help="per-port conformance of the shipped ports (not a gate)")
    ap.add_argument("--emit-c-header", action="store_true",
                    help="rebuild KAT/bitarray_vector.h alone")
    args = ap.parse_args()

    if args.report:
        return report()

    vectors = build_vectors()
    text = json.dumps(vectors, indent=2, sort_keys=False) + "\n"
    header = emit_c_header(vectors)

    if args.emit_c_header:
        with open(C_HEADER, "w", encoding="utf-8") as f:
            f.write(header)
        print(f"wrote {os.path.relpath(C_HEADER, ROOT)}")
        return 0

    if args.check:
        if not os.path.exists(OUT):
            print(f"FAIL: {OUT} does not exist; run without --check to generate it.")
            return 1
        with open(OUT, "r", encoding="utf-8") as f:
            have = f.read()
        if have != text:
            print(f"FAIL: {os.path.relpath(OUT, ROOT)} is STALE "
                  f"(regenerate: python3 KAT/generate_bitarray_kat.py)")
            return 1
        if not os.path.exists(C_HEADER):
            print(f"FAIL: {C_HEADER} does not exist; regenerate.")
            return 1
        with open(C_HEADER, "r", encoding="utf-8") as f:
            have_h = f.read()
        if have_h != header:
            print(f"FAIL: {os.path.relpath(C_HEADER, ROOT)} does NOT match "
                  f"bitarray.json (regenerate: python3 KAT/generate_bitarray_kat.py)")
            return 1
        print(f"bitarray.json is up to date ({vectors['case_count']} cases, "
              f"widths {', '.join(map(str, WIDTHS))}).")
        print("bitarray_vector.h matches bitarray.json.")
        return 0

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    with open(C_HEADER, "w", encoding="utf-8") as f:
        f.write(header)
    print(f"wrote {os.path.relpath(OUT, ROOT)} "
          f"({vectors['case_count']} cases, widths {', '.join(map(str, WIDTHS))})")
    print(f"wrote {os.path.relpath(C_HEADER, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
