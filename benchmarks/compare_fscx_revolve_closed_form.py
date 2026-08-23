"""TODO #213: the closed-form FSCX_REVOLVE against the loop it replaced, in all
three implementation languages, on the same hardware.

FSCX_REVOLVE(A, B, i) iterates FSCX i times with B held constant.  Because the
classical FSCX map is affine over GF(2), that telescopes to

    FSCX_REVOLVE(A, B, i) = M^i . A + T_i . B,    T_i = M . S_i,  M = 1 + x + x^(n-1)

in GF(2)[x]/(x^n + 1), and in characteristic 2 every M^(2^u) is still a
three-term polynomial (Frobenius), so the whole evaluation is O(log i)
rotate-XOR steps with no dense polynomial multiplication anywhere.  The
derivation and its bit-exactness proof live in
SecurityProofsCode/fscx_revolve_closed_form.py; this script only measures.

Both paths produce identical bytes — this is an evaluation strategy, not a
protocol change — so the only question is speed, and the answer differs sharply
by language.  See the caveats below before drawing conclusions.

Run:
    python3 benchmarks/compare_fscx_revolve_closed_form.py
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

STEPS = [1, 2, 4, 8, 16, 32, 64, 192, 1024]
DEPLOYED = {64: "i = n/4, encrypt", 192: "r = 3n/4, decrypt"}

CAVEATS = """
Caveats:
  - These are ratios between two implementations of the SAME function in the
    same language, not cross-language comparisons.  A Python microsecond and a C
    microsecond are not the same unit of work; do not read the tables against
    each other.
  - The speedup depends entirely on the step count, which is a public protocol
    parameter.  The deployed counts are i = n/4 = 64 and r = 3n/4 = 192 at
    n = 256; those rows are the ones that matter.
  - The closed form pays a fixed setup cost.  Below a language-specific
    crossover the loop wins, and each implementation falls back to it there
    (C below 8 steps, Go below 2, Python never).  Rows at or under that
    threshold therefore show both paths as the same code.
  - Steps >= n cost LESS than their bit length suggests: once 2^u is a multiple
    of n the stride is 0 and that factor is trivial.  The 1024 row is not a typo.
  - Only classical FSCX_REVOLVE telescopes this way.  The NL-FSCX variants are
    non-linear by construction and remain O(i); nothing here applies to them.
"""

C_HARNESS = r"""
#include <stdio.h>
#include <time.h>
#include "herradura.h"

static void ref_revolve(BitArray *out, const BitArray *a, const BitArray *b, int steps)
{
    BitArray buf[2]; int idx = 0, i;
    buf[0] = *a;
    for (i = 0; i < steps; i++) { ba_fscx(&buf[1-idx], &buf[idx], b); idx ^= 1; }
    *out = buf[idx];
}

static double now(void)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec*1e-9; }

static volatile uint8_t SINK;

int main(void)
{
    BitArray a, b, o; int i, j;
    int steps[] = {1,2,4,8,16,32,64,192,1024};
    unsigned int seed = 7;
    for (i = 0; i < KEYBYTES; i++) {
        seed = seed*1103515245u+12345u; a.b[i] = (uint8_t)(seed>>16);
        seed = seed*1103515245u+12345u; b.b[i] = (uint8_t)(seed>>16);
    }
    for (j = 0; j < 9; j++) {
        int st = steps[j], reps = 2000000 / (st + 8);
        double t0, tl, tc;
        if (reps < 200) reps = 200;
        t0 = now();
        for (i = 0; i < reps; i++) { ref_revolve(&o, &a, &b, st); SINK ^= o.b[0]; }
        tl = (now() - t0) / reps * 1e6;
        t0 = now();
        for (i = 0; i < reps; i++) { ba_fscx_revolve(&o, &a, &b, st); SINK ^= o.b[0]; }
        tc = (now() - t0) / reps * 1e6;
        printf("%d %.6f %.6f\n", st, tl, tc);
    }
    return 0;
}
"""

GO_HARNESS = r"""
package main

import (
	"fmt"
	"math/rand"
	"time"

	"herradurakex/herradura"
)

func refRevolve(a, b *herradura.BitArray, steps int) *herradura.BitArray {
	r := a.Copy()
	for i := 0; i < steps; i++ {
		r = herradura.Fscx(r, b)
	}
	return r
}

func main() {
	rng := rand.New(rand.NewSource(7))
	n := 256
	ab := make([]byte, n/8)
	bb := make([]byte, n/8)
	rng.Read(ab)
	rng.Read(bb)
	a := herradura.NewFromBytes(ab, 0, n)
	b := herradura.NewFromBytes(bb, 0, n)
	var sink byte
	for _, st := range []int{1, 2, 4, 8, 16, 32, 64, 192, 1024} {
		reps := 400000 / (st + 8)
		if reps < 300 {
			reps = 300
		}
		t0 := time.Now()
		for i := 0; i < reps; i++ {
			sink ^= refRevolve(a, b, st).Bytes()[0]
		}
		tl := float64(time.Since(t0).Nanoseconds()) / float64(reps) / 1000
		t0 = time.Now()
		for i := 0; i < reps; i++ {
			sink ^= herradura.FscxRevolve(a, b, st).Bytes()[0]
		}
		tc := float64(time.Since(t0).Nanoseconds()) / float64(reps) / 1000
		fmt.Printf("%d %.6f %.6f\n", st, tl, tc)
	}
	_ = sink
}
"""

GO_MOD = """module fscxbench

go 1.21

require herradurakex v0.0.0

replace herradurakex => {root}
"""


def _table(title, rows):
    print(f"\n{title}")
    print(f"  {'steps':>6} {'loop us':>12} {'closed us':>12} {'speedup':>9}   note")
    for st, tl, tc in rows:
        note = DEPLOYED.get(st, "")
        if st == 1024:
            note = note or "steps >= n: strides collapse"
        print(f"  {st:>6} {tl:>12.4f} {tc:>12.4f} {tl / tc:>8.1f}x   {note}")


def bench_python():
    spec = importlib.util.spec_from_file_location(
        "suite", os.path.join(_ROOT, "Herradura cryptographic suite.py"))
    suite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(suite)

    def loop_revolve(A, B, steps):
        r = A.copy()
        for _ in range(steps):
            r = suite.fscx(r, B)
        return r

    import random
    rng = random.Random(7)
    n = 256
    A = suite.BitArray(n, rng.getrandbits(n))
    B = suite.BitArray(n, rng.getrandbits(n))
    rows = []
    for st in STEPS:
        reps = max(30, min(2000, 40000 // max(st, 1)))
        t0 = time.perf_counter()
        for _ in range(reps):
            loop_revolve(A, B, st)
        tl = (time.perf_counter() - t0) / reps * 1e6
        t0 = time.perf_counter()
        for _ in range(reps):
            suite.fscx_revolve(A, B, st)
        tc = (time.perf_counter() - t0) / reps * 1e6
        rows.append((st, tl, tc))
    _table("Python (suite, big-int BitArray)", rows)


def _parse(out):
    rows = []
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) == 3:
            rows.append((int(parts[0]), float(parts[1]), float(parts[2])))
    return rows


def bench_c(tmp):
    if not shutil.which("gcc"):
        print("\nC: skipped (gcc not found)")
        return
    src = os.path.join(tmp, "cbench.c")
    exe = os.path.join(tmp, "cbench")
    with open(src, "w") as f:
        f.write(C_HARNESS)
    r = subprocess.run(["gcc", "-O2", f"-I{_ROOT}", "-o", exe, src],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"\nC: skipped (build failed)\n{r.stderr[:400]}")
        return
    out = subprocess.run([exe], capture_output=True, text=True).stdout
    _table("C (herradura.h, gcc -O2, byte-array BitArray)", _parse(out))


def bench_go(tmp):
    if not shutil.which("go"):
        print("\nGo: skipped (go not found)")
        return
    d = os.path.join(tmp, "gobench")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "main.go"), "w") as f:
        f.write(GO_HARNESS)
    with open(os.path.join(d, "go.mod"), "w") as f:
        f.write(GO_MOD.replace("{root}", _ROOT))
    r = subprocess.run(["go", "run", "."], cwd=d, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"\nGo: skipped (build failed)\n{r.stderr[:400]}")
        return
    _table("Go (herradura package, big.Int BitArray)", _parse(r.stdout))


def main():
    print(__doc__.strip())
    print(CAVEATS)
    bench_python()
    with tempfile.TemporaryDirectory() as tmp:
        bench_c(tmp)
        bench_go(tmp)
    print("\nBoth paths are bit-identical; see"
          " SecurityProofsCode/fscx_revolve_closed_form.py for the proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
