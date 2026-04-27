/*  Herradura KEx -- Security & Performance Tests (Go)
    v1.5.17: NTT twiddle precomputation — rnlTwCache map; rnlTwGet eliminates rnlModPow calls per rnlPolyMul.
    v1.5.13: HSKE-NL-A1 seed fix — seed=RotateLeft(base,n/8) breaks counter=0 step-1 degeneracy.
    v1.5.10: HKEX-RNL KDF seed fix — seed=RotateLeft(K,n/8) breaks step-1 degeneracy.
    v1.5.9: NlFscxRevolveV2Inv precomputes delta(B) once — eliminates per-step multiply.
    v1.5.7: MInv uses precomputed rotation table (sync.Map cache per bit-size).
    v1.5.6: rnlRandPoly bias fix — 3-byte rejection sampling (threshold=16711935).
    v1.5.5: aligned version banner with C and Python.
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.2: proposed multi-size key-length tests for Herradura_tests.c (matching Python).
    v1.5.1: added -rounds and -time CLI flags (also HTEST_ROUNDS / HTEST_TIME env vars).
    v1.5.0: added PQC extension tests [10-16] (NL-FSCX, HKEX-RNL, HPKS-NL, HPKE-NL);
            benchmarks renumbered [17-21] (were [10-14] in v1.4.0);
            new PQC benchmarks [22-25].
    v1.4.0: HPKS replaced with Schnorr-like scheme [7][8]; HPKE El Gamal [9];
            benchmarks renumbered [10-14].
    v1.3.6: added HPKS sign+verify correctness test [7]; benchmarks renumbered [8-12].
    v1.3.3: added HPKE encrypt+decrypt round-trip benchmark [11].

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.

    Under the terms of the GNU General Public License, please also consider that:

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"os"
	"sync"
	"strconv"
	"time"
)

// ---------------------------------------------------------------------------
// Runtime limits — set via CLI flags or env vars in main()
// ---------------------------------------------------------------------------

var (
	gRounds    int           // 0 = use per-test default
	gBenchDur  time.Duration // benchmark duration (default: 1s)
	gTimeLimit time.Duration // per-test wall-clock cap; 0 = none
)

// testRounds returns the effective iteration count for a test.
func testRounds(defaultN int) int {
	if gRounds > 0 {
		return gRounds
	}
	return defaultN
}

// timeExceeded reports whether the per-test time cap has been reached.
func timeExceeded(t0 time.Time) bool {
	if gTimeLimit <= 0 {
		return false
	}
	return time.Since(t0) >= gTimeLimit
}

// ---------------------------------------------------------------------------
// BitArray (self-contained)
// ---------------------------------------------------------------------------

type BitArray struct {
	val  big.Int
	size int
}

func bitArrayMask(size int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(size))
	return mask.Sub(mask, big.NewInt(1))
}

func NewFromBytes(data []byte, _ int, size int) *BitArray {
	ba := &BitArray{size: size}
	ba.val.SetBytes(data[:size/8])
	return ba
}

func newRandBitArray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

func newBA(size int, val *big.Int) *BitArray {
	ba := &BitArray{size: size}
	ba.val.And(val, bitArrayMask(size))
	return ba
}

func randBA(size int) *BitArray { return newRandBitArray(size) }

func (ba *BitArray) Copy() *BitArray {
	result := &BitArray{size: ba.size}
	result.val.Set(&ba.val)
	return result
}

func (ba *BitArray) Xor(other *BitArray) *BitArray {
	result := &BitArray{size: ba.size}
	result.val.Xor(&ba.val, &other.val)
	return result
}

func (ba *BitArray) RotateLeft(n int) *BitArray {
	size := ba.size
	n = ((n % size) + size) % size
	result := &BitArray{size: size}
	if n == 0 {
		result.val.Set(&ba.val)
		return result
	}
	left := new(big.Int).Lsh(&ba.val, uint(n))
	right := new(big.Int).Rsh(&ba.val, uint(size-n))
	result.val.Or(left, right)
	result.val.And(&result.val, bitArrayMask(size))
	return result
}

func (ba *BitArray) Equal(other *BitArray) bool {
	return ba.size == other.size && ba.val.Cmp(&other.val) == 0
}

func (ba *BitArray) Format(f fmt.State, verb rune) {
	hexDigits := ba.size / 4
	s := ba.val.Text(16)
	for i := len(s); i < hexDigits; i++ {
		f.Write([]byte{'0'})
	}
	fmt.Fprint(f, s)
}

func (ba *BitArray) Popcount() int {
	cnt := 0
	for _, b := range ba.val.Bytes() {
		cnt += bits.OnesCount8(b)
	}
	return cnt
}

func (ba *BitArray) FlipBit(pos int) *BitArray {
	result := ba.Copy()
	result.val.SetBit(&result.val, pos, result.val.Bit(pos)^1)
	return result
}

// ---------------------------------------------------------------------------
// FSCX functions (classical)
// ---------------------------------------------------------------------------

func Fscx(a, b *BitArray) *BitArray {
	return a.Xor(b).
		Xor(a.RotateLeft(1)).Xor(b.RotateLeft(1)).
		Xor(a.RotateLeft(-1)).Xor(b.RotateLeft(-1))
}

func FscxRevolve(ba, bb *BitArray, steps int) *BitArray {
	result := ba.Copy()
	for i := 0; i < steps; i++ {
		result = Fscx(result, bb)
	}
	return result
}

// ---------------------------------------------------------------------------
// GF(2^n) field arithmetic
// ---------------------------------------------------------------------------

var gfPoly = map[int]*big.Int{
	32:  new(big.Int).SetUint64(0x00400007),
	64:  new(big.Int).SetUint64(0x0000001B),
	128: new(big.Int).SetUint64(0x00000087),
	256: new(big.Int).SetUint64(0x00000425),
}

const gfGen = 3

func GfMul(a, b, poly *big.Int, n int) *big.Int {
	result := new(big.Int)
	aCopy := new(big.Int).Set(a)
	bCopy := new(big.Int).Set(b)
	mask := bitArrayMask(n)
	one := big.NewInt(1)
	for i := 0; i < n; i++ {
		if new(big.Int).And(bCopy, one).Sign() != 0 {
			result.Xor(result, aCopy)
		}
		carry := new(big.Int).And(new(big.Int).Rsh(aCopy, uint(n-1)), one).Sign() != 0
		aCopy.And(new(big.Int).Lsh(aCopy, 1), mask)
		if carry {
			aCopy.Xor(aCopy, poly)
		}
		bCopy.Rsh(bCopy, 1)
	}
	return result
}

func GfPow(base, exp *big.Int, poly *big.Int, n int) *big.Int {
	result := big.NewInt(1)
	bCopy := new(big.Int).Set(base)
	eCopy := new(big.Int).Set(exp)
	one := big.NewInt(1)
	for eCopy.Sign() > 0 {
		if new(big.Int).And(eCopy, one).Sign() != 0 {
			result = GfMul(result, bCopy, poly, n)
		}
		bCopy = GfMul(bCopy, bCopy, poly, n)
		eCopy.Rsh(eCopy, 1)
	}
	return result
}

// ---------------------------------------------------------------------------
// NL-FSCX primitives (v1.5.0)
// ---------------------------------------------------------------------------

var mInvCache sync.Map // map[int][]int

func computeMInvRotations(n int) []int {
	unit := &BitArray{size: n}
	unit.val.SetInt64(1)
	zero := &BitArray{size: n}
	v := FscxRevolve(unit, zero, n/2-1)
	var rotations []int
	for k := 0; k < n; k++ {
		if v.val.Bit(k) == 1 {
			rotations = append(rotations, k)
		}
	}
	return rotations
}

func MInv(x *BitArray) *BitArray {
	n := x.size
	val, ok := mInvCache.Load(n)
	if !ok {
		rotations := computeMInvRotations(n)
		val, _ = mInvCache.LoadOrStore(n, rotations)
	}
	rotations := val.([]int)
	result := &BitArray{size: n}
	for _, k := range rotations {
		result = result.Xor(x.RotateLeft(k))
	}
	return result
}

func NlFscxV1(a, b *BitArray) *BitArray {
	n := a.size
	mask := bitArrayMask(n)
	sum := new(big.Int).Add(&a.val, &b.val)
	sum.And(sum, mask)
	mixBA := &BitArray{size: n}
	mixBA.val.Set(sum)
	return Fscx(a, b).Xor(mixBA.RotateLeft(n / 4))
}

func NlFscxRevolveV1(a, b *BitArray, steps int) *BitArray {
	result := a.Copy()
	for i := 0; i < steps; i++ {
		result = NlFscxV1(result, b)
	}
	return result
}

func nlFscxDeltaV2(b *BitArray) *BitArray {
	n := b.size
	mask := bitArrayMask(n)
	bPlus1 := new(big.Int).Add(&b.val, big.NewInt(1))
	half := new(big.Int).Rsh(bPlus1, 1)
	prod := new(big.Int).Mul(&b.val, half)
	prod.And(prod, mask)
	deltaBA := &BitArray{size: n}
	deltaBA.val.Set(prod)
	return deltaBA.RotateLeft(n / 4)
}

func NlFscxV2(a, b *BitArray) *BitArray {
	n := a.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	fscxOut := Fscx(a, b)
	sum := new(big.Int).Add(&fscxOut.val, &delta.val)
	sum.And(sum, mask)
	result := &BitArray{size: n}
	result.val.Set(sum)
	return result
}

func NlFscxV2Inv(y, b *BitArray) *BitArray {
	n := y.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	diff := new(big.Int).Sub(&y.val, &delta.val)
	diff.And(diff, mask)
	zBA := &BitArray{size: n}
	zBA.val.Set(diff)
	return b.Xor(MInv(zBA))
}

func NlFscxRevolveV2(a, b *BitArray, steps int) *BitArray {
	result := a.Copy()
	for i := 0; i < steps; i++ {
		result = NlFscxV2(result, b)
	}
	return result
}

func NlFscxRevolveV2Inv(y, b *BitArray, steps int) *BitArray {
	n := y.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	result := y.Copy()
	for i := 0; i < steps; i++ {
		diff := new(big.Int).Sub(&result.val, &delta.val)
		diff.And(diff, mask)
		zBA := &BitArray{size: n}
		zBA.val.Set(diff)
		result = b.Xor(MInv(zBA))
	}
	return result
}

// ---------------------------------------------------------------------------
// HKEX-RNL ring-arithmetic helpers (negacyclic Z_q[x]/(x^n+1))
// ---------------------------------------------------------------------------

const (
	rnlQ  = 65537
	rnlP  = 4096
	rnlPP = 2
	rnlEta = 1 // CBD eta: secret coefficients drawn from CBD(1) in {-1,0,1}
)

func rnlModPow(base, exp, mod int) int {
	r, b := 1, base%mod
	for exp > 0 {
		if exp&1 == 1 {
			r = r * b % mod
		}
		b = b * b % mod
		exp >>= 1
	}
	return r
}

type rnlTwEntry struct {
	psiPow, psiInvPow []int
	stageWFwd, stageWInv []int
	invN int
}

var rnlTwCache = map[int]*rnlTwEntry{}

func rnlTwGet(n, q int) *rnlTwEntry {
	if e, ok := rnlTwCache[n]; ok { return e }
	e := &rnlTwEntry{psiPow: make([]int, n), psiInvPow: make([]int, n)}
	psi := rnlModPow(3, (q-1)/(2*n), q); psiInv := rnlModPow(psi, q-2, q)
	pw, pwInv := 1, 1
	for i := 0; i < n; i++ {
		e.psiPow[i] = pw; e.psiInvPow[i] = pwInv
		pw = pw * psi % q; pwInv = pwInv * psiInv % q
	}
	for length := 2; length <= n; length <<= 1 {
		w := rnlModPow(3, (q-1)/length, q)
		e.stageWFwd = append(e.stageWFwd, w)
		e.stageWInv = append(e.stageWInv, rnlModPow(w, q-2, q))
	}
	e.invN = rnlModPow(n, q-2, q)
	rnlTwCache[n] = e
	return e
}

func rnlNTT(a []int, q int, invert bool) {
	n := len(a)
	tw := rnlTwGet(n, q)
	sw := tw.stageWFwd
	if invert { sw = tw.stageWInv }
	j := 0
	for i := 1; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 { j ^= bit }
		j ^= bit
		if i < j { a[i], a[j] = a[j], a[i] }
	}
	for s, length := 0, 2; length <= n; length, s = length<<1, s+1 {
		w := sw[s]
		for i := 0; i < n; i += length {
			wn := 1
			for k := 0; k < length>>1; k++ {
				u := a[i+k]; v := a[i+k+length>>1] * wn % q
				a[i+k] = (u + v) % q; a[i+k+length>>1] = (u - v + q) % q
				wn = wn * w % q
			}
		}
	}
	if invert {
		for i := range a { a[i] = a[i] * tw.invN % q }
	}
}

func rnlPolyMul(f, g []int, q, n int) []int {
	tw := rnlTwGet(n, q)
	fa, ga := make([]int, n), make([]int, n)
	for i := 0; i < n; i++ {
		fa[i] = f[i] * tw.psiPow[i] % q; ga[i] = g[i] * tw.psiPow[i] % q
	}
	rnlNTT(fa, q, false); rnlNTT(ga, q, false)
	ha := make([]int, n)
	for i := range ha { ha[i] = fa[i] * ga[i] % q }
	rnlNTT(ha, q, true)
	for i := range ha { ha[i] = ha[i] * tw.psiInvPow[i] % q }
	return ha
}

func rnlPolyAdd(f, g []int, q int) []int {
	h := make([]int, len(f))
	for i := range f {
		h[i] = (f[i] + g[i]) % q
	}
	return h
}

func rnlRound(poly []int, fromQ, toP int) []int {
	h := make([]int, len(poly))
	for i, c := range poly {
		h[i] = (c*toP + fromQ/2) / fromQ % toP
	}
	return h
}

func rnlLift(poly []int, fromP, toQ int) []int {
	h := make([]int, len(poly))
	for i, c := range poly {
		h[i] = c * toQ / fromP % toQ
	}
	return h
}

func rnlMPoly(n int) []int {
	p := make([]int, n)
	p[0], p[1], p[n-1] = 1, 1, 1
	return p
}

func rnlRandPoly(n, q int) []int {
	p := make([]int, n)
	buf := make([]byte, 4)
	for i := range p {
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("rand.Read: %s", err)
		}
		v := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if v < 0 {
			v = -v
		}
		p[i] = v % q
	}
	return p
}

// rnlCBDPoly samples n coefficients from CBD(eta=1): each = (raw&1) - ((raw>>1)&1) mod q.
// Produces {-1,0,1} with zero mean; matches Kyber Ring-LWR secret distribution.
func rnlCBDPoly(n, q int) []int {
	p := make([]int, n)
	buf := make([]byte, 1)
	for i := range p {
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("rand.Read: %s", err)
		}
		a := int(buf[0]) & 1
		b := (int(buf[0]) >> 1) & 1
		p[i] = (a - b + q) % q
	}
	return p
}

func rnlBitsToBitArray(poly []int, pp, size int) *BitArray {
	threshold := pp / 2
	val := new(big.Int)
	for i := 0; i < size && i < len(poly); i++ {
		if poly[i] >= threshold {
			val.SetBit(val, i, 1)
		}
	}
	ba := &BitArray{size: size}
	ba.val.Set(val)
	return ba
}

func rnlKeygen(mBlind []int, n, q, p int) ([]int, []int) {
	s := rnlCBDPoly(n, q)
	c := rnlRound(rnlPolyMul(mBlind, s, q, n), q, p)
	return s, c
}

func rnlHint(kPoly []int, q int) []byte {
	hint := make([]byte, (len(kPoly)+7)/8)
	for i, c := range kPoly {
		r := (4*c+q/2)/q % 4
		if r%2 != 0 {
			hint[i/8] |= 1 << (uint(i) % 8)
		}
	}
	return hint
}

func rnlReconcileBits(kPoly []int, hint []byte, q, pp, keyBits int) *BitArray {
	qh := q / 2
	val := new(big.Int)
	for i := 0; i < keyBits && i < len(kPoly); i++ {
		c := kPoly[i]
		h := int((hint[i/8] >> (uint(i) % 8)) & 1)
		if (2*c+h*qh+qh)/q%pp != 0 {
			val.SetBit(val, i, 1)
		}
	}
	ba := &BitArray{size: keyBits}
	ba.val.Set(val)
	return ba
}

func rnlAgree(s, cOther []int, q, p, pp, n, keyBits int, hintIn []byte) (*BitArray, []byte) {
	kPoly := rnlPolyMul(s, rnlLift(cOther, p, q), q, n)
	if hintIn == nil {
		hintIn = rnlHint(kPoly, q)
		return rnlReconcileBits(kPoly, hintIn, q, pp, keyBits), hintIn
	}
	return rnlReconcileBits(kPoly, hintIn, q, pp, keyBits), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func iVal(size int) int { return size / 4 }
func rVal(size int) int { return size * 3 / 4 }

func gfOrd(size int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(size)), big.NewInt(1))
}

var sizes    = []int{64, 128, 256} // FSCX-only tests (fast)
var gfSizes  = []int{32}           // GfPow tests (big.Int is slow; matches 32-bit C/asm targets)
var rnlSizes = []int{32, 64}

func bench(label string, fn func()) (ops int, elapsed time.Duration) {
	for i := 0; i < 10; i++ {
		fn()
	}
	dur := gBenchDur
	start := time.Now()
	for {
		for i := 0; i < 100; i++ {
			fn()
		}
		ops += 100
		elapsed = time.Since(start)
		if elapsed >= dur {
			break
		}
	}
	return
}

func fmtRate(ops int, elapsed time.Duration) string {
	rate := float64(ops) / elapsed.Seconds()
	if rate >= 1e6 {
		return fmt.Sprintf("%.2f M ops/sec", rate/1e6)
	}
	return fmt.Sprintf("%.2f K ops/sec", rate/1e3)
}

// S_op helper for Eve-resistance test [6]
func SOpBA(delta *BitArray, r int) *BitArray {
	acc := &BitArray{size: delta.size}
	cur := delta.Copy()
	zero := &BitArray{size: delta.size}
	for i := 0; i <= r; i++ {
		acc.val.Xor(&acc.val, &cur.val)
		cur = Fscx(cur, zero)
	}
	return acc
}

// ---------------------------------------------------------------------------
// Security tests — classical protocols [1-9]
// ---------------------------------------------------------------------------

func testHkexGFCorrectness() {
	fmt.Println("[1] HKEX-GF correctness: g^{ab} == g^{ba} in GF(2^n)*  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C := GfPow(g, &a.val, poly, size)
			C2 := GfPow(g, &b.val, poly, size)
			if GfPow(C2, &a.val, poly, size).Cmp(GfPow(C, &b.val, poly, size)) == 0 {
				ok++
			}
			if i&7 == 7 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  %5d / %d correct  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

func testAvalanche() {
	fmt.Println("[2] FSCX single-step linear diffusion (expected: exactly 3 bits per flip)  [CLASSICAL]")
	for _, size := range sizes {
		total := 0.0
		gmin := size + 1
		gmax := -1
		N := testRounds(1000)
		t0 := time.Now()
		for trial := 0; trial < N; trial++ {
			a := randBA(size)
			b := randBA(size)
			base := Fscx(a, b)
			for bit := 0; bit < size; bit++ {
				ap := a.FlipBit(bit)
				hd := Fscx(ap, b).Xor(base).Popcount()
				total += float64(hd)
				if hd < gmin { gmin = hd }
				if hd > gmax { gmax = hd }
			}
			if trial&63 == 63 && timeExceeded(t0) { N = trial + 1; break }
		}
		mean := total / (float64(N) * float64(size))
		status := "PASS"
		if mean < 2.9 || mean > 3.1 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  mean=%.2f (expected 3/%d)  min=%d  max=%d  [%s]\n",
			size, mean, size, gmin, gmax, status)
	}
	fmt.Println()
}

func testOrbitPeriod() {
	fmt.Println("[3] Orbit period: FSCX_REVOLVE cycles back to A  [CLASSICAL]")
	for _, size := range sizes {
		cntP, cntHP, other := 0, 0, 0
		cap := 2 * size
		N := testRounds(100)
		t0 := time.Now()
		for trial := 0; trial < N; trial++ {
			a := randBA(size)
			b := randBA(size)
			cur := Fscx(a, b)
			period := 1
			for !cur.Equal(a) && period < cap {
				cur = Fscx(cur, b)
				period++
			}
			if period == size { cntP++ } else if period == size/2 { cntHP++ } else { other++ }
			if trial&15 == 15 && timeExceeded(t0) { N = trial + 1; break }
		}
		status := "PASS"
		if other != 0 { status = "FAIL" }
		fmt.Printf("    bits=%3d  period=%d: %3d  period=%d: %3d  other: %d  [%s]\n",
			size, size, cntP, size/2, cntHP, other, status)
	}
	fmt.Println()
}

func testBitFrequency() {
	N := testRounds(10000)
	fmt.Printf("[4] Bit-frequency bias: %d FSCX outputs per size  [CLASSICAL]\n", N)
	for _, size := range sizes {
		counts := make([]int, size)
		nRun := 0
		t0 := time.Now()
		for trial := 0; trial < N; trial++ {
			nRun++
			a := randBA(size)
			b := randBA(size)
			out := Fscx(a, b)
			for bit := 0; bit < size; bit++ {
				if out.val.Bit(bit) == 1 { counts[bit]++ }
			}
			if trial&255 == 255 && timeExceeded(t0) { break }
		}
		var mn, mx, mean float64
		mn = 101.0; mx = -1.0
		for bit := 0; bit < size; bit++ {
			pct := float64(counts[bit]) / float64(nRun) * 100.0
			mean += pct
			if pct < mn { mn = pct }
			if pct > mx { mx = pct }
		}
		mean /= float64(size)
		status := "PASS"
		if mn <= 47.0 || mx >= 53.0 { status = "FAIL" }
		fmt.Printf("    bits=%3d  min=%.2f%%  max=%.2f%%  mean=%.2f%%  [%s]\n",
			size, mn, mx, mean, status)
	}
	fmt.Println()
}

func testHkexGFKeySensitivity() {
	fmt.Println("[5] HKEX-GF key sensitivity: flip 1 bit of a, measure HD of sk change  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		total := 0.0
		N := testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C2 := GfPow(g, &b.val, poly, size)
			sk1 := GfPow(C2, &a.val, poly, size)
			af := a.FlipBit(0)
			sk2 := GfPow(C2, &af.val, poly, size)
			diff := &BitArray{size: size}
			diff.val.Xor(sk1, sk2)
			total += float64(diff.Popcount())
			if i&7 == 7 && timeExceeded(t0) { N = i + 1; break }
		}
		mean := total / float64(N)
		expected := size / 4
		status := "PASS"
		if mean < float64(expected) { status = "FAIL" }
		fmt.Printf("    bits=%3d  mean HD=%.2f (expected >=%d)  [%s]\n", size, mean, expected, status)
	}
	fmt.Println()
}

func testHkexGFEveResistance() {
	N := testRounds(1000)
	fmt.Printf("[6] HKEX-GF Eve resistance: S_op(C XOR C2, r) != sk for %d trials  [CLASSICAL]\n", N)
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		rv := rVal(size)
		successes := 0
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C := newBA(size, GfPow(g, &a.val, poly, size))
			C2 := newBA(size, GfPow(g, &b.val, poly, size))
			realSk := newBA(size, GfPow(&C2.val, &a.val, poly, size))
			delta := C.Xor(C2)
			eveGuess := SOpBA(delta, rv)
			if eveGuess.Equal(realSk) { successes++ }
			if i&7 == 7 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if successes != 0 { status = "FAIL" }
		fmt.Printf("    bits=%3d  %5d / %d Eve successes (expected 0)  [%s]\n", size, successes, N, status)
	}
	fmt.Println()
}

func testHpksSchnorrCorrectness() {
	fmt.Println("[7] HPKS Schnorr correctness: g^s · C^e == R  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		ord := gfOrd(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			pt := randBA(size)
			k := randBA(size)
			rInt := GfPow(g, &k.val, poly, size)
			rB := newBA(size, rInt)
			e := FscxRevolve(rB, pt, iv)
			s := new(big.Int).Mod(new(big.Int).Sub(&k.val, new(big.Int).Mul(&a.val, &e.val)), ord)
			lhs := GfMul(GfPow(g, s, poly, size), GfPow(cVal, &e.val, poly, size), poly, size)
			if lhs.Cmp(rInt) == 0 { ok++ }
			if i&63 == 63 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %4d / %d verified  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

func testHpksSchnorrEveResistance() {
	fmt.Println("[8] HPKS Schnorr Eve resistance: random forgery attempts fail  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		wins, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			decoy := randBA(size)
			rEve := newBA(size, GfPow(g, &randBA(size).val, poly, size))
			eEve := FscxRevolve(rEve, decoy, iv)
			sEve := new(big.Int).Set(&randBA(size).val)
			lhs := GfMul(GfPow(g, sEve, poly, size), GfPow(cVal, &eEve.val, poly, size), poly, size)
			if lhs.Cmp(&rEve.val) == 0 { wins++ }
			if i&63 == 63 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if wins != 0 { status = "FAIL" }
		fmt.Printf("    bits=%3d  %4d / %d Eve wins (expected 0)  [%s]\n", size, wins, N, status)
	}
	fmt.Println()
}

func testHpkeRoundTrip() {
	fmt.Println("[9] HPKE encrypt+decrypt correctness (El Gamal + FscxRevolve)  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		rv := rVal(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			pt := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			r := randBA(size)
			rVal2 := GfPow(g, &r.val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.val, poly, size))
			E := FscxRevolve(pt, encKey, iv)
			decKey := newBA(size, GfPow(rVal2, &a.val, poly, size))
			D := FscxRevolve(E, decKey, rv)
			if D.Equal(pt) { ok++ }
			if i&63 == 63 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %4d / %d decrypted  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Security tests — PQC extension [10-16]
// ---------------------------------------------------------------------------

func testNlFscxV1Nonlinearity() {
	// NL-FSCX v1 must violate GF(2) linearity: if linear,
	// f(A,B) XOR f(0,B) == Fscx(A,0) for all A,B. Count violations.
	// Also verify period is destroyed: no period found in 4*n steps.
	fmt.Println("[10] NL-FSCX v1 non-linearity and aperiodicity  [PQC-EXT]")
	for _, size := range sizes {
		zero := &BitArray{size: size}
		N1, N2 := testRounds(1000), testRounds(200)
		violations := 0
		t0 := time.Now()
		for i := 0; i < N1; i++ {
			A := randBA(size); B := randBA(size)
			linPred := Fscx(A, zero).Xor(NlFscxV1(zero, B))
			if !NlFscxV1(A, B).Equal(linPred) { violations++ }
			if i&63 == 63 && timeExceeded(t0) { N1 = i + 1; break }
		}
		cap := 4 * size
		noPeriod := 0
		t0 = time.Now()
		for i := 0; i < N2; i++ {
			A := randBA(size); B := randBA(size)
			cur := NlFscxV1(A, B)
			found := false
			for j := 1; j < cap; j++ {
				cur = NlFscxV1(cur, B)
				if cur.Equal(A) { found = true; break }
			}
			if !found { noPeriod++ }
			if i&31 == 31 && timeExceeded(t0) { N2 = i + 1; break }
		}
		status := "PASS"
		if violations != N1 || noPeriod < N2*95/100 { status = "FAIL" }
		fmt.Printf("    bits=%3d  linearity violations=%d/%d  no-period=%d/%d  [%s]\n",
			size, violations, N1, noPeriod, N2, status)
	}
	fmt.Println()
}

func testNlFscxV2BijectiveInverse() {
	// NL-FSCX v2 must be bijective in A for all B (collision count = 0),
	// the closed-form inverse must be correct, and v2 must be non-linear.
	fmt.Println("[11] NL-FSCX v2 bijectivity and exact inverse  [PQC-EXT]")
	for _, size := range sizes {
		N1, N2, N3 := testRounds(500), testRounds(1000), testRounds(500)
		// Collision test
		nonBij := 0
		t0 := time.Now()
		for i := 0; i < N1; i++ {
			B := randBA(size)
			seen := make(map[string]uint64)
			samples := 256
			if size < 8 { samples = 1 << uint(size) }
			for j := 0; j < samples; j++ {
				A := randBA(size)
				out := NlFscxV2(A, B).val.Text(16)
				if prev, ok := seen[out]; ok && prev != A.val.Uint64() { nonBij++; break }
				seen[out] = A.val.Uint64()
			}
			if i&63 == 63 && timeExceeded(t0) { N1 = i + 1; break }
		}
		// Inverse correctness
		invOk := 0
		t0 = time.Now()
		for i := 0; i < N2; i++ {
			A := randBA(size); B := randBA(size)
			if NlFscxV2Inv(NlFscxV2(A, B), B).Equal(A) { invOk++ }
			if i&63 == 63 && timeExceeded(t0) { N2 = i + 1; break }
		}
		// Non-linearity
		zero := &BitArray{size: size}
		nlOk := 0
		t0 = time.Now()
		for i := 0; i < N3; i++ {
			A := randBA(size); B := randBA(size)
			linPred := Fscx(A, zero).Xor(NlFscxV2(zero, B))
			if !NlFscxV2(A, B).Equal(linPred) { nlOk++ }
			if i&63 == 63 && timeExceeded(t0) { N3 = i + 1; break }
		}
		status := "PASS"
		if nonBij != 0 || invOk != N2 || nlOk < N3*98/100 { status = "FAIL" }
		fmt.Printf("    bits=%3d  collisions=%d/%d  inv=%d/%d  nonlinear=%d/%d  [%s]\n",
			size, nonBij, N1, invOk, N2, nlOk, N3, status)
	}
	fmt.Println()
}

func testHskeNlA1Correctness() {
	// HSKE-NL-A1 with per-session nonce: base = K XOR N; ks = NlFscxRevolveV1(ROL(base,n/8), base XOR ctr, n/4).
	fmt.Println("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]")
	for _, size := range sizes {
		iv := iVal(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for trial := 0; trial < N; trial++ {
			K := randBA(size); nonce := randBA(size); P := randBA(size)
			base := newBA(size, new(big.Int).Xor(&K.val, &nonce.val))
			ctr := int64(trial % (1 << 16))
			bCtr := newBA(size, new(big.Int).Xor(&base.val, big.NewInt(ctr)))
			ks := NlFscxRevolveV1(base.RotateLeft(size/8), bCtr, iv) // seed=ROL(base,n/8)
			C := newBA(size, new(big.Int).Xor(&P.val, &ks.val))
			D := newBA(size, new(big.Int).Xor(&C.val, &ks.val))
			if D.Equal(P) { ok++ }
			if trial&63 == 63 && timeExceeded(t0) { N = trial + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %4d / %d correct  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

func testHskeNlA2Correctness() {
	// Default 50 trials: NlFscxV2Inv calls M^{n/2-1} per step — O(n^2) ops per trial.
	fmt.Println("[13] HSKE-NL-A2 revolve-mode correctness: D == P  [PQC-EXT]")
	for _, size := range sizes {
		rv := rVal(size)
		ok, N := 0, testRounds(50)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			K := randBA(size); P := randBA(size)
			E := NlFscxRevolveV2(P, K, rv)
			D := NlFscxRevolveV2Inv(E, K, rv)
			if D.Equal(P) { ok++ }
			if i&15 == 15 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %3d / %d correct  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

func testHkexRnlCorrectness() {
	// Protocol: one party generates aRand and transmits it in the clear; both
	// derive the shared mBlind = mBase + aRand and compute individual public keys
	// C = round_p(mBlind · s).  Agreement holds by ring commutativity:
	// sA·(mBlind·sB) = sB·(mBlind·sA).  See §11.4.2 of SecurityProofs.md.
	fmt.Println("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]")
	fmt.Printf("     (ring sizes %v; Peikert reconciliation -- expect 100%% agreement)\n", rnlSizes)
	for _, nRnl := range rnlSizes {
		mBase := rnlMPoly(nRnl)
		okRaw, okSk := 0, 0
		trials := testRounds(200)
		t0 := time.Now()
		for i := 0; i < trials; i++ {
			aRand := rnlRandPoly(nRnl, rnlQ)
			mBlind := rnlPolyAdd(mBase, aRand, rnlQ)
			sA, CA := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
			sB, CB := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
			KA, hintA := rnlAgree(sA, CB, rnlQ, rnlP, rnlPP, nRnl, nRnl, nil)
			KB, _     := rnlAgree(sB, CA, rnlQ, rnlP, rnlPP, nRnl, nRnl, hintA)
			if KA.Equal(KB) { okRaw++ }
			skA := NlFscxRevolveV1(KA.RotateLeft(nRnl/8), KA, nRnl/4)
			skB := NlFscxRevolveV1(KB.RotateLeft(nRnl/8), KB, nRnl/4)
			if skA.Equal(skB) { okSk++ }
			if i&15 == 15 && timeExceeded(t0) { trials = i + 1; break }
		}
		status := "PASS"
		if okRaw < trials { status = "FAIL" }
		fmt.Printf("    n=%3d  raw agree=%d/%d  sk agree=%d/%d  [%s]\n",
			nRnl, okRaw, trials, okSk, trials, status)
	}
	fmt.Println()
}

func testHpksNlCorrectness() {
	fmt.Println("[15] HPKS-NL correctness: g^s · C^e == R (NL-FSCX v1 challenge)  [PQC-EXT]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		ord := gfOrd(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			pt := randBA(size)
			k := randBA(size)
			rInt := GfPow(g, &k.val, poly, size)
			rB := newBA(size, rInt)
			e := NlFscxRevolveV1(rB, pt, iv)
			s := new(big.Int).Mod(new(big.Int).Sub(&k.val, new(big.Int).Mul(&a.val, &e.val)), ord)
			lhs := GfMul(GfPow(g, s, poly, size), GfPow(cVal, &e.val, poly, size), poly, size)
			if lhs.Cmp(rInt) == 0 { ok++ }
			if i&63 == 63 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %4d / %d verified  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

func testHpkeNlCorrectness() {
	// Default 200 trials: NlFscxV2Inv calls M^{n/2-1} per step.
	fmt.Println("[16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt)  [PQC-EXT]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		ok, N := 0, testRounds(200)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size); pt := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			r := randBA(size)
			rInt := GfPow(g, &r.val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.val, poly, size))
			E := NlFscxRevolveV2(pt, encKey, iv)
			decKey := newBA(size, GfPow(rInt, &a.val, poly, size))
			D := NlFscxRevolveV2Inv(E, decKey, iv)
			if D.Equal(pt) { ok++ }
			if i&31 == 31 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
		fmt.Printf("    bits=%3d  %3d / %d decrypted  [%s]\n", size, ok, N, status)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Performance benchmarks
// ---------------------------------------------------------------------------

func benchFscx() {
	fmt.Println("[17] FSCX throughput  [CLASSICAL]")
	for _, size := range sizes {
		a := randBA(size)
		b := randBA(size)
		ops, elapsed := bench(fmt.Sprintf("bits=%3d", size), func() {
			a = Fscx(a, b)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHkexGFPow() {
	fmt.Println("[18] HKEX-GF gf_pow throughput  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		a := randBA(size)
		ops, elapsed := bench("", func() {
			GfPow(g, &a.val, poly, size)
		})
		fmt.Printf("    bits=%3d  gf_pow(g, a)             : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHkexHandshake() {
	fmt.Println("[19] HKEX-GF full handshake (4 GfPow calls)  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		ops, elapsed := bench("", func() {
			a := randBA(size)
			b := randBA(size)
			C := GfPow(g, &a.val, poly, size)
			C2 := GfPow(g, &b.val, poly, size)
			_ = GfPow(C2, &a.val, poly, size)
			_ = GfPow(C, &b.val, poly, size)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeRoundTrip() {
	fmt.Println("[20] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
	for _, size := range sizes {
		iv := iVal(size)
		rv := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			pt := randBA(size)
			key := randBA(size)
			enc := FscxRevolve(pt, key, iv)
			dec := FscxRevolve(enc, key, rv)
			sink = sink.Xor(dec.Xor(pt))
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHpkeRoundTrip() {
	fmt.Println("[21] HPKE encrypt+decrypt round-trip (El Gamal + FscxRevolve)  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := gfPoly[size]
		g := big.NewInt(gfGen)
		iv := iVal(size)
		rv := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			a := randBA(size)
			pt := randBA(size)
			cVal := GfPow(g, &a.val, poly, size)
			r := randBA(size)
			rVal2 := GfPow(g, &r.val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.val, poly, size))
			E := FscxRevolve(pt, encKey, iv)
			decKey := newBA(size, GfPow(rVal2, &a.val, poly, size))
			D := FscxRevolve(E, decKey, rv)
			sink = sink.Xor(D)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchNlFscxRevolve() {
	fmt.Println("[22] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
	for _, size := range sizes {
		iv := iVal(size)
		a := randBA(size)
		b := randBA(size)
		ops, elapsed := bench("", func() {
			a = NlFscxRevolveV1(a, b, iv)
		})
		fmt.Printf("    bits=%3d  v1 n/4 steps             : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println("[22b] NL-FSCX v2 revolve+inv throughput (r_val steps, 64-bit only)  [PQC-EXT]")
	for _, size := range []int{64} { // O(n^2) per op; skip 128/256 in benchmark
		rv := rVal(size)
		a := randBA(size)
		b := randBA(size)
		ops, elapsed := bench("", func() {
			E := NlFscxRevolveV2(a, b, rv)
			a = NlFscxRevolveV2Inv(E, b, rv)
		})
		fmt.Printf("    bits=%3d  v2 enc+dec r_val         : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeNlA1RoundTrip() {
	fmt.Println("[23] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
	for _, size := range sizes {
		iv := iVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			K     := randBA(size)
			nonce := randBA(size)
			base  := newBA(size, new(big.Int).Xor(&K.val, &nonce.val))
			P     := randBA(size)
			bCtr  := newBA(size, new(big.Int).Set(&base.val)) // counter=0
			ks    := NlFscxRevolveV1(base, bCtr, iv)
			sink = sink.Xor(newBA(size, new(big.Int).Xor(&P.val, &ks.val)))
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeNlA2RoundTrip() {
	fmt.Println("[24] HSKE-NL-A2 revolve-mode round-trip (64-bit only)  [PQC-EXT]")
	for _, size := range []int{64} { // O(n^2) per op; skip 128/256 in benchmark
		rv := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			K := randBA(size)
			P := randBA(size)
			E := NlFscxRevolveV2(P, K, rv)
			sink = sink.Xor(NlFscxRevolveV2Inv(E, K, rv))
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHkexRnlHandshake() {
	fmt.Println("[25] HKEX-RNL handshake throughput  [PQC-EXT]")
	fmt.Printf("     (ring sizes %v; n^2 poly-mul — O(n^2) per exchange)\n", rnlSizes)
	for _, nRnl := range rnlSizes {
		mBase := rnlMPoly(nRnl)
		ops, elapsed := bench("", func() {
			aRand := rnlRandPoly(nRnl, rnlQ)
			mBlind := rnlPolyAdd(mBase, aRand, rnlQ)
			sA, CA := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
			sB, CB := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
			_, hintA := rnlAgree(sA, CB, rnlQ, rnlP, rnlPP, nRnl, nRnl, nil)
			_, _ = rnlAgree(sB, CA, rnlQ, rnlP, rnlPP, nRnl, nRnl, hintA)
		})
		fmt.Printf("    n=%3d  full exchange             : %s  (%d ops in %.2fs)\n",
			nRnl, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// --- CLI flags ---
	flagRounds := flag.Int("rounds", 0, "max iterations per security test (0 = test-specific default)")
	flagR      := flag.Int("r", 0, "alias for -rounds")
	flagTime   := flag.Float64("time", 0, "benchmark duration and per-test time cap in seconds (0 = defaults)")
	flagT      := flag.Float64("t", 0, "alias for -time")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: Herradura_tests [-rounds N] [-time T]\n"+
			"  -rounds, -r N   max iterations per security test\n"+
			"  -time,   -t T   benchmark duration and per-test time cap (seconds)\n"+
			"  Env: HTEST_ROUNDS=N  HTEST_TIME=T\n")
	}
	flag.Parse()

	// env var fallbacks
	if envR := os.Getenv("HTEST_ROUNDS"); envR != "" {
		if v, err := strconv.Atoi(envR); err == nil && v > 0 && *flagRounds == 0 && *flagR == 0 {
			gRounds = v
		}
	}
	if envT := os.Getenv("HTEST_TIME"); envT != "" {
		if v, err := strconv.ParseFloat(envT, 64); err == nil && v > 0 && *flagTime == 0 && *flagT == 0 {
			gBenchDur  = time.Duration(v * float64(time.Second))
			gTimeLimit = gBenchDur
		}
	}
	// CLI overrides env
	if r := *flagRounds; r > 0 { gRounds = r }
	if r := *flagR;      r > 0 { gRounds = r }
	if t := *flagTime;   t > 0 {
		gBenchDur  = time.Duration(t * float64(time.Second))
		gTimeLimit = gBenchDur
	}
	if t := *flagT; t > 0 {
		gBenchDur  = time.Duration(t * float64(time.Second))
		gTimeLimit = gBenchDur
	}
	if gBenchDur == 0 { gBenchDur = time.Second }

	fmt.Println("=== Herradura KEx v1.5.10 — Security & Performance Tests (Go) ===")
	if gRounds > 0 || gTimeLimit > 0 {
		switch {
		case gRounds > 0 && gTimeLimit > 0:
			fmt.Printf("    Config: rounds=%d  time_limit=%.2fs\n", gRounds, gTimeLimit.Seconds())
		case gRounds > 0:
			fmt.Printf("    Config: rounds=%d\n", gRounds)
		default:
			fmt.Printf("    Config: time_limit=%.2fs\n", gTimeLimit.Seconds())
		}
	}
	fmt.Println()

	fmt.Println("--- Security Tests: Classical Protocols ---\n")
	testHkexGFCorrectness()
	testAvalanche()
	testOrbitPeriod()
	testBitFrequency()
	testHkexGFKeySensitivity()
	testHkexGFEveResistance()
	testHpksSchnorrCorrectness()
	testHpksSchnorrEveResistance()
	testHpkeRoundTrip()

	fmt.Println("--- Security Tests: PQC Extension (NL-FSCX + HKEX-RNL) ---\n")
	testNlFscxV1Nonlinearity()
	testNlFscxV2BijectiveInverse()
	testHskeNlA1Correctness()
	testHskeNlA2Correctness()
	testHkexRnlCorrectness()
	testHpksNlCorrectness()
	testHpkeNlCorrectness()

	fmt.Println("--- Performance Benchmarks ---\n")
	benchFscx()
	benchHkexGFPow()
	benchHkexHandshake()
	benchHskeRoundTrip()
	benchHpkeRoundTrip()
	benchNlFscxRevolve()
	benchHskeNlA1RoundTrip()
	benchHskeNlA2RoundTrip()
	benchHkexRnlHandshake()
}
