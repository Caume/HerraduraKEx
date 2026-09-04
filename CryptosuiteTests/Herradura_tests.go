/*  Herradura KEx — Security & Performance Tests (Go) v1.9.91
    v1.9.91: test [45] — weak-key/malformed-input rejection: gfPubIsValid rejects the
            GF(2^n)* identity/zero element in HKEX-GF/HPKS/HPKE-style checked helpers, and
            HPKS-Stern-F rejects a corrupted syndrome (TODO #131).
    v1.9.77: HCRED test [44] — completeness, tamper/replay/split-witness rejection, issuer binding (TODO #128 Batch 4a).
    v1.9.63: ZKP-RNL test [21] structured cheats — wrong-key, tampered-w, perturbed-z rejection
            (C/Go parity with Python, TODO #94 item 2).
    v1.9.43: HPKS-T threshold Schnorr test [31] (TODO #98); benchmarks renumbered [32]–[43].
    v1.9.42: HPKS-WOTS-F / HPKS-XMSS-F test [30] (TODO #102); benchmarks renumbered [31]–[42].
    v1.9.35: HFSCX-256-DM finalization of Stern parity-matrix rows (TODO #88);
    v1.9.34: HDRBG test [29] — KAT, determinism, reseed separation, block limit (TODO #96);
            benchmarks renumbered [30]–[41].
    v1.9.33: HSKE-NL-AEAD test [28] — round-trip, tamper rejection, cross-language KAT (TODO #95);
            benchmarks renumbered [29]–[40].
    v1.9.11: ZKP-RNL + ZKP-NL security tests [20][21] and benchmarks [32][33] (TODO #77 Batch 7);
            benchmarks renumbered [22]-[33].
    v1.8.7: 32-bit benchmark columns; benchHpksSternF loops over all sizes (TODO #61 extension).
    v1.8.0: KDF domain constant (TODO #38) — RnlKdfSeed applied to all HSKE-NL-A1 and HKEX-RNL seed sites.
    v1.6.1: SternHash ds parameter (TODO #36).
    v1.5.27: refactored to import package herradura; added HFSCX-256 KAV test [17].
    v1.5.23: HPKS-Stern-F + HPKE-Stern-F tests [17][18] (now [18][19]).
    v1.5.22: CBD(eta=1) 4-coeffs/byte; test[14] n∈{32,64,128,256}.
    v1.5.18: code-based PQC; benchmarks renumbered.
    v1.5.0:  NL-FSCX PQC extension tests.
    v1.4.0:  HKEX-GF Schnorr/El Gamal tests.
    v1.3:    BitArray support.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License or the GNU General Public License
    as published by the Free Software Foundation, either version 3 of the License,
    or (at your option) any later version.
*/

package main

import (
	. "herradurakex/herradura"
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Runtime limits
// ---------------------------------------------------------------------------

var (
	gRounds    int
	gBenchDur  time.Duration
	gTimeLimit time.Duration
)

func testRounds(defaultN int) int {
	if gRounds > 0 {
		return gRounds
	}
	return defaultN
}

func timeExceeded(t0 time.Time) bool {
	if gTimeLimit <= 0 {
		return false
	}
	return time.Since(t0) >= gTimeLimit
}

// ---------------------------------------------------------------------------
// Test-local helpers
// ---------------------------------------------------------------------------

func newBA(size int, val *big.Int) *BitArray { return NewBitArray(size, val) }
func randBA(size int) *BitArray              { return NewRandBitArray(size) }

func iVal(size int) int { return size / 4 }
func rVal(size int) int { return size * 3 / 4 }

func gfOrd(size int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(size)), big.NewInt(1))
}

var sizes    = []int{32, 64, 128, 256}
var gfSizes  = []int{32, 64, 128, 256}
var rnlSizes = []int{32, 64, 128, 256}

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

// SOpBA computes S_op(delta, r) = XOR_{i=0}^{r} Fscx^i(delta, 0).
func SOpBA(delta *BitArray, r int) *BitArray {
	acc  := NewBitArray(delta.Size(), new(big.Int))
	cur  := delta.Copy()
	zero := NewBitArray(delta.Size(), new(big.Int))
	for i := 0; i <= r; i++ {
		acc.Val.Xor(&acc.Val, &cur.Val)
		cur = Fscx(cur, zero)
	}
	return acc
}

// hpkeSternFBruteForce32 decapsulates by enumerating all C(32,2)=496 weight-2 errors.
func hpkeSternFBruteForce32(seed *BitArray, ct *big.Int) (*BitArray, bool) {
	for i := 0; i < 32; i++ {
		for j := i + 1; j < 32; j++ {
			e := NewBitArray(32, new(big.Int))
			e.Val.SetBit(&e.Val, i, 1)
			e.Val.SetBit(&e.Val, j, 1)
			if SternSyndrome(seed, e).Cmp(ct) == 0 {
				return e, true
			}
		}
	}
	return nil, false
}

const sdfTestRounds = 4

// sdfBenchRounds matches C's SDF_TEST_ROUNDS=8 for benchmark [41] specifically,
// so throughput numbers are comparable across languages (TODO #146.C); the
// correctness tests [17]/[20] keep sdfTestRounds=4 for speed.
const sdfBenchRounds = 8

// ---------------------------------------------------------------------------
// Security tests — classical protocols [1-9]
// ---------------------------------------------------------------------------

func testHkexGFCorrectness() {
	fmt.Println("[1] HKEX-GF correctness: g^{ab} == g^{ba} in GF(2^n)*  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C := GfPow(g, &a.Val, poly, size)
			C2 := GfPow(g, &b.Val, poly, size)
			if GfPow(C2, &a.Val, poly, size).Cmp(GfPow(C, &b.Val, poly, size)) == 0 {
				ok++
			}
			if i&7 == 7 && timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if ok != N { status = "FAIL" }
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
		if mean < 2.9 || mean > 3.1 { status = "FAIL" }
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
				if out.Val.Bit(bit) == 1 { counts[bit]++ }
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
		// Sample-size-aware tolerance (TODO #233).  Each bit count is
		// Binomial(nRun, 1/2), so the per-bit percentage has sigma =
		// 50/sqrt(nRun) points.  The historical window was a hard +/-3, which
		// is 6 sigma at the default N=10000 -- but only 0.19 sigma once -r 2
		// or a -t truncation cuts nRun to 1000x fewer samples, so the check
		// failed on sample noise rather than on bias.  Keeping the 6-sigma
		// intent and letting the window follow nRun reproduces +/-3.00
		// exactly at N=10000 and stays sound below it; the union bound over
		// 256+128+64 bits puts the false-alarm rate near 1e-6 per run.
		tol := 100.0
		if nRun > 0 { tol = 6.0 * 50.0 / math.Sqrt(float64(nRun)) }
		// At tol >= 50 the window spans the whole 0-100% range, so the check
		// cannot discriminate at all (nRun <= 36).  Say SKIP rather than
		// claim a PASS the samples do not support.
		status := "PASS"
		switch {
		case tol >= 50.0:
			status = "SKIP"
		case mn <= 50.0-tol || mx >= 50.0+tol:
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  min=%.2f%%  max=%.2f%%  mean=%.2f%%"+
			"  (tol +/-%.2f, N=%d)  [%s]\n",
			size, mn, mx, mean, tol, nRun, status)
	}
	fmt.Println()
}

func testHkexGFKeySensitivity() {
	fmt.Println("[5] HKEX-GF key sensitivity: flip 1 bit of a, measure HD of sk change  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		total := 0.0
		N := testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C2 := GfPow(g, &b.Val, poly, size)
			sk1 := GfPow(C2, &a.Val, poly, size)
			af := a.FlipBit(0)
			sk2 := GfPow(C2, &af.Val, poly, size)
			diff := NewBitArray(size, new(big.Int).Xor(sk1, sk2))
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
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		rv := rVal(size)
		successes := 0
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			b := randBA(size)
			C := newBA(size, GfPow(g, &a.Val, poly, size))
			C2 := newBA(size, GfPow(g, &b.Val, poly, size))
			realSk := newBA(size, GfPow(&C2.Val, &a.Val, poly, size))
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
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		iv := iVal(size)
		ord := gfOrd(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.Val, poly, size)
			pt := randBA(size)
			k := randBA(size)
			rInt := GfPow(g, &k.Val, poly, size)
			rB := newBA(size, rInt)
			e := FscxRevolve(rB, pt, iv)
			s := new(big.Int).Mod(new(big.Int).Sub(&k.Val, new(big.Int).Mul(&a.Val, &e.Val)), ord)
			lhs := GfMul(GfPow(g, s, poly, size), GfPow(cVal, &e.Val, poly, size), poly, size)
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
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		iv := iVal(size)
		wins, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.Val, poly, size)
			decoy := randBA(size)
			rEve := newBA(size, GfPow(g, &randBA(size).Val, poly, size))
			eEve := FscxRevolve(rEve, decoy, iv)
			sEve := new(big.Int).Set(&randBA(size).Val)
			lhs := GfMul(GfPow(g, sEve, poly, size), GfPow(cVal, &eEve.Val, poly, size), poly, size)
			if lhs.Cmp(&rEve.Val) == 0 { wins++ }
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
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		iv := iVal(size)
		rv := rVal(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			pt := randBA(size)
			cVal := GfPow(g, &a.Val, poly, size)
			r := randBA(size)
			rVal2 := GfPow(g, &r.Val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.Val, poly, size))
			E := FscxRevolve(pt, encKey, iv)
			decKey := newBA(size, GfPow(rVal2, &a.Val, poly, size))
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
	fmt.Println("[10] NL-FSCX v1 non-linearity and aperiodicity  [PQC-EXT]")
	for _, size := range sizes {
		zero := NewBitArray(size, new(big.Int))
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
	fmt.Println("[11] NL-FSCX v2 bijectivity and exact inverse  [PQC-EXT]")
	for _, size := range sizes {
		N1, N2, N3 := testRounds(500), testRounds(1000), testRounds(500)
		nonBij := 0
		t0 := time.Now()
		for i := 0; i < N1; i++ {
			B := randBA(size)
			seen := make(map[string]uint64)
			samples := 256
			if size < 8 { samples = 1 << uint(size) }
			for j := 0; j < samples; j++ {
				A := randBA(size)
				out := NlFscxV2(A, B).Val.Text(16)
				if prev, ok := seen[out]; ok && prev != A.Val.Uint64() { nonBij++; break }
				seen[out] = A.Val.Uint64()
			}
			if i&63 == 63 && timeExceeded(t0) { N1 = i + 1; break }
		}
		invOk := 0
		t0 = time.Now()
		for i := 0; i < N2; i++ {
			A := randBA(size); B := randBA(size)
			if NlFscxV2Inv(NlFscxV2(A, B), B).Equal(A) { invOk++ }
			if i&63 == 63 && timeExceeded(t0) { N2 = i + 1; break }
		}
		zero := NewBitArray(size, new(big.Int))
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
	fmt.Println("[12] HSKE-NL-A1 counter-mode correctness: D == P  [PQC-EXT]")
	for _, size := range sizes {
		iv := iVal(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for trial := 0; trial < N; trial++ {
			K := randBA(size); nonce := randBA(size); P := randBA(size)
			base := newBA(size, new(big.Int).Xor(&K.Val, &nonce.Val))
			ctr := int64(trial % (1 << 16))
			bCtr := newBA(size, new(big.Int).Xor(&base.Val, big.NewInt(ctr)))
			ks := NlFscxRevolveV1(RnlKdfSeed(base), bCtr, iv)
			C := newBA(size, new(big.Int).Xor(&P.Val, &ks.Val))
			D := newBA(size, new(big.Int).Xor(&C.Val, &ks.Val))
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
	fmt.Println("[14] HKEX-RNL key agreement: K_raw_A == K_raw_B / sk_A == sk_B  [PQC-EXT]")
	fmt.Printf("     (ring sizes %v; Peikert reconciliation -- expect 100%% agreement)\n", rnlSizes)
	for _, nRnl := range rnlSizes {
		mBase := RnlMPoly(nRnl)
		okRaw, okSk := 0, 0
		trials := testRounds(200)
		t0 := time.Now()
		for i := 0; i < trials; i++ {
			aRand  := RnlRandPoly(nRnl, RnlQ)
			mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
			sA, CA := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
			sB, CB := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
			KA, hintA := RnlAgree(sA, CB, RnlQ, RnlP, RnlPP, nRnl, nRnl, nil)
			KB, _     := RnlAgree(sB, CA, RnlQ, RnlP, RnlPP, nRnl, nRnl, hintA)
			if KA.Equal(KB) { okRaw++ }
			skA := NlFscxRevolveV1(RnlKdfSeed(KA), KA, nRnl/4)
			skB := NlFscxRevolveV1(RnlKdfSeed(KB), KB, nRnl/4)
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
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		iv := iVal(size)
		ord := gfOrd(size)
		ok, N := 0, testRounds(1000)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size)
			cVal := GfPow(g, &a.Val, poly, size)
			pt := randBA(size)
			k := randBA(size)
			rInt := GfPow(g, &k.Val, poly, size)
			rB := newBA(size, rInt)
			e := NlFscxRevolveV1(rB, pt, iv)
			s := new(big.Int).Mod(new(big.Int).Sub(&k.Val, new(big.Int).Mul(&a.Val, &e.Val)), ord)
			lhs := GfMul(GfPow(g, s, poly, size), GfPow(cVal, &e.Val, poly, size), poly, size)
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
	fmt.Println("[16] HPKE-NL correctness: D == P (NL-FSCX v2 encrypt/decrypt)  [PQC-EXT]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		iv := iVal(size)
		ok, N := 0, testRounds(200)
		t0 := time.Now()
		for i := 0; i < N; i++ {
			a := randBA(size); pt := randBA(size)
			cVal := GfPow(g, &a.Val, poly, size)
			r := randBA(size)
			rInt := GfPow(g, &r.Val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.Val, poly, size))
			E := NlFscxRevolveV2(pt, encKey, iv)
			decKey := newBA(size, GfPow(rInt, &a.Val, poly, size))
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
// Security test — HFSCX-256 hash known-answer vectors [19]
// ---------------------------------------------------------------------------

func testHfscx256KAV() {
	fmt.Println("[19] HFSCX-256-DM known-answer vectors  [NL-FSCX HASH]")
	expEmpty := []byte{
		0xe7, 0x08, 0x2e, 0x7f, 0x03, 0x8a, 0x6e, 0x32,
		0xe4, 0x80, 0xb5, 0xf1, 0xd9, 0x69, 0xea, 0x2c,
		0x19, 0x56, 0x5d, 0x32, 0x7d, 0xef, 0xb0, 0xf8,
		0x50, 0x0f, 0x6f, 0xac, 0x8f, 0xe2, 0x46, 0xcc,
	}
	expA := []byte{
		0x73, 0xb2, 0xd9, 0x1b, 0xbd, 0xf0, 0xfc, 0x00,
		0x0d, 0xe7, 0xcd, 0x16, 0xac, 0x45, 0xd7, 0xf3,
		0xf4, 0x1b, 0xe5, 0x60, 0x95, 0x24, 0xdb, 0xeb,
		0xa3, 0x06, 0x05, 0xa8, 0x9d, 0x13, 0x8e, 0xc5,
	}
	exp33A := []byte{
		0x96, 0x25, 0x19, 0x76, 0x47, 0x09, 0xbc, 0x00,
		0x80, 0xce, 0x8a, 0x1e, 0x52, 0x66, 0x0b, 0xec,
		0x8e, 0x33, 0x9e, 0xa4, 0xc3, 0x49, 0xf4, 0xd8,
		0xd1, 0xb9, 0xac, 0x2b, 0xfd, 0x68, 0x3f, 0xda,
	}
	type kav struct {
		msg    []byte
		label  string
		expect []byte
	}
	tests := []kav{
		{[]byte{}, "empty", expEmpty},
		{[]byte{0x61}, "0x61", expA},
		{bytes.Repeat([]byte{'A'}, 33), "33×A", exp33A},
	}
	pass := true
	for _, tc := range tests {
		got := Hfscx256(tc.msg, nil)
		ok := bytes.Equal(got, tc.expect)
		if !ok { pass = false }
		lbl := "OK"
		if !ok { lbl = "FAIL" }
		fmt.Printf("    %-8s : %x  [%s]\n", tc.label, got, lbl)
	}
	status := "PASS"
	if !pass { status = "FAIL" }
	fmt.Printf("    [%s]\n\n", status)
}

// ---------------------------------------------------------------------------
// Security tests — Code-Based PQC (Stern-F) [17-18]
// ---------------------------------------------------------------------------

func testHpksSternFCorrectness() {
	fmt.Printf("[17] HPKS-Stern-F correctness: sign+verify  (N=256, t=16, rounds=%d)  [CODE-BASED PQC]\n", sdfTestRounds)
	N := testRounds(3)
	ok := 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		seed, e, syn := SternFKeygen(256)
		msg := randBA(256)
		sig := HpksSternFSign(msg, e, seed, sdfTestRounds)
		if HpksSternFVerify(msg, sig, seed, syn) {
			ok++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if ok != N { status = "FAIL" }
	fmt.Printf("    %d / %d verified  [%s]\n\n", ok, N, status)
}

func testHpkeSternFCorrectness() {
	fmt.Println("[18] HPKE-Stern-F correctness: encap+decap  (n=32, t=2, brute-force)  [CODE-BASED PQC]")
	N := testRounds(20)
	ok := 0
	// A weight-2 code of length 32 with a 16-bit syndrome is NOT uniquely
	// decodable: C(32,2)=496 error vectors land in 2^16 syndromes, so the
	// birthday model predicts ~1.87 colliding pairs per key and 43% of keys
	// carry at least one.  Measured over 5000 keys: 0.76% of weight-2 vectors
	// share a syndrome and 0.38% decode to a different e' -- which made this
	// line report [FAIL] on 7.4% of runs, a failure nothing propagated until
	// TODO #233 added the exit gate.  Brute force is not wrong when it returns
	// the other preimage; the parameters are simply ambiguous, so those trials
	// are counted and reported separately rather than scored.
	ambiguous, bad := 0, 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		seed   := randBA(32)
		ePrime := SternRandError(32, 2)
		ct     := SternSyndrome(seed, ePrime)
		K      := SternHash(4, seed, ePrime)
		eDec, found := hpkeSternFBruteForce32(seed, ct)
		switch {
		case found && K.Equal(SternHash(4, seed, eDec)):
			ok++
		case found && !eDec.Equal(ePrime):
			// A decode that returns a *different* weight-t preimage of the
			// same syndrome is the code being ambiguous, not the decoder
			// being wrong.
			ambiguous++
		default:
			// Anything else -- including no preimage at all, which cannot
			// happen since ePrime is one -- is a real failure.
			bad++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if bad != 0 { status = "FAIL" }
	plural := "s"
	if ambiguous == 1 { plural = "" }
	fmt.Printf("    %d / %d decapsulated  (%d ambiguous syndrome%s, not a failure)  [%s]\n\n",
		ok, N, ambiguous, plural, status)
}

func testHpksSternRingCorrectness() {
	fmt.Printf("[20] HPKS-Stern-Ring correctness: OR-composition, k=3, N=256, rounds=%d  [CODE-BASED RING SIG]\n", sdfTestRounds)
	N  := testRounds(3)
	ok := 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		const ringK = 3
		rKeys := make([]RingKeypair, ringK)
		rE    := make([]*BitArray, ringK)
		for ki := 0; ki < ringK; ki++ {
			rKeys[ki].Seed, rE[ki], rKeys[ki].Syndrome = SternFKeygen(256)
		}
		msg  := randBA(256)
		j    := i % ringK
		rsig := HpksSternRingSign(msg, rE[j], j, rKeys, sdfTestRounds)
		if HpksSternRingVerify(msg, rsig, rKeys) {
			ok++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if ok != N { status = "FAIL" }
	fmt.Printf("    %d / %d ring-verified  [%s]\n\n", ok, N, status)
}

// ---------------------------------------------------------------------------
// Performance benchmarks [28-39]
// ---------------------------------------------------------------------------

func benchFscx() {
	fmt.Println("[32] FSCX throughput  [CLASSICAL]")
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
	fmt.Println("[33] HKEX-GF gf_pow throughput  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		a := randBA(size)
		ops, elapsed := bench("", func() {
			GfPow(g, &a.Val, poly, size)
		})
		fmt.Printf("    bits=%3d  gf_pow(g, a)             : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHkexHandshake() {
	fmt.Println("[34] HKEX-GF full handshake (4 GfPow calls)  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g := big.NewInt(GfGen)
		ops, elapsed := bench("", func() {
			a := randBA(size)
			b := randBA(size)
			C  := GfPow(g, &a.Val, poly, size)
			C2 := GfPow(g, &b.Val, poly, size)
			_ = GfPow(C2, &a.Val, poly, size)
			_ = GfPow(C, &b.Val, poly, size)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeRoundTrip() {
	fmt.Println("[35] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
	for _, size := range sizes {
		iv   := iVal(size)
		rv   := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			pt  := randBA(size)
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
	fmt.Println("[36] HPKE encrypt+decrypt round-trip (El Gamal + FscxRevolve)  [CLASSICAL]")
	for _, size := range gfSizes {
		poly := GfPoly[size]
		g    := big.NewInt(GfGen)
		iv   := iVal(size)
		rv   := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			a      := randBA(size)
			pt     := randBA(size)
			cVal   := GfPow(g, &a.Val, poly, size)
			r      := randBA(size)
			rVal2  := GfPow(g, &r.Val, poly, size)
			encKey := newBA(size, GfPow(cVal, &r.Val, poly, size))
			E      := FscxRevolve(pt, encKey, iv)
			decKey := newBA(size, GfPow(rVal2, &a.Val, poly, size))
			D      := FscxRevolve(E, decKey, rv)
			sink = sink.Xor(D)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchNlFscxRevolve() {
	fmt.Println("[37] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
	for _, size := range sizes {
		iv := iVal(size)
		a  := randBA(size)
		b  := randBA(size)
		ops, elapsed := bench("", func() {
			a = NlFscxRevolveV1(a, b, iv)
		})
		fmt.Printf("    bits=%3d  v1 n/4 steps             : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println("[35b] NL-FSCX v2 revolve+inv throughput (r_val steps)  [PQC-EXT]")
	for _, size := range sizes {
		rv := rVal(size)
		a  := randBA(size)
		b  := randBA(size)
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
	fmt.Println("[38] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
	for _, size := range sizes {
		iv   := iVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			K     := randBA(size)
			nonce := randBA(size)
			base  := newBA(size, new(big.Int).Xor(&K.Val, &nonce.Val))
			P     := randBA(size)
			bCtr  := newBA(size, new(big.Int).Set(&base.Val))
			ks    := NlFscxRevolveV1(RnlKdfSeed(base), bCtr, iv)
			sink = sink.Xor(newBA(size, new(big.Int).Xor(&P.Val, &ks.Val)))
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeNlA2RoundTrip() {
	fmt.Println("[39] HSKE-NL-A2 revolve-mode round-trip  [PQC-EXT]")
	for _, size := range sizes {
		rv   := rVal(size)
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
	fmt.Println("[40] HKEX-RNL handshake throughput  [PQC-EXT]")
	fmt.Printf("     (ring sizes %v; NTT O(n log n) per exchange)\n", rnlSizes)
	for _, nRnl := range rnlSizes {
		mBase := RnlMPoly(nRnl)
		ops, elapsed := bench("", func() {
			aRand  := RnlRandPoly(nRnl, RnlQ)
			mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
			sA, CA := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
			sB, CB := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
			_, hintA := RnlAgree(sA, CB, RnlQ, RnlP, RnlPP, nRnl, nRnl, nil)
			_, _     = RnlAgree(sB, CA, RnlQ, RnlP, RnlPP, nRnl, nRnl, hintA)
		})
		fmt.Printf("    n=%3d  full exchange             : %s  (%d ops in %.2fs)\n",
			nRnl, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHpksSternF() {
	fmt.Printf("[41] HPKS-Stern-F sign+verify throughput  (N=n, rounds=%d)  [CODE-BASED PQC]\n", sdfBenchRounds)
	for _, size := range sizes {
		seed, e, syn := SternFKeygen(size)
		msg := randBA(size)
		ops, elapsed := bench("", func() {
			sig := HpksSternFSign(msg, e, seed, sdfBenchRounds)
			HpksSternFVerify(msg, sig, seed, syn)
		})
		fmt.Printf("    bits=%3d  sign+verify              : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Security tests [21]-[22]: ZKP-RNL and ZKP-NL
// ---------------------------------------------------------------------------

var zkpMsg  = []byte("Herradura ZKP test")
var zkpMsg2 = []byte("Herradura ZKP tamper")

func testZkpRnlCorrectness() {
	fmt.Println("[21] ZKP-RNL Sigma-protocol completeness + tamper-rejection  [PQC-EXT]")
	zkpRnlSizes := []int{32, 256}
	for _, n := range zkpRnlSizes {
		N := testRounds(5)
		okVerify, okTamper := 0, 0
		okWrongkey, okWtamper, okZtamper := 0, 0, 0
		t0 := time.Now()
		mBase := RnlMPoly(n)
		for i := 0; i < N; i++ {
			aRand  := RnlRandPoly(n, RnlQ)
			mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
			s, C   := RnlKeygen(mBlind, n, RnlQ, RnlP)
			w, c, z, err := RnlSigmaSign(s, mBlind, C, n, zkpMsg)
			if err != nil { N = i + 1; break }
			if RnlSigmaVerify(mBlind, C, n, zkpMsg, w, c, z) {
				okVerify++
			}
			if !RnlSigmaVerify(mBlind, C, n, zkpMsg2, w, c, z) {
				okTamper++
			}
			// Structured cheats (TODO #94 item 2 — C/Go parity):
			// (a) wrong-key witness: honest signer run with a fresh s' != s
			//     against the original public key C — must not verify.
			s2, _ := RnlKeygen(mBlind, n, RnlQ, RnlP)
			w2, c2, z2, err2 := RnlSigmaSign(s2, mBlind, C, n, zkpMsg)
			if err2 != nil {
				okWrongkey++ // rejection-limit on a wrong key is also a reject
			} else if !RnlSigmaVerify(mBlind, C, n, zkpMsg, w2, c2, z2) {
				okWrongkey++
			}
			// (b) tampered commitment w — must fail Fiat-Shamir re-derivation.
			wT := append([]int(nil), w...)
			wT[0]++
			if !RnlSigmaVerify(mBlind, C, n, zkpMsg, wT, c, z) {
				okWtamper++
			}
			// (c) perturbed response z (FS check still passes; the residual
			//     norm check must catch it).
			zT := append([]int(nil), z...)
			zT[0]++
			if !RnlSigmaVerify(mBlind, C, n, zkpMsg, w, c, zT) {
				okZtamper++
			}
			if timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if okVerify != N || okTamper != N || okWrongkey != N ||
			okWtamper != N || okZtamper != N { status = "FAIL" }
		fmt.Printf("    n=%3d  verify=%d/%d  tamper_reject=%d/%d"+
			"  wrongkey_reject=%d/%d  w_tamper=%d/%d  z_tamper=%d/%d  [%s]\n",
			n, okVerify, N, okTamper, N, okWrongkey, N, okWtamper, N,
			okZtamper, N, status)
	}
	fmt.Println()
}

func testZkpNlCorrectness() {
	fmt.Println("[22] ZKP-NL (ZKBoo) completeness + tamper-rejection  [PQC-EXT]")
	zkpNlSizes  := []int{32, 64}
	zkpNlRounds := 16
	for _, n := range zkpNlSizes {
		N := testRounds(5)
		okVerify, okTamper := 0, 0
		t0 := time.Now()
		for i := 0; i < N; i++ {
			A, B, y, err := ZkpNlKeygen(n)
			if err != nil { N = i + 1; break }
			proof, err := ZkpNlProve(A, B, y, n, zkpNlRounds, zkpMsg)
			if err != nil { N = i + 1; break }
			if ZkpNlVerify(B, y, n, zkpNlRounds, zkpMsg, proof) {
				okVerify++
			}
			// tamper: flip one bit in com_1[0]
			proof[0].Com1[0] ^= 1
			if !ZkpNlVerify(B, y, n, zkpNlRounds, zkpMsg, proof) {
				okTamper++
			}
			if timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if okVerify != N || okTamper != N { status = "FAIL" }
		fmt.Printf("    n=%2d  rounds=%d  verify=%d/%d  tamper_reject=%d/%d  [%s]\n",
			n, zkpNlRounds, okVerify, N, okTamper, N, status)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Performance benchmarks [40]-[41]: ZKP
// ---------------------------------------------------------------------------

func benchZkpRnl() {
	const n = 256
	fmt.Printf("[42] ZKP-RNL sign+verify throughput  (n=%d)  [PQC-EXT]\n", n)
	mBase  := RnlMPoly(n)
	aRand  := RnlRandPoly(n, RnlQ)
	mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
	s, C   := RnlKeygen(mBlind, n, RnlQ, RnlP)
	ops, elapsed := bench("", func() {
		w, c, z, err := RnlSigmaSign(s, mBlind, C, n, zkpMsg)
		if err == nil {
			RnlSigmaVerify(mBlind, C, n, zkpMsg, w, c, z)
		}
	})
	fmt.Printf("    n=%3d  sign+verify              : %s  (%d ops in %.2fs)\n",
		n, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	fmt.Println()
}

func benchZkpNl() {
	const (
		n      = 32
		rounds = 16
	)
	fmt.Printf("[43] ZKP-NL prove+verify throughput  (n=%d, rounds=%d)  [PQC-EXT]\n", n, rounds)
	A, B, y, _ := ZkpNlKeygen(n)
	ops, elapsed := bench("", func() {
		proof, err := ZkpNlProve(A, B, y, n, rounds, zkpMsg)
		if err == nil {
			ZkpNlVerify(B, y, n, rounds, zkpMsg, proof)
		}
	})
	fmt.Printf("    n=%2d  rounds=%d  prove+verify     : %s  (%d ops in %.2fs)\n",
		n, rounds, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Security tests [23]-[25]: FPE / Tweakable / Accumulator (78.A/B/J)
// ---------------------------------------------------------------------------

func testFpeCorrectness() {
	fmt.Println("[23] FPE (78.A) encrypt→decrypt round-trip  [NEW]")
	N := testRounds(1000)
	ok := 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		P   := NewRandBitArray(256)
		key := NewRandBitArray(256).Bytes()
		ctx := NewRandBitArray(64).Bytes()
		C   := FpeEncrypt(P, key, ctx)
		D   := FpeDecrypt(C, key, ctx)
		if D.Equal(P) {
			ok++
		}
		if gTimeLimit > 0 && i&63 == 63 && time.Since(t0) >= gTimeLimit {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if ok != N { status = "FAIL" }
	fmt.Printf("    %d / %d round-trips correct  [%s]\n\n", ok, N, status)
}

func testTwkCorrectness() {
	fmt.Println("[24] Tweakable wide-block cipher (78.B) encrypt→decrypt round-trip  [NEW]")
	N := testRounds(1000)
	ok := 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		P      := NewRandBitArray(256)
		key    := NewRandBitArray(256).Bytes()
		sector := uint64(mrand.Int63())
		bidx   := uint32(mrand.Int31())
		C := TwkEncrypt(P, key, sector, bidx)
		D := TwkDecrypt(C, key, sector, bidx)
		if D.Equal(P) {
			ok++
		}
		if gTimeLimit > 0 && i&63 == 63 && time.Since(t0) >= gTimeLimit {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if ok != N { status = "FAIL" }
	fmt.Printf("    %d / %d round-trips correct  [%s]\n\n", ok, N, status)
}

func testAccumulatorCorrectness() {
	fmt.Println("[25] Cryptographic Accumulator (78.J) — Merkle proof  [NEW]")
	sizes  := []int{1, 2, 4, 8, 16}
	total, okValid, okReject := 0, 0, 0
	for _, n := range sizes {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = HaccumLeaf(NewRandBitArray(64).Bytes())
		}
		root := HaccumRoot(leaves)
		for idx := 0; idx < n; idx++ {
			proof := HaccumProve(leaves, idx)
			if HaccumVerify(root, leaves[idx], proof, idx) {
				okValid++
			}
			// tamper: flip a byte in the first sibling hash
			if len(proof) > 0 {
				tampered := make([][]byte, len(proof))
				for j, s := range proof {
					tampered[j] = append([]byte(nil), s...)
				}
				tampered[0][0] ^= 0xFF
				if !HaccumVerify(root, leaves[idx], tampered, idx) {
					okReject++
				}
			} else {
				okReject++ // leaf n=1 has empty proof — root == leaf, tamper not possible
			}
			total++
		}
	}
	status := "PASS"
	if okValid != total || okReject != total { status = "FAIL" }
	fmt.Printf("    valid=%d/%d  tamper_reject=%d/%d  [%s]\n\n",
		okValid, total, okReject, total, status)
}

// ---------------------------------------------------------------------------
// Security tests [26]-[27]: Masking / Ratchet (78.H/C)
// ---------------------------------------------------------------------------

func testMaskedHske() {
	fmt.Println("[26] Masked HSKE (78.H) — GF(2)-linearity masking  [NEW]")
	N := testRounds(200)
	okRt, okLin := 0, 0
	for i := 0; i < N; i++ {
		pt   := NewRandBitArray(256)
		key  := NewRandBitArray(256)
		ct, _  := HskeEncryptMasked(pt, key)
		rec, _ := HskeDecryptMasked(ct, key)
		if rec.Equal(pt) {
			okRt++
		}
	}
	// linearity: FscxRevolveMasked(A, B, r, n) == FscxRevolve(A, B, n)
	linN := 100
	for i := 0; i < linN; i++ {
		A := NewRandBitArray(256)
		B := NewRandBitArray(256)
		r := NewRandBitArray(256)
		direct := FscxRevolve(A, B, 64)
		masked := FscxRevolveMasked(A, B, r, 64)
		if masked.Equal(direct) {
			okLin++
		}
	}
	status := "PASS"
	if okRt != N || okLin != linN { status = "FAIL" }
	fmt.Printf("    round-trips=%d/%d  linearity=%d/%d  [%s]\n\n",
		okRt, N, okLin, linN, status)
}

func testRatchetForwardSecrecy() {
	fmt.Println("[27] Ratchet (78.C) — forward secrecy & key uniqueness  [NEW]")
	steps := testRounds(10); if steps > 10 { steps = 10 }
	okUniq, okDiv := true, true

	// key uniqueness: steps should produce distinct keys
	state := RatchetInit([]byte("test-seed-0"))
	var first []byte
	for i := 0; i < steps; i++ {
		var mk []byte
		state, mk = RatchetAdvance(state)
		if i == 0 {
			first = mk
		} else if bytes.Equal(mk, first) {
			okUniq = false
		}
	}

	// divergence: two seeds should not converge
	s1 := RatchetInit([]byte("seed-alice"))
	s2 := RatchetInit([]byte("seed-bob"))
	for i := 0; i < steps; i++ {
		var dummy []byte
		s1, dummy = RatchetAdvance(s1)
		s2, dummy = RatchetAdvance(s2)
		if s1.Equal(s2) { okDiv = false }
		_ = dummy
	}

	status := "PASS"
	if !okUniq || !okDiv { status = "FAIL" }
	uniqStr := "PASS"; if !okUniq { uniqStr = "FAIL" }
	divStr  := "PASS"; if !okDiv  { divStr  = "FAIL" }
	fmt.Printf("    key_uniqueness=%s  divergence=%s  [%s]\n\n",
		uniqStr, divStr, status)
}

func testHskeNlAead() {
	fmt.Println("[28] HSKE-NL-AEAD (TODO #95) — round-trip, tamper rejection, cross-language KAT  [NEW]")

	// Cross-language known-answer test (must match C/Go/Python suite outputs)
	kb := make([]byte, 32)
	nb := make([]byte, 32)
	for i := 0; i < 32; i++ {
		kb[i] = byte(i)
		nb[i] = byte(0xA0 ^ i)
	}
	katKey := NewBitArray(256, new(big.Int).SetBytes(kb))
	katNonce := NewBitArray(256, new(big.Int).SetBytes(nb))
	katPt := []byte("HSKE-NL-AEAD cross-language vector, 41 bytes!")
	katCt, katTag := HskeNlAeadEncrypt(katKey, katNonce, []byte("hdr"), katPt)
	okKat := fmt.Sprintf("%x", katCt) ==
		"75fe38c5204d65381fc11f084181ee0cce44940c4b62b697ab85178f20022ce4cfbad25099f9e16d5ad7abf73d" &&
		fmt.Sprintf("%x", katTag) ==
			"b9bc7eb9cf31ec444a50ef670750d62a189f4518908a42d16ec6872eb710d022"

	// Round-trip + tamper rejection over random inputs of irregular lengths
	trials := testRounds(50)
	if trials > 50 {
		trials = 50
	}
	okRt, okTamper := 0, 0
	for t := 0; t < trials; t++ {
		key := NewRandBitArray(256)
		nonce := NewRandBitArray(256)
		pt := make([]byte, 1+(t*7)%97)
		ad := make([]byte, t%17)
		mrand.Read(pt)
		mrand.Read(ad)
		ct, tag := HskeNlAeadEncrypt(key, nonce, ad, pt)
		if rec, ok := HskeNlAeadDecrypt(key, nonce, ad, ct, tag); ok && bytes.Equal(rec, pt) {
			okRt++
		}
		badCt := append([]byte{ct[0] ^ 1}, ct[1:]...)
		badTag := append([]byte{tag[0] ^ 1}, tag[1:]...)
		badNonce := NewBitArray(256, new(big.Int).Xor(&nonce.Val, big.NewInt(1)))
		badKey := NewBitArray(256, new(big.Int).Xor(&key.Val, big.NewInt(1)))
		_, r1 := HskeNlAeadDecrypt(key, nonce, ad, badCt, tag)
		_, r2 := HskeNlAeadDecrypt(key, nonce, ad, ct, badTag)
		_, r3 := HskeNlAeadDecrypt(key, nonce, append(append([]byte{}, ad...), 'x'), ct, tag)
		_, r4 := HskeNlAeadDecrypt(key, badNonce, ad, ct, tag)
		_, r5 := HskeNlAeadDecrypt(badKey, nonce, ad, ct, tag)
		if !r1 && !r2 && !r3 && !r4 && !r5 {
			okTamper++
		}
	}
	status := "PASS"
	if !okKat || okRt != trials || okTamper != trials {
		status = "FAIL"
	}
	katStr := "PASS"
	if !okKat {
		katStr = "FAIL"
	}
	fmt.Printf("    kat=%s  roundtrip=%d/%d  tamper_reject=%d/%d  [%s]\n\n",
		katStr, okRt, trials, okTamper, trials, status)
}

func testHdrbg() {
	fmt.Println("[29] HDRBG (TODO #96) — KAT, determinism, reseed separation, block limit, monobit  [NEW]")

	// Cross-language KAT (must match C/Go/Python suite outputs)
	ent := make([]byte, 32)
	for i := range ent {
		ent[i] = byte(i)
	}
	d := DrbgSeed(ent, []byte("HDRBG-KAT"))
	out, _ := d.DrbgGenerate(80)
	okKat := fmt.Sprintf("%x", out) ==
		"cd3e576bee89501a3760fb96fc05b6a3029c26f405e8667c71f311fc39ab1b23"+
			"90620f2641a2a2dabf28cf35ae991d6b9fc254509a7720de24cbd9c603cd718e"+
			"089ea95dc62208133b3475fadb10ef6d"
	re := make([]byte, 16)
	for i := range re {
		re[i] = 0xa5
	}
	d.DrbgReseed(re)
	out2, _ := d.DrbgGenerate(32)
	okKat = okKat && fmt.Sprintf("%x", out2) ==
		"bd5324b039a98172fae214390fe9bcc928f3bd65231213efd9162664b5e756bf"

	// Determinism + personalization divergence + reseed separation
	d1 := DrbgSeed([]byte("ent-A"), []byte("p1"))
	d2 := DrbgSeed([]byte("ent-A"), []byte("p1"))
	d3 := DrbgSeed([]byte("ent-A"), []byte("p2"))
	s1, _ := d1.DrbgGenerate(64)
	s2, _ := d2.DrbgGenerate(64)
	s3, _ := d3.DrbgGenerate(64)
	okDet := bytes.Equal(s1, s2) && !bytes.Equal(s1, s3)
	d2.DrbgReseed([]byte("fresh"))
	s4, _ := d2.DrbgGenerate(64)
	s5, _ := d1.DrbgGenerate(64)
	okDet = okDet && !bytes.Equal(s4, s5)

	// Block-limit enforcement: 2 blocks requested with 1 remaining
	d4 := DrbgSeed([]byte("ent-limit"), nil)
	d4.Blocks = DrbgMaxBlocks - 1
	_, okOver := d4.DrbgGenerate(64)
	_, okLast := d4.DrbgGenerate(32)
	okLimit := !okOver && okLast

	// Monobit sanity on 8 KiB of output
	d5 := DrbgSeed([]byte("ent-monobit"), nil)
	stream, _ := d5.DrbgGenerate(8192)
	ones := 0
	for _, b := range stream {
		ones += bits.OnesCount8(b)
	}
	frac := float64(ones) / float64(8192*8)
	okMono := frac >= 0.48 && frac <= 0.52

	status := "PASS"
	if !okKat || !okDet || !okLimit || !okMono {
		status = "FAIL"
	}
	p := func(b bool) string {
		if b {
			return "PASS"
		}
		return "FAIL"
	}
	fmt.Printf("    kat=%s  determinism=%s  block_limit=%s  monobit=%.2f%%  [%s]\n\n",
		p(okKat), p(okDet), p(okLimit), frac*100, status)
}

func testWotsXmss() {
	const xmssH = 3 // 8 leaves; production uses h=10
	N := testRounds(3)
	okSign, okTamper, okReuse, okRangeReject := 0, 0, 0, 0
	fmt.Printf("[30] HPKS-WOTS-F / HPKS-XMSS-F sign+verify (h=%d)  [PQC]\n", xmssH)
	t0 := time.Now()
	for i := 0; i < N; i++ {
		seed := make([]byte, 32)
		for j := range seed { seed[j] = byte(mrand.Intn(256)) }
		kp   := HpksXmssKeygen(seed, xmssH)
		msg  := []byte("HPKS-XMSS-F security test")
		sig0, err0 := HpksXmssSign(msg, kp, 0)
		sig1, err1 := HpksXmssSign(msg, kp, 1)
		if err0 == nil && err1 == nil &&
			HpksXmssVerify(msg, sig0, kp.Root) && HpksXmssVerify(msg, sig1, kp.Root) {
			okSign++
		}
		if err0 == nil && !HpksXmssVerify([]byte("tampered"), sig0, kp.Root) {
			okTamper++
		}
		if err0 == nil && !HpksXmssVerify([]byte("different message"), sig0, kp.Root) {
			okReuse++
		}
		// TODO #262: an out-of-range leaf index (negative, or >= the tree
		// size) must be rejected by HpksXmssSign itself rather than
		// silently narrowed by uint32(leafIdx) into an in-range, already-
		// used leaf -- that would be WOTS key reuse.
		_, errNeg := HpksXmssSign(msg, kp, -1)
		_, errHigh := HpksXmssSign(msg, kp, len(kp.LeafHashes))
		if errNeg != nil && errHigh != nil {
			okRangeReject++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if okSign != N || okTamper != N || okReuse != N || okRangeReject != N { status = "FAIL" }
	fmt.Printf("    sign_ok=%d/%d  tamper_reject=%d/%d  reuse_reject=%d/%d  range_reject=%d/%d  [%s]\n\n",
		okSign, N, okTamper, N, okReuse, N, okRangeReject, N, status)
}

func testHpkst() {
	const tN = 3
	N := testRounds(3)
	okSign, okTamper := 0, 0
	fmt.Printf("[31] HPKS-T  %d-of-%d threshold Schnorr over GF(2^n)*  [CLASSICAL]\n", tN, tN)
	t0 := time.Now()
	msg := []byte("HPKS-T threshold security test!")
	for i := 0; i < N; i++ {
		secrets := make([]*big.Int, tN)
		pubkeys := make([]*big.Int, tN)
		gGen    := big.NewInt(3)
		poly    := GfPoly[256]
		for j := 0; j < tN; j++ {
			kb := make([]byte, 32)
			for k := range kb { kb[k] = byte(mrand.Intn(256)) }
			secrets[j] = new(big.Int).SetBytes(kb)
			pubkeys[j] = GfPow(gGen, secrets[j], poly, 256)
		}
		cAgg, R, s := HpkstSign(secrets, pubkeys, msg)
		if HpkstVerify(cAgg, R, s, msg) {
			okSign++
		}
		sBad := new(big.Int).Xor(s, big.NewInt(1))
		if !HpkstVerify(cAgg, R, sBad, msg) {
			okTamper++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if okSign != N || okTamper != N { status = "FAIL" }
	fmt.Printf("    sign_ok=%d/%d  tamper_reject=%d/%d  [%s]\n\n",
		okSign, N, okTamper, N, status)
}

// ---------------------------------------------------------------------------
// Failure aggregation (TODO #233)
//
// Until v3.0.8 this harness printed "[PASS]"/"[FAIL]" and exited 0 either way,
// so a failing security test could not fail its CI job: `native-go` was a
// required, blocking check that went green whenever a test failed -- it had no
// os.Exit call at all.  The same was true of the C and Python harnesses.
//
// The aggregate status is read off the printed output rather than threaded out
// of each of the ~141 fmt.Print* sites.  That is deliberate: this harness's
// contract *is* its output, the marker format is uniform, and swapping the
// file descriptor cannot be forgotten by whoever adds test [46] -- rewriting
// every call site to a checking helper can be, and would then regress the gate
// in silence, which is exactly the failure mode being fixed.
// ---------------------------------------------------------------------------

var (
	gFailures  int
	gFailLines []string
)

const gFailKeep = 32

// captureStdout redirects os.Stdout through a pipe, scanning every line that
// passes for a failure marker before relaying it to the real stdout.  The
// returned func restores os.Stdout and blocks until the relay has drained.
func captureStdout() func() {
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		// Without a pipe there is no gate; say so rather than exiting 0 on a
		// silent downgrade.
		fmt.Fprintf(os.Stderr, "WARNING: stdout capture failed (%v); "+
			"[FAIL] markers will not be gated\n", err)
		return func() {}
	}
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				if strings.Contains(line, "[FAIL]") ||
					strings.Contains(line, "FAIL (accepted!)") {
					gFailures++
					if len(gFailLines) < gFailKeep {
						gFailLines = append(gFailLines,
							strings.TrimSpace(line))
					}
				}
				fmt.Fprint(real, line)
			}
			if err != nil {
				return
			}
		}
	}()
	return func() {
		os.Stdout = real
		w.Close()
		<-done
		r.Close()
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
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

	restore := captureStdout()

	fmt.Println("=== Herradura KEx v1.9.35 — Security & Performance Tests (Go) ===")
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

	fmt.Println("--- Security Tests: Code-Based PQC (Stern-F) ---\n")
	testHpksSternFCorrectness()
	testHpkeSternFCorrectness()

	fmt.Println("--- Security Tests: Hash (HFSCX-256) ---\n")
	testHfscx256KAV()

	fmt.Println("--- Security Tests: Code-Based PQC (Ring Signatures) ---\n")
	testHpksSternRingCorrectness()

	fmt.Println("--- Security Tests: ZKP (Ring-LWR Sigma + NL-FSCX ZKBoo) ---\n")
	testZkpRnlCorrectness()
	testZkpNlCorrectness()

	fmt.Println("--- Security Tests: FPE / Tweakable / Accumulator (78.A/B/J) ---\n")
	testFpeCorrectness()
	testTwkCorrectness()
	testAccumulatorCorrectness()

	fmt.Println("--- Security Tests: Masking / Ratchet (78.H/C) ---\n")
	testMaskedHske()
	testRatchetForwardSecrecy()
	testHskeNlAead()
	testHdrbg()
	testWotsXmss()
	testHpkst()

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
	benchHpksSternF()
	benchZkpRnl()
	benchZkpNl()
	testHcred()
	testWeakKeyRejection()
	testFpeTwkDomainSeparation()
	testNlFscxV3()
	testNlFscxV3Consumers()
	testRnlMBlindGuard()
	testHcredKkw()
	testQcmdpcWeakKeyScreen()

	// Failure gate (TODO #233).  Exit non-zero if any check reported [FAIL],
	// so that `native-go` can actually fail.  There is no allow-list: the C
	// harness's banner used to describe [4] "Bit-frequency bias" as an
	// "expected FAIL", but [4] passes in all three languages (FSCX(A,B) over
	// random A is bit-balanced; what is not PRF-like about FSCX is its
	// 3-bits-per-flip diffusion, which is test [2]'s job).  That banner line
	// has been corrected rather than encoded here as an exemption.
	restore()
	if gFailures > 0 {
		fmt.Printf("\n*** FAILED: %d check(s) reported [FAIL] ***\n", gFailures)
		for _, line := range gFailLines {
			fmt.Printf("    %s\n", line)
		}
		if gFailures > len(gFailLines) {
			fmt.Printf("    ... and %d more\n", gFailures-len(gFailLines))
		}
		os.Exit(1)
	}
	fmt.Println("\n*** OK: no check reported [FAIL] ***")
}

// Security test [44]: HCRED hybrid credential.  Appended after the benchmarks
// to avoid renumbering [32]-[43] across all three languages (TODO #128
// Batch 4); same number and checks in C, Go, and Python.
func testHcred() {
	fmt.Println("[44] HCRED hybrid credential: completeness + tamper/replay rejection  [PQC-EXT]")
	n := 32
	N := testRounds(3)
	R := 4
	okVerify, okReplay, okSynd, okKey, okSplit, okCred := 0, 0, 0, 0, 0, 0
	t0 := time.Now()
	mBase := RnlMPoly(n)
	for i := 0; i < N; i++ {
		aRand := RnlRandPoly(n, RnlQ)
		mB := RnlPolyAdd(mBase, aRand, RnlQ)
		seedH := NewRandBitArray(n)
		s, C, e := HcredUserKeygen(mB, n)
		y := HcredSyndrome(seedH, e, n)
		proof, err := HcredProve(s, mB, C, seedH, y, n, R, zkpMsg)
		if err != nil {
			N = i + 1
			break
		}
		if HcredVerify(mB, C, seedH, y, proof, n, R, zkpMsg) {
			okVerify++
		}
		if !HcredVerify(mB, C, seedH, y, proof, n, R, zkpMsg2) {
			okReplay++
		}
		yBad := new(big.Int).Xor(y, big.NewInt(1))
		if !HcredVerify(mB, C, seedH, yBad, proof, n, R, zkpMsg) {
			okSynd++
		}
		s2, C2, _ := HcredUserKeygen(mB, n)
		_ = s2
		if !HcredVerify(mB, C2, seedH, y, proof, n, R, zkpMsg) {
			okKey++
		}
		// Split witness: s2 satisfies C2 but not this y — prove must refuse.
		if _, err2 := HcredProve(s2, mB, C2, seedH, y, n, R, zkpMsg); err2 != nil {
			okSplit++
		}
		// Issuer binding round-trip (Stern-F signature over (m,C,seed_H,y)).
		isd, ie, isyn := SternFKeygen(n)
		cred := HcredIssue(mB, C, seedH, y, n, ie, isd, 8)
		if HcredCredVerify(mB, C, seedH, y, n, cred, isd, isyn) {
			okCred++
		}
		if timeExceeded(t0) {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if okVerify != N || okReplay != N || okSynd != N || okKey != N ||
		okSplit != N || okCred != N {
		status = "FAIL"
	}
	fmt.Printf("    n=%d R=%d  verify=%d/%d  replay_reject=%d/%d"+
		"  synd_reject=%d/%d  key_reject=%d/%d  split_refuse=%d/%d"+
		"  cred=%d/%d  [%s]\n",
		n, R, okVerify, N, okReplay, N, okSynd, N, okKey, N,
		okSplit, N, okCred, N, status)
	fmt.Println()
}

// Security test [45]: weak-key & malformed-input rejection.  Appended
// after [44] to avoid renumbering (same number in C/Go/Python; TODO #131).
// Exercises the guarded protocol-level API (GfPubIsValid/HkexGfAgree/
// HpksVerify/HpkeEncrypt/HpkeDecrypt) added to herradura/herradura.go by
// TODO #144, rather than local test-only duplicates.
// [46] fpe/twk domain separation (TODO #242). The two primitives shared an
// unseparated HFSCX-256(key || tweak) subkey derivation until v4.0.0, so a
// 12-byte fpe context equal to twk's sector_be64 || bidx_be32 made them the
// identical function. Regression guard: they must differ on exactly that input,
// and the key/tweak boundary must be length-encoded.
func testFpeTwkDomainSeparation() {
	fmt.Println("[46] fpe/twk domain separation + no cross-primitive collision  [SECURITY]")
	N := testRounds(200)
	coll, amb := 0, 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		P := NewRandBitArray(256)
		key := NewRandBitArray(256).Bytes()
		sector := binary.BigEndian.Uint64(NewRandBitArray(64).Bytes())
		bidx := binary.BigEndian.Uint32(NewRandBitArray(32).Bytes())
		ctx := make([]byte, 12)
		binary.BigEndian.PutUint64(ctx, sector)
		binary.BigEndian.PutUint32(ctx[8:], bidx)
		if FpeEncrypt(P, key, ctx).Equal(TwkEncrypt(P, key, sector, bidx)) {
			coll++
		}
		if FpeEncrypt(P, key[:2], key[2:3]).Equal(FpeEncrypt(P, key[:1], key[1:3])) {
			amb++
		}
		if gTimeLimit > 0 && i&63 == 63 && time.Since(t0) >= gTimeLimit {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if coll != 0 || amb != 0 {
		status = "FAIL"
	}
	fmt.Printf("    n=%d  fpe/twk collisions=%d  key-boundary collisions=%d  [%s]\n\n",
		N, coll, amb, status)
}

// [47] NL-FSCX v3 primitive (TODO #255). Four properties, each of which the
// design rests on and none of which is implied by the others:
//
//	(a) the chi layer matches a straightforward per-row reference;
//	(b) chi^-1 . chi == id, and the revolve round-trips at R3Value -- chi
//	    being a bijection on ODD rows is what makes the layer invertible;
//	(c) the row partition is legal: every row odd and >= 5, summing to the
//	    key width.  A 3-row would be a complete break (§11.33.4), so this is
//	    a security assertion, not a bookkeeping one;
//	(d) v3 differs from v2 at the same round count -- a guard against a chi
//	    layer that silently degenerates to the identity.
func testNlFscxV3() {
	fmt.Println("[47] NL-FSCX v3: chi vs reference, invertibility, partition  [SECURITY]")
	N := testRounds(200)
	rows := V3Rows(256)
	rowsum, badrow := 0, 0
	for _, L := range rows {
		if L < 5 || L%2 == 0 {
			badrow++
		}
		rowsum += L
	}
	badRef, badInv, badRT, sameAsV2 := 0, 0, 0, 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		P := NewRandBitArray(256)
		K := NewRandBitArray(256)
		// (a) chi against a per-row reference
		C := NlChiV3(P)
		ref := new(big.Int)
		off := 0
		for _, L := range rows {
			for j := 0; j < L; j++ {
				bi := P.Val.Bit(off + j)
				b1 := P.Val.Bit(off + (j+1)%L)
				b2 := P.Val.Bit(off + (j+2)%L)
				ref.SetBit(ref, off+j, bi^((1-b1)&b2))
			}
			off += L
		}
		if ref.Cmp(&C.Val) != 0 {
			badRef++
		}
		// (b) invertibility
		if NlChiV3Inv(C).Val.Cmp(&P.Val) != 0 {
			badInv++
		}
		Y := NlFscxRevolveV3(P, K, R3Value)
		if NlFscxRevolveV3Inv(Y, K, R3Value).Val.Cmp(&P.Val) != 0 {
			badRT++
		}
		// (d) v3 != v2
		if NlFscxRevolveV2(P, K, R3Value).Val.Cmp(&Y.Val) == 0 {
			sameAsV2++
		}
		if gTimeLimit > 0 && i&63 == 63 && time.Since(t0) >= gTimeLimit {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if rowsum != 256 || badrow != 0 || badRef != 0 || badInv != 0 || badRT != 0 || sameAsV2 != 0 {
		status = "FAIL"
	}
	fmt.Printf("    n=%d  R3Value=%d  rows=%d sum=%d illegal=%d  chi!=ref=%d"+
		"  chi-inv fails=%d  revolve round-trip fails=%d  v3==v2=%d  [%s]\n\n",
		N, R3Value, len(rows), rowsum, badrow, badRef, badInv, badRT, sameAsV2, status)
}

// [48] The NL-FSCX v3 consumers (TODO #255).  [47] pins the primitive; this
// pins the five constructions on top of it, and every check is a property the
// primitive alone does not give you:
//
//	(a) each consumer round-trips.  A wrong round count still round-trips;
//	    a wrong INVERSE round count does not;
//	(b) each v3 consumer differs from its v2 counterpart on the same inputs
//	    -- the domain-separation assertion.  A copy-paste that reused v2's
//	    DS strings or tags would still round-trip;
//	(c) fpe --v3 and twk --v3 disagree at a 12-BYTE CONTEXT, the exact shape
//	    of the TODO #241 bug (§11.24.4) where the v2 pair were literally the
//	    same function whenever ctx == sector||bidx.  [46] guards the v2 pair;
//	(d) the duplex rejects a flipped AD.
func testNlFscxV3Consumers() {
	fmt.Println("[48] NL-FSCX v3 consumers: round-trip, v2 separation, AEAD  [SECURITY]")
	N := testRounds(100)
	const sector uint64 = 0x0123456789ABCDEF
	const bidx uint32 = 0x00C0FFEE
	tw12 := make([]byte, 12)
	binary.BigEndian.PutUint64(tw12, sector)
	binary.BigEndian.PutUint32(tw12[8:], bidx)

	badRT, sameAsV2, fpeEqTwk, forged := 0, 0, 0, 0
	t0 := time.Now()
	for i := 0; i < N; i++ {
		P := NewRandBitArray(256)
		K := NewRandBitArray(256)
		nonce := NewRandBitArray(256)
		pt := make([]byte, 40)
		for j := range pt {
			pt[j] = P.Bytes()[j%32] ^ byte(j)
		}

		// hske-nla3
		E3 := NlFscxRevolveV3(P, K, R3Value)
		if NlFscxRevolveV3Inv(E3, K, R3Value).Val.Cmp(&P.Val) != 0 {
			badRT++
		}
		if NlFscxRevolveV2(P, K, 3*256/4).Val.Cmp(&E3.Val) == 0 {
			sameAsV2++
		}

		// hske-duplex3
		ct, tag := HskeNlV3DuplexEncrypt(K, nonce, []byte("ad"), pt)
		if got, ok := HskeNlV3DuplexDecrypt(K, nonce, []byte("ad"), ct, tag); !ok ||
			!bytes.Equal(got, pt) {
			badRT++
		}
		if _, ok := HskeNlV3DuplexDecrypt(K, nonce, []byte("AD"), ct, tag); ok {
			forged++
		}
		ct2, _ := HskeNlV2DuplexEncrypt(K, nonce, []byte("ad"), pt)
		if bytes.Equal(ct2, ct) {
			sameAsV2++
		}

		// fpe --v3 / twk --v3, and the 12-byte-context collision (c)
		keyB := K.Bytes()
		F3 := FpeV3Encrypt(P, keyB, tw12)
		if FpeV3Decrypt(F3, keyB, tw12).Val.Cmp(&P.Val) != 0 {
			badRT++
		}
		if FpeEncrypt(P, keyB, tw12).Val.Cmp(&F3.Val) == 0 {
			sameAsV2++
		}
		T3 := TwkV3Encrypt(P, keyB, sector, bidx)
		if TwkV3Decrypt(T3, keyB, sector, bidx).Val.Cmp(&P.Val) != 0 {
			badRT++
		}
		if TwkEncrypt(P, keyB, sector, bidx).Val.Cmp(&T3.Val) == 0 {
			sameAsV2++
		}
		if F3.Val.Cmp(&T3.Val) == 0 {
			fpeEqTwk++
		}

		if gTimeLimit > 0 && i&63 == 63 && time.Since(t0) >= gTimeLimit {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if badRT != 0 || sameAsV2 != 0 || fpeEqTwk != 0 || forged != 0 {
		status = "FAIL"
	}
	fmt.Printf("    n=%d  round-trip fails=%d  v3==v2=%d  fpe-v3==twk-v3 at "+
		"12-byte ctx=%d  AEAD forgeries=%d  [%s]\n\n",
		N, badRT, sameAsV2, fpeEqTwk, forged, status)
}

// [49] The HKEX-RNL peer-m_blind substitution guard (TODO #261).  m_blind is
// chosen by the INITIATOR and its uniformity rests entirely on that party's RNG
// (TODO #89), so the responder cannot verify the draw -- it can only reject the
// degenerate shapes that break the construction outright: a sparse m_blind makes
// C = round_p(m_blind*s) leak s almost directly, and a clustered one collapses
// the rounding noise the hardness argument depends on.  Untested in all four
// languages until TODO #261.  (a) is the accept-control: a guard that rejects
// everything would otherwise score a perfect pass on (b)-(e).
func testRnlMBlindGuard() {
	fmt.Println("[49] HKEX-RNL peer-m_blind substitution guard  [SECURITY]")
	const n = 256
	N := testRounds(50)
	badAccept, badReject, nRun := 0, 0, 0
	for i := 0; i < N; i++ {
		nRun++
		// (a) accept-control: a genuine uniform draw must pass.
		if !RnlValidateMBlind(RnlRandPoly(n, RnlQ), RnlQ) {
			badReject++
		}
		// (b) the all-zero polynomial.
		if RnlValidateMBlind(make([]int, n), RnlQ) {
			badAccept++
		}
		// (c) sparse: n/8 non-zero, full range -- isolates the count bound.
		sparse := make([]int, n)
		for j := 0; j < n/8; j++ {
			sparse[j] = RnlQ - 1
		}
		if RnlValidateMBlind(sparse, RnlQ) {
			badAccept++
		}
		// (d) clustered: all non-zero but inside [1, q/8) -- isolates the
		//     range bound.
		clustered := make([]int, n)
		for j := range clustered {
			clustered[j] = 1 + mrand.Intn(RnlQ/8-1)
		}
		if RnlValidateMBlind(clustered, RnlQ) {
			badAccept++
		}
		// (e) the count boundary, both sides.  Range is full in both, so only
		//     the non-zero count decides.
		for _, tc := range []struct {
			nz   int
			want bool
		}{{n / 4, true}, {n/4 - 1, false}} {
			poly := make([]int, n)
			for j := 0; j < tc.nz; j++ {
				poly[j] = RnlQ - 1
			}
			if got := RnlValidateMBlind(poly, RnlQ); got != tc.want {
				if got {
					badAccept++
				} else {
					badReject++
				}
			}
		}
	}
	ok := badAccept == 0 && badReject == 0
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
	}
	fmt.Printf("    n=%d  bad accepts=%d  bad rejects=%d  [%s]\n\n",
		nRun, badAccept, badReject, verdict)
}

// [50] HCRED-KKW prove/verify and its rejection axes (TODO #266).
//
// KKW shipped in all four languages under TODO #261 verified only
// STRUCTURALLY -- round-trips plus rejection checks written by hand during each
// port and then thrown away.  Three of the four ports carried a real
// transcription bug found that way, THIS ONE INCLUDED: the "reveal aux when
// party N-1 is opened" condition was inverted here on the first pass, and every
// genuine proof failed verification until a fail-point-tagged debug run
// isolated it.  Nothing kept that check.  KAT/hcred_kkw.json now pins the
// VERIFY side across all four languages; this is the PROVE side, which a
// consume-only vector cannot reach by construction.
//
// (a) is the accept-control: without it a verifier that refused everything
// would score a perfect 6/6 on the rejection axes below.
func testHcredKkw() {
	fmt.Println("[50] HCRED-KKW prove/verify + rejection axes  [PQC-EXT]")
	const n = 32
	const nPar, m, tau = 4, 4, 2 // demo params; production is (64, 343, 27)
	N := testRounds(1)
	msg := []byte("HCRED-KKW test [50]")
	nRun, okVerify := 0, 0
	names := []string{"wrong_msg", "flip_W", "flip_u", "flip_t",
		"flip_pre_root", "relabel_pbar"}
	rejected := map[string]int{}

	for i := 0; i < N; i++ {
		nRun++
		mB := RnlPolyAdd(RnlMPoly(n), RnlRandPoly(n, RnlQ), RnlQ)
		seedH := NewRandBitArray(n)
		s, c, eInt := HcredUserKeygen(mB, n)
		y := HcredSyndrome(seedH, eInt, n)
		p, err := HcredProveKkw(s, mB, c, seedH, y, n, nPar, m, tau, msg)
		if err != nil {
			fmt.Printf("    prove error: %v  [FAIL]\n\n", err)
			return
		}
		// (a) accept-control.
		if HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			okVerify++
		}
		// (b)-(g) the six axes, the same set KAT/hcred_kkw.json's tamper table
		// applies -- so a divergence between this and the vector is itself
		// visible rather than two independent opinions about what to check.
		e0, r0 := -1, -1
		for k := range p.Online {
			if e0 < 0 || k < e0 {
				e0 = k
			}
		}
		for k := range p.Pre {
			if r0 < 0 || k < r0 {
				r0 = k
			}
		}
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, append(append([]byte{}, msg...), '!')) {
			rejected["wrong_msg"]++
		}
		// Each case rebuilds from the same proof and restores after, so a
		// mutation never leaks into the next axis.
		origW := p.W
		p.W++
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			rejected["flip_W"]++
		}
		p.W = origW

		origU := p.Online[e0].U
		p.Online[e0].U = (origU + 1) % RnlQ
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			rejected["flip_u"]++
		}
		p.Online[e0].U = origU

		origT := p.Online[e0].T[0]
		p.Online[e0].T[0] = (origT + 1) % RnlQ
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			rejected["flip_t"]++
		}
		p.Online[e0].T[0] = origT

		p.Pre[r0][0] ^= 1
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			rejected["flip_pre_root"]++
		}
		p.Pre[r0][0] ^= 1

		origPbar := p.Online[e0].Pbar
		p.Online[e0].Pbar = (origPbar + 1) % nPar
		if !HcredVerifyKkw(mB, c, seedH, y, p, n, msg) {
			rejected["relabel_pbar"]++
		}
		p.Online[e0].Pbar = origPbar
	}

	ok := nRun > 0 && okVerify == nRun
	miss := ""
	for _, k := range names {
		if rejected[k] != nRun {
			ok = false
			if miss != "" {
				miss += ","
			}
			miss += k
		}
	}
	if miss == "" {
		miss = "none"
	}
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
	}
	fmt.Printf("    n=%d  verified=%d/%d  rejections missed=%s  "+
		"(N=%d, M=%d, tau=%d)  [%s]\n\n",
		nRun, okVerify, nRun, miss, nPar, m, tau, verdict)
}

// [51] The QC-MDPC weak-key screen (TODO #261).  QcMdpcKeyIsStrong rejects and
// redraws any private polynomial whose cyclic distance spectrum has a
// multiplicity above 5 -- the screen TODO #235 Part 1 added to make the entire
// measured DFR tail unreachable from keygen.  Until TODO #261 it was UNTESTED IN
// ALL FOUR LANGUAGES: it is called only from QcMdpcKeygen, so nothing in
// CryptosuiteTests/, SelfTest.java or CliTest/ ever exercised it, and a screen
// that accepted everything would have passed the entire repo -- the same
// four-way absence #261 found for RnlValidateMBlind before it became test [49].
//
// SCOPE: the screen covers KEYGEN only.  No PEM decode path checks an imported
// key's spectrum, in any language, and that is a recorded position rather than
// an oversight -- a supplied arithmetic-progression key fails its own
// decapsulations, a self-inflicted denial of service and not a confidentiality
// break (SecurityProofsCode/qcmdpc_dfr_weak_keys.py section 4).
//
// The supports are PINNED, not sampled, so each case asserts a known answer
// rather than a probable one, and every one is exactly QcMdpcD = 15 elements
// because C's qcmdpc_key_is_strong takes a QcMdpcPriv whose support arrays are
// fixed at that width.  qcSupWrap is the interesting one: its run of
// consecutive positions straddles zero (519..522, 0..2), so its true
// multiplicity is 6 and it must be rejected -- but computed WITHOUT the
// min(d, r-d) cyclic fold the largest count is 5 and it would be accepted.  An
// implementation that dropped the fold passes every other case and fails only
// that one.
var (
	qcSupAP1  = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	qcSupAP35 = []int{0, 35, 70, 105, 140, 175, 210, 245, 280, 315, 350, 385, 420, 455, 490}
	// max multiplicity exactly 5 -- accepted, the boundary from below
	qcSupB5 = []int{0, 1, 2, 3, 4, 5, 122, 135, 203, 252, 254, 287, 406, 500, 515}
	// qcSupB5 with 135 replaced by 6: the run becomes {0..6}, multiplicity 6
	qcSupB6 = []int{0, 1, 2, 3, 4, 5, 6, 122, 203, 252, 254, 287, 406, 500, 515}
	// cyclic multiplicity 6, non-cyclic 5 -- the fold discriminator
	qcSupWrap = []int{0, 1, 2, 41, 265, 310, 394, 414, 430, 488, 497, 519, 520, 521, 522}
)

func testQcmdpcWeakKeyScreen() {
	fmt.Println("[51] QC-MDPC weak-key screen (distance spectrum)  [SECURITY]")
	N := testRounds(50)
	badAccept, badReject, nRun, wrapMissed := 0, 0, 0, 0
	for i := 0; i < N; i++ {
		nRun++
		// (a) accept-control.  Without it a screen that rejects EVERYTHING
		//     scores a perfect pass on (b)-(f).  qcSupB5 sits exactly on the
		//     threshold, so this is also the boundary from below.
		if !QcMdpcKeyIsStrong(qcSupB5, qcSupB5) {
			badReject++
		}
		// (b) the arithmetic progression the screen exists to reject.
		if QcMdpcKeyIsStrong(qcSupAP1, qcSupB5) {
			badAccept++
		}
		// (c) the same multiplicity at a non-unit step.
		if QcMdpcKeyIsStrong(qcSupAP35, qcSupB5) {
			badAccept++
		}
		// (d) the boundary from above -- one element moved from (a).
		if QcMdpcKeyIsStrong(qcSupB6, qcSupB5) {
			badAccept++
		}
		// (e) BOTH supports must be screened.  A predicate testing sup0 twice,
		//     or sup1 twice, passes (a)-(d) and fails exactly here.
		if QcMdpcKeyIsStrong(qcSupB5, qcSupB6) {
			badAccept++
		}
		// (f) the cyclic-distance discriminator, counted separately so a
		//     failure names its cause instead of incrementing a total.
		if QcMdpcKeyIsStrong(qcSupWrap, qcSupB5) {
			wrapMissed++
		}
	}
	// What keygen PRODUCES must be what the screen ACCEPTS -- no pinned vector
	// can assert that.
	keygenOK := 0
	for i := 0; i < 8; i++ {
		sup0, sup1, _, _, _ := QcMdpcKeygen(nil)
		if QcMdpcKeyIsStrong(sup0, sup1) {
			keygenOK++
		}
	}
	ok := badAccept == 0 && badReject == 0 && wrapMissed == 0 && keygenOK == 8
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
	}
	fmt.Printf("    n=%d  bad accepts=%d  bad rejects=%d  cyclic-fold misses=%d  "+
		"keygen accepted=%d/8  [%s]\n\n",
		nRun, badAccept, badReject, wrapMissed, keygenOK, verdict)
}

func testWeakKeyRejection() {
	fmt.Println("[45] Weak-key & malformed-input rejection (identity pubkey, " +
		"zero/degenerate elements, tampered syndrome/AEAD)  [SECURITY]")
	size := 256
	poly := GfPoly[size]
	sternN := 32
	N := testRounds(10)
	okHkex, okHpks, okHpke, okHpkeDec := 0, 0, 0, 0
	okAeadTamper, okAeadKeySwap := 0, 0
	okV2Weak := 0
	zero := newBA(size, big.NewInt(0))
	one := newBA(size, big.NewInt(1))

	// HPKS-Stern-F: an honestly-generated signature must be rejected when
	// verified against a corrupted (flipped-bit) syndrome.  This one runs on
	// its own fixed budget rather than N times, because it is the only check
	// here whose outcome is probabilistic (TODO #233): a bad syndrome is
	// caught only in the b=0 round, so a forgery slips through with
	// probability (2/3)^rounds per trial.  At the old rounds=8 that is 3.90%
	// -- measured 6/200 -- which made the whole of [45] fail 38.5% of the
	// time at N=10.  sternRounds=32 (matching the C harness's compile-time
	// SDF_ROUNDS) drops it to (2/3)^32 = 2.4e-6 -- ~8000x less likely to flake,
	// and cheaper in total too: 2.08s for sternTrials=2 against 2.86s for the
	// old ten (measured in the Python harness; Go is faster but same shape).
	const sternRounds, sternTrials = 32, 2
	okStern := 0
	for t := 0; t < sternTrials; t++ {
		seed, e, syndrome := SternFKeygen(sternN)
		msgS := randBA(sternN)
		sig := HpksSternFSign(msgS, e, seed, sternRounds)
		syndromeBad := new(big.Int).Xor(syndrome, big.NewInt(1))
		if HpksSternFVerify(msgS, sig, seed, syndrome) &&
			!HpksSternFVerify(msgS, sig, seed, syndromeBad) {
			okStern++
		}
	}

	// Start the -t budget *after* the Stern block, not before.  It is a fixed
	// two-trial cost, and charging it to the loop's cap let it consume the
	// whole 2.0s on a slow host -- observed once in the Python harness, as
	// "SKIP (no iterations completed)", which silently skipped this test's
	// seven other checks.  The loop now gets exactly the budget it had
	// before (TODO #233).
	t0 := time.Now()
	for i := 0; i < N; i++ {
		// HKEX-GF: a peer public key of 0 or 1 (identity) must be refused
		// before agreement -- either collapses the shared secret to a
		// constant independent of the caller's own private key.
		myPriv := randBA(size)
		if _, ok0 := HkexGfAgree(myPriv, zero, poly, size); !ok0 {
			if _, ok1 := HkexGfAgree(myPriv, one, poly, size); !ok1 {
				okHkex++
			}
		}

		// HPKS: an attacker who picks s at random and sets R=g^s can make
		// any (msg, pub=identity) triple satisfy the raw Schnorr equation.
		// The hardened verifier must reject pub in {0, 1} regardless.
		sForged := randBA(size)
		g := big.NewInt(GfGen)
		rForged := newBA(size, GfPow(g, &sForged.Val, poly, size))
		msg := randBA(size)
		if !HpksVerify(msg, zero, rForged, sForged, poly, size) &&
			!HpksVerify(msg, one, rForged, sForged, poly, size) {
			okHpks++
		}

		// HPKE: encrypt must refuse an identity/zero recipient pubkey.
		pt := randBA(size)
		if _, _, ok0 := HpkeEncrypt(pt, zero, poly, size); !ok0 {
			if _, _, ok1 := HpkeEncrypt(pt, one, poly, size); !ok1 {
				okHpke++
			}
		}

		// HPKE decrypt: an honestly-encrypted ct must still decrypt (sanity),
		// and decrypt must refuse a degenerate ephemeral R.
		priv := randBA(size)
		pub := newBA(size, GfPow(g, &priv.Val, poly, size))
		Rhonest, ct, _ := HpkeEncrypt(pt, pub, poly, size)
		dec, okDec := HpkeDecrypt(ct, Rhonest, priv, poly, size)
		_, okDecZero := HpkeDecrypt(ct, zero, priv, poly, size)
		_, okDecOne := HpkeDecrypt(ct, one, priv, poly, size)
		if okDec && dec.Val.Cmp(&pt.Val) == 0 && !okDecZero && !okDecOne {
			okHpkeDec++
		}

		// HSKE-NL-A1-AEAD: tampered ciphertext must fail the tag check, and
		// re-using the same (key, nonce) pair for a different plaintext must
		// produce a different tag/ciphertext (no silent keystream reuse).
		{
			aeadKey := NewRandBitArray(256)
			aeadNonce := NewRandBitArray(256)
			ptBytes := make([]byte, 256/8)
			pt2Bytes := make([]byte, 256/8)
			for j := range ptBytes {
				ptBytes[j] = byte(j ^ i)
				pt2Bytes[j] = byte(j ^ i ^ 0xFF)
			}
			ctBuf, tag := HskeNlAeadEncrypt(aeadKey, aeadNonce, nil, ptBytes)
			ctBad := append([]byte{ctBuf[0] ^ 1}, ctBuf[1:]...)
			if _, ok := HskeNlAeadDecrypt(aeadKey, aeadNonce, nil, ctBad, tag); !ok {
				okAeadTamper++
			}
			ct2Buf, _ := HskeNlAeadEncrypt(aeadKey, aeadNonce, nil, pt2Bytes)
			if !bytes.Equal(ctBuf, ct2Buf) {
				okAeadKeySwap++
			}
		}

		// NL-FSCX v2 (TODO #168): keys with delta(K) in {0, 2^(n-1)} make
		// pi_K GF(2)-affine, collapsing HSKE-NL-A2/HPKE-NL to a linear map.
		// At n=256 that is every K divisible by 2^129, plus e.g. K=2^96.
		weak129 := NewBitArray(256, new(big.Int).Lsh(big.NewInt(1), 129))
		weak130 := NewBitArray(256, new(big.Int).Lsh(big.NewInt(1), 130))
		weak96 := NewBitArray(256, new(big.Int).Lsh(big.NewInt(1), 96))
		weakZero := NewBitArray(256, big.NewInt(0))
		goodKey := NewBitArray(256, new(big.Int).Or(&NewRandBitArray(256).Val, big.NewInt(1)))
		if !NlV2KeyIsValid(weak129) && !NlV2KeyIsValid(weak130) &&
			!NlV2KeyIsValid(weak96) && !NlV2KeyIsValid(weakZero) &&
			NlV2KeyIsValid(goodKey) {
			okV2Weak++
		}

		if timeExceeded(t0) {
			N = i + 1
			break
		}
	}
	status := "PASS"
	if okHkex != N || okHpks != N || okHpke != N || okHpkeDec != N ||
		okStern != sternTrials ||
		okAeadTamper != N || okAeadKeySwap != N || okV2Weak != N {
		status = "FAIL"
	}
	fmt.Printf("    n=%d  hkex_reject=%d/%d  hpks_id_reject=%d/%d"+
		"  hpke_enc_reject=%d/%d  hpke_dec_reject=%d/%d"+
		"  stern_synd_reject=%d/%d  aead_tamper_reject=%d/%d"+
		"  aead_reuse_distinct=%d/%d  v2_weak_key_reject=%d/%d  [%s]\n",
		N, okHkex, N, okHpks, N, okHpke, N, okHpkeDec, N,
		okStern, sternTrials, okAeadTamper, N, okAeadKeySwap, N, okV2Weak, N, status)
	fmt.Println()
}
