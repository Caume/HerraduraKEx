/*  Herradura KEx — Security & Performance Tests (Go) v1.9.42
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
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"math/bits"
	mrand "math/rand"
	"os"
	"strconv"
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
	t0 := time.Now()
	for i := 0; i < N; i++ {
		seed   := randBA(32)
		ePrime := SternRandError(32, 2)
		ct     := SternSyndrome(seed, ePrime)
		K      := SternHash(4, seed, ePrime)
		eDec, found := hpkeSternFBruteForce32(seed, ct)
		if found {
			KDec := SternHash(4, seed, eDec)
			if K.Equal(KDec) { ok++ }
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if ok != N { status = "FAIL" }
	fmt.Printf("    %d / %d decapsulated  [%s]\n\n", ok, N, status)
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
	fmt.Println("[31] FSCX throughput  [CLASSICAL]")
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
	fmt.Println("[32] HKEX-GF gf_pow throughput  [CLASSICAL]")
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
	fmt.Println("[33] HKEX-GF full handshake (4 GfPow calls)  [CLASSICAL]")
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
	fmt.Println("[34] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
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
	fmt.Println("[35] HPKE encrypt+decrypt round-trip (El Gamal + FscxRevolve)  [CLASSICAL]")
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
	fmt.Println("[36] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
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
	fmt.Println("[37] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
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
	fmt.Println("[38] HSKE-NL-A2 revolve-mode round-trip  [PQC-EXT]")
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
	fmt.Println("[39] HKEX-RNL handshake throughput  [PQC-EXT]")
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
	fmt.Printf("[40] HPKS-Stern-F sign+verify throughput  (N=n, rounds=%d)  [CODE-BASED PQC]\n", sdfTestRounds)
	for _, size := range sizes {
		seed, e, syn := SternFKeygen(size)
		msg := randBA(size)
		ops, elapsed := bench("", func() {
			sig := HpksSternFSign(msg, e, seed, sdfTestRounds)
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
			if timeExceeded(t0) { N = i + 1; break }
		}
		status := "PASS"
		if okVerify != N || okTamper != N { status = "FAIL" }
		fmt.Printf("    n=%3d  verify=%d/%d  tamper_reject=%d/%d  [%s]\n",
			n, okVerify, N, okTamper, N, status)
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
	fmt.Printf("[41] ZKP-RNL sign+verify throughput  (n=%d)  [PQC-EXT]\n", n)
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
	fmt.Printf("[42] ZKP-NL prove+verify throughput  (n=%d, rounds=%d)  [PQC-EXT]\n", n, rounds)
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
	okSign, okTamper, okReuse := 0, 0, 0
	fmt.Printf("[30] HPKS-WOTS-F / HPKS-XMSS-F sign+verify (h=%d)  [PQC]\n", xmssH)
	t0 := time.Now()
	for i := 0; i < N; i++ {
		seed := make([]byte, 32)
		for j := range seed { seed[j] = byte(mrand.Intn(256)) }
		kp   := HpksXmssKeygen(seed, xmssH)
		msg  := []byte("HPKS-XMSS-F security test")
		sig0 := HpksXmssSign(msg, kp, 0)
		sig1 := HpksXmssSign(msg, kp, 1)
		if HpksXmssVerify(msg, sig0, kp.Root) && HpksXmssVerify(msg, sig1, kp.Root) {
			okSign++
		}
		if !HpksXmssVerify([]byte("tampered"), sig0, kp.Root) {
			okTamper++
		}
		if !HpksXmssVerify([]byte("different message"), sig0, kp.Root) {
			okReuse++
		}
		if timeExceeded(t0) { N = i + 1; break }
	}
	status := "PASS"
	if okSign != N || okTamper != N || okReuse != N { status = "FAIL" }
	fmt.Printf("    sign_ok=%d/%d  tamper_reject=%d/%d  reuse_reject=%d/%d  [%s]\n\n",
		okSign, N, okTamper, N, okReuse, N, status)
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
}
