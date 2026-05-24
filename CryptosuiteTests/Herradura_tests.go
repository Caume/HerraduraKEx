/*  Herradura KEx — Security & Performance Tests (Go)
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
// Security test — HFSCX-256 hash known-answer vectors [17]
// ---------------------------------------------------------------------------

func testHfscx256KAV() {
	fmt.Println("[17] HFSCX-256 known-answer vectors  [NL-FSCX HASH]")
	expEmpty := []byte{
		0x75, 0xde, 0x75, 0xae, 0xff, 0xa8, 0xd6, 0xfb,
		0x3d, 0x56, 0x13, 0x4c, 0xb4, 0x0a, 0x3f, 0x18,
		0x75, 0x85, 0x79, 0x74, 0xe1, 0x97, 0xa6, 0x32,
		0xbb, 0xf4, 0x36, 0x16, 0x0e, 0xd9, 0x7a, 0x6b,
	}
	expA := []byte{
		0xe3, 0x7b, 0xd2, 0x0f, 0x15, 0xe0, 0x4f, 0x21,
		0xa0, 0x92, 0x1c, 0xf0, 0xa6, 0x66, 0xd2, 0x45,
		0x7b, 0xc2, 0xbc, 0xcf, 0xd7, 0xbd, 0x28, 0x22,
		0xe6, 0x71, 0xda, 0x24, 0xbd, 0xb8, 0x38, 0xa0,
	}
	exp33A := []byte{
		0x95, 0x1d, 0x82, 0x84, 0x2d, 0x31, 0x2b, 0x67,
		0xfa, 0x47, 0xd4, 0x81, 0x22, 0x03, 0x61, 0x22,
		0xa4, 0x5b, 0xbe, 0xfb, 0x0c, 0x1f, 0x42, 0xcd,
		0x4e, 0xbc, 0x07, 0xb5, 0xd7, 0xd8, 0x79, 0xf6,
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
// Security tests — Code-Based PQC (Stern-F) [18-19]
// ---------------------------------------------------------------------------

func testHpksSternFCorrectness() {
	fmt.Printf("[18] HPKS-Stern-F correctness: sign+verify  (N=256, t=16, rounds=%d)  [CODE-BASED PQC]\n", sdfTestRounds)
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
	fmt.Println("[19] HPKE-Stern-F correctness: encap+decap  (n=32, t=2, brute-force)  [CODE-BASED PQC]")
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

// ---------------------------------------------------------------------------
// Performance benchmarks [20-29]
// ---------------------------------------------------------------------------

func benchFscx() {
	fmt.Println("[20] FSCX throughput  [CLASSICAL]")
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
	fmt.Println("[21] HKEX-GF gf_pow throughput  [CLASSICAL]")
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
	fmt.Println("[22] HKEX-GF full handshake (4 GfPow calls)  [CLASSICAL]")
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
	fmt.Println("[23] HSKE round-trip: encrypt+decrypt  [CLASSICAL]")
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
	fmt.Println("[24] HPKE encrypt+decrypt round-trip (El Gamal + FscxRevolve)  [CLASSICAL]")
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
	fmt.Println("[25] NL-FSCX v1 revolve throughput (n/4 steps)  [PQC-EXT]")
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
	fmt.Println("[25b] NL-FSCX v2 revolve+inv throughput (r_val steps)  [PQC-EXT]")
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
	fmt.Println("[26] HSKE-NL-A1 counter-mode throughput  [PQC-EXT]")
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
	fmt.Println("[27] HSKE-NL-A2 revolve-mode round-trip  [PQC-EXT]")
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
	fmt.Println("[28] HKEX-RNL handshake throughput  [PQC-EXT]")
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
	fmt.Printf("[29] HPKS-Stern-F sign+verify throughput  (N=n, rounds=%d)  [CODE-BASED PQC]\n", sdfTestRounds)
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

	fmt.Println("=== Herradura KEx v1.8.0 — Security & Performance Tests (Go) ===")
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

	fmt.Println("--- Security Tests: HFSCX-256 Hash ---\n")
	testHfscx256KAV()

	fmt.Println("--- Security Tests: Code-Based PQC (Stern-F) ---\n")
	testHpksSternFCorrectness()
	testHpkeSternFCorrectness()

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
}
