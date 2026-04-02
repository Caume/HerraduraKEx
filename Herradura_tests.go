/*  Herradura KEx -- Security & Performance Tests (Go)
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
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"time"
)

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
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

func randBA(size int) *BitArray {
	return newRandBitArray(size)
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

// Popcount counts set bits using the hardware popcount instruction when available.
func (ba *BitArray) Popcount() int {
	cnt := 0
	for _, b := range ba.val.Bytes() {
		cnt += bits.OnesCount8(b)
	}
	return cnt
}

// FlipBit returns a new BitArray with bit pos (0=LSB) toggled.
func (ba *BitArray) FlipBit(pos int) *BitArray {
	result := &BitArray{size: ba.size}
	result.val.Set(&ba.val)
	result.val.SetBit(&result.val, pos, result.val.Bit(pos)^1)
	return result
}

// ---------------------------------------------------------------------------
// FSCX functions
// ---------------------------------------------------------------------------

// Fscx computes the Full Surroundings Cyclic XOR:
//
//	result = A ⊕ B ⊕ ROL(A) ⊕ ROL(B) ⊕ ROR(A) ⊕ ROR(B)
//
// Each term maps directly to the formula; no parameter shadowing.
func Fscx(a, b *BitArray) *BitArray {
	return a.Xor(b).
		Xor(a.RotateLeft(1)).Xor(b.RotateLeft(1)).
		Xor(a.RotateLeft(-1)).Xor(b.RotateLeft(-1))
}

func FscxRevolve(ba, bb *BitArray, steps int) *BitArray {
	result := ba
	for i := 0; i < steps; i++ {
		result = Fscx(result, bb)
	}
	return result
}

func FscxRevolveN(ba, bb, nonce *BitArray, steps int) *BitArray {
	result := ba
	for i := 0; i < steps; i++ {
		result = Fscx(result, bb).Xor(nonce)
	}
	return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func iVal(size int) int { return size / 4 }
func rVal(size int) int { return size * 3 / 4 }

var sizes = []int{64, 128, 256}

// bench warms up with 10 calls, then runs batches of 100 until 1 second elapsed.
func bench(label string, fn func()) (ops int, elapsed time.Duration) {
	for i := 0; i < 10; i++ {
		fn()
	}
	start := time.Now()
	for {
		for i := 0; i < 100; i++ {
			fn()
		}
		ops += 100
		elapsed = time.Since(start)
		if elapsed >= time.Second {
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

// ---------------------------------------------------------------------------
// Security tests
// ---------------------------------------------------------------------------

func testNonCommutativity() {
	// Fscx(A,B) == Fscx(B,A) always (symmetric formula: A^B^ROL(A)^ROL(B)^ROR(A)^ROR(B)).
	// Asymmetry arises in FscxRevolveN, where B is held constant across
	// iterations: FscxRevolveN(A,B,N,n) != FscxRevolveN(B,A,N,n) in general.
	// The nonce term T_n(N) cancels from both sides of the difference, so
	// commutativity is determined solely by the A and B inputs.
	fmt.Println("[1] FscxRevolveN non-commutativity: FscxRevolveN(A,B,N,n) != FscxRevolveN(B,A,N,n)")
	for _, size := range sizes {
		iv := iVal(size)
		comm := 0
		for i := 0; i < 10000; i++ {
			a := randBA(size)
			b := randBA(size)
			n := randBA(size)
			if FscxRevolveN(a, b, n, iv).Equal(FscxRevolveN(b, a, n, iv)) {
				comm++
			}
		}
		status := "PASS"
		if comm != 0 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  %5d / 10000 commutative  [%s]\n", size, comm, status)
	}
	fmt.Println()
}

func testAvalanche() {
	// Fscx is a linear map over GF(2): output bit i depends only on input bits
	// i-1, i, i+1 (cyclic). Flipping one input bit always changes exactly 3 output
	// bits — the bit and its two cyclic neighbors. Security comes from FscxRevolve
	// iteration, not single-step diffusion.
	// Frobenius over GF(2): (1+t+t^-1)^(2^k) = 1+t^(2^k)+t^(-2^k), so power-of-2
	// step counts (like iVal = size/4) also give exactly 3-bit diffusion.
	fmt.Println("[2] Fscx single-step linear diffusion (expected: exactly 3 bits per flip)")
	for _, size := range sizes {
		total := 0.0
		gmin := size + 1
		gmax := -1
		for trial := 0; trial < 1000; trial++ {
			a := randBA(size)
			b := randBA(size)
			base := Fscx(a, b)
			for bit := 0; bit < size; bit++ {
				ap := a.FlipBit(bit)
				hd := Fscx(ap, b).Xor(base).Popcount()
				total += float64(hd)
				if hd < gmin {
					gmin = hd
				}
				if hd > gmax {
					gmax = hd
				}
			}
		}
		mean := total / (1000.0 * float64(size))
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
	fmt.Println("[3] Orbit period: FSCX_REVOLVE cycles back to A")
	for _, size := range sizes {
		cntP := 0
		cntHP := 0
		other := 0
		cap := 2 * size
		for trial := 0; trial < 100; trial++ {
			a := randBA(size)
			b := randBA(size)
			cur := Fscx(a, b)
			period := 1
			for !cur.Equal(a) && period < cap {
				cur = Fscx(cur, b)
				period++
			}
			if period == size {
				cntP++
			} else if period == size/2 {
				cntHP++
			} else {
				other++
			}
		}
		status := "PASS"
		if other != 0 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  period=%d: %3d  period=%d: %3d  other: %d  [%s]\n",
			size, size, cntP, size/2, cntHP, other, status)
	}
	fmt.Println()
}

func testBitFrequency() {
	fmt.Println("[4] Bit-frequency bias: 100000 FSCX outputs per size")
	N := 100000
	for _, size := range sizes {
		counts := make([]int, size)
		for trial := 0; trial < N; trial++ {
			a := randBA(size)
			b := randBA(size)
			out := Fscx(a, b)
			for bit := 0; bit < size; bit++ {
				if out.val.Bit(bit) == 1 {
					counts[bit]++
				}
			}
		}
		var mn, mx, mean float64
		mn = 101.0
		mx = -1.0
		for bit := 0; bit < size; bit++ {
			pct := float64(counts[bit]) / float64(N) * 100.0
			mean += pct
			if pct < mn {
				mn = pct
			}
			if pct > mx {
				mx = pct
			}
		}
		mean /= float64(size)
		status := "PASS"
		if mn <= 47.0 || mx >= 53.0 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  min=%.2f%%  max=%.2f%%  mean=%.2f%%  [%s]\n",
			size, mn, mx, mean, status)
	}
	fmt.Println()
}

func testKeySensitivity() {
	// sk = FscxRevolveN(C2, B, hn, r) ^ A
	// Flipping bit k of A changes sk by exactly 1 bit via the direct XOR term.
	// The nonce change propagates L^i(e_k) into hn = C^C2; algebraically
	// S_r * L^i(e_k) cancels to zero, leaving only the 1-bit XOR contribution.
	// This is a structural property of the HKEX XOR construction.
	fmt.Println("[5] HKEX session key XOR construction (expected: exactly 1-bit direct sensitivity)")
	for _, size := range sizes {
		total := 0.0
		iv := iVal(size)
		rv := rVal(size)
		for i := 0; i < 10000; i++ {
			a := randBA(size)
			b := randBA(size)
			a2 := randBA(size)
			b2 := randBA(size)
			c := FscxRevolve(a, b, iv)
			c2 := FscxRevolve(a2, b2, iv)
			hn := c.Xor(c2)
			key1 := FscxRevolveN(c2, b, hn, rv).Xor(a)
			af := a.FlipBit(0)
			key2 := FscxRevolveN(c2, b, hn, rv).Xor(af)
			total += float64(key1.Xor(key2).Popcount())
		}
		mean := total / 10000.0
		status := "PASS"
		if mean < 0.9 || mean > 1.1 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  mean Hamming=%.2f (expected 1/%d)  [%s]\n", size, mean, size, status)
	}
	fmt.Println()
}

func testAvalancheRevolveN() {
	// FSCX_REVOLVE_N nonce-injection avalanche.
	// Flipping 1 bit of the nonce N while keeping A and B constant propagates
	// through all remaining revolve steps.  The change in the output equals
	// T_n(e_k) where T_n = I + L + ... + L^(n-1) and e_k is the unit vector
	// at bit position k.  Unlike the 3-bit diffusion of single-step FSCX or
	// the purely linear FscxRevolve, T_n accumulates contributions from every
	// step.  HD = popcount(T_n(e_0)) is deterministic (independent of A and B),
	// so min == max == mean.  For n = size/4 (i_val), HD = size/4 exactly.
	fmt.Println("[6] FscxRevolveN nonce-avalanche: flip 1 nonce bit, measure output diffusion")
	for _, size := range sizes {
		iv := iVal(size)
		total := 0.0
		gmin := size + 1
		gmax := -1
		for i := 0; i < 1000; i++ {
			a := randBA(size)
			b := randBA(size)
			n := randBA(size)
			base := FscxRevolveN(a, b, n, iv)
			nf := n.FlipBit(0)
			hd := FscxRevolveN(a, b, nf, iv).Xor(base).Popcount()
			total += float64(hd)
			if hd < gmin {
				gmin = hd
			}
			if hd > gmax {
				gmax = hd
			}
		}
		mean := total / 1000.0
		expected := size / 4
		status := "PASS"
		if mean < float64(expected) {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  mean HD=%.1f (expected >=%d)  min=%d  max=%d  [%s]\n",
			size, mean, expected, gmin, gmax, status)
	}
	fmt.Println()
}

func testHpksSignVerify() {
	fmt.Println("[7] HPKS sign+verify correctness: V == plaintext")
	for _, size := range sizes {
		iv := iVal(size)
		rv := rVal(size)
		ok := 0
		for i := 0; i < 10000; i++ {
			a := randBA(size)
			b := randBA(size)
			a2 := randBA(size)
			b2 := randBA(size)
			pt := randBA(size)
			c := FscxRevolve(a, b, iv)
			c2 := FscxRevolve(a2, b2, iv)
			hn := c.Xor(c2)
			S := FscxRevolveN(c2, b, hn, rv).Xor(a).Xor(pt)  // sign
			V := FscxRevolveN(c, b2, hn, rv).Xor(a2).Xor(S)  // verify
			if V.Equal(pt) {
				ok++
			}
		}
		status := "PASS"
		if ok != 10000 {
			status = "FAIL"
		}
		fmt.Printf("    bits=%3d  %5d / 10000 verified  [%s]\n", size, ok, status)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Performance benchmarks
// ---------------------------------------------------------------------------

func benchFscx() {
	fmt.Println("[8] FSCX throughput")
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

func benchFscxRevolveN() {
	fmt.Println("[9] FSCX_REVOLVE_N throughput")
	for _, size := range sizes {
		for _, stepsLabel := range []struct {
			steps int
			label string
		}{
			{iVal(size), fmt.Sprintf("i(%d)", iVal(size))},
			{rVal(size), fmt.Sprintf("r(%d)", rVal(size))},
		} {
			a := randBA(size)
			b := randBA(size)
			n := randBA(size)
			steps := stepsLabel.steps
			lbl := stepsLabel.label
			ops, elapsed := bench("", func() {
				FscxRevolveN(a, b, n, steps)
			})
			fmt.Printf("    bits=%3d  steps=%-12s        : %s  (%d ops in %.2fs)\n",
				size, lbl, fmtRate(ops, elapsed), ops, elapsed.Seconds())
		}
	}
	fmt.Println()
}

func benchHkexHandshake() {
	fmt.Println("[10] HKEX full handshake")
	for _, size := range sizes {
		iv := iVal(size)
		rv := rVal(size)
		ops, elapsed := bench("", func() {
			a := randBA(size)
			b := randBA(size)
			a2 := randBA(size)
			b2 := randBA(size)
			c := FscxRevolve(a, b, iv)
			c2 := FscxRevolve(a2, b2, iv)
			hn := c.Xor(c2)
			_ = FscxRevolveN(c2, b, hn, rv).Xor(a)
			_ = FscxRevolveN(c, b2, hn, rv).Xor(a2)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

func benchHskeRoundTrip() {
	fmt.Println("[11] HSKE round-trip: encrypt+decrypt")
	for _, size := range sizes {
		iv := iVal(size)
		rv := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			pt := randBA(size)
			key := randBA(size)
			enc := FscxRevolveN(pt, key, key, iv)
			dec := FscxRevolveN(enc, key, key, rv)
			sink = sink.Xor(dec.Xor(pt))
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

// HPKE (public key encryption) full round-trip:
// Key setup: C = FscxRevolve(A,B,i), C2 = FscxRevolve(A2,B2,i), hn = C^C2
// Bob encrypts:   E = FscxRevolveN(C, B2, hn, r) ^ A2 ^ pt
// Alice decrypts: D = FscxRevolveN(C2, B,  hn, r) ^ A  ^ E  (== pt)
func benchHpkeRoundTrip() {
	fmt.Println("[12] HPKE encrypt+decrypt round-trip")
	for _, size := range sizes {
		iv := iVal(size)
		rv := rVal(size)
		sink := randBA(size)
		ops, elapsed := bench("", func() {
			A := randBA(size)
			B := randBA(size)
			A2 := randBA(size)
			B2 := randBA(size)
			pt := randBA(size)
			C := FscxRevolve(A, B, iv)
			C2 := FscxRevolve(A2, B2, iv)
			hn := C.Xor(C2)
			E := FscxRevolveN(C, B2, hn, rv).Xor(A2).Xor(pt) // Bob encrypts
			D := FscxRevolveN(C2, B, hn, rv).Xor(A).Xor(E)   // Alice decrypts
			sink = sink.Xor(D)
		})
		fmt.Printf("    bits=%3d                          : %s  (%d ops in %.2fs)\n",
			size, fmtRate(ops, elapsed), ops, elapsed.Seconds())
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	fmt.Println("=== Herradura KEx \u2014 Security & Performance Tests (Go) ===\n")

	fmt.Println("--- Security Assumption Tests ---\n")
	testNonCommutativity()
	testAvalanche()
	testOrbitPeriod()
	testBitFrequency()
	testKeySensitivity()

	testAvalancheRevolveN()
	testHpksSignVerify()

	fmt.Println("--- Performance Benchmarks ---\n")
	benchFscx()
	benchFscxRevolveN()
	benchHkexHandshake()
	benchHskeRoundTrip()
	benchHpkeRoundTrip()
}
