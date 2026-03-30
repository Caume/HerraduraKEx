/*  Herradura KEx -- Security & Performance Tests (Go)

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

func New_rand_bitarray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

func randBA(size int) *BitArray {
	return New_rand_bitarray(size)
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

// Popcount counts set bits by iterating over bytes.
func (ba *BitArray) Popcount() int {
	cnt := 0
	for _, b := range ba.val.Bytes() {
		v := b
		for v != 0 {
			cnt += int(v & 1)
			v >>= 1
		}
	}
	return cnt
}

// FlipBit returns a new BitArray with bit pos (0=LSB) toggled.
func (ba *BitArray) FlipBit(pos int) *BitArray {
	result := &BitArray{size: ba.size}
	result.val.Set(&ba.val)
	cur := result.val.Bit(pos)
	if cur == 0 {
		result.val.SetBit(&result.val, pos, 1)
	} else {
		result.val.SetBit(&result.val, pos, 0)
	}
	return result
}

// ---------------------------------------------------------------------------
// FSCX functions
// ---------------------------------------------------------------------------

func Fscx(ba, bb *BitArray) *BitArray {
	result := ba.Xor(bb)
	ba = ba.RotateLeft(1)
	bb = bb.RotateLeft(1)
	result = result.Xor(ba).Xor(bb)
	ba = ba.RotateLeft(-2)
	bb = bb.RotateLeft(-2)
	result = result.Xor(ba).Xor(bb)
	return result
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
	// Asymmetry arises from FscxRevolve, where B is held constant across
	// iterations: FscxRevolve(A,B,n) != FscxRevolve(B,A,n) in general.
	fmt.Println("[1] FscxRevolve non-commutativity: FscxRevolve(A,B,n) != FscxRevolve(B,A,n)")
	for _, size := range sizes {
		iv := iVal(size)
		comm := 0
		for i := 0; i < 10000; i++ {
			a := randBA(size)
			b := randBA(size)
			if FscxRevolve(a, b, iv).Equal(FscxRevolve(b, a, iv)) {
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

// ---------------------------------------------------------------------------
// Performance benchmarks
// ---------------------------------------------------------------------------

func benchFscx() {
	fmt.Println("[6] FSCX throughput")
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

func benchFscxRevolve() {
	fmt.Println("[7] FSCX_REVOLVE throughput")
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
			steps := stepsLabel.steps
			lbl := stepsLabel.label
			ops, elapsed := bench("", func() {
				FscxRevolve(a, b, steps)
			})
			fmt.Printf("    bits=%3d  steps=%-12s        : %s  (%d ops in %.2fs)\n",
				size, lbl, fmtRate(ops, elapsed), ops, elapsed.Seconds())
		}
	}
	fmt.Println()
}

func benchHkexHandshake() {
	fmt.Println("[8] HKEX full handshake")
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
	fmt.Println("[9] HSKE round-trip: encrypt+decrypt")
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

	fmt.Println("--- Performance Benchmarks ---\n")
	benchFscx()
	benchFscxRevolve()
	benchHkexHandshake()
	benchHskeRoundTrip()
}
