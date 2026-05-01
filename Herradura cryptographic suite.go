/*  Herradura Cryptographic Suite v1.5.22

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

    --- v1.5.18: HPKS-Stern-F + HPKE-Stern-F code-based PQC — ZKP sign/verify and Niederreiter KEM (all targets) ---

    --- v1.5.17: NTT twiddle precomputation — rnlTwCache map; rnlTwGet eliminates rnlModPow calls per rnlPolyMul ---

    --- v1.5.13: HSKE-NL-A1 seed fix — RotateLeft(base, n/8) breaks counter=0 step-1 degeneracy ---

    HSKE-NL-A1 keystream: seed = base.RotateLeft(n/8); ks = NlFscxRevolveV1(seed, base^ctr, n/4).
    When A=B=base (counter=0), Fscx(base,base)=0 so step 1 was a pure rotation (linear in base).
    RotateLeft(base,n/8) ensures seed!=base, activating full carry non-linearity from step 1.
    Same degeneracy pattern fixed for HKEX-RNL KDF in v1.5.10; now applied consistently.

    --- v1.5.10: HKEX-RNL KDF seed fix — RotateLeft(K, n/8) breaks step-1 degeneracy ---

    HKEX-RNL KDF: seed = K.RotateLeft(n/8); sk = NlFscxRevolveV1(seed, K, n/4).
    When A0=B=K, Fscx(K,K)=0 so step 1 was a pure rotation (linear in K).
    RotateLeft(K,n/8) ensures seed!=K, activating full carry non-linearity from step 1.

    --- v1.5.9: HSKE-NL-A1 per-session nonce; NlFscxRevolveV2Inv delta precompute ---
    HSKE-NL-A1 now generates a random per-session nonce N and derives session base
    = K XOR N (transmitted alongside ciphertext).  Eliminates keystream reuse when
    the same long-term key K is used across sessions.
    NlFscxRevolveV2Inv precomputes delta(B) once before the loop.
    Loop body: diff = result - delta; result = b.Xor(MInv(diff)).
    Eliminates one nlFscxDeltaV2 big.Int multiply per iteration.

    --- v1.5.7: precomputed M^{-1} for NlFscxV2Inv ---
    MInv now computes the rotation table for M^{-1} = M^{n/2-1} once on first call
    (bootstrapping from FscxRevolve(1, 0, n/2-1)), caches it per bit-size via sync.Map,
    then applies M^{-1}(X) as XOR of RotateLeft(X, k) for each k in the table.

    --- v1.5.6: rnlRandPoly bias fix — 3-byte rejection sampling ---
    rnlRandPoly now draws 3 bytes (24-bit) with rejection sampling (threshold =
    (1<<24) - (1<<24)%q = 16711935) to eliminate the ~1/2^32 modular bias.

    --- v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)) ---
    rnlPolyMul now uses Cooley-Tukey NTT over Z_{65537} with negacyclic twist.

    --- v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1) ---

    HKEX-RNL secret polynomial now uses centered binomial distribution CBD(eta=1)
    instead of uniform {0,1}.  Produces {-1,0,1} with zero mean; matches the Kyber
    baseline for proper Ring-LWR hardness without changing the noise budget.

    --- v1.5.0: NL-FSCX non-linear extension and PQC protocols ---

    Adds two NL-FSCX primitives and five PQC-hardened protocol variants
    alongside the existing classical (non-PQC) algorithms (kept for reference).

    NL-FSCX v1:  NlFscxV1(A,B) = Fscx(A,B) XOR ROL((A+B) mod 2^n, n/4)
      Injects integer-carry non-linearity.  Not bijective in A — for one-way
      use only (counter-mode HSKE, HKEX KDF, HPKS challenge hash).

    NL-FSCX v2:  NlFscxV2(A,B) = (Fscx(A,B) + delta(B)) mod 2^n
      delta(B) = ROL(B*floor((B+1)/2) mod 2^n, n/4)
      B-only additive offset; bijective in A with closed-form inverse.
      Used for revolve-mode HSKE and HPKE where decryption is required.

    PQC protocol variants (C3 hybrid assignment):
      HSKE-NL-A1  — counter-mode HSKE with NL-FSCX v1 keystream
      HSKE-NL-A2  — revolve-mode HSKE with NL-FSCX v2 (invertible); deterministic
                    (no nonce — embed one in plaintext for multi-message use)
      HKEX-RNL    — Ring-LWR key exchange (quantum-resistant; replaces HKEX-GF)
      HPKS-NL     — Schnorr with NL-FSCX v1 challenge (linear preimage hardened)
      HPKE-NL      — El Gamal with NL-FSCX v2 encryption/decryption
      HPKS-Stern-F — Stern ZKP signature (EUF-CMA ≤ q_H/T_SD + ε_PRF)
      HPKE-Stern-F — Niederreiter KEM (IND-CPA under SD; demo uses known e')

    Classical protocols (not PQC — kept for reference and comparison):
      HKEX-GF     — Diffie-Hellman over GF(2^n)* (broken by Shor's algorithm)
      HSKE        — FscxRevolve symmetric encryption (linear key recovery)
      HPKS        — Schnorr with FscxRevolve challenge (linear challenge)
      HPKE        — El Gamal + FscxRevolve (linear encryption)

    --- v1.4.0: HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The broken FscxRevolveN-based HKEX is replaced with HKEX-GF: a correct
    Diffie-Hellman key exchange over the multiplicative group GF(2^n)*.

    --- v1.3.2: performance and readability ---
    --- v1.3: BitArray (multi-byte parameter support) ---
*/

package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sync"
)

// ---------------------------------------------------------------------------
// BitArray
// ---------------------------------------------------------------------------

// BitArray is a fixed-width bit string backed by big.Int.
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

func NewRandBitArray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

func NewBitArray(size int, val *big.Int) *BitArray {
	ba := &BitArray{size: size}
	ba.val.And(val, bitArrayMask(size))
	return ba
}

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

// ---------------------------------------------------------------------------
// FSCX functions (classical — linear map M = I+ROL+ROR over GF(2))
// ---------------------------------------------------------------------------

func Fscx(a, b *BitArray) *BitArray {
	return a.Xor(b).
		Xor(a.RotateLeft(1)).Xor(b.RotateLeft(1)).
		Xor(a.RotateLeft(-1)).Xor(b.RotateLeft(-1))
}

func FscxRevolve(a, b *BitArray, steps int, verbose bool) *BitArray {
	result := a.Copy()
	for i := 1; i <= steps; i++ {
		result = Fscx(result, b)
		if verbose {
			fmt.Printf("Step %d: %x\n", i, result)
		}
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
// NL-FSCX primitives (v1.5.0 — non-linear; for PQC-hardened protocols)
// ---------------------------------------------------------------------------

// mInvCache holds per-bit-size precomputed rotation tables for MInv.
var mInvCache sync.Map // map[int][]int

// computeMInvRotations bootstraps the rotation table for M^{-1} at bit-size n.
func computeMInvRotations(n int) []int {
	unit := &BitArray{size: n}
	unit.val.SetInt64(1)
	zero := &BitArray{size: n}
	v := FscxRevolve(unit, zero, n/2-1, false)
	var rotations []int
	for k := 0; k < n; k++ {
		if v.val.Bit(k) == 1 {
			rotations = append(rotations, k)
		}
	}
	return rotations
}

// MInv applies M^{-1}(X) via a precomputed rotation table (cached per bit-size).
// The table is bootstrapped once from FscxRevolve(1, 0, n/2-1).
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

// NlFscxV1 computes Fscx(A,B) XOR ROL((A+B) mod 2^n, n/4).
// Injects integer-carry non-linearity. NOT bijective in A.
func NlFscxV1(a, b *BitArray) *BitArray {
	n := a.size
	mask := bitArrayMask(n)
	sum := new(big.Int).Add(&a.val, &b.val)
	sum.And(sum, mask)
	mixBA := &BitArray{size: n}
	mixBA.val.Set(sum)
	return Fscx(a, b).Xor(mixBA.RotateLeft(n / 4))
}

// NlFscxRevolveV1 iterates NlFscxV1 steps times (B held constant).
func NlFscxRevolveV1(a, b *BitArray, steps int) *BitArray {
	result := a.Copy()
	for i := 0; i < steps; i++ {
		result = NlFscxV1(result, b)
	}
	return result
}

// nlFscxDeltaV2 computes delta(B) = ROL(B * floor((B+1)/2) mod 2^n, n/4).
func nlFscxDeltaV2(b *BitArray) *BitArray {
	n := b.size
	mask := bitArrayMask(n)
	one := big.NewInt(1)
	bPlus1 := new(big.Int).Add(&b.val, one)
	half := new(big.Int).Rsh(bPlus1, 1) // floor((B+1)/2)
	prod := new(big.Int).Mul(&b.val, half)
	prod.And(prod, mask)
	deltaBA := &BitArray{size: n}
	deltaBA.val.Set(prod)
	return deltaBA.RotateLeft(n / 4)
}

// NlFscxV2 computes (Fscx(A,B) + delta(B)) mod 2^n.
// delta(B) = ROL(B*floor((B+1)/2) mod 2^n, n/4). Bijective in A; exact inverse.
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

// NlFscxV2Inv computes the exact inverse of one NlFscxV2 step:
// A = B XOR M^{-1}((Y - delta(B)) mod 2^n).
func NlFscxV2Inv(y, b *BitArray) *BitArray {
	n := y.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	diff := new(big.Int).Sub(&y.val, &delta.val)
	diff.And(diff, mask) // mod 2^n (handles negative via mask)
	// ensure non-negative after and-with-mask: Add(2^n, diff) if diff < 0
	// but big.Int.And with a positive mask always gives non-negative result
	zBA := &BitArray{size: n}
	zBA.val.Set(diff)
	return b.Xor(MInv(zBA))
}

// NlFscxRevolveV2 iterates NlFscxV2 steps times (B held constant).
func NlFscxRevolveV2(a, b *BitArray, steps int) *BitArray {
	result := a.Copy()
	for i := 0; i < steps; i++ {
		result = NlFscxV2(result, b)
	}
	return result
}

// NlFscxRevolveV2Inv inverts NlFscxRevolveV2 by applying NlFscxV2Inv steps times.
// delta(b) is precomputed once — b is constant throughout the revolve.
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

// HKEX-RNL parameters (see SecurityProofs.md §11.4)
const (
	rnlQ  = 65537 // Fermat prime (2^16+1)
	rnlP  = 4096  // public-key rounding modulus
	rnlPP = 2     // reconciliation modulus (1 bit per coefficient)
	rnlEta = 1    // CBD eta: secret coefficients drawn from CBD(1) in {-1,0,1}
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

// rnlTwEntry holds precomputed NTT twiddle values for one (n, q) pair.
type rnlTwEntry struct {
	psiPow    []int
	psiInvPow []int
	stageWFwd []int
	stageWInv []int
	invN      int
}

var rnlTwCache = map[int]*rnlTwEntry{}

func rnlTwGet(n, q int) *rnlTwEntry {
	if e, ok := rnlTwCache[n]; ok {
		return e
	}
	e := &rnlTwEntry{psiPow: make([]int, n), psiInvPow: make([]int, n)}
	psi := rnlModPow(3, (q-1)/(2*n), q)
	psiInv := rnlModPow(psi, q-2, q)
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

// rnlMulModQ computes a*b mod 65537 using the Fermat-prime identity
// 2^16 ≡ -1, 2^32 ≡ 1 mod 65537, avoiding a hardware divide.
func rnlMulModQ(a, b int) int {
	x := a * b
	r := (x & 0xFFFF) - ((x >> 16) & 0xFFFF) + (x >> 32)
	if r < 0 {
		r += 65537
	}
	return r
}

func rnlNTT(a []int, q int, invert bool) {
	n := len(a)
	tw := rnlTwGet(n, q)
	sw := tw.stageWFwd
	if invert {
		sw = tw.stageWInv
	}
	j := 0
	for i := 1; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}
	for s, length := 0, 2; length <= n; length, s = length<<1, s+1 {
		w := sw[s]
		for i := 0; i < n; i += length {
			wn := 1
			for k := 0; k < length>>1; k++ {
				u := a[i+k]
				v := rnlMulModQ(a[i+k+length>>1], wn)
				a[i+k] = (u + v) % q
				a[i+k+length>>1] = (u - v + q) % q
				wn = rnlMulModQ(wn, w)
			}
		}
	}
	if invert {
		for i := range a {
			a[i] = rnlMulModQ(a[i], tw.invN)
		}
	}
}

func rnlPolyMul(f, g []int, q, n int) []int {
	tw := rnlTwGet(n, q)
	fa, ga := make([]int, n), make([]int, n)
	for i := 0; i < n; i++ {
		fa[i] = rnlMulModQ(f[i], tw.psiPow[i])
		ga[i] = rnlMulModQ(g[i], tw.psiPow[i])
	}
	rnlNTT(fa, q, false)
	rnlNTT(ga, q, false)
	ha := make([]int, n)
	for i := range ha {
		ha[i] = rnlMulModQ(fa[i], ga[i])
	}
	rnlNTT(ha, q, true)
	for i := range ha {
		ha[i] = rnlMulModQ(ha[i], tw.psiInvPow[i])
	}
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
	buf := make([]byte, 3)
	threshold := (1 << 24) - (1<<24)%q
	i := 0
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("rand.Read: %s", err)
		}
		v := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
		if v < threshold {
			p[i] = v % q
			i++
		}
	}
	return p
}

// rnlCBDPoly samples n coefficients from CBD(eta=1): 4 coefficients per byte,
// bit-pairs (0-1),(2-3),(4-5),(6-7). Produces {-1,0,1} with zero mean.
func rnlCBDPoly(n, q int) []int {
	p   := make([]int, n)
	buf := make([]byte, (n+3)/4)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("rand.Read: %s", err)
	}
	for i := range p {
		off := (i & 3) * 2
		a   := int(buf[i>>2]>>off) & 1
		b   := int(buf[i>>2]>>(off+1)) & 1
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
	ms := rnlPolyMul(mBlind, s, q, n)
	c := rnlRound(ms, q, p)
	return s, c
}

// rnlHint returns the Peikert cross-rounding hint: 1 bit per coefficient.
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

// rnlReconcileBits extracts keyBits key bits from kPoly using the reconciliation hint.
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

// rnlAgree computes raw key bits with Peikert cross-rounding reconciliation.
// Reconciler path (hintIn=nil): generate hint, return (K_raw, hint).
// Receiver path  (hintIn≠nil): use provided hint, return (K_raw, nil).
func rnlAgree(s, cOther []int, q, p, pp, n, keyBits int, hintIn []byte) (*BitArray, []byte) {
	cLifted := rnlLift(cOther, p, q)
	kPoly := rnlPolyMul(s, cLifted, q, n)
	if hintIn == nil {
		hintIn = rnlHint(kPoly, q)
		return rnlReconcileBits(kPoly, hintIn, q, pp, keyBits), hintIn
	}
	return rnlReconcileBits(kPoly, hintIn, q, pp, keyBits), nil
}

// ---------------------------------------------------------------------------
// Stern-F: Code-Based PQC (HPKS-Stern-F / HPKE-Stern-F)
// ---------------------------------------------------------------------------

const (
	sdfNRows  = 256 / 2  // 128 parity-check rows
	sdfT      = 256 / 16 // 16 error weight
	sdfRounds = 32        // ZKP rounds (soundness (2/3)^32)
)

// sternHash computes the chain hash h <- NlFscxV1^{n/4}(h^v, ROL(v,n/8)) for each item.
func sternHash(items ...*BitArray) *BitArray {
	n := 256
	if len(items) > 0 {
		n = items[0].size
	}
	h := &BitArray{size: n}
	for _, v := range items {
		h = NlFscxRevolveV1(h.Xor(v), v.RotateLeft(n/8), n/4)
	}
	return h
}

// sternMatrixRow generates row i of the parity-check matrix: NlFscxV1^{n/4}(ROL(seed^row, n/8), seed).
func sternMatrixRow(seed *BitArray, row int) *BitArray {
	n := seed.size
	sxr := seed.Xor(NewBitArray(n, big.NewInt(int64(row&0xFF))))
	return NlFscxRevolveV1(sxr.RotateLeft(n/8), seed, n/4)
}

// sternSyndrome computes H·e^T mod 2 (nRows bits packed into *big.Int, bit i = row i).
func sternSyndrome(seed, e *BitArray) *big.Int {
	nRows := seed.size / 2
	syn := new(big.Int)
	for i := 0; i < nRows; i++ {
		row := sternMatrixRow(seed, i)
		dot := new(big.Int).And(&row.val, &e.val)
		if countBits(dot)%2 == 1 {
			syn.SetBit(syn, i, 1)
		}
	}
	return syn
}

// syndrToBA stores a syndrome *big.Int in the low bits of a BitArray.
func syndrToBA(n int, syn *big.Int) *BitArray {
	ba := &BitArray{size: n}
	ba.val.Set(syn)
	return ba
}

// sternGenPerm derives a Fisher-Yates permutation deterministically from piSeed via NlFscxV1.
func sternGenPerm(piSeed *BitArray, N int) []int {
	n := piSeed.size
	key := piSeed.RotateLeft(n / 8)
	st := piSeed.Copy()
	perm := make([]int, N)
	for i := range perm {
		perm[i] = i
	}
	for i := N - 1; i > 0; i-- {
		st = NlFscxV1(st, key)
		v := uint32(st.val.Uint64())
		j := int(v % uint32(i+1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// sternApplyPerm applies permutation: out[perm[i]] = v[i].
func sternApplyPerm(perm []int, v *BitArray) *BitArray {
	N := v.size
	out := &BitArray{size: N}
	for i := 0; i < N; i++ {
		if v.val.Bit(i) == 1 {
			out.val.SetBit(&out.val, perm[i], 1)
		}
	}
	return out
}

// sternRandError generates a weight-t error vector via partial Fisher-Yates with crypto/rand.
func sternRandError(n, t int) *BitArray {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	for i := n - 1; i >= n-t; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			log.Fatalf("rand.Int: %s", err)
		}
		ji := int(j.Int64())
		idx[i], idx[ji] = idx[ji], idx[i]
	}
	e := &BitArray{size: n}
	for i := n - 1; i >= n-t; i-- {
		e.val.SetBit(&e.val, idx[i], 1)
	}
	return e
}

// sternFKeygen generates (seed, e, syndrome): random seed, weight-t error, H·e^T.
func sternFKeygen(n int) (*BitArray, *BitArray, *big.Int) {
	seed := NewRandBitArray(n)
	e := sternRandError(n, n/16)
	return seed, e, sternSyndrome(seed, e)
}

// sternFsChallenges derives Fiat-Shamir challenges from msg and all round commitments.
func sternFsChallenges(rounds int, msg *BitArray, c0, c1, c2 []*BitArray) []int {
	n := msg.size
	chSt := &BitArray{size: n}
	sfs := func(item *BitArray) {
		chSt = NlFscxRevolveV1(chSt.Xor(item), item.RotateLeft(n/8), n/4)
	}
	sfs(msg)
	for i := 0; i < rounds; i++ {
		sfs(c0[i]); sfs(c1[i]); sfs(c2[i])
	}
	chals := make([]int, rounds)
	for i := 0; i < rounds; i++ {
		idxBA := NewBitArray(n, big.NewInt(int64(i&0xFF)))
		chSt = NlFscxV1(chSt, idxBA)
		chals[i] = int(uint32(chSt.val.Uint64()) % 3)
	}
	return chals
}

// SternRound holds one round of a Stern ZKP signature.
type SternRound struct {
	c0, c1, c2   *BitArray
	b             int
	respA, respB  *BitArray
}

// SternSig is a Fiat-Shamir Stern signature.
type SternSig struct {
	rounds []SternRound
}

// hpksSternFSign produces a Stern-F signature over msg using secret (e, seed).
func hpksSternFSign(msg, e, seed *BitArray, rounds int) *SternSig {
	n := msg.size
	t := n / 16
	sig := &SternSig{rounds: make([]SternRound, rounds)}
	type rtmp struct{ r, y, pi, sr, sy *BitArray }
	tmp := make([]rtmp, rounds)
	c0s := make([]*BitArray, rounds)
	c1s := make([]*BitArray, rounds)
	c2s := make([]*BitArray, rounds)

	for i := 0; i < rounds; i++ {
		r := sternRandError(n, t)
		y := e.Xor(r)
		pi := NewRandBitArray(n)
		perm := sternGenPerm(pi, n)
		sr := sternApplyPerm(perm, r)
		sy := sternApplyPerm(perm, y)
		hrBA := syndrToBA(n, sternSyndrome(seed, r))
		c0 := sternHash(pi, hrBA)
		c1 := sternHash(sr)
		c2 := sternHash(sy)
		tmp[i] = rtmp{r, y, pi, sr, sy}
		sig.rounds[i].c0 = c0; sig.rounds[i].c1 = c1; sig.rounds[i].c2 = c2
		c0s[i] = c0; c1s[i] = c1; c2s[i] = c2
	}
	chals := sternFsChallenges(rounds, msg, c0s, c1s, c2s)
	for i := 0; i < rounds; i++ {
		bv := chals[i]
		sig.rounds[i].b = bv
		switch bv {
		case 0:
			sig.rounds[i].respA = tmp[i].sr
			sig.rounds[i].respB = tmp[i].sy
		case 1:
			sig.rounds[i].respA = tmp[i].pi
			sig.rounds[i].respB = tmp[i].r
		default:
			sig.rounds[i].respA = tmp[i].pi
			sig.rounds[i].respB = tmp[i].y
		}
	}
	return sig
}

// hpksSternFVerify verifies a Stern-F signature. Returns true iff valid.
func hpksSternFVerify(msg *BitArray, sig *SternSig, seed *BitArray, syndrome *big.Int) bool {
	rounds := len(sig.rounds)
	n := msg.size
	t := n / 16
	c0s := make([]*BitArray, rounds)
	c1s := make([]*BitArray, rounds)
	c2s := make([]*BitArray, rounds)
	for i, r := range sig.rounds {
		c0s[i] = r.c0; c1s[i] = r.c1; c2s[i] = r.c2
	}
	chals := sternFsChallenges(rounds, msg, c0s, c1s, c2s)
	for i, r := range sig.rounds {
		if chals[i] != r.b {
			return false
		}
	}
	for _, r := range sig.rounds {
		switch r.b {
		case 0:
			if !sternHash(r.respA).Equal(r.c1) { return false }
			if !sternHash(r.respB).Equal(r.c2) { return false }
			if countBits(&r.respA.val) != t { return false }
		case 1:
			if countBits(&r.respB.val) != t { return false }
			hrBA := syndrToBA(n, sternSyndrome(seed, r.respB))
			if !sternHash(r.respA, hrBA).Equal(r.c0) { return false }
			sr2 := sternApplyPerm(sternGenPerm(r.respA, n), r.respB)
			if !sternHash(sr2).Equal(r.c1) { return false }
		default:
			hysBA := syndrToBA(n, new(big.Int).Xor(sternSyndrome(seed, r.respB), syndrome))
			if !sternHash(r.respA, hysBA).Equal(r.c0) { return false }
			sy2 := sternApplyPerm(sternGenPerm(r.respA, n), r.respB)
			if !sternHash(sy2).Equal(r.c2) { return false }
		}
	}
	return true
}

// hpkeSternFEncap generates K = hash(seed, e'), ct = H·e'^T (Niederreiter KEM).
// Returns (K, ct, e'). e' is returned for demo decap; production needs QC-MDPC decoder.
func hpkeSternFEncap(seed *BitArray, n int) (*BitArray, *big.Int, *BitArray) {
	ePrime := sternRandError(n, n/16)
	ct := sternSyndrome(seed, ePrime)
	return sternHash(seed, ePrime), ct, ePrime
}

// hpkeSternFDecapKnown recomputes K = hash(seed, e') given e' directly (demo only).
func hpkeSternFDecapKnown(ePrime, seed *BitArray) *BitArray {
	return sternHash(seed, ePrime)
}

// ---------------------------------------------------------------------------
// main — protocol demonstrations
// ---------------------------------------------------------------------------

func main() {
	const n = 256
	iValue := n / 4
	rValue := 3 * n / 4

	poly := gfPoly[n]
	g := big.NewInt(gfGen)
	ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), n), big.NewInt(1))

	a         := NewRandBitArray(n)
	b         := NewRandBitArray(n)
	preshared := NewRandBitArray(n)
	plaintext := NewRandBitArray(n)
	decoy     := NewRandBitArray(n)

	// HKEX-GF key exchange
	C  := NewBitArray(n, GfPow(g, &a.val, poly, n))
	C2 := NewBitArray(n, GfPow(g, &b.val, poly, n))
	sk := NewBitArray(n, GfPow(&C2.val, &a.val, poly, n))
	skBob := NewBitArray(n, GfPow(&C.val, &b.val, poly, n))

	fmt.Printf("a         : %x\n", a)
	fmt.Printf("b         : %x\n", b)
	fmt.Printf("preshared : %x\n", preshared)
	fmt.Printf("plaintext : %x\n", plaintext)
	fmt.Printf("decoy     : %x\n", decoy)
	fmt.Printf("C         : %x\n", C)
	fmt.Printf("C2        : %x\n", C2)

	// ── CLASSICAL protocols ──────────────────────────────────────────────────
	fmt.Printf("\n--- HKEX-GF [CLASSICAL — not PQC; Shor's algorithm breaks DLP]\n")
	fmt.Printf("    (DH over GF(2^%d)*)\n", n)
	fmt.Printf("sk (Alice): %x\n", sk)
	fmt.Printf("sk (Bob)  : %x\n", skBob)
	if sk.Equal(skBob) {
		fmt.Println("+ session keys agree!")
	} else {
		fmt.Println("- session keys differ!")
	}

	fmt.Println("\n--- HSKE [CLASSICAL — not PQC; linear key recovery from 1 KPT pair]")
	fmt.Println("    (FscxRevolve symmetric encryption)")
	eHske := FscxRevolve(plaintext, preshared, iValue, false)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Alice) : %x\n", eHske)
	dHske := FscxRevolve(eHske, preshared, rValue, false)
	fmt.Printf("D (Bob)   : %x\n", dHske)
	if dHske.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	fmt.Println("\n--- HPKS [CLASSICAL — not PQC; DLP + linear challenge]")
	fmt.Println("    (Schnorr-like with FscxRevolve challenge)")
	kS := NewRandBitArray(n)
	RS := NewBitArray(n, GfPow(g, &kS.val, poly, n))
	eS := FscxRevolve(RS, plaintext, iValue, false)
	sS := new(big.Int).Mod(new(big.Int).Sub(&kS.val, new(big.Int).Mul(&a.val, &eS.val)), ord)
	eV := FscxRevolve(RS, plaintext, iValue, false)
	lhs := GfMul(GfPow(g, sS, poly, n), GfPow(&C.val, &eV.val, poly, n), poly, n)
	fmt.Printf("P (msg)        : %x\n", plaintext)
	fmt.Printf("R [Alice,sign] : %x\n", RS)
	fmt.Printf("e [Alice,sign] : %x\n", eS)
	fmt.Printf("s [Alice,sign] : %0*x\n", n/4, sS)
	fmt.Printf("  [Bob,verify] : g^s·C^e = %0*x\n", n/4, lhs)
	if lhs.Cmp(&RS.val) == 0 {
		fmt.Println("  [Bob,verify] : + Schnorr verified: g^s · C^e == R")
	} else {
		fmt.Println("  [Bob,verify] : - Schnorr verification failed!")
	}

	fmt.Println("\n--- HPKE [CLASSICAL — not PQC; DLP + linear HSKE sub-protocol]")
	fmt.Println("    (El Gamal + FscxRevolve)")
	rHpke  := NewRandBitArray(n)
	RHpke  := NewBitArray(n, GfPow(g, &rHpke.val, poly, n))
	encKey := NewBitArray(n, GfPow(&C.val, &rHpke.val, poly, n))
	eHpke  := FscxRevolve(plaintext, encKey, iValue, false)
	decKey := NewBitArray(n, GfPow(&RHpke.val, &a.val, poly, n))
	dHpke  := FscxRevolve(eHpke, decKey, rValue, false)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Bob)   : %x\n", eHpke)
	fmt.Printf("D (Alice) : %x\n", dHpke)
	if dHpke.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	// ── PQC-HARDENED protocols ───────────────────────────────────────────────
	fmt.Println("\n--- HSKE-NL-A1 [PQC-HARDENED — counter-mode with NL-FSCX v1]")
	nA1    := NewRandBitArray(n)                                           // per-session nonce
	baseA1 := NewBitArray(n, new(big.Int).Xor(&preshared.val, &nA1.val)) // base = K XOR N
	counter := 0
	bA1 := NewBitArray(n, new(big.Int).Xor(&baseA1.val, big.NewInt(int64(counter))))
	ksA1 := NlFscxRevolveV1(baseA1.RotateLeft(n/8), bA1, n/4) // seed=ROL(base,n/8) avoids step-1 degeneracy
	eA1 := NewBitArray(n, new(big.Int).Xor(&plaintext.val, &ksA1.val))
	dA1 := NewBitArray(n, new(big.Int).Xor(&eA1.val, &ksA1.val))
	fmt.Printf("N (nonce) : %x\n", nA1)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Alice) : %x\n", eA1)
	fmt.Printf("D (Bob)   : %x\n", dA1)
	if dA1.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	fmt.Println("\n--- HSKE-NL-A2 [PQC-HARDENED — revolve-mode with NL-FSCX v2]")
	eA2 := NlFscxRevolveV2(plaintext, preshared, rValue)
	dA2 := NlFscxRevolveV2Inv(eA2, preshared, rValue)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Alice) : %x\n", eA2)
	fmt.Printf("D (Bob)   : %x\n", dA2)
	if dA2.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	fmt.Printf("\n--- HKEX-RNL [PQC — Ring-LWR key exchange; conjectured quantum-resistant]\n")
	fmt.Printf("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=%d, q=%d)\n", n, rnlQ)
	nRnl := n
	mBase := rnlMPoly(nRnl)
	aRand := rnlRandPoly(nRnl, rnlQ)
	mBlind := rnlPolyAdd(mBase, aRand, rnlQ)
	sA, CA := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
	sB, CB := rnlKeygen(mBlind, nRnl, rnlQ, rnlP)
	kRawA, hintA := rnlAgree(sA, CB, rnlQ, rnlP, rnlPP, nRnl, n, nil)
	kRawB, _     := rnlAgree(sB, CA, rnlQ, rnlP, rnlPP, nRnl, n, hintA)
	skRnlA := NlFscxRevolveV1(kRawA.RotateLeft(n/8), kRawA, n/4)
	skRnlB := NlFscxRevolveV1(kRawB.RotateLeft(n/8), kRawB, n/4)
	fmt.Printf("sk (Alice): %x\n", skRnlA)
	fmt.Printf("sk (Bob)  : %x\n", skRnlB)
	if kRawA.Equal(kRawB) {
		fmt.Println("+ raw key bits agree; shared session key established!")
	} else {
		diffBits := new(big.Int).Xor(&kRawA.val, &kRawB.val)
		fmt.Printf("- raw key disagrees (%d bit(s)) — reconciliation failed!\n",
			countBits(diffBits))
	}

	fmt.Println("\n--- HPKS-NL [NL-hardened Schnorr — NL-FSCX v1 challenge]")
	fmt.Println("    (GF DLP still present; NL hardens linear challenge preimage)")
	kNl  := NewRandBitArray(n)
	RNl  := NewBitArray(n, GfPow(g, &kNl.val, poly, n))
	eNl  := NlFscxRevolveV1(RNl, plaintext, iValue)
	sNl  := new(big.Int).Mod(new(big.Int).Sub(&kNl.val, new(big.Int).Mul(&a.val, &eNl.val)), ord)
	eNlV := NlFscxRevolveV1(RNl, plaintext, iValue)
	lhsNl := GfMul(GfPow(g, sNl, poly, n), GfPow(&C.val, &eNlV.val, poly, n), poly, n)
	fmt.Printf("P (msg)        : %x\n", plaintext)
	fmt.Printf("R [Alice,sign] : %x\n", RNl)
	fmt.Printf("e [Alice,sign] : %x\n", eNl)
	fmt.Printf("s [Alice,sign] : %0*x\n", n/4, sNl)
	fmt.Printf("  [Bob,verify] : g^s·C^e = %0*x\n", n/4, lhsNl)
	if lhsNl.Cmp(&RNl.val) == 0 {
		fmt.Println("  [Bob,verify] : + HPKS-NL verified: g^s · C^e == R")
	} else {
		fmt.Println("  [Bob,verify] : - HPKS-NL verification failed!")
	}

	fmt.Println("\n--- HPKE-NL [NL-hardened El Gamal — NL-FSCX v2 encryption]")
	fmt.Println("    (GF DLP still present; NL hardens linear HSKE sub-protocol)")
	rNl   := NewRandBitArray(n)
	RNl2  := NewBitArray(n, GfPow(g, &rNl.val, poly, n))
	encNl := NewBitArray(n, GfPow(&C.val, &rNl.val, poly, n))
	eHpkeNl := NlFscxRevolveV2(plaintext, encNl, iValue)
	decNl := NewBitArray(n, GfPow(&RNl2.val, &a.val, poly, n))
	dHpkeNl := NlFscxRevolveV2Inv(eHpkeNl, decNl, iValue)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Bob)   : %x\n", eHpkeNl)
	fmt.Printf("D (Alice) : %x\n", dHpkeNl)
	if dHpkeNl.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	fmt.Println("\n--- HPKS-Stern-F [CODE-BASED PQC — EUF-CMA ≤ q_H/T_SD + ε_PRF]")
	fmt.Printf("    (N=%d, t=%d, rounds=%d; soundness=(2/3)^%d)\n", n, sdfT, sdfRounds, sdfRounds)
	sfSeed, sfE, sfSyn := sternFKeygen(n)
	sfSig := hpksSternFSign(plaintext, sfE, sfSeed, sdfRounds)
	fmt.Printf("seed     : %x\n", sfSeed)
	fmt.Printf("msg      : %x\n", plaintext)
	if hpksSternFVerify(plaintext, sfSig, sfSeed, sfSyn) {
		fmt.Println("+ HPKS-Stern-F signature verified")
	} else {
		fmt.Println("- HPKS-Stern-F verification FAILED")
	}

	fmt.Printf("\n--- HPKE-Stern-F [CODE-BASED PQC — Niederreiter KEM, N=%d]\n", n)
	fmt.Println("    (brute-force decap infeasible at N=256; demo uses known e')")
	sfKEnc, _, sfEPrime := hpkeSternFEncap(sfSeed, n)
	sfKDec := hpkeSternFDecapKnown(sfEPrime, sfSeed)
	fmt.Printf("K (encap): %x\n", sfKEnc)
	fmt.Printf("K (decap): %x\n", sfKDec)
	fmt.Println("    NOTE: decap uses known e' (demo only; production: QC-MDPC decoder)")
	if sfKEnc.Equal(sfKDec) {
		fmt.Println("+ HPKE-Stern-F session keys agree")
	} else {
		fmt.Println("- HPKE-Stern-F key agreement FAILED")
	}

	// ── Eve bypass tests ─────────────────────────────────────────────────────
	fmt.Println("\n\n*** EVE bypass TESTS")

	fmt.Println("*** HPKS-NL — Eve cannot forge Schnorr without knowing private key a")
	REve  := NewBitArray(n, GfPow(g, &NewRandBitArray(n).val, poly, n))
	eEve  := NlFscxRevolveV1(REve, decoy, iValue)
	sEve  := &NewRandBitArray(n).val
	lhsEve := GfMul(GfPow(g, sEve, poly, n), GfPow(&C.val, &eEve.val, poly, n), poly, n)
	if lhsEve.Cmp(&REve.val) == 0 {
		fmt.Println("+ Eve forged HPKS-NL signature (Eve wins)!")
	} else {
		fmt.Println("- Eve could not forge: g^s_eve · C^e_eve ≠ R_eve  (DLP protection)")
	}

	fmt.Println("*** HPKE-NL — Eve cannot decrypt without Alice's private key")
	eveKey := NewBitArray(n, new(big.Int).Xor(&C.val, &RNl2.val))
	dEve   := NlFscxRevolveV2Inv(eHpkeNl, eveKey, iValue)
	if dEve.Equal(plaintext) {
		fmt.Println("+ Eve decrypted plaintext (Eve wins)!")
	} else {
		fmt.Println("- Eve could not decrypt without Alice's private key (CDH + NL protection)")
	}

	fmt.Println("*** HKEX-RNL — Eve cannot derive shared key from public ring polynomials")
	eveRnlGuess := NewRandBitArray(n)
	if eveRnlGuess.Equal(skRnlA) {
		fmt.Println("+ Eve guessed HKEX-RNL shared key (astronomically unlikely)!")
	} else {
		fmt.Println("- Eve random guess does not match shared key (Ring-LWR protection)")
	}

	fmt.Println("*** HPKS-Stern-F — Eve cannot forge without solving SD(N,t)")
	eveSig := &SternSig{rounds: make([]SternRound, sdfRounds)}
	for i := range eveSig.rounds {
		eveSig.rounds[i].c0 = NewRandBitArray(n)
		eveSig.rounds[i].c1 = NewRandBitArray(n)
		eveSig.rounds[i].c2 = NewRandBitArray(n)
		eveSig.rounds[i].b = 0
		eveSig.rounds[i].respA = NewRandBitArray(n)
		eveSig.rounds[i].respB = NewRandBitArray(n)
	}
	if hpksSternFVerify(decoy, eveSig, sfSeed, sfSyn) {
		fmt.Println("+ Eve forged HPKS-Stern-F (Eve wins)!")
	} else {
		fmt.Println("- Eve cannot forge: Fiat-Shamir mismatch  (SD + PRF protection)")
	}

	fmt.Println("*** HPKE-Stern-F — Eve cannot derive session key from syndrome ciphertext")
	eveKGuess := NewRandBitArray(n)
	if eveKGuess.Equal(sfKEnc) {
		fmt.Println("+ Eve guessed HPKE-Stern-F session key (astronomically unlikely)!")
	} else {
		fmt.Println("- Eve random guess does not match session key  (SD protection)")
	}
}

// countBits counts set bits in a *big.Int.
func countBits(x *big.Int) int {
	count := 0
	for _, b := range x.Bytes() {
		for b != 0 {
			count += int(b & 1)
			b >>= 1
		}
	}
	return count
}
