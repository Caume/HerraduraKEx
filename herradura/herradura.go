/*  package herradura — Herradura Cryptographic Suite shared library
    v1.5.27: extracted from "Herradura cryptographic suite.go".

    Provides all crypto primitives (FSCX, GF, NL-FSCX, HKEX-RNL, Stern-F),
    HFSCX-256 hash, HSKE-NL-A1 streaming helpers, and the PEM/DER codec.
    The suite demo, tests, and CLI all import this single package.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    Dual-licensed MIT / GPL v3.0 — see repository root LICENSE files.
*/

package herradura

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"sync"
)

// ---------------------------------------------------------------------------
// BitArray
// ---------------------------------------------------------------------------

// BitArray is a fixed-width bit string backed by big.Int.
// Val is the integer value; size is the bit width.
type BitArray struct {
	Val  big.Int
	size int
}

func bitArrayMask(size int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(size))
	return mask.Sub(mask, big.NewInt(1))
}

// Size returns the bit width.
func (ba *BitArray) Size() int { return ba.size }

// Bytes returns the value as a big-endian byte slice of exactly size/8 bytes.
func (ba *BitArray) Bytes() []byte {
	b := ba.Val.Bytes()
	out := make([]byte, ba.size/8)
	if len(b) <= len(out) {
		copy(out[len(out)-len(b):], b)
	}
	return out
}

// NewFromBytes interprets the first size/8 bytes of data as a big-endian integer.
func NewFromBytes(data []byte, _ int, size int) *BitArray {
	ba := &BitArray{size: size}
	ba.Val.SetBytes(data[:size/8])
	return ba
}

// NewRandBitArray generates a cryptographically random bit string.
func NewRandBitArray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

// NewBitArray creates a BitArray from a *big.Int, masked to the correct width.
func NewBitArray(size int, val *big.Int) *BitArray {
	ba := &BitArray{size: size}
	ba.Val.And(val, bitArrayMask(size))
	return ba
}

// Copy returns a deep copy.
func (ba *BitArray) Copy() *BitArray {
	result := &BitArray{size: ba.size}
	result.Val.Set(&ba.Val)
	return result
}

// Xor returns ba XOR other.
func (ba *BitArray) Xor(other *BitArray) *BitArray {
	result := &BitArray{size: ba.size}
	result.Val.Xor(&ba.Val, &other.Val)
	return result
}

// RotateLeft rotates ba left by n positions; negative n rotates right.
func (ba *BitArray) RotateLeft(n int) *BitArray {
	size := ba.size
	n = ((n % size) + size) % size
	result := &BitArray{size: size}
	if n == 0 {
		result.Val.Set(&ba.Val)
		return result
	}
	left := new(big.Int).Lsh(&ba.Val, uint(n))
	right := new(big.Int).Rsh(&ba.Val, uint(size-n))
	result.Val.Or(left, right)
	result.Val.And(&result.Val, bitArrayMask(size))
	return result
}

// Equal reports whether ba and other have the same size and value.
func (ba *BitArray) Equal(other *BitArray) bool {
	return ba.size == other.size && ba.Val.Cmp(&other.Val) == 0
}

// Format implements fmt.Formatter for zero-padded hex output (%x).
func (ba *BitArray) Format(f fmt.State, verb rune) {
	hexDigits := ba.size / 4
	s := ba.Val.Text(16)
	for i := len(s); i < hexDigits; i++ {
		f.Write([]byte{'0'})
	}
	fmt.Fprint(f, s)
}

// Popcount returns the number of set bits.
func (ba *BitArray) Popcount() int {
	cnt := 0
	for _, b := range ba.Val.Bytes() {
		cnt += bits.OnesCount8(b)
	}
	return cnt
}

// FlipBit returns a copy with bit pos toggled.
func (ba *BitArray) FlipBit(pos int) *BitArray {
	result := ba.Copy()
	result.Val.SetBit(&result.Val, pos, result.Val.Bit(pos)^1)
	return result
}

// CountBits counts set bits in a *big.Int.
func CountBits(x *big.Int) int {
	count := 0
	for _, b := range x.Bytes() {
		for b != 0 {
			count += int(b & 1)
			b >>= 1
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// FSCX (classical — linear map M = I+ROL+ROR over GF(2))
// ---------------------------------------------------------------------------

// Fscx computes one step of the Full Surroundings Cyclic XOR.
func Fscx(a, b *BitArray) *BitArray {
	return a.Xor(b).
		Xor(a.RotateLeft(1)).Xor(b.RotateLeft(1)).
		Xor(a.RotateLeft(-1)).Xor(b.RotateLeft(-1))
}

// FscxRevolve iterates Fscx steps times with B held constant.
func FscxRevolve(a, b *BitArray, steps int) *BitArray {
	result := a.Copy()
	for i := 0; i < steps; i++ {
		result = Fscx(result, b)
	}
	return result
}

// ---------------------------------------------------------------------------
// GF(2^n) field arithmetic
// ---------------------------------------------------------------------------

// GfPoly maps supported bit sizes to their irreducible polynomial (low bits).
var GfPoly = map[int]*big.Int{
	32:  new(big.Int).SetUint64(0x00400007),
	64:  new(big.Int).SetUint64(0x0000001B),
	128: new(big.Int).SetUint64(0x00000087),
	256: new(big.Int).SetUint64(0x00000425),
}

// GfGen is the generator element g=3 of GF(2^n)*.
const GfGen = 3

// GfMul computes a·b in GF(2^n) (carryless multiply mod poly).
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

// GfPow computes base^exp in GF(2^n) using square-and-multiply.
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
// NL-FSCX primitives (v1.5.0 — non-linear)
// ---------------------------------------------------------------------------

var mInvCache sync.Map // map[int][]int

func computeMInvRotations(n int) []int {
	unit := &BitArray{size: n}
	unit.Val.SetInt64(1)
	zero := &BitArray{size: n}
	v := FscxRevolve(unit, zero, n/2-1)
	var rotations []int
	for k := 0; k < n; k++ {
		if v.Val.Bit(k) == 1 {
			rotations = append(rotations, k)
		}
	}
	return rotations
}

// MInv applies M^{-1}(X) via a precomputed rotation table (cached per bit-size).
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
	sum := new(big.Int).Add(&a.Val, &b.Val)
	sum.And(sum, mask)
	mixBA := &BitArray{size: n}
	mixBA.Val.Set(sum)
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

func nlFscxDeltaV2(b *BitArray) *BitArray {
	n := b.size
	mask := bitArrayMask(n)
	one := big.NewInt(1)
	bPlus1 := new(big.Int).Add(&b.Val, one)
	half := new(big.Int).Rsh(bPlus1, 1)
	prod := new(big.Int).Mul(&b.Val, half)
	prod.And(prod, mask)
	deltaBA := &BitArray{size: n}
	deltaBA.Val.Set(prod)
	return deltaBA.RotateLeft(n / 4)
}

// NlFscxV2 computes (Fscx(A,B) + delta(B)) mod 2^n.
// Bijective in A; exact inverse via NlFscxV2Inv.
func NlFscxV2(a, b *BitArray) *BitArray {
	n := a.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	fscxOut := Fscx(a, b)
	sum := new(big.Int).Add(&fscxOut.Val, &delta.Val)
	sum.And(sum, mask)
	result := &BitArray{size: n}
	result.Val.Set(sum)
	return result
}

// NlFscxV2Inv inverts one NlFscxV2 step: A = B XOR M^{-1}((Y - delta(B)) mod 2^n).
func NlFscxV2Inv(y, b *BitArray) *BitArray {
	n := y.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	diff := new(big.Int).Sub(&y.Val, &delta.Val)
	diff.And(diff, mask)
	zBA := &BitArray{size: n}
	zBA.Val.Set(diff)
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

// NlFscxRevolveV2Inv inverts NlFscxRevolveV2; delta(B) is precomputed once.
func NlFscxRevolveV2Inv(y, b *BitArray, steps int) *BitArray {
	n := y.size
	mask := bitArrayMask(n)
	delta := nlFscxDeltaV2(b)
	result := y.Copy()
	for i := 0; i < steps; i++ {
		diff := new(big.Int).Sub(&result.Val, &delta.Val)
		diff.And(diff, mask)
		zBA := &BitArray{size: n}
		zBA.Val.Set(diff)
		result = b.Xor(MInv(zBA))
	}
	return result
}

// ---------------------------------------------------------------------------
// HFSCX-256: Merkle-Damgård hash on NL-FSCX v1
// ---------------------------------------------------------------------------

// Hfscx256IV is the 32-byte domain separation constant (ASCII + zero padding).
var Hfscx256IV = [32]byte{
	'H', 'F', 'S', 'C', 'X', '-', '2', '5', '6', '/',
	'H', 'E', 'R', 'R', 'A', 'D', 'U', 'R', 'A', '-',
	'S', 'U', 'I', 'T', 'E', 0, 0, 0, 0, 0, 0, 0,
}

// Hfscx256 computes the HFSCX-256 hash of data.
// iv==nil uses the standard domain IV (bare hash).
// A non-nil iv (32 bytes, caller sets iv = key XOR Hfscx256IV[:]) selects the keyed-MAC variant.
func Hfscx256(data []byte, iv []byte) []byte {
	init_ := Hfscx256IV[:]
	if iv != nil {
		init_ = iv
	}

	state := &BitArray{size: 256}
	state.Val.SetBytes(init_)

	// ISO 7816-4 padding: data || 0x80 || zeros to 32-byte boundary
	padded := make([]byte, len(data)+1)
	copy(padded, data)
	padded[len(data)] = 0x80
	if rem := len(padded) % 32; rem != 0 {
		padded = append(padded, make([]byte, 32-rem)...)
	}

	// MD-strengthening: 32-byte length block = init XOR (0...0 || bit_len_be64).
	// XORing init into the length block binds the key and prevents fixed-point collapse.
	lb := make([]byte, 32)
	copy(lb, init_)
	bitLen := uint64(len(data)) * 8
	var bitLenBuf [8]byte
	binary.BigEndian.PutUint64(bitLenBuf[:], bitLen)
	for i, b := range bitLenBuf {
		lb[24+i] ^= b
	}
	padded = append(padded, lb...)

	// Chain each 32-byte block: state = NlFscxRevolveV1(state, block, 64)
	for off := 0; off < len(padded); off += 32 {
		block := &BitArray{size: 256}
		block.Val.SetBytes(padded[off : off+32])
		state = NlFscxRevolveV1(state, block, 64)
	}

	return state.Bytes()
}

// ---------------------------------------------------------------------------
// HSKE-NL-A1 CTR-mode streaming helpers
// ---------------------------------------------------------------------------

// HskeNla1KsBlock returns the 32-byte keystream block for counter i.
// Caller must set: base = K XOR nonce; seed = base.RotateLeft(256/8).
func HskeNla1KsBlock(seed, base *BitArray, i uint32) *BitArray {
	baseI := base.Copy()
	iBI := new(big.Int).SetUint64(uint64(i))
	baseI.Val.Xor(&baseI.Val, iBI)
	return NlFscxRevolveV1(seed, baseI, 64) // 64 = 256/4 = I_VALUE
}

// HskeNla1MacKey returns the MAC key (domain-separated from encryption).
// mac_key = NlFscxRevolveV1(ROL(seed, 64), base, 64)
func HskeNla1MacKey(seed, base *BitArray) *BitArray {
	seed2 := seed.RotateLeft(64) // ROL(seed, n/4)
	return NlFscxRevolveV1(seed2, base, 64)
}

// ---------------------------------------------------------------------------
// HKEX-RNL ring-arithmetic helpers (negacyclic Z_q[x]/(x^n+1))
// ---------------------------------------------------------------------------

// RNL protocol parameters (see SecurityProofs.md §11.4).
const (
	RnlQ   = 65537 // Fermat prime (2^16+1)
	RnlP   = 4096  // public-key rounding modulus
	RnlPP  = 2     // reconciliation modulus (1 bit per coefficient)
	RnlEta = 1     // CBD eta: secret coefficients in {-1,0,1}
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
		e.psiPow[i] = pw
		e.psiInvPow[i] = pwInv
		pw = pw * psi % q
		pwInv = pwInv * psiInv % q
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

// rnlMulModQ computes a*b mod 65537 using the Fermat-prime identity.
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

// RnlPolyMul multiplies two polynomials in Z_q[x]/(x^n+1) using NTT.
func RnlPolyMul(f, g []int, q, n int) []int {
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

// RnlPolyAdd adds two polynomials coefficient-wise mod q.
func RnlPolyAdd(f, g []int, q int) []int {
	h := make([]int, len(f))
	for i := range f {
		h[i] = (f[i] + g[i]) % q
	}
	return h
}

// RnlRound rounds polynomial coefficients from Z_fromQ to Z_toP.
func RnlRound(poly []int, fromQ, toP int) []int {
	h := make([]int, len(poly))
	for i, c := range poly {
		h[i] = (c*toP + fromQ/2) / fromQ % toP
	}
	return h
}

// RnlLift lifts polynomial coefficients from Z_fromP to Z_toQ.
func RnlLift(poly []int, fromP, toQ int) []int {
	h := make([]int, len(poly))
	for i, c := range poly {
		h[i] = c * toQ / fromP % toQ
	}
	return h
}

// RnlMPoly returns the Ring-LWR public base polynomial m(x) = 1+x+x^{n-1}.
func RnlMPoly(n int) []int {
	p := make([]int, n)
	p[0], p[1], p[n-1] = 1, 1, 1
	return p
}

// RnlRandPoly samples n uniform coefficients from Z_q using rejection sampling.
func RnlRandPoly(n, q int) []int {
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

// RnlCBDPoly samples n coefficients from CBD(eta=1): values in {-1,0,1} mod q.
func RnlCBDPoly(n, q int) []int {
	p := make([]int, n)
	buf := make([]byte, (n+3)/4)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("rand.Read: %s", err)
	}
	for i := range p {
		off := (i & 3) * 2
		a := int(buf[i>>2]>>off) & 1
		b := int(buf[i>>2]>>(off+1)) & 1
		p[i] = (a - b + q) % q
	}
	return p
}

// RnlBitsToBitArray extracts key bits: coefficient >= pp/2 → bit 1.
func RnlBitsToBitArray(poly []int, pp, size int) *BitArray {
	threshold := pp / 2
	val := new(big.Int)
	for i := 0; i < size && i < len(poly); i++ {
		if poly[i] >= threshold {
			val.SetBit(val, i, 1)
		}
	}
	ba := &BitArray{size: size}
	ba.Val.Set(val)
	return ba
}

// RnlKeygen generates a secret polynomial s and public key C = round(m·s).
func RnlKeygen(mBlind []int, n, q, p int) ([]int, []int) {
	s := RnlCBDPoly(n, q)
	ms := RnlPolyMul(mBlind, s, q, n)
	c := RnlRound(ms, q, p)
	return s, c
}

// RnlHint returns the Peikert cross-rounding hint: 1 bit per coefficient.
func RnlHint(kPoly []int, q int) []byte {
	hint := make([]byte, (len(kPoly)+7)/8)
	for i, c := range kPoly {
		r := (4*c+q/2)/q % 4
		if r%2 != 0 {
			hint[i/8] |= 1 << (uint(i) % 8)
		}
	}
	return hint
}

// RnlReconcileBits extracts keyBits key bits using the reconciliation hint.
func RnlReconcileBits(kPoly []int, hint []byte, q, pp, keyBits int) *BitArray {
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
	ba.Val.Set(val)
	return ba
}

// RnlAgree computes raw key bits with Peikert reconciliation.
// Reconciler (hintIn==nil): generates hint; returns (K_raw, hint).
// Receiver  (hintIn!=nil):  uses provided hint; returns (K_raw, nil).
func RnlAgree(s, cOther []int, q, p, pp, n, keyBits int, hintIn []byte) (*BitArray, []byte) {
	cLifted := RnlLift(cOther, p, q)
	kPoly := RnlPolyMul(s, cLifted, q, n)
	if hintIn == nil {
		hintIn = RnlHint(kPoly, q)
		return RnlReconcileBits(kPoly, hintIn, q, pp, keyBits), hintIn
	}
	return RnlReconcileBits(kPoly, hintIn, q, pp, keyBits), nil
}

// ---------------------------------------------------------------------------
// Stern-F: Code-Based PQC (HPKS-Stern-F / HPKE-Stern-F)
// ---------------------------------------------------------------------------

// Stern-F default parameters for full-security targets (C/Go/Python suite).
const (
	SdfNRows  = 256 / 2  // 128 parity-check rows
	SdfT      = 256 / 16 // 16 error weight
	SdfRounds = 32       // ZKP rounds (soundness (2/3)^32)
)

// SternHash computes the Fiat-Shamir chain hash over items using NL-FSCX v1.
func SternHash(items ...*BitArray) *BitArray {
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

// SternMatrixRow generates row i of the parity-check matrix.
func SternMatrixRow(seed *BitArray, row int) *BitArray {
	n := seed.size
	sxr := seed.Xor(NewBitArray(n, big.NewInt(int64(row&0xFF))))
	return NlFscxRevolveV1(sxr.RotateLeft(n/8), seed, n/4)
}

// SternSyndrome computes H·e^T mod 2.
func SternSyndrome(seed, e *BitArray) *big.Int {
	nRows := seed.size / 2
	syn := new(big.Int)
	for i := 0; i < nRows; i++ {
		row := SternMatrixRow(seed, i)
		dot := new(big.Int).And(&row.Val, &e.Val)
		if CountBits(dot)%2 == 1 {
			syn.SetBit(syn, i, 1)
		}
	}
	return syn
}

// SyndrToBA stores a syndrome *big.Int in the low bits of a BitArray.
func SyndrToBA(n int, syn *big.Int) *BitArray {
	ba := &BitArray{size: n}
	ba.Val.Set(syn)
	return ba
}

// SternGenPerm derives a Fisher-Yates permutation deterministically from piSeed.
func SternGenPerm(piSeed *BitArray, N int) []int {
	n := piSeed.size
	key := piSeed.RotateLeft(n / 8)
	st := piSeed.Copy()
	perm := make([]int, N)
	for i := range perm {
		perm[i] = i
	}
	for i := N - 1; i > 0; i-- {
		st = NlFscxV1(st, key)
		v := uint32(st.Val.Uint64())
		j := int(v % uint32(i+1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// SternApplyPerm applies permutation perm: out[perm[i]] = v[i].
func SternApplyPerm(perm []int, v *BitArray) *BitArray {
	N := v.size
	out := &BitArray{size: N}
	for i := 0; i < N; i++ {
		if v.Val.Bit(i) == 1 {
			out.Val.SetBit(&out.Val, perm[i], 1)
		}
	}
	return out
}

// SternRandError generates a weight-t error vector via partial Fisher-Yates.
func SternRandError(n, t int) *BitArray {
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
		e.Val.SetBit(&e.Val, idx[i], 1)
	}
	return e
}

// SternFKeygen generates (seed, e, syndrome): random seed, weight-t error, H·e^T.
func SternFKeygen(n int) (*BitArray, *BitArray, *big.Int) {
	seed := NewRandBitArray(n)
	e := SternRandError(n, n/16)
	return seed, e, SternSyndrome(seed, e)
}

func sternFsChallenges(rounds int, msg *BitArray, c0, c1, c2 []*BitArray) []int {
	n := msg.size
	chSt := &BitArray{size: n}
	sfs := func(item *BitArray) {
		chSt = NlFscxRevolveV1(chSt.Xor(item), item.RotateLeft(n/8), n/4)
	}
	sfs(msg)
	for i := 0; i < rounds; i++ {
		sfs(c0[i])
		sfs(c1[i])
		sfs(c2[i])
	}
	chals := make([]int, rounds)
	for i := 0; i < rounds; i++ {
		idxBA := NewBitArray(n, big.NewInt(int64(i&0xFF)))
		chSt = NlFscxV1(chSt, idxBA)
		chals[i] = int(uint32(chSt.Val.Uint64()) % 3)
	}
	return chals
}

// SternRound holds one round of a Stern ZKP signature.
type SternRound struct {
	C0, C1, C2  *BitArray
	B            int
	RespA, RespB *BitArray
}

// SternSig is a Fiat-Shamir Stern signature.
type SternSig struct {
	Rounds []SternRound
}

// HpksSternFSign produces a Stern-F signature over msg using secret (e, seed).
func HpksSternFSign(msg, e, seed *BitArray, rounds int) *SternSig {
	n := msg.size
	t := n / 16
	sig := &SternSig{Rounds: make([]SternRound, rounds)}
	type rtmp struct{ r, y, pi, sr, sy *BitArray }
	tmp := make([]rtmp, rounds)
	c0s := make([]*BitArray, rounds)
	c1s := make([]*BitArray, rounds)
	c2s := make([]*BitArray, rounds)

	for i := 0; i < rounds; i++ {
		r := SternRandError(n, t)
		y := e.Xor(r)
		pi := NewRandBitArray(n)
		perm := SternGenPerm(pi, n)
		sr := SternApplyPerm(perm, r)
		sy := SternApplyPerm(perm, y)
		hrBA := SyndrToBA(n, SternSyndrome(seed, r))
		c0 := SternHash(pi, hrBA)
		c1 := SternHash(sr)
		c2 := SternHash(sy)
		tmp[i] = rtmp{r, y, pi, sr, sy}
		sig.Rounds[i].C0 = c0
		sig.Rounds[i].C1 = c1
		sig.Rounds[i].C2 = c2
		c0s[i] = c0
		c1s[i] = c1
		c2s[i] = c2
	}
	chals := sternFsChallenges(rounds, msg, c0s, c1s, c2s)
	for i := 0; i < rounds; i++ {
		bv := chals[i]
		sig.Rounds[i].B = bv
		switch bv {
		case 0:
			sig.Rounds[i].RespA = tmp[i].sr
			sig.Rounds[i].RespB = tmp[i].sy
		case 1:
			sig.Rounds[i].RespA = tmp[i].pi
			sig.Rounds[i].RespB = tmp[i].r
		default:
			sig.Rounds[i].RespA = tmp[i].pi
			sig.Rounds[i].RespB = tmp[i].y
		}
	}
	return sig
}

// HpksSternFVerify verifies a Stern-F signature. Returns true iff valid.
func HpksSternFVerify(msg *BitArray, sig *SternSig, seed *BitArray, syndrome *big.Int) bool {
	rounds := len(sig.Rounds)
	n := msg.size
	t := n / 16
	c0s := make([]*BitArray, rounds)
	c1s := make([]*BitArray, rounds)
	c2s := make([]*BitArray, rounds)
	for i, r := range sig.Rounds {
		c0s[i] = r.C0
		c1s[i] = r.C1
		c2s[i] = r.C2
	}
	chals := sternFsChallenges(rounds, msg, c0s, c1s, c2s)
	for i, r := range sig.Rounds {
		if chals[i] != r.B {
			return false
		}
	}
	for _, r := range sig.Rounds {
		switch r.B {
		case 0:
			if !SternHash(r.RespA).Equal(r.C1) {
				return false
			}
			if !SternHash(r.RespB).Equal(r.C2) {
				return false
			}
			if CountBits(&r.RespA.Val) != t {
				return false
			}
		case 1:
			if CountBits(&r.RespB.Val) != t {
				return false
			}
			hrBA := SyndrToBA(n, SternSyndrome(seed, r.RespB))
			if !SternHash(r.RespA, hrBA).Equal(r.C0) {
				return false
			}
			sr2 := SternApplyPerm(SternGenPerm(r.RespA, n), r.RespB)
			if !SternHash(sr2).Equal(r.C1) {
				return false
			}
		default:
			hysBA := SyndrToBA(n, new(big.Int).Xor(SternSyndrome(seed, r.RespB), syndrome))
			if !SternHash(r.RespA, hysBA).Equal(r.C0) {
				return false
			}
			sy2 := SternApplyPerm(SternGenPerm(r.RespA, n), r.RespB)
			if !SternHash(sy2).Equal(r.C2) {
				return false
			}
		}
	}
	return true
}

// HpkeSternFEncap generates K = hash(seed, e'), ct = H·e'^T (Niederreiter KEM).
// Returns (K, ct, e'). e' is returned for demo decap; production needs QC-MDPC decoder.
func HpkeSternFEncap(seed *BitArray, n int) (*BitArray, *big.Int, *BitArray) {
	ePrime := SternRandError(n, n/16)
	ct := SternSyndrome(seed, ePrime)
	return SternHash(seed, ePrime), ct, ePrime
}

// HpkeSternFDecapKnown recomputes K = hash(seed, e') given e' directly (demo only).
func HpkeSternFDecapKnown(ePrime, seed *BitArray) *BitArray {
	return SternHash(seed, ePrime)
}
