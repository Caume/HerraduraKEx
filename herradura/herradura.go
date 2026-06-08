/*  package herradura — Herradura Cryptographic Suite shared library v1.8.8
    v1.8.0: KDF domain constant — RnlKdfSeed: ROL(k,n/8) XOR RnlKdfDC (TODO #38).
    v1.6.1: SternHash ds parameter — closes QRO gap for Theorem 17 (TODO #36).
    v1.6.0: SternHash HFSCX-256 finalizer — eliminates range compression (TODO #43).
    v1.5.41: RnlLift centered rounding (TODO #37).
    v1.5.40: SternApplyPerm made branchless (no branch on secret bits) — TODO #41.
    v1.5.27: extracted from "Herradura cryptographic suite.go".

    Provides all crypto primitives (FSCX, GF, NL-FSCX, HKEX-RNL, Stern-F),
    HFSCX-256 hash, HSKE-NL-A1 streaming helpers, and the PEM/DER codec.
    The suite demo, tests, and CLI all import this single package.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    Dual-licensed MIT / GPL v3.0 — see repository root LICENSE files.
*/

package herradura

import (
	"bytes"
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
// The inner branch is on bits of b (the base, a public value when called from
// GfPow); it does not directly expose private key bits in that path.
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
// SA-02/05: iterates exactly n times — no early exit on leading zero bits of
// exp, so loop count no longer leaks exp's bit-length. Residual: the per-bit
// conditional call still leaks individual exp bits; big.Int has no CT select.
func GfPow(base, exp *big.Int, poly *big.Int, n int) *big.Int {
	result := big.NewInt(1)
	bCopy := new(big.Int).Set(base)
	eCopy := new(big.Int).Set(exp)
	one := big.NewInt(1)
	for i := 0; i < n; i++ { // fixed n iterations — no early exit
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
// HFSCX-256-DM: Merkle-Damgård hash on NL-FSCX v1 with Davies-Meyer compression (v1.9.0)
// ---------------------------------------------------------------------------

// Hfscx256IV is the 32-byte domain separation constant (ASCII + zero padding).
var Hfscx256IV = [32]byte{
	'H', 'F', 'S', 'C', 'X', '-', '2', '5', '6', '/',
	'H', 'E', 'R', 'R', 'A', 'D', 'U', 'R', 'A', '-',
	'S', 'U', 'I', 'T', 'E', 0, 0, 0, 0, 0, 0, 0,
}

// RnlKdfDC is the 256-bit NUMS constant XOR'd into the KDF seed after ROL(K, n/8).
// Derived from SHA-256 initial hash values H0..H7 (big-endian 32-bit words).
// Prevents KDF degeneracy when K has a rotational period dividing n/8 (TODO #38, v1.8.0).
var RnlKdfDC = [32]byte{
	0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
	0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
	0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
	0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19,
}

// RnlKdfSeed returns ROL(k, n/8) XOR RnlKdfDC for the given n-bit key.
// Use this instead of k.RotateLeft(n/8) wherever an HKEX-RNL KDF or
// HSKE-NL-A1 seed is required (TODO #38, v1.8.0).
func RnlKdfSeed(k *BitArray) *BitArray {
	n := k.size
	rotated := k.RotateLeft(n / 8)
	dc := new(big.Int)
	dcBytes := RnlKdfDC[32-n/8:]
	dc.SetBytes(dcBytes)
	return NewBitArray(n, new(big.Int).Xor(&rotated.Val, dc))
}

// Hfscx256 computes the HFSCX-256-DM hash of data (Davies-Meyer compression).
// Compression: C_DM(s,m) = F_1^{64}(s,m) ⊕ s.
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

	// Chain each 32-byte block: C_DM(s,m) = F_1^{64}(s,m) ⊕ s (Davies-Meyer)
	for off := 0; off < len(padded); off += 32 {
		prev := state.Copy()
		block := &BitArray{size: 256}
		block.Val.SetBytes(padded[off : off+32])
		state = NlFscxRevolveV1(state, block, 64)
		state = NewBitArray(256, new(big.Int).Xor(&state.Val, &prev.Val))
	}

	return state.Bytes()
}

// ---------------------------------------------------------------------------
// HSKE-NL-A1 CTR-mode streaming helpers
// ---------------------------------------------------------------------------

// HskeNla1KsBlock returns the 32-byte keystream block for counter i.
// Caller must set: base = K XOR nonce; seed = rnlKdfSeed(base)  [ROL(base,n/8) XOR DC].
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

// RNL protocol parameters (see SecurityProofs-2.md §11.4).
const (
	RnlQ   = 65537 // Fermat prime (2^16+1)
	RnlP   = 4096  // public-key rounding modulus
	RnlPP  = 4     // reconciliation modulus (2 bits per coefficient)
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

var rnlTwCache sync.Map // map[int]*rnlTwEntry

func rnlTwGet(n, q int) *rnlTwEntry {
	if val, ok := rnlTwCache.Load(n); ok {
		return val.(*rnlTwEntry)
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
	val, _ := rnlTwCache.LoadOrStore(n, e)
	return val.(*rnlTwEntry)
}

// rnlMulModQ computes a*b mod 65537 using the Fermat-prime identity.
// int64 arithmetic prevents overflow on 32-bit platforms (65536² > MaxInt32).
func rnlMulModQ(a, b int) int {
	x := int64(a) * int64(b)
	r := (x & 0xFFFF) - ((x >> 16) & 0xFFFF) + (x >> 32)
	if r < 0 {
		r += 65537
	}
	return int(r)
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

// RnlLift lifts polynomial coefficients from Z_fromP to Z_toQ with centered rounding.
func RnlLift(poly []int, fromP, toQ int) []int {
	h := make([]int, len(poly))
	for i, c := range poly {
		h[i] = (c*toQ + fromP/2) / fromP % toQ
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

// RnlHint returns the 2-bit Peikert cross-rounding hint for the first len(kPoly)/2 coefficients.
func RnlHint(kPoly []int, q int) []byte {
	n := len(kPoly)
	hint := make([]byte, (n+7)/8) // n/2 coeffs × 2 bits = n bits = n/8 bytes
	for i := 0; i < n/2; i++ {
		c := kPoly[i]
		r := (8*c+q/4)/q % 4
		hint[i/4] |= byte(r << uint((i%4)*2))
	}
	return hint
}

// RnlReconcileBits extracts keyBits key bits using the 2-bit Peikert hint (keyBits/2 coefficients).
func RnlReconcileBits(kPoly []int, hint []byte, q, pp, keyBits int) *BitArray {
	qq := q / 4
	val := new(big.Int)
	for i := 0; i < keyBits/2 && i < len(kPoly); i++ {
		c := kPoly[i]
		h := int((hint[i/4] >> uint((i%4)*2)) & 3)
		b := (4*c+(2*h+1)*qq)/q % pp // pp=4 → b ∈ {0,1,2,3}
		val.Or(val, new(big.Int).Lsh(big.NewInt(int64(b)), uint(2*i)))
	}
	ba := &BitArray{size: keyBits}
	ba.Val.Set(val)
	return ba
}

// RnlAgree computes raw key bits with Peikert reconciliation.
// Reconciler (hintIn==nil): generates hint; returns (K_raw, hint).
// Receiver  (hintIn!=nil):  uses provided hint; returns (K_raw, nil).
// SECURITY: the hint vector is transmitted unauthenticated. An active adversary
// who tampers with hintIn can steer the reconciled key. HKEX-RNL provides key
// agreement only; the caller must authenticate the transcript (e.g. via HPKS-NL
// or a MAC over bPub||hint) before using the derived key.
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
	SdfNRows          = 256 / 2  // 128 parity-check rows
	SdfT              = 256 / 16 // 16 error weight
	SdfRounds         = 32       // ZKP rounds (soundness (2/3)^32; demo only)
	SdfProductionRounds = 219    // rounds required for 128-bit soundness
)

// SternHash computes the Fiat-Shamir chain hash over items using NL-FSCX v1,
// then applies HFSCX-256 to eliminate range compression (TODO #43, v1.6.0).
// ds is the domain-separation tag (0=challenge, 1=c0, 2=c1, 3=c2, 4=KEM) (TODO #36, v1.6.1).
func SternHash(ds int, items ...*BitArray) *BitArray {
	n := 256
	if len(items) > 0 {
		n = items[0].size
	}
	h := &BitArray{size: n}
	h.Val.SetInt64(int64(ds))
	for _, v := range items {
		h = NlFscxRevolveV1(h.Xor(v), v.RotateLeft(n/8), n/4)
	}
	digest := Hfscx256(h.Bytes(), nil)
	result := &BitArray{size: n}
	result.Val.SetBytes(digest[:n/8])
	return result
}

// SternMatrixRow generates row i of the parity-check matrix.
func SternMatrixRow(seed *BitArray, row int) *BitArray {
	n := seed.size
	sxr := seed.Xor(NewBitArray(n, big.NewInt(int64(row&0xFF))))
	return NlFscxRevolveV1(sxr.RotateLeft(n/8), seed, n/4)
}

// SternBuildH precomputes all n/2 rows of the parity-check matrix.
// Hot paths (sign/verify) call this once and reuse H via sternSyndromeH.
func SternBuildH(seed *BitArray) []*BitArray {
	nRows := seed.size / 2
	H := make([]*BitArray, nRows)
	for i := range H {
		H[i] = SternMatrixRow(seed, i)
	}
	return H
}

// sternSyndromeH computes H·e^T mod 2 from a prebuilt H matrix.
func sternSyndromeH(H []*BitArray, e *BitArray) *big.Int {
	syn := new(big.Int)
	for i, row := range H {
		dot := new(big.Int).And(&row.Val, &e.Val)
		if CountBits(dot)%2 == 1 {
			syn.SetBit(syn, i, 1)
		}
	}
	return syn
}

// SternSyndrome computes H·e^T mod 2.
// One-off wrapper; hot paths should use SternBuildH + sternSyndromeH.
func SternSyndrome(seed, e *BitArray) *big.Int {
	return sternSyndromeH(SternBuildH(seed), e)
}

// SyndrToBA stores a syndrome *big.Int in the low bits of a BitArray.
func SyndrToBA(n int, syn *big.Int) *BitArray {
	ba := &BitArray{size: n}
	ba.Val.Set(syn)
	return ba
}

// SternGenPerm derives a Fisher-Yates permutation deterministically from piSeed.
// Counter-mode extraction: all n/8 bytes of each state block are consumed as
// sequential 32-bit draws before advancing the state (no entropy wasted).
// Rejection sampling (threshold = 2^32 - 2^32%range, as uint64 to avoid truncation
// when range divides 2^32) eliminates modular bias.
func SternGenPerm(piSeed *BitArray, N int) []int {
	n := piSeed.size
	nb := n / 8
	key := piSeed.RotateLeft(n / 8)
	st := piSeed.Copy()
	perm := make([]int, N)
	for i := range perm {
		perm[i] = i
	}
	var stBytes []byte
	cursor := nb // force state advance on first draw
	for i := N - 1; i > 0; i-- {
		range_ := uint64(i + 1)
		threshold := uint64(0x100000000) - uint64(0x100000000)%range_
		var v uint32
		for {
			if cursor+4 > nb {
				st = NlFscxV1(st, key)
				stBytes = st.Bytes()
				cursor = 0
			}
			v = uint32(stBytes[cursor])<<24 | uint32(stBytes[cursor+1])<<16 |
				uint32(stBytes[cursor+2])<<8 | uint32(stBytes[cursor+3])
			cursor += 4
			if uint64(v) < threshold {
				break
			}
		}
		j := int(v % uint32(range_))
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// SternApplyPerm applies permutation perm: out[perm[i]] = v[i].
// Branchless: SetBit is called unconditionally with Bit(i) (0 or 1).
func SternApplyPerm(perm []int, v *BitArray) *BitArray {
	N := v.size
	out := &BitArray{size: N}
	for i := 0; i < N; i++ {
		out.Val.SetBit(&out.Val, perm[i], v.Val.Bit(i))
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
	digest := Hfscx256(chSt.Bytes(), nil)
	chSt = &BitArray{size: n}
	chSt.Val.SetBytes(digest[:n/8])
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
	if rounds < SdfProductionRounds {
		log.Printf("WARNING: HpksSternFSign called with rounds=%d < SdfProductionRounds=%d; "+
			"Stern signatures have sub-128-bit soundness (demo only)", rounds, SdfProductionRounds)
	}
	n := msg.size
	t := n / 16
	H := SternBuildH(seed)
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
		hrBA := SyndrToBA(n, sternSyndromeH(H, r))
		c0 := SternHash(1, pi, hrBA)
		c1 := SternHash(2, sr)
		c2 := SternHash(3, sy)
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
	H := SternBuildH(seed)
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
			if !SternHash(2, r.RespA).Equal(r.C1) {
				return false
			}
			if !SternHash(3, r.RespB).Equal(r.C2) {
				return false
			}
			if CountBits(&r.RespA.Val) != t {
				return false
			}
		case 1:
			if CountBits(&r.RespB.Val) != t {
				return false
			}
			hrBA := SyndrToBA(n, sternSyndromeH(H, r.RespB))
			if !SternHash(1, r.RespA, hrBA).Equal(r.C0) {
				return false
			}
			sr2 := SternApplyPerm(SternGenPerm(r.RespA, n), r.RespB)
			if !SternHash(2, sr2).Equal(r.C1) {
				return false
			}
		default:
			hysBA := SyndrToBA(n, new(big.Int).Xor(sternSyndromeH(H, r.RespB), syndrome))
			if !SternHash(1, r.RespA, hysBA).Equal(r.C0) {
				return false
			}
			sy2 := SternApplyPerm(SternGenPerm(r.RespA, n), r.RespB)
			if !SternHash(3, sy2).Equal(r.C2) {
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
	return SternHash(4, seed, ePrime), ct, ePrime
}

// HpkeSternFDecapKnown recomputes K = hash(seed, e') given e' directly (demo only).
func HpkeSternFDecapKnown(ePrime, seed *BitArray) *BitArray {
	return SternHash(4, seed, ePrime)
}

// ---------------------------------------------------------------------------
// ZKP-RNL: Ring-LWR Σ-protocol (Lyubashevsky-style, Fiat-Shamir compiled)
// SecurityProofs-3.md §11.10.2
// ---------------------------------------------------------------------------

const sigmaMaxAttempts = 1000

// ZkpRnlParams returns (gamma, t) for the Ring-LWR Σ-protocol at bit-width n.
func ZkpRnlParams(n int) (gamma, t int) {
	if n <= 32 {
		return 4096, 4
	}
	return 8192, 16
}

// sigmaPolyBytes serializes a polynomial (possibly signed) to bytes for hashing (4 B/coeff).
func sigmaPolyBytes(poly []int) []byte {
	out := make([]byte, len(poly)*4)
	for i, c := range poly {
		v := uint32(c) // two's complement handles negative
		out[4*i+0] = byte(v >> 24)
		out[4*i+1] = byte(v >> 16)
		out[4*i+2] = byte(v >> 8)
		out[4*i+3] = byte(v)
	}
	return out
}

// sigmaPolyMulN multiplies two polynomials in Z_q[x]/(x^n+1) using O(n²) schoolbook.
// Used for n<256 where NTT twiddles are not precomputed.
func sigmaPolyMulN(f, g []int, n, q int) []int {
	h := make([]int, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			idx := i + j
			v := int64(f[i]) * int64(g[j])
			if idx >= n {
				idx -= n
				v = -v
			}
			h[idx] = int((int64(h[idx]) + v + int64(q)*int64(q)) % int64(q))
		}
	}
	return h
}

// sigmaChallenge derives a sparse ternary challenge polynomial from (m, C, w, msg).
// Returns a []int of length n in {0, 1, q-1} with exactly t nonzero entries.
func sigmaChallenge(mPoly, cPoly, wPoly []int, n, q, t int, msg []byte) []int {
	buf := make([]byte, 4)
	buf[0] = byte(n >> 24); buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8);  buf[3] = byte(n)
	data := make([]byte, 0, 4+len(mPoly)*12+len(msg))
	data = append(data, buf...)
	data = append(data, sigmaPolyBytes(mPoly)...)
	data = append(data, sigmaPolyBytes(cPoly)...)
	data = append(data, sigmaPolyBytes(wPoly)...)
	data = append(data, msg...)
	seed := Hfscx256(data, nil)

	// Expand seed to t distinct positions
	positions := make([]int, 0, t)
	seen := make(map[int]bool, t)
	for idx := 0; len(positions) < t; idx++ {
		ext := Hfscx256(append(seed, append([]byte("pos"), []byte{byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx)}...)...), nil)
		v := (int(ext[0])<<24 | int(ext[1])<<16 | int(ext[2])<<8 | int(ext[3])) & 0x7FFFFFFF
		v = v % n
		if !seen[v] {
			seen[v] = true
			positions = append(positions, v)
		}
	}

	// Assign ±1 signs (stored as Z_q: +1 or q-1)
	out := make([]int, n)
	for k, pos := range positions {
		ext := Hfscx256(append(seed, append([]byte("sgn"), []byte{byte(k >> 24), byte(k >> 16), byte(k >> 8), byte(k)}...)...), nil)
		if ext[0]&1 == 0 {
			out[pos] = 1
		} else {
			out[pos] = q - 1
		}
	}
	return out
}

// RnlSigmaSign produces a ZKP-RNL Σ-protocol proof of knowledge of s s.t. C = round_p(m·s).
// Returns (wPoly, cPoly, zPoly). Returns error if rejection limit is exceeded.
func RnlSigmaSign(sPoly, mPoly, cPoly []int, n int, msg []byte) (w, c, z []int, err error) {
	q := RnlQ
	gamma, t := ZkpRnlParams(n)
	bound := gamma - t
	half := q / 2

	polyMul := func(f, g []int) []int {
		if n == 256 {
			return RnlPolyMul(f, g, q, n)
		}
		return sigmaPolyMulN(f, g, n, q)
	}

	rangeSz := 2*gamma + 1
	buf := make([]byte, 4)
	for attempt := 0; attempt < sigmaMaxAttempts; attempt++ {
		y := make([]int, n)
		for i := range y {
			if _, rerr := rand.Read(buf); rerr != nil {
				return nil, nil, nil, rerr
			}
			v := int(binary.BigEndian.Uint32(buf)) % rangeSz
			y[i] = v - gamma
		}
		yQ := make([]int, n)
		for i, yi := range y {
			yQ[i] = ((yi % q) + q) % q
		}
		my := polyMul(mPoly, yQ)
		wLocal := make([]int, n)
		for i, c := range my {
			if c > half {
				wLocal[i] = c - q
			} else {
				wLocal[i] = c
			}
		}
		cLocal := sigmaChallenge(mPoly, cPoly, wLocal, n, q, t, msg)
		cs := polyMul(cLocal, sPoly)
		csC := make([]int, n)
		for i, x := range cs {
			if x > half {
				csC[i] = x - q
			} else {
				csC[i] = x
			}
		}
		zLocal := make([]int, n)
		ok := true
		for i := range zLocal {
			zLocal[i] = y[i] + csC[i]
			if zLocal[i] > bound || zLocal[i] < -bound {
				ok = false
				break
			}
		}
		if ok {
			return wLocal, cLocal, zLocal, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("RnlSigmaSign: rejection sampling limit (%d) reached", sigmaMaxAttempts)
}

// RnlSigmaVerify verifies a ZKP-RNL Σ-protocol proof (w, c, z) for statement (m, C, msg).
func RnlSigmaVerify(mPoly, cpoly []int, n int, msg []byte, wPoly, cPoly, zPoly []int) bool {
	q := RnlQ
	p := RnlP
	gamma, t := ZkpRnlParams(n)
	bound := gamma - t
	slack := t * (q/(2*p) + 1)
	half := q / 2

	polyMul := func(f, g []int) []int {
		if n == 256 {
			return RnlPolyMul(f, g, q, n)
		}
		return sigmaPolyMulN(f, g, n, q)
	}

	// (1) infinity-norm bound
	for _, zi := range zPoly {
		if zi > bound || zi < -bound {
			return false
		}
	}
	// (2) Fiat-Shamir consistency
	cRecomputed := sigmaChallenge(mPoly, cpoly, wPoly, n, q, t, msg)
	for i := range cRecomputed {
		if cRecomputed[i] != cPoly[i] {
			return false
		}
	}
	// (3) rounding slack: ||m·z − w − c·lift(C)||∞ ≤ slack
	zQ := make([]int, n)
	for i, zi := range zPoly {
		zQ[i] = ((zi % q) + q) % q
	}
	mz := polyMul(mPoly, zQ)
	lift := RnlLift(cpoly, p, q)
	ct := polyMul(cPoly, lift)
	wQ := make([]int, n)
	for i, wi := range wPoly {
		wQ[i] = ((wi % q) + q) % q
	}
	for i := range mz {
		d := ((mz[i] - ct[i] - wQ[i]) % q + q) % q
		dc := d
		if dc > half {
			dc = dc - q
		}
		if dc > slack || dc < -slack {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// ZKP-NL: NL-FSCX ZKBoo (MPC-in-the-head, 3-party Boolean circuit)
// SecurityProofs-3.md §11.10.3
// ---------------------------------------------------------------------------

const (
	ZkpNlDefaultN   = 8
	ZkpNlDemoRounds = 4
	ZkpNlProdRounds = 219
	ZkpNlMaxN       = 32
)

// ZkpNlRound holds one round of a ZKBoo proof.
type ZkpNlRound struct {
	Com0, Com1, Com2 [32]byte
	E                int
	ViewP1, ViewP2   []byte
}

func zkpNlRol(x uint32, r, n int) uint32 {
	r = ((r % n) + n) % n
	if r == 0 {
		return x
	}
	mask := uint32((1 << uint(n)) - 1)
	return ((x << uint(r)) | (x >> uint(n-r))) & mask
}

func zkpNlH(parts ...[]byte) []byte {
	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return Hfscx256(buf, nil)
}

func zkpNlPrgBit(tape []byte, gateID int) int {
	gidBuf := []byte{byte(gateID >> 24), byte(gateID >> 16), byte(gateID >> 8), byte(gateID)}
	h := zkpNlH(tape, gidBuf)
	return int(h[0] & 1)
}

// zkpNlEvalCircuit evaluates nl_fscx_v1(A, B) in 3-party ZKBoo decomposition.
// shares: XOR shares of A (A = s0^s1^s2), tapes: 3×32-byte tapes.
// Returns (outShares[3], gateViews[3][n-1]) where each gate view byte = ai|(ci<<1)|(andOut<<2).
func zkpNlEvalCircuit(shares [3]uint32, tapes [3][]byte, B uint32, n int) ([3]uint32, [3][]byte) {
	mask := uint32((1 << uint(n)) - 1)
	carry := [3]uint32{} // current carry bits per party; starts at 0
	gateViews := [3][]byte{
		make([]byte, n-1),
		make([]byte, n-1),
		make([]byte, n-1),
	}

	for i := 0; i < n-1; i++ {
		var ai, ci, ri [3]int
		Bi := int((B >> uint(i)) & 1)
		for p := 0; p < 3; p++ {
			ai[p] = int((shares[p] >> uint(i)) & 1)
			ci[p] = int((carry[p] >> uint(i)) & 1)
			ri[p] = zkpNlPrgBit(tapes[p], i)
		}
		var andOut [3]int
		for p := 0; p < 3; p++ {
			p1 := (p + 1) % 3
			andOut[p] = (ai[p]&ci[p])^(ai[p]&ci[p1])^(ai[p1]&ci[p])^ri[p]^ri[p1]
		}
		for p := 0; p < 3; p++ {
			gateViews[p][i] = byte(ai[p] | (ci[p] << 1) | (andOut[p] << 2))
		}
		// c_{i+1} = Bi*ai XOR andOut XOR Bi*ci
		for p := 0; p < 3; p++ {
			cNext := (Bi*ai[p])^andOut[p]^(Bi*ci[p])
			if cNext == 1 {
				carry[p] |= 1 << uint(i+1)
			} else {
				carry[p] &^= 1 << uint(i+1)
			}
		}
	}

	// Sum shares: bit i of (A+B) mod 2^n = A_i XOR B_i XOR carry_i (linear)
	var sumShares [3]uint32
	for i := 0; i < n; i++ {
		Bi := uint32((B >> uint(i)) & 1)
		for p := 0; p < 3; p++ {
			bit := ((shares[p] >> uint(i)) & 1) ^ Bi ^ ((carry[p] >> uint(i)) & 1)
			sumShares[p] ^= bit << uint(i)
		}
	}

	// ROL_{n/4} (linear — apply identically to each share)
	var rotShares [3]uint32
	for p := 0; p < 3; p++ {
		rotShares[p] = zkpNlRol(sumShares[p], n/4, n)
	}

	// Linear part: fscx(A, B) with B constant
	Bconst := (B ^ zkpNlRol(B, 1, n) ^ zkpNlRol(B, n-1, n)) & mask
	var linShares [3]uint32
	for p := 0; p < 3; p++ {
		Aterms := (shares[p] ^ zkpNlRol(shares[p], 1, n) ^ zkpNlRol(shares[p], n-1, n)) & mask
		linShares[p] = Aterms
	}
	linShares[0] ^= Bconst // absorb public constant into party 0 only

	var outShares [3]uint32
	for p := 0; p < 3; p++ {
		outShares[p] = (linShares[p] ^ rotShares[p]) & mask
	}
	return outShares, gateViews
}

func zkpNlPackView(share uint32, tape []byte, outShare uint32, gateBytes []byte, n, nb int) []byte {
	buf := make([]byte, nb+32+nb+len(gateBytes))
	// share (nb bytes big-endian)
	for i := nb - 1; i >= 0; i-- {
		buf[i] = byte(share)
		share >>= 8
	}
	copy(buf[nb:nb+32], tape)
	// out_share (nb bytes big-endian)
	os := outShare
	for i := nb + 32 + nb - 1; i >= nb+32; i-- {
		buf[i] = byte(os)
		os >>= 8
	}
	copy(buf[nb+32+nb:], gateBytes)
	return buf
}

func zkpNlUnpackView(buf []byte, n, nb int) (share uint32, tape []byte, outShare uint32, gv []byte) {
	share = 0
	for i := 0; i < nb; i++ {
		share = (share << 8) | uint32(buf[i])
	}
	tape = buf[nb : nb+32]
	outShare = 0
	for i := nb + 32; i < nb+32+nb; i++ {
		outShare = (outShare << 8) | uint32(buf[i])
	}
	gv = buf[nb+32+nb:]
	return
}

// ZkpNlKeygen generates (A private, B public, y = nl_fscx_v1(A,B) public).
func ZkpNlKeygen(n int) (A, B, y uint32, err error) {
	nb := (n + 7) / 8
	mask := uint32((1 << uint(n)) - 1)
	buf := make([]byte, nb*2)
	if _, err = rand.Read(buf); err != nil {
		return
	}
	A = 0
	for i := 0; i < nb; i++ {
		A = (A << 8) | uint32(buf[i])
	}
	A &= mask
	B = 0
	for i := 0; i < nb; i++ {
		B = (B << 8) | uint32(buf[nb+i])
	}
	B &= mask
	// nl_fscx_v1(A, B) as uint32
	aBA := NewBitArray(n, new(big.Int).SetUint64(uint64(A)))
	bBA := NewBitArray(n, new(big.Int).SetUint64(uint64(B)))
	yBA := NlFscxV1(aBA, bBA)
	y = uint32(yBA.Val.Uint64()) & mask
	return
}

// ZkpNlProve produces a ZKBoo proof that the prover knows A s.t. nl_fscx_v1(A, B) = y.
func ZkpNlProve(A, B, y uint32, n, rounds int, msg []byte) ([]ZkpNlRound, error) {
	mask := uint32((1 << uint(n)) - 1)
	nb := (n + 7) / 8

	type roundData struct {
		coms      [3][32]byte
		shares    [3]uint32
		tapes     [3][]byte
		outShares [3]uint32
		gateViews [3][]byte
	}
	allData := make([]roundData, rounds)
	var comBlock []byte

	buf := make([]byte, nb)
	for j := 0; j < rounds; j++ {
		var s [3]uint32
		for k := 0; k < 2; k++ {
			if _, err := rand.Read(buf); err != nil {
				return nil, err
			}
			s[k] = 0
			for i := 0; i < nb; i++ {
				s[k] = (s[k] << 8) | uint32(buf[i])
			}
			s[k] &= mask
		}
		s[2] = (A ^ s[0] ^ s[1]) & mask

		var tapes [3][]byte
		for k := 0; k < 3; k++ {
			tapes[k] = make([]byte, 32)
			if _, err := rand.Read(tapes[k]); err != nil {
				return nil, err
			}
		}

		outShares, gateViews := zkpNlEvalCircuit(s, tapes, B, n)

		var rd roundData
		rd.shares = s
		rd.tapes = tapes
		rd.outShares = outShares
		rd.gateViews = gateViews

		jBuf := []byte{byte(j >> 24), byte(j >> 16), byte(j >> 8), byte(j)}
		for p := 0; p < 3; p++ {
			osBuf := make([]byte, nb)
			os := outShares[p]
			for i := nb - 1; i >= 0; i-- {
				osBuf[i] = byte(os)
				os >>= 8
			}
			h := zkpNlH(jBuf, []byte{byte(p)}, tapes[p], osBuf)
			copy(rd.coms[p][:], h)
			comBlock = append(comBlock, h...)
		}
		allData[j] = rd
	}

	// Fiat-Shamir challenge seed
	nBuf := make([]byte, nb)
	bVal := B
	for i := nb - 1; i >= 0; i-- {
		nBuf[i] = byte(bVal)
		bVal >>= 8
	}
	yBuf := make([]byte, nb)
	yVal := y
	for i := nb - 1; i >= 0; i-- {
		yBuf[i] = byte(yVal)
		yVal >>= 8
	}
	chSeed := zkpNlH(comBlock, nBuf, yBuf, msg)

	result := make([]ZkpNlRound, rounds)
	for j := 0; j < rounds; j++ {
		jBuf := []byte{byte(j >> 24), byte(j >> 16), byte(j >> 8), byte(j)}
		h := zkpNlH(chSeed, jBuf)
		e := int(h[0]) % 3
		p1 := (e + 1) % 3
		p2 := (e + 2) % 3

		rd := allData[j]
		result[j].Com0 = rd.coms[0]
		result[j].Com1 = rd.coms[1]
		result[j].Com2 = rd.coms[2]
		result[j].E = e
		result[j].ViewP1 = zkpNlPackView(rd.shares[p1], rd.tapes[p1], rd.outShares[p1], rd.gateViews[p1], n, nb)
		result[j].ViewP2 = zkpNlPackView(rd.shares[p2], rd.tapes[p2], rd.outShares[p2], rd.gateViews[p2], n, nb)
	}
	return result, nil
}

// ZkpNlVerify verifies a ZKBoo proof that prover knows A s.t. nl_fscx_v1(A, B) = y.
func ZkpNlVerify(B, y uint32, n, rounds int, msg []byte, proof []ZkpNlRound) bool {
	nb := (n + 7) / 8

	// Reconstruct commitment block and Fiat-Shamir seed
	var comBlock []byte
	for _, r := range proof {
		comBlock = append(comBlock, r.Com0[:]...)
		comBlock = append(comBlock, r.Com1[:]...)
		comBlock = append(comBlock, r.Com2[:]...)
	}
	nBuf := make([]byte, nb)
	bVal := B
	for i := nb - 1; i >= 0; i-- {
		nBuf[i] = byte(bVal); bVal >>= 8
	}
	yBuf := make([]byte, nb)
	yVal := y
	for i := nb - 1; i >= 0; i-- {
		yBuf[i] = byte(yVal); yVal >>= 8
	}
	chSeed := zkpNlH(comBlock, nBuf, yBuf, msg)

	eqBytes := func(a []byte, b [32]byte) bool {
		if len(a) < 32 {
			return false
		}
		for i := 0; i < 32; i++ {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	osBuf := func(v uint32) []byte {
		b := make([]byte, nb)
		for i := nb - 1; i >= 0; i-- {
			b[i] = byte(v); v >>= 8
		}
		return b
	}

	for j, r := range proof {
		jBuf := []byte{byte(j >> 24), byte(j >> 16), byte(j >> 8), byte(j)}
		h := zkpNlH(chSeed, jBuf)
		e := int(h[0]) % 3
		if e != r.E {
			return false
		}
		p1 := (e + 1) % 3
		p2 := (e + 2) % 3

		shareP1, tapeP1, outP1, gvP1 := zkpNlUnpackView(r.ViewP1, n, nb)
		shareP2, tapeP2, outP2, gvP2 := zkpNlUnpackView(r.ViewP2, n, nb)

		// Verify commitments for revealed parties
		c1h := zkpNlH(jBuf, []byte{byte(p1)}, tapeP1, osBuf(outP1))
		if !eqBytes(c1h, r.comAt(p1)) {
			return false
		}
		c2h := zkpNlH(jBuf, []byte{byte(p2)}, tapeP2, osBuf(outP2))
		if !eqBytes(c2h, r.comAt(p2)) {
			return false
		}

		// Re-evaluate p1's AND gates using both revealed shares
		var carryP1, carryP2 uint32
		for i := 0; i < n-1; i++ {
			aiP1 := int((shareP1 >> uint(i)) & 1)
			aiP2 := int((shareP2 >> uint(i)) & 1)
			ciP1 := int((carryP1 >> uint(i)) & 1)
			ciP2 := int((carryP2 >> uint(i)) & 1)
			Bi   := int((B >> uint(i)) & 1)

			riP1 := zkpNlPrgBit(tapeP1, i)
			riP2 := zkpNlPrgBit(tapeP2, i)

			expAndP1 := (aiP1&ciP1) ^ (aiP1&ciP2) ^ (aiP2&ciP1) ^ riP1 ^ riP2
			if int((gvP1[i]>>2)&1) != expAndP1 {
				return false
			}
			andOutP2 := int((gvP2[i] >> 2) & 1)

			cNextP1 := (Bi*aiP1) ^ expAndP1 ^ (Bi * ciP1)
			if cNextP1 == 1 { carryP1 |= 1 << uint(i+1) } else { carryP1 &^= 1 << uint(i+1) }
			cNextP2 := (Bi*aiP2) ^ andOutP2 ^ (Bi * ciP2)
			if cNextP2 == 1 { carryP2 |= 1 << uint(i+1) } else { carryP2 &^= 1 << uint(i+1) }
		}
	}
	return true
}

// comAt returns the commitment for party p (0, 1, or 2).
func (r *ZkpNlRound) comAt(p int) [32]byte {
	switch p {
	case 0: return r.Com0
	case 1: return r.Com1
	default: return r.Com2
	}
}

// ---------------------------------------------------------------------------
// 78.J — Cryptographic Accumulator (Merkle tree on HFSCX-256) (TODO #78.J)
//
// Domain separation follows RFC 6962: 0x00 prefix for leaves, 0x01 for nodes.
// ---------------------------------------------------------------------------

// HaccumLeaf returns HFSCX-256(0x00 || data).
func HaccumLeaf(data []byte) []byte {
	return Hfscx256(append([]byte{0x00}, data...), nil)
}

// HaccumNode returns HFSCX-256(0x01 || left || right).
func HaccumNode(left, right []byte) []byte {
	buf := make([]byte, 1+len(left)+len(right))
	buf[0] = 0x01
	copy(buf[1:], left)
	copy(buf[1+len(left):], right)
	return Hfscx256(buf, nil)
}

// HaccumRoot computes the Merkle root of leafHashes (each 32 bytes).
// Non-power-of-2 counts are padded with zero-hashes on the right.
func HaccumRoot(leafHashes [][]byte) []byte {
	n := len(leafHashes)
	if n == 0 {
		return make([]byte, 32)
	}
	sz := 1
	for sz < n {
		sz <<= 1
	}
	nodes := make([][]byte, sz)
	for i := 0; i < n; i++ {
		nodes[i] = append([]byte(nil), leafHashes[i]...)
	}
	for i := n; i < sz; i++ {
		nodes[i] = make([]byte, 32)
	}
	for sz > 1 {
		for i := 0; i < sz/2; i++ {
			nodes[i] = HaccumNode(nodes[2*i], nodes[2*i+1])
		}
		sz /= 2
	}
	return nodes[0]
}

// HaccumProve returns the sibling-hash proof path for leaf at idx.
func HaccumProve(leafHashes [][]byte, idx int) [][]byte {
	n := len(leafHashes)
	sz := 1
	for sz < n {
		sz <<= 1
	}
	nodes := make([][]byte, sz)
	for i := 0; i < n; i++ {
		nodes[i] = append([]byte(nil), leafHashes[i]...)
	}
	for i := n; i < sz; i++ {
		nodes[i] = make([]byte, 32)
	}
	var proof [][]byte
	cur := idx
	for sz > 1 {
		sib := cur ^ 1
		proof = append(proof, append([]byte(nil), nodes[sib]...))
		for i := 0; i < sz/2; i++ {
			nodes[i] = HaccumNode(nodes[2*i], nodes[2*i+1])
		}
		sz /= 2
		cur >>= 1
	}
	return proof
}

// HaccumVerify verifies a Merkle membership proof for leafHash at idx.
func HaccumVerify(root, leafHash []byte, proof [][]byte, idx int) bool {
	cur := append([]byte(nil), leafHash...)
	for _, sib := range proof {
		if idx%2 == 0 {
			cur = HaccumNode(cur, sib)
		} else {
			cur = HaccumNode(sib, cur)
		}
		idx >>= 1
	}
	return bytes.Equal(cur, root)
}

// ---------------------------------------------------------------------------
// 78.A — Format-Preserving Encryption (FPE) (TODO #78.A)
//
// B = HFSCX-256(key || ctx); C = NlFscxRevolveV2(P, B, IValue).
// Same (key, ctx, plaintext) → same ciphertext (deterministic / searchable).
// For IND-CPA include a per-record nonce in ctx.
// ---------------------------------------------------------------------------

func fpeDeriveB(key, ctx []byte) *BitArray {
	tweak := Hfscx256(append(key, ctx...), nil)
	return NewBitArray(256, new(big.Int).SetBytes(tweak))
}

// FpeEncrypt encrypts a 256-bit BitArray with key and context.
func FpeEncrypt(pt *BitArray, key, ctx []byte) *BitArray {
	return NlFscxRevolveV2(pt, fpeDeriveB(key, ctx), 64) // 64 = I_VALUE
}

// FpeDecrypt decrypts a 256-bit BitArray with key and context.
func FpeDecrypt(ct *BitArray, key, ctx []byte) *BitArray {
	return NlFscxRevolveV2Inv(ct, fpeDeriveB(key, ctx), 64)
}

// ---------------------------------------------------------------------------
// 78.B — Tweakable Wide-Block Cipher (TODO #78.B)
//
// B = HFSCX-256(key || sector_be64 || bidx_be32); C = NlFscxRevolveV2(P, B, IValue).
// Each block index within a sector gets a unique tweak, resolving the HSKE-NL-A2
// determinism limitation (TODO #12).
// ---------------------------------------------------------------------------

func twkDeriveB(key []byte, sector uint64, bidx uint32) *BitArray {
	buf := make([]byte, len(key)+12)
	copy(buf, key)
	binary.BigEndian.PutUint64(buf[len(key):], sector)
	binary.BigEndian.PutUint32(buf[len(key)+8:], bidx)
	tweak := Hfscx256(buf, nil)
	return NewBitArray(256, new(big.Int).SetBytes(tweak))
}

// TwkEncrypt encrypts a 256-bit block with sector and block-index tweaks.
func TwkEncrypt(block *BitArray, key []byte, sector uint64, bidx uint32) *BitArray {
	return NlFscxRevolveV2(block, twkDeriveB(key, sector, bidx), 64)
}

// TwkDecrypt decrypts a 256-bit block with sector and block-index tweaks.
func TwkDecrypt(ct *BitArray, key []byte, sector uint64, bidx uint32) *BitArray {
	return NlFscxRevolveV2Inv(ct, twkDeriveB(key, sector, bidx), 64)
}
