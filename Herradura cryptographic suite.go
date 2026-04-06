/*  Herradura Cryptographic Suite v1.4.0

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

    --- v1.4.0: HKEX-GF (Diffie-Hellman over GF(2^n)*) ---

    The broken fscx_revolve_n-based HKEX is replaced with HKEX-GF: a correct
    Diffie-Hellman key exchange over the multiplicative group GF(2^n)*.

    FscxRevolveN has been removed entirely from all protocol code.

    HKEX-GF protocol:
    - Pre-agreed: generator g=3 (polynomial x+1), irreducible poly p(x)
    - Alice: private scalar a -> public C = g^a in GF(2^n)*
    - Bob:   private scalar b -> public C2 = g^b
    - Shared key: sk = C2^a = C^b = g^{ab}  (DH commutativity in GF(2^n)*)
    Security rests on the hardness of DLP in GF(2^n)*, not on orbit structure.

    Protocol stack:
    - HKEX: replaced with GF DH (above)
    - HSKE: FscxRevolve(P, key, i) / FscxRevolve(E, key, r) — unchanged
    - HPKS: Schnorr-like signature with FscxRevolve challenge.
            Sign:   k random; R=g^k; e=FscxRevolve(R,P,I); s=(k-a*e) mod ord
            Verify: g^s * C^e == R  (public key C = g^a; anyone can verify)
    - HPKE: El Gamal + FscxRevolve.
            Bob: r ephemeral; R=g^r; enc_key=C^r=g^{ar}; E=FscxRevolve(P,enc_key,I)
            Alice: dec_key=R^a=g^{ar}; D=FscxRevolve(E,dec_key,R)==P

    --- v1.3.2: performance and readability ---

    - Fscx: rewritten without parameter shadowing; each term maps directly
      to the formula A⊕B⊕ROL(A)⊕ROL(B)⊕ROR(A)⊕ROR(B).
    - FscxRevolve: renamed from Fscx_revolve to follow Go's PascalCase convention.
    - NewRandBitArray: renamed from New_rand_bitarray for the same reason.
    - Local variables in main: renamed to camelCase.
    - Version header updated to v1.4.0.

    --- v1.3: BitArray (multi-byte parameter support) ---

    The Go implementation now uses 256-bit parameters by default, matching
    the C and Python versions at the same bit width.
*/

package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

// BitArray is a fixed-width bit string backed by big.Int.
// Supports XOR, rotation, equality, and hex formatting via %x.
// Size must be a positive multiple of 8.
type BitArray struct {
	val  big.Int
	size int
}

func bitArrayMask(size int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(size))
	return mask.Sub(mask, big.NewInt(1))
}

// NewFromBytes constructs a BitArray from raw bytes (big-endian). The offset
// parameter is accepted for API compatibility but must be 0.
func NewFromBytes(data []byte, _ int, size int) *BitArray {
	ba := &BitArray{size: size}
	ba.val.SetBytes(data[:size/8])
	return ba
}

// NewRandBitArray returns a cryptographically random BitArray of bitlength bits.
func NewRandBitArray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

// Xor returns a new BitArray that is the bitwise XOR of ba and other.
func (ba *BitArray) Xor(other *BitArray) *BitArray {
	result := &BitArray{size: ba.size}
	result.val.Xor(&ba.val, &other.val)
	return result
}

// RotateLeft returns a new BitArray rotated left by n bits.
// Negative n rotates right.
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

// Equal reports whether ba and other have the same size and value.
func (ba *BitArray) Equal(other *BitArray) bool {
	return ba.size == other.size && ba.val.Cmp(&other.val) == 0
}

// Format implements fmt.Formatter; supports the %x verb with zero-padded output.
func (ba *BitArray) Format(f fmt.State, verb rune) {
	hexDigits := ba.size / 4
	s := ba.val.Text(16)
	for i := len(s); i < hexDigits; i++ {
		f.Write([]byte{'0'})
	}
	fmt.Fprint(f, s)
}

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

// FscxRevolve iterates Fscx(a, b) for the given number of steps,
// keeping b constant. If verbose is true, each intermediate result is printed.
func FscxRevolve(a, b *BitArray, steps int, verbose bool) *BitArray {
	result := a
	for i := 1; i <= steps; i++ {
		result = Fscx(result, b)
		if verbose {
			fmt.Printf("Step %d: %x\n", i, result)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// GF(2^n) field arithmetic — XOR + left-shift using big.Int
// ---------------------------------------------------------------------------

// gfPoly maps bit-width to irreducible polynomial (lower n bits; x^n implicit).
var gfPoly = map[int]*big.Int{
	32:  new(big.Int).SetUint64(0x00400007),
	64:  new(big.Int).SetUint64(0x0000001B),
	128: new(big.Int).SetUint64(0x00000087),
	256: new(big.Int).SetUint64(0x00000425),
}

const gfGen = 3 // g = x+1 in GF(2^n)[x]

// GfMul multiplies a and b in GF(2^n) using carryless polynomial multiplication
// modulo the irreducible polynomial poly, with field size n bits.
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

// GfPow computes base^exp in GF(2^n)* via repeated squaring.
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

/*
HKEX-GF (key exchange over GF(2^n)*)
    Pre-agreed: generator g=gfGen, irreducible polynomial gfPoly[n]
    Alice:  private scalar a (random n-bit integer)
            C = g^a in GF(2^n)*
            send C to Bob and receive C2
            sk = C2^a in GF(2^n)*
    Bob:    private scalar b (random n-bit integer)
            C2 = g^b in GF(2^n)*
            send C2 to Alice and receive C
            sk = C^b in GF(2^n)*
    Result: C2^a = (g^b)^a = g^{ab} = (g^a)^b = C^b

HSKE (symmetric key encryption):
    Alice,Bob:  share preshared key of bitlength n
    Alice:  E = FscxRevolve(P, key, i)
            shares E with Bob
    Bob:    P = FscxRevolve(E, key, r)

HPKS (Schnorr-like public key signature — publicly verifiable)
    Alice:  private scalar a (integer), public C = g^a
    Sign(P):
      k  = random nonce scalar
      R  = g^k  in GF(2^n)*                           (commitment)
      e  = FscxRevolve(R_bits, P, I_VALUE)             (challenge via FscxRevolve)
      s  = (k - a * e) mod (2^n - 1)                  (Schnorr response)
      signature = (R, s)
    Verify(P, C, sig=(R, s)):
      e  = FscxRevolve(R_bits, P, I_VALUE)             (recompute challenge)
      check: g^s * C^e == R  in GF(2^n)*
    Correctness: g^s * C^e = g^{k-ae} * g^{ae} = g^k = R  ✓
    Security: forging (R, s) without a requires solving DLP for C = g^a.

HPKE (public key encryption — El Gamal + FscxRevolve)
    Alice:  private scalar a, public C = g^a
    Bob:    picks ephemeral r; R = g^r  (ephemeral public)
            enc_key = C^r = g^{ar}     (from Alice's public + Bob's ephemeral private)
            E = FscxRevolve(P, enc_key, I_VALUE)
            sends (R, E) to Alice
    Alice:  dec_key = R^a = g^{ra} = enc_key
            D = FscxRevolve(E, dec_key, R_VALUE) == P
    Security: Eve has (C, R, E). Deriving enc_key = g^{ar} from g^a and g^r is CDH.
*/

func main() {
	const n = 256
	iValue := n / 4   // 64
	rValue := 3 * n / 4 // 192

	poly := gfPoly[n]
	g := big.NewInt(gfGen)

	// ORD = 2^n - 1  (group order of GF(2^n)* for Schnorr integer arithmetic)
	ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), n), big.NewInt(1))

	a         := NewRandBitArray(n)   // Alice's private scalar
	b         := NewRandBitArray(n)   // Bob's private scalar
	preshared := NewRandBitArray(n)
	plaintext := NewRandBitArray(n)
	decoy     := NewRandBitArray(n)   // Eve's random value (cannot compute sk)

	// HKEX-GF key exchange
	C  := &BitArray{size: n}; C.val.Set(GfPow(g, &a.val, poly, n))
	C2 := &BitArray{size: n}; C2.val.Set(GfPow(g, &b.val, poly, n))
	sk := &BitArray{size: n}; sk.val.Set(GfPow(&C2.val, &a.val, poly, n))
	skBob := &BitArray{size: n}; skBob.val.Set(GfPow(&C.val, &b.val, poly, n))

	fmt.Printf("a         : %x\n", a)
	fmt.Printf("b         : %x\n", b)
	fmt.Printf("preshared : %x\n", preshared)
	fmt.Printf("plaintext : %x\n", plaintext)
	fmt.Printf("decoy     : %x\n", decoy)
	fmt.Printf("C         : %x\n", C)
	fmt.Printf("C2        : %x\n", C2)

	fmt.Printf("\n--- HKEX-GF (key exchange over GF(2^%d)*)\n", n)
	fmt.Printf("sk (Alice): %x\n", sk)
	fmt.Printf("sk (Bob)  : %x\n", skBob)
	if sk.Equal(skBob) {
		fmt.Printf("+ session keys sk (Alice) and sk (Bob) are equal!\n")
	} else {
		fmt.Printf("- session keys sk (Alice) and sk (Bob) are different!\n")
	}

	fmt.Printf("\n--- HSKE (symmetric key encryption)\n")
	E := FscxRevolve(plaintext, preshared, iValue, false)
	fmt.Printf("E (Alice) : %x\n", E)
	D := FscxRevolve(E, preshared, rValue, false)
	fmt.Printf("D (Bob)   : %x\n", D)
	if D.Equal(plaintext) {
		fmt.Printf("+ plaintext is correctly decrypted from E with preshared key\n")
	} else {
		fmt.Printf("- plaintext is different from decrypted E with preshared key!\n")
	}

	fmt.Printf("\n--- HPKS (Schnorr-like signature: sign with private, verify with public key)\n")
	// Sign: Alice picks nonce k, commitment R=g^k,
	//       challenge e = FscxRevolve(R, P, I),  response s = (k - a*e) mod ord
	kS  := NewRandBitArray(n)
	RS  := &BitArray{size: n}; RS.val.Set(GfPow(g, &kS.val, poly, n))
	eS  := FscxRevolve(RS, plaintext, iValue, false)  // challenge via FscxRevolve
	ae  := new(big.Int).Mul(&a.val, &eS.val)
	sS  := new(big.Int).Mod(new(big.Int).Sub(&kS.val, ae), ord) // Schnorr response
	fmt.Printf("R (commit): %x\n", RS)
	fmt.Printf("e (fscx)  : %x\n", eS)
	fmt.Printf("s (resp)  : %0*x\n", n/4, sS)
	// Verify: anyone with Alice's public key C checks g^s * C^e == R
	eV  := FscxRevolve(RS, plaintext, iValue, false)
	lhs := GfMul(GfPow(g, sS, poly, n), GfPow(&C.val, &eV.val, poly, n), poly, n)
	if lhs.Cmp(&RS.val) == 0 {
		fmt.Printf("+ Schnorr verified: g^s · C^e == R  [public key sufficient]\n")
	} else {
		fmt.Printf("- Schnorr verification failed!\n")
	}

	fmt.Printf("\n--- HPKS (Schnorr) + HSKE: Alice signs the HSKE ciphertext; Bob verifies then decrypts\n")
	EHs := FscxRevolve(plaintext, preshared, iValue, false)  // HSKE: Alice encrypts P
	kHs := NewRandBitArray(n)
	RHs := &BitArray{size: n}; RHs.val.Set(GfPow(g, &kHs.val, poly, n))
	eHs := FscxRevolve(RHs, EHs, iValue, false)              // challenge over ciphertext
	aeH := new(big.Int).Mul(&a.val, &eHs.val)
	sHs := new(big.Int).Mod(new(big.Int).Sub(&kHs.val, aeH), ord)
	fmt.Printf("E (HSKE)  : %x\n", EHs)
	fmt.Printf("R (commit): %x\n", RHs)
	fmt.Printf("s (resp)  : %0*x\n", n/4, sHs)
	// Bob verifies Schnorr on E, then decrypts via HSKE
	eHv  := FscxRevolve(RHs, EHs, iValue, false)
	lhsH := GfMul(GfPow(g, sHs, poly, n), GfPow(&C.val, &eHv.val, poly, n), poly, n)
	DHs  := FscxRevolve(EHs, preshared, rValue, false)  // HSKE: Bob decrypts
	fmt.Printf("D (Bob)   : %x\n", DHs)
	if lhsH.Cmp(&RHs.val) == 0 && DHs.Equal(plaintext) {
		fmt.Printf("+ Schnorr on ciphertext verified; plaintext decrypted correctly!\n")
	} else {
		fmt.Printf("- Schnorr verification or decryption failed!\n")
	}

	fmt.Printf("\n--- HPKE (public key encryption, El Gamal + FscxRevolve)\n")
	// Bob generates ephemeral key pair; derives enc_key from Alice's public C
	r      := NewRandBitArray(n)
	R      := &BitArray{size: n}; R.val.Set(GfPow(g, &r.val, poly, n))
	encKey := &BitArray{size: n}; encKey.val.Set(GfPow(&C.val, &r.val, poly, n)) // C^r = g^{ar}
	EHpke  := FscxRevolve(plaintext, encKey, iValue, false)  // Bob encrypts
	fmt.Printf("r   (Bob eph priv): %x\n", r)
	fmt.Printf("R   (Bob eph pub) : %x\n", R)
	fmt.Printf("E   (Bob)         : %x\n", EHpke)
	// Alice derives the same enc_key using her private scalar a and Bob's ephemeral public R
	decKey := &BitArray{size: n}; decKey.val.Set(GfPow(&R.val, &a.val, poly, n)) // R^a = g^{ra}
	DHpke  := FscxRevolve(EHpke, decKey, rValue, false)  // Alice decrypts
	fmt.Printf("D   (Alice)       : %x\n", DHpke)
	if DHpke.Equal(plaintext) {
		fmt.Printf("+ plaintext is correctly decrypted from E with Alice's private key!\n")
	} else {
		fmt.Printf("- plaintext is different from decrypted E with private key!\n")
	}

	fmt.Printf("\n\n*** EVE bypass TESTS\n")
	fmt.Printf("*** HPKS Schnorr — Eve cannot forge without knowing Alice's private key a\n")
	// Eve wants to forge (R_eve, s_eve) for decoy so that g^{s_eve} * C^{e_eve} == R_eve
	// where e_eve = FscxRevolve(R_eve, decoy, I).  Without a, Eve can't compute s_eve.
	// Eve's attempt: pick a random R_eve and a random s_eve, hope the equation holds.
	REve   := &BitArray{size: n}
	REve.val.Set(GfPow(g, &NewRandBitArray(n).val, poly, n))
	eEve   := FscxRevolve(REve, decoy, iValue, false)
	sEve   := new(big.Int).Set(&NewRandBitArray(n).val)   // random guess — Eve doesn't know a
	lhsEve := GfMul(GfPow(g, sEve, poly, n), GfPow(&C.val, &eEve.val, poly, n), poly, n)
	lhsEveBA := &BitArray{size: n}; lhsEveBA.val.Set(lhsEve)
	fmt.Printf("R_eve (Eve)  : %x\n", REve)
	fmt.Printf("lhs_eve      : %x\n", lhsEveBA)
	fmt.Printf("match R_eve? : %v\n", lhsEve.Cmp(&REve.val) == 0)
	if lhsEve.Cmp(&REve.val) == 0 {
		fmt.Printf("+ Eve forged Schnorr signature (Eve wins)!\n")
	} else {
		fmt.Printf("- Eve could not forge: g^s_eve · C^e_eve ≠ R_eve  (DLP protection)\n")
	}

	fmt.Printf("\n*** HPKE — Eve cannot decrypt without Alice's private key\n")
	// Bob encrypted with enc_key = C^r = g^{ar}; sent (R, E).
	// Eve intercepts (R, E) and knows public values (C, R).
	// Eve's best attempt: use C XOR R as a key guess (no math, just public combination).
	eveKeyGuess := C.Xor(R)
	fmt.Printf("R (Bob eph pub)  : %x\n", R)
	fmt.Printf("E (ciphertext)   : %x\n", EHpke)
	fmt.Printf("Eve key guess    : %x\n", eveKeyGuess)
	DEve := FscxRevolve(EHpke, eveKeyGuess, rValue, false)
	fmt.Printf("D_eve (Eve)      : %x\n", DEve)
	if DEve.Equal(plaintext) {
		fmt.Printf("+ Eve decrypted plaintext (Eve wins)!\n")
	} else {
		fmt.Printf("- Eve could not decrypt without Alice's private key (CDH protection holds)\n")
	}
}
