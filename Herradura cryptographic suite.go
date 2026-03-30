/*  Herradura Cryptographic Suite v1.1

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

    --- v1.1: FSCX_REVOLVE_N ---

    v1.1 introduces FSCX_REVOLVE_N: a nonce-augmented variant of FSCX_REVOLVE
    where each iteration XORs a nonce N after the FSCX step:
        result = FSCX(result, B) ⊕ N

    This converts the purely linear GF(2) function to affine, breaking linearity
    while preserving the HKEX equality and orbit properties.

    Nonce derivation (no new secrets):
    - For HKEX, HPKS, HPKE: hkex_nonce = C ⊕ C2  — computable from the public key
      (C is in the public key; C2 = fscx_revolve(A2, B2, i) can be computed from
      A2, B2 also in the public key)
    - For HSKE: N = preshared key — the key is injected at every revolve step,
      not just at input/output boundaries

    Mathematical proof that HKEX equality is preserved:
    The HKEX equality
        FSCX_REVOLVE_N(C2, B, N, r) ⊕ A = FSCX_REVOLVE_N(C, B2, N, r) ⊕ A2
    holds because when you expand with C = FSCX_REVOLVE(A, B, i) and
    C2 = FSCX_REVOLVE(A2, B2, i), and use L^(r+i) = I (since r+i=P), the
    condition reduces to L^r(T_i(Z)) = T_r(Z) — the same condition as without
    the nonce. N cancels identically from both sides.
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

func New_rand_bitarray(bitlength int) *BitArray {
	buf := make([]byte, bitlength/8)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("ERROR while generating random string: %s", err)
	}
	return NewFromBytes(buf, 0, bitlength)
}

func Fscx_revolve(ba *BitArray, bb *BitArray, steps int, verbose bool) *BitArray {
	result := ba
	for i := 1; i <= steps; i++ {
		result = Fscx(result, bb)
		if verbose {
			fmt.Printf("Step %d: %x\n", i, result)
		}
	}
	return result
}

// Fscx_revolve_n: nonce-augmented FSCX_REVOLVE (v1.1).
// Each step: result = FSCX(result, bb) ⊕ nonce
// Breaks the pure GF(2)-linearity of FSCX_REVOLVE while preserving the HKEX equality
// and orbit properties. The HKEX equality holds for any nonce value because N cancels
// from both sides of the protocol equality condition.
func Fscx_revolve_n(ba *BitArray, bb *BitArray, nonce *BitArray, steps int, verbose bool) *BitArray {
	result := ba
	for i := 1; i <= steps; i++ {
		result = Fscx(result, bb).Xor(nonce)
		if verbose {
			fmt.Printf("Step %d: %x\n", i, result)
		}
	}
	return result
}

func Fscx(ba *BitArray, bb *BitArray) *BitArray {
	result := ba.Xor(bb)
	ba = ba.RotateLeft(1)
	bb = bb.RotateLeft(1)
	result = result.Xor(ba).Xor(bb) // result ^= A ^ B
	ba = ba.RotateLeft(-2)
	bb = bb.RotateLeft(-2)
	result = result.Xor(ba).Xor(bb) // result ^= A ^ B
	return result
}

/*
	let,    Alice, Bob: i + r == bitlength b;  i == 1/4 bitlength; r == 3/4 bitlength; bitlength is a power of 2 >= 8
			P be a plaintext message of bitlength b,
			E the encrypted version of plaintext P,
			D == P the decrypted version of E.
	let,    Alice: A,B be random values of bitlength b,
			Bob: A2,B2 be random values of bitlength b
	let,    Alice: C = fscx_revolve(A, B, i) ,
			Bob: C2 = fscx_revolve(A2, B2, i)
	then,   Alice: D = fscx_revolve(C2, B, r) ^ A ,
			Bob: D2 = fscx_revolve(C, B2, r) ^ A2
	where,  Alice, Bob: D == D2
	then,   fscx_revolve(C2, B, r) ^ A  == fscx_revolve(C, B2, r) ^ A2,
			fscx_revolve(C2, B, r) ^ A ^ P == fscx_revolve(C, B2, r) ^ A2 ^ P,
			fscx_revolve(C2, B, R) ^ A ^ A2 ^ P == fscx_revolve(C, B2, r)  ^ P #Note that this form breaks trapdoor
	also,   fscx_revolve(C2, B, r) ^ A  ^ P == fscx_revolve(C2 ^ P, B, r) ^ A

	let,    public key => {C,B2,A2,r},
			private key => {C2,B,A,r}
	then,   E = fscx_revolve(C, B2, r) ^ A2  ^ P,
			P == (D = fscx_revolve(C2, B, r) ^ A ^ E)

	let,    E = fscx_revolve(C2, B, r) ^ A  ^ P
	then,   fscx_revolve(E, B2, i) ^ A2 ^ P  == 0
			fscx_revolve(E ^ P, B2, i) == 0

	HKEX (key exchange)
		Alice:  C = fscx_revolve(A,B,i)
				send C to Bob and get C2
				shared_key = fscx_revolve(C2, B, r) ^ A,
		Bob:    C2 = fscx_revolve(A2,B2,i)
				send C2 to Alice and get C
				shared_key => fscx_revolve(C, B2, r) ^ A2

	HSKE (symmetric key encryption):
		Alice,Bob:  share key of bitlength b
		Alice:  E = fscx_revolve(P , key , i)
				shares E with Bob
		Bob:    P = fscx_revolve(E , key , r)

	HPKS (public key signature)
		Alice:  C = fscx_revolve(A,B,i)
				C2 = fscx_revolve(A2,B2,i)
				{publish (C,B2,A2,r) as public key, also disclose b,r,i; keep the rest of parameters (C2,B,A) as private key},
				S = fscx_revolve(C2, B, r) ^ A ^ P
				shares E, S with Bob
		Bob:    P = fscx_revolve(C,B2, r) ^ A2  ^ S

	HPKE (public key encryption)
		Alice:  C = fscx_revolve(A,B,i),
				C2 = fscx_revolve(A2,B2,i),
				{publish (C,B2,A2,r) as public key, keep the rest of parameters as private key},
		Bob:    E = fscx_revolve(C, B2, r) ^ A2  ^ P
				shares E with Alice
		Alice:  P = fscx_revolve(C2, B, r) ^ A ^ E
*/

func main() {
	/*
		A := New_rand_bitarray(256)
		B := New_rand_bitarray(256)
		C := Fscx(A, B)
		D := Fscx_revolve(A, B, 256, false)
		fmt.Printf("A         : %x\n", A)
		fmt.Printf("B         : %x\n", B)
		fmt.Printf("C         : %x\n", C)
		fmt.Printf("D         : %x\n\n", D)
	*/

	// Example Usage:
	r_value := 192 // Adjust as needed
	i_value := 64  // Adjust as needed

	A := New_rand_bitarray(256)
	fmt.Printf("A         : %x\n", A)
	A2 := New_rand_bitarray(256)
	fmt.Printf("A2        : %x\n", A2)
	B := New_rand_bitarray(256)
	fmt.Printf("B         : %x\n", B)
	B2 := New_rand_bitarray(256)
	fmt.Printf("B2        : %x\n", B2)
	C := Fscx_revolve(A, B, i_value, false)
	fmt.Printf("C         : %x\n", C)
	C2 := Fscx_revolve(A2, B2, i_value, false)
	fmt.Printf("C2        : %x\n", C2)
	hkex_nonce := C.Xor(C2) // N = C ⊕ C2: session-specific nonce (computable from public key)
	fmt.Printf("hkex_nonce: %x\n", hkex_nonce)
	nonce := New_rand_bitarray(256)
	fmt.Printf("nonce     : %x\n", nonce)
	preshared := New_rand_bitarray(256)
	fmt.Printf("preshared : %x\n", preshared)
	plaintext := New_rand_bitarray(256)
	fmt.Printf("plaintext : %x\n", plaintext)

	fmt.Printf("\n--- HKEX (key exchange)\n")
	skeyA := Fscx_revolve_n(C2, B, hkex_nonce, r_value, false).Xor(A)
	fmt.Printf("skeyA     : %x\n", skeyA)
	skeyB := Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2)
	fmt.Printf("skeyB     : %x\n", skeyB)
	if skeyA.Equal(skeyB) { // Assert equality
		fmt.Printf("+ session keys skeyA and skeyB are equal!\n")
	} else {
		fmt.Printf("- session keys skeyA and skeyB are different!\n")
	}

	fmt.Printf("\n--- HSKE (symmetric key encryption)\n")
	E := Fscx_revolve_n(plaintext, preshared, preshared, i_value, false)
	fmt.Printf("E (Alice) : %x\n", E)
	D := Fscx_revolve_n(E, preshared, preshared, r_value, false)
	fmt.Printf("D (Bob)   : %x\n", D)
	if D.Equal(plaintext) { // Assert equality
		fmt.Printf("+ plaintext is correctly decrypted from E with preshared key\n")
	} else {
		fmt.Printf("- plaintext is different from decrypted E with preshared key!\n")
	}

	fmt.Printf("\n--- HPKS (public key signature)\n")
	S := Fscx_revolve_n(C2, B, hkex_nonce, r_value, false).Xor(A).Xor(plaintext)
	fmt.Printf("S (Alice) : %x\n", S)
	V := Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(S) // == plaintext !!!!
	fmt.Printf("V (Bob)   : %x\n", V)
	if V.Equal(plaintext) { // Assert equality
		fmt.Printf("+ signature S from plaintext is correct!\n")
	} else {
		fmt.Printf("- signature S from plaintext is incorrect!\n")
	}

	fmt.Printf("\n--- HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n")
	E = Fscx_revolve_n(plaintext, preshared, preshared, i_value, false)
	fmt.Printf("E (Alice) : %x\n", E)
	S = Fscx_revolve_n(C2, B, hkex_nonce, r_value, false).Xor(A).Xor(E) // A+B2+C is the trapdoor for deceiving EVE!!!!
	fmt.Printf("S (Alice) : %x\n", S)
	V = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(S) // == encryptedText
	fmt.Printf("V (Bob)   : %x\n", V)
	D = Fscx_revolve_n(V, preshared, preshared, r_value, false) // => plaintext
	fmt.Printf("D (Bob)   : %x\n", D)
	if D.Equal(plaintext) { // Assert equality
		fmt.Printf("+ signature S(E) from plaintext is correct!\n")
	} else {
		fmt.Printf("- signature S(E) from plaintext is incorrect!\n")
	}

	fmt.Printf("\n--- HPKE (public key encryption)\n")
	E = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(plaintext)
	fmt.Printf("E (Bob)   : %x\n", E)
	D = Fscx_revolve_n(C2, B, hkex_nonce, r_value, false).Xor(A).Xor(E) // == plaintext !!!!
	fmt.Printf("D (Alice) : %x\n", D)
	if D.Equal(plaintext) { // Assert equality
		fmt.Printf("+ plaintext is correctly decrypted from E with private key!\n")
	} else {
		fmt.Printf("- plaintext is different from decrypted E with private key!\n")
	}

	fmt.Printf("\n\n*** EVE bypass TESTS\n")
	fmt.Printf("*** HPKS (public key signature)\n")
	S = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(nonce) // ^ bruteForceValue  // w/o A+A2+C2 Eve would be forced to do a Brute force attack to find it.
	fmt.Printf("S (Eve)   : %x\n", S)
	V = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2) // X
	fmt.Printf("V (Bob)   : %x\n", V)
	if V.Equal(nonce) { // Assert equality
		fmt.Printf("+ nonce fake signature 1 verification with Alice public key is correct!\n")
	} else {
		fmt.Printf("- nonce fake signature 1 verification with Alice public key is incorrect!\n")
	}
	S2 := V.Xor(nonce)
	fmt.Printf("S2 (Eve)  : %x\n", S2)
	V2 := Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(S2) // KK
	fmt.Printf("V2 (Bob)  : %x\n", V2)
	if V2.Equal(nonce) { // Assert equality
		fmt.Printf("+ nonce fake signature 2 verification with Alice public key is correct!\n")
	} else {
		fmt.Printf("- nonce fake signature 2 verification with Alice public key is incorrect!\n")
	}

	fmt.Printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public\n")
	E = Fscx_revolve_n(nonce, preshared, preshared, i_value, false)
	fmt.Printf("E (Eve)   : %x\n", E)
	S = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(E) // ^ bruteForceValue  // w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
	fmt.Printf("S (Eve)   : %x\n", S)
	V = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2) // X
	fmt.Printf("V (Eve)   : %x\n", V)
	S2 = V.Xor(S)
	fmt.Printf("S2 (Eve)  : %x\n", S2)
	V2 = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(S2) // KK
	fmt.Printf("V2 (Bob)  : %x\n", V2)
	D = Fscx_revolve_n(V2, preshared, preshared, r_value, false)
	fmt.Printf("D (Bob)   : %x\n", D) //X
	if D.Equal(nonce) {               // Assert equality
		fmt.Printf("+ fake signature(encrypted nonce) verification with Alice public key is correct!\n")
	} else {
		fmt.Printf("- fake signature(encrypted nonce) verification with Alice public key is incorrect!\n")
	}

	fmt.Printf("\n*** HPKS (public key signature) + HSKE (symmetric key encryption) with preshared key made public - v2\n")
	S = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(nonce) // ^ bruteForceValue  // w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
	fmt.Printf("S (Eve)   : %x\n", S)
	E = Fscx_revolve_n(S, preshared, preshared, i_value, false)
	fmt.Printf("E (Eve)   : %x\n", E)
	V = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2) // X
	fmt.Printf("V (Eve)   : %x\n", V)
	S2 = V.Xor(E)
	fmt.Printf("S2 (Eve)  : %x\n", S2)
	V2 = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(S2) // KK
	fmt.Printf("V2 (Bob)  : %x\n", V2)
	D = Fscx_revolve_n(V2, preshared, preshared, r_value, false)
	fmt.Printf("D (Bob)   : %x\n", D) //X
	if D.Equal(nonce) {               // Assert equality
		fmt.Printf("+ fake signature(encrypted nonce) v2 verification with Alice public key is correct!\n")
	} else {
		fmt.Printf("- fake signature(encrypted nonce) v2 verification with Alice public key is incorrect!\n")
	}

	fmt.Printf("\n*** HPKE (public key encryption)\n")
	E = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2).Xor(plaintext) // ^ bruteForceValue  // w/o A+B2+C  Eve would be forced to do a Brute force attack to find it.
	fmt.Printf("E (Bob)   : %x\n", E)
	D = Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(A2) //X, but == fsession from private/public key generation if components had been reused from an HKEX!?
	fmt.Printf("D (Eve)   : %x\n", D)
	E2 := D.Xor(E)
	D2 := Fscx_revolve_n(C, B2, hkex_nonce, r_value, false).Xor(E2) // KK
	fmt.Printf("D2 (Eve)  : %x\n", D2)
	if D.Equal(nonce) || D2.Equal(nonce) { // Assert equality
		fmt.Printf("+ Eve could decrypt plaintext without Alice's private key!\n")
	} else {
		fmt.Printf("- Eve could not decrypt plaintext without Alice's private key!\n")
	}
}
