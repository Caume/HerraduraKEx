/*  hello_herradura.go — Minimal Go integration example for the Herradura suite.
 *
 *  Build / run from the repo root:
 *    go run docs/examples/go/hello_herradura.go
 *
 *  Or from this directory if your GOPATH / module config points to the repo root:
 *    go run hello_herradura.go
 *
 *  The herradura package lives at herradurakex/herradura (see go.mod in the
 *  repo root).  Copy or vendor the herradura/ directory into your own module
 *  and adjust the import path to match your module name.
 */

package main

import (
	"fmt"
	"math/big"

	. "herradurakex/herradura"
)

func main() {
	const n = 256
	iValue := n / 4
	rValue := 3 * n / 4
	poly := GfPoly[n]

	// ── HKEX-GF: Diffie-Hellman over GF(2^256)* ─────────────────────────────
	fmt.Println("=== HKEX-GF key exchange ===")

	alicePriv := NewRandBitArray(n)
	bobPriv   := NewRandBitArray(n)
	g         := big.NewInt(GfGen)

	alicePub := NewBitArray(n, GfPow(g, &alicePriv.Val, poly, n))
	bobPub   := NewBitArray(n, GfPow(g, &bobPriv.Val,  poly, n))

	aliceShared := NewBitArray(n, GfPow(&bobPub.Val,   &alicePriv.Val, poly, n))
	bobShared   := NewBitArray(n, GfPow(&alicePub.Val, &bobPriv.Val,   poly, n))

	fmt.Printf("Alice shared: %x\n", aliceShared)
	fmt.Printf("Bob   shared: %x\n", bobShared)
	if aliceShared.Equal(bobShared) {
		fmt.Println("✓ shared secrets agree")
	} else {
		fmt.Println("✗ shared secrets differ!")
	}

	// ── HSKE: symmetric encryption with the derived shared key ───────────────
	fmt.Println("\n=== HSKE symmetric encryption ===")

	plaintext := NewRandBitArray(n)
	ciphertext := FscxRevolve(plaintext, aliceShared, iValue)
	recovered  := FscxRevolve(ciphertext, aliceShared, rValue)

	fmt.Printf("Plaintext : %x\n", plaintext)
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Recovered : %x\n", recovered)
	if plaintext.Equal(recovered) {
		fmt.Println("✓ decryption correct")
	} else {
		fmt.Println("✗ decryption failed!")
	}

	// ── HKEX-RNL: Ring-LWR key exchange (PQC-hardened) ───────────────────────
	fmt.Printf("\n=== HKEX-RNL (Ring-LWR, n=%d, q=%d) ===\n", n, RnlQ)

	mBase  := RnlMPoly(n)
	aRand  := RnlRandPoly(n, RnlQ)
	mBlind := RnlPolyAdd(mBase, aRand, RnlQ)

	sA, CA := RnlKeygen(mBlind, n, RnlQ, RnlP)
	sB, CB := RnlKeygen(mBlind, n, RnlQ, RnlP)

	kA, hintA := RnlAgree(sA, CB, RnlQ, RnlP, RnlPP, n, n, nil)
	kB, _      := RnlAgree(sB, CA, RnlQ, RnlP, RnlPP, n, n, hintA)

	// KDF: seed = ROL(K, n/8); sk = NL-FSCX-v1(seed, K, n/4)
	skA := NlFscxRevolveV1(kA.RotateLeft(n/8), kA, n/4)
	skB := NlFscxRevolveV1(kB.RotateLeft(n/8), kB, n/4)

	fmt.Printf("sk (Alice): %x\n", skA)
	fmt.Printf("sk (Bob)  : %x\n", skB)
	if kA.Equal(kB) {
		fmt.Println("✓ Ring-LWR keys agree")
	} else {
		fmt.Println("✗ Ring-LWR key disagreement!")
	}
	_ = skA; _ = skB

	// ── HPKS-Stern-F: code-based signature (PQC) ─────────────────────────────
	fmt.Printf("\n=== HPKS-Stern-F (N=%d, t=%d, rounds=%d) ===\n",
		n, SdfT, SdfRounds)

	seed, e, syn := SternFKeygen(n)
	msg := NewRandBitArray(n)
	sig := HpksSternFSign(msg, e, seed, SdfRounds)

	if HpksSternFVerify(msg, sig, seed, syn) {
		fmt.Println("✓ Stern-F signature verified")
	} else {
		fmt.Println("✗ Stern-F signature invalid!")
	}
}
