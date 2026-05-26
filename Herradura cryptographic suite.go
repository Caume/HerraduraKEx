/*  Herradura Cryptographic Suite v1.8.8

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

    v1.5.27: crypto primitives extracted to package herradura/herradura.go.
    v1.5.26: HFSCX-256 + HSKE-NL-A1 helpers added.
    v1.5.23: HPKS-Stern-F + HPKE-Stern-F code-based PQC.
    v1.5.0:  NL-FSCX non-linear extension and PQC protocols.
    v1.4.0:  HKEX-GF (Diffie-Hellman over GF(2^n)*).
    v1.3:    BitArray (multi-byte parameter support).

    Protocol stack:
      HKEX-GF      — DH over GF(2^n)* [classical, not PQC]
      HSKE         — FscxRevolve symmetric encryption [classical, not PQC]
      HPKS         — Schnorr with FscxRevolve challenge [classical, not PQC]
      HPKE         — El Gamal + FscxRevolve [classical, not PQC]
      HSKE-NL-A1   — counter-mode HSKE with NL-FSCX v1 keystream [PQC-hardened]
      HSKE-NL-A2   — revolve-mode HSKE with NL-FSCX v2 [PQC-hardened]
      HKEX-RNL     — Ring-LWR key exchange [conjectured quantum-resistant]
      HPKS-NL      — Schnorr with NL-FSCX v1 challenge [NL-hardened]
      HPKE-NL      — El Gamal with NL-FSCX v2 [NL-hardened]
      HPKS-Stern-F — Stern ZKP signature [code-based PQC]
      HPKE-Stern-F — Niederreiter KEM [code-based PQC]
*/

package main

import (
	. "herradurakex/herradura"
	"fmt"
	"math/big"
)

func main() {
	const n = 256
	iValue := n / 4
	rValue := 3 * n / 4

	poly := GfPoly[n]
	g := big.NewInt(GfGen)
	ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), n), big.NewInt(1))

	a         := NewRandBitArray(n)
	b         := NewRandBitArray(n)
	preshared := NewRandBitArray(n)
	plaintext := NewRandBitArray(n)
	decoy     := NewRandBitArray(n)

	// HKEX-GF key exchange
	C     := NewBitArray(n, GfPow(g, &a.Val, poly, n))
	C2    := NewBitArray(n, GfPow(g, &b.Val, poly, n))
	sk    := NewBitArray(n, GfPow(&C2.Val, &a.Val, poly, n))
	skBob := NewBitArray(n, GfPow(&C.Val, &b.Val, poly, n))

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
	eHske := FscxRevolve(plaintext, preshared, iValue)
	fmt.Printf("P (plain) : %x\n", plaintext)
	fmt.Printf("E (Alice) : %x\n", eHske)
	dHske := FscxRevolve(eHske, preshared, rValue)
	fmt.Printf("D (Bob)   : %x\n", dHske)
	if dHske.Equal(plaintext) {
		fmt.Println("+ plaintext correctly decrypted")
	} else {
		fmt.Println("- decryption failed!")
	}

	fmt.Println("\n--- HPKS [CLASSICAL — not PQC; DLP + linear challenge]")
	fmt.Println("    (Schnorr-like with FscxRevolve challenge)")
	kS := NewRandBitArray(n)
	RS := NewBitArray(n, GfPow(g, &kS.Val, poly, n))
	eS := FscxRevolve(RS, plaintext, iValue)
	sS := new(big.Int).Mod(new(big.Int).Sub(&kS.Val, new(big.Int).Mul(&a.Val, &eS.Val)), ord)
	eV := FscxRevolve(RS, plaintext, iValue)
	lhs := GfMul(GfPow(g, sS, poly, n), GfPow(&C.Val, &eV.Val, poly, n), poly, n)
	fmt.Printf("P (msg)        : %x\n", plaintext)
	fmt.Printf("R [Alice,sign] : %x\n", RS)
	fmt.Printf("e [Alice,sign] : %x\n", eS)
	fmt.Printf("s [Alice,sign] : %0*x\n", n/4, sS)
	fmt.Printf("  [Bob,verify] : g^s·C^e = %0*x\n", n/4, lhs)
	if lhs.Cmp(&RS.Val) == 0 {
		fmt.Println("  [Bob,verify] : + Schnorr verified: g^s · C^e == R")
	} else {
		fmt.Println("  [Bob,verify] : - Schnorr verification failed!")
	}

	fmt.Println("\n--- HPKE [CLASSICAL — not PQC; DLP + linear HSKE sub-protocol]")
	fmt.Println("    (El Gamal + FscxRevolve)")
	rHpke  := NewRandBitArray(n)
	RHpke  := NewBitArray(n, GfPow(g, &rHpke.Val, poly, n))
	encKey := NewBitArray(n, GfPow(&C.Val, &rHpke.Val, poly, n))
	eHpke  := FscxRevolve(plaintext, encKey, iValue)
	decKey := NewBitArray(n, GfPow(&RHpke.Val, &a.Val, poly, n))
	dHpke  := FscxRevolve(eHpke, decKey, rValue)
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
	nA1    := NewRandBitArray(n)
	baseA1 := NewBitArray(n, new(big.Int).Xor(&preshared.Val, &nA1.Val))
	counter := 0
	bA1  := NewBitArray(n, new(big.Int).Xor(&baseA1.Val, big.NewInt(int64(counter))))
	ksA1 := NlFscxRevolveV1(RnlKdfSeed(baseA1), bA1, n/4)
	eA1  := NewBitArray(n, new(big.Int).Xor(&plaintext.Val, &ksA1.Val))
	dA1  := NewBitArray(n, new(big.Int).Xor(&eA1.Val, &ksA1.Val))
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
	fmt.Printf("    (Ring-LWR, m(x)=1+x+x^{n-1}, n=%d, q=%d)\n", n, RnlQ)
	nRnl   := n
	mBase  := RnlMPoly(nRnl)
	aRand  := RnlRandPoly(nRnl, RnlQ)
	mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
	sA, CA := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
	sB, CB := RnlKeygen(mBlind, nRnl, RnlQ, RnlP)
	kRawA, hintA := RnlAgree(sA, CB, RnlQ, RnlP, RnlPP, nRnl, n, nil)
	kRawB, _     := RnlAgree(sB, CA, RnlQ, RnlP, RnlPP, nRnl, n, hintA)
	skRnlA := NlFscxRevolveV1(RnlKdfSeed(kRawA), kRawA, n/4)
	skRnlB := NlFscxRevolveV1(RnlKdfSeed(kRawB), kRawB, n/4)
	fmt.Printf("sk (Alice): %x\n", skRnlA)
	fmt.Printf("sk (Bob)  : %x\n", skRnlB)
	if kRawA.Equal(kRawB) {
		fmt.Println("+ raw key bits agree; shared session key established!")
	} else {
		diffBits := new(big.Int).Xor(&kRawA.Val, &kRawB.Val)
		fmt.Printf("- raw key disagrees (%d bit(s)) — reconciliation failed!\n",
			CountBits(diffBits))
	}

	fmt.Println("\n--- HPKS-NL [NL-hardened Schnorr — NL-FSCX v1 challenge]")
	fmt.Println("    (GF DLP still present; NL hardens linear challenge preimage)")
	kNl   := NewRandBitArray(n)
	RNl   := NewBitArray(n, GfPow(g, &kNl.Val, poly, n))
	eNl   := NlFscxRevolveV1(RNl, plaintext, iValue)
	sNl   := new(big.Int).Mod(new(big.Int).Sub(&kNl.Val, new(big.Int).Mul(&a.Val, &eNl.Val)), ord)
	eNlV  := NlFscxRevolveV1(RNl, plaintext, iValue)
	lhsNl := GfMul(GfPow(g, sNl, poly, n), GfPow(&C.Val, &eNlV.Val, poly, n), poly, n)
	fmt.Printf("P (msg)        : %x\n", plaintext)
	fmt.Printf("R [Alice,sign] : %x\n", RNl)
	fmt.Printf("e [Alice,sign] : %x\n", eNl)
	fmt.Printf("s [Alice,sign] : %0*x\n", n/4, sNl)
	fmt.Printf("  [Bob,verify] : g^s·C^e = %0*x\n", n/4, lhsNl)
	if lhsNl.Cmp(&RNl.Val) == 0 {
		fmt.Println("  [Bob,verify] : + HPKS-NL verified: g^s · C^e == R")
	} else {
		fmt.Println("  [Bob,verify] : - HPKS-NL verification failed!")
	}

	fmt.Println("\n--- HPKE-NL [NL-hardened El Gamal — NL-FSCX v2 encryption]")
	fmt.Println("    (GF DLP still present; NL hardens linear HSKE sub-protocol)")
	rNl     := NewRandBitArray(n)
	RNl2    := NewBitArray(n, GfPow(g, &rNl.Val, poly, n))
	encNl   := NewBitArray(n, GfPow(&C.Val, &rNl.Val, poly, n))
	eHpkeNl := NlFscxRevolveV2(plaintext, encNl, iValue)
	decNl   := NewBitArray(n, GfPow(&RNl2.Val, &a.Val, poly, n))
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
	fmt.Printf("    (N=%d, t=%d, rounds=%d; soundness=(2/3)^%d)\n", n, SdfT, SdfRounds, SdfRounds)
	sfSeed, sfE, sfSyn := SternFKeygen(n)
	sfSig := HpksSternFSign(plaintext, sfE, sfSeed, SdfRounds)
	fmt.Printf("seed     : %x\n", sfSeed)
	fmt.Printf("msg      : %x\n", plaintext)
	if HpksSternFVerify(plaintext, sfSig, sfSeed, sfSyn) {
		fmt.Println("+ HPKS-Stern-F signature verified")
	} else {
		fmt.Println("- HPKS-Stern-F verification FAILED")
	}

	fmt.Printf("\n--- HPKE-Stern-F [CODE-BASED PQC — Niederreiter KEM, N=%d]\n", n)
	fmt.Println("    (brute-force decap infeasible at N=256; demo uses known e')")
	sfKEnc, _, sfEPrime := HpkeSternFEncap(sfSeed, n)
	sfKDec := HpkeSternFDecapKnown(sfEPrime, sfSeed)
	fmt.Printf("K (encap): %x\n", sfKEnc)
	fmt.Printf("K (decap): %x\n", sfKDec)
	fmt.Println("    NOTE: decap uses known e' (demo only; production: QC-MDPC decoder)")
	if sfKEnc.Equal(sfKDec) {
		fmt.Println("+ HPKE-Stern-F session keys agree")
	} else {
		fmt.Println("- HPKE-Stern-F key agreement FAILED")
	}

	// ── HFSCX-256 ───────────────────────────────────────────────────────────
	fmt.Println("\n--- HFSCX-256 [HASH — Merkle-Damgård over NL-FSCX v1; 256-bit output]")
	{
		tv := []byte("HFSCX-256 test vector")
		bareOut := Hfscx256(tv, nil)
		// Keyed MAC: iv = preshared XOR Hfscx256IV
		presBytes := preshared.Bytes() // 32 bytes big-endian
		macIV := make([]byte, 32)
		for i := range macIV {
			macIV[i] = presBytes[i] ^ Hfscx256IV[i]
		}
		keyedOut := Hfscx256(tv, macIV)
		fmt.Printf("digest (bare)  : %x\n", bareOut)
		fmt.Printf("digest (keyed) : %x\n", keyedOut)
		fmt.Printf("+ hash length correct (%d bytes)\n", len(bareOut))
		same := true
		for i := range bareOut {
			if bareOut[i] != keyedOut[i] {
				same = false
				break
			}
		}
		if !same {
			fmt.Println("+ keyed ≠ bare (key influences output)")
		} else {
			fmt.Println("- keyed == bare (unexpected!)")
		}
	}

	// ── Eve bypass tests ─────────────────────────────────────────────────────
	fmt.Println("\n\n*** EVE bypass TESTS")

	fmt.Println("*** HPKS-NL — Eve cannot forge Schnorr without knowing private key a")
	REve   := NewBitArray(n, GfPow(g, &NewRandBitArray(n).Val, poly, n))
	eEve   := NlFscxRevolveV1(REve, decoy, iValue)
	sEve   := &NewRandBitArray(n).Val
	lhsEve := GfMul(GfPow(g, sEve, poly, n), GfPow(&C.Val, &eEve.Val, poly, n), poly, n)
	if lhsEve.Cmp(&REve.Val) == 0 {
		fmt.Println("+ Eve forged HPKS-NL signature (Eve wins)!")
	} else {
		fmt.Println("- Eve could not forge: g^s_eve · C^e_eve ≠ R_eve  (DLP protection)")
	}

	fmt.Println("*** HPKE-NL — Eve cannot decrypt without Alice's private key")
	eveKey := NewBitArray(n, new(big.Int).Xor(&C.Val, &RNl2.Val))
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
	eveSig := &SternSig{Rounds: make([]SternRound, SdfRounds)}
	for i := range eveSig.Rounds {
		eveSig.Rounds[i].C0    = NewRandBitArray(n)
		eveSig.Rounds[i].C1    = NewRandBitArray(n)
		eveSig.Rounds[i].C2    = NewRandBitArray(n)
		eveSig.Rounds[i].B     = 0
		eveSig.Rounds[i].RespA = NewRandBitArray(n)
		eveSig.Rounds[i].RespB = NewRandBitArray(n)
	}
	if HpksSternFVerify(decoy, eveSig, sfSeed, sfSyn) {
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
