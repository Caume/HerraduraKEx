/*  Herradura Cryptographic Suite v1.9.40

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
	"bytes"
	"crypto/rand"
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

	// ── HPKS-Stern-Ring (78.I) ───────────────────────────────────────────────
	fmt.Printf("\n--- HPKS-Stern-Ring (78.I) [CODE-BASED RING SIG — OR-composed Stern, N=%d, k=3]\n", n)
	{
		const ringK = 3
		rKeys := make([]RingKeypair, ringK)
		rE    := make([]*BitArray, ringK)
		for i := 0; i < ringK; i++ {
			rKeys[i].Seed, rE[i], rKeys[i].Syndrome = SternFKeygen(n)
		}
		// Sign as member 1 (index 1 in the ring)
		rsig := HpksSternRingSign(plaintext, rE[1], 1, rKeys, SdfRounds)
		if HpksSternRingVerify(plaintext, rsig, rKeys) {
			fmt.Printf("+ HPKS-Stern-Ring signature verified (k=%d, signer=1)\n", ringK)
		} else {
			fmt.Printf("- HPKS-Stern-Ring verification FAILED (k=%d)\n", ringK)
		}
	}

	// ── HFSCX-256-DM ─────────────────────────────────────────────────────────
	fmt.Println("\n--- HFSCX-256-DM [HASH — Merkle-Damgård over NL-FSCX v1, Davies-Meyer; 256-bit output]")
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

	// ── ZKP-RNL: Ring-LWR Σ-protocol ────────────────────────────────────────
	fmt.Printf("\n--- ZKP-RNL [PROOF — Ring-LWR Σ-protocol, Fiat-Shamir; n=%d]\n", n)
	{
		zkpN := n
		zkpQ := RnlQ
		zkpP := RnlP
		zkpM := RnlMPoly(zkpN)
		zkpA := RnlRandPoly(zkpN, zkpQ)
		zkpMBlind := RnlPolyAdd(zkpM, zkpA, zkpQ)
		zkpS, zkpCp := RnlKeygen(zkpMBlind, zkpN, zkpQ, zkpP)
		zkpMsg := []byte("ZKP-RNL test message")
		zkpW, zkpC, zkpZ, zkpErr := RnlSigmaSign(zkpS, zkpMBlind, zkpCp, zkpN, zkpMsg)
		if zkpErr != nil {
			fmt.Println("- ZKP-RNL sign error:", zkpErr)
		} else {
			ok := RnlSigmaVerify(zkpMBlind, zkpCp, zkpN, zkpMsg, zkpW, zkpC, zkpZ)
			if ok {
				fmt.Println("+ ZKP-RNL proof verified")
			} else {
				fmt.Println("- ZKP-RNL verify FAILED")
			}
		}
	}

	// ── ZKP-NL: NL-FSCX ZKBoo ───────────────────────────────────────────────
	fmt.Printf("\n--- ZKP-NL [PROOF — NL-FSCX ZKBoo, MPC-in-the-head; n=%d, R=%d]\n",
		ZkpNlDefaultN, ZkpNlDemoRounds)
	{
		zkpA, zkpB, zkpY, zkpErr := ZkpNlKeygen(ZkpNlDefaultN)
		if zkpErr != nil {
			fmt.Println("- ZKP-NL keygen error:", zkpErr)
		} else {
			zkpMsg := []byte("ZKP-NL test message")
			zkpProof, zkpErr2 := ZkpNlProve(zkpA, zkpB, zkpY, ZkpNlDefaultN, ZkpNlDemoRounds, zkpMsg)
			if zkpErr2 != nil {
				fmt.Println("- ZKP-NL prove error:", zkpErr2)
			} else {
				ok := ZkpNlVerify(zkpB, zkpY, ZkpNlDefaultN, ZkpNlDemoRounds, zkpMsg, zkpProof)
				if ok {
					fmt.Println("+ ZKP-NL proof verified")
				} else {
					fmt.Println("- ZKP-NL verify FAILED")
				}
			}
		}
	}

	// ── HPKS-WOTS-F / HPKS-XMSS-F ───────────────────────────────────────────────
	fmt.Println("\n--- HPKS-XMSS-F [PQC — hash-based many-time sig; WOTS-F chains + Merkle tree]")
	{
		xmssSeed := make([]byte, 32)
		if _, err := rand.Read(xmssSeed); err != nil {
			fmt.Println("+ HPKS-XMSS-F: rand.Read failed:", err)
		} else {
			xmssH  := 3 // 8 leaves; production uses h=10
			xmssKp := HpksXmssKeygen(xmssSeed, xmssH)
			xmssMsg := []byte("HPKS-XMSS-F test message")
			sig0 := HpksXmssSign(xmssMsg, xmssKp, 0)
			sig1 := HpksXmssSign(xmssMsg, xmssKp, 1)
			ok0   := HpksXmssVerify(xmssMsg, sig0, xmssKp.Root)
			ok1   := HpksXmssVerify(xmssMsg, sig1, xmssKp.Root)
			bad   := HpksXmssVerify([]byte("tampered"), sig0, xmssKp.Root)
			reuse := HpksXmssVerify([]byte("different message"), sig0, xmssKp.Root)
			if ok0 && ok1 && !bad && !reuse {
				fmt.Printf("- HPKS-XMSS-F sign/verify correct (h=%d, 2 leaves, tamper/reuse rejected)\n", xmssH)
			} else {
				fmt.Printf("+ HPKS-XMSS-F FAILED: ok0=%v ok1=%v bad=%v reuse=%v\n", ok0, ok1, bad, reuse)
			}
		}
	}

	// ── HPKS-T ───────────────────────────────────────────────────────────────────
	fmt.Println("\n--- HPKS-T [THRESHOLD — n-of-n MuSig2-style aggregate Schnorr over GF(2^n)*]")
	{
		tN     := 3
		gGen   := big.NewInt(3)
		poly256 := GfPoly[n]
		tSecrets := make([]*big.Int, tN)
		tPubkeys := make([]*big.Int, tN)
		for j := 0; j < tN; j++ {
			kb := make([]byte, 32)
			rand.Read(kb)
			tSecrets[j] = new(big.Int).SetBytes(kb)
			tPubkeys[j] = GfPow(gGen, tSecrets[j], poly256, n)
		}
		tMsg  := []byte("HPKS-T threshold signature test")
		tCAgg, tR, tS := HpkstSign(tSecrets, tPubkeys, tMsg)
		tOk  := HpkstVerify(tCAgg, tR, tS, tMsg)
		tBad := HpkstVerify(tCAgg, tR, new(big.Int).Xor(tS, big.NewInt(1)), tMsg)
		if tOk && !tBad {
			fmt.Printf("- HPKS-T %d-of-%d sign/verify correct, tamper rejected\n", tN, tN)
		} else {
			fmt.Printf("+ HPKS-T FAILED: ok=%v bad=%v\n", tOk, tBad)
		}
	}

	// ── HDRBG ────────────────────────────────────────────────────────────────────
	fmt.Println("\n--- HDRBG [FORWARD-SECURE DRBG — NL-FSCX v1 ratchet, fast-key-erasure]")
	{
		d1 := DrbgSeed([]byte("demo-entropy-96"), []byte("pers"))
		d2 := DrbgSeed([]byte("demo-entropy-96"), []byte("pers"))
		out1, _ := d1.DrbgGenerate(64)
		out2, _ := d2.DrbgGenerate(64)
		d2.DrbgReseed([]byte("fresh-entropy"))
		out3, _ := d2.DrbgGenerate(64)
		out4, _ := d1.DrbgGenerate(64)
		if bytes.Equal(out1, out2) && !bytes.Equal(out3, out4) && len(out1) == 64 {
			fmt.Println("- HDRBG determinism + reseed separation correct")
		} else {
			fmt.Println("+ HDRBG failed!")
		}
	}

	// ── HSKE-NL-AEAD ─────────────────────────────────────────────────────────────
	fmt.Println("\n--- HSKE-NL-AEAD [AEAD — NL-FSCX v1 keystream + HFSCX-256 MAC]")
	{
		aeadKey   := NewRandBitArray(n)
		aeadNonce := NewRandBitArray(n)
		aeadPt    := []byte("HSKE-NL-AEAD demo plaintext (arbitrary length, 47 B)")
		aeadAd    := []byte("header-v1")
		aeadCt, aeadTag := HskeNlAeadEncrypt(aeadKey, aeadNonce, aeadAd, aeadPt)
		aeadDec, aeadOk := HskeNlAeadDecrypt(aeadKey, aeadNonce, aeadAd, aeadCt, aeadTag)
		badCt := append(append([]byte{}, aeadCt...), []byte{}...)
		badCt[0] ^= 1
		_, badOk   := HskeNlAeadDecrypt(aeadKey, aeadNonce, aeadAd, badCt, aeadTag)
		_, badAdOk := HskeNlAeadDecrypt(aeadKey, aeadNonce, []byte("header-v2"), aeadCt, aeadTag)
		if aeadOk && bytes.Equal(aeadDec, aeadPt) && !badOk && !badAdOk {
			fmt.Println("- HSKE-NL-AEAD round-trip + tamper/AD rejection correct")
		} else {
			fmt.Println("+ HSKE-NL-AEAD failed!")
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

	fmt.Println("*** HPKS-Stern-Ring (78.I) — Eve cannot forge ring signature without valid secret key")
	{
		const ringK = 3
		eveRKeys := make([]RingKeypair, ringK)
		eveRE    := make([]*BitArray, ringK)
		for i := 0; i < ringK; i++ {
			eveRKeys[i].Seed, eveRE[i], eveRKeys[i].Syndrome = SternFKeygen(n)
		}
		// Eve builds a random ring sig without knowing any secret key
		eveRSig := &SternRingSig{K: ringK, Rounds: SdfRounds, Members: make([]SternSig, ringK)}
		for i := 0; i < ringK; i++ {
			eveRSig.Members[i].Rounds = make([]SternRound, SdfRounds)
			for r := 0; r < SdfRounds; r++ {
				eveRSig.Members[i].Rounds[r].C0    = NewRandBitArray(n)
				eveRSig.Members[i].Rounds[r].C1    = NewRandBitArray(n)
				eveRSig.Members[i].Rounds[r].C2    = NewRandBitArray(n)
				eveRSig.Members[i].Rounds[r].B     = 0
				eveRSig.Members[i].Rounds[r].RespA = NewRandBitArray(n)
				eveRSig.Members[i].Rounds[r].RespB = NewRandBitArray(n)
			}
		}
		if HpksSternRingVerify(decoy, eveRSig, eveRKeys) {
			fmt.Println("+ Eve forged HPKS-Stern-Ring (Eve wins)!")
		} else {
			fmt.Println("- Eve cannot forge ring sig: challenge-sum mismatch  (SD + PRF protection)")
		}
	}

	fmt.Println("*** HPKE-Stern-F — Eve cannot derive session key from syndrome ciphertext")
	eveKGuess := NewRandBitArray(n)
	if eveKGuess.Equal(sfKEnc) {
		fmt.Println("+ Eve guessed HPKE-Stern-F session key (astronomically unlikely)!")
	} else {
		fmt.Println("- Eve random guess does not match session key  (SD protection)")
	}

	fmt.Println("*** FPE (78.A) — format-preserving encrypt/decrypt round-trip")
	{
		fpeKey := []byte("herradura-fpe-key-256bit-example")
		fpeCtx := []byte("record:42")
		fpePlain := NewRandBitArray(n)
		fpeCt    := FpeEncrypt(fpePlain, fpeKey, fpeCtx)
		fpeRec   := FpeDecrypt(fpeCt,   fpeKey, fpeCtx)
		if fpeRec.Equal(fpePlain) {
			fmt.Println("- FPE round-trip correct")
		} else {
			fmt.Println("+ FPE round-trip failed!")
		}
	}

	fmt.Println("*** Tweakable cipher (78.B) — sector-block encrypt/decrypt")
	{
		twkKey   := []byte("herradura-twk-key-256bit-example")
		twkPlain := NewRandBitArray(n)
		twkCt    := TwkEncrypt(twkPlain, twkKey, 7, 3)
		twkRec   := TwkDecrypt(twkCt,   twkKey, 7, 3)
		if twkRec.Equal(twkPlain) {
			fmt.Println("- Tweakable cipher round-trip correct")
		} else {
			fmt.Println("+ Tweakable cipher round-trip failed!")
		}
	}

	fmt.Println("*** Accumulator (78.J) — Merkle root + proof/verify for 4 leaves")
	{
		var leavesData [][]byte
		var leafHashes [][]byte
		for i := 0; i < 4; i++ {
			d := []byte(fmt.Sprintf("leaf%d", i))
			leavesData = append(leavesData, d)
			leafHashes = append(leafHashes, HaccumLeaf(d))
		}
		root  := HaccumRoot(leafHashes)
		proof := HaccumProve(leafHashes, 2)
		ok    := HaccumVerify(root, leafHashes[2], proof, 2)
		// tamper check: wrong leaf must fail
		okWrong := HaccumVerify(root, leafHashes[0], proof, 2)
		if ok && !okWrong {
			fmt.Println("- Accumulator proof/verify correct")
		} else {
			fmt.Println("+ Accumulator proof/verify failed!")
		}
		_ = leavesData
	}

	// ── 78.H — Masked HSKE ──────────────────────────────────────────────────
	fmt.Println("\n*** Masked HSKE (78.H) — GF(2)-linearity masking")
	{
		plain := NewRandBitArray(256)
		key   := NewRandBitArray(256)
		ct, _ := HskeEncryptMasked(plain, key)
		rec, _ := HskeDecryptMasked(ct, key)
		if rec.Equal(plain) {
			fmt.Println("- Masked HSKE encrypt/decrypt correct")
		} else {
			fmt.Println("+ Masked HSKE encrypt/decrypt failed!")
		}
	}

	// ── 78.C — Ratchet ──────────────────────────────────────────────────────
	fmt.Println("\n*** Forward-secret ratchet (78.C) — 5 steps")
	{
		state := RatchetInit([]byte("demo-seed-78c"))
		keys  := make([][]byte, 5)
		for i := range keys {
			var mk []byte
			state, mk = RatchetAdvance(state)
			keys[i] = mk
		}
		unique := true
		for i := 1; i < 5 && unique; i++ {
			if string(keys[0]) == string(keys[i]) {
				unique = false
			}
		}
		if unique {
			fmt.Println("- Ratchet: 5 distinct message keys")
		} else {
			fmt.Println("+ Ratchet: duplicate message keys!")
		}
	}

	// ── 80 — OPRF demo ───────────────────────────────────────────────────────
	fmt.Println("\n*** OPRF (80) — 2HashDH over GF(2^256)*")
	{
		oprfMsg := []byte("oprf-demo-input")
		k, err := OprfKeygen(256)
		if err != nil {
			fmt.Println("+ OprfKeygen error:", err)
		} else {
			r, alpha, err2 := OprfBlind(oprfMsg, 256)
			if err2 != nil {
				fmt.Println("+ OprfBlind error:", err2)
			} else {
				beta    := OprfEval(alpha, k, 256)
				F       := OprfUnblind(beta, r, 256)
				Fdirect := OprfDirect(oprfMsg, k, 256)
				if F.Cmp(Fdirect) == 0 {
					fmt.Println("- OPRF blind/eval/unblind round-trip correct")
				} else {
					fmt.Println("+ OPRF round-trip failed!")
				}
			}
		}
	}

	// ── 80 — aPAKE demo ──────────────────────────────────────────────────────
	fmt.Println("\n*** aPAKE (80) — HKEX-RNL + ZKBoo + OPRF augmented PAKE")
	{
		pakePw := []byte("s3cr3t-pw")
		pakeK, err := OprfKeygen(256)
		if err != nil {
			fmt.Println("+ OprfKeygen error:", err)
		} else {
			rec, err2 := HpakeRegister(pakePw, pakeK)
			if err2 != nil {
				fmt.Println("+ HpakeRegister error:", err2)
			} else {
				sk, err3 := HpakeLoginDemo(rec, pakePw, pakeK)
				if err3 != nil {
					fmt.Println("+ HpakeLoginDemo error:", err3)
				} else if sk != nil {
					fmt.Println("- aPAKE login with correct password: session key established")
				} else {
					fmt.Println("+ aPAKE login with correct password: FAILED!")
				}
				skBad, _ := HpakeLoginDemo(rec, []byte("wrong-pw"), pakeK)
				if skBad == nil {
					fmt.Println("- aPAKE login with wrong password: correctly rejected")
				} else {
					fmt.Println("+ aPAKE login with wrong password: ACCEPTED (security failure)!")
				}
			}
		}
	}
}
