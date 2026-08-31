// TODO #190: cross-language verifier for KAT/classical_quartet.json.
//
// Recomputes each HKEX-GF/HSKE/HPKS/HPKE vector using the herradura Go
// package (not the Python reference that generated the file) and confirms
// byte-identical results — proof that the vectors aren't merely
// self-consistent within one implementation.
//
// Usage: go run KAT/verify_kat.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	. "herradurakex/herradura"
)

func hexToBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex: " + s)
	}
	return v
}

func hexToBA(size int, s string) *BitArray {
	return NewBitArray(size, hexToBig(s))
}

type vectorSet struct {
	HkexGf map[string]interface{} `json:"hkex_gf"`
	Hske   map[string]interface{} `json:"hske"`
	Hpks   map[string]interface{} `json:"hpks"`
	Hpke   map[string]interface{} `json:"hpke"`
}

// TODO #226: HKEX-RNL vectors live in their own file, since the ring is not part
// of the classical quartet and its polynomials are far larger.
type rnlFile struct {
	Deployed  map[string]interface{} `json:"deployed"`
	SmallRing map[string]interface{} `json:"small_ring"`
}

// TODO #255: NL-FSCX v3 and its five consumers, likewise in their own file.
type v3File struct {
	Primitive map[string]interface{} `json:"nl_fscx_v3"`
	HskeNla3  map[string]interface{} `json:"hske_nla3"`
	HpkeNl3   map[string]interface{} `json:"hpke_nl3"`
	Duplex3   map[string]interface{} `json:"hske_duplex3"`
	FpeTwkV3  map[string]interface{} `json:"fpe_twk_v3"`
}

func str(m map[string]interface{}, k string) string { return m[k].(string) }

func num(m map[string]interface{}, k string) int { return int(m[k].(float64)) }

// unpackPoly reads a fixed-width big-endian coefficient blob (the packing used
// by the PEM codec and by generate_kat.py's poly_hex).
func unpackPoly(hexs string, n, bytesPerCoeff int) []int {
	raw, err := hex.DecodeString(hexs)
	if err != nil || len(raw) != n*bytesPerCoeff {
		panic(fmt.Sprintf("bad polynomial blob: %d bytes for n=%d", len(raw), n))
	}
	out := make([]int, n)
	for i := 0; i < n; i++ {
		v := 0
		for k := 0; k < bytesPerCoeff; k++ {
			v = v<<8 | int(raw[i*bytesPerCoeff+k])
		}
		out[i] = v
	}
	return out
}

// verifyRnl recomputes one HKEX-RNL handshake from the vector's fixed secrets.
// The secrets are inputs here: a KAT fixes the randomness and tests the
// deterministic parts — ring arithmetic, rounding, reconciliation, and the KDF.
func verifyRnl(name string, v map[string]interface{}) bool {
	n := num(v, "n")
	q, p, pp := num(v, "q"), num(v, "p"), num(v, "pp")
	keyBits := num(v, "key_bits")
	used := num(v, "hint_coefficients")

	mBlind := unpackPoly(str(v, "m_blind"), n, 4)
	sA := unpackPoly(str(v, "alice_s"), n, 4)
	sB := unpackPoly(str(v, "bob_s"), n, 4)

	// m_blind must be m(x) + a_rand; recomputing C from it exercises the ring.
	cA := RnlRound(RnlPolyMul(mBlind, sA, q, n), q, p)
	cB := RnlRound(RnlPolyMul(mBlind, sB, q, n), q, p)
	gotCA := polyHex(cA, 2)
	gotCB := polyHex(cB, 2)

	// Bob reconciles and publishes the hint; Alice consumes it.
	kBob, hint := RnlAgree(sB, cA, q, p, pp, n, keyBits, nil)
	kAlice, _ := RnlAgree(sA, cB, q, p, pp, n, keyBits, hint)
	gotHint := hex.EncodeToString(hint[:(used+3)/4])
	gotK := fmt.Sprintf("%0*x", keyBits/4, &kAlice.Val)

	ok := gotCA == str(v, "alice_C") && gotCB == str(v, "bob_C") &&
		gotHint == str(v, "hint") && gotK == str(v, "k_raw") &&
		kAlice.Val.Cmp(&kBob.Val) == 0

	// The session KDF only applies where the derived key is the full width.
	if sk, present := v["session_key"].(string); present {
		got := fmt.Sprintf("%0*x", keyBits/4, &NlFscxRevolveV1(RnlKdfSeed(kAlice), kAlice, keyBits/4).Val)
		if got != sk {
			fmt.Printf("FAIL %s: session_key got=%s want=%s\n", name, got, sk)
			return false
		}
	}
	if !ok {
		fmt.Printf("FAIL %s: C_A match=%v C_B match=%v hint match=%v k_raw match=%v agree=%v\n",
			name, gotCA == str(v, "alice_C"), gotCB == str(v, "bob_C"),
			gotHint == str(v, "hint"), gotK == str(v, "k_raw"),
			kAlice.Val.Cmp(&kBob.Val) == 0)
		return false
	}
	fmt.Printf("PASS %s (n=%d, key_bits=%d)\n", name, n, keyBits)
	return true
}

// verifyV3 recomputes every NL-FSCX v3 vector with the Go package.  The four
// ports are byte-identical by design, so a divergence here is a port bug, not a
// tolerance question -- there is nothing probabilistic in any of these.
func verifyV3(v v3File) int {
	n := 256
	fails := 0
	check := func(name, got, want string) {
		if got != want {
			fmt.Printf("FAIL %s: got %s want %s\n", name, got, want)
			fails++
		} else {
			fmt.Println("PASS " + name)
		}
	}
	hx := func(b *BitArray) string { return fmt.Sprintf("%0*x", n/4, &b.Val) }

	// The primitive: chi, one round, the full revolve, and its inverse.
	{
		p := v.Primitive
		key := hexToBA(n, str(p, "key"))
		pt := hexToBA(n, str(p, "plaintext"))
		r3 := num(p, "r3_steps")
		if r3 != R3Value {
			fmt.Printf("FAIL nl_fscx_v3: vector says r3_steps=%d, package says %d\n", r3, R3Value)
			fails++
		}
		if i3 := num(p, "i3_steps"); i3 != I3Value {
			fmt.Printf("FAIL nl_fscx_v3: vector says i3_steps=%d, package says %d\n", i3, I3Value)
			fails++
		}
		check("nl_fscx_v3 chi", hx(NlChiV3(pt)), str(p, "chi_of_plaintext"))
		check("nl_fscx_v3 round", hx(NlFscxV3(pt, key)), str(p, "one_round"))
		ct := NlFscxRevolveV3(pt, key, r3)
		check("nl_fscx_v3 revolve", hx(ct), str(p, "revolve"))
		check("nl_fscx_v3 revolve_inv", hx(NlFscxRevolveV3Inv(ct, key, r3)), str(p, "plaintext"))
	}

	// HSKE-NL-A3.
	{
		a := v.HskeNla3
		ct := NlFscxRevolveV3(hexToBA(n, str(a, "plaintext")),
			hexToBA(n, str(a, "key")), num(a, "r3_steps"))
		check("hske_nla3", hx(ct), str(a, "ciphertext"))
	}

	// HPKE-NL3: rederive the shared encryption key from both sides, then encrypt.
	{
		e := v.HpkeNl3
		poly := GfPoly[n]
		priv := hexToBig(str(e, "priv"))
		r := hexToBig(str(e, "ephemeral_r"))
		pub := GfPow(big.NewInt(GfGen), priv, poly, n)
		bigR := GfPow(big.NewInt(GfGen), r, poly, n)
		encKey := NewBitArray(n, GfPow(pub, r, poly, n))
		decKey := NewBitArray(n, GfPow(bigR, priv, poly, n))
		check("hpke_nl3 pub", fmt.Sprintf("%0*x", n/4, pub), str(e, "pub"))
		check("hpke_nl3 R", fmt.Sprintf("%0*x", n/4, bigR), str(e, "R"))
		check("hpke_nl3 enc_key", hx(encKey), str(e, "enc_key"))
		check("hpke_nl3 dec_key agrees", hx(decKey), str(e, "enc_key"))
		ct := NlFscxRevolveV3(hexToBA(n, str(e, "plaintext")), encKey, num(e, "r3_steps"))
		check("hpke_nl3", hx(ct), str(e, "ciphertext"))
	}

	// HSKE-NL-V3-Duplex.
	{
		d := v.Duplex3
		pt, _ := hex.DecodeString(str(d, "plaintext"))
		ad, _ := hex.DecodeString(str(d, "ad"))
		ct, tag := HskeNlV3DuplexEncrypt(hexToBA(n, str(d, "key")),
			hexToBA(n, str(d, "nonce")), ad, pt)
		check("hske_duplex3 ct", hex.EncodeToString(ct), str(d, "ciphertext"))
		check("hske_duplex3 tag", hex.EncodeToString(tag), str(d, "tag"))
	}

	// fpe --v3 / twk --v3.
	{
		f := v.FpeTwkV3
		key := hexToBA(n, str(f, "key")).Bytes()
		pt := hexToBA(n, str(f, "plaintext"))
		ctx, _ := hex.DecodeString(str(f, "fpe_context"))
		check("fpe_v3", hx(FpeV3Encrypt(pt, key, ctx)), str(f, "fpe_ciphertext"))
		sector := hexToBig(str(f, "twk_sector")).Uint64()
		bidx := uint32(hexToBig(str(f, "twk_bidx")).Uint64())
		check("twk_v3", hx(TwkV3Encrypt(pt, key, sector, bidx)), str(f, "twk_ciphertext"))
	}
	return fails
}

func polyHex(coeffs []int, bytesPerCoeff int) string {
	raw := make([]byte, len(coeffs)*bytesPerCoeff)
	for i, c := range coeffs {
		for k := bytesPerCoeff - 1; k >= 0; k-- {
			raw[i*bytesPerCoeff+k] = byte(c & 0xFF)
			c >>= 8
		}
	}
	return hex.EncodeToString(raw)
}

func main() {
	data, err := os.ReadFile("KAT/classical_quartet.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/classical_quartet.json:", err)
		os.Exit(1)
	}
	var v vectorSet
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Fprintln(os.Stderr, "bad JSON:", err)
		os.Exit(1)
	}

	n := 256
	poly := GfPoly[n]
	fails := 0

	// HKEX-GF
	{
		a := hexToBig(str(v.HkexGf, "alice_priv"))
		b := hexToBig(str(v.HkexGf, "bob_priv"))
		C := GfPow(big.NewInt(GfGen), a, poly, n)
		C2 := GfPow(big.NewInt(GfGen), b, poly, n)
		sk := GfPow(C2, a, poly, n)
		skOther := GfPow(C, b, poly, n)
		want := str(v.HkexGf, "shared_secret")
		got := fmt.Sprintf("%0*x", n/4, sk)
		if got != want || sk.Cmp(skOther) != 0 {
			fmt.Printf("FAIL hkex_gf: got %s want %s (C^b agree=%v)\n", got, want, sk.Cmp(skOther) == 0)
			fails++
		} else {
			fmt.Println("PASS hkex_gf")
		}
	}

	// HSKE
	{
		key := hexToBA(n, str(v.Hske, "key"))
		pt := hexToBA(n, str(v.Hske, "plaintext"))
		iSteps := int(v.Hske["i_steps"].(float64))
		ct := FscxRevolve(pt, key, iSteps)
		want := str(v.Hske, "ciphertext")
		got := fmt.Sprintf("%0*x", n/4, &ct.Val)
		if got != want {
			fmt.Printf("FAIL hske: got %s want %s\n", got, want)
			fails++
		} else {
			fmt.Println("PASS hske")
		}
	}

	// HPKS
	{
		pub := hexToBA(n, str(v.Hpks, "pub"))
		R := hexToBA(n, str(v.Hpks, "R"))
		s := hexToBA(n, str(v.Hpks, "s"))
		msg := hexToBA(n, str(v.Hpks, "message"))
		ok := HpksVerify(msg, pub, R, s, poly, n)
		if !ok {
			fmt.Println("FAIL hpks: verify returned false")
			fails++
		} else {
			fmt.Println("PASS hpks")
		}
	}

	// HPKE
	{
		privA := hexToBig(str(v.Hpke, "recipient_priv"))
		ephR := hexToBig(str(v.Hpke, "ephemeral_r"))
		pub := hexToBA(n, str(v.Hpke, "recipient_pub"))
		pt := hexToBA(n, str(v.Hpke, "plaintext"))

		// Recompute R and enc_key directly (HpkeEncrypt draws r randomly),
		// then confirm ciphertext + full decrypt round-trip match.
		Rbig := GfPow(big.NewInt(GfGen), ephR, poly, n)
		encKey := GfPow(&pub.Val, ephR, poly, n)
		ct := FscxRevolve(pt, NewBitArray(n, encKey), n/4)
		gotCt := fmt.Sprintf("%0*x", n/4, &ct.Val)
		wantCt := str(v.Hpke, "ciphertext")
		gotR := fmt.Sprintf("%0*x", n/4, Rbig)
		wantR := str(v.Hpke, "R")

		Rba := NewBitArray(n, Rbig)
		dec, ok := HpkeDecrypt(ct, Rba, NewBitArray(n, privA), poly, n)
		decOk := ok && dec.Val.Cmp(&pt.Val) == 0

		if gotCt != wantCt || gotR != wantR || !decOk {
			fmt.Printf("FAIL hpke: ct(got=%s want=%s) R(got=%s want=%s) decrypt_roundtrip=%v\n",
				gotCt, wantCt, gotR, wantR, decOk)
			fails++
		} else {
			fmt.Println("PASS hpke")
		}
	}

	// ── HKEX-RNL (TODO #226) ────────────────────────────────────────────
	if rdata, err := os.ReadFile("KAT/hkex_rnl.json"); err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/hkex_rnl.json:", err)
		fails++
	} else {
		var rv rnlFile
		if err := json.Unmarshal(rdata, &rv); err != nil {
			fmt.Fprintln(os.Stderr, "cannot parse KAT/hkex_rnl.json:", err)
			fails++
		} else {
			if !verifyRnl("hkex_rnl deployed", rv.Deployed) {
				fails++
			}
			if !verifyRnl("hkex_rnl small_ring", rv.SmallRing) {
				fails++
			}
		}
	}

	// ── NL-FSCX v3 (TODO #255) ──────────────────────────────────────────
	if vdata, err := os.ReadFile("KAT/nl_fscx_v3.json"); err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/nl_fscx_v3.json:", err)
		fails++
	} else {
		var vv v3File
		if err := json.Unmarshal(vdata, &vv); err != nil {
			fmt.Fprintln(os.Stderr, "cannot parse KAT/nl_fscx_v3.json:", err)
			fails++
		} else {
			fails += verifyV3(vv)
		}
	}

	if fails > 0 {
		fmt.Printf("%d vector set(s) FAILED\n", fails)
		os.Exit(1)
	}
	fmt.Println("All KAT vectors verified against the Go herradura package.")
}
