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

func str(m map[string]interface{}, k string) string { return m[k].(string) }

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

	if fails > 0 {
		fmt.Printf("%d vector set(s) FAILED\n", fails)
		os.Exit(1)
	}
	fmt.Println("All KAT vectors verified against the Go herradura package.")
}
