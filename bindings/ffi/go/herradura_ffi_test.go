package herraduraffi

import (
	"bytes"
	"testing"
)

func TestRoundTrips(t *testing.T) {
	aPriv, _ := RandomBytes()
	bPriv, _ := RandomBytes()
	aPub, err := HkexGfPubkey(aPriv)
	if err != nil {
		t.Fatal(err)
	}
	bPub, _ := HkexGfPubkey(bPriv)

	sharedA, _ := HkexGfAgree(aPriv, bPub)
	sharedB, _ := HkexGfAgree(bPriv, aPub)
	if sharedA == nil || !bytes.Equal(sharedA, sharedB) {
		t.Fatalf("HKEX-GF shared secrets mismatch")
	}

	pt, _ := RandomBytes()
	key, _ := RandomBytes()
	ct, _ := HskeEncrypt(pt, key)
	dec, _ := HskeDecrypt(ct, key)
	if !bytes.Equal(dec, pt) {
		t.Fatalf("HSKE roundtrip mismatch")
	}

	msg, _ := RandomBytes()
	R, s, _ := HpksSign(msg, aPriv)
	ok, _ := HpksVerify(msg, aPub, R, s)
	if !ok {
		t.Fatalf("HPKS signature failed to verify")
	}

	R2, ct2, err := HpkeEncrypt(pt, aPub)
	if err != nil || R2 == nil {
		t.Fatalf("HPKE encrypt failed: %v", err)
	}
	dec2, _ := HpkeDecrypt(ct2, R2, aPriv)
	if !bytes.Equal(dec2, pt) {
		t.Fatalf("HPKE roundtrip mismatch")
	}
}
