package herraduraffi

// Cross-checks the cgo FFI binding against the native Go suite (package
// herradura) for the classical v1.4.0 quartet, replicating the exact
// composition used in "Herradura cryptographic suite.go" main().

import (
	"bytes"
	"math/big"
	"testing"

	herradura "herradurakex/herradura"
)

const keyBits = 256

var ivalue = keyBits / 4
var rvalue = 3 * keyBits / 4

func toBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func toBytes(v *big.Int) []byte {
	out := make([]byte, KeyBytes)
	v.FillBytes(out)
	return out
}

func nativeBA(b []byte) *herradura.BitArray {
	return herradura.NewBitArray(keyBits, toBig(b))
}

func TestFFIMatchesNativeGo(t *testing.T) {
	poly := herradura.GfPoly[keyBits]
	g := big.NewInt(herradura.GfGen)

	aPriv, _ := RandomBytes()
	bPriv, _ := RandomBytes()

	aPubFFI, err := HkexGfPubkey(aPriv)
	if err != nil {
		t.Fatal(err)
	}
	aPubNative := toBytes(herradura.GfPow(g, toBig(aPriv), poly, keyBits))
	if !bytes.Equal(aPubFFI, aPubNative) {
		t.Fatalf("hkex_gf_pubkey mismatch: ffi=%x native=%x", aPubFFI, aPubNative)
	}

	bPubFFI, _ := HkexGfPubkey(bPriv)
	sharedFFI, _ := HkexGfAgree(aPriv, bPubFFI)
	sharedNative := toBytes(herradura.GfPow(toBig(bPubFFI), toBig(aPriv), poly, keyBits))
	if !bytes.Equal(sharedFFI, sharedNative) {
		t.Fatalf("hkex_gf_agree mismatch: ffi=%x native=%x", sharedFFI, sharedNative)
	}

	pt, _ := RandomBytes()
	key, _ := RandomBytes()
	ctFFI, _ := HskeEncrypt(pt, key)
	ctNative := herradura.FscxRevolve(nativeBA(pt), nativeBA(key), ivalue).Val.FillBytes(make([]byte, KeyBytes))
	if !bytes.Equal(ctFFI, ctNative) {
		t.Fatalf("hske_encrypt mismatch: ffi=%x native=%x", ctFFI, ctNative)
	}
	ptBackFFI, _ := HskeDecrypt(ctFFI, key)
	ptBackNative := herradura.FscxRevolve(nativeBA(ctFFI), nativeBA(key), rvalue).Val.FillBytes(make([]byte, KeyBytes))
	if !bytes.Equal(ptBackFFI, ptBackNative) || !bytes.Equal(ptBackFFI, pt) {
		t.Fatalf("hske_decrypt mismatch: ffi=%x native=%x pt=%x", ptBackFFI, ptBackNative, pt)
	}

	// HPKS: k is drawn independently on each side, so cross-check via verify.
	msg, _ := RandomBytes()
	R, s, _ := HpksSign(msg, aPriv)
	e := herradura.FscxRevolve(nativeBA(R), nativeBA(msg), ivalue)
	lhs := herradura.GfMul(
		herradura.GfPow(g, toBig(s), poly, keyBits),
		herradura.GfPow(toBig(aPubFFI), &e.Val, poly, keyBits),
		poly, keyBits)
	if lhs.Cmp(toBig(R)) != 0 {
		t.Fatalf("native verify of FFI-produced HPKS signature failed")
	}

	// HPKE: encrypt natively with a known r, decrypt via FFI.
	r, _ := RandomBytes()
	RNative := toBytes(herradura.GfPow(g, toBig(r), poly, keyBits))
	encKey := nativeBA(toBytes(herradura.GfPow(toBig(aPubFFI), toBig(r), poly, keyBits)))
	ctHpkeNative := herradura.FscxRevolve(nativeBA(pt), encKey, ivalue).Val.FillBytes(make([]byte, KeyBytes))
	decFFI, err := HpkeDecrypt(ctHpkeNative, RNative, aPriv)
	if err != nil || !bytes.Equal(decFFI, pt) {
		t.Fatalf("hpke_decrypt(native ct) mismatch: got=%x want=%x err=%v", decFFI, pt, err)
	}
}
