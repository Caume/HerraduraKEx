// Package herraduraffi is a cgo wrapper around libherradura_ffi
// (bindings/ffi/herradura_shim.c). It is an opt-in fast path for
// performance-sensitive users that calls into the C implementation instead
// of the pure-Go suite; the native Go suite in "Herradura cryptographic
// suite.go" is untouched and remains the pedagogical reference.
//
// Build the shared library first: bash bindings/ffi/build.sh
//
// Scope: the classical v1.4.0 quartet (HKEX-GF, HSKE, HPKS, HPKE). NL/PQC
// and Stern-F protocols are not exposed through this binding — see TODO #137.
package herraduraffi

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo LDFLAGS: -L${SRCDIR}/.. -lherradura_ffi -Wl,-rpath,${SRCDIR}/..
#include "herradura_shim.h"
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

// KeyBytes is the fixed width (in bytes) of every buffer used by this
// binding's classical protocol quartet.
const KeyBytes = C.HFFI_KEYBYTES

func init() {
	if int(C.hffi_keybytes()) != KeyBytes {
		panic("herraduraffi: KEYBYTES mismatch between binding and shared library")
	}
}

// RandomBytes returns KeyBytes bytes of cryptographically secure randomness.
func RandomBytes() ([]byte, error) {
	b := make([]byte, KeyBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func checkLen(name string, b []byte) error {
	if len(b) != KeyBytes {
		return fmt.Errorf("herraduraffi: %s must be %d bytes, got %d", name, KeyBytes, len(b))
	}
	return nil
}

func cptr(b []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// HkexGfPubkey derives the HKEX-GF public key pub = g^priv.
func HkexGfPubkey(priv []byte) ([]byte, error) {
	if err := checkLen("priv", priv); err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	C.hffi_hkex_gf_pubkey(cptr(priv), cptr(out))
	return out, nil
}

// HkexGfAgree derives the HKEX-GF shared secret. Returns (nil, nil) if
// theirPub is a degenerate (identity/zero) public key.
func HkexGfAgree(myPriv, theirPub []byte) ([]byte, error) {
	if err := checkLen("myPriv", myPriv); err != nil {
		return nil, err
	}
	if err := checkLen("theirPub", theirPub); err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	ok := C.hffi_hkex_gf_agree(cptr(myPriv), cptr(theirPub), cptr(out))
	if ok == 0 {
		return nil, nil
	}
	return out, nil
}

// HskeEncrypt encrypts pt under key.
func HskeEncrypt(pt, key []byte) ([]byte, error) {
	if err := checkLen("pt", pt); err != nil {
		return nil, err
	}
	if err := checkLen("key", key); err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	C.hffi_hske_encrypt(cptr(pt), cptr(key), cptr(out))
	return out, nil
}

// HskeDecrypt decrypts ct under key.
func HskeDecrypt(ct, key []byte) ([]byte, error) {
	if err := checkLen("ct", ct); err != nil {
		return nil, err
	}
	if err := checkLen("key", key); err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	C.hffi_hske_decrypt(cptr(ct), cptr(key), cptr(out))
	return out, nil
}

// HpksSign produces a Schnorr signature (R, s) on msg under priv.
func HpksSign(msg, priv []byte) (R, s []byte, err error) {
	if err = checkLen("msg", msg); err != nil {
		return nil, nil, err
	}
	if err = checkLen("priv", priv); err != nil {
		return nil, nil, err
	}
	R = make([]byte, KeyBytes)
	s = make([]byte, KeyBytes)
	C.hffi_hpks_sign(cptr(msg), cptr(priv), cptr(R), cptr(s))
	return R, s, nil
}

// HpksVerify verifies a Schnorr signature (R, s) on msg under pub.
func HpksVerify(msg, pub, R, s []byte) (bool, error) {
	for name, b := range map[string][]byte{"msg": msg, "pub": pub, "R": R, "s": s} {
		if err := checkLen(name, b); err != nil {
			return false, err
		}
	}
	return C.hffi_hpks_verify(cptr(msg), cptr(pub), cptr(R), cptr(s)) != 0, nil
}

// HpkeEncrypt encrypts pt for the holder of the private key matching pub.
// Returns (nil, nil, nil) if pub is a degenerate public key.
func HpkeEncrypt(pt, pub []byte) (R, ct []byte, err error) {
	if err = checkLen("pt", pt); err != nil {
		return nil, nil, err
	}
	if err = checkLen("pub", pub); err != nil {
		return nil, nil, err
	}
	R = make([]byte, KeyBytes)
	ct = make([]byte, KeyBytes)
	ok := C.hffi_hpke_encrypt(cptr(pt), cptr(pub), cptr(R), cptr(ct))
	if ok == 0 {
		return nil, nil, nil
	}
	return R, ct, nil
}

// HpkeDecrypt decrypts ct using priv and the sender's ephemeral R. Returns
// (nil, nil) if R is a degenerate public key.
func HpkeDecrypt(ct, R, priv []byte) ([]byte, error) {
	if err := checkLen("ct", ct); err != nil {
		return nil, err
	}
	if err := checkLen("R", R); err != nil {
		return nil, err
	}
	if err := checkLen("priv", priv); err != nil {
		return nil, err
	}
	out := make([]byte, KeyBytes)
	ok := C.hffi_hpke_decrypt(cptr(ct), cptr(R), cptr(priv), cptr(out))
	if ok == 0 {
		return nil, nil
	}
	return out, nil
}
