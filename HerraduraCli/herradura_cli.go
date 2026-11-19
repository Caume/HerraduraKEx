// HerraduraCli/herradura_cli.go — Go CLI for the Herradura Cryptographic Suite
//
// Usage:
//   herradura_cli_go genpkey  --algo hkex-gf  --bits 256 --out alice.pem
//   herradura_cli_go pkey     --in alice.pem   --pubout  --out alice_pub.pem
//   herradura_cli_go kex      --algo hkex-gf   --our alice.pem --their bob_pub.pem --out sk.pem
//   herradura_cli_go enc      --algo hske      --key sk.pem --in msg.bin --out ct.pem
//   herradura_cli_go dec      --algo hske      --key sk.pem --in ct.pem  --out plain.bin
//   herradura_cli_go enc      --algo hske-duplex --key sk.pem --in msg.bin --ad hdr --out ct.pem
//   herradura_cli_go dec      --algo hske-duplex --key sk.pem --in ct.pem  --ad hdr --out plain.bin
//   herradura_cli_go sign     --algo hpks      --key priv.pem --in msg.bin --out sig.pem
//   herradura_cli_go verify   --algo hpks      --pubkey pub.pem --in msg.bin --sig sig.pem
//   herradura_cli_go dgst     --in file.bin                       # hex to stdout
//   herradura_cli_go dgst     --algo hfscx-256 --in file.bin --out d.pem
//   herradura_cli_go rand     --seed seed.bin --bytes 64 --hex     # deterministic bytes
//
// HKEX-RNL (2-round):
//   herradura_cli_go kex --algo hkex-rnl --our bob.pem --their alice_pub.pem --out resp.pem
//   herradura_cli_go kex --algo hkex-rnl --our alice.pem --their resp.pem    --out sk.pem
//
// hybrid-rnl-stern (2-round; TODO #167, port of TODO #162):
//   herradura_cli_go kex --algo hybrid-rnl-stern --our bob.pem --their alice_pub.pem \
//       --their-kem alice_kem_pub.pem --out resp.pem
//   herradura_cli_go kex --algo hybrid-rnl-stern --our alice.pem --their resp.pem \
//       --our-kem alice_kem.pem --out sk.pem
package main

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"

	. "herradurakex/herradura"
)

// ── Bounds on PEM fields that size an allocation (TODO #240) ────────────────
//
// TODO #239 range-checked these fields in the C CLI and stopped there, so every
// reader below was still multiplying counts straight off the wire into a
// make([]byte, ...).  A four-byte edit to a signature became
// "fatal error: out of memory" with a goroutine dump rather than a diagnostic,
// and — because these are the same wire fields the C reader now refuses — a
// disagreement between the two CLIs about what a valid artifact is.
//
// Reject rather than clamp, and reject inside the reader: verify's own
// "signature ring size != provided members" check runs after the allocation it
// was meant to guard.
const (
	ringMaxK  = 64      // herradura_cli.c RING_MAX_K
	xmssMaxH  = 20      // herradura_cli.c XMSS_MAX_H; genpkey's --xmss-height cap
	sternMaxN = 256     // the suite key width; nothing here emits a wider Stern instance
)

// bounded returns v, or exits 1 if it falls outside [lo, hi].  `what` names the
// field as the wire calls it and `where` is the subcommand, so the message
// shape matches the C CLI's.
func bounded(v, lo, hi int, what, where string) int {
	if v < lo || v > hi {
		fmt.Fprintf(os.Stderr, "%s: %s is %d (expected %d..%d)\n", where, what, v, lo, hi)
		os.Exit(1)
	}
	return v
}

// boundedN bounds a wire-supplied bit width: a multiple of 8, at least 16, no
// wider than the suite's own key width.
//
// The floor was 8 until TODO #314 pass 3 and is now BITARRAY.md §2's: fscx
// reads the octet on both sides of every position and degenerates below two
// octets, so a one-octet BitArray is not representable in any converted port
// and KAT/bitarray.json pins nbits = 8 as E_WIDTH.  No writer here emits a
// narrower Stern instance either -- sternT(8) is 0, a degenerate error weight --
// so this refuses an artifact that was never valid, rather than carrying it
// into a width the type cannot hold.
func boundedN(v int, where string) int {
	v = bounded(v, 16, sternMaxN, "n", where)
	if v%8 != 0 {
		fmt.Fprintf(os.Stderr, "%s: n is %d (expected a multiple of 8)\n", where, v)
		os.Exit(1)
	}
	return v
}

// gfWidth bounds a wire-supplied width for the classical GF(2^n) algorithms:
// it must be one of the widths BITARRAY.md §4.6 lists a primitive polynomial
// for.  Before TODO #314 pass 3 every one of these call sites read
// `poly := GfPoly[n]; if poly == nil { poly = GfPoly[256] }`, i.e. it kept the
// wire's width and did the arithmetic under the 256-bit polynomial — garbage,
// silently, on an artifact no writer here can produce (genpkey normalises an
// unlisted --bits to 256, so every legitimate classical key is 32, 64, 128 or
// 256).  The width now selects the polynomial, so an unlisted one is E_NO_POLY
// and this refuses it the way TODO #239/#240 refuse every other wire field that
// sizes a computation.
func gfWidth(v int, where string) int {
	switch v {
	case 32, 64, 128, 256:
		return v
	}
	fmt.Fprintf(os.Stderr, "%s: n is %d (expected 32, 64, 128 or 256)\n", where, v)
	os.Exit(1)
	return 0
}

// wireInt decodes a DER INTEGER's value bytes as a non-negative int, refusing
// anything too wide to be a count.  bytesToInt goes through Int64 and would
// silently truncate; a 2^64 round count must be rejected, not wrapped to 0.
func wireInt(b []byte, what, where string) int {
	if len(b) == 0 || len(b) > 4 {
		fmt.Fprintf(os.Stderr, "%s: %s is not a valid count (%d-byte field)\n",
			where, what, len(b))
		os.Exit(1)
	}
	return bytesToInt(b)
}

// rnlWireN bounds a wire-supplied HKEX-RNL ring dimension: a power of two from
// 8 to the deployed RnlN (TODO #367).  It sizes every polynomial unpacked
// after it, so an unbounded one panicked or ran the process out of memory.
// C is compiled for RnlN alone and requires it exactly (rnl_require_n).
func rnlWireN(b []byte, where string) int {
	v := bounded(wireInt(b, "ring dimension n", where), 8, RnlN, "ring dimension n", where)
	if v&(v-1) != 0 {
		fmt.Fprintf(os.Stderr, "%s: ring dimension n is %d (expected a power of two)\n", where, v)
		os.Exit(1)
	}
	return v
}

// sternWireN bounds a wire-supplied Stern / HPKE-Stern key width (TODO #367).
// rnlSameRing refuses a peer artifact whose ring dimension is not ours.  Go
// used to read only its own key's n and ignore the peer's (TODO #367); Python
// and Java refused the mismatch, and C requires RnlN of both.
func rnlSameRing(ours int, theirs []byte, where string) {
	if t := rnlWireN(theirs, where); t != ours {
		fmt.Fprintf(os.Stderr, "%s: ring size mismatch (ours=%d, theirs=%d)\n", where, ours, t)
		os.Exit(1)
	}
}

func sternWireN(b []byte, where string) int {
	return boundedN(wireInt(b, "n", where), where)
}

// checkDerItemsExact reports a shared-label artifact (CIPHERTEXT, SIGNATURE)
// whose item count is not the one this algorithm's decoder reads (TODO #367).
func checkDerItemsExact(label string, ints [][]byte, want int) error {
	return fmt.Errorf("malformed PEM '%s': %d DER items, expected %d", label, len(ints), want)
}

// wireIntZ is wireInt for a field whose legitimate value may be 0, which DER
// carries as an empty INTEGER body here (leading zero bytes are stripped).
func wireIntZ(b []byte, what, where string) int {
	if len(b) == 0 {
		return 0
	}
	return wireInt(b, what, where)
}

// fitBytes returns a wire integer's bytes right-aligned in a width-byte field,
// or refuses it when it does not fit.  big.Int.FillBytes PANICS on an
// oversized value, which is what a crafted field reached before TODO #367.
func fitBytes(b []byte, width int, what, where string) []byte {
	v := new(big.Int).SetBytes(b)
	if (v.BitLen()+7)/8 > width {
		fmt.Fprintf(os.Stderr, "%s: %s is %d bytes (expected at most %d)\n",
			where, what, (v.BitLen()+7)/8, width)
		os.Exit(1)
	}
	return v.FillBytes(make([]byte, width))
}

// ── PEM label constants (must match Python and C exactly) ───────────────────

const (
	lblHkexGFPriv    = "HERRADURA HKEX-GF PRIVATE KEY"
	lblHkexRNLPriv   = "HERRADURA HKEX-RNL PRIVATE KEY"
	lblHpksPriv      = "HERRADURA HPKS PRIVATE KEY"
	lblHpksNLPriv    = "HERRADURA HPKS-NL PRIVATE KEY"
	lblHpkePriv      = "HERRADURA HPKE PRIVATE KEY"
	lblHpkeNLPriv    = "HERRADURA HPKE-NL PRIVATE KEY"
	lblHpkeNL3Priv   = "HERRADURA HPKE-NL3 PRIVATE KEY" // TODO #255
	lblHpksSternPriv = "HERRADURA HPKS-STERN PRIVATE KEY"
	lblHpkeSternPriv = "HERRADURA HPKE-STERN PRIVATE KEY"

	lblHkexGFPub    = "HERRADURA HKEX-GF PUBLIC KEY"
	lblHkexRNLPub   = "HERRADURA HKEX-RNL PUBLIC KEY"
	lblHpksPub      = "HERRADURA HPKS PUBLIC KEY"
	lblHpksNLPub    = "HERRADURA HPKS-NL PUBLIC KEY"
	lblHpkePub      = "HERRADURA HPKE PUBLIC KEY"
	lblHpkeNLPub    = "HERRADURA HPKE-NL PUBLIC KEY"
	lblHpkeNL3Pub   = "HERRADURA HPKE-NL3 PUBLIC KEY"
	lblHpksSternPub = "HERRADURA HPKS-STERN PUBLIC KEY"
	lblHpkeSternPub = "HERRADURA HPKE-STERN PUBLIC KEY"

	lblKemPriv = "HERRADURA HPKE-STERN-KEM PRIVATE KEY"
	lblKemPub  = "HERRADURA HPKE-STERN-KEM PUBLIC KEY"

	lblHpksWotsPriv = "HERRADURA HPKS-WOTS PRIVATE KEY"
	lblHpksWotsPub  = "HERRADURA HPKS-WOTS PUBLIC KEY"
	lblHpksWotsSig  = "HERRADURA HPKS-WOTS SIGNATURE"
	lblHpksXmssPriv = "HERRADURA HPKS-XMSS PRIVATE KEY"
	lblHpksXmssPub  = "HERRADURA HPKS-XMSS PUBLIC KEY"
	lblHpksXmssSig  = "HERRADURA HPKS-XMSS SIGNATURE"
	lblRingSig      = "HERRADURA HPKS-RING SIGNATURE"

	lblSession    = "HERRADURA SESSION KEY"
	lblRnlResp    = "HERRADURA HKEX-RNL RESPONSE"
	lblHybridResp = "HERRADURA HYBRID-RNL-STERN RESPONSE"
	lblCT      = "HERRADURA CIPHERTEXT"
	lblSig     = "HERRADURA SIGNATURE"
	lblDigest  = "HERRADURA DIGEST"
	lblHdrbg   = "HERRADURA HDRBG STATE"

	lblZkpRnlProof = "HERRADURA ZKP-RNL PROOF"
	lblZkpNlPriv   = "HERRADURA ZKP-NL PRIVATE KEY"
	lblZkpNlPub    = "HERRADURA ZKP-NL PUBLIC KEY"
	lblZkpNlProof  = "HERRADURA ZKP-NL PROOF"
	lblZkpNlPpSig  = "HERRADURA ZKP-NL-PP SIGNATURE"

	lblOprfPriv   = "HERRADURA OPRF PRIVATE KEY"
	lblOprfState  = "HERRADURA OPRF CLIENT STATE"
	lblOprfEval   = "HERRADURA OPRF EVALUATION"
	lblPakeRecord = "HERRADURA PAKE RECORD"

	lblHpkstCommit    = "HERRADURA HPKST COMMITMENT"
	lblHpkstNonce     = "HERRADURA HPKST NONCE"
	lblHpkstAggregate = "HERRADURA HPKST AGGREGATE"
	lblHpkstPartial   = "HERRADURA HPKST PARTIAL"
	lblHpkstSig       = "HERRADURA HPKST SIGNATURE"

	lblHcredPriv  = "HERRADURA HCRED PRIVATE KEY"
	lblHcredPub   = "HERRADURA HCRED PUBLIC KEY"
	lblHcredCred  = "HERRADURA HCRED CREDENTIAL"
	lblHcredProof = "HERRADURA HCRED PROOF"
)

var privToAlgo = map[string]string{
	lblHkexGFPriv:    "hkex-gf",
	lblHkexRNLPriv:   "hkex-rnl",
	lblHpksPriv:      "hpks",
	lblHpksNLPriv:    "hpks-nl",
	lblHpkePriv:      "hpke",
	lblHpkeNLPriv:    "hpke-nl",
	lblHpkeNL3Priv:   "hpke-nl3",
	lblHpksSternPriv: "hpks-stern",
	lblHpkeSternPriv: "hpke-stern",
	lblKemPriv:       "hpke-stern-kem",
	lblHpksWotsPriv:  "hpks-wots",
	lblHpksXmssPriv:  "hpks-xmss",
	lblOprfPriv:      "oprf", // pkey --text only (TODO #374)
}

var algoToPrivLbl = map[string]string{
	"hkex-gf":    lblHkexGFPriv,
	"hkex-rnl":   lblHkexRNLPriv,
	"hpks":       lblHpksPriv,
	"hpks-nl":    lblHpksNLPriv,
	"hpke":       lblHpkePriv,
	"hpke-nl":    lblHpkeNLPriv,
	"hpke-nl3":   lblHpkeNL3Priv,
	"hpks-stern": lblHpksSternPriv,
	"hpke-stern": lblHpkeSternPriv,
	"hpks-wots":  lblHpksWotsPriv,
	"hpks-xmss":  lblHpksXmssPriv,
}

var algoToPubLbl = map[string]string{
	"hkex-gf":    lblHkexGFPub,
	"hkex-rnl":   lblHkexRNLPub,
	"hpks":       lblHpksPub,
	"hpks-nl":    lblHpksNLPub,
	"hpke":       lblHpkePub,
	"hpke-nl":    lblHpkeNLPub,
	"hpke-nl3":   lblHpkeNL3Pub,
	"hpks-stern": lblHpksSternPub,
	"hpke-stern": lblHpkeSternPub,
	"hpks-wots":  lblHpksWotsPub,
	"hpks-xmss":  lblHpksXmssPub,
}

var classicalAlgos = map[string]bool{
	"hkex-gf": true, "hpks": true, "hpks-nl": true,
	"hpke": true, "hpke-nl": true, "hpke-nl3": true,
}

var sternAlgos = map[string]bool{
	"hpks-stern": true, "hpke-stern": true,
}

// ── I/O helpers ──────────────────────────────────────────────────────────────

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeString(path, s string) error {
	if path == "-" {
		_, err := fmt.Fprint(os.Stdout, s)
		return err
	}
	return os.WriteFile(path, []byte(s), 0644)
}

func writeBytes(path string, b []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// ─────────────────────────────────────────────────────────────────────────────
// Passphrase-encrypted private-key envelope (TODO #166, ported by TODO #268)
//
// The whole cleartext PEM -- label, base64 and all -- is encrypted as opaque
// bytes, so this composes with every subcommand: decrypt, then feed the exact
// original file to anything.  That is why the envelope carries no algorithm
// field and needs none.
//
//	salt     16 random bytes
//	key      PBKDF2-HFSCX-256(HFSCX-256(passphrase), salt, iterations)
//	nonce    32 random bytes
//	ct, tag  HSKE-NL-AEAD(key, nonce, ad = "", pt = the PEM text)
//	DER      SEQUENCE(salt[16], iterations, nonce[32], ct[pt_len], tag[32], pt_len)
// ─────────────────────────────────────────────────────────────────────────────

const lblEncPriv = "HERRADURA ENCRYPTED PRIVATE KEY"

const pbkdf2SaltBytes = 16

// The envelope is always 256-bit: its key comes from a 32-byte PRF output, not
// from any user-selected width, so it does not follow genpkey --bits.
const envKeyBits = 256

// pbkdf2IterDemo matches Python's default.  SP 800-132 wants >= 200,000; a
// pure-Python HFSCX-256 runs ~300/sec, so the shared default is low for CLI
// responsiveness and --kdf-iterations opts into the floor.  The count travels
// in the PEM, so a reader honours whatever the writer chose regardless of its
// own default -- the contract Stern-F's round count has had since TODO #236.
const pbkdf2IterDemo = 1000

// pbkdf2IterMax is the most any writer may choose, and the most any reader honours.
const pbkdf2IterMax = 100000000

// pbkdf2Hfscx256 is RFC 8018 PBKDF2 with the suite's own HMAC-HFSCX-256 as the
// PRF: a standard, analysed shape rather than a bespoke construction, and
// dependency-free.  Only dklen == 32 (the PRF's native width, hence a single
// block) is ever needed.
func pbkdf2Hfscx256(password, salt []byte, iterations int) []byte {
	// HMAC-HFSCX-256 takes an exactly-32-byte key, so an arbitrary-length
	// password is hashed down first -- standard HMAC over-length-key handling,
	// and identical in all four languages.
	key := Hfscx256(password, nil)
	block := append(append([]byte{}, salt...), 0, 0, 0, 1)
	u := HmacHfscx256(key, block)
	t := append([]byte{}, u...)
	for i := 1; i < iterations; i++ {
		u = HmacHfscx256(key, u)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

func encryptPEMText(pemText, passphrase string, iterations int) (string, error) {
	saltBA := NewRandBitArray(pbkdf2SaltBytes * 8)
	salt := saltBA.Bytes()
	nonce := NewRandBitArray(envKeyBits)
	key := NewBitArray(envKeyBits, new(big.Int).SetBytes(pbkdf2Hfscx256([]byte(passphrase), salt, iterations)))
	pt := []byte(pemText)
	ct, tag := HskeNlAeadEncrypt(key, nonce, nil, pt)

	der, err := DerSeqEnc(
		mustDerInt(salt),
		mustDerInt(minimalBE(uint64(iterations))),
		mustDerInt(nonce.Bytes()),
		mustDerInt(ct),
		mustDerInt(tag),
		mustDerInt(minimalBE(uint64(len(pt)))),
	)
	if err != nil {
		return "", err
	}
	return PemWrap(lblEncPriv, der), nil
}

// minimalBE renders v as the shortest big-endian byte string, matching Python's
// der_int(x) with no explicit width (TODO #271).
func minimalBE(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	return b
}

func mustDerInt(val []byte) []byte {
	b, err := DerIntEnc(val)
	if err != nil {
		die("der", err)
	}
	return b
}

// leftPad restores a fixed-width field that lost leading zero bytes to a
// minimal DER INTEGER encoding (TODO #280).  A field already at or above the
// width is returned unchanged; callers bound the length before calling.
func leftPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

// decryptPEMFile recovers the cleartext PEM, or fails -- it never returns
// unverified bytes.
func decryptPEMFile(path, passphrase string) (string, error) {
	body, err := readRawPEM(path, lblEncPriv)
	if err != nil {
		return "", err
	}
	items, enc, err := derParseLabeled(lblEncPriv, body)
	if err != nil {
		return "", err
	}
	if err := checkDerItems(lblEncPriv, items); err != nil {   // TODO #367
		return "", err
	}
	if err := checkDerCaps(lblEncPriv, items, enc); err != nil {   // TODO #372, #373
		return "", err
	}
	salt, iterB, nonceB, ct, tag, ptLenB := items[0], items[1], items[2], items[3], items[4], items[5]
	// The salt, nonce, ciphertext and tag are FIXED-WIDTH byte strings carried
	// as DER INTEGERs, and a DER INTEGER has no leading zero to carry: a field
	// whose first byte is 0x00 encodes one significant byte SHORT, and
	// DerParseSeq's single sign-byte strip cannot put it back.  So a length
	// here is an upper bound to check and then LEFT-PAD from, never an equality
	// to assert.  Asserting it rejected roughly one envelope in 64 -- P(any of
	// four random fields starts with 0x00) -- which Python and Java both read
	// back correctly, because both restore the width from an integer.  TODO #280.
	if len(salt) > pbkdf2SaltBytes || len(nonceB) > envKeyBits/8 || len(tag) > 32 {
		return "", fmt.Errorf("malformed ENCRYPTED PRIVATE KEY envelope (field width)")
	}
	salt = leftPad(salt, pbkdf2SaltBytes)
	nonceB = leftPad(nonceB, envKeyBits/8)
	tag = leftPad(tag, 32)
	if len(iterB) == 0 || len(iterB) > 4 || len(ptLenB) > 8 {
		return "", fmt.Errorf("malformed ENCRYPTED PRIVATE KEY envelope (header width)")
	}
	iterations := 0
	for _, b := range iterB {
		iterations = iterations<<8 | int(b)
	}
	ptLen := 0
	for _, b := range ptLenB {
		ptLen = ptLen<<8 | int(b)
	}
	// Both size work below, so both are bounded before use -- the field class
	// TODO #239/#240/#275 exist over.
	if iterations < 1 || iterations > pbkdf2IterMax {
		return "", fmt.Errorf("iteration count out of range (%d)", iterations)
	}
	// The comparison runs the other way from the pre-TODO-#280 form: the
	// ciphertext is ptLen bytes LEFT-PADDED from len(ct) significant ones, so a
	// shorter field is a leading zero byte and a LONGER one is malformed.
	//
	// That reversal also removes the bound the old form gave for free: with
	// `ptLen > len(ct)` rejected, ptLen could never exceed the ciphertext
	// actually present.  It can now, so it is bounded explicitly against the
	// envelope body -- the ciphertext cannot be longer than the file carrying
	// it -- or a hostile PEM naming 2^62 bytes sizes the allocation below.
	// TODO #239/#240 exist over exactly this.
	if ptLen < 1 || len(ct) > ptLen || ptLen > len(body) {
		return "", fmt.Errorf("declared plaintext length does not match ciphertext")
	}
	ct = leftPad(ct, ptLen)

	key := NewBitArray(envKeyBits, new(big.Int).SetBytes(pbkdf2Hfscx256([]byte(passphrase), salt, iterations)))
	nonce := NewBitArray(envKeyBits, new(big.Int).SetBytes(nonceB))
	pt, ok := HskeNlAeadDecrypt(key, nonce, nil, ct, tag)
	if !ok {
		return "", fmt.Errorf("wrong passphrase or corrupted/tampered file")
	}
	return string(pt), nil
}

func readPEMInts(path string) (string, [][]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return "", nil, err
	}
	label, der, err := PemUnwrap(string(data))
	if err != nil {
		return "", nil, err
	}
	// FAIL CLOSED (TODO #268).  An envelope IS a valid DER SEQUENCE, so it
	// would parse cleanly and its salt/iterations/nonce be read as key
	// material.  The caller's "unrecognised PEM label" would refuse it, but
	// sends the reader looking for the wrong problem; naming it is the point.
	if label == lblEncPriv {
		return "", nil, fmt.Errorf("%s is a passphrase-encrypted private key; decrypt it "+
			"first with `pkey --decrypt --passphrase ... --in %s --out plain.pem`", path, path)
	}
	ints, enc, err := derParseLabeled(label, der)
	if err == nil {
		err = checkDerItems(label, ints)
	}
	if err == nil {
		err = checkDerCaps(label, ints, enc)
	}
	return label, ints, err
}

// rawEnd refuses bytes after a raw-body PEM's last field (TODO #372); the text
// is the one every CLI prints.
func rawEnd(label string, body []byte, off int) error {
	if off < len(body) {
		return fmt.Errorf("malformed PEM '%s': %d bytes after its last field", label, len(body)-off)
	}
	return nil
}

// checkDerCaps holds each field to the generated PEM_DER_FIELD_CAPS width
// (TODO #372): no field wider than its writer pads it to.
// checkDerCaps runs the generated field check: #372's widths, #373's
// encodings and value rules.
func checkDerCaps(label string, ints [][]byte, enc DerEnc) error {
	if len(enc.Width) != len(ints) {
		return fmt.Errorf("malformed PEM '%s': cannot parse DER", label)
	}
	if msg := derFieldCheck(label, ints, enc.Width, enc.Lead); msg != "" {
		return errors.New(msg)
	}
	return nil
}

func hkxMin(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// derParseLabeled is DerParseSeq with the PEM label in the trailing-data
// message every CLI prints (TODO #372).
func derParseLabeled(label string, der []byte) ([][]byte, DerEnc, error) {
	if t, err := DerSeqTrailing(der); err == nil && t > 0 {
		return nil, DerEnc{}, fmt.Errorf("malformed PEM '%s': %d bytes after the DER SEQUENCE", label, t)
	}
	// TODO #373: one encoding of the lengths and signs.
	enc, kind, bad := DerSeqScan(der)
	switch kind {
	case 1:
		return nil, enc, fmt.Errorf("malformed PEM '%s': DER length not in its shortest form", label)
	case 2:
		return nil, enc, fmt.Errorf("malformed PEM '%s': field %d is a negative INTEGER", label, bad)
	case 3:
		return nil, enc, fmt.Errorf("malformed PEM '%s': field %d is an empty INTEGER", label, bad)
	}
	ints, err := DerParseSeq(der)
	return ints, enc, err
}

// checkDerItems holds a parsed DER SEQUENCE to the generated derItems table
// (TODO #367), so no decoder indexes past the end of a short list.
func checkDerItems(label string, ints [][]byte) error {
	lim, ok := derItems[label]
	if !ok || (len(ints) >= lim[0] && len(ints) <= lim[1]) {
		return nil
	}
	want := fmt.Sprint(lim[0])
	if lim[0] != lim[1] {
		want = fmt.Sprintf("%d..%d", lim[0], lim[1])
	}
	return fmt.Errorf("malformed PEM '%s': %d DER items, expected %s", label, len(ints), want)
}

// ── DER encoding helpers ─────────────────────────────────────────────────────

func derIntBig(v *big.Int, width int) ([]byte, error) {
	// FillBytes panics on a value wider than the field; a key read from a
	// crafted PEM reaches here with one (TODO #367).
	if (v.BitLen()+7)/8 > width {
		return nil, fmt.Errorf("value is %d bytes, wider than its %d-byte field",
			(v.BitLen()+7)/8, width)
	}
	return DerIntEnc(v.FillBytes(make([]byte, width)))
}

func derIntSmall(n int) ([]byte, error) {
	b := new(big.Int).SetInt64(int64(n)).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	return DerIntEnc(b)
}

// fillBA writes ba's octets RIGHT-ALIGNED into dst, which is what the
// *big.Int FillBytes calls this file used to make did.  A plain
// copy(dst, ba.Bytes()) is left-aligned and is NOT the same when the two
// lengths differ, so the alignment is spelled out rather than assumed equal
// (TODO #314 pass 3).
func fillBA(dst []byte, ba *BitArray) {
	b := ba.Bytes()
	copy(dst[len(dst)-len(b):], b)
}

func bytesToInt(b []byte) int {
	return int(new(big.Int).SetBytes(b).Int64())
}

// ── Polynomial pack/unpack (matches Python codec.pack_poly) ──────────────────

func packPoly(coeffs []int, bpc int) []byte {
	raw := make([]byte, len(coeffs)*bpc)
	for i, c := range coeffs {
		v := uint64(c)
		for j := bpc - 1; j >= 0; j-- {
			raw[i*bpc+j] = byte(v)
			v >>= 8
		}
	}
	return raw
}

func unpackPolyRaw(raw []byte, n, bpc int) []int {
	need := n * bpc
	if len(raw) < need {
		padded := make([]byte, need)
		copy(padded[need-len(raw):], raw)
		raw = padded
	}
	coeffs := make([]int, n)
	for i := range coeffs {
		v := 0
		for j := 0; j < bpc; j++ {
			v = (v << 8) | int(raw[i*bpc+j])
		}
		coeffs[i] = v
	}
	return coeffs
}

// ── Key serialization ────────────────────────────────────────────────────────

func encodeClassicalPriv(priv, pub *big.Int, nbits int, algo string) (string, error) {
	a, err := derIntBig(priv, nbits/8)
	if err != nil {
		return "", err
	}
	b, err := derIntBig(pub, nbits/8)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(nbits)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(a, b, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(algoToPrivLbl[algo], seq), nil
}

func encodeClassicalPub(pub *big.Int, nbits int, algo string) (string, error) {
	b, err := derIntBig(pub, nbits/8)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(nbits)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(b, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(algoToPubLbl[algo], seq), nil
}

func encodeRNLPriv(s, mBlind []int, n int, nA []byte) (string, error) {
	sDer, err := DerIntEnc(packPoly(s, 4))
	if err != nil {
		return "", err
	}
	mDer, err := DerIntEnc(packPoly(mBlind, 4))
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	if nA == nil {
		seq, err := DerSeqEnc(sDer, mDer, nn)
		if err != nil {
			return "", err
		}
		return PemWrap(lblHkexRNLPriv, seq), nil
	}
	naDer, err := DerIntEnc(nA)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(sDer, mDer, nn, naDer)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHkexRNLPriv, seq), nil
}

func encodeRNLPub(C, mBlind []int, n int, nA []byte) (string, error) {
	cDer, err := DerIntEnc(packPoly(C, 2))
	if err != nil {
		return "", err
	}
	mDer, err := DerIntEnc(packPoly(mBlind, 4))
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	if nA == nil {
		seq, err := DerSeqEnc(cDer, mDer, nn)
		if err != nil {
			return "", err
		}
		return PemWrap(lblHkexRNLPub, seq), nil
	}
	naDer, err := DerIntEnc(nA)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(cDer, mDer, nn, naDer)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHkexRNLPub, seq), nil
}

func encodeSternPriv(e, seed *BitArray, n int, algo string) (string, error) {
	a, err := derIntBig(e.BigInt(), n/8)
	if err != nil {
		return "", err
	}
	b, err := derIntBig(seed.BigInt(), n/8)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(a, b, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(algoToPrivLbl[algo], seq), nil
}

func encodeSternPub(syn *big.Int, seed *BitArray, n int, algo string) (string, error) {
	a, err := derIntBig(syn, n/8)
	if err != nil {
		return "", err
	}
	b, err := derIntBig(seed.BigInt(), n/8)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(a, b, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(algoToPubLbl[algo], seq), nil
}

func encodeSessionKey(key *BitArray, nbits int) (string, error) {
	// Minimum byte width matching Python: max(1, (bit_length+7)//8)
	nb := (key.BigInt().BitLen() + 7) / 8
	if nb < 1 {
		nb = 1
	}
	a, err := derIntBig(key.BigInt(), nb)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(nbits)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(a, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblSession, seq), nil
}

// encodeRNLResponse encodes Bob's HKEX-RNL step-1 response.
// hint is Go's native packed hint (2-bit per coeff).
// Bytes are reversed before DER encoding to match Python's big-endian convention.
// nB is Bob's 32-byte contributory nonce; pass nil to omit (old format).
func encodeRNLResponse(K_B *BitArray, C_B []int, hint []byte, n int, nB []byte) (string, error) {
	// K_B: minimum-width big-endian encoding
	nb := (K_B.BigInt().BitLen() + 7) / 8
	if nb < 1 {
		nb = 1
	}
	kDer, err := derIntBig(K_B.BigInt(), nb)
	if err != nil {
		return "", err
	}

	cDer, err := DerIntEnc(packPoly(C_B, 2))
	if err != nil {
		return "", err
	}

	// Reverse hint bytes: Go LSB-first → Python/DER big-endian
	hintRev := make([]byte, len(hint))
	for i, j := 0, len(hint)-1; i <= j; i, j = i+1, j-1 {
		hintRev[i], hintRev[j] = hint[j], hint[i]
	}
	hDer, err := DerIntEnc(hintRev)
	if err != nil {
		return "", err
	}

	// n and hint_len: n/2, the coefficients the hint covers, as the other three
	// CLIs and encodeHybridResponse write (this wrote n until TODO #373).
	nDer, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	hlDer, err := derIntSmall(n / 2)
	if err != nil {
		return "", err
	}

	if nB == nil {
		seq, err := DerSeqEnc(kDer, cDer, hDer, nDer, hlDer)
		if err != nil {
			return "", err
		}
		return PemWrap(lblRnlResp, seq), nil
	}
	nbDer, err := DerIntEnc(nB)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(kDer, cDer, hDer, nDer, hlDer, nbDer)
	if err != nil {
		return "", err
	}
	return PemWrap(lblRnlResp, seq), nil
}

// padLeftN pads src with leading zero bytes to exactly n bytes.
func padLeftN(src []byte, n int) []byte {
	if len(src) >= n {
		return src[len(src)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(src):], src)
	return out
}

// rnlContributoryKDF derives the final HKEX-RNL session key.
// Returns HFSCX-256(kRaw || nA || nB); nA and nB must each be 32 bytes.
// Pass make([]byte, 32) for zero nonces when interoperating with old peers.
// isSet reports whether the named flag was explicitly given on the command line
// (flag.FlagSet.Visit walks only the flags that were actually set).
// TODO #381: the shape of the argument list, in one rule shared by all four CLIs.
//
//   - `--flag=value` is `--flag value`.  A boolean flag takes no value, so
//     `--aead=false` is refused instead of quietly switching AEAD off.
//   - A value-taking flag needs a value: at the end of the list, or followed by
//     another flag of this subcommand, it is refused.  The flag package would
//     take `--out --algo` as the file name "--algo".
//   - A token that is neither a flag nor a flag's value is refused.  The flag
//     package stops at the first one and the commands never looked at the
//     rest, so `genpkey --algo hpks extra` ran and `genpkey extra --algo hpks`
//     ran WITHOUT its --algo.
//   - Where Python requires --in or --out, so does this CLI (requiredFlags).
//     They used to default to "-", so an omitted --in read stdin and an omitted
//     --out wrote stdout; "-" still means exactly that when given.
//
// The threshold path lists (--commits / --commit / --partials / --partial) are
// removed by filterMultiFlags before this runs (TODO #270).
var requiredFlags = map[string][]string{
	"kex": {"out"}, "dgst": {"in"}, "enc": {"in", "out"}, "dec": {"in", "out"},
	"sign": {"in", "out"}, "verify": {"in"}, "encfile": {"in", "out"},
	"decfile": {"in", "out"}, "fpe": {"in"}, "twk": {"in"},
	"threshold-aggregate": {"in", "out"}, "threshold-respond": {"out"},
	"threshold-combine": {"out"},
}

func flagOf(fs *flag.FlagSet, tok string) (*flag.Flag, string, bool) {
	if len(tok) < 2 || tok[0] != '-' || tok == "--" {
		return nil, "", false
	}
	name := strings.TrimPrefix(strings.TrimPrefix(tok, "-"), "-")
	hasEq := false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, hasEq = name[:k], true
	}
	return fs.Lookup(name), name, hasEq
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

func parseArgs(fs *flag.FlagSet, args []string) {
	cmd := fs.Name()
	for i := 0; i < len(args); i++ {
		f, name, hasEq := flagOf(fs, args[i])
		if f == nil {
			continue // a value, a stray token, or an unknown flag fs.Parse reports
		}
		if isBoolFlag(f) {
			if hasEq {
				fmt.Fprintf(os.Stderr, "%s: --%s takes no value\n", cmd, name)
				os.Exit(2)
			}
			continue
		}
		if hasEq {
			continue
		}
		if i+1 >= len(args) {
			fmt.Fprintf(os.Stderr, "%s: --%s needs a value\n", cmd, name)
			os.Exit(2)
		}
		if g, _, _ := flagOf(fs, args[i+1]); g != nil {
			fmt.Fprintf(os.Stderr, "%s: --%s needs a value\n", cmd, name)
			os.Exit(2)
		}
		i++ // its value
	}
	fs.Parse(args)
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "%s: unexpected argument '%s'\n", cmd, fs.Arg(0))
		os.Exit(2)
	}
	for _, r := range requiredFlags[cmd] {
		if !isSet(fs, r) {
			fmt.Fprintf(os.Stderr, "%s: --%s required\n", cmd, r)
			os.Exit(1)
		}
	}
}

func isSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// rnlKeyBits returns the RAW reconciliation width for an HKEX-RNL ring of
// dimension n (TODO #223).  Reconciliation extracts 2 bits from each of
// keyBits/2 coefficients, so a ring of n coefficients supplies at most 2n key
// bits.  Since TODO #223 the ring dimension (RnlN = 1024) and the key width
// (256) are separate; a small demo/test ring can only supply n raw bits.
//
// This is the width of K_raw — the contributory KDF's input — not the width of
// the session key that comes out of it.  See rnlSessionBits (TODO #228).
func rnlKeyBits(n int) int {
	if n >= 256 {
		return 256
	}
	return n
}

// rnlSessionBits returns the DERIVED session-key width for HKEX-RNL, which is
// always 256 regardless of ring dimension (TODO #228): rnlContributoryKDF
// returns an HFSCX-256 digest, and the ring only bounds how much raw entropy
// feeds into it.  Labelling the session key with rnlKeyBits(n) made Go truncate
// that digest to n bits below n=256 while Python kept all 256, so the two CLIs
// derived different keys from the same handshake.  At n >= 256 the two
// functions coincide, so the deployed n=1024 wire format is unchanged.
//
// n is accepted and ignored so call sites read symmetrically with rnlKeyBits.
// HKEX-GF is genuinely nbits-wide and must not use this.
func rnlSessionBits(n int) int {
	_ = n
	return 256
}

// rnlContributoryKDF derives the HKEX-RNL session key: HFSCX-256(K_raw || nA ||
// nB).  rawBits is the width K_raw is serialised at (rnlKeyBits); the result is
// always rnlSessionBits wide, since it is a whole HFSCX-256 digest.
//
// TODO #261 (v6.1.0): the body moved to the suite as RnlContributoryKdf, where
// C and Java had always kept theirs.  This wrapper stays only to keep the call
// sites reading in rnlKeyBits/rnlSessionBits terms; it must not grow a body
// again.  The width assertion below is what makes the delegation safe: the
// suite returns a whole 256-bit digest, which is rnlSessionBits by definition.
func rnlContributoryKDF(kRaw *BitArray, rawBits int, nA, nB []byte) *BitArray {
	k := RnlContributoryKdf(kRaw, rawBits, nA, nB)
	if k.Size() != rnlSessionBits(rawBits) {
		panic("rnlContributoryKDF: suite KDF width != rnlSessionBits")
	}
	return k
}

// ── TODO #167: hybrid HKEX-RNL + HPKE-Stern-KEM combiner (port of TODO #162) ─

// rnlHintToBytes unpacks Go's native 2-bit-per-coefficient hint packing
// (RnlHint/RnlAgree's []byte return) into one raw byte per coefficient
// (value 0..3), matching Python's `hint` list representation used as the
// combiner's `hint_used` transcript input (n/2 coefficients).
func rnlHintToBytes(hint []byte, n int) []byte {
	half := n / 2
	out := make([]byte, half)
	for i := 0; i < half; i++ {
		out[i] = (hint[i/4] >> uint((i%4)*2)) & 3
	}
	return out
}

// hybridRnlSternCombine implements the SP 800-227 §4.6-style IND-CCA-preserving
// key combiner from TODO #162/§11.16, ported bit-for-bit from Python's
// _hybrid_rnl_stern_combine:
//
//	K = HFSCX-256-DS(0x05, K1 || K2 || C_A || m_A || C_B || hint || h_pub || syn ||
//	                  "HERRADURA-HYBRID-RNL-STERN-v1")
func hybridRnlSternCombine(K1 *big.Int, K2 []byte, C_A, m_A, C_B []int, hintUsed []byte,
	hPub, syn *big.Int, n, rQC int) *big.Int {
	// K1 is serialised at the KEY width, not the ring dimension. Those were the
	// same number until TODO #223 moved the ring to 1024 while the derived key
	// stayed 256 bits; using n here writes 128 zero-padded bytes where C's
	// combiner writes KEYBYTES (32), so the two sides derive different keys.
	K1Bytes := padLeftN(K1.Bytes(), rnlSessionBits(n)/8)
	C_A_packed := packPoly(C_A, 2)
	m_A_packed := packPoly(m_A, 4)
	C_B_packed := packPoly(C_B, 2)
	rb := (rQC + 7) / 8
	hPubBytes := padLeftN(hPub.Bytes(), rb)
	synBytes := padLeftN(syn.Bytes(), rb)

	data := make([]byte, 0, len(K1Bytes)+len(K2)+len(C_A_packed)+len(m_A_packed)+
		len(C_B_packed)+len(hintUsed)+len(hPubBytes)+len(synBytes)+32)
	data = append(data, K1Bytes...)
	data = append(data, K2...)
	data = append(data, C_A_packed...)
	data = append(data, m_A_packed...)
	data = append(data, C_B_packed...)
	data = append(data, hintUsed...)
	data = append(data, hPubBytes...)
	data = append(data, synBytes...)
	data = append(data, []byte("HERRADURA-HYBRID-RNL-STERN-v1")...)

	digest := Hfscx256DS(0x05, data, nil)
	return new(big.Int).SetBytes(digest)
}

// encodeHybridResponse encodes Bob's hybrid-rnl-stern response:
// (K, C_B, hint, n, hint_len, n_B, syn, r) — matching Python's
// _encode_hybrid_response field order exactly.
func encodeHybridResponse(K *big.Int, C_B []int, hintUsedLen int, hint []byte, n int,
	nB []byte, syn *big.Int, rQC int) (string, error) {
	Knb := (K.BitLen() + 7) / 8
	if Knb < 1 {
		Knb = 1
	}
	kDer, err := derIntBig(K, Knb)
	if err != nil {
		return "", err
	}
	cDer, err := DerIntEnc(packPoly(C_B, 2))
	if err != nil {
		return "", err
	}

	// Reverse hint bytes: Go LSB-first → Python/DER big-endian (matches
	// encodeRNLResponse's convention).
	hintRev := make([]byte, len(hint))
	for i, j := 0, len(hint)-1; i <= j; i, j = i+1, j-1 {
		hintRev[i], hintRev[j] = hint[j], hint[i]
	}
	hDer, err := DerIntEnc(hintRev)
	if err != nil {
		return "", err
	}
	nDer, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	hlDer, err := derIntSmall(hintUsedLen)
	if err != nil {
		return "", err
	}
	nbDer, err := DerIntEnc(nB)
	if err != nil {
		return "", err
	}
	rb := (rQC + 7) / 8
	synDer, err := derIntBig(syn, rb)
	if err != nil {
		return "", err
	}
	rDer, err := derIntSmall(rQC)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(kDer, cDer, hDer, nDer, hlDer, nbDer, synDer, rDer)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHybridResp, seq), nil
}

// decodeHybridResponse returns (K, C_B, hintPacked (Go's native 2-bit-per-
// coefficient packing, suitable as RnlAgree's hintIn), n, nB, syn, rQC) from
// a HYBRID-RNL-STERN RESPONSE PEM's parsed DER ints. Use rnlHintToBytes on
// the returned hintPacked to get the combiner's raw per-coefficient bytes.
func decodeHybridResponse(ints [][]byte) (K *big.Int, C_B []int, hintPacked []byte,
	n int, nB []byte, syn *big.Int, rQC int) {
	K = new(big.Int).SetBytes(ints[0])
	n = rnlWireN(ints[3], "kex hybrid-rnl-stern")

	C_B = unpackPolyRaw(ints[1], n, 2)

	// Undo the encode-time byte reversal to recover Go's native packed hint.
	hintN := n / 8
	hintRaw := ints[2]
	hintBuf := make([]byte, hintN)
	if len(hintRaw) > hintN {
		hintRaw = hintRaw[len(hintRaw)-hintN:]
	}
	copy(hintBuf[hintN-len(hintRaw):], hintRaw)
	for i, j := 0, hintN-1; i < j; i, j = i+1, j-1 {
		hintBuf[i], hintBuf[j] = hintBuf[j], hintBuf[i]
	}

	nB = padLeftN(ints[5], 32)
	rQC = bounded(wireInt(ints[7], "QC-MDPC r", "kex hybrid-rnl-stern"), QcMdpcR, QcMdpcR,
		"QC-MDPC r", "kex hybrid-rnl-stern")
	rb := (rQC + 7) / 8
	syn = new(big.Int).SetBytes(padLeftN(ints[6], rb))
	return K, C_B, hintBuf, n, nB, syn, rQC
}

// ── HPKS-WOTS-F one-time signature helpers (TODO #120) ───────────────────────
//
// One-time use is enforced via a `<key>.idx` state file (0 = unused, 1 = burned).
// A WOTS public key / signature is WotsL chain values, serialised as a single
// (WotsL * 32)-byte DER INTEGER blob.

func wotsIdxPath(keyPath string) string { return keyPath + ".idx" }

func wotsIsUsed(keyPath string) bool {
	b, err := os.ReadFile(wotsIdxPath(keyPath))
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(b))
	return v != "" && v != "0"
}

func wotsWriteIdx(keyPath string, val int) {
	_ = os.WriteFile(wotsIdxPath(keyPath), []byte(fmt.Sprintf("%d\n", val)), 0644)
}

func wotsBlobPack(vals [WotsL]*BitArray) []byte {
	blob := make([]byte, WotsL*32)
	for i := 0; i < WotsL; i++ {
		fillBA(blob[i*32 : (i+1)*32], vals[i])
	}
	return blob
}

func wotsBlobUnpack(v []byte) [WotsL]*BitArray {
	blob := make([]byte, WotsL*32)
	if len(v) > len(blob) {
		v = v[len(v)-len(blob):]
	}
	copy(blob[len(blob)-len(v):], v)
	var out [WotsL]*BitArray
	for i := 0; i < WotsL; i++ {
		out[i] = NewBitArray(256, new(big.Int).SetBytes(blob[i*32:(i+1)*32]))
	}
	return out
}

func encodeWotsBlobPEM(vals [WotsL]*BitArray, label string) string {
	blob := wotsBlobPack(vals)
	bd, _ := derIntBig(new(big.Int).SetBytes(blob), len(blob))
	ed, _ := derIntSmall(WotsL)
	seq, _ := DerSeqEnc(bd, ed)
	return PemWrap(label, seq)
}

// ── HPKS-XMSS-F helpers (TODO #208) ───────────────────────────────────────────
//
// Leaf-index one-time-use state is tracked in a `<key>.idx` sidecar file
// (0-based next-unused-leaf), reusing the same convention as HPKS-WOTS-F's
// 0/1 burned flag (wotsIdxPath above).

func xmssReadIdx(keyPath string) int {
	b, err := os.ReadFile(wotsIdxPath(keyPath))
	if err != nil {
		return 0
	}
	v, cerr := strconv.Atoi(strings.TrimSpace(string(b)))
	if cerr != nil || v < 0 {
		return 0
	}
	return v
}

func xmssWriteIdx(keyPath string, val int) {
	_ = os.WriteFile(wotsIdxPath(keyPath), []byte(fmt.Sprintf("%d\n", val)), 0644)
}

// alignBlob right-aligns v into a dst_len-byte slice (generic version of
// wotsBlobUnpack's alignment, for arbitrary blob sizes).
func alignBlob(v []byte, dstLen int) []byte {
	blob := make([]byte, dstLen)
	if len(v) > dstLen {
		v = v[len(v)-dstLen:]
	}
	copy(blob[dstLen-len(v):], v)
	return blob
}

// ── HPKS-Stern-Ring signature helpers (TODO #121) ────────────────────────────
//
// Wire format matches the Python/C CLIs: SEQ(k, rounds, n, blob) where blob is a
// member-major / round-major flat layout of c0||c1||c2||b(1 byte)||respA||respB
// (each n-bit value = n/8 bytes) per (member, round).

func loadRingPubkeys(ringArg string) ([]RingKeypair, int) {
	paths := strings.Split(ringArg, ",")
	var ring []RingKeypair
	ringN := -1
	for _, p := range paths {
		if p == "" {
			continue
		}
		label, ints, err := readPEMInts(p)
		if err != nil {
			die("hpks-ring", err)
		}
		if label != lblHpksSternPub {
			fmt.Fprintf(os.Stderr, "hpks-ring: ring member %q is %q, expected hpks-stern public key\n", p, label)
			os.Exit(1)
		}
		n := sternWireN(ints[2], "hpks-ring")
		if ringN < 0 {
			ringN = n
		} else if n != ringN {
			fmt.Fprintln(os.Stderr, "hpks-ring: all ring members must share the same n")
			os.Exit(1)
		}
		ring = append(ring, RingKeypair{
			Seed:     NewBitArray(n, new(big.Int).SetBytes(ints[1])),
			Syndrome: new(big.Int).SetBytes(ints[0]),
		})
	}
	if len(ring) < 2 {
		fmt.Fprintln(os.Stderr, "hpks-ring: --ring needs at least 2 member public keys")
		os.Exit(1)
	}
	return ring, ringN
}

func encodeRingSig(sig *SternRingSig, n int) string {
	nb := n / 8
	blob := make([]byte, 0, sig.K*sig.Rounds*(5*nb+1))
	put := func(ba *BitArray) {
		b := make([]byte, nb)
		fillBA(b, ba)
		blob = append(blob, b...)
	}
	for i := 0; i < sig.K; i++ {
		for r := 0; r < sig.Rounds; r++ {
			rd := sig.Members[i].Rounds[r]
			put(rd.C0)
			put(rd.C1)
			put(rd.C2)
			blob = append(blob, byte(rd.B))
			put(rd.RespA)
			put(rd.RespB)
		}
	}
	kd, _ := derIntSmall(sig.K)
	rdd, _ := derIntSmall(sig.Rounds)
	nd, _ := derIntSmall(n)
	bd, _ := derIntBig(new(big.Int).SetBytes(blob), len(blob))
	seq, _ := DerSeqEnc(kd, rdd, nd, bd)
	return PemWrap(lblRingSig, seq)
}

func decodeRingSig(path string) (*SternRingSig, int) {
	label, ints, err := readPEMInts(path)
	if err != nil {
		die("verify", err)
	}
	if label != lblRingSig {
		fmt.Fprintf(os.Stderr, "verify: expected HPKS-RING SIGNATURE PEM, got %q\n", label)
		os.Exit(1)
	}
	// Bounded before use: k, rounds and n each multiply into the blob length
	// below, and verify's own k/n cross-checks only run after this returns.
	k := bounded(wireInt(ints[0], "ring member count", "verify"), 2, ringMaxK,
		"ring member count", "verify")
	rounds := bounded(wireInt(ints[1], "round count", "verify"), 1, SdfMaxRounds,
		"round count", "verify")
	n := boundedN(wireInt(ints[2], "n", "verify"), "verify")
	nb := n / 8
	entry := 5*nb + 1
	blen := k * rounds * entry
	// A payload longer than (k, rounds, n) describe is a mismatch, not
	// something to truncate; shorter is legal (DER strips leading zero bytes)
	// and FillBytes zero-pads it.
	if len(ints[3]) > blen {
		fmt.Fprintf(os.Stderr, "verify: HPKS-RING signature payload is %d bytes, "+
			"but k=%d rounds=%d n=%d describe %d\n", len(ints[3]), k, rounds, n, blen)
		os.Exit(1)
	}
	blob := make([]byte, blen)
	new(big.Int).SetBytes(ints[3]).FillBytes(blob)

	sig := &SternRingSig{K: k, Rounds: rounds, Members: make([]SternSig, k)}
	off := 0
	take := func() *BitArray {
		v := NewBitArray(n, new(big.Int).SetBytes(blob[off:off+nb]))
		off += nb
		return v
	}
	for i := 0; i < k; i++ {
		sig.Members[i].Rounds = make([]SternRound, rounds)
		for r := 0; r < rounds; r++ {
			c0 := take()
			c1 := take()
			c2 := take()
			b := int(blob[off])
			off++
			ra := take()
			rb := take()
			sig.Members[i].Rounds[r] = SternRound{C0: c0, C1: c1, C2: c2, B: b, RespA: ra, RespB: rb}
		}
	}
	return sig, n
}

// ── genpkey ──────────────────────────────────────────────────────────────────

// genpkeyDefaultBits is genpkey's --bits default.  An algorithm with its own
// natural width (hpks-zkp-nl, TODO #281) tests isSet(fs, "bits") instead of
// comparing against this value, so an explicit --bits 256 is not "unset" (#374).
const genpkeyDefaultBits = 256

// paramSet is one row of genpkey's key parameter-set table (TODO #379); the
// rows are generated into paramSets by spec/generate_spec.py.
type paramSet struct {
	algo      string
	bits      int // -1: no --bits value names this row
	level     string
	isDefault bool
	status    string
	security  string
	ports     string // the CLIs that run this row today
	withdrawn string
}

func strIn(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// resolveKeyParams resolves genpkey's --bits / --level against paramSets.  It
// returns the row's bits (-1 for a row with no width), 0 when the algorithm has
// fixed parameters and neither flag was given, or -2 when --bits goes to the
// algorithm's own rule (hpks-zkp-nl).  Every refusal happens here, before any
// key is generated, with the message the other three CLIs print.
func resolveKeyParams(algo string, bitsSet bool, bitsS string, levelSet bool, levelS string) int {
	fail := func(f string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, f+"\n", a...)
		os.Exit(1)
	}
	if strIn(paramFixed, algo) {
		if bitsSet || levelSet {
			fail("genpkey: --algo %s has fixed parameters; --bits and --level do not apply", algo)
		}
		return 0
	}
	if bitsSet && levelSet {
		fail("genpkey: give --bits or --level, not both")
	}
	var rows []paramSet
	for _, r := range paramSets {
		if r.algo == algo {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return 0
	}
	var row paramSet
	found := false
	switch {
	case levelSet:
		if !strIn(paramLevels, levelS) {
			fail("genpkey: --level must be one of %s, got '%s'", strings.Join(paramLevels, ", "), levelS)
		}
		for _, r := range rows {
			if r.level == levelS {
				row, found = r, true
			}
		}
		if !found {
			var avail []string
			for _, l := range paramLevels {
				for _, r := range rows {
					if r.level == l {
						avail = append(avail, l)
						break
					}
				}
			}
			msg := fmt.Sprintf("genpkey: --level %s is not available for --algo %s (available: %s)",
				levelS, algo, strings.Join(avail, ", "))
			if note, ok := paramLevelNotes[algo]; ok {
				msg += "; " + note
			}
			fail("%s", msg)
		}
	case bitsSet:
		if strIn(paramOwnBits, algo) {
			return -2
		}
		var listed []string
		firstLevel := ""
		for _, r := range rows {
			if r.bits > 0 && r.withdrawn == "" {
				listed = append(listed, strconv.Itoa(r.bits))
			}
			if firstLevel == "" && r.level != "" {
				firstLevel = r.level
			}
		}
		if len(listed) == 0 {
			fail("genpkey: --bits does not apply to --algo %s (use --level %s)", algo, firstLevel)
		}
		for _, r := range rows {
			if r.bits > 0 && strconv.Itoa(r.bits) == bitsS {
				row, found = r, true
			}
		}
		if !found {
			fail("genpkey: --bits must be one of %s for --algo %s, got '%s'",
				strings.Join(listed, ", "), algo, bitsS)
		}
		if row.withdrawn != "" {
			fail("genpkey: --bits %d for --algo %s is withdrawn: %s", row.bits, algo, row.withdrawn)
		}
	default:
		for _, r := range rows {
			if r.isDefault {
				row = r
			}
		}
	}
	if !strIn(strings.Fields(row.ports), "go") {
		var here []string
		for _, r := range rows {
			if r.bits > 0 && strIn(strings.Fields(r.ports), "go") {
				here = append(here, strconv.Itoa(r.bits))
			}
		}
		fail("genpkey: --algo %s at %d bits is not yet supported by this CLI (supported here: %s)",
			algo, row.bits, strings.Join(here, ", "))
	}
	dflt := 0
	for _, r := range rows {
		if r.isDefault {
			dflt = r.bits
		}
	}
	if row.bits > 0 && row.bits < dflt {
		fmt.Fprintf(os.Stderr, "WARNING: --algo %s at %d bits is a demonstration width (estimated security: %s)\n",
			algo, row.bits, row.security)
	}
	return row.bits
}

func cmdGenpkey(args []string) {
	fs := flag.NewFlagSet("genpkey", flag.ExitOnError)
	algo := fs.String("algo", "", "Algorithm (hkex-gf|hkex-rnl|hpks|hpks-nl|hpke|hpke-nl|hpke-nl3|hpks-stern|hpke-stern|hcred|hpks-wots|hpks-xmss)")
	bitsS := fs.String("bits", "", "Key size in bits: key width, HKEX-RNL ring dimension or Stern-F N, from the algorithm's listed values (TODO #379); prefer --level")
	levelS := fs.String("level", "", "Parameter set by the strength it is sized for: demo, 128 (192, 256 reserved)")
	out  := fs.String("out", "-", "Output path (- = stdout)")
	xmssHeightS := fs.String("xmss-height", "10", "hpks-xmss: tree height (2^H leaves, 1 to 20)")
	passphrase := fs.String("passphrase", "", "Encrypt the exported private key under this passphrase (TODO #268)")
	kdfIterationsS := fs.String("kdf-iterations", strconv.Itoa(pbkdf2IterDemo), "PBKDF2-HFSCX256 iterations for --passphrase (1 to 100000000)")
	parseArgs(fs, args)
	// TODO #380: parsed strictly and range-checked before any key is generated.
	xmssHeight := numFlag(fs, "xmss-height", xmssHeightS, 1, 20, 10)
	kdfIterations := numFlag(fs, "kdf-iterations", kdfIterationsS, 1, pbkdf2IterMax, pbkdf2IterDemo)

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "genpkey: --algo required")
		os.Exit(1)
	}
	// TODO #376: a GIVEN passphrase must be non-empty.  Before #376 this read
	// --passphrase '' as no passphrase and wrote the key in the clear, and
	// accepted --kdf-iterations alone and ignored it.  Both are refused
	// before any key is generated.
	if isSet(fs, "passphrase") && *passphrase == "" {
		fmt.Fprintln(os.Stderr, "genpkey: --passphrase must not be empty")
		os.Exit(1)
	}
	if isSet(fs, "kdf-iterations") && !isSet(fs, "passphrase") {
		fmt.Fprintln(os.Stderr, "genpkey: --kdf-iterations requires --passphrase")
		os.Exit(1)
	}

	// TODO #379: every width comes from the parameter-set table.
	n := resolveKeyParams(*algo, isSet(fs, "bits"), *bitsS, isSet(fs, "level"), *levelS)

	var pem string
	var err error

	switch {
	case classicalAlgos[*algo]:
		// TODO #379: an unlisted --bits used to normalise silently to 256;
		// resolveKeyParams now refuses it by name.
		a := NewRandBitArray(n)
		C := GfPow(GfGenBA(n), a)
		pem, err = encodeClassicalPriv(a.BigInt(), C.BigInt(), n, *algo)

	case *algo == "hkex-rnl":
		// Ring dimension is independent of the key width (TODO #223); the
		// table's rows choose it (TODO #379).
		mBase  := RnlMPoly(n)
		aRand  := RnlRandPoly(n, RnlQ)
		mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
		s, _   := RnlKeygen(mBlind, n, RnlQ, RnlP)
		nA     := NewRandBitArray(256).Bytes()  // Alice's contributory nonce (32 bytes)
		pem, err = encodeRNLPriv(s, mBlind, n, nA)

	case sternAlgos[*algo]:
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		seed, e, _ := SternFKeygen(n)
		pem, err = encodeSternPriv(e, seed, n, *algo)

	case *algo == "hpke-stern-kem":
		sup0, sup1, h0, h1, _ := QcMdpcKeygen(nil)
		pem, err = encodeKemPriv(sup0, sup1, h0, h1)

	case *algo == "hcred":
		fmt.Fprintln(os.Stderr, "WARNING: HCRED is a demonstration parameter set. Do not use for production.")
		mBase := RnlMPoly(n)
		aRand := RnlRandPoly(n, RnlQ)
		mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
		s, C, eInt := HcredUserKeygen(mBlind, n)
		seedH := NewRandBitArray(n)
		syndr := HcredSyndrome(seedH, eInt, n)
		pem = encodeHcredPriv(s, C, mBlind, seedH, syndr, n)

	case *algo == "hpks-zkp-nl":
		// n comes from --bits, exactly as in the Python and Java CLIs (TODO
		// #281): an omitted --bits means ZkpNlDefaultN, because at R = 219 a ZKBoo proof is already
		// ~35 KB at n = 8, so a wider n is a deliberate choice.  An
		// out-of-range value is rejected by name rather than clamped: this
		// branch passed ZkpNlDefaultN as a literal and dropped the flag
		// silently until v6.7.0, so a caller asking for 64 got 8 and no error.
		// TODO #374: "unset" means the flag was not given, not that it equals
		// its default -- an explicit --bits 256 used to read as unset and wrote
		// an n = 8 key; it now fails the range check below.
		zkpN := ZkpNlDefaultN
		if n == -2 { // TODO #379: --bits is a string now, read as decimal digits
			v, perr := strconv.Atoi(*bitsS)
			ok := perr == nil && *bitsS != ""
			for _, ch := range *bitsS {
				ok = ok && ch >= '0' && ch <= '9'
			}
			if !ok || v <= 0 || v%2 != 0 || v > ZkpNlMaxN {
				fmt.Fprintf(os.Stderr,
					"genpkey hpks-zkp-nl: --bits must be a positive even integer <= %d, got %s\n",
					ZkpNlMaxN, *bitsS)
				os.Exit(1)
			}
			zkpN = v
		}
		A, B, y, kerr := ZkpNlKeygen(zkpN)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, "genpkey:", kerr)
			os.Exit(1)
		}
		pem = encodeZkpNlPriv(A, B, y, zkpN)

	case *algo == "oprf":
		k, kerr := OprfKeygen(n)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, "genpkey:", kerr)
			os.Exit(1)
		}
		kDer, e1 := derIntBig(k, n/8)
		nDer, e2 := derIntSmall(n)
		if e1 != nil || e2 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER encode error")
			os.Exit(1)
		}
		seq, e3 := DerSeqEnc(kDer, nDer)
		if e3 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER seq error")
			os.Exit(1)
		}
		pem = PemWrap(lblOprfPriv, seq)

	case *algo == "hpks-wots":
		seed := NewRandBitArray(256).Bytes() // 32-byte master seed
		sd, e1 := derIntBig(new(big.Int).SetBytes(seed), 32)
		ld, e2 := derIntSmall(0) // leaf_idx = 0
		if e1 != nil || e2 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER encode error")
			os.Exit(1)
		}
		seq, e3 := DerSeqEnc(sd, ld)
		if e3 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER seq error")
			os.Exit(1)
		}
		pem = PemWrap(lblHpksWotsPriv, seq)
		if *out != "-" {
			wotsWriteIdx(*out, 0)
		}
		fmt.Fprintln(os.Stderr, "HPKS-WOTS: ONE-TIME key — it may sign exactly one message.")

	case *algo == "hpks-xmss":
		h := xmssHeight
		fmt.Fprintf(os.Stderr, "Generating XMSS tree (h=%d, %d leaves) — may take a moment...\n",
			h, 1<<uint(h))
		seed := NewRandBitArray(256).Bytes()
		kp := HpksXmssKeygen(seed, h)
		blob := make([]byte, 0, len(kp.LeafHashes)*32)
		for _, lh := range kp.LeafHashes {
			blob = append(blob, lh...)
		}
		sd, e1 := derIntBig(new(big.Int).SetBytes(seed), 32)
		hd, e2 := derIntSmall(h)
		id, e3 := derIntSmall(0) // next_idx = 0
		bd, e4 := derIntBig(new(big.Int).SetBytes(blob), len(blob))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER encode error")
			os.Exit(1)
		}
		seq, e5 := DerSeqEnc(sd, hd, id, bd)
		if e5 != nil {
			fmt.Fprintln(os.Stderr, "genpkey: DER seq error")
			os.Exit(1)
		}
		pem = PemWrap(lblHpksXmssPriv, seq)
		if *out != "-" {
			xmssWriteIdx(*out, 0)
		}

	default:
		fmt.Fprintf(os.Stderr, "genpkey: unknown algorithm %q\n", *algo)
		os.Exit(1)
	}

	if err != nil {
		die("genpkey", err)
	}
	// TODO #268.  Wrapping the finished PEM string keeps CLEARTEXT OFF DISK:
	// the plaintext only ever exists in memory.
	if *passphrase != "" {
		pem, err = encryptPEMText(pem, *passphrase, kdfIterations)
		if err != nil {
			die("genpkey", err)
		}
	}
	if err := writeString(*out, pem); err != nil {
		die("genpkey", err)
	}
}

// ── pkey ─────────────────────────────────────────────────────────────────────

func cmdPkey(args []string) {
	fs := flag.NewFlagSet("pkey", flag.ExitOnError)
	in     := fs.String("in", "", "Input private key file")
	pubout := fs.Bool("pubout", false, "Extract public key")
	text   := fs.Bool("text", false, "Print key fields")
	out    := fs.String("out", "-", "Output path")
	decrypt := fs.Bool("decrypt", false, "Decrypt a --passphrase-protected private key PEM (TODO #268)")
	passphrase := fs.String("passphrase", "", "Passphrase for --decrypt")
	parseArgs(fs, args)

	if *in == "" {
		fmt.Fprintln(os.Stderr, "pkey: --in required")
		os.Exit(1)
	}
	// TODO #268: --decrypt reverses genpkey --passphrase, recovering the PEM
	// byte-for-byte so it can be fed to any other subcommand unmodified.  It is
	// its own mode, not a modifier of --pubout/--text, so it is handled before
	// the "specify --pubout or --text" check.
	if *decrypt {
		// TODO #376: '' is a passphrase here, so a key C or Java encrypted
		// under '' before #376 stays readable.
		if !isSet(fs, "passphrase") {
			fmt.Fprintln(os.Stderr, "pkey --decrypt: --passphrase required")
			os.Exit(1)
		}
		plain, derr := decryptPEMFile(*in, *passphrase)
		if derr != nil {
			die("pkey --decrypt", derr)
		}
		if werr := writeString(*out, plain); werr != nil {
			die("pkey", werr)
		}
		return
	}
	if isSet(fs, "passphrase") {
		fmt.Fprintln(os.Stderr, "pkey: --passphrase is only meaningful with --decrypt")
		os.Exit(1)
	}
	if !*pubout && !*text {
		fmt.Fprintln(os.Stderr, "pkey: specify --pubout or --text")
		os.Exit(1)
	}

	// Handle ZKP-NL private key (raw binary PEM — not DER SEQUENCE)
	{
		lbl, lerr := peekPEMLabel(*in)
		if lerr != nil {
			die("pkey", lerr)
		}
		if lbl == lblZkpNlPriv {
			body, rerr := readRawPEM(*in, lblZkpNlPriv)
			if rerr != nil {
				die("pkey", rerr)
			}
			A, B, y, zkpN, derr := decodeZkpNlPriv(body)
			if derr != nil {
				die("pkey", derr)
			}
			if *pubout {
				pemOut := encodeZkpNlPub(B, y, zkpN)
				if werr := writeString(*out, pemOut); werr != nil {
					die("pkey", werr)
				}
			} else {
				fmt.Printf("algorithm : hpks-zkp-nl\n")
				fmt.Printf("n         : %d\n", zkpN)
				nb := (zkpN + 7) / 8
				fmt.Printf("A (priv)  : %0*x\n", nb*2, A)
				fmt.Printf("B (pub)   : %0*x\n", nb*2, B)
				fmt.Printf("y (pub)   : %0*x\n", nb*2, y)
			}
			return
		}
		if lbl == lblHcredPriv {
			body, rerr := readRawPEM(*in, lblHcredPriv)
			if rerr != nil {
				die("pkey", rerr)
			}
			sPoly, cPoly, mPoly, seedH, syndr, hn, derr := decodeHcredPriv(body)
			if derr != nil {
				die("pkey", derr)
			}
			if *pubout {
				pemOut := encodeHcredPub(cPoly, mPoly, seedH, syndr, hn)
				if werr := writeString(*out, pemOut); werr != nil {
					die("pkey", werr)
				}
			} else {
				fmt.Printf("algorithm : hcred\n")
				fmt.Printf("n         : %d\n", hn)
				fmt.Printf("W (weight): %d\n", CountBits(HcredPhi(sPoly)))
			}
			return
		}
	}

	label, ints, err := readPEMInts(*in)
	if err != nil {
		die("pkey", err)
	}
	algo := privToAlgo[label]
	if algo == "" {
		fmt.Fprintf(os.Stderr, "pkey: unrecognised PEM label %q\n", label)
		os.Exit(1)
	}

	if *pubout {
		var pem string

		switch {
		case classicalAlgos[algo]:
			n := gfWidth(bytesToInt(ints[2]), "pkey")
			pub := new(big.Int).SetBytes(ints[1])
			pem, err = encodeClassicalPub(pub, n, algo)

		case algo == "hkex-rnl":
			n := rnlWireN(ints[2], "pkey")
			s      := unpackPolyRaw(ints[0], n, 4)
			mBlind := unpackPolyRaw(ints[1], n, 4)
			ms     := RnlPolyMul(mBlind, s, RnlQ, n)
			C      := RnlRound(ms, RnlQ, RnlP)
			var nA []byte
			if len(ints) >= 4 {
				nA = padLeftN(ints[3], 32)
			}
			pem, err = encodeRNLPub(C, mBlind, n, nA)

		case sternAlgos[algo]:
			n    := sternWireN(ints[2], "pkey")
			e    := NewBitArray(n, new(big.Int).SetBytes(ints[0]))
			seed := NewBitArray(n, new(big.Int).SetBytes(ints[1]))
			syn  := SternSyndrome(seed, e)
			pem, err = encodeSternPub(syn, seed, n, algo)

		case algo == "hpks-wots":
			seed := fitBytes(ints[0], 32, "WOTS seed", "pkey")
			var leafIdx uint32
			if len(ints) >= 2 {
				leafIdx = uint32(wireInt(ints[1], "WOTS leaf index", "pkey"))
			}
			_, pk := HpksWotsKeygen(seed, leafIdx)
			pem = encodeWotsBlobPEM(pk, lblHpksWotsPub)

		case algo == "hpks-xmss":
			// h sizes `1 << h` leaves and the 32-bytes-per-leaf blob behind them.
			h := bounded(wireInt(ints[1], "XMSS height", "pkey"), 1, xmssMaxH,
				"XMSS height", "pkey")
			numLeaves := 1 << uint(h)
			blob := alignBlob(ints[3], numLeaves*32)
			leafHashes := make([][]byte, numLeaves)
			for i := 0; i < numLeaves; i++ {
				leafHashes[i] = blob[i*32 : (i+1)*32]
			}
			root := HaccumRoot(leafHashes)
			rd, e1 := derIntBig(new(big.Int).SetBytes(root), 32)
			hd, e2 := derIntSmall(h)
			if e1 != nil || e2 != nil {
				fmt.Fprintln(os.Stderr, "pkey: DER encode error")
				os.Exit(1)
			}
			seq, e3 := DerSeqEnc(rd, hd)
			if e3 != nil {
				die("pkey", e3)
			}
			pem = PemWrap(lblHpksXmssPub, seq)

		case algo == "hpke-stern-kem":
			_, _, h0, h1 := decodeKemPriv(ints)
			inv, ok := QcMdpcInv(h0)
			if !ok {
				fmt.Fprintln(os.Stderr, "pkey: h0 not invertible")
				os.Exit(1)
			}
			pem, err = encodeKemPub(QcMdpcMul(h1, inv))

		default:
			// TODO #374: an OPRF server key has no public half; any other
			// label reaching here wrote an empty file and exited 0.
			fmt.Fprintf(os.Stderr, "pkey --pubout: %s has no public key\n", algo)
			os.Exit(1)
		}

		if err != nil {
			die("pkey", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("pkey", err)
		}
		return
	}

	// --text
	switch {
	case classicalAlgos[algo]:
		n    := gfWidth(bytesToInt(ints[2]), "pkey")
		priv := new(big.Int).SetBytes(ints[0])
		pub  := new(big.Int).SetBytes(ints[1])
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("bits      : %d\n", n)
		fmt.Printf("private   : %0*x\n", n/4, priv)
		fmt.Printf("public    : %0*x\n", n/4, pub)

	case algo == "hkex-rnl":
		n      := rnlWireN(ints[2], "pkey")
		s      := unpackPolyRaw(ints[0], n, 4)
		mBlind := unpackPolyRaw(ints[1], n, 4)
		ms     := RnlPolyMul(mBlind, s, RnlQ, n)
		C      := RnlRound(ms, RnlQ, RnlP)
		fmt.Printf("algorithm : hkex-rnl\n")
		fmt.Printf("n         : %d\n", n)
		fmt.Printf("s_packed  : %x\n", packPoly(s, 4))
		fmt.Printf("C_packed  : %x\n", packPoly(C, 2))
		if len(ints) >= 4 {
			fmt.Printf("n_A       : %x\n", padLeftN(ints[3], 32))
		}

	case sternAlgos[algo]:
		n    := sternWireN(ints[2], "pkey")
		eBig := new(big.Int).SetBytes(ints[0])
		sBig := new(big.Int).SetBytes(ints[1])
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("n         : %d\n", n)
		fmt.Printf("e_int     : %0*x\n", n/4, eBig)
		fmt.Printf("seed      : %0*x\n", n/4, sBig)

	// TODO #374: the four cases below were missing, so --text printed nothing
	// and exited 0 for these keys; an unhandled label now fails.
	case algo == "hpke-stern-kem":
		decodeKemPriv(ints) // validates the key
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("r         : %d\n", QcMdpcR)
		fmt.Printf("d         : %d\n", QcMdpcD)

	case algo == "hpks-wots":
		fitBytes(ints[0], 32, "WOTS seed", "pkey")
		var leafIdx uint32
		if len(ints) >= 2 {
			leafIdx = uint32(wireInt(ints[1], "WOTS leaf index", "pkey"))
		}
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("leaf_idx  : %d\n", leafIdx)

	case algo == "hpks-xmss":
		h := bounded(wireInt(ints[1], "XMSS height", "pkey"), 1, xmssMaxH,
			"XMSS height", "pkey")
		numLeaves := 1 << uint(h)
		blob := alignBlob(ints[3], numLeaves*32)
		leafHashes := make([][]byte, numLeaves)
		for i := 0; i < numLeaves; i++ {
			leafHashes[i] = blob[i*32 : (i+1)*32]
		}
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("h         : %d (%d leaves)\n", h, numLeaves)
		fmt.Printf("root      : %x\n", HaccumRoot(leafHashes))

	case algo == "oprf":
		fitBytes(ints[0], 32, "OPRF key", "pkey")
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("bits      : %d\n", genpkeyDefaultBits)

	default:
		fmt.Fprintf(os.Stderr, "pkey --text: no text form for %s\n", algo)
		os.Exit(1)
	}
}

// ── kex ──────────────────────────────────────────────────────────────────────

func cmdKex(args []string) {
	fs  := flag.NewFlagSet("kex", flag.ExitOnError)
	algo := fs.String("algo", "", "Algorithm (hkex-gf|hkex-rnl|hybrid-rnl-stern)")
	our  := fs.String("our", "", "Our private key file")
	their := fs.String("their", "", "Their public key or response file")
	out  := fs.String("out", "-", "Output path")
	kdf  := fs.String("kdf", "", "KDF applied to raw shared secret (none|hfscx-256; both sides must match)")
	theirKem := fs.String("their-kem", "", "hybrid-rnl-stern: Alice's HPKE-Stern-KEM public key (Bob step)")
	ourKem   := fs.String("our-kem", "", "hybrid-rnl-stern: Alice's own HPKE-Stern-KEM private key (Alice step)")
	parseArgs(fs, args)
	checkKeyLabels("kex", fs) // TODO #366

	if *algo == "" || *our == "" || *their == "" {
		fmt.Fprintln(os.Stderr, "kex: --algo, --our, --their required")
		os.Exit(1)
	}
	// TODO #269: `none` is Python's DEFAULT value for this flag and was a hard
	// error here, so a command line copied from the Python CLI's own help text
	// failed against this one. Accept it, and normalise it to the empty string so
	// applyKDF below keeps reading "" as "no post-hash". Anything else is still
	// refused: the value set is {none, hfscx-256}, and `sp800227` (TODO #165) is
	// Python-only and rejected here by name.
	if *kdf == "none" {
		*kdf = ""
	} else if *kdf != "" && *kdf != "hfscx-256" {
		fmt.Fprintf(os.Stderr, "kex: unsupported --kdf value %q (choices: none, hfscx-256)\n", *kdf)
		os.Exit(1)
	}

	// applyKDF returns a new BitArray with HFSCX-256 applied when --kdf is set.
	applyKDF := func(ba *BitArray, n int) *BitArray {
		if *kdf != "hfscx-256" {
			return ba
		}
		digest := Hfscx256(ba.Bytes(), nil)
		return NewBitArray(n, new(big.Int).SetBytes(digest))
	}

	switch *algo {
	case "hkex-gf":
		_, ourInts, err := readPEMInts(*our)
		if err != nil {
			die("kex", err)
		}
		_, theirInts, err := readPEMInts(*their)
		if err != nil {
			die("kex", err)
		}

		n    := gfWidth(bytesToInt(ourInts[2]), "kex")
		priv := NewBitArray(n, new(big.Int).SetBytes(ourInts[0]))
		pub  := NewBitArray(n, new(big.Int).SetBytes(theirInts[0]))
		if !GfPubIsValid(pub) {
			die("kex", errors.New("their public key is the GF(2^n)* identity/zero element (rejected: degenerate key)"))
		}

		skBA := applyKDF(GfPow(pub, priv), n)
		pem, err := encodeSessionKey(skBA, n)
		if err != nil {
			die("kex", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("kex", err)
		}

	case "hkex-rnl":
		theirLabel, theirInts, err := readPEMInts(*their)
		if err != nil {
			die("kex", err)
		}

		switch theirLabel {
		case lblHkexRNLPub:
			// ── Step 1: Bob responds to Alice's public key ──────────────
			_, ourInts, err := readPEMInts(*our)
			if err != nil {
				die("kex", err)
			}
			n   := rnlWireN(ourInts[2], "kex")
			rnlSameRing(n, theirInts[2], "kex")
			s_B := unpackPolyRaw(ourInts[0], n, 4)
			C_A := unpackPolyRaw(theirInts[0], n, 2)
			m_A := unpackPolyRaw(theirInts[1], n, 4)

			// Extract Alice's contributory nonce n_A (field 3 of her public key)
			var n_A []byte
			if len(theirInts) >= 4 {
				n_A = padLeftN(theirInts[3], 32)
			} else {
				n_A = make([]byte, 32)
			}

			if !RnlValidateMBlind(m_A, RnlQ) {
				fmt.Fprintln(os.Stderr, "kex hkex-rnl: peer m_blind failed entropy check — possible substitution attack")
				os.Exit(1)
			}

			// Derive C_B = round_p(m_A * s_B)
			ms  := RnlPolyMul(m_A, s_B, RnlQ, n)
			C_B := RnlRound(ms, RnlQ, RnlP)

			// Compute K_B and reconciliation hint
			if !RnlValidatePub(C_A) {
				die("kex hkex-rnl", errors.New("peer C failed entropy check (rejected: degenerate key)"))
			}
			K_B_raw, hint := RnlAgree(s_B, C_A, RnlQ, RnlP, RnlPP, n, rnlKeyBits(n), nil)

			// Bob's contributory nonce n_B
			n_B := NewRandBitArray(256).Bytes()

			// Contributory KDF: final_key = HFSCX-256(K_B_raw || n_A || n_B)
			K_B := rnlContributoryKDF(K_B_raw, rnlKeyBits(n), n_A, n_B)
			K_B = applyKDF(K_B, rnlSessionBits(n))

			pem, err := encodeRNLResponse(K_B, C_B, hint, n, n_B)
			if err != nil {
				die("kex", err)
			}
			if err := writeString(*out, pem); err != nil {
				die("kex", err)
			}

		case lblRnlResp:
			// ── Step 2: Alice completes the handshake ───────────────────
			_, ourInts, err := readPEMInts(*our)
			if err != nil {
				die("kex", err)
			}
			n   := rnlWireN(ourInts[2], "kex")
			rnlSameRing(n, theirInts[3], "kex")
			s_A := unpackPolyRaw(ourInts[0], n, 4)
			C_B := unpackPolyRaw(theirInts[1], n, 2)

			// Extract Alice's n_A from her private key (field 3)
			var n_A []byte
			if len(ourInts) >= 4 {
				n_A = padLeftN(ourInts[3], 32)
			} else {
				n_A = make([]byte, 32)
			}

			// Extract Bob's n_B from RESPONSE (field 5)
			var n_B []byte
			if len(theirInts) >= 6 {
				n_B = padLeftN(theirInts[5], 32)
			} else {
				n_B = make([]byte, 32)
			}

			// Decode hint: DER bytes are big-endian (Python compat);
			// right-align to n/8 bytes then reverse to Go LSB-first order.
			hintRaw := theirInts[2]
			hintN   := n / 8
			hintBuf := make([]byte, hintN)
			if len(hintRaw) > hintN {
				hintRaw = hintRaw[len(hintRaw)-hintN:]
			}
			copy(hintBuf[hintN-len(hintRaw):], hintRaw)
			for i, j := 0, hintN-1; i < j; i, j = i+1, j-1 {
				hintBuf[i], hintBuf[j] = hintBuf[j], hintBuf[i]
			}

			if !RnlValidatePub(C_B) {
				die("kex hkex-rnl", errors.New("peer C failed entropy check (rejected: degenerate key)"))
			}
			K_A_raw, _ := RnlAgree(s_A, C_B, RnlQ, RnlP, RnlPP, n, rnlKeyBits(n), hintBuf)

			// Contributory KDF: final_key = HFSCX-256(K_A_raw || n_A || n_B)
			K_A := rnlContributoryKDF(K_A_raw, rnlKeyBits(n), n_A, n_B)
			K_A = applyKDF(K_A, rnlSessionBits(n))
			pem, err := encodeSessionKey(K_A, rnlSessionBits(n))
			if err != nil {
				die("kex", err)
			}
			if err := writeString(*out, pem); err != nil {
				die("kex", err)
			}

		default:
			fmt.Fprintf(os.Stderr,
				"kex hkex-rnl: --their must be HKEX-RNL PUBLIC KEY or RESPONSE PEM (got %q)\n",
				theirLabel)
			os.Exit(1)
		}

	case "hybrid-rnl-stern":
		// TODO #167 (port of TODO #162): hybrid HKEX-RNL (lattice) + HPKE-Stern-KEM/
		// QC-MDPC (code-based) combiner, per SP 800-227 §4.6's IND-CCA-preserving shape.
		theirLabel, theirInts, err := readPEMInts(*their)
		if err != nil {
			die("kex", err)
		}

		switch theirLabel {
		case lblHkexRNLPub:
			// ── Step 1: Bob responds — encapsulator for both components ──────
			if *theirKem == "" {
				fmt.Fprintln(os.Stderr, "kex hybrid-rnl-stern: --their-kem required (Alice's HPKE-Stern-KEM public key)")
				os.Exit(1)
			}
			_, ourInts, err := readPEMInts(*our)
			if err != nil {
				die("kex", err)
			}
			n   := rnlWireN(ourInts[2], "kex")
			rnlSameRing(n, theirInts[2], "kex")
			s_B := unpackPolyRaw(ourInts[0], n, 4)
			C_A := unpackPolyRaw(theirInts[0], n, 2)
			m_A := unpackPolyRaw(theirInts[1], n, 4)

			var n_A []byte
			if len(theirInts) >= 4 {
				n_A = padLeftN(theirInts[3], 32)
			} else {
				n_A = make([]byte, 32)
			}

			if !RnlValidateMBlind(m_A, RnlQ) {
				fmt.Fprintln(os.Stderr, "kex hybrid-rnl-stern: peer m_blind failed entropy check — possible substitution attack")
				os.Exit(1)
			}

			_, kemInts, err := readPEMInts(*theirKem)
			if err != nil {
				die("kex", err)
			}
			hPub := decodeKemPub(kemInts)
			rQC  := QcMdpcR

			ms  := RnlPolyMul(m_A, s_B, RnlQ, n)
			C_B := RnlRound(ms, RnlQ, RnlP)

			if !RnlValidatePub(C_A) {
				die("kex hybrid-rnl-stern", errors.New("peer C failed entropy check (rejected: degenerate key)"))
			}
			K1_raw, hint := RnlAgree(s_B, C_A, RnlQ, RnlP, RnlPP, n, rnlKeyBits(n), nil)
			n_B := NewRandBitArray(256).Bytes()
			K1_ba := rnlContributoryKDF(K1_raw, rnlKeyBits(n), n_A, n_B)
			K1_ba = applyKDF(K1_ba, rnlSessionBits(n))

			syn, K2 := QcMdpcEncap(hPub, nil)

			hintUsed := rnlHintToBytes(hint, n)
			K := hybridRnlSternCombine(K1_ba.BigInt(), K2, C_A, m_A, C_B, hintUsed, hPub, syn, n, rQC)

			pem, err := encodeHybridResponse(K, C_B, n/2, hint, n, n_B, syn, rQC)
			if err != nil {
				die("kex", err)
			}
			if err := writeString(*out, pem); err != nil {
				die("kex", err)
			}

		case lblHybridResp:
			// ── Step 2: Alice completes — decapsulator for the KEM component ─
			if *ourKem == "" {
				fmt.Fprintln(os.Stderr, "kex hybrid-rnl-stern: --our-kem required (Alice's own HPKE-Stern-KEM private key)")
				os.Exit(1)
			}
			_, ourInts, err := readPEMInts(*our)
			if err != nil {
				die("kex", err)
			}
			n   := rnlWireN(ourInts[2], "kex")
			s_A := unpackPolyRaw(ourInts[0], n, 4)
			m_A := unpackPolyRaw(ourInts[1], n, 4)

			var n_A []byte
			if len(ourInts) >= 4 {
				n_A = padLeftN(ourInts[3], 32)
			} else {
				n_A = make([]byte, 32)
			}

			_, C_B, hintPacked, nResp, n_B, syn, rQC := decodeHybridResponse(theirInts)
			if n != nResp {
				fmt.Fprintf(os.Stderr, "Ring size mismatch: ours n=%d, response n=%d\n", n, nResp)
				os.Exit(1)
			}

			_, kemInts, err := readPEMInts(*ourKem)
			if err != nil {
				die("kex", err)
			}
			sup0, sup1, h0, h1 := decodeKemPriv(kemInts)
			h0Inv, ok := QcMdpcInv(h0)
			if !ok {
				fmt.Fprintln(os.Stderr, "kex hybrid-rnl-stern: h0 not invertible")
				os.Exit(1)
			}
			hPub := QcMdpcMul(h1, h0Inv)

			ms  := RnlPolyMul(m_A, s_A, RnlQ, n)
			C_A := RnlRound(ms, RnlQ, RnlP)

			if !RnlValidatePub(C_B) {
				die("kex hybrid-rnl-stern", errors.New("peer C failed entropy check (rejected: degenerate key)"))
			}
			K1_raw, _ := RnlAgree(s_A, C_B, RnlQ, RnlP, RnlPP, n, rnlKeyBits(n), hintPacked)
			K1_ba := rnlContributoryKDF(K1_raw, rnlKeyBits(n), n_A, n_B)
			K1_ba = applyKDF(K1_ba, rnlSessionBits(n))

			// Implicit rejection (TODO #235): decapsulation always yields a
			// key.  A DFR event or a corrupt ciphertext now shows up as a
			// session key Bob disagrees with, never as an error here.
			K2 := QcMdpcDecapBgf(syn, sup0, sup1)

			hintUsed := rnlHintToBytes(hintPacked, n)
			K := hybridRnlSternCombine(K1_ba.BigInt(), K2, C_A, m_A, C_B, hintUsed, hPub, syn, n, rQC)

			pem, err := encodeSessionKey(NewBitArray(256, K), rnlSessionBits(n))
			if err != nil {
				die("kex", err)
			}
			if err := writeString(*out, pem); err != nil {
				die("kex", err)
			}

		default:
			fmt.Fprintf(os.Stderr,
				"kex hybrid-rnl-stern: --their must be HKEX-RNL PUBLIC KEY or HYBRID-RNL-STERN RESPONSE PEM (got %q)\n",
				theirLabel)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "kex: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
}

// ── dgst ─────────────────────────────────────────────────────────────────────

func cmdDgst(args []string) {
	fs := flag.NewFlagSet("dgst", flag.ExitOnError)
	algo := fs.String("algo", "hfscx-256", "Digest algorithm")
	in   := fs.String("in", "-", "Input file (- = stdin)")
	out  := fs.String("out", "-", "Output: - = hex to stdout; path = DIGEST PEM")
	parseArgs(fs, args)

	data, err := readFile(*in)
	if err != nil {
		die("dgst", err)
	}

	var digest []byte
	switch *algo {
	case "hfscx-256":
		digest = Hfscx256(data, nil)
	case "hfscx-256-ds":
		digest = Hfscx256DS(0x01, data, nil)
	default:
		fmt.Fprintf(os.Stderr, "dgst: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}

	if *out == "-" {
		fmt.Println(hex.EncodeToString(digest))
		return
	}

	digestBig := new(big.Int).SetBytes(digest)
	a, err := derIntBig(digestBig, 32)
	if err != nil {
		die("dgst", err)
	}
	seq, err := DerSeqEnc(a)
	if err != nil {
		die("dgst", err)
	}
	pem := PemWrap(lblDigest, seq)
	if err := writeString(*out, pem); err != nil {
		die("dgst", err)
	}
}

// ── rand — HDRBG deterministic byte generation (TODO #119) ───────────────────
//
// Deterministic DRBG (NOT an OS entropy source): identical seed +
// personalization + byte count yield byte-identical output across the
// Python, C, and Go CLIs.  State can be checkpointed to a
// 'HERRADURA HDRBG STATE' PEM (state[32], blocks) and resumed.

func encodeHdrbgState(d *HDrbg) string {
	sd, _ := derIntBig(new(big.Int).SetBytes(d.DrbgState()), 32)
	bd, _ := derIntSmall(int(d.Blocks))
	seq, _ := DerSeqEnc(sd, bd)
	return PemWrap(lblHdrbg, seq)
}

func loadHdrbgState(path string) *HDrbg {
	label, ints, err := readPEMInts(path)
	if err != nil {
		die("rand", err)
	}
	if label != lblHdrbg {
		fmt.Fprintf(os.Stderr, "rand: expected HDRBG STATE PEM, got %q\n", label)
		os.Exit(1)
	}
	if len(ints) < 2 {
		fmt.Fprintln(os.Stderr, "rand: malformed HDRBG state")
		os.Exit(1)
	}
	state := fitBytes(ints[0], 32, "HDRBG state", "rand")
	return DrbgFromState(state, uint64(bytesToInt(ints[1])))
}

func cmdRand(args []string) {
	fs := flag.NewFlagSet("rand", flag.ExitOnError)
	seed   := fs.String("seed", "", "Seed/entropy file to instantiate the DRBG")
	state  := fs.String("state", "", "HDRBG STATE PEM to resume from and/or update")
	pers   := fs.String("personalization", "", "Personalization string (with --seed only)")
	reseed := fs.String("reseed", "", "Entropy file to fold into the state before generating")
	nbytesS := fs.String("bytes", "", "Number of output bytes to generate (0 to 33554432)")
	asHex  := fs.Bool("hex", false, "Hex-encode the output instead of raw bytes")
	out    := fs.String("out", "-", "Output file (default: - = stdout)")
	parseArgs(fs, args)

	var d *HDrbg
	switch {
	case *seed != "":
		sbuf, err := readFile(*seed)
		if err != nil {
			die("rand", err)
		}
		d = DrbgSeed(sbuf, []byte(*pers))
	case *state != "":
		d = loadHdrbgState(*state)
	default:
		fmt.Fprintln(os.Stderr, "rand: one of --seed or --state is required")
		os.Exit(1)
	}

	if *reseed != "" {
		rbuf, err := readFile(*reseed)
		if err != nil {
			die("rand", err)
		}
		d.DrbgReseed(rbuf)
	}

	// TODO #269: -1 was doing double duty as "not given" and as a value, so
	// `--bytes -1` fell through to "nothing to do" while Python, C and Java all
	// report "--bytes must be non-negative".  isSet distinguishes the two, which
	// is what the other three get for free from argparse / an explicit NULL check.
	// TODO #380: at most one seed's worth of output (DrbgMaxBlocks blocks),
	// the most a single request can ever return; -1 means "not given".
	nbytes := numFlag(fs, "bytes", nbytesS, 0, DrbgMaxBlocks*32, -1)
	if nbytes >= 0 {
		outBytes, ok := d.DrbgGenerate(nbytes)
		if !ok {
			fmt.Fprintln(os.Stderr, "rand: output limit reached — reseed required")
			os.Exit(1)
		}
		var data []byte
		if *asHex {
			data = []byte(hex.EncodeToString(outBytes) + "\n")
		} else {
			data = outBytes
		}
		if *out == "-" {
			os.Stdout.Write(data)
		} else if err := writeBytes(*out, data); err != nil {
			die("rand", err)
		}
	} else if *reseed == "" {
		fmt.Fprintln(os.Stderr, "rand: nothing to do (specify --bytes and/or --reseed)")
		os.Exit(1)
	}

	if *state != "" {
		if err := writeString(*state, encodeHdrbgState(d)); err != nil {
			die("rand", err)
		}
	}
}

// ── Key loading helper (for enc/dec) ─────────────────────────────────────────

// loadKey loads a session key from a SESSION KEY PEM, HKEX-RNL RESPONSE PEM,
// or a plain-text 0x... hex string.  Returns (key, nbits).
//
// The hex form's width is set by its DIGIT COUNT, rounded up to a multiple of
// 32 (at least 32), never by its value (TODO #355): 64 hex digits are a 256-bit
// key even when the top digits are zero.  All four CLIs apply the same rule.
func loadKey(path string) (*big.Int, int, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, 0, err
	}
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		digits := s[2:]
		if digits == "" || strings.Trim(digits, "0123456789abcdefABCDEF") != "" {
			return nil, 0, fmt.Errorf("%s: invalid hex key (expected 0x followed by hex digits)", path)
		}
		v, _ := new(big.Int).SetString(digits, 16)
		nb := ((4*len(digits) + 31) / 32) * 32
		if nb < 32 {
			nb = 32
		}
		if nb > BAMaxBits {
			return nil, 0, fmt.Errorf("%s: hex key is %d-bit; the maximum is %d", path, nb, BAMaxBits)
		}
		return v, nb, nil
	}
	label, der, err := PemUnwrap(s)
	if err != nil {
		return nil, 0, err
	}
	ints, enc, err := derParseLabeled(label, der)
	if err == nil {
		err = checkDerItems(label, ints)
	}
	if err == nil {
		err = checkDerCaps(label, ints, enc)
	}
	if err != nil {
		return nil, 0, err
	}
	switch label {
	case lblSession:
		// TODO #367: the width sizes every BitArray the key builds; 0 or 7
		// panicked in NewZero (E_WIDTH).
		bits := new(big.Int).SetBytes(ints[1])
		if !bits.IsInt64() || bits.Int64() < 16 || bits.Int64() > BAMaxBits || bits.Int64()%8 != 0 {
			return nil, 0, fmt.Errorf("%s: session key width is %s (expected a multiple of 8, 16..%d)",
				path, bits, BAMaxBits)
		}
		return new(big.Int).SetBytes(ints[0]), int(bits.Int64()), nil
	case lblRnlResp:
		// ints[3] is the RING dimension, which since TODO #223 is no longer the
		// key width — the ring is 1024 while the derived key stays 256 bits.
		// Returning it raw made `enc` use a 1024-bit key width against a SESSION
		// KEY PEM's 256, so a cross-party HSKE round trip failed.  The derived
		// key is 256 bits at every ring dimension (TODO #228).
		return new(big.Int).SetBytes(ints[0]), rnlSessionBits(bytesToInt(ints[3])), nil
	}
	return nil, 0, fmt.Errorf("loadKey: expected SESSION KEY or HKEX-RNL RESPONSE PEM, got %q", label)
}

// ── Ciphertext encoding helpers ───────────────────────────────────────────────

// encodeSymCT encodes a symmetric ciphertext (HSKE / HSKE-NL-A1 / HSKE-NL-A2).
// For HSKE-NL-A1 pass nonce != nil to include format tag 1 + nonce field;
// all other algos use format tag 0 (no nonce).
func encodeSymCT(algo string, E *big.Int, n int, nonce *big.Int) (string, error) {
	return encodeSymCTTag(algo, E, n, nonce, nil)
}

// encodeSymCTTag: authTag != nil selects AEAD format tag 2 (TODO #95):
// SEQ(2, nonce, E, tag, nbits).
func encodeSymCTTag(algo string, E *big.Int, n int, nonce, authTag *big.Int) (string, error) {
	nb := n / 8
	var items [][]byte
	if algo == "hske-nla1" && nonce != nil && authTag != nil {
		tag, _ := derIntSmall(2)
		nd, _  := derIntBig(nonce, nb)
		ed, _  := derIntBig(E, nb)
		td, _  := derIntBig(authTag, 32)
		nn, _  := derIntSmall(n)
		items = [][]byte{tag, nd, ed, td, nn}
		seq, err := DerSeqEnc(items...)
		if err != nil {
			return "", err
		}
		return PemWrap(lblCT, seq), nil
	}
	if algo == "hske-nla1" && nonce != nil {
		tag, _ := derIntSmall(1)
		nd, _  := derIntBig(nonce, nb)
		ed, _  := derIntBig(E, nb)
		nn, _  := derIntSmall(n)
		items = [][]byte{tag, nd, ed, nn}
	} else {
		tag, _ := derIntSmall(0)
		ed, _  := derIntBig(E, nb)
		nn, _  := derIntSmall(n)
		items = [][]byte{tag, ed, nn}
	}
	seq, err := DerSeqEnc(items...)
	if err != nil {
		return "", err
	}
	return PemWrap(lblCT, seq), nil
}

// encodeDuplexCT: HSKE-NL-V2-Duplex AEAD, format tag 3 (TODO #118):
// SEQ(3, nonce, ct_len, ct, tag, nbits) with variable-length ciphertext.
// v3 selects format tag 4 (HSKE-NL-V3-Duplex, TODO #255) over tag 3.
func encodeDuplexCT(nonce *big.Int, ct []byte, tag *big.Int, n int, v3 bool) (string, error) {
	nb := n / 8
	ctLen := len(ct)
	ctWidth := ctLen
	if ctWidth == 0 {
		ctWidth = 1
	}
	fmtTag := 3
	if v3 {
		fmtTag = 4
	}
	t3, _ := derIntSmall(fmtTag)
	nd, _ := derIntBig(nonce, nb)
	ld, _ := derIntSmall(ctLen)
	ed, _ := derIntBig(new(big.Int).SetBytes(ct), ctWidth)
	td, _ := derIntBig(tag, 32)
	nn, _ := derIntSmall(n)
	seq, err := DerSeqEnc(t3, nd, ld, ed, td, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblCT, seq), nil
}

func encodeAsymCT(R, E *big.Int, n int) (string, error) {
	nb := n / 8
	rd, err := derIntBig(R, nb)
	if err != nil {
		return "", err
	}
	ed, err := derIntBig(E, nb)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(rd, ed, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblCT, seq), nil
}

// encodeSternCT encodes an HPKE-Stern-F KEM ciphertext.
// K is stored for session-key extraction; e' stored for demo brute-force decap.
func encodeSternCT(ctSyn *big.Int, ePrime, K *BitArray, E *big.Int, n int) (string, error) {
	nb := n / 8
	ca, err := derIntBig(ctSyn, nb)
	if err != nil {
		return "", err
	}
	ea, err := derIntBig(ePrime.BigInt(), nb)
	if err != nil {
		return "", err
	}
	ka, err := derIntBig(K.BigInt(), nb)
	if err != nil {
		return "", err
	}
	enc, err := derIntBig(E, nb)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(ca, ea, ka, enc, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblCT, seq), nil
}

// ── Signature encoding helpers ────────────────────────────────────────────────

func encodeSchnorrSig(s, R, e *big.Int, n int) (string, error) {
	nb := n / 8
	sa, err := derIntBig(s, nb)
	if err != nil {
		return "", err
	}
	ra, err := derIntBig(R, nb)
	if err != nil {
		return "", err
	}
	ea, err := derIntBig(e, nb)
	if err != nil {
		return "", err
	}
	nn, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(sa, ra, ea, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblSig, seq), nil
}

// ── HPKE-Stern-KEM (QC-MDPC Niederreiter) DER helpers ────────────────────────

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// polyToDerInt returns the DER-INTEGER value for a little-endian poly: the
// poly's width-byte little-endian representation reinterpreted as big-endian.
func polyToDerInt(poly *big.Int, width int) *big.Int {
	be := make([]byte, width)
	poly.FillBytes(be) // big-endian
	return new(big.Int).SetBytes(reverseBytes(be))
}

// polyFromDerInt inverts polyToDerInt.
func polyFromDerInt(v *big.Int, width int) *big.Int {
	le := fitBytes(v.Bytes(), width, "QC-MDPC polynomial", "hpke-stern-kem") // little-endian view
	return new(big.Int).SetBytes(reverseBytes(le))
}

func supToDerInt(sup []int, d int) *big.Int {
	s := append([]int(nil), sup...)
	// insertion sort ascending (d is tiny)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
	buf := make([]byte, d*2)
	for i, p := range s {
		buf[i*2] = byte(p >> 8)
		buf[i*2+1] = byte(p)
	}
	return new(big.Int).SetBytes(buf)
}

func supFromDerInt(v *big.Int, d int) []int {
	buf := fitBytes(v.Bytes(), d*2, "QC-MDPC support", "hpke-stern-kem")
	sup := make([]int, d)
	for i := 0; i < d; i++ {
		sup[i] = int(buf[i*2])<<8 | int(buf[i*2+1])
	}
	return sup
}

func encodeKemPriv(sup0, sup1 []int, h0, h1 *big.Int) (string, error) {
	rb, d := QcMdpcRBytes, QcMdpcD
	h0d, e1 := derIntBig(polyToDerInt(h0, rb), rb)
	h1d, e2 := derIntBig(polyToDerInt(h1, rb), rb)
	s0d, e3 := derIntBig(supToDerInt(sup0, d), d*2)
	s1d, e4 := derIntBig(supToDerInt(sup1, d), d*2)
	rd, e5 := derIntSmall(QcMdpcR)
	dd, e6 := derIntSmall(d)
	for _, e := range []error{e1, e2, e3, e4, e5, e6} {
		if e != nil {
			return "", e
		}
	}
	seq, err := DerSeqEnc(h0d, h1d, s0d, s1d, rd, dd)
	if err != nil {
		return "", err
	}
	return PemWrap(lblKemPriv, seq), nil
}

func decodeKemPriv(ints [][]byte) (sup0, sup1 []int, h0, h1 *big.Int) {
	rb := QcMdpcRBytes
	// d sizes supFromDerInt's buffer and indexes the support arrays; in the C
	// reader it sized a fixed stack buffer (TODO #239).
	d := bounded(wireInt(ints[5], "QC-MDPC row weight d", "pkey"), 1, QcMdpcD,
		"QC-MDPC row weight d", "pkey")
	h0 = polyFromDerInt(new(big.Int).SetBytes(ints[0]), rb)
	h1 = polyFromDerInt(new(big.Int).SetBytes(ints[1]), rb)
	sup0 = supFromDerInt(new(big.Int).SetBytes(ints[2]), d)
	sup1 = supFromDerInt(new(big.Int).SetBytes(ints[3]), d)
	return sup0, sup1, h0, h1
}

func encodeKemPub(hPub *big.Int) (string, error) {
	rb := QcMdpcRBytes
	hd, e1 := derIntBig(polyToDerInt(hPub, rb), rb)
	rd, e2 := derIntSmall(QcMdpcR)
	if e1 != nil {
		return "", e1
	}
	if e2 != nil {
		return "", e2
	}
	seq, err := DerSeqEnc(hd, rd)
	if err != nil {
		return "", err
	}
	return PemWrap(lblKemPub, seq), nil
}

func decodeKemPub(ints [][]byte) *big.Int {
	// TODO #371: the declared r must be the one this CLI runs (it was ignored).
	if len(ints) > 1 {
		bounded(wireInt(ints[1], "QC-MDPC r", "QC-MDPC public key"), QcMdpcR, QcMdpcR,
			"QC-MDPC r", "QC-MDPC public key")
	}
	return polyFromDerInt(new(big.Int).SetBytes(ints[0]), QcMdpcRBytes)
}

func encodeKemCT(syn *big.Int, E *big.Int) (string, error) {
	rb := QcMdpcRBytes
	sd, e1 := derIntBig(polyToDerInt(syn, rb), rb)
	ed, e2 := derIntBig(E, 32)
	rd, e3 := derIntSmall(QcMdpcR)
	for _, e := range []error{e1, e2, e3} {
		if e != nil {
			return "", e
		}
	}
	seq, err := DerSeqEnc(sd, ed, rd)
	if err != nil {
		return "", err
	}
	return PemWrap(lblCT, seq), nil
}

func decodeKemCT(ints [][]byte) (syn, E *big.Int) {
	if len(ints) > 2 {   // TODO #371, as decodeKemPub
		bounded(wireInt(ints[2], "QC-MDPC r", "QC-MDPC ciphertext"), QcMdpcR, QcMdpcR,
			"QC-MDPC r", "QC-MDPC ciphertext")
	}
	syn = polyFromDerInt(new(big.Int).SetBytes(ints[0]), QcMdpcRBytes)
	E = new(big.Int).SetBytes(ints[1])
	return syn, E
}

// packSternSig serialises a *SternSig to the HERRADURA SIGNATURE PEM format,
// matching Python's _pack_stern_sig and C's pack_stern_sig exactly.
func packSternSig(sig *SternSig, n int) (string, error) {
	return packSternSigLabel(sig, n, lblSig)
}

// packSternSigLabel is packSternSig with a caller-supplied PEM label — used
// to reuse the HERRADURA SIGNATURE wire layout under the
// HERRADURA HCRED CREDENTIAL label.
func packSternSigLabel(sig *SternSig, n int, label string) (string, error) {
	rounds := len(sig.Rounds)
	nb := n / 8

	// Commits: c0||c1||c2 per round, each nb bytes big-endian
	commitsBuf := make([]byte, 3*rounds*nb)
	for i, r := range sig.Rounds {
		off := i * 3 * nb
		fillBA(commitsBuf[off : off+nb], r.C0)
		fillBA(commitsBuf[off+nb : off+2*nb], r.C1)
		fillBA(commitsBuf[off+2*nb : off+3*nb], r.C2)
	}

	// Challenges: 2 bits per round, packed LSB-first within each byte
	chalNb := (rounds + 3) / 4
	chalBytes := make([]byte, chalNb)
	for i, r := range sig.Rounds {
		chalBytes[i/4] |= byte((r.B & 3) << ((i % 4) * 2))
	}

	// Responses: respA||respB per round, each nb bytes big-endian
	respBuf := make([]byte, 2*rounds*nb)
	for i, r := range sig.Rounds {
		off := i * 2 * nb
		fillBA(respBuf[off : off+nb], r.RespA)
		fillBA(respBuf[off+nb : off+2*nb], r.RespB)
	}

	nDer, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	rDer, err := derIntSmall(rounds)
	if err != nil {
		return "", err
	}
	cDer, err := derIntBig(new(big.Int).SetBytes(commitsBuf), len(commitsBuf))
	if err != nil {
		return "", err
	}
	chDer, err := derIntBig(new(big.Int).SetBytes(chalBytes), chalNb)
	if err != nil {
		return "", err
	}
	resDer, err := derIntBig(new(big.Int).SetBytes(respBuf), len(respBuf))
	if err != nil {
		return "", err
	}
	seq, err := DerSeqEnc(nDer, rDer, cDer, chDer, resDer)
	if err != nil {
		return "", err
	}
	return PemWrap(label, seq), nil
}

// unpackSternSig deserialises a *SternSig from DER-parsed integer fields.
func unpackSternSig(ints [][]byte) (*SternSig, int, error) {
	if len(ints) != 5 {
		return nil, 0, checkDerItemsExact(lblSig, ints, 5)
	}
	n := boundedN(wireInt(ints[0], "n", "verify"), "verify")
	rounds := bounded(wireInt(ints[1], "round count", "verify"), 1, SdfMaxRounds,
		"round count", "verify")
	nb := n / 8

	padLeft := func(raw []byte, want int) []byte {
		if len(raw) >= want {
			return raw[len(raw)-want:]
		}
		out := make([]byte, want)
		copy(out[want-len(raw):], raw)
		return out
	}

	commitsRaw := padLeft(ints[2], 3*rounds*nb)
	chalRaw    := padLeft(ints[3], (rounds+3)/4)
	respRaw    := padLeft(ints[4], 2*rounds*nb)

	sig := &SternSig{Rounds: make([]SternRound, rounds)}
	for i := range sig.Rounds {
		off := i * 3 * nb
		sig.Rounds[i].C0 = NewBitArray(n, new(big.Int).SetBytes(commitsRaw[off:off+nb]))
		sig.Rounds[i].C1 = NewBitArray(n, new(big.Int).SetBytes(commitsRaw[off+nb:off+2*nb]))
		sig.Rounds[i].C2 = NewBitArray(n, new(big.Int).SetBytes(commitsRaw[off+2*nb:off+3*nb]))
		sig.Rounds[i].B  = int((chalRaw[i/4] >> ((i % 4) * 2)) & 3)
		off2 := i * 2 * nb
		sig.Rounds[i].RespA = NewBitArray(n, new(big.Int).SetBytes(respRaw[off2:off2+nb]))
		sig.Rounds[i].RespB = NewBitArray(n, new(big.Int).SetBytes(respRaw[off2+nb:off2+2*nb]))
	}
	return sig, n, nil
}

// HSKE-NL-A1's plain mode ran at any width but 256 only by accident until TODO
// #314: below 256 the four ports produced four different keystreams, so #313
// refused every width but 256 in all four CLIs.  Pass 6 RELAXED that refusal —
// C, Go, Python and Java now agree octet for octet at 32, 64, 128 and 256 —
// and what is left is the width's own validity (BITARRAY.md §2) plus the rule
// that a width is never coerced (§3).  The refusal is not merely deleted: a
// width that is not a legal BitArray width was never representable, and a
// ciphertext whose declared width disagrees with the key is a MIXED WIDTH,
// which §3 makes an error rather than something to resolve by preferring one
// of the two — and preferring one is exactly what this CLI used to do, since
// dec built the key at the CIPHERTEXT's width.  See MIGRATING.md §23.
const (
	nla1MinWidth = 16
	nla1MaxWidth = BAMaxBits
)

// sym256OK exits unless n is 256 (TODO #356).  hske, hske-nla2, hske-nla3, fpe
// and twk agree across the four CLIs at 256 bits only: below it C zero-extended
// the key while Go and Python ran at its width, and NL-FSCX v2's inverse
// M^(n/2 - 1) is M^-1 only at powers of two.  MIGRATING.md §27.
func sym256OK(n int, ctx, what string) {
	if n != 256 {
		fmt.Fprintf(os.Stderr, "%s: requires a 256-bit %s; got %d-bit\n", ctx, what, n)
		os.Exit(1)
	}
}

// nla1WidthOK exits unless n is a legal BitArray width.  what names the carrier.
func nla1WidthOK(n int, ctx, what string) {
	if n%8 != 0 || n < nla1MinWidth || n > nla1MaxWidth {
		fmt.Fprintf(os.Stderr,
			"%s: hske-nla1 %s width must be a multiple of 8 between %d and %d; "+
				"got %d-bit (BITARRAY.md §2)\n", ctx, what, nla1MinWidth, nla1MaxWidth, n)
		os.Exit(1)
	}
}

// nla1SameWidth exits unless the ciphertext's declared width matches the key's.
func nla1SameWidth(keyN, ctN int, ctx string) {
	if keyN != ctN {
		fmt.Fprintf(os.Stderr,
			"%s: hske-nla1 ciphertext declares %d-bit, key is %d-bit "+
				"(BITARRAY.md §3: a mixed width is never coerced)\n", ctx, ctN, keyN)
		os.Exit(1)
	}
}

// msgPad returns inBytes truncated/zero-padded to exactly nbytes.
// aeadFlagsOK refuses --aead / --ad on an --algo that would ignore them
// (TODO #378).  --aead means something only to hske-nla1, --ad only to
// hske-duplex, hske-duplex3 and hske-nla1; anywhere else the flag was dropped
// without a word.  Presence is what counts: `--ad ''` is a flag given.
func aeadFlagsOK(cmd, algo string, adSet, aeadSet bool) {
	if aeadSet && algo != "hske-nla1" {
		fmt.Fprintf(os.Stderr, "%s: --aead is only for --algo hske-nla1, not '%s'\n", cmd, algo)
		os.Exit(1)
	}
	if adSet && algo != "hske-duplex" && algo != "hske-duplex3" && algo != "hske-nla1" {
		fmt.Fprintf(os.Stderr, "%s: --ad is only for --algo hske-duplex, hske-duplex3 "+
			"or hske-nla1, not '%s'\n", cmd, algo)
		os.Exit(1)
	}
}

// oneBlockOK refuses input longer than the one block a single-block --algo
// encrypts (TODO #378); it used to be cut to its first block with exit 0.
func oneBlockOK(algo string, inLen, nbytes int) {
	if inLen > nbytes {
		hint := "for longer input, encrypt a key with it and the message with --algo hske-duplex"
		if strings.HasPrefix(algo, "hske") {
			hint = "use --algo hske-duplex or encfile for longer input"
		}
		fmt.Fprintf(os.Stderr, "enc: --algo %s encrypts one %d-byte block; --in is %d bytes (%s)\n",
			algo, nbytes, inLen, hint)
		os.Exit(1)
	}
}

func msgPad(inBytes []byte, nbytes int) []byte {
	out := make([]byte, nbytes)
	copy(out, inBytes)
	return out
}

// ── ZKP raw-binary PEM helpers ────────────────────────────────────────────────

func peekPEMLabel(path string) (string, error) {
	data, err := readFile(path)
	if err != nil {
		return "", err
	}
	label, _, err := PemUnwrap(string(data))
	return label, err
}

func readRawPEM(path, expectLabel string) ([]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	label, body, err := PemUnwrap(string(data))
	if err != nil {
		return nil, err
	}
	if label != expectLabel {
		// Naming the envelope is the point of failing closed: "expected X, got
		// Y" sends the reader looking for the wrong problem (TODO #268).
		if label == lblEncPriv && expectLabel != lblEncPriv {
			return nil, fmt.Errorf("%s is a passphrase-encrypted private key; decrypt it "+
				"first with `pkey --decrypt --passphrase ... --in %s --out plain.pem`", path, path)
		}
		return nil, fmt.Errorf("expected PEM label %q, got %q", expectLabel, label)
	}
	return body, nil
}

// encodeZkpRnlProof serializes a ZKP-RNL proof to raw binary PEM.
// Wire: 4B n | n×4B w (s32-be) | n×4B c (u32-be) | n×4B z (s32-be)
func encodeZkpRnlProof(w, c, z []int, n int) string {
	buf := make([]byte, 4+n*12)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint32(buf[4+i*4:], uint32(int32(w[i])))
	}
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint32(buf[4+n*4+i*4:], uint32(c[i]))
	}
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint32(buf[4+n*8+i*4:], uint32(int32(z[i])))
	}
	return PemWrap(lblZkpRnlProof, buf)
}

func decodeZkpRnlProof(body []byte) (w, c, z []int, n int, err error) {
	if len(body) < 4 {
		return nil, nil, nil, 0, fmt.Errorf("ZKP-RNL proof too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	if n <= 0 || n > RnlN {
		return nil, nil, nil, 0, fmt.Errorf("ZKP-RNL proof: n out of range (%d)", n)
	}
	if len(body) < 4+n*12 {
		return nil, nil, nil, 0, fmt.Errorf("ZKP-RNL proof truncated (n=%d)", n)
	}
	w = make([]int, n)
	c = make([]int, n)
	z = make([]int, n)
	for i := 0; i < n; i++ {
		w[i] = int(int32(binary.BigEndian.Uint32(body[4+i*4:])))
	}
	for i := 0; i < n; i++ {
		c[i] = int(binary.BigEndian.Uint32(body[4+n*4+i*4:]))
	}
	for i := 0; i < n; i++ {
		z[i] = int(int32(binary.BigEndian.Uint32(body[4+n*8+i*4:])))
	}
	err = rawEnd(lblZkpRnlProof, body, 4+n*12)
	return
}

// encodeZkpNlPriv: Wire: 4B n | nb A | nb B | nb y
func encodeZkpNlPriv(A, B, y uint64, n int) string {
	nb := (n + 7) / 8
	buf := make([]byte, 4+3*nb)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	for i := nb - 1; i >= 0; i-- {
		buf[4+i] = byte(A); A >>= 8
	}
	for i := nb - 1; i >= 0; i-- {
		buf[4+nb+i] = byte(B); B >>= 8
	}
	for i := nb - 1; i >= 0; i-- {
		buf[4+2*nb+i] = byte(y); y >>= 8
	}
	return PemWrap(lblZkpNlPriv, buf)
}

func decodeZkpNlPriv(body []byte) (A, B, y uint64, n int, err error) {
	if len(body) < 4 {
		return 0, 0, 0, 0, fmt.Errorf("ZKP-NL privkey too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	if n <= 0 || n > ZkpNlMaxN {
		return 0, 0, 0, 0, fmt.Errorf("ZKP-NL privkey: n out of range (%d)", n)
	}
	nb := (n + 7) / 8
	if len(body) < 4+3*nb {
		return 0, 0, 0, 0, fmt.Errorf("ZKP-NL privkey truncated")
	}
	for i := 0; i < nb; i++ {
		A = (A << 8) | uint64(body[4+i])
	}
	for i := 0; i < nb; i++ {
		B = (B << 8) | uint64(body[4+nb+i])
	}
	for i := 0; i < nb; i++ {
		y = (y << 8) | uint64(body[4+2*nb+i])
	}
	err = rawEnd(lblZkpNlPriv, body, 4+3*nb)
	return
}

// encodeZkpNlPub: Wire: 4B n | nb B | nb y
func encodeZkpNlPub(B, y uint64, n int) string {
	nb := (n + 7) / 8
	buf := make([]byte, 4+2*nb)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	for i := nb - 1; i >= 0; i-- {
		buf[4+i] = byte(B); B >>= 8
	}
	for i := nb - 1; i >= 0; i-- {
		buf[4+nb+i] = byte(y); y >>= 8
	}
	return PemWrap(lblZkpNlPub, buf)
}

func decodeZkpNlPub(body []byte) (B, y uint64, n int, err error) {
	if len(body) < 4 {
		return 0, 0, 0, fmt.Errorf("ZKP-NL pubkey too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	if n <= 0 || n > ZkpNlMaxN {
		return 0, 0, 0, fmt.Errorf("ZKP-NL pubkey: n out of range (%d)", n)
	}
	nb := (n + 7) / 8
	if len(body) < 4+2*nb {
		return 0, 0, 0, fmt.Errorf("ZKP-NL pubkey truncated")
	}
	for i := 0; i < nb; i++ {
		B = (B << 8) | uint64(body[4+i])
	}
	for i := 0; i < nb; i++ {
		y = (y << 8) | uint64(body[4+nb+i])
	}
	err = rawEnd(lblZkpNlPub, body, 4+2*nb)
	return
}

// encodeZkpNlProof: Wire: 4B n | 4B rounds | R×(96B coms | 1B e | 2B l1 | v1 | 2B l2 | v2)
func encodeZkpNlProof(proof []ZkpNlRound, n int) string {
	R := len(proof)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	binary.BigEndian.PutUint32(buf[4:], uint32(R))
	for _, r := range proof {
		buf = append(buf, r.Com0[:]...)
		buf = append(buf, r.Com1[:]...)
		buf = append(buf, r.Com2[:]...)
		buf = append(buf, byte(r.E))
		l1 := len(r.ViewP1)
		buf = append(buf, byte(l1>>8), byte(l1))
		buf = append(buf, r.ViewP1...)
		l2 := len(r.ViewP2)
		buf = append(buf, byte(l2>>8), byte(l2))
		buf = append(buf, r.ViewP2...)
	}
	return PemWrap(lblZkpNlProof, buf)
}

func decodeZkpNlProof(body []byte) (proof []ZkpNlRound, n int, err error) {
	if len(body) < 8 {
		return nil, 0, fmt.Errorf("ZKP-NL proof too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	R := int(binary.BigEndian.Uint32(body[4:8]))
	// Both header fields size an allocation, so bound them before allocating.
	// A zero round count is the dangerous one: the verifier's per-round loop
	// then runs zero times and reports success (TODO #275).
	if n <= 0 || n > ZkpNlMaxN {
		return nil, 0, fmt.Errorf("ZKP-NL proof: n out of range (%d)", n)
	}
	if R <= 0 || R > ZkpNlMaxRounds {
		return nil, 0, fmt.Errorf("ZKP-NL proof: rounds out of range (%d)", R)
	}
	off := 8
	proof = make([]ZkpNlRound, R)
	for j := 0; j < R; j++ {
		// 96B commitments + 1B e + 2B len_p1 = 99, not 97: the length field
		// itself has to be in range before it can be read.
		if off+99 > len(body) {
			return nil, 0, fmt.Errorf("ZKP-NL proof round %d truncated", j)
		}
		copy(proof[j].Com0[:], body[off:off+32]); off += 32
		copy(proof[j].Com1[:], body[off:off+32]); off += 32
		copy(proof[j].Com2[:], body[off:off+32]); off += 32
		proof[j].E = int(body[off]); off++
		l1 := int(body[off])<<8 | int(body[off+1]); off += 2
		if l1 > len(body)-off {
			return nil, 0, fmt.Errorf("ZKP-NL proof round %d view1 truncated", j)
		}
		proof[j].ViewP1 = body[off : off+l1]; off += l1
		if off+2 > len(body) {
			return nil, 0, fmt.Errorf("ZKP-NL proof round %d view2 truncated", j)
		}
		l2 := int(body[off])<<8 | int(body[off+1]); off += 2
		if l2 > len(body)-off {
			return nil, 0, fmt.Errorf("ZKP-NL proof round %d view2 truncated", j)
		}
		proof[j].ViewP2 = body[off : off+l2]; off += l2
	}
	err = rawEnd(lblZkpNlProof, body, off)
	return
}

// encodeZkpNlPpProof: Wire format:
// 4B n | 4B rounds | per-round:
//   32B com_e | 1B e | nb B out_e | 16B seed_p1 | 16B seed_p2
//   | 1B gates_len | gates_p2 | 1B has_share2 | [nb B share2 if has_share2]
func encodeZkpNlPpProof(proof []ZkpNlPpRound, n int) string {
	R := len(proof)
	nb := (n + 7) / 8
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	binary.BigEndian.PutUint32(buf[4:], uint32(R))
	for _, r := range proof {
		buf = append(buf, r.ComE[:]...)
		buf = append(buf, byte(r.E))
		buf = append(buf, r.OutE...)
		buf = append(buf, r.SeedP1[:]...)
		buf = append(buf, r.SeedP2[:]...)
		buf = append(buf, byte(len(r.GatesP2)))
		buf = append(buf, r.GatesP2...)
		if r.Share2 != nil {
			buf = append(buf, 1)
			buf = append(buf, r.Share2...)
		} else {
			buf = append(buf, 0)
		}
	}
	_ = nb
	return PemWrap(lblZkpNlPpSig, buf)
}

func decodeZkpNlPpProof(body []byte) (proof []ZkpNlPpRound, n int, err error) {
	if len(body) < 8 {
		return nil, 0, fmt.Errorf("ZKP-NL-PP proof too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	R := int(binary.BigEndian.Uint32(body[4:8]))
	// Same two sizing fields, same reasons, as decodeZkpNlProof (TODO #275).
	if n <= 0 || n > ZkpNlMaxN {
		return nil, 0, fmt.Errorf("ZKP-NL-PP proof: n out of range (%d)", n)
	}
	if R <= 0 || R > ZkpNlMaxRounds {
		return nil, 0, fmt.Errorf("ZKP-NL-PP proof: rounds out of range (%d)", R)
	}
	nb := (n + 7) / 8
	off := 8
	proof = make([]ZkpNlPpRound, R)
	for j := 0; j < R; j++ {
		minLen := 32 + 1 + nb + 16 + 16
		if off+minLen > len(body) {
			return nil, 0, fmt.Errorf("ZKP-NL-PP proof round %d truncated", j)
		}
		copy(proof[j].ComE[:], body[off:off+32]); off += 32
		proof[j].E = int(body[off]); off++
		proof[j].OutE = make([]byte, nb)
		copy(proof[j].OutE, body[off:off+nb]); off += nb
		copy(proof[j].SeedP1[:], body[off:off+16]); off += 16
		copy(proof[j].SeedP2[:], body[off:off+16]); off += 16
		if off >= len(body) {
			return nil, 0, fmt.Errorf("ZKP-NL-PP proof round %d truncated (gates_len)", j)
		}
		gl := int(body[off]); off++
		if off+gl+1 > len(body) {
			return nil, 0, fmt.Errorf("ZKP-NL-PP proof round %d truncated (gates)", j)
		}
		proof[j].GatesP2 = make([]byte, gl)
		copy(proof[j].GatesP2, body[off:off+gl]); off += gl
		hasShare2 := int(body[off]); off++
		if hasShare2 != 0 {
			if off+nb > len(body) {
				return nil, 0, fmt.Errorf("ZKP-NL-PP proof round %d truncated (share2)", j)
			}
			proof[j].Share2 = make([]byte, nb)
			copy(proof[j].Share2, body[off:off+nb]); off += nb
		}
	}
	err = rawEnd(lblZkpNlPpSig, body, off)
	return
}

// ── HCRED raw-binary PEM helpers ─────────────────────────────────────────────
//
// Wire formats (raw binary, no DER) — must match Python's codec.py
// (_hcred_ser3/_hcred_ser2/encode_hcred_*) and C's hcred_ser/pack helpers
// exactly:
//   HCRED PRIVATE KEY:
//     4B n | n×3B s_poly (Z_q) | n×2B C_poly (Z_p) | n×3B m_poly (Z_q)
//     | (n/8)B seed_H (big-endian) | ceil(rows/8)B syndr (little-endian)
//   HCRED PUBLIC KEY:
//     4B n | n×2B C_poly (Z_p) | n×3B m_poly (Z_q)
//     | (n/8)B seed_H (big-endian) | ceil(rows/8)B syndr (little-endian)
//   HCRED CREDENTIAL: same binary layout as HERRADURA SIGNATURE (Stern-F sig)
//   HCRED PROOF:
//     4B n | 4B W | 4B rounds | per round:
//       96B coms (3×32B) | outs_bytes | 32B seed_c | 32B seed_c1
//       | n×3B a1 | n×3B b1 | nb×3B g1 | nd×3B h1
//       | 1B has_aux | if has_aux: n×3B aux_s | nb×3B aux_B | nd×3B aux_D

const (
	hcredSignRounds = 219 // Stern-F rounds for issuer credential (prod soundness)
	hcredCliRounds  = 219 // ZKBoo rounds for presentation proof (prod soundness)
)

// hcredSer3 serialises a Z_q (mod 65537) vector at 3 bytes/coeff, big-endian.
func hcredSer3(vec []int) []byte {
	out := make([]byte, 3*len(vec))
	for i, v := range vec {
		w := ((v % 65537) + 65537) % 65537
		out[3*i] = byte(w >> 16)
		out[3*i+1] = byte(w >> 8)
		out[3*i+2] = byte(w)
	}
	return out
}

func hcredDeser3(data []byte, off, count int) ([]int, int) {
	// off < 0 is the "already truncated" sentinel; it propagates through a
	// chain of these so one check after the chain suffices (TODO #275).
	if off < 0 || count < 0 || off+3*count > len(data) {
		return nil, -1
	}
	out := make([]int, count)
	for i := 0; i < count; i++ {
		out[i] = int(data[off])<<16 | int(data[off+1])<<8 | int(data[off+2])
		off += 3
	}
	return out, off
}

// hcredSer2 serialises a Z_p (mod 4096) vector at 2 bytes/coeff, big-endian.
func hcredSer2(vec []int) []byte {
	out := make([]byte, 2*len(vec))
	for i, v := range vec {
		w := ((v % 4096) + 4096) % 4096
		out[2*i] = byte(w >> 8)
		out[2*i+1] = byte(w)
	}
	return out
}

func hcredDeser2(data []byte, off, count int) ([]int, int) {
	// off < 0 is the "already truncated" sentinel; it propagates through a
	// chain of these so one check after the chain suffices (TODO #275).
	if off < 0 || count < 0 || off+2*count > len(data) {
		return nil, -1
	}
	out := make([]int, count)
	for i := 0; i < count; i++ {
		out[i] = int(data[off])<<8 | int(data[off+1])
		off += 2
	}
	return out, off
}

// hcredNbNd returns (nb, nd, rows) for HCRED at n bits.
func hcredNbNd(n int) (nb, nd, rows int) {
	rows, rowBits, _ := HcredParams(n)
	return rows * rowBits, n * HcredEpsBits, rows
}

func hcredOutsToBytes(outs *HcredOuts, n int) []byte {
	var buf []byte
	for j := 0; j < 3; j++ {
		buf = append(buf, hcredSer3(outs.Ter[j])...)
		buf = append(buf, hcredSer3(outs.Bit[j])...)
		buf = append(buf, hcredSer3(outs.Del[j])...)
		buf = append(buf, hcredSer3([]int{outs.Wsh[j]})...)
		buf = append(buf, hcredSer3(outs.S[j])...)
		buf = append(buf, hcredSer3(outs.Y[j])...)
		buf = append(buf, hcredSer3(outs.Rnd[j])...)
	}
	return buf
}

func hcredOutsFromBytes(data []byte, off, n int) (HcredOuts, int) {
	nb, nd, rows := hcredNbNd(n)
	var outs HcredOuts
	for j := 0; j < 3; j++ {
		outs.Ter[j], off = hcredDeser3(data, off, n)
		outs.Bit[j], off = hcredDeser3(data, off, nb)
		outs.Del[j], off = hcredDeser3(data, off, nd)
		var wv []int
		wv, off = hcredDeser3(data, off, 1)
		if off < 0 {
			return outs, -1 // truncated; the sentinel is checked by the caller
		}
		outs.Wsh[j] = wv[0]
		outs.S[j], off = hcredDeser3(data, off, rows)
		outs.Y[j], off = hcredDeser3(data, off, rows)
		outs.Rnd[j], off = hcredDeser3(data, off, n)
	}
	return outs, off
}

func encodeHcredPriv(sPoly, cPoly, mPoly []int, seedH *BitArray, syndr *big.Int, n int) string {
	seedNb := n / 8
	syndrNb := (n/2 + 7) / 8
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	buf = append(buf, hcredSer3(sPoly)...)
	buf = append(buf, hcredSer2(cPoly)...)
	buf = append(buf, hcredSer3(mPoly)...)
	seedBuf := make([]byte, seedNb)
	fillBA(seedBuf, seedH)
	buf = append(buf, seedBuf...)
	buf = append(buf, hcredLE(syndr, syndrNb)...)
	return PemWrap(lblHcredPriv, buf)
}

func decodeHcredPriv(body []byte) (sPoly, cPoly, mPoly []int, seedH *BitArray, syndr *big.Int, n int, err error) {
	if len(body) < 4 {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("HCRED private key too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	if n <= 0 || n > HcredMaxN {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("HCRED private key: n out of range (%d)", n)
	}
	// The layout is fixed, so the body length is EXACTLY what n implies.  A
	// ">=" test only catches an n too LARGE; an n too small parses a prefix
	// and succeeds, which is how a poked n=33 passed at n=256 (TODO #275).
	if e := rawEnd(lblHcredPriv, body, 4+8*n+n/8+(n/2+7)/8); e != nil { // TODO #372
		err = e
		return
	}
	if len(body) != 4+8*n+n/8+(n/2+7)/8 {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("HCRED private key: body length does not match n=%d", n)
	}
	off := 4
	sPoly, off = hcredDeser3(body, off, n)
	cPoly, off = hcredDeser2(body, off, n)
	mPoly, off = hcredDeser3(body, off, n)
	seedNb := n / 8
	syndrNb := (n/2 + 7) / 8
	if off+seedNb+syndrNb > len(body) {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("HCRED private key truncated")
	}
	seedH = NewBitArray(n, new(big.Int).SetBytes(body[off:off+seedNb]))
	off += seedNb
	syndr = hcredFromLE(body[off:off+syndrNb])
	return
}

func encodeHcredPub(cPoly, mPoly []int, seedH *BitArray, syndr *big.Int, n int) string {
	seedNb := n / 8
	syndrNb := (n/2 + 7) / 8
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	buf = append(buf, hcredSer2(cPoly)...)
	buf = append(buf, hcredSer3(mPoly)...)
	seedBuf := make([]byte, seedNb)
	fillBA(seedBuf, seedH)
	buf = append(buf, seedBuf...)
	buf = append(buf, hcredLE(syndr, syndrNb)...)
	return PemWrap(lblHcredPub, buf)
}

func decodeHcredPub(body []byte) (cPoly, mPoly []int, seedH *BitArray, syndr *big.Int, n int, err error) {
	if len(body) < 4 {
		return nil, nil, nil, nil, 0, fmt.Errorf("HCRED public key too short")
	}
	n = int(binary.BigEndian.Uint32(body[0:4]))
	if n <= 0 || n > HcredMaxN {
		return nil, nil, nil, nil, 0, fmt.Errorf("HCRED public key: n out of range (%d)", n)
	}
	// The layout is fixed, so the body length is EXACTLY what n implies.  A
	// ">=" test only catches an n too LARGE; an n too small parses a prefix
	// and succeeds, which is how a poked n=33 passed at n=256 (TODO #275).
	if e := rawEnd(lblHcredPub, body, 4+5*n+n/8+(n/2+7)/8); e != nil { // TODO #372
		err = e
		return
	}
	if len(body) != 4+5*n+n/8+(n/2+7)/8 {
		return nil, nil, nil, nil, 0, fmt.Errorf("HCRED public key: body length does not match n=%d", n)
	}
	off := 4
	cPoly, off = hcredDeser2(body, off, n)
	mPoly, off = hcredDeser3(body, off, n)
	seedNb := n / 8
	syndrNb := (n/2 + 7) / 8
	if off+seedNb+syndrNb > len(body) {
		return nil, nil, nil, nil, 0, fmt.Errorf("HCRED public key truncated")
	}
	seedH = NewBitArray(n, new(big.Int).SetBytes(body[off:off+seedNb]))
	off += seedNb
	syndr = hcredFromLE(body[off:off+syndrNb])
	return
}

// hcredLE encodes v as `nbytes` little-endian bytes (matches Python's/C's
// LSB-first syndrome byte layout).
func hcredLE(v *big.Int, nbytes int) []byte {
	be := v.FillBytes(make([]byte, nbytes))
	le := make([]byte, nbytes)
	for i := 0; i < nbytes; i++ {
		le[i] = be[nbytes-1-i]
	}
	return le
}

func hcredFromLE(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[i] = le[len(le)-1-i]
	}
	return new(big.Int).SetBytes(be)
}

// loadHcredPubinfo loads (C, m, seed_H, syndr, n) from either an HCRED
// PUBLIC KEY or PRIVATE KEY PEM — mirrors Python's _load_hcred_pubkey and
// C's hcred_load_pubinfo.
func loadHcredPubinfo(path string) (cPoly, mPoly []int, seedH *BitArray, syndr *big.Int, n int, err error) {
	lbl, lerr := peekPEMLabel(path)
	if lerr != nil {
		return nil, nil, nil, nil, 0, lerr
	}
	if lbl == lblHcredPriv {
		body, rerr := readRawPEM(path, lblHcredPriv)
		if rerr != nil {
			return nil, nil, nil, nil, 0, rerr
		}
		_, cPoly, mPoly, seedH, syndr, n, err = decodeHcredPriv(body)
		return cPoly, mPoly, seedH, syndr, n, err
	}
	if lbl != lblHcredPub {
		return nil, nil, nil, nil, 0, fmt.Errorf("expected HCRED PUBLIC KEY (or PRIVATE KEY), got %q", lbl)
	}
	body, rerr := readRawPEM(path, lblHcredPub)
	if rerr != nil {
		return nil, nil, nil, nil, 0, rerr
	}
	return decodeHcredPub(body)
}

func encodeHcredProof(proof *HcredProof, n int) string {
	W := proof.W
	R := len(proof.Rounds)
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:], uint32(n))
	binary.BigEndian.PutUint32(buf[4:], uint32(W))
	binary.BigEndian.PutUint32(buf[8:], uint32(R))
	for _, rd := range proof.Rounds {
		for _, c := range rd.Coms {
			buf = append(buf, c...)
		}
		buf = append(buf, hcredOutsToBytes(&rd.Outs, n)...)
		buf = append(buf, rd.SeedC...)
		buf = append(buf, rd.SeedC1...)
		buf = append(buf, hcredSer3(rd.A1)...)
		buf = append(buf, hcredSer3(rd.B1)...)
		buf = append(buf, hcredSer3(rd.G1)...)
		buf = append(buf, hcredSer3(rd.H1)...)
		if rd.AuxS != nil {
			buf = append(buf, 1)
			buf = append(buf, hcredSer3(rd.AuxS)...)
			buf = append(buf, hcredSer3(rd.AuxB)...)
			buf = append(buf, hcredSer3(rd.AuxD)...)
		} else {
			buf = append(buf, 0)
		}
	}
	return PemWrap(lblHcredProof, buf)
}

func decodeHcredProof(body []byte) (*HcredProof, int, error) {
	if len(body) < 12 {
		return nil, 0, fmt.Errorf("HCRED proof too short")
	}
	n := int(binary.BigEndian.Uint32(body[0:4]))
	W := int(binary.BigEndian.Uint32(body[4:8]))
	R := int(binary.BigEndian.Uint32(body[8:12]))
	// All three size allocations below; R == 0 additionally makes the
	// per-round verification loop vacuous, so it is a forgery (TODO #275).
	if n <= 0 || n > HcredMaxN {
		return nil, 0, fmt.Errorf("HCRED proof: n out of range (%d)", n)
	}
	if W <= 0 || W > HcredMaxN {
		return nil, 0, fmt.Errorf("HCRED proof: W out of range (%d)", W)
	}
	if R <= 0 || R > ZkpNlMaxRounds {
		return nil, 0, fmt.Errorf("HCRED proof: rounds out of range (%d)", R)
	}
	nb, nd, _ := hcredNbNd(n)
	off := 12
	proof := &HcredProof{W: W, Rounds: make([]HcredRound, R)}
	for j := 0; j < R; j++ {
		var rd HcredRound
		for k := 0; k < 3; k++ {
			if off+32 > len(body) {
				return nil, 0, fmt.Errorf("HCRED proof round %d truncated (coms)", j)
			}
			rd.Coms[k] = append([]byte(nil), body[off:off+32]...)
			off += 32
		}
		rd.Outs, off = hcredOutsFromBytes(body, off, n)
		if off < 0 {
			return nil, 0, fmt.Errorf("HCRED proof round %d truncated (outs)", j)
		}
		if off+64 > len(body) {
			return nil, 0, fmt.Errorf("HCRED proof round %d truncated (seeds)", j)
		}
		rd.SeedC = append([]byte(nil), body[off:off+32]...)
		off += 32
		rd.SeedC1 = append([]byte(nil), body[off:off+32]...)
		off += 32
		rd.A1, off = hcredDeser3(body, off, n)
		rd.B1, off = hcredDeser3(body, off, n)
		rd.G1, off = hcredDeser3(body, off, nb)
		rd.H1, off = hcredDeser3(body, off, nd)
		if off < 0 {
			return nil, 0, fmt.Errorf("HCRED proof round %d truncated (shares)", j)
		}
		if off >= len(body) {
			return nil, 0, fmt.Errorf("HCRED proof round %d truncated (has_aux)", j)
		}
		hasAux := body[off]
		off++
		if hasAux != 0 {
			rd.AuxS, off = hcredDeser3(body, off, n)
			rd.AuxB, off = hcredDeser3(body, off, nb)
			rd.AuxD, off = hcredDeser3(body, off, nd)
			if off < 0 {
				return nil, 0, fmt.Errorf("HCRED proof round %d truncated (aux)", j)
			}
		}
		proof.Rounds[j] = rd
	}
	if e := rawEnd(lblHcredProof, body, off); e != nil {
		return nil, 0, e
	}
	return proof, n, nil
}

// ── cred-issue / cred-prove / cred-verify ────────────────────────────────────

func cmdCredIssue(args []string) {
	fs := flag.NewFlagSet("cred-issue", flag.ExitOnError)
	in := fs.String("in", "", "User HCRED public (or private) key PEM")
	our := fs.String("our", "", "Issuer hpks-stern/hpke-stern private key PEM")
	out := fs.String("out", "-", "HCRED CREDENTIAL PEM output")
	roundsS := fs.String("rounds", "", "Stern-F rounds (1 to 4096; default: 219 for 128-bit soundness)")
	parseArgs(fs, args)
	checkKeyLabels("cred-issue", fs) // TODO #366
	rounds := numFlag(fs, "rounds", roundsS, 1, SdfMaxRounds, hcredSignRounds) // TODO #380

	if *in == "" {
		fmt.Fprintln(os.Stderr, "cred-issue: --in (HCRED public/private key) required")
		os.Exit(1)
	}
	if *our == "" {
		fmt.Fprintln(os.Stderr, "cred-issue: --our (hpks-stern private key) required")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). Do not use for production.")

	cPoly, mPoly, seedH, syndr, n, lerr := loadHcredPubinfo(*in)
	if lerr != nil {
		die("cred-issue", lerr)
	}

	label, ourInts, err := readPEMInts(*our)
	if err != nil {
		die("cred-issue", err)
	}
	if label != lblHpksSternPriv && label != lblHpkeSternPriv {
		fmt.Fprintf(os.Stderr, "cred-issue: --our must be an hpks-stern or hpke-stern private key, got %q\n", label)
		os.Exit(1)
	}
	issuerN := sternWireN(ourInts[2], "cred-issue")
	issuerE := NewBitArray(issuerN, new(big.Int).SetBytes(ourInts[0]))
	issuerSeed := NewBitArray(issuerN, new(big.Int).SetBytes(ourInts[1]))

	r := rounds

	sig := HcredIssue(mPoly, cPoly, seedH, syndr, n, issuerE, issuerSeed, r)
	pem, perr := packSternSigLabel(sig, issuerN, lblHcredCred)
	if perr != nil {
		die("cred-issue", perr)
	}
	if werr := writeString(*out, pem); werr != nil {
		die("cred-issue", werr)
	}
}

func cmdCredProve(args []string) {
	fs := flag.NewFlagSet("cred-prove", flag.ExitOnError)
	in := fs.String("in", "", "User HCRED PRIVATE KEY PEM")
	out := fs.String("out", "-", "HCRED PROOF PEM output")
	msg := fs.String("msg", "", "Message to bind into the proof")
	roundsS := fs.String("rounds", "", "ZKBoo rounds (1 to 4096; default: 219 for 128-bit soundness)")
	parseArgs(fs, args)
	checkKeyLabels("cred-prove", fs) // TODO #366
	rounds := numFlag(fs, "rounds", roundsS, 1, SdfMaxRounds, 0) // TODO #380; 0 = default

	if *in == "" {
		fmt.Fprintln(os.Stderr, "cred-prove: --in (HCRED private key) required")
		os.Exit(1)
	}

	body, rerr := readRawPEM(*in, lblHcredPriv)
	if rerr != nil {
		die("cred-prove", rerr)
	}
	sPoly, cPoly, mPoly, seedH, syndr, n, derr := decodeHcredPriv(body)
	if derr != nil {
		die("cred-prove", derr)
	}

	r := hcredCliRounds
	if rounds > 0 {
		r = rounds
	}

	proof, perr := HcredProve(sPoly, mPoly, cPoly, seedH, syndr, n, r, []byte(*msg))
	if perr != nil {
		die("cred-prove", perr)
	}

	pem := encodeHcredProof(proof, n)
	if werr := writeString(*out, pem); werr != nil {
		die("cred-prove", werr)
	}
}

func cmdCredVerify(args []string) {
	fs := flag.NewFlagSet("cred-verify", flag.ExitOnError)
	proofPath := fs.String("proof", "", "HCRED PROOF PEM")
	pubkeyPath := fs.String("pubkey", "", "User HCRED PUBLIC (or PRIVATE) KEY PEM")
	credPath := fs.String("cred", "", "HCRED CREDENTIAL PEM (optional; verify issuer binding)")
	issuerPath := fs.String("issuer", "", "Issuer hpks-stern/hpke-stern public key PEM (required with --cred)")
	msg := fs.String("msg", "", "Message bound into the proof")
	roundsS := fs.String("rounds", "", "Rounds to verify (1 to 4096; default: proof's own round count)")
	minR := fs.String("min-rounds", strconv.Itoa(cliMinVerifyRounds),
		"Refuse a proof or credential declaring fewer rounds (TODO #364)")
	parseArgs(fs, args)
	checkKeyLabels("cred-verify", fs) // TODO #366
	rounds := numFlag(fs, "rounds", roundsS, 1, SdfMaxRounds, 0) // TODO #380; 0 = proof's own
	minRounds := numFlag(fs, "min-rounds", minR, 1, SdfMaxRounds, cliMinVerifyRounds)

	if *proofPath == "" {
		fmt.Fprintln(os.Stderr, "cred-verify: --proof required")
		os.Exit(1)
	}
	if *pubkeyPath == "" {
		fmt.Fprintln(os.Stderr, "cred-verify: --pubkey required")
		os.Exit(1)
	}

	body, rerr := readRawPEM(*proofPath, lblHcredProof)
	if rerr != nil {
		die("cred-verify", rerr)
	}
	proof, _, derr := decodeHcredProof(body)
	if derr != nil {
		die("cred-verify", derr)
	}

	requireRounds(len(proof.Rounds), minRounds, "HCRED proof", "cred-verify")
	r := len(proof.Rounds)
	if rounds > 0 {
		r = rounds
	}

	cPoly, mPoly, seedH, syndr, pubN, lerr := loadHcredPubinfo(*pubkeyPath)
	if lerr != nil {
		die("cred-verify", lerr)
	}

	msgBytes := []byte(*msg)
	okProof := HcredVerify(mPoly, cPoly, seedH, syndr, proof, pubN, r, msgBytes)
	if !okProof {
		fmt.Println("Verification FAILED (proof)")
		os.Exit(1)
	}

	if *credPath != "" {
		if *issuerPath == "" {
			fmt.Fprintln(os.Stderr, "cred-verify: --cred requires --issuer (hpks-stern public key)")
			os.Exit(1)
		}
		_, credInts, cerr := readPEMInts(*credPath)
		if cerr != nil {
			die("cred-verify", cerr)
		}
		credSig, _, uerr := unpackSternSig(credInts)
		if uerr != nil {
			die("cred-verify", uerr)
		}
		requireRounds(len(credSig.Rounds), minRounds, "HCRED credential", "cred-verify")

		issLabel, issInts, ierr := readPEMInts(*issuerPath)
		if ierr != nil {
			die("cred-verify", ierr)
		}
		if issLabel != lblHpksSternPub && issLabel != lblHpkeSternPub {
			fmt.Fprintf(os.Stderr, "cred-verify: --issuer must be an hpks-stern or hpke-stern public key, got %q\n", issLabel)
			os.Exit(1)
		}
		issuerN := sternWireN(issInts[2], "cred-verify")
		issuerSyn := new(big.Int).SetBytes(issInts[0])
		issuerSeed := NewBitArray(issuerN, new(big.Int).SetBytes(issInts[1]))

		okCred := HcredCredVerify(mPoly, cPoly, seedH, syndr, pubN, credSig, issuerSeed, issuerSyn)
		if !okCred {
			fmt.Println("Verification FAILED (credential)")
			os.Exit(1)
		}
		fmt.Println("Credential OK")
	}

	fmt.Println("Proof OK")
}

// ── enc ───────────────────────────────────────────────────────────────────────

func cmdEnc(args []string) {
	fs := flag.NewFlagSet("enc", flag.ExitOnError)
	algo   := fs.String("algo", "", "Encryption algorithm")
	key    := fs.String("key", "", "Key file (symmetric algos and HPKE enc uses --pubkey)")
	pubkey := fs.String("pubkey", "", "Recipient public key file (asymmetric algos)")
	in     := fs.String("in", "-", "Plaintext input file")
	out    := fs.String("out", "-", "Ciphertext output PEM file")
	aead   := fs.Bool("aead", false, "HSKE-NL-AEAD authenticated encryption (hske-nla1 only)")
	ad     := fs.String("ad", "", "Associated data bound into the AEAD tag (hske-duplex, hske-duplex3, or hske-nla1 with --aead; refused elsewhere)")
	parseArgs(fs, args)
	checkKeyLabels("enc", fs) // TODO #366

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "enc: --algo required")
		os.Exit(1)
	}
	aeadFlagsOK("enc", *algo, isSet(fs, "ad"), isSet(fs, "aead"))

	inBytes, err := readFile(*in)
	if err != nil {
		die("enc", err)
	}


	switch *algo {
	case "hske-duplex", "hske-duplex3":
		// HSKE-NL-V2/V3-Duplex AEAD (single-pass) — TODO #118, #255
		dplexV3 := *algo == "hske-duplex3"
		if *key == "" {
			fmt.Fprintf(os.Stderr, "enc: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, n, err := loadKey(*key)
		if err != nil {
			die("enc", err)
		}
		if n != 256 {
			fmt.Fprintf(os.Stderr, "enc: %s requires a 256-bit key\n", *algo)
			os.Exit(1)
		}
		K := NewBitArray(n, keyInt)
		nonce := NewRandBitArray(n)
		var ct, authTag []byte
		if dplexV3 {
			ct, authTag = HskeNlV3DuplexEncrypt(K, nonce, []byte(*ad), inBytes)
		} else {
			ct, authTag = HskeNlV2DuplexEncrypt(K, nonce, []byte(*ad), inBytes)
		}
		pem, err := encodeDuplexCT(nonce.BigInt(), ct, new(big.Int).SetBytes(authTag), n, dplexV3)
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hske", "hske-nla1", "hske-nla2", "hske-nla3":
		if *key == "" {
			fmt.Fprintf(os.Stderr, "enc: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, n, err := loadKey(*key)
		if err != nil {
			die("enc", err)
		}
		if *algo != "hske-nla1" {
			sym256OK(n, "enc "+*algo, "key")
		}
		nb := n / 8
		oneBlockOK(*algo, len(inBytes), nb)
		P := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		K := NewBitArray(n, keyInt)

		var pem string
		switch *algo {
		case "hske":
			E := FscxRevolve(P, K, n/4)
			pem, err = encodeSymCT("hske", E.BigInt(), n, nil)
		case "hske-nla1":
			nonce := NewRandBitArray(n)
			if *aead {
				// HSKE-NL-AEAD (TODO #95): format tag 2 with auth tag
				if n != 256 {
					fmt.Fprintln(os.Stderr, "enc: --aead requires a 256-bit key")
					os.Exit(1)
				}
				ct, authTag := HskeNlAeadEncrypt(K, nonce, []byte(*ad), msgPad(inBytes, nb))
				pem, err = encodeSymCTTag("hske-nla1", new(big.Int).SetBytes(ct), n,
					nonce.BigInt(), new(big.Int).SetBytes(authTag))
				break
			}
			if isSet(fs, "ad") {
				fmt.Fprintln(os.Stderr, "enc: --ad requires --aead")
				os.Exit(1)
			}
			nla1WidthOK(n, "enc", "key")
			E     := HskeNlA1Encrypt(P, K, nonce)
			pem, err = encodeSymCT("hske-nla1", E.BigInt(), n, nonce.BigInt())
		case "hske-nla2":
			if !NlV2KeyIsValid(K) {
				die("enc hske-nla2", errWeakV2Key)
			}
			E := NlFscxRevolveV2(P, K, 3*n/4)
			pem, err = encodeSymCT("hske-nla2", E.BigInt(), n, nil)
		case "hske-nla3":
			// no key check: v3 has no weak class (TODO #255)
			E := NlFscxRevolveV3(P, K, 5*n/8)
			pem, err = encodeSymCT("hske-nla3", E.BigInt(), n, nil)
		}
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hpke", "hpke-nl", "hpke-nl3":
		if *pubkey == "" {
			fmt.Fprintf(os.Stderr, "enc: --pubkey required for %s\n", *algo)
			os.Exit(1)
		}
		_, theirInts, err := readPEMInts(*pubkey)
		if err != nil {
			die("enc", err)
		}
		n := gfWidth(bytesToInt(theirInts[1]), "enc")
		pubBA := NewBitArray(n, new(big.Int).SetBytes(theirInts[0]))
		if !GfPubIsValid(pubBA) {
			die("enc", errors.New("public key is the GF(2^n)* identity/zero element (rejected: degenerate key)"))
		}
		nb := n / 8
		oneBlockOK(*algo, len(inBytes), nb)
		P := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		// r is ours to choose, so for hpke-nl resample past the ~2^-96 short-arc
		// weak-key class (TODO #168, #354) rather than failing an honest encryption.
		var r *BitArray
		var Rba *BitArray
		var encKey *BitArray
		for i := 0; i < 64; i++ {
			r = NewRandBitArray(n)
			Rba = GfPow(GfGenBA(n), r)
			encKey = GfPow(pubBA, r)
			// hpke-nl3 has no affine-degenerate key class to sample past
			// (SecurityProofs-8.md 11.34.4), so it takes the first draw.
			if *algo != "hpke-nl" || NlV2KeyIsValid(encKey) {
				break
			}
			encKey = nil
		}
		if encKey == nil {
			die("enc hpke-nl", errors.New("could not sample a non-degenerate ephemeral key"))
		}

		var pem string
		switch *algo {
		case "hpke":
			E := FscxRevolve(P, encKey, n/4)
			pem, err = encodeAsymCT(Rba.BigInt(), E.BigInt(), n)
		case "hpke-nl3":
			E := NlFscxRevolveV3(P, encKey, 5*n/8)
			pem, err = encodeAsymCT(Rba.BigInt(), E.BigInt(), n)
		default:
			E := NlFscxRevolveV2(P, encKey, n/4)
			pem, err = encodeAsymCT(Rba.BigInt(), E.BigInt(), n)
		}
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hpke-stern":
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		if *pubkey == "" {
			fmt.Fprintln(os.Stderr, "enc: --pubkey required for hpke-stern")
			os.Exit(1)
		}
		_, theirInts, err := readPEMInts(*pubkey)
		if err != nil {
			die("enc", err)
		}
		n    := sternWireN(theirInts[2], "enc")
		seed := NewBitArray(n, new(big.Int).SetBytes(theirInts[1]))
		nb   := n / 8
		oneBlockOK(*algo, len(inBytes), nb)
		P    := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		K, ctSyn, ePrime := HpkeSternFEncap(seed, n)
		E := FscxRevolve(P, K, n/4)
		pem, err := encodeSternCT(ctSyn, ePrime, K, E.BigInt(), n)
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hpke-stern-kem":
		if *pubkey == "" {
			fmt.Fprintln(os.Stderr, "enc: --pubkey required for hpke-stern-kem")
			os.Exit(1)
		}
		_, theirInts, err := readPEMInts(*pubkey)
		if err != nil {
			die("enc", err)
		}
		hPub := decodeKemPub(theirInts)
		oneBlockOK(*algo, len(inBytes), 32)
		P := NewBitArray(256, new(big.Int).SetBytes(msgPad(inBytes, 32)))
		syn, K := QcMdpcEncap(hPub, nil)
		Kba := NewBitArray(256, new(big.Int).SetBytes(K))
		E := FscxRevolve(P, Kba, 64)
		pem, err := encodeKemCT(syn, E.BigInt())
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	default:
		fmt.Fprintf(os.Stderr, "enc: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
}

// ── dec ───────────────────────────────────────────────────────────────────────

func cmdDec(args []string) {
	fs := flag.NewFlagSet("dec", flag.ExitOnError)
	algo := fs.String("algo", "", "Decryption algorithm")
	key  := fs.String("key", "", "Key or private key file")
	in   := fs.String("in", "-", "Ciphertext PEM input file")
	out  := fs.String("out", "-", "Plaintext output file")
	ad   := fs.String("ad", "", "Associated data for AEAD ciphertexts (must match enc --ad; refused on algos without AEAD)")
	parseArgs(fs, args)
	checkKeyLabels("dec", fs) // TODO #366

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "dec: --algo required")
		os.Exit(1)
	}
	aeadFlagsOK("dec", *algo, isSet(fs, "ad"), false)

	switch *algo {
	case "hske-duplex", "hske-duplex3":
		// HSKE-NL-V2/V3-Duplex AEAD (single-pass) — TODO #118, #255
		dplexV3 := *algo == "hske-duplex3"
		if *key == "" {
			fmt.Fprintf(os.Stderr, "dec: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, keyBits, err := loadKey(*key)
		if err != nil {
			die("dec", err)
		}
		sym256OK(keyBits, "dec "+*algo, "key")
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		wantFmt := 3
		if dplexV3 {
			wantFmt = 4
		}
		if len(ctInts) < 6 || bytesToInt(ctInts[0]) != wantFmt {
			fmt.Fprintf(os.Stderr, "dec: not a V%d-Duplex (format %d) ciphertext\n",
				wantFmt-1, wantFmt)
			os.Exit(1)
		}
		n := bytesToInt(ctInts[5])
		sym256OK(n, "dec "+*algo, "ciphertext")
		K := NewBitArray(n, keyInt)
		nonce := NewBitArray(n, new(big.Int).SetBytes(ctInts[1]))
		// The declared length sizes the buffer.  It cannot exceed the payload
		// field's own upper bound, and the payload cannot be longer than the
		// length claiming to describe it; shorter is legal (DER strips leading
		// zero bytes) and FillBytes zero-pads it.
		derBudget := 0
		for _, it := range ctInts {
			derBudget += len(it)
		}
		ctLen := bounded(wireInt(ctInts[2], "declared ciphertext length", "dec"),
			0, derBudget, "declared ciphertext length", "dec")
		// Compare SIGNIFICANT bytes: an empty payload is the INTEGER 0, one
		// 00 byte in DER, which was refused here from TODO #239 until #370.
		payload := ctInts[3]
		for len(payload) > 0 && payload[0] == 0 {
			payload = payload[1:]
		}
		if len(payload) > ctLen {
			fmt.Fprintf(os.Stderr, "dec: V%d-Duplex ciphertext declares %d bytes "+
				"but carries %d\n", wantFmt-1, ctLen, len(payload))
			os.Exit(1)
		}
		ct := make([]byte, ctLen)
		if ctLen > 0 {
			new(big.Int).SetBytes(ctInts[3]).FillBytes(ct)
		}
		authTag := fitBytes(ctInts[4], 32, "authentication tag", "dec")
		var pt []byte
		var ok bool
		if dplexV3 {
			pt, ok = HskeNlV3DuplexDecrypt(K, nonce, []byte(*ad), ct, authTag)
		} else {
			pt, ok = HskeNlV2DuplexDecrypt(K, nonce, []byte(*ad), ct, authTag)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "dec: authentication tag mismatch — "+
				"ciphertext corrupt, wrong key, or wrong --ad")
			os.Exit(1)
		}
		if err := writeBytes(*out, pt); err != nil {
			die("dec", err)
		}
		return

	case "hske", "hske-nla1", "hske-nla2", "hske-nla3":
		if *key == "" {
			fmt.Fprintf(os.Stderr, "dec: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, keyBits, err := loadKey(*key)
		if err != nil {
			die("dec", err)
		}
		if *algo != "hske-nla1" {
			sym256OK(keyBits, "dec "+*algo, "key")
		}
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		// ctInts[0] = fmt tag; tag 1 → nonce present; tag 2 → AEAD (TODO #95)
		fmtTag := bytesToInt(ctInts[0])
		if fmtTag == 2 {
			if *algo != "hske-nla1" {
				fmt.Fprintln(os.Stderr, "dec: AEAD ciphertext requires --algo hske-nla1")
				os.Exit(1)
			}
			if len(ctInts) != 5 {
				die("dec", checkDerItemsExact(lblCT, ctInts, 5))
			}
			n := wireInt(ctInts[4], "n", "dec")
			nla1WidthOK(n, "dec", "ciphertext")
			K := NewBitArray(n, keyInt)
			nonce := NewBitArray(n, new(big.Int).SetBytes(ctInts[1]))
			ct := fitBytes(ctInts[2], n/8, "ciphertext", "dec")
			authTag := fitBytes(ctInts[3], 32, "authentication tag", "dec")
			pt, ok := HskeNlAeadDecrypt(K, nonce, []byte(*ad), ct, authTag)
			if !ok {
				fmt.Fprintln(os.Stderr, "dec: authentication tag mismatch — "+
					"ciphertext corrupt, wrong key, or wrong --ad")
				os.Exit(1)
			}
			if err := writeBytes(*out, pt); err != nil {
				die("dec", err)
			}
			return
		}
		var EInt, nonceInt *big.Int
		var n int
		if fmtTag == 1 {
			if len(ctInts) != 4 {
				die("dec", checkDerItemsExact(lblCT, ctInts, 4))
			}
			EInt    = new(big.Int).SetBytes(ctInts[2])
			n       = wireInt(ctInts[3], "n", "dec")
			nonceInt = new(big.Int).SetBytes(ctInts[1])
		} else {
			if len(ctInts) != 3 {
				die("dec", checkDerItemsExact(lblCT, ctInts, 3))
			}
			EInt = new(big.Int).SetBytes(ctInts[1])
			n    = wireInt(ctInts[2], "n", "dec")
		}
		if *algo != "hske-nla1" {
			sym256OK(n, "dec "+*algo, "ciphertext")
		} else {
			nla1WidthOK(n, "dec", "ciphertext")
		}
		K := NewBitArray(n, keyInt)
		E := NewBitArray(n, EInt)

		var D *BitArray
		switch *algo {
		case "hske":
			D = FscxRevolve(E, K, 3*n/4)
		case "hske-nla1":
			// TODO #378: format tag 1 has no tag to bind associated data to.
			if isSet(fs, "ad") {
				fmt.Fprintln(os.Stderr, "dec: --ad given, but this hske-nla1 ciphertext "+
					"is not an AEAD one (it has no tag to bind it to)")
				os.Exit(1)
			}
			if nonceInt == nil {
				fmt.Fprintln(os.Stderr, "dec: hske-nla1 ciphertext missing nonce")
				os.Exit(1)
			}
			nla1WidthOK(keyBits, "dec", "key")
			nla1WidthOK(n, "dec", "ciphertext")
			nla1SameWidth(keyBits, n, "dec")
			nonce := NewBitArray(n, nonceInt)
			D      = HskeNlA1Decrypt(E, K, nonce)
		case "hske-nla2":
			if !NlV2KeyIsValid(K) {
				die("dec hske-nla2", errWeakV2Key)
			}
			D = NlFscxRevolveV2Inv(E, K, 3*n/4)
		case "hske-nla3":
			// no key check: v3 has no weak class (TODO #255)
			D = NlFscxRevolveV3Inv(E, K, 5*n/8)
		}
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	case "hpke", "hpke-nl", "hpke-nl3":
		if *key == "" {
			fmt.Fprintf(os.Stderr, "dec: --key required for %s\n", *algo)
			os.Exit(1)
		}
		_, ourInts, err := readPEMInts(*key)
		if err != nil {
			die("dec", err)
		}
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		n    := gfWidth(bytesToInt(ourInts[2]), "dec")
		priv := NewBitArray(n, new(big.Int).SetBytes(ourInts[0]))
		R    := NewBitArray(n, new(big.Int).SetBytes(ctInts[0]))
		if !GfPubIsValid(R) {
			die("dec", errors.New("ciphertext R is the GF(2^n)* identity/zero element (rejected: degenerate key)"))
		}
		EInt := new(big.Int).SetBytes(ctInts[1])
		decKey := GfPow(R, priv)
		E      := NewBitArray(n, EInt)

		var D *BitArray
		switch *algo {
		case "hpke":
			D = FscxRevolve(E, decKey, 3*n/4)
		case "hpke-nl3":
			D = NlFscxRevolveV3Inv(E, decKey, 5*n/8)
		default:
			if !NlV2KeyIsValid(decKey) {
				die("dec hpke-nl", errWeakV2Key)
			}
			D = NlFscxRevolveV2Inv(E, decKey, n/4)
		}
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	case "hpke-stern":
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		if *key == "" {
			fmt.Fprintln(os.Stderr, "dec: --key required for hpke-stern")
			os.Exit(1)
		}
		_, ourInts, err := readPEMInts(*key)
		if err != nil {
			die("dec", err)
		}
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		if len(ctInts) != 5 {
			die("dec", checkDerItemsExact(lblCT, ctInts, 5))
		}
		n       := sternWireN(ourInts[2], "dec")
		seed    := NewBitArray(n, new(big.Int).SetBytes(ourInts[1]))
		ePrime  := NewBitArray(n, new(big.Int).SetBytes(ctInts[1]))
		EInt    := new(big.Int).SetBytes(ctInts[3])
		K_dec   := HpkeSternFDecapKnown(ePrime, seed)
		E       := NewBitArray(n, EInt)
		D       := FscxRevolve(E, K_dec, 3*n/4)
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	case "hpke-stern-kem":
		if *key == "" {
			fmt.Fprintln(os.Stderr, "dec: --key required for hpke-stern-kem")
			os.Exit(1)
		}
		_, ourInts, err := readPEMInts(*key)
		if err != nil {
			die("dec", err)
		}
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		sup0, sup1, _, _ := decodeKemPriv(ourInts)
		syn, EInt := decodeKemCT(ctInts)
		// Implicit rejection (TODO #235): no failure path — a DFR event or a
		// corrupt ciphertext decrypts to garbage rather than reporting.
		K := QcMdpcDecapBgf(syn, sup0, sup1)
		Kba := NewBitArray(256, new(big.Int).SetBytes(K))
		E := NewBitArray(256, EInt)
		D := FscxRevolve(E, Kba, 192)
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	default:
		fmt.Fprintf(os.Stderr, "dec: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
}

// ── sign ──────────────────────────────────────────────────────────────────────

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	algo   := fs.String("algo", "", "Signature algorithm (hpks|hpks-nl|hpks-stern)")
	key    := fs.String("key", "", "Private key file")
	in     := fs.String("in", "-", "Message input file")
	digest := fs.String("digest", "", "Pre-hash: hfscx-256 (default) or none (pad/truncate to 32 bytes)")
	out    := fs.String("out", "-", "Signature PEM output file")
	ring   := fs.String("ring", "", "hpks-ring: comma-separated member public-key PEM paths")
	roundsS := fs.String("rounds", "", "ZKP/Stern-F rounds, 1 to 4096 (nl-zkboo, nl-zkbpp, hpks-stern, hpks-ring; "+
		"default: 219, the 128-bit count every verifier requires unless it passes "+
		"--min-rounds; TODO #364)")
	parseArgs(fs, args)
	checkKeyLabels("sign", fs) // TODO #366
	// TODO #380: an explicit 0 used to read as omitted (219), and 5000 signed
	// a signature every verifier refuses.  0 here means "not given".
	rounds := numFlag(fs, "rounds", roundsS, 1, SdfMaxRounds, 0)
	digestValue("sign", digest)

	if *algo == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "sign: --algo and --key required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil {
		die("sign", err)
	}
	if *digest == "hfscx-256" {
		inBytes = Hfscx256(inBytes, nil)
	}

	zkpRounds := ZkpNlProdRounds
	if rounds > 0 {
		zkpRounds = rounds
	}
	// The CLI default is the 128-bit count, not the suite's SdfRounds demo
	// value: verifiers refuse fewer unless asked (TODO #364).
	sternRounds := SdfProductionRounds
	if rounds > 0 {
		sternRounds = rounds
	}

	// ZKP-NL: raw binary PEM — must not call readPEMInts
	if *algo == "nl-zkboo" {
		body, rerr := readRawPEM(*key, lblZkpNlPriv)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "sign nl-zkboo: %v\n", rerr)
			os.Exit(1)
		}
		A, B, y, zkpN, derr := decodeZkpNlPriv(body)
		if derr != nil {
			die("sign", derr)
		}
		proof, perr := ZkpNlProve(A, B, y, zkpN, zkpRounds, msgPad(inBytes, 32))
		if perr != nil {
			die("sign", perr)
		}
		pem := encodeZkpNlProof(proof, zkpN)
		if werr := writeString(*out, pem); werr != nil {
			die("sign", werr)
		}
		return
	}

	// ZKB++: compact ZKP-NL encoding
	if *algo == "nl-zkbpp" {
		body, rerr := readRawPEM(*key, lblZkpNlPriv)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "sign nl-zkbpp: %v\n", rerr)
			os.Exit(1)
		}
		A, B, y, zkpN, derr := decodeZkpNlPriv(body)
		if derr != nil {
			die("sign", derr)
		}
		proof, perr := ZkpNlProvepp(A, B, y, zkpN, zkpRounds, msgPad(inBytes, 32))
		if perr != nil {
			die("sign", perr)
		}
		pem := encodeZkpNlPpProof(proof, zkpN)
		if werr := writeString(*out, pem); werr != nil {
			die("sign", werr)
		}
		return
	}

	_, ourInts, err := readPEMInts(*key)
	if err != nil {
		die("sign", err)
	}

	switch *algo {
	case "rnl-sigma":
		// derive Cp from stored s and m_blind
		zkpN := rnlWireN(ourInts[2], "sign")
		zkpS := unpackPolyRaw(ourInts[0], zkpN, 4)
		zkpM := unpackPolyRaw(ourInts[1], zkpN, 4)
		ms   := RnlPolyMul(zkpM, zkpS, RnlQ, zkpN)
		zkpCp := RnlRound(ms, RnlQ, RnlP)
		w, c, z, serr := RnlSigmaSign(zkpS, zkpM, zkpCp, zkpN, msgPad(inBytes, 32))
		if serr != nil {
			die("sign", serr)
		}
		pem := encodeZkpRnlProof(w, c, z, zkpN)
		if werr := writeString(*out, pem); werr != nil {
			die("sign", werr)
		}
		return

	case "hpks", "hpks-nl":
		privInt := new(big.Int).SetBytes(ourInts[0])
		n       := gfWidth(bytesToInt(ourInts[2]), "sign")
		msg  := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		priv := NewBitArray(n, privInt)

		// TODO #308: call the suite operation rather than transcribing it.
		// HpksSign/HpksNlSign draw the Schnorr nonce themselves, so the draw
		// this CLI used to make now lands in a censused suite consumer.  e is
		// recomputed here because it travels in the signature PEM and the
		// suite operation returns only (R, s).
		var R *BitArray
		var sBa *BitArray
		var e *BitArray
		if *algo == "hpks" {
			R, sBa = HpksSign(msg, priv)
			e = FscxRevolve(R, msg, n/4)
		} else {
			R, sBa = HpksNlSign(msg, priv)
			e = HpksNlChallenge(R, msg)
		}
		pem, err := encodeSchnorrSig(sBa.BigInt(), R.BigInt(), e.BigInt(), n)
		if err != nil {
			die("sign", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}

	case "hpks-stern":
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		n    := sternWireN(ourInts[2], "sign")
		e    := NewBitArray(n, new(big.Int).SetBytes(ourInts[0]))
		seed := NewBitArray(n, new(big.Int).SetBytes(ourInts[1]))
		msg  := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		sig  := HpksSternFSign(msg, e, seed, sternRounds)
		pem, err := packSternSig(sig, n)
		if err != nil {
			die("sign", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}

	case "hpks-ring":
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		if *ring == "" {
			fmt.Fprintln(os.Stderr, "hpks-ring sign: --ring (comma-separated member public keys) required")
			os.Exit(1)
		}
		n := sternWireN(ourInts[2], "sign")
		e := NewBitArray(n, new(big.Int).SetBytes(ourInts[0]))
		signerSeed := new(big.Int).SetBytes(ourInts[1])
		ringKeys, ringN := loadRingPubkeys(*ring)
		if ringN != n {
			fmt.Fprintf(os.Stderr, "hpks-ring sign: signer n=%d != ring n=%d\n", n, ringN)
			os.Exit(1)
		}
		j := -1
		for idx := range ringKeys {
			if ringKeys[idx].Seed.BigInt().Cmp(signerSeed) == 0 {
				j = idx
				break
			}
		}
		if j < 0 {
			fmt.Fprintln(os.Stderr, "hpks-ring sign: signer's public key is not in --ring "+
				"(run pkey --pubout on the signer key and include it)")
			os.Exit(1)
		}
		// TODO #272: ringMaxK bounds the READER in every CLI (TODO #240), but
		// only C's writer enforced it, so Go signed rings that every verifier
		// -- Go's included -- then refused.
		if len(ringKeys) > ringMaxK {
			fmt.Fprintf(os.Stderr, "hpks-ring sign: ring has %d members, at most %d "+
				"supported (a larger ring produces a signature no CLI will verify)\n",
				len(ringKeys), ringMaxK)
			os.Exit(1)
		}
		msg := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		sig := HpksSternRingSign(msg, e, j, ringKeys, sternRounds)
		pem := encodeRingSig(sig, n)
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}
		fmt.Fprintf(os.Stderr, "Ring signature created (k=%d); signer index is hidden.\n", len(ringKeys))

	case "hpks-wots":
		if wotsIsUsed(*key) {
			fmt.Fprintln(os.Stderr, "sign: this HPKS-WOTS key was already used — WOTS keys "+
				"are ONE-TIME. Generate a fresh key (genpkey --algo hpks-wots).")
			os.Exit(1)
		}
		seed := fitBytes(ourInts[0], 32, "WOTS seed", "sign")
		var leafIdx uint32
		if len(ourInts) >= 2 {
			leafIdx = uint32(wireInt(ourInts[1], "WOTS leaf index", "sign"))
		}
		sig := HpksWotsSign(inBytes, seed, leafIdx)
		pem := encodeWotsBlobPEM(sig, lblHpksWotsSig)
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}
		wotsWriteIdx(*key, 1)
		fmt.Fprintln(os.Stderr, "HPKS-WOTS key burned (one-time use); do not sign again with it.")

	case "hpks-xmss":
		label, xmssInts, rerr := readPEMInts(*key)
		if rerr != nil {
			die("sign", rerr)
		}
		if label != lblHpksXmssPriv {
			fmt.Fprintf(os.Stderr, "sign: expected HPKS-XMSS private key, got %q\n", label)
			os.Exit(1)
		}
		seed := fitBytes(xmssInts[0], 32, "XMSS seed", "sign")
		h := bounded(wireInt(xmssInts[1], "XMSS height", "sign"), 1, xmssMaxH,
			"XMSS height", "sign")
		numLeaves := 1 << uint(h)
		blob := alignBlob(xmssInts[3], numLeaves*32)
		leafHashes := make([][]byte, numLeaves)
		for i := 0; i < numLeaves; i++ {
			leafHashes[i] = blob[i*32 : (i+1)*32]
		}
		kp := &HpksXmssKeypair{MasterSeed: seed, Root: HaccumRoot(leafHashes), LeafHashes: leafHashes}

		leafIdx := xmssReadIdx(*key)
		if leafIdx >= numLeaves {
			fmt.Fprintf(os.Stderr, "sign: XMSS key exhausted (%d leaves used). Generate a new key.\n",
				numLeaves)
			os.Exit(1)
		}
		sig, serr := HpksXmssSign(inBytes, kp, leafIdx)
		if serr != nil {
			die("sign", serr)
		}

		sigBlob := wotsBlobPack(sig.WotsSig)
		pathBlob := make([]byte, 0, len(sig.AuthPath)*32)
		for _, s := range sig.AuthPath {
			pathBlob = append(pathBlob, s...)
		}
		ld, e1 := derIntSmall(leafIdx)
		sd, e2 := derIntBig(new(big.Int).SetBytes(sigBlob), len(sigBlob))
		pd, e3 := derIntBig(new(big.Int).SetBytes(pathBlob), len(pathBlob))
		hd, e4 := derIntSmall(len(sig.AuthPath))
		nd, e5 := derIntSmall(256)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			fmt.Fprintln(os.Stderr, "sign: DER encode error")
			os.Exit(1)
		}
		seq, e6 := DerSeqEnc(ld, sd, pd, hd, nd)
		if e6 != nil {
			die("sign", e6)
		}
		pem := PemWrap(lblHpksXmssSig, seq)
		if werr := writeString(*out, pem); werr != nil {
			die("sign", werr)
		}
		xmssWriteIdx(*key, leafIdx+1)
		fmt.Fprintf(os.Stderr, "XMSS leaf %d used; %d leaves remaining.\n",
			leafIdx, numLeaves-leafIdx-1)

	default:
		fmt.Fprintf(os.Stderr, "sign: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
}

// ── verify ────────────────────────────────────────────────────────────────────

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	algo   := fs.String("algo", "", "Signature algorithm")
	pubkey := fs.String("pubkey", "", "Public key file")
	in     := fs.String("in", "-", "Message input file")
	digest := fs.String("digest", "", "Pre-hash: hfscx-256 (default) or none (pad/truncate to 32 bytes)")
	sig    := fs.String("sig", "", "Signature PEM file")
	ring   := fs.String("ring", "", "hpks-ring: comma-separated member public-key PEM paths")
	minR   := fs.String("min-rounds", strconv.Itoa(cliMinVerifyRounds),
		"Refuse hpks-stern/hpks-ring/nl-zkboo/nl-zkbpp artifacts declaring fewer rounds (TODO #364)")
	parseArgs(fs, args)
	checkKeyLabels("verify", fs) // TODO #366
	digestValue("verify", digest)
	minRounds := numFlag(fs, "min-rounds", minR, 1, SdfMaxRounds, cliMinVerifyRounds) // TODO #380

	if *algo == "" || *sig == "" {
		fmt.Fprintln(os.Stderr, "verify: --algo and --sig required")
		os.Exit(1)
	}
	if *algo != "hpks-t" && *algo != "hpks-ring" && *pubkey == "" {
		fmt.Fprintln(os.Stderr, "verify: --pubkey required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil {
		die("verify", err)
	}
	if *digest == "hfscx-256" {
		inBytes = Hfscx256(inBytes, nil)
	}

	// hpks-ring: anonymous ring verification against --ring members.
	if *algo == "hpks-ring" {
		if *ring == "" {
			fmt.Fprintln(os.Stderr, "hpks-ring verify: --ring (comma-separated member public keys) required")
			os.Exit(1)
		}
		ringKeys, n := loadRingPubkeys(*ring)
		rsig, sigN := decodeRingSig(*sig)
		requireRounds(rsig.Rounds, minRounds, "hpks-ring signature", "verify")
		if sigN != n {
			fmt.Fprintf(os.Stderr, "hpks-ring verify: signature n=%d != ring n=%d\n", sigN, n)
			os.Exit(1)
		}
		if rsig.K != len(ringKeys) {
			fmt.Fprintf(os.Stderr, "hpks-ring verify: signature ring size %d != %d provided members\n",
				rsig.K, len(ringKeys))
			os.Exit(1)
		}
		msg := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		if HpksSternRingVerify(msg, rsig, ringKeys) {
			fmt.Println("Signature OK")
			os.Exit(0)
		}
		fmt.Println("Verification FAILED")
		os.Exit(1)
	}

	// hpks-t: C_agg is embedded in sig — no pubkey file needed.
	if *algo == "hpks-t" {
		// Pass --in, --sig, --digest directly from parsed values.
		tvArgs := []string{"--sig", *sig, "--in", *in}
		// digestValue normalised none to "", which threshold-verify would now
		// read as the hfscx-256 default (TODO #365): forward it explicitly.
		fwd := *digest
		if fwd == "" {
			fwd = "none"
		}
		tvArgs = append(tvArgs, "--digest", fwd)
		cmdThresholdVerify(tvArgs)
		return
	}

	// ZKP-NL: raw binary PEM — must not call readPEMInts
	if *algo == "nl-zkboo" {
		pubBody, rerr := readRawPEM(*pubkey, lblZkpNlPub)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "verify nl-zkboo: %v\n", rerr)
			os.Exit(1)
		}
		B, y, zkpN, derr := decodeZkpNlPub(pubBody)
		if derr != nil {
			die("verify", derr)
		}
		proofBody, perr := readRawPEM(*sig, lblZkpNlProof)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "verify nl-zkboo: %v\n", perr)
			os.Exit(1)
		}
		proof, prfN, uerr := decodeZkpNlProof(proofBody)
		if uerr != nil {
			die("verify", uerr)
		}
		// The proof carries its own n; a proof for a different width is not a
		// proof about this key.  C has always checked this (TODO #275).
		if prfN != zkpN {
			die("verify", fmt.Errorf("proof n mismatch with pubkey n (%d vs %d)", prfN, zkpN))
		}
		requireRounds(len(proof), minRounds, "nl-zkboo proof", "verify")
		if ZkpNlVerify(B, y, zkpN, len(proof), msgPad(inBytes, 32), proof) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}
	}

	// ZKB++: compact ZKP-NL verify
	if *algo == "nl-zkbpp" {
		pubBody, rerr := readRawPEM(*pubkey, lblZkpNlPub)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "verify nl-zkbpp: %v\n", rerr)
			os.Exit(1)
		}
		B, y, zkpN, derr := decodeZkpNlPub(pubBody)
		if derr != nil {
			die("verify", derr)
		}
		proofBody, perr := readRawPEM(*sig, lblZkpNlPpSig)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "verify nl-zkbpp: %v\n", perr)
			os.Exit(1)
		}
		proof, _, uerr := decodeZkpNlPpProof(proofBody)
		if uerr != nil {
			die("verify", uerr)
		}
		requireRounds(len(proof), minRounds, "nl-zkbpp proof", "verify")
		if ZkpNlVerifypp(B, y, zkpN, len(proof), msgPad(inBytes, 32), proof) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}
	}

	_, theirInts, err := readPEMInts(*pubkey)
	if err != nil {
		die("verify", err)
	}

	switch *algo {
	case "rnl-sigma":
		// HKEX-RNL public key: theirInts[0]=C (2B/coeff), theirInts[1]=mBlind (4B/coeff), theirInts[2]=n
		zkpN  := rnlWireN(theirInts[2], "verify")
		zkpCp := unpackPolyRaw(theirInts[0], zkpN, 2)
		zkpM  := unpackPolyRaw(theirInts[1], zkpN, 4)

		proofBody, perr := readRawPEM(*sig, lblZkpRnlProof)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "verify rnl-sigma: %v\n", perr)
			os.Exit(1)
		}
		w, c, z, prfN, derr := decodeZkpRnlProof(proofBody)
		if derr != nil {
			die("verify", derr)
		}
		// A proof over a different ring is not a proof about this key; C and
		// Java both refuse it, and Go reached the verifier instead (TODO #275).
		if prfN != zkpN {
			die("verify", fmt.Errorf("ring size mismatch (pubkey n=%d, proof n=%d)", zkpN, prfN))
		}
		if RnlSigmaVerify(zkpM, zkpCp, zkpN, msgPad(inBytes, 32), w, c, z) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}

	case "hpks", "hpks-nl":
		n   := gfWidth(bytesToInt(theirInts[1]), "verify")
		pub := NewBitArray(n, new(big.Int).SetBytes(theirInts[0]))
		if !GfPubIsValid(pub) {
			die("verify", errors.New("public key is the GF(2^n)* identity/zero element (rejected: degenerate key)"))
		}
		msg := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))

		_, sigInts, err := readPEMInts(*sig)
		if err != nil {
			die("verify", err)
		}
		if len(sigInts) != 4 {
			die("verify", fmt.Errorf("malformed PEM '%s': %d DER items, expected 4", lblSig, len(sigInts)))
		}
		sInt := new(big.Int).SetBytes(sigInts[0])
		R    := new(big.Int).SetBytes(sigInts[1])
		eStored := new(big.Int).SetBytes(sigInts[2])
		if sn := new(big.Int).SetBytes(sigInts[3]); !sn.IsInt64() || sn.Int64() != int64(n) {
			die("verify", fmt.Errorf("signature n is %s, public key n is %d", sn, n))
		}

		// e_v = challenge recomputed from R and msg
		var eV *BitArray
		if *algo == "hpks" {
			eV = FscxRevolve(NewBitArray(n, R), msg, n/4)
		} else {
			eV = HpksNlChallenge(NewBitArray(n, R), msg)
		}
		// Verify: g^s * pub^(e_recomputed) == R  (matches Python verify)
		lhs := GfMul(GfPow(GfGenBA(n), NewBitArray(n, sInt)), GfPow(pub, eV))
		if lhs.BigInt().Cmp(R) != 0 {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}
		// TODO #372: the stored challenge is part of the signature's bytes, so
		// one that is not the recomputed e is a second encoding of the same
		// signature -- refused, as every CLI does.  Checked only once the
		// algebra holds: a wrong message or key changes e too, and stays an
		// ordinary "Verification FAILED".
		if eV.BigInt().Cmp(eStored) != 0 {
			die("verify", errors.New("signature challenge e is not the recomputed one (rejected: non-canonical signature)"))
		}
		fmt.Println("Signature OK")
		os.Exit(0)

	case "hpks-stern":
		fmt.Fprintln(os.Stderr, "WARNING: Stern-F at N=256 provides only ~30-40 bits of security (demo parameters). 128-bit security requires N>=17000. Do not use for production.")
		synInt  := new(big.Int).SetBytes(theirInts[0])
		n       := sternWireN(theirInts[2], "verify")
		seed    := NewBitArray(n, new(big.Int).SetBytes(theirInts[1]))
		msg     := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))

		_, sigInts, err := readPEMInts(*sig)
		if err != nil {
			die("verify", err)
		}
		sternSig, _, err := unpackSternSig(sigInts)
		if err != nil {
			die("verify", err)
		}
		requireRounds(len(sternSig.Rounds), minRounds, "hpks-stern signature", "verify")
		if HpksSternFVerify(msg, sternSig, seed, synInt) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}

	case "hpks-xmss":
		root := alignBlob(theirInts[0], 32)
		_, sigInts, serr := readPEMInts(*sig)
		if serr != nil {
			die("verify", serr)
		}
		leafIdx := wireIntZ(sigInts[0], "XMSS leaf index", "verify")
		depth := bounded(wireInt(sigInts[3], "XMSS signature depth", "verify"),
			1, xmssMaxH, "XMSS signature depth", "verify")
		sig := &HpksXmssSig{
			LeafIdx:  leafIdx,
			WotsSig:  wotsBlobUnpack(sigInts[1]),
			AuthPath: make([][]byte, depth),
		}
		pathBlob := alignBlob(sigInts[2], depth*32)
		for i := 0; i < depth; i++ {
			sig.AuthPath[i] = pathBlob[i*32 : (i+1)*32]
		}
		if HpksXmssVerify(inBytes, sig, root) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}

	case "hpks-wots":
		pk := wotsBlobUnpack(theirInts[0])
		_, sigInts, serr := readPEMInts(*sig)
		if serr != nil {
			die("verify", serr)
		}
		sigArr := wotsBlobUnpack(sigInts[0])
		if HpksWotsVerify(inBytes, sigArr, pk) {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "verify: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
}

// ── encfile / decfile ────────────────────────────────────────────────────────
//
// Binary .hkx container format (HSKE-NL-A1 CTR-mode AEAD):
//   [0:4]         Magic "HKX1"
//   [4]           Algo byte: 0x01 = hske-nla1
//   [5:13]        Plaintext length (big-endian uint64)
//   [13:45]       Nonce N (32 bytes)
//   [45:45+m*32]  Ciphertext blocks (m = ⌈len/32⌉; last block zero-padded)
//   [45+m*32:]    Auth tag: HFSCX-256-MAC(mac_key, nonce‖len‖ciphertext)
//
// Keystream: ks_i = HskeNla1KsBlock(seed, base, i)
// MAC key:   HskeNla1MacKey(seed, base)  [domain-separated via inner ROL]
// MAC IV:    mac_key XOR Hfscx256IV
//
// Where: base = K XOR N_nonce;  seed = base.RotateLeft(32)

const (
	hkxMagic    = "HKX1"
	hkxAlgoNLA1 = byte(0x01)
	hkxHdrSize  = 4 + 1 + 8 + 32 // magic + algo + len8 + nonce32 = 45
	hkxBlock    = 32
	hkxMinSize  = hkxHdrSize + hkxBlock // 45 + 32-byte tag (0-byte plaintext)
)

func cmdEncfile(args []string) {
	fs := flag.NewFlagSet("encfile", flag.ExitOnError)
	algo := fs.String("algo", "hske-nla1", "Encryption algorithm (hske-nla1)")
	key  := fs.String("key", "", "Session key file")
	in   := fs.String("in", "-", "Plaintext input file")
	out  := fs.String("out", "-", "Output .hkx file")
	parseArgs(fs, args)

	if *algo != "hske-nla1" {
		fmt.Fprintf(os.Stderr, "encfile: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
	if *key == "" {
		fmt.Fprintln(os.Stderr, "encfile: --key required")
		os.Exit(1)
	}

	keyInt, nbits, err := loadKey(*key)
	if err != nil {
		die("encfile", err)
	}
	if nbits != 256 {
		fmt.Fprintf(os.Stderr, "encfile: key must be 256-bit; got %d-bit\n", nbits)
		os.Exit(1)
	}

	plaintext, err := readFile(*in)
	if err != nil {
		die("encfile", err)
	}
	ptLen := len(plaintext)
	n := 256

	K     := NewBitArray(n, keyInt)
	nonce := NewRandBitArray(n)
	base  := NewBitArray(n, new(big.Int).Xor(K.BigInt(), nonce.BigInt()))
	seed  := RnlKdfSeed(base) // ROL(base, n/8) XOR DC

	// Encrypt in hkxBlock-byte blocks (last block zero-padded if needed)
	nBlocks := (ptLen + hkxBlock - 1) / hkxBlock
	ctBuf   := make([]byte, nBlocks*hkxBlock)
	for i := 0; i < nBlocks; i++ {
		ks     := HskeNla1KsBlock(seed, base, uint32(i))
		ksBytes := ks.Bytes()
		off    := i * hkxBlock
		for j := 0; j < hkxBlock; j++ {
			pb := byte(0)
			if off+j < ptLen {
				pb = plaintext[off+j]
			}
			ctBuf[off+j] = pb ^ ksBytes[j]
		}
	}

	// MAC key (domain-separated from encryption by inner RotateLeft(64))
	macKey := HskeNla1MacKey(seed, base)
	ivConst := new(big.Int).SetBytes(Hfscx256IV[:])
	macIV  := NewBitArray(n, new(big.Int).Xor(macKey.BigInt(), ivConst))

	// Auth tag: HFSCX-256-MAC over nonce || plaintext_len || ciphertext
	nonceBytes := nonce.Bytes()
	lenBytes    := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(ptLen))
	macData := make([]byte, 0, len(nonceBytes)+8+len(ctBuf))
	macData  = append(macData, nonceBytes...)
	macData  = append(macData, lenBytes...)
	macData  = append(macData, ctBuf...)
	tag := Hfscx256(macData, macIV.Bytes())

	// Assemble .hkx output
	out_ := make([]byte, 0, hkxHdrSize+len(ctBuf)+hkxBlock)
	out_  = append(out_, []byte(hkxMagic)...)
	out_  = append(out_, hkxAlgoNLA1)
	out_  = append(out_, lenBytes...)
	out_  = append(out_, nonceBytes...)
	out_  = append(out_, ctBuf...)
	out_  = append(out_, tag...)

	if err := writeBytes(*out, out_); err != nil {
		die("encfile", err)
	}
}

func cmdDecfile(args []string) {
	fs := flag.NewFlagSet("decfile", flag.ExitOnError)
	algo := fs.String("algo", "hske-nla1", "Decryption algorithm (hske-nla1)")
	key  := fs.String("key", "", "Session key file")
	in   := fs.String("in", "-", "Input .hkx file")
	out  := fs.String("out", "-", "Plaintext output file")
	parseArgs(fs, args)

	if *algo != "hske-nla1" {
		fmt.Fprintf(os.Stderr, "decfile: unsupported algorithm %q\n", *algo)
		os.Exit(1)
	}
	if *key == "" {
		fmt.Fprintln(os.Stderr, "decfile: --key required")
		os.Exit(1)
	}

	keyInt, nbits, err := loadKey(*key)
	if err != nil {
		die("decfile", err)
	}
	if nbits != 256 {
		fmt.Fprintf(os.Stderr, "decfile: key must be 256-bit; got %d-bit\n", nbits)
		os.Exit(1)
	}

	raw, err := readFile(*in)
	if err != nil {
		die("decfile", err)
	}

	// Validate header
	if len(raw) < hkxMinSize {
		fmt.Fprintln(os.Stderr, "decfile: file too short to be a valid .hkx container")
		os.Exit(1)
	}
	if string(raw[:4]) != hkxMagic {
		fmt.Fprintf(os.Stderr, "decfile: invalid magic %q (expected %q)\n", raw[:4], hkxMagic)
		os.Exit(1)
	}
	if raw[4] != hkxAlgoNLA1 {
		fmt.Fprintf(os.Stderr, "decfile: unsupported algo byte 0x%02x\n", raw[4])
		os.Exit(1)
	}

	// Bound the wire length by the file before converting it: a value past
	// 2^63 became a negative int and panicked the slice below (TODO #368).
	ptLen64  := binary.BigEndian.Uint64(raw[5:13])
	if ptLen64 > uint64(len(raw)) {
		fmt.Fprintln(os.Stderr, "decfile: file truncated (ciphertext blocks or auth tag missing)")
		os.Exit(1)
	}
	ptLen    := int(ptLen64)
	nonceBuf := raw[13:45]
	nBlocks  := (ptLen + hkxBlock - 1) / hkxBlock
	ctEnd    := hkxHdrSize + nBlocks*hkxBlock

	if len(raw) < ctEnd+hkxBlock {
		fmt.Fprintln(os.Stderr, "decfile: file truncated (ciphertext blocks or auth tag missing)")
		os.Exit(1)
	}
	// TODO #368: exactly one encoding per file -- nothing after the tag.
	if len(raw) > ctEnd+hkxBlock {
		fmt.Fprintf(os.Stderr, "decfile: %d bytes after the auth tag\n", len(raw)-ctEnd-hkxBlock)
		os.Exit(1)
	}

	ctBytes   := raw[hkxHdrSize:ctEnd]
	tagStored := raw[ctEnd : ctEnd+hkxBlock]

	n := 256
	K     := NewBitArray(n, keyInt)
	nonce := NewBitArray(n, new(big.Int).SetBytes(nonceBuf))
	base  := NewBitArray(n, new(big.Int).Xor(K.BigInt(), nonce.BigInt()))
	seed  := RnlKdfSeed(base) // ROL(base, n/8) XOR DC

	// Recompute MAC and verify before decrypting (verify-then-decrypt)
	macKey  := HskeNla1MacKey(seed, base)
	ivConst := new(big.Int).SetBytes(Hfscx256IV[:])
	macIV   := NewBitArray(n, new(big.Int).Xor(macKey.BigInt(), ivConst))
	lenBuf  := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(ptLen))
	macData := make([]byte, 0, len(nonceBuf)+8+len(ctBytes))
	macData  = append(macData, nonceBuf...)
	macData  = append(macData, lenBuf...)
	macData  = append(macData, ctBytes...)
	tagComputed := Hfscx256(macData, macIV.Bytes())

	if subtle.ConstantTimeCompare(tagStored, tagComputed) != 1 {
		fmt.Fprintln(os.Stderr, "decfile: authentication tag mismatch — file corrupt or wrong key")
		os.Exit(1)
	}

	// Decrypt and trim to exact plaintext length
	plaintext := make([]byte, nBlocks*hkxBlock)
	for i := 0; i < nBlocks; i++ {
		cBlk    := ctBytes[i*hkxBlock : (i+1)*hkxBlock]
		ks      := HskeNla1KsBlock(seed, base, uint32(i))
		ksBytes := ks.Bytes()
		off     := i * hkxBlock
		for j := 0; j < hkxBlock; j++ {
			plaintext[off+j] = cBlk[j] ^ ksBytes[j]
		}
	}

	if err := writeBytes(*out, plaintext[:ptLen]); err != nil {
		die("decfile", err)
	}
}

// ── fpe (78.A) ───────────────────────────────────────────────────────────────

// block32OK — TODO #377: fpe / twk map exactly one 32-byte block.  Longer input
// used to be cut to its first 32 bytes (exit 0, nothing round-tripped), and
// shorter input went through big.Int.SetBytes, which pads on the LEFT where
// Python, C and Java pad on the right, so Go's ciphertext differed from theirs.
// Any other length is now refused rather than reshaped.
func block32OK(cmd string, data []byte) {
	if len(data) != 32 {
		fmt.Fprintf(os.Stderr, "%s: --in must be exactly 32 bytes (one block), got %d\n", cmd, len(data))
		os.Exit(1)
	}
}

func cmdFpe(args []string) {
	fs      := flag.NewFlagSet("fpe", flag.ExitOnError)
	keyPath := fs.String("key",     "",  "Session key PEM")
	ctx     := fs.String("context", "",  "Context string (tweak)")
	in      := fs.String("in",      "-", "Input file (exactly 32 bytes)")
	out     := fs.String("out",     "-", "Output file")
	doEnc   := fs.Bool("encrypt",   false, "Encrypt")
	doDec   := fs.Bool("decrypt",   false, "Decrypt")
	v3      := fs.Bool("v3", false, "Use the NL-FSCX v3 round (TODO #255) "+
		"instead of v2.  Separate subkey domain; decrypt with --v3 too.")
	parseArgs(fs, args)

	// TODO #377: both mode flags used to encrypt; Python and Java refused.
	if *doEnc == *doDec {
		fmt.Fprintln(os.Stderr, "fpe: exactly one of --encrypt or --decrypt required")
		os.Exit(1)
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "fpe: --key required")
		os.Exit(1)
	}
	keyBig, keyBits, err := loadKey(*keyPath)
	if err != nil {
		die("fpe", err)
	}
	sym256OK(keyBits, "fpe", "key")
	K := NewBitArray(256, keyBig)

	data, err := readFile(*in)
	if err != nil {
		die("fpe", err)
	}
	block32OK("fpe", data)
	P := NewBitArray(256, new(big.Int).SetBytes(data))

	var R *BitArray
	switch {
	case *doEnc && *v3:
		R = FpeV3Encrypt(P, K.Bytes(), []byte(*ctx))
	case *doEnc:
		R = FpeEncrypt(P, K.Bytes(), []byte(*ctx))
	case *v3:
		R = FpeV3Decrypt(P, K.Bytes(), []byte(*ctx))
	default:
		R = FpeDecrypt(P, K.Bytes(), []byte(*ctx))
	}
	if err := writeBytes(*out, R.Bytes()); err != nil {
		die("fpe", err)
	}
}

// ── twk (78.B) ───────────────────────────────────────────────────────────────

// decRangeArg is THE numeric-flag parser (TODO #375, #380): a decimal integer
// in [lo, hi], digits only (no sign, space, 0x, _ or exponent), refused by name
// otherwise.  flag.Int took 0x10 as 16 and could not tell an explicit 0 from an
// omitted flag; every numeric flag is now an fs.String read through this, with
// the message the other three CLIs print.
func decRangeArg(s string, lo, hi uint64, cmd, flagName string) uint64 {
	ok := s != ""
	for i := 0; ok && i < len(s); i++ {
		ok = s[i] >= '0' && s[i] <= '9'
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if !ok || err != nil || v < lo || v > hi {
		fmt.Fprintf(os.Stderr, "%s: %s must be a decimal integer from %d to %d, got '%s'\n",
			cmd, flagName, lo, hi, s)
		os.Exit(1)
	}
	return v
}

// numFlag returns the named string flag through decRangeArg, or deflt when the
// flag was not given.
func numFlag(fs *flag.FlagSet, name string, val *string, lo, hi uint64, deflt int) int {
	if !isSet(fs, name) {
		return deflt
	}
	return int(decRangeArg(*val, lo, hi, fs.Name(), "--"+name))
}

func cmdTwk(args []string) {
	fs      := flag.NewFlagSet("twk", flag.ExitOnError)
	keyPath := fs.String("key",     "",  "Session key PEM")
	sector  := fs.String("sector",  "0", "Sector number (decimal, 0 to 2^64-1)")
	bidx    := fs.String("bidx",    "0", "Block index within sector (decimal, 0 to 2^32-1)")
	in      := fs.String("in",      "-", "Input file (exactly 32 bytes)")
	out     := fs.String("out",     "-", "Output file")
	doEnc   := fs.Bool("encrypt",   false, "Encrypt")
	doDec   := fs.Bool("decrypt",   false, "Decrypt")
	v3      := fs.Bool("v3", false, "Use the NL-FSCX v3 round (TODO #255) "+
		"instead of v2.  Separate subkey domain; decrypt with --v3 too.")
	parseArgs(fs, args)

	// TODO #377: both mode flags used to encrypt; Python and Java refused.
	if *doEnc == *doDec {
		fmt.Fprintln(os.Stderr, "twk: exactly one of --encrypt or --decrypt required")
		os.Exit(1)
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "twk: --key required")
		os.Exit(1)
	}
	// TODO #375: the tweak is sector_be64 || bidx_be32.  fs.Uint then
	// uint32(*bidx) wrapped --bidx mod 2^32, so --bidx 4294967296 encrypted
	// under block 0's tweak; flag.Uint also read 0x10 as 16.
	sectorV := decRangeArg(*sector, 0, math.MaxUint64, "twk", "--sector")
	bidxV := uint32(decRangeArg(*bidx, 0, math.MaxUint32, "twk", "--bidx"))
	keyBig, keyBits, err := loadKey(*keyPath)
	if err != nil {
		die("twk", err)
	}
	sym256OK(keyBits, "twk", "key")
	K := NewBitArray(256, keyBig)

	data, err := readFile(*in)
	if err != nil {
		die("twk", err)
	}
	block32OK("twk", data)
	P := NewBitArray(256, new(big.Int).SetBytes(data))

	var R *BitArray
	switch {
	case *doEnc && *v3:
		R = TwkV3Encrypt(P, K.Bytes(), sectorV, bidxV)
	case *doEnc:
		R = TwkEncrypt(P, K.Bytes(), sectorV, bidxV)
	case *v3:
		R = TwkV3Decrypt(P, K.Bytes(), sectorV, bidxV)
	default:
		R = TwkDecrypt(P, K.Bytes(), sectorV, bidxV)
	}
	if err := writeBytes(*out, R.Bytes()); err != nil {
		die("twk", err)
	}
}

// ── oprf-blind / oprf-eval / oprf-unblind  (TODO #80) ────────────────────────

func cmdOprfBlind(args []string) {
	fs    := flag.NewFlagSet("oprf-blind", flag.ExitOnError)
	inF   := fs.String("in", "", "Input bytes file (- for stdin)")
	outF  := fs.String("out", "-", "Output OPRF CLIENT STATE PEM")
	parseArgs(fs, args)
	if *inF == "" {
		fmt.Fprintln(os.Stderr, "oprf-blind: --in required")
		os.Exit(1)
	}
	data, err := readFile(*inF)
	if err != nil {
		die("oprf-blind", err)
	}
	r, alpha, err := OprfBlind(data, 256)
	if err != nil {
		die("oprf-blind", err)
	}
	rDer, e1    := derIntBig(r, 32)
	aDer, e2    := derIntBig(alpha, 32)
	nDer, e3    := derIntSmall(256)
	if e1 != nil || e2 != nil || e3 != nil {
		fmt.Fprintln(os.Stderr, "oprf-blind: DER encode error")
		os.Exit(1)
	}
	seq, e4 := DerSeqEnc(rDer, aDer, nDer)
	if e4 != nil {
		die("oprf-blind", e4)
	}
	if err := writeString(*outF, PemWrap(lblOprfState, seq)); err != nil {
		die("oprf-blind", err)
	}
}

func cmdOprfEval(args []string) {
	fs    := flag.NewFlagSet("oprf-eval", flag.ExitOnError)
	keyF  := fs.String("key", "", "OPRF PRIVATE KEY PEM (server key)")
	inF   := fs.String("in", "", "OPRF CLIENT STATE PEM")
	outF  := fs.String("out", "-", "Output OPRF EVALUATION PEM")
	parseArgs(fs, args)
	checkKeyLabels("oprf-eval", fs) // TODO #366
	if *keyF == "" {
		fmt.Fprintln(os.Stderr, "oprf-eval: --key required")
		os.Exit(1)
	}
	if *inF == "" {
		fmt.Fprintln(os.Stderr, "oprf-eval: --in required")
		os.Exit(1)
	}
	/* Load server key: SEQUENCE(INTEGER(k), INTEGER(256)) */
	kLabel, kInts, err := readPEMInts(*keyF)
	if err != nil {
		die("oprf-eval", err)
	}
	if kLabel != lblOprfPriv {
		fmt.Fprintf(os.Stderr, "oprf-eval: expected OPRF PRIVATE KEY PEM, got %q\n", kLabel)
		os.Exit(1)
	}
	if len(kInts) < 1 {
		fmt.Fprintln(os.Stderr, "oprf-eval: malformed OPRF private key")
		os.Exit(1)
	}
	k := new(big.Int).SetBytes(kInts[0])

	/* Load CLIENT STATE: SEQUENCE(INTEGER(r), INTEGER(alpha), INTEGER(256)) */
	sLabel, sInts, err := readPEMInts(*inF)
	if err != nil {
		die("oprf-eval", err)
	}
	if sLabel != lblOprfState {
		fmt.Fprintf(os.Stderr, "oprf-eval: expected OPRF CLIENT STATE PEM, got %q\n", sLabel)
		os.Exit(1)
	}
	if len(sInts) < 2 {
		fmt.Fprintln(os.Stderr, "oprf-eval: malformed CLIENT STATE PEM")
		os.Exit(1)
	}
	alpha := new(big.Int).SetBytes(sInts[1])

	beta := OprfEval(alpha, k, 256)
	bDer, e1 := derIntBig(beta, 32)
	nDer, e2 := derIntSmall(256)
	if e1 != nil || e2 != nil {
		fmt.Fprintln(os.Stderr, "oprf-eval: DER encode error")
		os.Exit(1)
	}
	seq, e3 := DerSeqEnc(bDer, nDer)
	if e3 != nil {
		die("oprf-eval", e3)
	}
	if err := writeString(*outF, PemWrap(lblOprfEval, seq)); err != nil {
		die("oprf-eval", err)
	}
}

func cmdOprfUnblind(args []string) {
	fs     := flag.NewFlagSet("oprf-unblind", flag.ExitOnError)
	stateF := fs.String("state", "", "OPRF CLIENT STATE PEM")
	evalF  := fs.String("eval",  "", "OPRF EVALUATION PEM")
	outF   := fs.String("out", "-", "Output PRF hex")
	parseArgs(fs, args)
	if *stateF == "" {
		fmt.Fprintln(os.Stderr, "oprf-unblind: --state required")
		os.Exit(1)
	}
	if *evalF == "" {
		fmt.Fprintln(os.Stderr, "oprf-unblind: --eval required")
		os.Exit(1)
	}
	/* CLIENT STATE: (r, alpha, nbits) */
	sLabel, sInts, err := readPEMInts(*stateF)
	if err != nil {
		die("oprf-unblind", err)
	}
	if sLabel != lblOprfState {
		fmt.Fprintf(os.Stderr, "oprf-unblind: expected OPRF CLIENT STATE PEM, got %q\n", sLabel)
		os.Exit(1)
	}
	if len(sInts) < 1 {
		fmt.Fprintln(os.Stderr, "oprf-unblind: malformed CLIENT STATE PEM")
		os.Exit(1)
	}
	r := new(big.Int).SetBytes(sInts[0])

	/* EVALUATION: (beta, nbits) */
	eLabel, eInts, err := readPEMInts(*evalF)
	if err != nil {
		die("oprf-unblind", err)
	}
	if eLabel != lblOprfEval {
		fmt.Fprintf(os.Stderr, "oprf-unblind: expected OPRF EVALUATION PEM, got %q\n", eLabel)
		os.Exit(1)
	}
	if len(eInts) < 1 {
		fmt.Fprintln(os.Stderr, "oprf-unblind: malformed EVALUATION PEM")
		os.Exit(1)
	}
	beta := new(big.Int).SetBytes(eInts[0])

	F := OprfUnblind(beta, r, 256)
	hex := fmt.Sprintf("%064x\n", F)
	if err := writeString(*outF, hex); err != nil {
		die("oprf-unblind", err)
	}
}

func cmdPakeRegister(args []string) {
	fs    := flag.NewFlagSet("pake-register", flag.ExitOnError)
	keyF  := fs.String("key",      "", "OPRF PRIVATE KEY PEM (server key)")
	pwF   := fs.String("password", "", "Password to register (required, non-empty)")
	outF  := fs.String("out",      "-", "Output PAKE RECORD PEM")
	parseArgs(fs, args)
	checkKeyLabels("pake-register", fs) // TODO #366
	if *keyF == "" {
		fmt.Fprintln(os.Stderr, "pake-register: --key required")
		os.Exit(1)
	}
	// TODO #376: a record is never written under a password nobody chose.
	// Before #376 an omitted or empty --password registered "demo-password".
	if !isSet(fs, "password") {
		fmt.Fprintln(os.Stderr, "pake-register: --password required")
		os.Exit(1)
	}
	if *pwF == "" {
		fmt.Fprintln(os.Stderr, "pake-register: --password must not be empty")
		os.Exit(1)
	}
	kLabel, kInts, err := readPEMInts(*keyF)
	if err != nil { die("pake-register", err) }
	if kLabel != lblOprfPriv {
		fmt.Fprintf(os.Stderr, "pake-register: expected OPRF PRIVATE KEY PEM, got %q\n", kLabel)
		os.Exit(1)
	}
	if len(kInts) < 1 {
		fmt.Fprintln(os.Stderr, "pake-register: malformed OPRF private key")
		os.Exit(1)
	}
	oprfKey := new(big.Int).SetBytes(kInts[0])
	pw := []byte(*pwF)
	rec, err := HpakeRegister(pw, oprfKey)
	if err != nil { die("pake-register", err) }

	/* Encode: SEQUENCE(INTEGER(salt,32), INTEGER(B,4), INTEGER(y,4)) */
	saltDer, e1 := DerIntEnc(rec.Salt[:])
	bBuf := []byte{byte(rec.B >> 24), byte(rec.B >> 16), byte(rec.B >> 8), byte(rec.B)}
	yBuf := []byte{byte(rec.Y >> 24), byte(rec.Y >> 16), byte(rec.Y >> 8), byte(rec.Y)}
	bDer, e2 := DerIntEnc(bBuf)
	yDer, e3 := DerIntEnc(yBuf)
	if e1 != nil || e2 != nil || e3 != nil {
		fmt.Fprintln(os.Stderr, "pake-register: DER encode error")
		os.Exit(1)
	}
	seq, err := DerSeqEnc(saltDer, bDer, yDer)
	if err != nil { die("pake-register", err) }
	if err := writeString(*outF, PemWrap(lblPakeRecord, seq)); err != nil {
		die("pake-register", err)
	}
}

func cmdPakeDemo(args []string) {
	fs   := flag.NewFlagSet("pake-demo", flag.ExitOnError)
	keyF := fs.String("key",      "", "OPRF PRIVATE KEY PEM (server key)")
	pwF  := fs.String("password", "demo-password", "Password")
	parseArgs(fs, args)
	checkKeyLabels("pake-demo", fs) // TODO #366
	if *keyF == "" {
		fmt.Fprintln(os.Stderr, "pake-demo: --key required")
		os.Exit(1)
	}
	// TODO #376: omitted, the demo uses "demo-password"; given, it must be one.
	if *pwF == "" {
		fmt.Fprintln(os.Stderr, "pake-demo: --password must not be empty")
		os.Exit(1)
	}
	kLabel, kInts, err := readPEMInts(*keyF)
	if err != nil { die("pake-demo", err) }
	if kLabel != lblOprfPriv {
		fmt.Fprintf(os.Stderr, "pake-demo: expected OPRF PRIVATE KEY PEM, got %q\n", kLabel)
		os.Exit(1)
	}
	if len(kInts) < 1 {
		fmt.Fprintln(os.Stderr, "pake-demo: malformed OPRF private key")
		os.Exit(1)
	}
	oprfKey := new(big.Int).SetBytes(kInts[0])
	pw := []byte(*pwF)

	rec, err := HpakeRegister(pw, oprfKey)
	if err != nil { die("pake-demo", err) }

	sk, err := HpakeLoginDemo(rec, pw, oprfKey)
	if err != nil { die("pake-demo", err) }
	if sk != nil {
		fmt.Printf("- aPAKE login succeeded; session key: %x\n", sk)
	} else {
		fmt.Fprintln(os.Stderr, "+ aPAKE login failed!")
		os.Exit(1)
	}
	skBad, _ := HpakeLoginDemo(rec, []byte("wrong-password"), oprfKey)
	if skBad == nil {
		fmt.Println("- aPAKE correctly rejects wrong password")
	} else {
		fmt.Println("+ aPAKE accepted wrong password! (security failure)")
		os.Exit(1)
	}
}

// ── main ─────────────────────────────────────────────────────────────────────

// errWeakV2Key is returned when an NL-FSCX v2 key falls in the short-arc weak-key
// class arc(delta(K)) <= n/4 (SecurityProofs-10.md 11.81, TODO #168, #354).
var errWeakV2Key = errors.New(
	"NL-FSCX v2 weak key - the set bits of delta(K) lie in a cyclic arc of at " +
		"most n/4 bits (this includes delta(K) = 0 and 2^(n-1), which make the " +
		"permutation GF(2)-affine); use a uniformly random key " +
		"(SecurityProofs-10.md 11.81, TODO #168, #354)")

func die(prefix string, err error) {
	fmt.Fprintln(os.Stderr, prefix+":", err)
	os.Exit(1)
}

// cliMinVerifyRounds is the verifier's round-count floor (TODO #364).  The
// round count travels in the artifact (TODO #236), so a verifier taking it from
// there let the SIGNER choose the verifier's soundness: one Stern-F or
// ZKBoo-(2,3) round can be answered without the witness for two of its three
// challenges, and under Fiat-Shamir a forger grinds the commitment until the
// challenge is one of those.  219 is the 128-bit count ((2/3)^219 < 2^-128);
// `verify` / `cred-verify --min-rounds N` lowers it.
const cliMinVerifyRounds = 219 // == SdfProductionRounds == ZkpNlProdRounds

func requireRounds(rounds, floor int, what, cmd string) {
	if rounds >= floor {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %s declares %d rounds, below the --min-rounds floor of %d "+
		"(%d = 128-bit Fiat-Shamir soundness); pass --min-rounds %d to accept it anyway\n",
		cmd, what, rounds, floor, cliMinVerifyRounds, rounds)
	os.Exit(1)
}

// digestValue validates --digest's value set in one place (TODO #269).
//
// Every call site tests `*digest == "hfscx-256"` and falls through to the
// raw-message path otherwise, so an unrecognised value used to be accepted
// SILENTLY and signed the message unhashed -- `--digest hfscx256`, one missing
// hyphen, produced a raw signature while reporting success. That is fail-OPEN on
// the weaker branch, and TODO #267's flag matrix cannot see it: the matrix knows
// only that the flag exists. Python rejects via argparse choices= and Java by
// name; this makes Go agree. `none` is normalised to "" so the call sites are
// unchanged.
//
// TODO #365: an absent --digest means hfscx-256.  The old default, none,
// padded/truncated the message to the key width, so a signature on one file
// verified for every file sharing its first 32 bytes.  The flags are declared
// with "" so that this function, not four declarations, owns the default.
func digestValue(cmd string, digest *string) {
	if *digest == "" {
		*digest = "hfscx-256"
		return
	}
	if *digest == "none" {
		*digest = ""
		return
	}
	if *digest != "" && *digest != "hfscx-256" {
		fmt.Fprintf(os.Stderr, "%s: unsupported --digest %q (choices: none, hfscx-256)\n", cmd, *digest)
		os.Exit(1)
	}
}

// usage prints the generated synopsis -- every subcommand, the flags its
// handler reads and its --algo tags -- and then the notes a synopsis cannot
// carry.  Only the notes are hand-written, so the list cannot drift from
// dispatch again (TODO #339).
func usage(w io.Writer) {
	fmt.Fprint(w, "Usage: herradura_cli_go <command> [options]\n\n")
	fmt.Fprint(w, helpSynopsis)
	fmt.Fprint(w, `
Notes:
  kex --algo hkex-rnl is 2-round: Bob responds first (--their alice_pub.pem),
      then Alice completes with Bob's response PEM.
  kex --algo hybrid-rnl-stern: --their-kem FILE (Bob step) | --our-kem FILE (Alice step)
  kex --kdf none|hfscx-256: both sides must pass the same value.
  sign/verify --algo hpks-ring --ring p0_pub.pem,p1_pub.pem,... : code-based ring signature
  sign --algo hpks-wots is ONE-TIME: a WOTS key may sign exactly once.
  encfile/decfile: hske-nla1 only (stream CTR-AEAD); decfile exits non-zero on auth failure.
  fpe: NOT format-preserving in the FF1/FF3-1 sense: no radix, no domain --
       32 bytes in, 32 raw bytes out. See SECURITY.md.
  PEM output goes to stdout when --out is '-', or is omitted where it is optional.
`)
}

// TODO #366: which key labels each (subcommand, --algo, key flag) accepts.  The
// table is generated from spec/generate_spec.py's KEY_LABEL_SITES, which holds
// the reasoning; C, Python and Java carry the same rows.
type keySite struct {
	cmd, algo, flag, tags string
	labels                []string
}

// BEGIN GENERATED key-label table (spec/generate_spec.py, TODO #366) -- DO NOT EDIT.
var keySites = []keySite{
	{"kex", "hkex-gf", "--our", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PRIVATE KEY", "HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY", "HERRADURA HPKE PRIVATE KEY", "HERRADURA HPKE-NL PRIVATE KEY"}},
	{"kex", "hkex-gf", "--their", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PUBLIC KEY", "HERRADURA HPKS PUBLIC KEY", "HERRADURA HPKS-NL PUBLIC KEY", "HERRADURA HPKE PUBLIC KEY", "HERRADURA HPKE-NL PUBLIC KEY"}},
	{"kex", "hkex-rnl", "--our", "hkex-rnl", []string{"HERRADURA HKEX-RNL PRIVATE KEY"}},
	{"kex", "hkex-rnl", "--their", "hkex-rnl", []string{"HERRADURA HKEX-RNL PUBLIC KEY"}},
	{"kex", "hybrid-rnl-stern", "--our", "hkex-rnl", []string{"HERRADURA HKEX-RNL PRIVATE KEY"}},
	{"kex", "hybrid-rnl-stern", "--their", "hkex-rnl", []string{"HERRADURA HKEX-RNL PUBLIC KEY"}},
	{"kex", "hybrid-rnl-stern", "--our-kem", "hpke-stern-kem", []string{"HERRADURA HPKE-STERN-KEM PRIVATE KEY"}},
	{"kex", "hybrid-rnl-stern", "--their-kem", "hpke-stern-kem", []string{"HERRADURA HPKE-STERN-KEM PUBLIC KEY"}},
	{"enc", "hpke", "--pubkey", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PUBLIC KEY", "HERRADURA HPKS PUBLIC KEY", "HERRADURA HPKS-NL PUBLIC KEY", "HERRADURA HPKE PUBLIC KEY", "HERRADURA HPKE-NL PUBLIC KEY"}},
	{"dec", "hpke", "--key", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PRIVATE KEY", "HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY", "HERRADURA HPKE PRIVATE KEY", "HERRADURA HPKE-NL PRIVATE KEY"}},
	{"enc", "hpke-nl", "--pubkey", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PUBLIC KEY", "HERRADURA HPKS PUBLIC KEY", "HERRADURA HPKS-NL PUBLIC KEY", "HERRADURA HPKE PUBLIC KEY", "HERRADURA HPKE-NL PUBLIC KEY"}},
	{"dec", "hpke-nl", "--key", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PRIVATE KEY", "HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY", "HERRADURA HPKE PRIVATE KEY", "HERRADURA HPKE-NL PRIVATE KEY"}},
	{"enc", "hpke-nl3", "--pubkey", "hpke-nl3", []string{"HERRADURA HPKE-NL3 PUBLIC KEY"}},
	{"dec", "hpke-nl3", "--key", "hpke-nl3", []string{"HERRADURA HPKE-NL3 PRIVATE KEY"}},
	{"enc", "hpke-stern", "--pubkey", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PUBLIC KEY", "HERRADURA HPKE-STERN PUBLIC KEY"}},
	{"dec", "hpke-stern", "--key", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PRIVATE KEY", "HERRADURA HPKE-STERN PRIVATE KEY"}},
	{"enc", "hpke-stern-kem", "--pubkey", "hpke-stern-kem", []string{"HERRADURA HPKE-STERN-KEM PUBLIC KEY"}},
	{"dec", "hpke-stern-kem", "--key", "hpke-stern-kem", []string{"HERRADURA HPKE-STERN-KEM PRIVATE KEY"}},
	{"sign", "hpks", "--key", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PRIVATE KEY", "HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY", "HERRADURA HPKE PRIVATE KEY", "HERRADURA HPKE-NL PRIVATE KEY"}},
	{"verify", "hpks", "--pubkey", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PUBLIC KEY", "HERRADURA HPKS PUBLIC KEY", "HERRADURA HPKS-NL PUBLIC KEY", "HERRADURA HPKE PUBLIC KEY", "HERRADURA HPKE-NL PUBLIC KEY"}},
	{"sign", "hpks-nl", "--key", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PRIVATE KEY", "HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY", "HERRADURA HPKE PRIVATE KEY", "HERRADURA HPKE-NL PRIVATE KEY"}},
	{"verify", "hpks-nl", "--pubkey", "hkex-gf, hpks, hpks-nl, hpke, hpke-nl", []string{"HERRADURA HKEX-GF PUBLIC KEY", "HERRADURA HPKS PUBLIC KEY", "HERRADURA HPKS-NL PUBLIC KEY", "HERRADURA HPKE PUBLIC KEY", "HERRADURA HPKE-NL PUBLIC KEY"}},
	{"sign", "hpks-stern", "--key", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PRIVATE KEY", "HERRADURA HPKE-STERN PRIVATE KEY"}},
	{"verify", "hpks-stern", "--pubkey", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PUBLIC KEY", "HERRADURA HPKE-STERN PUBLIC KEY"}},
	{"sign", "hpks-ring", "--key", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PRIVATE KEY", "HERRADURA HPKE-STERN PRIVATE KEY"}},
	{"verify", "hpks-ring", "--ring", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PUBLIC KEY", "HERRADURA HPKE-STERN PUBLIC KEY"}},
	{"sign", "rnl-sigma", "--key", "hkex-rnl", []string{"HERRADURA HKEX-RNL PRIVATE KEY"}},
	{"verify", "rnl-sigma", "--pubkey", "hkex-rnl", []string{"HERRADURA HKEX-RNL PUBLIC KEY"}},
	{"sign", "nl-zkboo", "--key", "hpks-zkp-nl", []string{"HERRADURA ZKP-NL PRIVATE KEY"}},
	{"verify", "nl-zkboo", "--pubkey", "hpks-zkp-nl", []string{"HERRADURA ZKP-NL PUBLIC KEY"}},
	{"sign", "nl-zkbpp", "--key", "hpks-zkp-nl", []string{"HERRADURA ZKP-NL PRIVATE KEY"}},
	{"verify", "nl-zkbpp", "--pubkey", "hpks-zkp-nl", []string{"HERRADURA ZKP-NL PUBLIC KEY"}},
	{"sign", "hpks-xmss", "--key", "hpks-xmss", []string{"HERRADURA HPKS-XMSS PRIVATE KEY"}},
	{"verify", "hpks-xmss", "--pubkey", "hpks-xmss", []string{"HERRADURA HPKS-XMSS PUBLIC KEY"}},
	{"sign", "hpks-wots", "--key", "hpks-wots", []string{"HERRADURA HPKS-WOTS PRIVATE KEY"}},
	{"verify", "hpks-wots", "--pubkey", "hpks-wots", []string{"HERRADURA HPKS-WOTS PUBLIC KEY"}},
	{"threshold-commit", "", "--key", "hpks, hpks-nl", []string{"HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY"}},
	{"threshold-respond", "", "--key", "hpks, hpks-nl", []string{"HERRADURA HPKS PRIVATE KEY", "HERRADURA HPKS-NL PRIVATE KEY"}},
	{"oprf-eval", "", "--key", "oprf", []string{"HERRADURA OPRF PRIVATE KEY"}},
	{"pake-register", "", "--key", "oprf", []string{"HERRADURA OPRF PRIVATE KEY"}},
	{"pake-demo", "", "--key", "oprf", []string{"HERRADURA OPRF PRIVATE KEY"}},
	{"cred-issue", "", "--our", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PRIVATE KEY", "HERRADURA HPKE-STERN PRIVATE KEY"}},
	{"cred-issue", "", "--in", "hcred", []string{"HERRADURA HCRED PUBLIC KEY", "HERRADURA HCRED PRIVATE KEY"}},
	{"cred-prove", "", "--in", "hcred", []string{"HERRADURA HCRED PRIVATE KEY"}},
	{"cred-verify", "", "--pubkey", "hcred", []string{"HERRADURA HCRED PUBLIC KEY", "HERRADURA HCRED PRIVATE KEY"}},
	{"cred-verify", "", "--issuer", "hpks-stern, hpke-stern", []string{"HERRADURA HPKS-STERN PUBLIC KEY", "HERRADURA HPKE-STERN PUBLIC KEY"}},
}

// TODO #367: DER INTEGER items each DER-SEQUENCE label carries (min, max).
var derItems = map[string][2]int{
	"HERRADURA CIPHERTEXT": {3, 6},
	"HERRADURA DIGEST": {1, 1},
	"HERRADURA ENCRYPTED PRIVATE KEY": {6, 6},
	"HERRADURA HCRED CREDENTIAL": {5, 5},
	"HERRADURA HDRBG STATE": {2, 2},
	"HERRADURA HKEX-GF PRIVATE KEY": {3, 3},
	"HERRADURA HKEX-GF PUBLIC KEY": {2, 2},
	"HERRADURA HKEX-RNL PRIVATE KEY": {3, 4},
	"HERRADURA HKEX-RNL PUBLIC KEY": {3, 4},
	"HERRADURA HKEX-RNL RESPONSE": {5, 6},
	"HERRADURA HPKE PRIVATE KEY": {3, 3},
	"HERRADURA HPKE PUBLIC KEY": {2, 2},
	"HERRADURA HPKE-NL PRIVATE KEY": {3, 3},
	"HERRADURA HPKE-NL PUBLIC KEY": {2, 2},
	"HERRADURA HPKE-NL3 PRIVATE KEY": {3, 3},
	"HERRADURA HPKE-NL3 PUBLIC KEY": {2, 2},
	"HERRADURA HPKE-STERN PRIVATE KEY": {3, 3},
	"HERRADURA HPKE-STERN PUBLIC KEY": {3, 3},
	"HERRADURA HPKE-STERN-KEM PRIVATE KEY": {6, 6},
	"HERRADURA HPKE-STERN-KEM PUBLIC KEY": {2, 2},
	"HERRADURA HPKS PRIVATE KEY": {3, 3},
	"HERRADURA HPKS PUBLIC KEY": {2, 2},
	"HERRADURA HPKS-NL PRIVATE KEY": {3, 3},
	"HERRADURA HPKS-NL PUBLIC KEY": {2, 2},
	"HERRADURA HPKS-RING SIGNATURE": {4, 4},
	"HERRADURA HPKS-STERN PRIVATE KEY": {3, 3},
	"HERRADURA HPKS-STERN PUBLIC KEY": {3, 3},
	"HERRADURA HPKS-WOTS PRIVATE KEY": {2, 2},
	"HERRADURA HPKS-WOTS PUBLIC KEY": {2, 2},
	"HERRADURA HPKS-WOTS SIGNATURE": {2, 2},
	"HERRADURA HPKS-XMSS PRIVATE KEY": {4, 4},
	"HERRADURA HPKS-XMSS PUBLIC KEY": {2, 2},
	"HERRADURA HPKS-XMSS SIGNATURE": {5, 5},
	"HERRADURA HPKST AGGREGATE": {4, 4},
	"HERRADURA HPKST COMMITMENT": {3, 3},
	"HERRADURA HPKST NONCE": {2, 2},
	"HERRADURA HPKST PARTIAL": {2, 2},
	"HERRADURA HPKST SIGNATURE": {4, 4},
	"HERRADURA HYBRID-RNL-STERN RESPONSE": {8, 8},
	"HERRADURA OPRF CLIENT STATE": {3, 3},
	"HERRADURA OPRF EVALUATION": {2, 2},
	"HERRADURA OPRF PRIVATE KEY": {2, 2},
	"HERRADURA PAKE RECORD": {3, 3},
	"HERRADURA SESSION KEY": {2, 2},
	"HERRADURA SIGNATURE": {4, 5},
}

// TODO #372 / #373: per DER-SEQUENCE label, each field's width cap
// (significant bytes), its encoding (exactly its width, or minimal) and the
// value rules.  ew[k] is field k's encoded width, lz[k] 1 when it starts with
// a 0x00 the sign does not need, 2 with a sign byte.  Returns the refusal, or "".
func derFieldCheck(label string, v [][]byte, ew []int, lz []uint8) string {
	n := len(v)
	L := func(k int) int64 {
		b := v[k]
		for len(b) > 0 && b[0] == 0 {
			b = b[1:]
		}
		return int64(len(b))
	}
	F := func(k int) int64 {
		if L(k) > 6 {
			return -1
		}
		var x int64
		for _, c := range v[k] {
			x = x<<8 | int64(c)
		}
		return x
	}
	_ = F
	switch label {
	case "HERRADURA HKEX-GF PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HKEX-GF PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKS PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKS PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKS-NL PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKS-NL PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKE PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKE-NL PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE-NL PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKE-NL3 PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE-NL3 PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HKEX-RNL PRIVATE KEY":
		if n >= 3 && n <= 4 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(2) * 4); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2) * 4); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(32); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if c := int64(F(2) * 4); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2) * 4); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if e := hkxRuleCoef(label, 0, v[0], 4, int64(F(2)), 65537, true); e != "" {
				return e
			}
			if e := hkxRuleCoef(label, 1, v[1], 4, int64(F(2)), 65537, false); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HKEX-RNL PUBLIC KEY":
		if n >= 3 && n <= 4 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(2) * 2); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2) * 4); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(32); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if c := int64(F(2) * 2); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2) * 4); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if e := hkxRuleCoef(label, 0, v[0], 2, int64(F(2)), 4096, false); e != "" {
				return e
			}
			if e := hkxRuleCoef(label, 1, v[1], 4, int64(F(2)), 65537, false); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HKEX-RNL RESPONSE":
		if n >= 5 && n <= 6 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(32); n > 5 && L(5) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 5, L(5), c)
			}
			if c := int64(F(3) * 2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if c := int64(32); n > 5 && !(int64(ew[5]) == c || (lz[5] == 2 && int64(ew[5])+1 == c) || (c == 0 && ew[5] == 1 && L(5) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 5, ew[5], c)
			}
			if c := int64(F(3) * 2); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if e := hkxRuleCoef(label, 1, v[1], 2, int64(F(3)), 4096, false); e != "" {
				return e
			}
			if e := hkxRuleEquals(label, 4, F(4), int64(F(3)/2)); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HYBRID-RNL-STERN RESPONSE":
		if n >= 8 && n <= 8 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(32); n > 5 && L(5) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 5, L(5), c)
			}
			if c := int64(2); n > 7 && L(7) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 7, L(7), c)
			}
			if c := int64(F(3) * 2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(7) + 7)/8); n > 6 && L(6) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 6, L(6), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if c := int64(32); n > 5 && !(int64(ew[5]) == c || (lz[5] == 2 && int64(ew[5])+1 == c) || (c == 0 && ew[5] == 1 && L(5) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 5, ew[5], c)
			}
			if n > 7 && lz[7] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 7)
			}
			if c := int64(F(3) * 2); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64((F(7) + 7)/8); n > 6 && !(int64(ew[6]) == c || (lz[6] == 2 && int64(ew[6])+1 == c) || (c == 0 && ew[6] == 1 && L(6) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 6, ew[6], c)
			}
			if e := hkxRuleCoef(label, 1, v[1], 2, int64(F(3)), 4096, false); e != "" {
				return e
			}
			if e := hkxRuleEquals(label, 4, F(4), int64(F(3)/2)); e != "" {
				return e
			}
			if e := hkxRuleBits(label, 6, v[6], int64(F(7)), false); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HPKS-STERN PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKS-STERN PUBLIC KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE-STERN PRIVATE KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE-STERN PUBLIC KEY":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKE-STERN-KEM PRIVATE KEY":
		if n >= 6 && n <= 6 {
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(2); n > 5 && L(5) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 5, L(5), c)
			}
			if c := int64((F(4) + 7)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64((F(4) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(5) * 2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(5) * 2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if n > 5 && lz[5] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 5)
			}
			if c := int64((F(4) + 7)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64((F(4) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(5) * 2); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64(F(5) * 2); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if e := hkxRuleSupport(label, 2, v[2], int64(F(5)), int64(F(4))); e != "" {
				return e
			}
			if e := hkxRuleSupport(label, 3, v[3], int64(F(5)), int64(F(4))); e != "" {
				return e
			}
			if e := hkxRuleLePolyOf(label, 0, v[0], 2, v[2], int64(F(5)), int64(F(4))); e != "" {
				return e
			}
			if e := hkxRuleLePolyOf(label, 1, v[1], 3, v[3], int64(F(5)), int64(F(4))); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HPKE-STERN-KEM PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64((F(1) + 7)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64((F(1) + 7)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if e := hkxRuleBits(label, 0, v[0], int64(F(1)), true); e != "" {
				return e
			}
			return ""
		}
	case "HERRADURA HPKS-WOTS PRIVATE KEY":
		if n >= 2 && n <= 2 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(4); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			return ""
		}
	case "HERRADURA HPKS-WOTS PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1) * 32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1) * 32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKS-WOTS SIGNATURE":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1) * 32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1) * 32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKS-XMSS PRIVATE KEY":
		if n >= 4 && n <= 4 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(1); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(4); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32 * (1 << hkxMin(F(1), 32))); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(32 * (1 << hkxMin(F(1), 32))); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			return ""
		}
	case "HERRADURA HPKS-XMSS PUBLIC KEY":
		if n >= 2 && n <= 2 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(1); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			return ""
		}
	case "HERRADURA HPKS-XMSS SIGNATURE":
		if n >= 5 && n <= 5 {
			if c := int64(4); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(1); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(67 * (F(4)/8)); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3) * 32); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if c := int64(67 * (F(4)/8)); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3) * 32); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
	case "HERRADURA HPKS-RING SIGNATURE":
		if n >= 4 && n <= 4 {
			if c := int64(1); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(0) * F(1) * (5 * (F(2)/8) + 1)); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(0) * F(1) * (5 * (F(2)/8) + 1)); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			return ""
		}
	case "HERRADURA OPRF PRIVATE KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA OPRF CLIENT STATE":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA OPRF EVALUATION":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA PAKE RECORD":
		if n >= 3 && n <= 3 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(4); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(4); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(4); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(4); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
	case "HERRADURA HPKST COMMITMENT":
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(2)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(2)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(F(2)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(2)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
	case "HERRADURA HPKST NONCE":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKST AGGREGATE":
		if n >= 4 && n <= 4 {
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(3)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(3)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if c := int64(F(3)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(3)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
	case "HERRADURA HPKST PARTIAL":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HPKST SIGNATURE":
		if n >= 4 && n <= 4 {
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(3)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(3)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if c := int64(F(3)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(3)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
	case "HERRADURA HCRED CREDENTIAL":
		if n >= 5 && n <= 5 {
			if c := int64(2); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1) * 3 * (F(0)/8)); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(1) + 3)/4); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(1) * 2 * (F(0)/8)); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1) * 3 * (F(0)/8)); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64((F(1) + 3)/4); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if c := int64(F(1) * 2 * (F(0)/8)); n > 4 && !(int64(ew[4]) == c || (lz[4] == 2 && int64(ew[4])+1 == c) || (c == 0 && ew[4] == 1 && L(4) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 4, ew[4], c)
			}
			return ""
		}
	case "HERRADURA SESSION KEY":
		if n >= 2 && n <= 2 {
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			return ""
		}
	case "HERRADURA DIGEST":
		if n >= 1 && n <= 1 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			return ""
		}
	case "HERRADURA HDRBG STATE":
		if n >= 2 && n <= 2 {
			if c := int64(32); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(32); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			return ""
		}
	case "HERRADURA ENCRYPTED PRIVATE KEY":
		if n >= 6 && n <= 6 {
			if c := int64(16); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(4); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(32); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(4); n > 5 && L(5) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 5, L(5), c)
			}
			if c := int64(F(5)); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(16); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(32); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64(32); n > 4 && !(int64(ew[4]) == c || (lz[4] == 2 && int64(ew[4])+1 == c) || (c == 0 && ew[4] == 1 && L(4) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 4, ew[4], c)
			}
			if n > 5 && lz[5] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 5)
			}
			if c := int64(F(5)); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			return ""
		}
	case "HERRADURA CIPHERTEXT":
		if n >= 3 && n <= 3 && (F(2) == 12323) {
			if c := int64(32); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(2) + 7)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(32); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64((F(2) + 7)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if e := hkxRuleBits(label, 0, v[0], int64(F(2)), true); e != "" {
				return e
			}
			return ""
		}
		if n >= 3 && n <= 3 && (F(0) == 0) {
			if c := int64(1); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(2) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64((F(2) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
		if n >= 3 && n <= 3 {
			if c := int64(2); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(2) + 7)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64((F(2) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64((F(2) + 7)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64((F(2) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			return ""
		}
		if n >= 4 && n <= 4 {
			if c := int64(1); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64((F(3) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64((F(3) + 7)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if c := int64((F(3) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64((F(3) + 7)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
		if n >= 5 && n <= 5 && (F(0) == 2) {
			if c := int64(1); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(32); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64((F(4) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64((F(4) + 7)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if c := int64(32); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if c := int64((F(4) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64((F(4) + 7)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
		if n >= 5 && n <= 5 {
			if c := int64(2); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(F(4)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(4)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(4)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(F(4)/8); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if n > 4 && lz[4] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 4)
			}
			if c := int64(F(4)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(4)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(4)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64(F(4)/8); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			return ""
		}
		if n >= 6 && n <= 6 {
			if c := int64(1); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(6); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64(32); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if c := int64(2); n > 5 && L(5) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 5, L(5), c)
			}
			if c := int64((F(5) + 7)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(2)); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 2 && lz[2] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 2)
			}
			if c := int64(32); n > 4 && !(int64(ew[4]) == c || (lz[4] == 2 && int64(ew[4])+1 == c) || (c == 0 && ew[4] == 1 && L(4) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 4, ew[4], c)
			}
			if n > 5 && lz[5] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 5)
			}
			if c := int64((F(5) + 7)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(2)); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			return ""
		}
	case "HERRADURA SIGNATURE":
		if n >= 4 && n <= 4 {
			if c := int64(2); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(3)/8); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(F(3)/8); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(3)/8); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if n > 3 && lz[3] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 3)
			}
			if c := int64(F(3)/8); n > 0 && !(int64(ew[0]) == c || (lz[0] == 2 && int64(ew[0])+1 == c) || (c == 0 && ew[0] == 1 && L(0) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 0, ew[0], c)
			}
			if c := int64(F(3)/8); n > 1 && !(int64(ew[1]) == c || (lz[1] == 2 && int64(ew[1])+1 == c) || (c == 0 && ew[1] == 1 && L(1) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 1, ew[1], c)
			}
			if c := int64(F(3)/8); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			return ""
		}
		if n >= 5 && n <= 5 {
			if c := int64(2); n > 0 && L(0) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 0, L(0), c)
			}
			if c := int64(2); n > 1 && L(1) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 1, L(1), c)
			}
			if c := int64(F(1) * 3 * (F(0)/8)); n > 2 && L(2) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 2, L(2), c)
			}
			if c := int64((F(1) + 3)/4); n > 3 && L(3) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 3, L(3), c)
			}
			if c := int64(F(1) * 2 * (F(0)/8)); n > 4 && L(4) > c {
				return fmt.Sprintf("%s: field %d is %d bytes (expected at most %d)", label, 4, L(4), c)
			}
			if n > 0 && lz[0] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 0)
			}
			if n > 1 && lz[1] == 1 {
				return fmt.Sprintf("%s: field %d is encoded with a leading zero byte (expected minimal)", label, 1)
			}
			if c := int64(F(1) * 3 * (F(0)/8)); n > 2 && !(int64(ew[2]) == c || (lz[2] == 2 && int64(ew[2])+1 == c) || (c == 0 && ew[2] == 1 && L(2) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 2, ew[2], c)
			}
			if c := int64((F(1) + 3)/4); n > 3 && !(int64(ew[3]) == c || (lz[3] == 2 && int64(ew[3])+1 == c) || (c == 0 && ew[3] == 1 && L(3) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 3, ew[3], c)
			}
			if c := int64(F(1) * 2 * (F(0)/8)); n > 4 && !(int64(ew[4]) == c || (lz[4] == 2 && int64(ew[4])+1 == c) || (c == 0 && ew[4] == 1 && L(4) == 0)) {
				return fmt.Sprintf("%s: field %d is encoded in %d bytes (expected exactly %d)", label, 4, ew[4], c)
			}
			return ""
		}
	}
	return ""
}

// TODO #373: the value rules.  Each returns the refusal, or "".  A rule reads
// a fixed-width field, which the encoding check has already held to its exact
// width; hkxPad reads it at that width (DerParseSeq drops one leading 0x00).
func hkxPad(b []byte, w int64) []byte {
	out := make([]byte, w)
	if int64(len(b)) > w {
		b = b[int64(len(b))-w:]
	}
	copy(out[w-int64(len(b)):], b)
	return out
}

func hkxRuleCoef(label string, k int, x []byte, w int, cnt, bound int64, cbd bool) string {
	b := hkxPad(x, int64(w)*cnt)
	for j := int64(0); j < cnt; j++ {
		var c int64
		for i := 0; i < w; i++ {
			c = c<<8 | int64(b[j*int64(w)+int64(i)])
		}
		if cbd && !(c == 0 || c == 1 || c == bound-1) {
			return fmt.Sprintf("%s: field %d coefficient %d is %d (expected 0, 1 or %d)", label, k, j, c, bound-1)
		}
		if !cbd && c >= bound {
			return fmt.Sprintf("%s: field %d coefficient %d is %d (expected below %d)", label, k, j, c, bound)
		}
	}
	return ""
}

// le: an R-bit little-endian byte string (spare bits in the LAST byte);
// otherwise a plain integer below 2^R (spare bits in the FIRST).
func hkxRuleBits(label string, k int, x []byte, r int64, le bool) string {
	w := (r + 7) / 8
	i := int64(0)
	if le {
		i = w - 1
	}
	if w > 0 && r%8 != 0 && hkxPad(x, w)[i]>>(r%8) != 0 {
		return fmt.Sprintf("%s: field %d has bits at or above r = %d", label, k, r)
	}
	return ""
}

func hkxRuleSupport(label string, k int, x []byte, d, r int64) string {
	b := hkxPad(x, 2*d)
	seen := make(map[int64]bool, d)
	for j := int64(0); j < d; j++ {
		idx := int64(b[2*j])<<8 | int64(b[2*j+1])
		if idx >= r {
			return fmt.Sprintf("%s: field %d index %d is %d (expected below r = %d)", label, k, j, idx, r)
		}
		if seen[idx] {
			return fmt.Sprintf("%s: field %d repeats index %d", label, k, idx)
		}
		seen[idx] = true
	}
	return ""
}

func hkxRuleLePolyOf(label string, k int, x []byte, s int, sup []byte, d, r int64) string {
	w := (r + 7) / 8
	want := make([]byte, w)
	b := hkxPad(sup, 2*d)
	for j := int64(0); j < d; j++ {
		idx := int64(b[2*j])<<8 | int64(b[2*j+1])
		if idx < r {
			want[idx>>3] |= 1 << uint(idx&7)
		}
	}
	got := hkxPad(x, w)
	for i := range want {
		if got[i] != want[i] {
			return fmt.Sprintf("%s: field %d is not the polynomial of field %d", label, k, s)
		}
	}
	return ""
}

func hkxRuleEquals(label string, k int, x, want int64) string {
	if x == want {
		return ""
	}
	return fmt.Sprintf("%s: field %d is %d (expected %d)", label, k, x, want)
}
// TODO #379: genpkey's key parameter sets (--bits / --level); bits -1: no
// --bits value names the row.  ports: the CLIs that run the row today.
var paramSets = []paramSet{
	{"hkex-gf", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hkex-gf", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hkex-gf", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hkex-gf", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hpks", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hpks-nl", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks-nl", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks-nl", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpks-nl", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hpke", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hpke-nl", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hpke-nl3", 32, "", false, "demo", "at most 2^8 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl3", 64, "", false, "demo", "at most 2^11 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl3", 128, "", false, "demo", "at most 2^23 (Pohlig-Hellman; index calculus is cheaper)", "py go", ""},
	{"hpke-nl3", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"oprf", 256, "demo", true, "demo", "at most 2^36 (Pohlig-Hellman; index calculus is cheaper)", "py go c java", ""},
	{"hkex-rnl", 32, "", false, "demo", "far below 2^87 (not estimated)", "py go java", ""},
	{"hkex-rnl", 64, "", false, "demo", "far below 2^87 (not estimated)", "py go java", ""},
	{"hkex-rnl", 128, "", false, "demo", "far below 2^87 (not estimated)", "py go java", ""},
	{"hkex-rnl", 256, "demo", false, "demo", "far below 2^87 (not estimated)", "py go java", ""},
	{"hkex-rnl", 512, "", false, "withdrawn", "~2^87 classical, ~2^79 quantum", "", "SECURITY.md withdraws ring dimension 512 (HKEX-RNL-128): about 87 classical bits, short of the 128 it was claimed to give"},
	{"hkex-rnl", 1024, "128", true, "production", ">= 2^128 classical (conjectured; SECURITY.md)", "py go c java", ""},
	{"hpks-stern", 32, "", false, "demo", "below 2^30", "py go", ""},
	{"hpks-stern", 64, "", false, "demo", "below 2^30", "py go", ""},
	{"hpks-stern", 128, "", false, "demo", "below 2^30", "py go", ""},
	{"hpks-stern", 256, "demo", true, "demo", "~2^30-2^40 (SECURITY.md)", "py go c java", ""},
	{"hpke-stern", 32, "", false, "demo", "below 2^30", "py go", ""},
	{"hpke-stern", 64, "", false, "demo", "below 2^30", "py go", ""},
	{"hpke-stern", 128, "", false, "demo", "below 2^30", "py go", ""},
	{"hpke-stern", 256, "demo", true, "demo", "~2^30-2^40 (SECURITY.md)", "py go c java", ""},
	{"hcred", 32, "", false, "demo", "research construction; its Stern-F half below 2^30", "py go", ""},
	{"hcred", 64, "", false, "demo", "research construction; its Stern-F half below 2^30", "py go", ""},
	{"hcred", 128, "", false, "demo", "research construction; its Stern-F half below 2^30", "py go", ""},
	{"hcred", 256, "demo", true, "demo", "research construction; its Stern-F half ~2^30-2^40 (SECURITY.md)", "py go c java", ""},
	{"hpke-stern-kem", -1, "128", true, "demo-only", "2^128 classical by its parameters (BIKE-128)", "py go c java", ""},
	{"hpks-zkp-nl", 8, "demo", true, "demo", "demonstration keypair; no security claim", "py go c java", ""},
}

var paramLevels = []string{"demo", "128", "192", "256"}
var paramFixed = []string{"hpks-wots", "hpks-xmss"}
var paramOwnBits = []string{"hpks-zkp-nl"}
var paramLevelNotes = map[string]string{
	"hcred": "128-bit Stern-F parameters are TODO #382",
	"hkex-gf": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpke": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpke-nl": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpke-nl3": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpke-stern": "128-bit Stern-F parameters are TODO #382",
	"hpks": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpks-nl": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
	"hpks-stern": "128-bit Stern-F parameters are TODO #382",
	"oprf": "the GF(2^n)* family is demo-only at every width (binary-field discrete logs fall to index calculus)",
}

// END GENERATED key-label table

// pemFileLabel returns the first PEM BEGIN label in path, or "" (unreadable or
// not PEM).
func pemFileLabel(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := string(raw)
	i := strings.Index(text, "-----BEGIN ")
	if i < 0 {
		return ""
	}
	j := strings.Index(text[i+11:], "-----")
	if j <= 0 {
		return ""
	}
	return text[i+11 : i+11+j]
}

// checkKeyLabels refuses a key whose PEM label this operation does not accept
// (TODO #366).  Only KEY labels are judged (ending in PRIVATE KEY or PUBLIC KEY,
// other than the passphrase envelope): a response, session key or hex key goes
// on to the loader, whose own message is the more specific one.
func checkKeyLabels(cmd string, fs *flag.FlagSet) {
	algo := ""
	if f := fs.Lookup("algo"); f != nil {
		algo = f.Value.String()
	}
	for _, r := range keySites {
		if r.cmd != cmd || r.algo != algo {
			continue
		}
		f := fs.Lookup(strings.TrimPrefix(r.flag, "--"))
		if f == nil || f.Value.String() == "" {
			continue
		}
		paths := []string{f.Value.String()}
		if r.flag == "--ring" {
			paths = strings.Split(paths[0], ",")
		}
		for _, p := range paths {
			label := pemFileLabel(strings.TrimSpace(p))
			if label == "" || label == "HERRADURA ENCRYPTED PRIVATE KEY" ||
				!(strings.HasSuffix(label, "PRIVATE KEY") || strings.HasSuffix(label, "PUBLIC KEY")) {
				continue
			}
			ok := false
			for _, l := range r.labels {
				if l == label {
					ok = true
				}
			}
			if !ok {
				where := cmd
				if algo != "" {
					where = cmd + " --algo " + algo
				}
				fmt.Fprintf(os.Stderr, "%s: wrong key type: %s holds '%s'; accepted: %s\n",
					where, r.flag, label, r.tags)
				os.Exit(1)
			}
		}
	}
}

// BEGIN GENERATED help synopsis (spec/generate_spec.py, TODO #339) -- DO NOT EDIT.
const helpSynopsis = `Subcommands and the flags each one reads (generated from this CLI's
own parser by spec/generate_spec.py; the notes below say which are
required):
  cred-issue           --in --our --out --rounds
  cred-prove           --in --msg --out --rounds
  cred-verify          --cred --issuer --min-rounds --msg --proof --pubkey
                       --rounds
  dec                  --ad --algo --in --key --out
                       --algo: hske hske-nla1 hske-nla2 hske-nla3 hske-duplex
                               hske-duplex3 hpke hpke-nl hpke-nl3 hpke-stern
                               hpke-stern-kem
  decfile              --algo --in --key --out
                       --algo: hske-nla1
  dgst                 --algo --in --out
                       --algo: hfscx-256 hfscx-256-ds
  enc                  --ad --aead --algo --in --key --out --pubkey
                       --algo: hske hske-nla1 hske-nla2 hske-nla3 hske-duplex
                               hske-duplex3 hpke hpke-nl hpke-nl3 hpke-stern
                               hpke-stern-kem
  encfile              --algo --in --key --out
                       --algo: hske-nla1
  fpe                  --context --decrypt --encrypt --in --key --out --v3
  genpkey              --algo --bits --kdf-iterations --level --out
                       --passphrase --xmss-height
                       --algo: hcred hkex-gf hkex-rnl hpke hpke-nl hpke-nl3
                               hpke-stern hpke-stern-kem hpks hpks-nl
                               hpks-stern hpks-wots hpks-xmss hpks-zkp-nl oprf
  kex                  --algo --kdf --our --our-kem --out --their --their-kem
                       --algo: hkex-gf hkex-rnl hybrid-rnl-stern
  oprf-blind           --in --out
  oprf-eval            --in --key --out
  oprf-unblind         --eval --out --state
  pake-demo            --key --password
  pake-register        --key --out --password
  pkey                 --decrypt --in --out --passphrase --pubout --text
  rand                 --bytes --hex --out --personalization --reseed --seed
                       --state
  sign                 --algo --digest --in --key --out --ring --rounds
                       --algo: hpks hpks-nl hpks-stern rnl-sigma nl-zkboo
                               nl-zkbpp hpks-xmss hpks-wots hpks-ring
  threshold-aggregate  --commit --commits --digest --in --out
  threshold-combine    --aggregate --out --partial --partials
  threshold-commit     --commit-out --key --nonce-out
  threshold-respond    --aggregate --commit --commits --key --nonce --out
  threshold-verify     --digest --in --sig
  twk                  --bidx --decrypt --encrypt --in --key --out --sector
                       --v3
  verify               --algo --digest --in --min-rounds --pubkey --ring --sig
                       --algo: hpks hpks-nl hpks-stern rnl-sigma nl-zkboo
                               nl-zkbpp hpks-xmss hpks-wots hpks-ring hpks-t
`
// END GENERATED help synopsis


// ── HPKS-T threshold signing (TODO #106) ─────────────────────────────────────

// loadHpksPrivForThreshold loads hpks or hpks-nl private key; returns (priv, pub, n).
func loadHpksPrivForThreshold(path string) (*big.Int, *big.Int, int) {
	label, ints, err := readPEMInts(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "threshold: cannot read key %s: %v\n", path, err)
		os.Exit(1)
	}
	if label != lblHpksPriv && label != lblHpksNLPriv {
		fmt.Fprintf(os.Stderr, "threshold: expected hpks or hpks-nl key, got %q\n", label)
		os.Exit(1)
	}
	n    := gfWidth(wireInt(ints[2], "n", "threshold"), "threshold")
	priv := new(big.Int).SetBytes(fitBytes(ints[0], n/8, "private key", "threshold"))
	pub  := new(big.Int).SetBytes(fitBytes(ints[1], n/8, "public key", "threshold"))
	return priv, pub, n
}

// encodeHpkstCommit encodes (R_j, C_j, n) as HPKST COMMITMENT PEM.
func encodeHpkstCommit(Rj, Cj *big.Int, n int) (string, error) {
	nb := n / 8
	a, e1 := derIntBig(Rj, nb)
	b, e2 := derIntBig(Cj, nb)
	c, e3 := derIntSmall(n)
	if e1 != nil || e2 != nil || e3 != nil {
		return "", fmt.Errorf("encodeHpkstCommit: DER error")
	}
	seq, err := DerSeqEnc(a, b, c)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHpkstCommit, seq), nil
}

// encodeHpkstNonce encodes (k_j, n) as HPKST NONCE PEM.
func encodeHpkstNonce(kj *big.Int, n int) (string, error) {
	nb := n / 8
	a, e1 := derIntBig(kj, nb)
	b, e2 := derIntSmall(n)
	if e1 != nil || e2 != nil {
		return "", fmt.Errorf("encodeHpkstNonce: DER error")
	}
	seq, err := DerSeqEnc(a, b)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHpkstNonce, seq), nil
}

// encodeHpkstAggregate encodes (R, C_agg, e, n) as HPKST AGGREGATE PEM.
func encodeHpkstAggregate(R, Cagg, e *big.Int, n int) (string, error) {
	nb := n / 8
	a, e1 := derIntBig(R, nb)
	b, e2 := derIntBig(Cagg, nb)
	c, e3 := derIntBig(e, nb)
	d, e4 := derIntSmall(n)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return "", fmt.Errorf("encodeHpkstAggregate: DER error")
	}
	seq, err := DerSeqEnc(a, b, c, d)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHpkstAggregate, seq), nil
}

// encodeHpkstPartial encodes (s_j, n) as HPKST PARTIAL PEM.
func encodeHpkstPartial(sj *big.Int, n int) (string, error) {
	nb := n / 8
	a, e1 := derIntBig(sj, nb)
	b, e2 := derIntSmall(n)
	if e1 != nil || e2 != nil {
		return "", fmt.Errorf("encodeHpkstPartial: DER error")
	}
	seq, err := DerSeqEnc(a, b)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHpkstPartial, seq), nil
}

// encodeHpkstSig encodes (C_agg, R, s, n) as HPKST SIGNATURE PEM.
func encodeHpkstSig(Cagg, R, s *big.Int, n int) (string, error) {
	nb := n / 8
	a, e1 := derIntBig(Cagg, nb)
	b, e2 := derIntBig(R, nb)
	c, e3 := derIntBig(s, nb)
	d, e4 := derIntSmall(n)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return "", fmt.Errorf("encodeHpkstSig: DER error")
	}
	seq, err := DerSeqEnc(a, b, c, d)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHpkstSig, seq), nil
}

// stringFlags collects all occurrences of a flag name from args (e.g. "--commit"),
// taking EVERY following non-"--" token as a value, not just the first.
//
// TODO #270: Go and C accepted only "--commit a --commit b" while Python and Java
// accepted only "--commits a b", so one capability had two spellings and a documented
// threshold command line did not port between CLIs.  All four now take both names with
// both syntaxes; multiValueFlags is the entry point that unions the two names.
func stringFlags(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] != name {
			continue
		}
		for j := i + 1; j < len(args) && !strings.HasPrefix(args[j], "--"); j++ {
			out = append(out, args[j])
		}
	}
	return out
}

// multiValueFlags unions the plural and singular spellings of a repeated path flag.
// Mixing the two NAMES is refused rather than concatenated: the list order is
// consensus-critical -- threshold-respond must see the order threshold-aggregate did --
// so there is no defensible interleaving, and silently choosing one would produce a
// wrong signature rather than an error.
func multiValueFlags(args []string, cmd, plural, singular string) []string {
	// TODO #381: a list flag given with no value is refused as such, not
	// reported later as the list being absent.
	for i, a := range args {
		if (a == plural || a == singular) && (i+1 == len(args) || strings.HasPrefix(args[i+1], "--")) {
			fmt.Fprintf(os.Stderr, "%s: %s needs a value\n", cmd, a)
			os.Exit(2)
		}
	}
	p := stringFlags(args, plural)
	sg := stringFlags(args, singular)
	if len(p) > 0 && len(sg) > 0 {
		fmt.Fprintf(os.Stderr, "%s: use %s or %s, not both (they name the same list, "+
			"and mixing them leaves its order undefined)\n", cmd, plural, singular)
		os.Exit(1)
	}
	if len(p) > 0 {
		return p
	}
	return sg
}

func cmdThresholdCommit(args []string) {
	fs      := flag.NewFlagSet("threshold-commit", flag.ExitOnError)
	key     := fs.String("key", "", "hpks or hpks-nl private key PEM")
	commitOut := fs.String("commit-out", "", "Output commitment PEM")
	nonceOut  := fs.String("nonce-out",  "", "Output nonce PEM")
	parseArgs(fs, args)
	checkKeyLabels("threshold-commit", fs) // TODO #366
	if *key == "" || *commitOut == "" || *nonceOut == "" {
		fmt.Fprintln(os.Stderr, "threshold-commit: --key, --commit-out, --nonce-out required")
		os.Exit(1)
	}
	_, pub, n := loadHpksPrivForThreshold(*key)
	kj        := NewRandBitArray(n)
	n = gfWidth(n, "threshold-commit")
	Rj        := GfPow(GfGenBA(n), kj).BigInt()

	commitPEM, err := encodeHpkstCommit(Rj, pub, n)
	if err != nil { die("threshold-commit", err) }
	noncePEM, err  := encodeHpkstNonce(kj.BigInt(), n)
	if err != nil { die("threshold-commit", err) }
	if err := writeString(*commitOut, commitPEM); err != nil { die("threshold-commit", err) }
	if err := writeString(*nonceOut, noncePEM); err != nil { die("threshold-commit", err) }
}

func cmdThresholdAggregate(args []string) {
	commitPaths := multiValueFlags(args, "threshold-aggregate", "--commits", "--commit")

	fs     := flag.NewFlagSet("threshold-aggregate", flag.ExitOnError)
	in     := fs.String("in", "-", "Message input file")
	out    := fs.String("out", "-", "Output aggregate PEM")
	digest := fs.String("digest", "", "Pre-hash: hfscx-256 (default) or none (pad/truncate to 32 bytes)")
	parseArgs(fs, filterMultiFlags(args, "--commits", "--commit"))
	digestValue("threshold-aggregate", digest)
	if len(commitPaths) == 0 {
		fmt.Fprintln(os.Stderr, "threshold-aggregate: --commits (or --commit) is required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil { die("threshold-aggregate", err) }
	if *digest == "hfscx-256" { inBytes = Hfscx256(inBytes, nil) }

	n     := 256
	R     := big.NewInt(1)
	pubs  := make([]*big.Int, len(commitPaths))
	for i, cp := range commitPaths {
		label, ints, cerr := readPEMInts(cp)
		if cerr != nil { die("threshold-aggregate", cerr) }
		if label != lblHpkstCommit || len(ints) < 2 {
			fmt.Fprintf(os.Stderr, "threshold-aggregate: invalid commitment PEM: %s\n", cp)
			os.Exit(1)
		}
		if len(ints) > 2 {   // TODO #371: a commitment at another width was read at ours
			bounded(wireInt(ints[2], "commitment n", "threshold-aggregate"), n, n, "commitment n", "threshold-aggregate")
		}
		Rj := new(big.Int).SetBytes(fitBytes(ints[0], n/8, "commitment R", "threshold-aggregate"))
		R   = GfMul(NewBitArray(n, R), NewBitArray(n, Rj)).BigInt()
		pubs[i] = new(big.Int).SetBytes(fitBytes(ints[1], n/8, "public key", "threshold-aggregate"))
	}

	msg   := msgPad(inBytes, n/8)
	RBa   := NewBitArray(n, R)
	msgBa := NewBitArray(n, new(big.Int).SetBytes(msg))
	eBa   := HpksNlChallenge(RBa, msgBa)
	eBig  := new(big.Int).SetBytes(eBa.Bytes())

	Cagg, _ := HpkstAggregatePublickeys(pubs)

	pemOut, err := encodeHpkstAggregate(R, Cagg, eBig, n)
	if err != nil { die("threshold-aggregate", err) }
	if err := writeString(*out, pemOut); err != nil { die("threshold-aggregate", err) }
}

// filterMultiFlags removes every "--flag v1 v2 ..." run from args so the remainder can
// be parsed by flag.FlagSet without unknown-flag errors.  Variadic since TODO #270:
// BOTH spellings must be stripped, or flag.Parse chokes on the one it was not told
// about -- and it must skip all of a run's values, not just the first, now that
// stringFlags consumes them.
func filterMultiFlags(args []string, names ...string) []string {
	isName := func(a string) bool {
		for _, n := range names {
			if a == n {
				return true
			}
		}
		return false
	}
	var out []string
	for i := 0; i < len(args); i++ {
		if isName(args[i]) {
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func cmdThresholdRespond(args []string) {
	commitPaths := multiValueFlags(args, "threshold-respond", "--commits", "--commit")
	rest        := filterMultiFlags(args, "--commits", "--commit")

	fs        := flag.NewFlagSet("threshold-respond", flag.ExitOnError)
	key       := fs.String("key", "", "hpks or hpks-nl private key PEM")
	aggregate := fs.String("aggregate", "", "Aggregate PEM from coordinator")
	nonce     := fs.String("nonce", "", "Nonce PEM from threshold-commit")
	out       := fs.String("out", "-", "Output partial signature PEM")
	parseArgs(fs, rest)
	checkKeyLabels("threshold-respond", fs) // TODO #366
	if *key == "" || *aggregate == "" || *nonce == "" {
		fmt.Fprintln(os.Stderr, "threshold-respond: --key, --aggregate, --nonce required")
		os.Exit(1)
	}
	if len(commitPaths) == 0 {
		fmt.Fprintln(os.Stderr, "threshold-respond: --commits (or --commit) is required")
		os.Exit(1)
	}

	priv, ourPub, n := loadHpksPrivForThreshold(*key)

	// Load aggregate PEM
	aggLabel, aggInts, err := readPEMInts(*aggregate)
	if err != nil { die("threshold-respond", err) }
	if aggLabel != lblHpkstAggregate || len(aggInts) < 3 {
		fmt.Fprintln(os.Stderr, "threshold-respond: invalid aggregate PEM")
		os.Exit(1)
	}
	eBig := new(big.Int).SetBytes(aggInts[2])

	// Load nonce PEM
	nonceLabel, nonceInts, err := readPEMInts(*nonce)
	if err != nil { die("threshold-respond", err) }
	if nonceLabel != lblHpkstNonce || len(nonceInts) < 1 {
		fmt.Fprintln(os.Stderr, "threshold-respond: invalid nonce PEM")
		os.Exit(1)
	}
	kj := new(big.Int).SetBytes(nonceInts[0])

	// Load pubkeys from commitments
	pubs := make([]*big.Int, len(commitPaths))
	for i, cp := range commitPaths {
		label, ints, cerr := readPEMInts(cp)
		if cerr != nil { die("threshold-respond", cerr) }
		if label != lblHpkstCommit || len(ints) < 2 {
			fmt.Fprintf(os.Stderr, "threshold-respond: invalid commitment PEM: %s\n", cp)
			os.Exit(1)
		}
		if len(ints) > 2 {   // TODO #371: a commitment at another width was read at ours
			bounded(wireInt(ints[2], "commitment n", "threshold-respond"), n, n, "commitment n", "threshold-respond")
		}
		pubs[i] = new(big.Int).SetBytes(ints[1])
	}

	// Compute mu_j
	_, coeffs := HpkstAggregatePublickeys(pubs)
	ourIdx := -1
	for i, p := range pubs {
		if p.Cmp(ourPub) == 0 { ourIdx = i; break }
	}
	if ourIdx < 0 {
		fmt.Fprintln(os.Stderr, "threshold-respond: our public key not found in commits")
		os.Exit(1)
	}
	mu := coeffs[ourIdx]

	// s_j = (k_j - priv * mu_j * e) mod ord
	ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))
	ame := new(big.Int).Mul(priv, mu)
	ame.Mul(ame, eBig)
	ame.Mod(ame, ord)
	sj := new(big.Int).Sub(kj, ame)
	sj.Mod(sj, ord)
	if sj.Sign() < 0 { sj.Add(sj, ord) }

	pemOut, err := encodeHpkstPartial(sj, n)
	if err != nil { die("threshold-respond", err) }
	if err := writeString(*out, pemOut); err != nil { die("threshold-respond", err) }
}

func cmdThresholdCombine(args []string) {
	partialPaths := multiValueFlags(args, "threshold-combine", "--partials", "--partial")
	rest         := filterMultiFlags(args, "--partials", "--partial")

	fs        := flag.NewFlagSet("threshold-combine", flag.ExitOnError)
	aggregate := fs.String("aggregate", "", "Aggregate PEM")
	out       := fs.String("out", "-", "Output HPKST SIGNATURE PEM")
	parseArgs(fs, rest)
	if *aggregate == "" {
		fmt.Fprintln(os.Stderr, "threshold-combine: --aggregate required")
		os.Exit(1)
	}
	if len(partialPaths) == 0 {
		fmt.Fprintln(os.Stderr, "threshold-combine: --partials (or --partial) is required")
		os.Exit(1)
	}

	aggLabel, aggInts, err := readPEMInts(*aggregate)
	if err != nil { die("threshold-combine", err) }
	if aggLabel != lblHpkstAggregate || len(aggInts) < 2 {
		fmt.Fprintln(os.Stderr, "threshold-combine: invalid aggregate PEM")
		os.Exit(1)
	}
	R    := new(big.Int).SetBytes(aggInts[0])
	Cagg := new(big.Int).SetBytes(aggInts[1])
	n    := 256
	ord  := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))

	sAcc := big.NewInt(0)
	for _, pp := range partialPaths {
		label, ints, perr := readPEMInts(pp)
		if perr != nil { die("threshold-combine", perr) }
		if label != lblHpkstPartial || len(ints) < 1 {
			fmt.Fprintf(os.Stderr, "threshold-combine: invalid partial PEM: %s\n", pp)
			os.Exit(1)
		}
		sj := new(big.Int).SetBytes(ints[0])
		sAcc.Add(sAcc, sj)
		sAcc.Mod(sAcc, ord)
	}

	pemOut, err := encodeHpkstSig(Cagg, R, sAcc, n)
	if err != nil { die("threshold-combine", err) }
	if err := writeString(*out, pemOut); err != nil { die("threshold-combine", err) }
}

func cmdThresholdVerify(args []string) {
	fs     := flag.NewFlagSet("threshold-verify", flag.ExitOnError)
	in     := fs.String("in", "-", "Message input file")
	sig    := fs.String("sig", "", "HPKST SIGNATURE PEM file")
	digest := fs.String("digest", "", "Pre-hash: hfscx-256 (default) or none (pad/truncate to 32 bytes)")
	parseArgs(fs, args)
	digestValue("threshold-verify", digest)
	if *sig == "" {
		fmt.Fprintln(os.Stderr, "threshold-verify: --sig required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil { die("threshold-verify", err) }
	if *digest == "hfscx-256" { inBytes = Hfscx256(inBytes, nil) }

	sigLabel, sigInts, err := readPEMInts(*sig)
	if err != nil { die("threshold-verify", err) }
	if sigLabel != lblHpkstSig || len(sigInts) < 3 {
		fmt.Fprintln(os.Stderr, "threshold-verify: invalid HPKST SIGNATURE PEM")
		os.Exit(1)
	}
	Cagg := new(big.Int).SetBytes(sigInts[0])
	R    := new(big.Int).SetBytes(sigInts[1])
	s    := new(big.Int).SetBytes(sigInts[2])
	n    := 256

	msg := msgPad(inBytes, n/8)
	if HpkstVerify(Cagg, R, s, msg) {
		fmt.Println("Signature OK")
		os.Exit(0)
	} else {
		fmt.Println("Verification FAILED")
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(1)
	}
	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage(os.Stdout)
		os.Exit(0)
	}
	cmd  := os.Args[1]
	rest := os.Args[2:]
	switch cmd {
	case "genpkey":
		cmdGenpkey(rest)
	case "pkey":
		cmdPkey(rest)
	case "kex":
		cmdKex(rest)
	case "enc":
		cmdEnc(rest)
	case "dec":
		cmdDec(rest)
	case "sign":
		cmdSign(rest)
	case "verify":
		cmdVerify(rest)
	case "encfile":
		cmdEncfile(rest)
	case "decfile":
		cmdDecfile(rest)
	case "dgst":
		cmdDgst(rest)
	case "rand":
		cmdRand(rest)
	case "fpe":
		cmdFpe(rest)
	case "twk":
		cmdTwk(rest)
	case "oprf-blind":
		cmdOprfBlind(rest)
	case "oprf-eval":
		cmdOprfEval(rest)
	case "oprf-unblind":
		cmdOprfUnblind(rest)
	case "pake-register":
		cmdPakeRegister(rest)
	case "pake-demo":
		cmdPakeDemo(rest)
	case "threshold-commit":
		cmdThresholdCommit(rest)
	case "threshold-aggregate":
		cmdThresholdAggregate(os.Args[2:])
	case "threshold-respond":
		cmdThresholdRespond(os.Args[2:])
	case "threshold-combine":
		cmdThresholdCombine(os.Args[2:])
	case "threshold-verify":
		cmdThresholdVerify(rest)
	case "cred-issue":
		cmdCredIssue(rest)
	case "cred-prove":
		cmdCredProve(rest)
	case "cred-verify":
		cmdCredVerify(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(1)
	}
}
