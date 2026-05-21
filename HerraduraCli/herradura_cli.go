// HerraduraCli/herradura_cli.go — Go CLI for the Herradura Cryptographic Suite
// v1.8.0
//
// Usage:
//   herradura_cli_go genpkey  --algo hkex-gf  --bits 256 --out alice.pem
//   herradura_cli_go pkey     --in alice.pem   --pubout  --out alice_pub.pem
//   herradura_cli_go kex      --algo hkex-gf   --our alice.pem --their bob_pub.pem --out sk.pem
//   herradura_cli_go enc      --algo hske      --key sk.pem --in msg.bin --out ct.pem
//   herradura_cli_go dec      --algo hske      --key sk.pem --in ct.pem  --out plain.bin
//   herradura_cli_go sign     --algo hpks      --key priv.pem --in msg.bin --out sig.pem
//   herradura_cli_go verify   --algo hpks      --pubkey pub.pem --in msg.bin --sig sig.pem
//   herradura_cli_go dgst     --in file.bin                       # hex to stdout
//   herradura_cli_go dgst     --algo hfscx-256 --in file.bin --out d.pem
//
// HKEX-RNL (2-round):
//   herradura_cli_go kex --algo hkex-rnl --our bob.pem --their alice_pub.pem --out resp.pem
//   herradura_cli_go kex --algo hkex-rnl --our alice.pem --their resp.pem    --out sk.pem
package main

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	. "herradurakex/herradura"
)

// ── PEM label constants (must match Python and C exactly) ───────────────────

const (
	lblHkexGFPriv    = "HERRADURA HKEX-GF PRIVATE KEY"
	lblHkexRNLPriv   = "HERRADURA HKEX-RNL PRIVATE KEY"
	lblHpksPriv      = "HERRADURA HPKS PRIVATE KEY"
	lblHpksNLPriv    = "HERRADURA HPKS-NL PRIVATE KEY"
	lblHpkePriv      = "HERRADURA HPKE PRIVATE KEY"
	lblHpkeNLPriv    = "HERRADURA HPKE-NL PRIVATE KEY"
	lblHpksSternPriv = "HERRADURA HPKS-STERN PRIVATE KEY"
	lblHpkeSternPriv = "HERRADURA HPKE-STERN PRIVATE KEY"

	lblHkexGFPub    = "HERRADURA HKEX-GF PUBLIC KEY"
	lblHkexRNLPub   = "HERRADURA HKEX-RNL PUBLIC KEY"
	lblHpksPub      = "HERRADURA HPKS PUBLIC KEY"
	lblHpksNLPub    = "HERRADURA HPKS-NL PUBLIC KEY"
	lblHpkePub      = "HERRADURA HPKE PUBLIC KEY"
	lblHpkeNLPub    = "HERRADURA HPKE-NL PUBLIC KEY"
	lblHpksSternPub = "HERRADURA HPKS-STERN PUBLIC KEY"
	lblHpkeSternPub = "HERRADURA HPKE-STERN PUBLIC KEY"

	lblSession = "HERRADURA SESSION KEY"
	lblRnlResp = "HERRADURA HKEX-RNL RESPONSE"
	lblCT      = "HERRADURA CIPHERTEXT"
	lblSig     = "HERRADURA SIGNATURE"
	lblDigest  = "HERRADURA DIGEST"
)

var privToAlgo = map[string]string{
	lblHkexGFPriv:    "hkex-gf",
	lblHkexRNLPriv:   "hkex-rnl",
	lblHpksPriv:      "hpks",
	lblHpksNLPriv:    "hpks-nl",
	lblHpkePriv:      "hpke",
	lblHpkeNLPriv:    "hpke-nl",
	lblHpksSternPriv: "hpks-stern",
	lblHpkeSternPriv: "hpke-stern",
}

var algoToPrivLbl = map[string]string{
	"hkex-gf":    lblHkexGFPriv,
	"hkex-rnl":   lblHkexRNLPriv,
	"hpks":       lblHpksPriv,
	"hpks-nl":    lblHpksNLPriv,
	"hpke":       lblHpkePriv,
	"hpke-nl":    lblHpkeNLPriv,
	"hpks-stern": lblHpksSternPriv,
	"hpke-stern": lblHpkeSternPriv,
}

var algoToPubLbl = map[string]string{
	"hkex-gf":    lblHkexGFPub,
	"hkex-rnl":   lblHkexRNLPub,
	"hpks":       lblHpksPub,
	"hpks-nl":    lblHpksNLPub,
	"hpke":       lblHpkePub,
	"hpke-nl":    lblHpkeNLPub,
	"hpks-stern": lblHpksSternPub,
	"hpke-stern": lblHpkeSternPub,
}

var classicalAlgos = map[string]bool{
	"hkex-gf": true, "hpks": true, "hpks-nl": true,
	"hpke": true, "hpke-nl": true,
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

func readPEMInts(path string) (string, [][]byte, error) {
	data, err := readFile(path)
	if err != nil {
		return "", nil, err
	}
	label, der, err := PemUnwrap(string(data))
	if err != nil {
		return "", nil, err
	}
	ints, err := DerParseSeq(der)
	return label, ints, err
}

// ── DER encoding helpers ─────────────────────────────────────────────────────

func derIntBig(v *big.Int, width int) ([]byte, error) {
	return DerIntEnc(v.FillBytes(make([]byte, width)))
}

func derIntSmall(n int) ([]byte, error) {
	b := new(big.Int).SetInt64(int64(n)).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	return DerIntEnc(b)
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

func encodeRNLPriv(s, mBlind []int, n int) (string, error) {
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
	seq, err := DerSeqEnc(sDer, mDer, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHkexRNLPriv, seq), nil
}

func encodeRNLPub(C, mBlind []int, n int) (string, error) {
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
	seq, err := DerSeqEnc(cDer, mDer, nn)
	if err != nil {
		return "", err
	}
	return PemWrap(lblHkexRNLPub, seq), nil
}

func encodeSternPriv(e, seed *BitArray, n int, algo string) (string, error) {
	a, err := derIntBig(&e.Val, n/8)
	if err != nil {
		return "", err
	}
	b, err := derIntBig(&seed.Val, n/8)
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
	b, err := derIntBig(&seed.Val, n/8)
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
	nb := (key.Val.BitLen() + 7) / 8
	if nb < 1 {
		nb = 1
	}
	a, err := derIntBig(&key.Val, nb)
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
// hint is Go's native packed hint (2-bit per coeff: hint[i/4] bits (i%4)*2..(i%4)*2+1 = coeff i hint).
// Bytes are reversed before DER encoding to match Python's big-endian convention.
func encodeRNLResponse(K_B *BitArray, C_B []int, hint []byte, n int) (string, error) {
	// K_B: minimum-width big-endian encoding
	nb := (K_B.Val.BitLen() + 7) / 8
	if nb < 1 {
		nb = 1
	}
	kDer, err := derIntBig(&K_B.Val, nb)
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

	// n and hint_len (= n, number of coefficients)
	nDer, err := derIntSmall(n)
	if err != nil {
		return "", err
	}
	hlDer, err := derIntSmall(n)
	if err != nil {
		return "", err
	}

	seq, err := DerSeqEnc(kDer, cDer, hDer, nDer, hlDer)
	if err != nil {
		return "", err
	}
	return PemWrap(lblRnlResp, seq), nil
}

// ── genpkey ──────────────────────────────────────────────────────────────────

func cmdGenpkey(args []string) {
	fs := flag.NewFlagSet("genpkey", flag.ExitOnError)
	algo := fs.String("algo", "", "Algorithm (hkex-gf|hkex-rnl|hpks|hpks-nl|hpke|hpke-nl|hpks-stern|hpke-stern)")
	bits := fs.Int("bits", 256, "Key size in bits")
	out  := fs.String("out", "-", "Output path (- = stdout)")
	fs.Parse(args)

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "genpkey: --algo required")
		os.Exit(1)
	}

	n := *bits
	gen := new(big.Int).SetInt64(GfGen)

	var pem string
	var err error

	switch {
	case classicalAlgos[*algo]:
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
			n = 256
		}
		a := NewRandBitArray(n)
		C := GfPow(gen, &a.Val, poly, n)
		pem, err = encodeClassicalPriv(&a.Val, C, n, *algo)

	case *algo == "hkex-rnl":
		mBase  := RnlMPoly(n)
		aRand  := RnlRandPoly(n, RnlQ)
		mBlind := RnlPolyAdd(mBase, aRand, RnlQ)
		s, _   := RnlKeygen(mBlind, n, RnlQ, RnlP)
		pem, err = encodeRNLPriv(s, mBlind, n)

	case sternAlgos[*algo]:
		seed, e, _ := SternFKeygen(n)
		pem, err = encodeSternPriv(e, seed, n, *algo)

	default:
		fmt.Fprintf(os.Stderr, "genpkey: unknown algorithm %q\n", *algo)
		os.Exit(1)
	}

	if err != nil {
		die("genpkey", err)
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
	fs.Parse(args)

	if *in == "" {
		fmt.Fprintln(os.Stderr, "pkey: --in required")
		os.Exit(1)
	}
	if !*pubout && !*text {
		fmt.Fprintln(os.Stderr, "pkey: specify --pubout or --text")
		os.Exit(1)
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
			n := bytesToInt(ints[2])
			pub := new(big.Int).SetBytes(ints[1])
			pem, err = encodeClassicalPub(pub, n, algo)

		case algo == "hkex-rnl":
			n := bytesToInt(ints[2])
			s      := unpackPolyRaw(ints[0], n, 4)
			mBlind := unpackPolyRaw(ints[1], n, 4)
			ms     := RnlPolyMul(mBlind, s, RnlQ, n)
			C      := RnlRound(ms, RnlQ, RnlP)
			pem, err = encodeRNLPub(C, mBlind, n)

		case sternAlgos[algo]:
			n    := bytesToInt(ints[2])
			e    := NewBitArray(n, new(big.Int).SetBytes(ints[0]))
			seed := NewBitArray(n, new(big.Int).SetBytes(ints[1]))
			syn  := SternSyndrome(seed, e)
			pem, err = encodeSternPub(syn, seed, n, algo)
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
		n    := bytesToInt(ints[2])
		priv := new(big.Int).SetBytes(ints[0])
		pub  := new(big.Int).SetBytes(ints[1])
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("bits      : %d\n", n)
		fmt.Printf("private   : %0*x\n", n/4, priv)
		fmt.Printf("public    : %0*x\n", n/4, pub)

	case algo == "hkex-rnl":
		n      := bytesToInt(ints[2])
		s      := unpackPolyRaw(ints[0], n, 4)
		mBlind := unpackPolyRaw(ints[1], n, 4)
		ms     := RnlPolyMul(mBlind, s, RnlQ, n)
		C      := RnlRound(ms, RnlQ, RnlP)
		fmt.Printf("algorithm : hkex-rnl\n")
		fmt.Printf("n         : %d\n", n)
		fmt.Printf("s_packed  : %x\n", packPoly(s, 4))
		fmt.Printf("C_packed  : %x\n", packPoly(C, 2))

	case sternAlgos[algo]:
		n    := bytesToInt(ints[2])
		eBig := new(big.Int).SetBytes(ints[0])
		sBig := new(big.Int).SetBytes(ints[1])
		fmt.Printf("algorithm : %s\n", algo)
		fmt.Printf("n         : %d\n", n)
		fmt.Printf("e_int     : %0*x\n", n/4, eBig)
		fmt.Printf("seed      : %0*x\n", n/4, sBig)
	}
}

// ── kex ──────────────────────────────────────────────────────────────────────

func cmdKex(args []string) {
	fs := flag.NewFlagSet("kex", flag.ExitOnError)
	algo  := fs.String("algo", "", "Algorithm (hkex-gf|hkex-rnl)")
	our   := fs.String("our", "", "Our private key file")
	their := fs.String("their", "", "Their public key or response file")
	out   := fs.String("out", "-", "Output path")
	fs.Parse(args)

	if *algo == "" || *our == "" || *their == "" {
		fmt.Fprintln(os.Stderr, "kex: --algo, --our, --their required")
		os.Exit(1)
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

		n    := bytesToInt(ourInts[2])
		priv := new(big.Int).SetBytes(ourInts[0])
		pub  := new(big.Int).SetBytes(theirInts[0])
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
		}

		sk   := GfPow(pub, priv, poly, n)
		skBA := NewBitArray(n, sk)
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
			n   := bytesToInt(ourInts[2])
			s_B := unpackPolyRaw(ourInts[0], n, 4)
			C_A := unpackPolyRaw(theirInts[0], n, 2)
			m_A := unpackPolyRaw(theirInts[1], n, 4)

			// Derive C_B = round_p(m_A * s_B)
			ms  := RnlPolyMul(m_A, s_B, RnlQ, n)
			C_B := RnlRound(ms, RnlQ, RnlP)

			// Compute K_B and reconciliation hint
			K_B, hint := RnlAgree(s_B, C_A, RnlQ, RnlP, RnlPP, n, n, nil)

			pem, err := encodeRNLResponse(K_B, C_B, hint, n)
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
			n   := bytesToInt(ourInts[2])
			s_A := unpackPolyRaw(ourInts[0], n, 4)
			C_B := unpackPolyRaw(theirInts[1], n, 2)

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

			K_A, _ := RnlAgree(s_A, C_B, RnlQ, RnlP, RnlPP, n, n, hintBuf)
			pem, err := encodeSessionKey(K_A, n)
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
	fs.Parse(args)

	data, err := readFile(*in)
	if err != nil {
		die("dgst", err)
	}

	var digest []byte
	switch *algo {
	case "hfscx-256":
		digest = Hfscx256(data, nil)
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

// ── Key loading helper (for enc/dec) ─────────────────────────────────────────

// loadKey loads a session key from a SESSION KEY PEM, HKEX-RNL RESPONSE PEM,
// or a plain-text 0x... hex string.  Returns (key, nbits).
func loadKey(path string) (*big.Int, int, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, 0, err
	}
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, 0, fmt.Errorf("invalid hex key %q", s)
		}
		nb := v.BitLen()
		if nb < 32 {
			nb = 32
		}
		nb = ((nb + 31) / 32) * 32
		return v, nb, nil
	}
	label, der, err := PemUnwrap(s)
	if err != nil {
		return nil, 0, err
	}
	ints, err := DerParseSeq(der)
	if err != nil {
		return nil, 0, err
	}
	switch label {
	case lblSession:
		return new(big.Int).SetBytes(ints[0]), bytesToInt(ints[1]), nil
	case lblRnlResp:
		return new(big.Int).SetBytes(ints[0]), bytesToInt(ints[3]), nil
	}
	return nil, 0, fmt.Errorf("loadKey: expected SESSION KEY or HKEX-RNL RESPONSE PEM, got %q", label)
}

// ── Ciphertext encoding helpers ───────────────────────────────────────────────

// encodeSymCT encodes a symmetric ciphertext (HSKE / HSKE-NL-A1 / HSKE-NL-A2).
// For HSKE-NL-A1 pass nonce != nil to include format tag 1 + nonce field;
// all other algos use format tag 0 (no nonce).
func encodeSymCT(algo string, E *big.Int, n int, nonce *big.Int) (string, error) {
	nb := n / 8
	var items [][]byte
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
	ea, err := derIntBig(&ePrime.Val, nb)
	if err != nil {
		return "", err
	}
	ka, err := derIntBig(&K.Val, nb)
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

// packSternSig serialises a *SternSig to the HERRADURA SIGNATURE PEM format,
// matching Python's _pack_stern_sig and C's pack_stern_sig exactly.
func packSternSig(sig *SternSig, n int) (string, error) {
	rounds := len(sig.Rounds)
	nb := n / 8

	// Commits: c0||c1||c2 per round, each nb bytes big-endian
	commitsBuf := make([]byte, 3*rounds*nb)
	for i, r := range sig.Rounds {
		off := i * 3 * nb
		r.C0.Val.FillBytes(commitsBuf[off : off+nb])
		r.C1.Val.FillBytes(commitsBuf[off+nb : off+2*nb])
		r.C2.Val.FillBytes(commitsBuf[off+2*nb : off+3*nb])
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
		r.RespA.Val.FillBytes(respBuf[off : off+nb])
		r.RespB.Val.FillBytes(respBuf[off+nb : off+2*nb])
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
	return PemWrap(lblSig, seq), nil
}

// unpackSternSig deserialises a *SternSig from DER-parsed integer fields.
func unpackSternSig(ints [][]byte) (*SternSig, int, error) {
	n := bytesToInt(ints[0])
	rounds := bytesToInt(ints[1])
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

// msgPad returns inBytes truncated/zero-padded to exactly nbytes.
func msgPad(inBytes []byte, nbytes int) []byte {
	out := make([]byte, nbytes)
	copy(out, inBytes)
	return out
}

// ── enc ───────────────────────────────────────────────────────────────────────

func cmdEnc(args []string) {
	fs := flag.NewFlagSet("enc", flag.ExitOnError)
	algo   := fs.String("algo", "", "Encryption algorithm")
	key    := fs.String("key", "", "Key file (symmetric algos and HPKE enc uses --pubkey)")
	pubkey := fs.String("pubkey", "", "Recipient public key file (asymmetric algos)")
	in     := fs.String("in", "-", "Plaintext input file")
	out    := fs.String("out", "-", "Ciphertext output PEM file")
	fs.Parse(args)

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "enc: --algo required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil {
		die("enc", err)
	}

	gen := new(big.Int).SetInt64(GfGen)

	switch *algo {
	case "hske", "hske-nla1", "hske-nla2":
		if *key == "" {
			fmt.Fprintf(os.Stderr, "enc: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, n, err := loadKey(*key)
		if err != nil {
			die("enc", err)
		}
		nb := n / 8
		P := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		K := NewBitArray(n, keyInt)

		var pem string
		switch *algo {
		case "hske":
			E := FscxRevolve(P, K, n/4)
			pem, err = encodeSymCT("hske", &E.Val, n, nil)
		case "hske-nla1":
			nonce := NewRandBitArray(n)
			base  := NewBitArray(n, new(big.Int).Xor(&K.Val, &nonce.Val))
			seed  := RnlKdfSeed(base)
			ks    := NlFscxRevolveV1(seed, base, n/4)
			E     := NewBitArray(n, new(big.Int).Xor(&P.Val, &ks.Val))
			pem, err = encodeSymCT("hske-nla1", &E.Val, n, &nonce.Val)
		case "hske-nla2":
			E := NlFscxRevolveV2(P, K, 3*n/4)
			pem, err = encodeSymCT("hske-nla2", &E.Val, n, nil)
		}
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hpke", "hpke-nl":
		if *pubkey == "" {
			fmt.Fprintf(os.Stderr, "enc: --pubkey required for %s\n", *algo)
			os.Exit(1)
		}
		_, theirInts, err := readPEMInts(*pubkey)
		if err != nil {
			die("enc", err)
		}
		pubInt := new(big.Int).SetBytes(theirInts[0])
		n := bytesToInt(theirInts[1])
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
		}
		nb := n / 8
		P := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		r := NewRandBitArray(n)
		R := GfPow(gen, &r.Val, poly, n)
		encKey := NewBitArray(n, GfPow(pubInt, &r.Val, poly, n))

		var pem string
		if *algo == "hpke" {
			E := FscxRevolve(P, encKey, n/4)
			pem, err = encodeAsymCT(R, &E.Val, n)
		} else {
			E := NlFscxRevolveV2(P, encKey, n/4)
			pem, err = encodeAsymCT(R, &E.Val, n)
		}
		if err != nil {
			die("enc", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("enc", err)
		}

	case "hpke-stern":
		if *pubkey == "" {
			fmt.Fprintln(os.Stderr, "enc: --pubkey required for hpke-stern")
			os.Exit(1)
		}
		_, theirInts, err := readPEMInts(*pubkey)
		if err != nil {
			die("enc", err)
		}
		n    := bytesToInt(theirInts[2])
		seed := NewBitArray(n, new(big.Int).SetBytes(theirInts[1]))
		nb   := n / 8
		P    := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, nb)))
		K, ctSyn, ePrime := HpkeSternFEncap(seed, n)
		E := FscxRevolve(P, K, n/4)
		pem, err := encodeSternCT(ctSyn, ePrime, K, &E.Val, n)
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
	fs.Parse(args)

	if *algo == "" {
		fmt.Fprintln(os.Stderr, "dec: --algo required")
		os.Exit(1)
	}

	switch *algo {
	case "hske", "hske-nla1", "hske-nla2":
		if *key == "" {
			fmt.Fprintf(os.Stderr, "dec: --key required for %s\n", *algo)
			os.Exit(1)
		}
		keyInt, _, err := loadKey(*key)
		if err != nil {
			die("dec", err)
		}
		_, ctInts, err := readPEMInts(*in)
		if err != nil {
			die("dec", err)
		}
		// ctInts[0] = fmt tag; tag 1 → nonce present
		fmtTag := bytesToInt(ctInts[0])
		var EInt, nonceInt *big.Int
		var n int
		if fmtTag == 1 {
			EInt    = new(big.Int).SetBytes(ctInts[2])
			n       = bytesToInt(ctInts[3])
			nonceInt = new(big.Int).SetBytes(ctInts[1])
		} else {
			EInt = new(big.Int).SetBytes(ctInts[1])
			n    = bytesToInt(ctInts[2])
		}
		K := NewBitArray(n, keyInt)
		E := NewBitArray(n, EInt)

		var D *BitArray
		switch *algo {
		case "hske":
			D = FscxRevolve(E, K, 3*n/4)
		case "hske-nla1":
			if nonceInt == nil {
				fmt.Fprintln(os.Stderr, "dec: hske-nla1 ciphertext missing nonce")
				os.Exit(1)
			}
			nonce := NewBitArray(n, nonceInt)
			base  := NewBitArray(n, new(big.Int).Xor(&K.Val, &nonce.Val))
			seed  := RnlKdfSeed(base)
			ks    := NlFscxRevolveV1(seed, base, n/4)
			D      = NewBitArray(n, new(big.Int).Xor(&E.Val, &ks.Val))
		case "hske-nla2":
			D = NlFscxRevolveV2Inv(E, K, 3*n/4)
		}
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	case "hpke", "hpke-nl":
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
		priv := new(big.Int).SetBytes(ourInts[0])
		n    := bytesToInt(ourInts[2])
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
		}
		R    := new(big.Int).SetBytes(ctInts[0])
		EInt := new(big.Int).SetBytes(ctInts[1])
		decKey := NewBitArray(n, GfPow(R, priv, poly, n))
		E      := NewBitArray(n, EInt)

		var D *BitArray
		if *algo == "hpke" {
			D = FscxRevolve(E, decKey, 3*n/4)
		} else {
			D = NlFscxRevolveV2Inv(E, decKey, n/4)
		}
		if err := writeBytes(*out, D.Bytes()); err != nil {
			die("dec", err)
		}

	case "hpke-stern":
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
		n       := bytesToInt(ourInts[2])
		seed    := NewBitArray(n, new(big.Int).SetBytes(ourInts[1]))
		ePrime  := NewBitArray(n, new(big.Int).SetBytes(ctInts[1]))
		EInt    := new(big.Int).SetBytes(ctInts[3])
		K_dec   := HpkeSternFDecapKnown(ePrime, seed)
		E       := NewBitArray(n, EInt)
		D       := FscxRevolve(E, K_dec, 3*n/4)
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
	digest := fs.String("digest", "", "Pre-hash algorithm (hfscx-256)")
	out    := fs.String("out", "-", "Signature PEM output file")
	fs.Parse(args)

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

	_, ourInts, err := readPEMInts(*key)
	if err != nil {
		die("sign", err)
	}

	gen := new(big.Int).SetInt64(GfGen)

	switch *algo {
	case "hpks", "hpks-nl":
		priv := new(big.Int).SetBytes(ourInts[0])
		n    := bytesToInt(ourInts[2])
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
		}
		msg := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		k   := NewRandBitArray(n)
		R   := GfPow(gen, &k.Val, poly, n)

		var e *BitArray
		if *algo == "hpks" {
			e = FscxRevolve(NewBitArray(n, R), msg, n/4)
		} else {
			e = NlFscxRevolveV1(NewBitArray(n, R), msg, n/4)
		}
		// s = (k - priv * e) mod (2^n - 1)
		ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1))
		s   := new(big.Int).Mod(
			new(big.Int).Sub(&k.Val, new(big.Int).Mul(priv, &e.Val)),
			ord,
		)
		pem, err := encodeSchnorrSig(s, R, &e.Val, n)
		if err != nil {
			die("sign", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}

	case "hpks-stern":
		n    := bytesToInt(ourInts[2])
		e    := NewBitArray(n, new(big.Int).SetBytes(ourInts[0]))
		seed := NewBitArray(n, new(big.Int).SetBytes(ourInts[1]))
		msg  := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))
		sig  := HpksSternFSign(msg, e, seed, SdfRounds)
		pem, err := packSternSig(sig, n)
		if err != nil {
			die("sign", err)
		}
		if err := writeString(*out, pem); err != nil {
			die("sign", err)
		}

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
	digest := fs.String("digest", "", "Pre-hash algorithm (hfscx-256)")
	sig    := fs.String("sig", "", "Signature PEM file")
	fs.Parse(args)

	if *algo == "" || *pubkey == "" || *sig == "" {
		fmt.Fprintln(os.Stderr, "verify: --algo, --pubkey, --sig required")
		os.Exit(1)
	}

	inBytes, err := readFile(*in)
	if err != nil {
		die("verify", err)
	}
	if *digest == "hfscx-256" {
		inBytes = Hfscx256(inBytes, nil)
	}

	_, theirInts, err := readPEMInts(*pubkey)
	if err != nil {
		die("verify", err)
	}

	gen := new(big.Int).SetInt64(GfGen)

	switch *algo {
	case "hpks", "hpks-nl":
		pub := new(big.Int).SetBytes(theirInts[0])
		n   := bytesToInt(theirInts[1])
		poly := GfPoly[n]
		if poly == nil {
			poly = GfPoly[256]
		}
		msg := NewBitArray(n, new(big.Int).SetBytes(msgPad(inBytes, n/8)))

		_, sigInts, err := readPEMInts(*sig)
		if err != nil {
			die("verify", err)
		}
		sInt := new(big.Int).SetBytes(sigInts[0])
		R    := new(big.Int).SetBytes(sigInts[1])
		_     = sigInts[2] // e stored in sig; recomputed below for verification

		// e_v = challenge recomputed from R and msg
		var eV *BitArray
		if *algo == "hpks" {
			eV = FscxRevolve(NewBitArray(n, R), msg, n/4)
		} else {
			eV = NlFscxRevolveV1(NewBitArray(n, R), msg, n/4)
		}
		// Verify: g^s * pub^(e_recomputed) == R  (matches Python verify)
		lhs := GfMul(
			GfPow(gen, sInt, poly, n),
			GfPow(pub, &eV.Val, poly, n),
			poly, n,
		)
		if lhs.Cmp(R) == 0 {
			fmt.Println("Signature OK")
			os.Exit(0)
		} else {
			fmt.Println("Verification FAILED")
			os.Exit(1)
		}

	case "hpks-stern":
		synInt  := new(big.Int).SetBytes(theirInts[0])
		n       := bytesToInt(theirInts[2])
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
		if HpksSternFVerify(msg, sternSig, seed, synInt) {
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
	fs.Parse(args)

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
	base  := NewBitArray(n, new(big.Int).Xor(&K.Val, &nonce.Val))
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
	macIV  := NewBitArray(n, new(big.Int).Xor(&macKey.Val, ivConst))

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
	fs.Parse(args)

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

	ptLen    := int(binary.BigEndian.Uint64(raw[5:13]))
	nonceBuf := raw[13:45]
	nBlocks  := (ptLen + hkxBlock - 1) / hkxBlock
	ctEnd    := hkxHdrSize + nBlocks*hkxBlock

	if len(raw) < ctEnd+hkxBlock {
		fmt.Fprintln(os.Stderr, "decfile: file truncated (ciphertext blocks or auth tag missing)")
		os.Exit(1)
	}

	ctBytes   := raw[hkxHdrSize:ctEnd]
	tagStored := raw[ctEnd : ctEnd+hkxBlock]

	n := 256
	K     := NewBitArray(n, keyInt)
	nonce := NewBitArray(n, new(big.Int).SetBytes(nonceBuf))
	base  := NewBitArray(n, new(big.Int).Xor(&K.Val, &nonce.Val))
	seed  := RnlKdfSeed(base) // ROL(base, n/8) XOR DC

	// Recompute MAC and verify before decrypting (verify-then-decrypt)
	macKey  := HskeNla1MacKey(seed, base)
	ivConst := new(big.Int).SetBytes(Hfscx256IV[:])
	macIV   := NewBitArray(n, new(big.Int).Xor(&macKey.Val, ivConst))
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

// ── main ─────────────────────────────────────────────────────────────────────

func die(prefix string, err error) {
	fmt.Fprintln(os.Stderr, prefix+":", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: herradura_cli_go <command> [options]

Commands:
  genpkey  --algo ALGO [--bits N] [--out FILE]
  pkey     --in FILE (--pubout | --text) [--out FILE]
  kex      --algo ALGO --our FILE --their FILE [--out FILE]
  enc      --algo ALGO (--key FILE | --pubkey FILE) --in FILE [--out FILE]
  dec      --algo ALGO --key FILE --in FILE [--out FILE]
  sign     --algo ALGO --key FILE --in FILE [--digest hfscx-256] [--out FILE]
  verify   --algo ALGO --pubkey FILE --in FILE --sig FILE [--digest hfscx-256]
  encfile  --key FILE --in FILE --out FILE
  decfile  --key FILE --in FILE --out FILE
  dgst     [--algo hfscx-256] --in FILE [--out FILE]

Algorithms (genpkey/pkey): hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpks-stern hpke-stern
Algorithms (kex):           hkex-gf hkex-rnl
Algorithms (enc/dec):       hske hske-nla1 hske-nla2 hpke hpke-nl hpke-stern
Algorithms (encfile/decfile): hske-nla1
Algorithms (sign/verify):   hpks hpks-nl hpks-stern
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}
