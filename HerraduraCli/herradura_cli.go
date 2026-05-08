// HerraduraCli/herradura_cli.go — Go CLI for the Herradura Cryptographic Suite
// v1.5.27
//
// Usage:
//   herradura_cli_go genpkey --algo hkex-gf  --bits 256 --out alice.pem
//   herradura_cli_go pkey    --in alice.pem   --pubout  --out alice_pub.pem
//   herradura_cli_go kex     --algo hkex-gf   --our alice.pem --their bob_pub.pem --out sk.pem
//   herradura_cli_go dgst    --in file.bin                       # hex to stdout
//   herradura_cli_go dgst    --algo hfscx-256 --in file.bin --out d.pem
//
// HKEX-RNL (2-round):
//   herradura_cli_go kex --algo hkex-rnl --our bob.pem --their alice_pub.pem --out resp.pem
//   herradura_cli_go kex --algo hkex-rnl --our alice.pem --their resp.pem    --out sk.pem
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"

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
// hint is Go's native packed hint (bit i/8 of byte[i] = coeff i hint).
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
  dgst     [--algo hfscx-256] --in FILE [--out FILE]

Algorithms (genpkey/pkey): hkex-gf hkex-rnl hpks hpks-nl hpke hpke-nl hpks-stern hpke-stern
Algorithms (kex):           hkex-gf hkex-rnl
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
	case "dgst":
		cmdDgst(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}
