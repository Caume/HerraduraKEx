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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"

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

// ── HCRED-KKW (TODO #266) ───────────────────────────────────────────────────
//
// This is the one vector set here that is CONSUMED rather than recomputed.
// hcred_prove_kkw is randomised (one root seed per emulation), so there is no
// deterministic transcript for Go to reproduce; what Go can do — and what the
// item is actually about — is READ Python's transcript and accept it, then
// reject each tampered variant.  Every KKW bug that has actually shipped was a
// reader disagreement about a byte layout (an inverted aux-reveal condition in
// this very package; a mis-sized commitment buffer and a flipped bit convention
// in C), and each of them is exactly what this catches.
type kkwFile struct {
	Sets map[string]kkwSet `json:"sets"`
}

// kkwProofJSON is the on-disk shape of a KKW proof.  ONE type for both
// vectors: hcred_kkw.json pins a transcript to CONSUME and
// operation_replay.json pins one this port must PRODUCE (TODO #303), and a
// second reader for the second vector would be a second opinion about the very
// byte layout every KKW bug so far has been a disagreement over.
type kkwProofJSON struct {
	W      int               `json:"W"`
	Params []int             `json:"params"`
	Pre    map[string]string `json:"pre"`
	Online map[string]struct {
		Pbar int             `json:"pbar"`
		Path [][]interface{} `json:"path"`
		ComH string          `json:"com_h"`
		Aux  *string         `json:"aux"`
		Zin  string          `json:"zin"`
		T    string          `json:"t"`
		U    int             `json:"u"`
	} `json:"online"`
}

type kkwSet struct {
	Params struct {
		N        int `json:"n"`
		NPar     int `json:"N_par"`
		M        int `json:"M"`
		Tau      int `json:"tau"`
		Rows     int `json:"rows"`
		RowBits  int `json:"row_bits"`
	} `json:"params"`
	Statement struct {
		MPoly string `json:"m_poly"`
		CPoly string `json:"C_poly"`
		SeedH string `json:"seed_H"`
		Y     string `json:"y"`
		Msg   string `json:"msg"`
	} `json:"statement"`
	Proof  kkwProofJSON `json:"proof"`
	Tamper []struct {
		Name  string `json:"name"`
		Apply string `json:"apply"`
	} `json:"tamper"`
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex: " + s)
	}
	return b
}

// unpackVec decodes the 3-bytes-per-coefficient encoding the vector uses for
// every Z_q vector (the protocol's own _hcred_ser layout).
func unpackVec(s string) []int {
	b := mustHex(s)
	out := make([]int, len(b)/3)
	for i := range out {
		out[i] = int(b[3*i])<<16 | int(b[3*i+1])<<8 | int(b[3*i+2])
	}
	return out
}

// packVec is unpackVec's inverse: the protocol's own 3-bytes-per-coefficient
// encoding (_hcred_ser), which is how every Z_q vector travels in the vectors.
func packVec(v []int) string {
	b := make([]byte, 3*len(v))
	for i, c := range v {
		b[3*i], b[3*i+1], b[3*i+2] = byte(c>>16), byte(c>>8), byte(c)
	}
	return hex.EncodeToString(b)
}

// intListStr renders a support (or any int list) for comparison against the
// vector's JSON array, sorted -- a support is a SET in Python and a slice
// here, so the order is the port's, not the protocol's.
func intListStr(v []int) string {
	c := append([]int(nil), v...)
	sort.Ints(c)
	parts := make([]string, len(c))
	for i, x := range c {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}

func jsonIntListStr(x interface{}) string {
	l := x.([]interface{})
	v := make([]int, len(l))
	for i, e := range l {
		v[i] = int(e.(float64))
	}
	return intListStr(v)
}

// buildKkwProof rebuilds the Go proof struct from the pinned JSON.  Kept
// separate from verifyKkw so each tamper case can start from a fresh copy.
func buildKkwProof(v kkwProofJSON) *HcredKkwProof {
	p := &HcredKkwProof{
		W: v.W, NPar: v.Params[0], M: v.Params[1],
		Tau: v.Params[2],
		Pre: map[int][]byte{}, Online: map[int]*KkwOnlineProof{},
	}
	for e, root := range v.Pre {
		var ei int
		fmt.Sscanf(e, "%d", &ei)
		p.Pre[ei] = mustHex(root)
	}
	for e, od := range v.Online {
		var ei int
		fmt.Sscanf(e, "%d", &ei)
		path := make([]KkwPathEntry, len(od.Path))
		for i, pe := range od.Path {
			path[i] = KkwPathEntry{
				L: int(pe[0].(float64)), I: int(pe[1].(float64)),
				Node: mustHex(pe[2].(string)),
			}
		}
		var aux []int
		if od.Aux != nil {
			aux = unpackVec(*od.Aux)
		}
		p.Online[ei] = &KkwOnlineProof{
			Path: path, ComH: mustHex(od.ComH), Pbar: od.Pbar, Aux: aux,
			Zin: unpackVec(od.Zin), T: unpackVec(od.T), U: od.U,
		}
	}
	return p
}

// buildKkwProofFrom re-reads an already-decoded `expect` object through the
// SAME kkwProofJSON parser, so operation_replay.json's row and hcred_kkw.json's
// transcript are understood by one piece of code rather than two.
func buildKkwProofFrom(expect map[string]interface{}) *HcredKkwProof {
	raw, err := json.Marshal(expect)
	if err != nil {
		panic("cannot re-marshal the KKW expect object: " + err.Error())
	}
	var pj kkwProofJSON
	if err := json.Unmarshal(raw, &pj); err != nil {
		panic("cannot parse the KKW expect object: " + err.Error())
	}
	return buildKkwProof(pj)
}

// compareKkwProof reports WHICH field of WHICH emulation diverged.  Field by
// field rather than one serialize-and-diff: the whole point of the row is to
// say where two ports disagree, and every KKW bug found so far has been in one
// named field (an inverted aux-reveal condition, a mis-sized commitment buffer,
// a flipped bit convention).
func compareKkwProof(name string, got, want *HcredKkwProof) int {
	fails := 0
	bad := func(what string, g, w interface{}) {
		fmt.Printf("FAIL op %s: %s is %v, vector says %v\n", name, what, g, w)
		fails++
	}
	if got.W != want.W {
		bad("W", got.W, want.W)
	}
	if got.NPar != want.NPar || got.M != want.M || got.Tau != want.Tau {
		bad("params", []int{got.NPar, got.M, got.Tau},
			[]int{want.NPar, want.M, want.Tau})
	}
	// The unopened set is the cut-and-choose challenge, derived by Fiat-Shamir
	// from every emulation's commitments -- so a divergence in ANY of the M
	// preprocessing emulations, opened or not, moves it.
	if len(got.Pre) != len(want.Pre) {
		bad("unopened emulation count", len(got.Pre), len(want.Pre))
	} else {
		for e, root := range want.Pre {
			g, ok := got.Pre[e]
			if !ok {
				bad(fmt.Sprintf("emulation %d unopened", e), "opened", "unopened")
			} else if !bytes.Equal(g, root) {
				bad(fmt.Sprintf("pre[%d] root", e), hex.EncodeToString(g),
					hex.EncodeToString(root))
			}
		}
	}
	eqInts := func(a, b []int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if len(got.Online) != len(want.Online) {
		bad("opened emulation count", len(got.Online), len(want.Online))
		return fails
	}
	for e, w := range want.Online {
		g, ok := got.Online[e]
		if !ok {
			bad(fmt.Sprintf("emulation %d opened", e), "unopened", "opened")
			continue
		}
		pfx := fmt.Sprintf("online[%d].", e)
		if g.Pbar != w.Pbar {
			bad(pfx+"pbar", g.Pbar, w.Pbar)
		}
		if !bytes.Equal(g.ComH, w.ComH) {
			bad(pfx+"com_h", hex.EncodeToString(g.ComH), hex.EncodeToString(w.ComH))
		}
		if len(g.Path) != len(w.Path) {
			bad(pfx+"path length", len(g.Path), len(w.Path))
		} else {
			for i := range w.Path {
				if g.Path[i].L != w.Path[i].L || g.Path[i].I != w.Path[i].I ||
					!bytes.Equal(g.Path[i].Node, w.Path[i].Node) {
					bad(fmt.Sprintf("%spath[%d]", pfx, i),
						fmt.Sprintf("(%d,%d,%s)", g.Path[i].L, g.Path[i].I,
							hex.EncodeToString(g.Path[i].Node)),
						fmt.Sprintf("(%d,%d,%s)", w.Path[i].L, w.Path[i].I,
							hex.EncodeToString(w.Path[i].Node)))
					break
				}
			}
		}
		// aux is revealed exactly when the hidden party is not party N_par-1.
		// Reading that condition the wrong way round is the bug this package
		// actually shipped (TODO #266), so nil-ness is compared before content.
		if (g.Aux == nil) != (w.Aux == nil) {
			bad(pfx+"aux revealed", g.Aux != nil, w.Aux != nil)
		} else if g.Aux != nil && !eqInts(g.Aux, w.Aux) {
			bad(pfx+"aux", "differs", "the pinned vector")
		}
		if !eqInts(g.Zin, w.Zin) {
			bad(pfx+"zin", "differs", "the pinned vector")
		}
		if !eqInts(g.T, w.T) {
			bad(pfx+"t", "differs", "the pinned vector")
		}
		if g.U != w.U {
			bad(pfx+"u", g.U, w.U)
		}
	}
	if fails == 0 {
		fmt.Printf("PASS op %s (%d emulations opened, %d unopened)\n",
			name, len(want.Online), len(want.Pre))
	}
	return fails
}

// applyKkwTamper mirrors _kkw_apply_tamper in KAT/generate_kat.py.  The two
// must agree case for case: a mutation Python applies and Go does not would
// silently downgrade a rejection test into a second accept test.
func applyKkwTamper(p *HcredKkwProof, msg []byte, which string) (*HcredKkwProof, []byte) {
	// Deep-copy only what a case mutates; Pre and Online are shared maps.
	cp := *p
	cp.Pre = map[int][]byte{}
	for k, v := range p.Pre {
		b := make([]byte, len(v))
		copy(b, v)
		cp.Pre[k] = b
	}
	cp.Online = map[int]*KkwOnlineProof{}
	for k, v := range p.Online {
		o := *v
		o.T = append([]int(nil), v.T...)
		cp.Online[k] = &o
	}
	e0, r0 := -1, -1
	for k := range cp.Online {
		if e0 < 0 || k < e0 {
			e0 = k
		}
	}
	for k := range cp.Pre {
		if r0 < 0 || k < r0 {
			r0 = k
		}
	}
	switch which {
	case "msg":
		return &cp, append(append([]byte(nil), msg...), '!')
	case "W":
		cp.W++
	case "online[0].u":
		cp.Online[e0].U = (cp.Online[e0].U + 1) % RnlQ
	case "online[0].t[0]":
		cp.Online[e0].T[0] = (cp.Online[e0].T[0] + 1) % RnlQ
	case "pre[0][0]":
		cp.Pre[r0][0] ^= 1
	case "online[0].pbar":
		cp.Online[e0].Pbar = (cp.Online[e0].Pbar + 1) % cp.NPar
	default:
		panic("unknown tamper case " + which)
	}
	return &cp, msg
}

func verifyKkwSet(name string, v kkwSet) int {
	n := v.Params.N
	m := unpackVec(v.Statement.MPoly)
	c := unpackVec(v.Statement.CPoly)
	seedH := hexToBA(n, v.Statement.SeedH)
	y := hexToBig(v.Statement.Y)
	msg := mustHex(v.Statement.Msg)

	fails := 0
	if !HcredVerifyKkw(m, c, seedH, y, buildKkwProof(v.Proof), n, msg) {
		fmt.Printf("FAIL %s: Go REJECTS the pinned Python transcript "+
			"— the two implementations disagree on the wire format\n", name)
		fails++
	} else {
		fmt.Printf("PASS %s (Go accepts the pinned Python transcript, n=%d)\n", name, n)
	}
	// The accept above is not self-validating: a verifier that returned true
	// unconditionally would pass it.  Each tamper case must be rejected.
	for _, tc := range v.Tamper {
		tp, tmsg := applyKkwTamper(buildKkwProof(v.Proof), msg, tc.Apply)
		if HcredVerifyKkw(m, c, seedH, y, tp, n, tmsg) {
			fmt.Printf("FAIL %s tamper %q ACCEPTED\n", name, tc.Name)
			fails++
		}
	}
	if fails == 0 {
		fmt.Printf("PASS %s tamper (%d/%d rejected)\n",
			name, len(v.Tamper), len(v.Tamper))
	}
	return fails
}

// ── TODO #296: fixed-stream sampler replay ──────────────────────────────
//
// Replaces crypto/rand's source with the vector's fixed stream and checks
// what the SHIPPED samplers produce.  This is the only check available for a
// sampler whose output reaches no artifact (TODO #294): no KAT can pin a
// value that is fresh per call, and no interop pair compares two samplers.
//
// The swap is `rand.Reader = <fixed>`, which is a documented package variable
// but not a guaranteed one -- a future Go that sourced rand.Read from the
// kernel directly would silently feed these samplers real entropy.  That
// failure mode is LOUD rather than silent here by construction: the outputs
// would not match the vector and every row would fail.  Do not "fix" such a
// failure by relaxing the comparison.
type countingReader struct {
	data []byte
	pos  int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func verifySamplerReplay(v map[string]interface{}) int {
	fails := 0
	check := func(name, got, want string) {
		if got != want {
			fmt.Printf("FAIL %s: got %s want %s\n", name, got, want)
			fails++
		} else {
			fmt.Println("PASS " + name)
		}
	}

	saved := rand.Reader
	defer func() { rand.Reader = saved }()

	rows, ok := v["samplers"].([]interface{})
	if !ok || len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "sampler_replay.json has no samplers")
		return fails + 1
	}

	for _, ri := range rows {
		r := ri.(map[string]interface{})
		name := str(r, "name")
		params := r["params"].(map[string]interface{})
		cr := &countingReader{data: mustHex(str(r, "stream"))}
		rand.Reader = cr

		switch name {
		case "rnl_cbd_poly":
			check("replay "+name, polyHex(RnlCBDPoly(num(params, "n"), num(params, "q")), 3),
				str(r, "expect_poly"))
		case "rnl_rand_poly":
			check("replay "+name, polyHex(RnlRandPoly(num(params, "n"), num(params, "q")), 3),
				str(r, "expect_poly"))
		case "stern_weight_t":
			n := num(params, "n")
			e := SternRandError(n, num(params, "t"))
			check("replay "+name, fmt.Sprintf("%0*x", n/4, &e.Val), str(r, "expect_value"))
		case "oprf_blind_scalar":
			n := num(params, "bits")
			rr, alpha, err := OprfBlind(mustHex(str(params, "input_hex")), n)
			if err != nil {
				fmt.Printf("FAIL replay %s: %s\n", name, err)
				fails++
				continue
			}
			check("replay "+name+" r", fmt.Sprintf("%0*x", n/4, rr), str(r, "expect_r"))
			check("replay "+name+" alpha", fmt.Sprintf("%0*x", n/4, alpha), str(r, "expect_alpha"))
		default:
			fmt.Printf("FAIL replay: unknown sampler %q -- a row was added to "+
				"the vector and no Go consumer follows it\n", name)
			fails++
			continue
		}

		// A null `consumed` means the four ports read the stream at
		// different granularities and only the output is common; the
		// vector carries the reason on the row.  Anything else is an
		// assertion, and it is the half that catches a port reading
		// ahead of or behind the others.
		if cv, present := r["consumed"]; present && cv != nil {
			want := int(cv.(float64))
			if cr.pos != want {
				fmt.Printf("FAIL replay %s: consumed %d stream bytes, vector says %d\n",
					name, cr.pos, want)
				fails++
			} else {
				fmt.Printf("PASS replay %s consumed %d bytes\n", name, want)
			}
		}
	}
	return fails
}

// ── TODO #297: fixed-stream OPERATION replay ────────────────────────────────
//
// One level above verifySamplerReplay.  A leaf row is one call with scalar
// arguments; these rows supply a fixed STATEMENT as well as a fixed stream and
// pin what a whole randomised operation produces, so the ORDER in which it
// visits its samplers -- and any inline draw loop that is not a callable
// sampler at all -- is held against the other three ports.  TODO #294's own
// defect was of the second kind: RnlSigmaSign's mask draw is written out inside
// the signing loop.
//
// The rand.Reader swap is the same fragile hook verifySamplerReplay documents,
// and the same argument applies: if a future Go bypasses the package variable,
// every row here fails LOUDLY rather than passing vacuously.  Do not "fix" such
// a failure by relaxing the comparison.
func verifyOperationReplay(v map[string]interface{}) int {
	fails := 0
	check := func(name, got, want string) {
		if got != want {
			fmt.Printf("FAIL %s: got %s want %s\n", name, got, want)
			fails++
		} else {
			fmt.Println("PASS " + name)
		}
	}
	baHex := func(ba *BitArray, n int) string { return fmt.Sprintf("%0*x", n/4, &ba.Val) }
	// Centered coefficients as 4-byte big-endian two's complement, which is
	// what the vector holds because it is what C's int32_t already holds.
	i32Hex := func(vals []int) string {
		var sb strings.Builder
		for _, x := range vals {
			sb.WriteString(fmt.Sprintf("%08x", uint32(int32(x))))
		}
		return sb.String()
	}
	strList := func(x interface{}) []interface{} { return x.([]interface{}) }

	saved := rand.Reader
	defer func() { rand.Reader = saved }()

	rows, ok := v["operations"].([]interface{})
	if !ok || len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "operation_replay.json has no operations")
		return fails + 1
	}

	for _, ri := range rows {
		r := ri.(map[string]interface{})
		name := str(r, "name")
		params := r["params"].(map[string]interface{})
		stmt := r["statement"].(map[string]interface{})
		expect := r["expect"].(map[string]interface{})
		cr := &countingReader{data: mustHex(str(r, "stream"))}
		rand.Reader = cr

		switch name {
		case "stern_f_keygen":
			n := num(params, "n")
			seed, e, syn := SternFKeygen(n)
			check("op "+name+" seed", baHex(seed, n), str(expect, "seed"))
			check("op "+name+" e", baHex(e, n), str(expect, "e"))
			check("op "+name+" syndrome",
				fmt.Sprintf("%0*x", num(params, "n_rows")/4, syn),
				str(expect, "syndrome"))

		case "hpks_stern_f_sign":
			n, rounds := num(params, "n"), num(params, "rounds")
			msg := NewFromBytes(mustHex(str(stmt, "msg")), 0, n)
			e := NewFromBytes(mustHex(str(stmt, "e")), 0, n)
			seed := NewFromBytes(mustHex(str(stmt, "seed")), 0, n)
			sig := HpksSternFSign(msg, e, seed, rounds)
			coms, chs, resps := strList(expect["commits"]), strList(expect["challenges"]),
				strList(expect["responses"])
			bad := -1
			for i := 0; i < rounds; i++ {
				c := strList(coms[i])
				if baHex(sig.Rounds[i].C0, n) != c[0].(string) ||
					baHex(sig.Rounds[i].C1, n) != c[1].(string) ||
					baHex(sig.Rounds[i].C2, n) != c[2].(string) {
					bad = i
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: commitments differ at round %d\n", name, bad)
				fails++
			} else {
				fmt.Println("PASS op " + name + " commitments")
			}
			bad = -1
			for i := 0; i < rounds; i++ {
				if sig.Rounds[i].B != int(chs[i].(float64)) {
					bad = i
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: challenge %d is %d, vector says %v\n",
					name, bad, sig.Rounds[bad].B, chs[bad])
				fails++
			} else {
				fmt.Println("PASS op " + name + " challenges")
			}
			// All three challenge values occur in this vector's stream, so
			// this one comparison covers all three response branches.
			bad = -1
			for i := 0; i < rounds; i++ {
				p := strList(resps[i])
				if baHex(sig.Rounds[i].RespA, n) != p[0].(string) ||
					baHex(sig.Rounds[i].RespB, n) != p[1].(string) {
					bad = i
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: response differs at round %d (b=%d)\n",
					name, bad, sig.Rounds[bad].B)
				fails++
			} else {
				fmt.Println("PASS op " + name + " responses")
			}

		case "zkp_nl_prove":
			n, rounds := num(params, "n"), num(params, "rounds")
			a, _ := new(big.Int).SetString(str(stmt, "a"), 16)
			b, _ := new(big.Int).SetString(str(stmt, "b"), 16)
			y, _ := new(big.Int).SetString(str(stmt, "y"), 16)
			proof, err := ZkpNlProve(a.Uint64(), b.Uint64(), y.Uint64(), n, rounds,
				mustHex(str(stmt, "msg_hex")))
			if err != nil {
				fmt.Printf("FAIL op %s: %s\n", name, err)
				fails++
				continue
			}
			want := strList(expect["rounds"])
			bad := -1
			for i := 0; i < rounds; i++ {
				w := want[i].(map[string]interface{})
				if hex.EncodeToString(proof[i].Com0[:]) != str(w, "com_0") ||
					hex.EncodeToString(proof[i].Com1[:]) != str(w, "com_1") ||
					hex.EncodeToString(proof[i].Com2[:]) != str(w, "com_2") {
					bad = i
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: commitments differ at round %d\n", name, bad)
				fails++
			} else {
				fmt.Println("PASS op " + name + " commitments")
			}
			bad = -1
			for i := 0; i < rounds; i++ {
				w := want[i].(map[string]interface{})
				if proof[i].E != num(w, "e") ||
					hex.EncodeToString(proof[i].ViewP1) != str(w, "view_p1") ||
					hex.EncodeToString(proof[i].ViewP2) != str(w, "view_p2") {
					bad = i
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: views differ at round %d (e=%d)\n",
					name, bad, proof[bad].E)
				fails++
			} else {
				fmt.Println("PASS op " + name + " views")
			}

		case "hpks_stern_ring_sign":
			// Two divergences lived in this operation and neither was visible
			// to any other check: the challenge trit had three schemes across
			// the four ports, and the b = 0 dummy commitment was a CONSTANT in
			// C and Go, which identified the real signer from the public
			// signature.  See sternSimulateRound.
			n := num(params, "n")
			k, rounds := num(params, "k"), num(params, "rounds")
			j := num(params, "j")
			seeds := strList(stmt["seeds"])
			syns := strList(stmt["syndromes"])
			ring := make([]RingKeypair, k)
			for i := 0; i < k; i++ {
				sy, _ := new(big.Int).SetString(syns[i].(string), 16)
				ring[i] = RingKeypair{
					Seed:     NewFromBytes(mustHex(seeds[i].(string)), 0, n),
					Syndrome: sy,
				}
			}
			msg := NewFromBytes(mustHex(str(stmt, "msg")), 0, n)
			e := NewFromBytes(mustHex(str(stmt, "e")), 0, n)
			sig := HpksSternRingSign(msg, e, j, ring, rounds)
			coms, chs, resps := strList(expect["commits"]), strList(expect["challenges"]),
				strList(expect["responses"])
			bi, br := -1, -1
			for i := 0; i < k && bi < 0; i++ {
				mc := strList(coms[i])
				for r := 0; r < rounds; r++ {
					c := strList(mc[r])
					rd := sig.Members[i].Rounds[r]
					if baHex(rd.C0, n) != c[0].(string) || baHex(rd.C1, n) != c[1].(string) ||
						baHex(rd.C2, n) != c[2].(string) {
						bi, br = i, r
						break
					}
				}
			}
			if bi >= 0 {
				fmt.Printf("FAIL op %s: commitments differ at member %d round %d\n",
					name, bi, br)
				fails++
			} else {
				fmt.Println("PASS op " + name + " commitments")
			}
			bi, br = -1, -1
			for i := 0; i < k && bi < 0; i++ {
				mb := strList(chs[i])
				for r := 0; r < rounds; r++ {
					if sig.Members[i].Rounds[r].B != int(mb[r].(float64)) {
						bi, br = i, r
						break
					}
				}
			}
			if bi >= 0 {
				fmt.Printf("FAIL op %s: challenge at member %d round %d is %d, vector says %v\n",
					name, bi, br, sig.Members[bi].Rounds[br].B, strList(chs[bi])[br])
				fails++
			} else {
				fmt.Println("PASS op " + name + " challenges")
			}
			bi, br = -1, -1
			for i := 0; i < k && bi < 0; i++ {
				mr := strList(resps[i])
				for r := 0; r < rounds; r++ {
					p := strList(mr[r])
					rd := sig.Members[i].Rounds[r]
					if baHex(rd.RespA, n) != p[0].(string) || baHex(rd.RespB, n) != p[1].(string) {
						bi, br = i, r
						break
					}
				}
			}
			if bi >= 0 {
				fmt.Printf("FAIL op %s: response differs at member %d round %d (b=%d)\n",
					name, bi, br, sig.Members[bi].Rounds[br].B)
				fails++
			} else {
				fmt.Println("PASS op " + name + " responses")
			}
			// The signature must still VERIFY: the fix changed a dummy
			// commitment no verifier checks, and a vector alone would not say so.
			if !HpksSternRingVerify(msg, sig, ring) {
				fmt.Println("FAIL op " + name + " verifies")
				fails++
			} else {
				fmt.Println("PASS op " + name + " verifies")
			}

		case "rnl_sigma_sign":
			n := num(params, "n")
			sPoly := unpackPoly(str(stmt, "s_poly"), n, 3)
			mPoly := unpackPoly(str(stmt, "m_poly"), n, 3)
			cPoly := unpackPoly(str(stmt, "c_poly"), n, 3)
			w, c, z, err := RnlSigmaSign(sPoly, mPoly, cPoly, n,
				mustHex(str(stmt, "msg_hex")))
			if err != nil {
				// The stream is exactly one buffered block and is chosen to
				// accept on the FIRST attempt; a retry runs off its end.
				fmt.Printf("FAIL op %s: %s\n", name, err)
				fails++
				continue
			}
			check("op "+name+" w", i32Hex(w), str(expect, "w"))
			check("op "+name+" c", i32Hex(c), str(expect, "c"))
			check("op "+name+" z", i32Hex(z), str(expect, "z"))

		case "hcred_prove_kkw":
			// The row TODO #303 added, and the gap TODO #302 §6 found: KKW's
			// PROVER was pinned nowhere.  hcred_kkw.json is verify-side by
			// construction (one os.urandom root per emulation, so a proof is
			// not a function of its statement) and KKW has no CLI surface, so
			// the 4x4 matrix does not reach it either -- leaving each port's
			// prover checked only against its OWN verifier, which is the shape
			// that let three of four ports ship a transcription bug at #266.
			// A fixed stream makes the prover a function again.
			//
			// `expect` is the SAME layout hcred_kkw.json's `proof` uses, so
			// buildKkwProof reads it unchanged: the comparison is against a
			// proof this file already knows how to parse, not against a second
			// opinion of the byte layout.
			n := num(params, "n")
			sPoly := unpackVec(str(stmt, "s_poly"))
			mPoly := unpackVec(str(stmt, "m_poly"))
			cPoly := unpackVec(str(stmt, "c_poly"))
			seedH := hexToBA(n, str(stmt, "seed_H"))
			y := hexToBig(str(stmt, "y"))
			got, err := HcredProveKkw(sPoly, mPoly, cPoly, seedH, y, n,
				num(params, "N_par"), num(params, "M"), num(params, "tau"),
				mustHex(str(stmt, "msg_hex")))
			if err != nil {
				fmt.Printf("FAIL op %s: %s\n", name, err)
				fails++
				continue
			}
			want := buildKkwProofFrom(expect)
			fails += compareKkwProof(name, got, want)

		// === TODO #307: the four rows #305's coverage census left OWED ====
		case "qcmdpc_keygen":
			// What is pinned is the LOOP, not the PRF: numbered test [52]
			// pins the seed expansion (TODO #277's 3-vs-1 byte-order split)
			// and KAT/pem/'s kem_priv is verify-side, so neither says
			// anything about the order seed -> sup0 -> sup1 -> screen ->
			// inversion.  The stream REJECTS ONCE on the weak-key screen and
			// then accepts, which pins the reject branch too -- a branch
			// about one draw in 550 reaches.
			r := num(params, "r")
			sup0, sup1, _, _, hPub := QcMdpcKeygen(nil)
			check("op "+name+" sup0", intListStr(sup0), jsonIntListStr(expect["sup0"]))
			check("op "+name+" sup1", intListStr(sup1), jsonIntListStr(expect["sup1"]))
			check("op "+name+" h_pub", fmt.Sprintf("%0*x", (r+3)/4, hPub),
				str(expect, "h_pub"))

		case "qcmdpc_encap":
			r := num(params, "r")
			hPub := hexToBig(str(stmt, "h_pub"))
			syn, K := QcMdpcEncap(hPub, nil)
			check("op "+name+" syndrome", fmt.Sprintf("%0*x", (r+3)/4, syn),
				str(expect, "syndrome"))
			check("op "+name+" k", hex.EncodeToString(K), str(expect, "k"))

		case "zkp_nl_pp_prove":
			// NARROWS TODO #302 §6: that section's "covered twice over" is
			// true of the CIRCUIT, which neither port carries its own copy
			// of, and does not extend to the SEED DRAW ORDER -- this
			// function's own consumption order, which no row pinned.  §2 of
			// the same file makes the 16-byte seed a security parameter.
			n, rounds := num(params, "n"), num(params, "rounds")
			pp, err := ZkpNlProvepp(hexToBig(str(stmt, "a")).Uint64(),
				hexToBig(str(stmt, "b")).Uint64(),
				hexToBig(str(stmt, "y")).Uint64(),
				n, rounds, mustHex(str(stmt, "msg_hex")))
			if err != nil {
				fmt.Printf("FAIL op %s: %s\n", name, err)
				fails++
				continue
			}
			want := strList(expect["rounds"])
			if len(pp) != len(want) {
				fmt.Printf("FAIL op %s: %d rounds, vector says %d\n",
					name, len(pp), len(want))
				fails++
				continue
			}
			bad := -1
			for j := range pp {
				w := want[j].(map[string]interface{})
				// share2 is EMPTY exactly when E == 2, because party 2's
				// share is DERIVED rather than seeded (TODO #302 §2) -- so
				// the empty case is a field value, not a missing field.
				if pp[j].E != num(w, "e") ||
					hex.EncodeToString(pp[j].ComE[:]) != str(w, "com_e") ||
					hex.EncodeToString(pp[j].OutE) != str(w, "out_e") ||
					hex.EncodeToString(pp[j].SeedP1[:]) != str(w, "seed_p1") ||
					hex.EncodeToString(pp[j].SeedP2[:]) != str(w, "seed_p2") ||
					hex.EncodeToString(pp[j].GatesP2) != str(w, "gates_p2") ||
					hex.EncodeToString(pp[j].Share2) != str(w, "share2") {
					bad = j
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: round %d differs (e=%d)\n",
					name, bad, pp[bad].E)
				fails++
			} else {
				fmt.Println("PASS op " + name + " rounds")
			}

		case "hcred_prove":
			// HCRED's OTHER prover, beside the KKW one above: same file,
			// same witness, and TODO #266's transcription bug was in this
			// family.  Numbered test [50] runs each port's prover against
			// ITS OWN verifier, which is precisely the shape that lets a
			// transcription bug pass in three of four ports.
			n, rounds := num(params, "n"), num(params, "rounds")
			pf, err := HcredProve(unpackVec(str(stmt, "s_poly")),
				unpackVec(str(stmt, "m_poly")), unpackVec(str(stmt, "c_poly")),
				hexToBA(n, str(stmt, "seed_H")), hexToBig(str(stmt, "y")),
				n, rounds, mustHex(str(stmt, "msg_hex")))
			if err != nil {
				fmt.Printf("FAIL op %s: %s\n", name, err)
				fails++
				continue
			}
			check("op "+name+" W", fmt.Sprintf("%d", pf.W),
				fmt.Sprintf("%d", num(expect, "W")))
			want := strList(expect["rounds"])
			if len(pf.Rounds) != len(want) {
				fmt.Printf("FAIL op %s: %d rounds, vector says %d\n",
					name, len(pf.Rounds), len(want))
				fails++
				continue
			}
			bad, badField := -1, ""
			for j := range pf.Rounds {
				w := want[j].(map[string]interface{})
				rd := &pf.Rounds[j]
				cw := strList(w["coms"])
				for p := 0; p < 3 && bad < 0; p++ {
					if hex.EncodeToString(rd.Coms[p]) != cw[p].(string) {
						bad, badField = j, fmt.Sprintf("coms[%d]", p)
					}
				}
				if bad >= 0 {
					break
				}
				// `outs` travels as the suite's OWN serialisation, the one
				// that feeds the FS hash, so this compares one hex string
				// rather than four opinions of a nested layout.
				for _, f := range []struct {
					key string
					got string
				}{
					{"outs", hex.EncodeToString(HcredOutputsSer(&rd.Outs))},
					{"seed_c", hex.EncodeToString(rd.SeedC)},
					{"seed_c1", hex.EncodeToString(rd.SeedC1)},
					{"a1", packVec(rd.A1)}, {"b1", packVec(rd.B1)},
					{"g1", packVec(rd.G1)}, {"h1", packVec(rd.H1)},
				} {
					if f.got != str(w, f.key) {
						bad, badField = j, f.key
						break
					}
				}
				if bad >= 0 {
					break
				}
				// aux is NULL on a round where party 2 is not opened, and
				// that nullness IS the aux-reveal condition the Go port read
				// backwards at TODO #266 -- so a nil where the vector has a
				// vector (or the reverse) is the failure, not a skip.
				for _, f := range []struct {
					key string
					got []int
				}{
					{"aux_s", rd.AuxS}, {"aux_B", rd.AuxB}, {"aux_D", rd.AuxD},
				} {
					wv, present := w[f.key]
					if (f.got == nil) != (wv == nil) || !present {
						bad, badField = j, f.key+" (reveal condition)"
						break
					}
					if f.got != nil && packVec(f.got) != wv.(string) {
						bad, badField = j, f.key
						break
					}
				}
				if bad >= 0 {
					break
				}
			}
			if bad >= 0 {
				fmt.Printf("FAIL op %s: round %d differs at %s\n", name, bad, badField)
				fails++
			} else {
				fmt.Println("PASS op " + name + " rounds")
			}
			if !HcredVerify(unpackVec(str(stmt, "m_poly")),
				unpackVec(str(stmt, "c_poly")), hexToBA(n, str(stmt, "seed_H")),
				hexToBig(str(stmt, "y")), pf, n, rounds,
				mustHex(str(stmt, "msg_hex"))) {
				fmt.Println("FAIL op " + name + " verifies")
				fails++
			} else {
				fmt.Println("PASS op " + name + " verifies")
			}

		default:
			fmt.Printf("FAIL op replay: unknown operation %q -- a row was added "+
				"to the vector and no Go consumer follows it\n", name)
			fails++
			continue
		}

		// A null `consumed` means the ports read at different granularities
		// and only the output is common; the row carries the reason.
		if cv, present := r["consumed"]; present && cv != nil {
			want := int(cv.(float64))
			if cr.pos != want {
				fmt.Printf("FAIL op %s: consumed %d stream bytes, vector says %d\n",
					name, cr.pos, want)
				fails++
			} else {
				fmt.Printf("PASS op %s consumed %d bytes\n", name, want)
			}
		}
	}
	return fails
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

	// ── HCRED-KKW (TODO #266) ───────────────────────────────────────────
	if vdata, err := os.ReadFile("KAT/hcred_kkw.json"); err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/hcred_kkw.json:", err)
		fails++
	} else {
		var vv kkwFile
		if err := json.Unmarshal(vdata, &vv); err != nil {
			fmt.Fprintln(os.Stderr, "cannot parse KAT/hcred_kkw.json:", err)
			fails++
		} else {
			// Both sets, and the full tamper matrix on each: Go is
			// compiled, so the n=256 pass that costs Python ~70 s
			// per verification costs well under a second here.
			// That is why check_kkw defers it to the consumers.
			if len(vv.Sets) == 0 {
				fmt.Fprintln(os.Stderr, "KAT/hcred_kkw.json has no vector sets")
				fails++
			}
			for _, sn := range []string{"n256", "n32"} {
				sv, ok := vv.Sets[sn]
				if !ok {
					fmt.Printf("FAIL hcred_kkw: set %q missing\n", sn)
					fails++
					continue
				}
				fails += verifyKkwSet("hcred_kkw["+sn+"]", sv)
			}
		}
	}

	// ── sampler replay (TODO #296) ──────────────────────────────────────
	if vdata, err := os.ReadFile("KAT/sampler_replay.json"); err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/sampler_replay.json:", err)
		fails++
	} else {
		var sv map[string]interface{}
		if err := json.Unmarshal(vdata, &sv); err != nil {
			fmt.Fprintln(os.Stderr, "cannot parse KAT/sampler_replay.json:", err)
			fails++
		} else {
			fails += verifySamplerReplay(sv)
		}
	}

	// ── operation replay (TODO #297) ────────────────────────────────────
	if vdata, err := os.ReadFile("KAT/operation_replay.json"); err != nil {
		fmt.Fprintln(os.Stderr, "cannot read KAT/operation_replay.json:", err)
		fails++
	} else {
		var ov map[string]interface{}
		if err := json.Unmarshal(vdata, &ov); err != nil {
			fmt.Fprintln(os.Stderr, "cannot parse KAT/operation_replay.json:", err)
			fails++
		} else {
			fails += verifyOperationReplay(ov)
		}
	}

	if fails > 0 {
		fmt.Printf("%d vector set(s) FAILED\n", fails)
		os.Exit(1)
	}
	fmt.Println("All KAT vectors verified against the Go herradura package.")
}
