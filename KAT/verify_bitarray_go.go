//go:build ignore

/*  KAT/verify_bitarray_go.go — the Go consumer for KAT/bitarray.json (TODO #314).

    BITARRAY.md is the specification; KAT/generate_bitarray_kat.py carries the
    reference implementation and pins its output; this runs the SHIPPED Go
    BitArray against those pinned answers.

    Go is pass 3 and therefore the SECOND port in the gating set, which is the
    point at which the vector stops being a currency check and becomes the
    cross-implementation check BITARRAY.md §7 describes: two INDEPENDENT
    implementations against ONE pinned answer is what no round-trip or interop
    test can supply, because those compare a port against another port's
    opinion.  Python and Java are still expected to diverge and are still
    reported rather than gated (§7, and CLAUDE.md's Testing section, which
    allows no failing test).

    Unlike KAT/verify_bitarray_c.c this reads the JSON directly: encoding/json
    is in Go's standard library, so the generated C view exists for C's benefit
    only and Go has no reason to consume a transposition of a file it can read.

    Run by CliTest/test_kat_vectors.sh; compiled on demand, not tracked
    (TODO #229).
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	. "herradurakex/herradura"
)

type baCase struct {
	Op        string                 `json:"op"`
	Nbits     int                    `json:"nbits"`
	MixedWith int                    `json:"mixed_with"`
	Args      map[string]interface{} `json:"args"`
	Expect    map[string]interface{} `json:"expect"`
}

type baVector struct {
	CaseCount int      `json:"case_count"`
	Cases     []baCase `json:"cases"`
}

var passN, failN int

func ok(cond bool, c *baCase, detail string) {
	if cond {
		passN++
		return
	}
	failN++
	mixed := ""
	if c.MixedWith != 0 {
		mixed = " mixed"
	}
	fmt.Printf("FAIL [%s n=%d%s] %s\n", c.Op, c.Nbits, mixed, detail)
}

func (c *baCase) str(k string) (string, bool) {
	v, present := c.Args[k]
	if !present {
		return "", false
	}
	s, isStr := v.(string)
	return s, isStr
}

func (c *baCase) num(k string) (int, bool) {
	v, present := c.Args[k]
	if !present {
		return 0, false
	}
	n, isNum := v.(json.Number)
	if !isNum {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	return int(i), err == nil
}

// jnum reads a JSON number EXACTLY.  The decoder below is set to UseNumber for
// this reason and the reason is worth keeping: two of these cases carry
// integers above 2^53 — to_uint's 7025791060798414911 at n = 64 and
// from_uint's 2^32 boundary — and a float64 decode silently rounds the first
// to ...414848.  Go is the first consumer to read this JSON at all (C consumes
// the transposed header, where the values are C literals), so it is the first
// that could meet the hazard CLAUDE.md already records for nl_fscx_v3.json.
// It is NOT silent here — the pinned answer disagrees and the case fails —
// which is the vector doing its job, and is why the fix is an exact decode
// rather than a change to the file.
func jnum(v interface{}) (int64, bool) {
	n, isNum := v.(json.Number)
	if !isNum {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	return i, err == nil
}

func (c *baCase) wantError() (string, bool) {
	v, present := c.Expect["error"]
	if !present {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// checkBits scores a case whose expected result is a value at a stated width,
// or one of BITARRAY.md §5's error codes.
func checkBits(c *baCase, err error, got *BitArray) {
	if want, isErr := c.wantError(); isErr {
		if err == nil {
			ok(false, c, fmt.Sprintf("expected %s, got a value", want))
			return
		}
		ok(string(BaCode(err)) == want, c,
			fmt.Sprintf("expected %s, got %s", want, BaCode(err)))
		return
	}
	if err != nil {
		ok(false, c, fmt.Sprintf("expected a value, got %s", BaCode(err)))
		return
	}
	wantHex, _ := c.Expect["hex"].(string)
	wn, _ := jnum(c.Expect["nbits"])
	wantNbits := int(wn)
	ok(got.Size() == wantNbits && got.Hex() == wantHex, c,
		fmt.Sprintf("got %s/%d want %s/%d", got.Hex(), got.Size(), wantHex, wantNbits))
}

func checkInt(c *baCase, err error, got int64) {
	if want, isErr := c.wantError(); isErr {
		gotDesc := "a value"
		if err != nil {
			gotDesc = string(BaCode(err))
		}
		ok(err != nil && string(BaCode(err)) == want, c,
			fmt.Sprintf("expected %s, got %s", want, gotDesc))
		return
	}
	if err != nil {
		ok(false, c, fmt.Sprintf("expected a value, got %s", BaCode(err)))
		return
	}
	want, _ := jnum(c.Expect["int"])
	ok(got == want, c, fmt.Sprintf("got %d want %d", got, want))
}

func checkBool(c *baCase, got bool) {
	want := c.Expect["bool"].(bool)
	ok(got == want, c, fmt.Sprintf("got %v want %v", got, want))
}

func main() {
	raw, err := os.ReadFile("KAT/bitarray.json")
	if err != nil {
		fmt.Printf("FAIL: %s\n", err)
		os.Exit(1)
	}
	var v baVector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		fmt.Printf("FAIL: %s\n", err)
		os.Exit(1)
	}
	if v.CaseCount != len(v.Cases) {
		fmt.Printf("FAIL: case_count %d but %d cases\n", v.CaseCount, len(v.Cases))
		os.Exit(1)
	}

	fmt.Println("=== KAT/bitarray.json against the shipped Go BitArray (TODO #314) ===")
	fmt.Printf("    %d cases, capacity BAMaxBits = %d\n", len(v.Cases), BAMaxBits)

	for i := range v.Cases {
		c := &v.Cases[i]
		bw := c.Nbits
		if c.MixedWith != 0 {
			bw = c.MixedWith
		}

		// Operands.  A width this port cannot represent is E_WIDTH, and that
		// is a legitimate answer the vector may be pinning.
		var a, b *BitArray
		var aErr, bErr error
		// The single-operand inspection cases (to_uint, popcount, is_zero)
		// spell their operand "hex" where the rest spell it "a"; the
		// constructors below read "hex" themselves.
		if h, present := c.str("a"); present {
			a, aErr = TryFromHex(h, c.Nbits)
		} else if h, present := c.str("hex"); present && c.Op != "from_hex" && c.Op != "from_bytes" {
			a, aErr = TryFromHex(h, c.Nbits)
		}
		if h, present := c.str("b"); present {
			b, bErr = TryFromHex(h, bw)
		}

		switch c.Op {
		case "zero":
			r, zErr := TryZero(c.Nbits)
			checkBits(c, zErr, r)
			continue
		case "from_hex":
			h, _ := c.str("hex")
			r, hErr := TryFromHex(h, c.Nbits)
			checkBits(c, hErr, r)
			continue
		case "from_bytes":
			h, _ := c.str("hex")
			buf := make([]byte, len(h)/2)
			for j := range buf {
				var x int
				fmt.Sscanf(h[2*j:2*j+2], "%02x", &x)
				buf[j] = byte(x)
			}
			r, fErr := TryFromBytes(buf, c.Nbits)
			checkBits(c, fErr, r)
			continue
		case "from_uint":
			// A negative value is E_RANGE and is spelled as such rather than
			// converted: uint64(-1.0) is not defined to wrap in Go.
			u, _ := jnum(c.Args["uint"])
			if u < 0 {
				checkBits(c, &BaError{Code: BaERange, Op: "from_uint"}, nil)
				continue
			}
			r, uErr := TryFromUint(uint64(u), c.Nbits)
			checkBits(c, uErr, r)
			continue
		}

		// Everything below needs its operands to have loaded.
		if aErr != nil {
			checkBits(c, aErr, nil)
			continue
		}
		if bErr != nil {
			checkBits(c, bErr, nil)
			continue
		}

		switch c.Op {
		case "to_uint":
			u, e := a.TryToUint()
			checkInt(c, e, int64(u))
		case "popcount":
			checkInt(c, nil, int64(a.Popcount()))
		case "is_zero":
			checkBool(c, a.IsZero())
		case "xor":
			r, e := a.TryXor(b)
			checkBits(c, e, r)
		case "and":
			r, e := a.TryAnd(b)
			checkBits(c, e, r)
		case "or":
			r, e := a.TryOr(b)
			checkBits(c, e, r)
		case "not":
			r, e := a.TryNot()
			checkBits(c, e, r)
		case "rot_left":
			s, _ := c.num("s")
			checkBits(c, nil, a.RotateLeft(s))
		case "rot_right":
			s, _ := c.num("s")
			checkBits(c, nil, a.RotateRight(s))
		case "shl":
			k, _ := c.num("k")
			r, e := a.TryShl(k)
			checkBits(c, e, r)
		case "shr":
			k, _ := c.num("k")
			r, e := a.TryShr(k)
			checkBits(c, e, r)
		case "truncate":
			m, _ := c.num("m")
			r, e := a.TryTruncate(m)
			checkBits(c, e, r)
		case "extend":
			m, _ := c.num("m")
			r, e := a.TryExtend(m)
			checkBits(c, e, r)
		case "resize_exact":
			m, _ := c.num("m")
			r, e := a.TryResizeExact(m)
			checkBits(c, e, r)
		case "equal":
			checkBool(c, a.Equal(b))
		case "compare":
			r, e := a.TryCompare(b)
			checkInt(c, e, int64(r))
		case "bit":
			i, _ := c.num("i")
			r, e := a.TryBit(i)
			checkInt(c, e, int64(r))
		case "fscx":
			r, e := TryFscx(a, b)
			checkBits(c, e, r)
		case "fscx_revolve":
			steps, _ := c.num("i")
			cur, e := a.Copy(), error(nil)
			for j := 0; j < steps && e == nil; j++ {
				cur, e = TryFscx(cur, b)
			}
			checkBits(c, e, cur)
		case "gf_mul":
			r, e := TryGfMul(a, b)
			checkBits(c, e, r)
		case "gf_pow":
			e64, _ := c.num("e")
			r, e := TryGfPow(a, uint64(e64))
			checkBits(c, e, r)
		case "rnl_kdf_seed":
			checkBits(c, nil, RnlKdfSeed(a))
		default:
			failN++
			fmt.Printf("FAIL [%s] no handler in verify_bitarray_go.go — a case the "+
				"consumer does not implement must not read as a pass\n", c.Op)
		}
	}

	fmt.Printf("\nResults: %d PASS / %d FAIL (of %d cases)\n", passN, failN, len(v.Cases))
	if passN+failN != len(v.Cases) {
		fmt.Printf("FAIL: %d case(s) were neither passed nor failed — a case that "+
			"did not run must not be scored (TODO #291)\n", len(v.Cases)-passN-failN)
		os.Exit(1)
	}
	if failN != 0 {
		fmt.Println("*** FAILED: the shipped Go BitArray disagrees with BITARRAY.md ***")
		os.Exit(1)
	}
	fmt.Println("*** OK: the shipped Go BitArray matches KAT/bitarray.json ***")
}
