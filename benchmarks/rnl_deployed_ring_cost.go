// rnl_deployed_ring_cost.go — TODO #292: the Go column of the deployed-ring
// table.  See benchmarks/rnl_deployed_ring_cost.c for why this table exists at
// all: both test harnesses stop at n = 256 while the suite ships RnlN = 1024,
// and #225 measured the deployed ring in Python only.
//
// This drives the shipped package (herradurakex/herradura) rather than a
// transcription, and gates on the same control the C sibling does: if the two
// sides do not reconcile to the same key, nothing is timed and it exits 1.
//
// Run:  go run benchmarks/rnl_deployed_ring_cost.go
//
// RECORDED (ARM64 SBC), per operation, at v7.0.11 -- i.e. AFTER TODO #293:
//
//	keygen (s, C)                     0.271 ms
//	agree, reconciler side (+hint)    0.262 ms
//	agree, receiver side              0.256 ms
//	RnlPolyMul alone (NTT)            0.179 ms
//	m_blind derivation (rand+add)     0.048 ms
//	full two-party handshake          1.088 ms   (919 /s)
//
// THE FINDING, and Go is where it surfaced.  In C and in Python the handshake
// is the NTT; here it was not.  At v7.0.10 m_blind derivation was 0.642 ms of
// a 1.517 ms handshake -- more than all four RnlPolyMul calls together, and
// 21x the same step in C (0.029 ms).  RnlRandPoly read THREE BYTES per
// iteration of its rejection loop, ~1028 crypto/rand.Read calls per polynomial
// at n = 1024.  Measured on its own, same byte count either way:
//
//	1028 x rand.Read(3)      0.613 ms
//	   1 x rand.Read(3084)   0.012 ms      50x
//
// so 0.613 of the 0.642 ms was per-call overhead, not entropy and not
// arithmetic.  The fix pattern was twenty lines below it in the same file:
// RnlCBDPoly has always drawn its whole buffer in one call.
//
// FIXED IN v7.0.11 (TODO #293), and the numbers above are the post-fix ones.
// m_blind is 0.048 ms -- 13.4x cheaper, 4.4% of a handshake rather than 40%
// -- and a handshake is 1.088 ms, 28% off, putting Go at 2.15x C rather than
// 3.0x.  Read the 50x above as what it is, a CEILING: it compares reads with
// no sampler around them.  Against the buffered sampler that actually shipped
// -- same rejection loop, same threshold, same modulus reduction -- the ratio
// is 19.9x (0.614 -> 0.031 ms) and the residue is loop arithmetic.  Python and
// Java were buffered in the same item (2.2x and 3.0x); C needed nothing, and
// remains the control that says the host has not moved between the two
// releases.
//
// Go runs the NTT itself 1.7x slower than C (0.197 against 0.114), which is the
// expected shape of []int with bounds checks against int32_t arrays and is not
// specific to HKEX-RNL.
package main

import (
	"fmt"
	"os"
	"time"

	h "herradurakex/herradura"
)

const (
	benchSecs    = 2.0
	controlIters = 20
)

func bench(label string, f func()) {
	ops := 0
	t0 := time.Now()
	var secs float64
	for {
		f()
		ops++
		secs = time.Since(t0).Seconds()
		if secs >= benchSecs {
			break
		}
	}
	fmt.Printf("  %-34s %8.3f ms   %9.1f /s\n",
		label, 1000*secs/float64(ops), float64(ops)/secs)
}

func main() {
	n, q, p, pp := h.RnlN, h.RnlQ, h.RnlP, h.RnlPP
	const keyBits = 256

	fmt.Printf("HKEX-RNL at the DEPLOYED ring -- RnlN=%d q=%d p=%d, "+
		"session key %d bits\n", n, q, p, keyBits)

	mBase := h.RnlMPoly(n)
	var mBlind, sA, cA, sB, cB []int
	var hint []byte

	// Control: a rate is meaningless if the two sides disagree.
	disagreed := 0
	for i := 0; i < controlIters; i++ {
		mBlind = h.RnlPolyAdd(mBase, h.RnlRandPoly(n, q), q)
		sA, cA = h.RnlKeygen(mBlind, n, q, p)
		sB, cB = h.RnlKeygen(mBlind, n, q, p)
		kA, hA := h.RnlAgree(sA, cB, q, p, pp, n, keyBits, nil)
		kB, _ := h.RnlAgree(sB, cA, q, p, pp, n, keyBits, hA)
		hint = hA
		if !kA.Equal(kB) {
			disagreed++
		}
	}
	mark := ""
	if disagreed > 0 {
		mark = "  <-- FAIL"
	}
	fmt.Printf("  control: %d/%d handshakes reconcile to the same key%s\n\n",
		controlIters-disagreed, controlIters, mark)
	if disagreed > 0 {
		fmt.Fprintf(os.Stderr, "*** FAILED: %d of %d handshakes disagreed at "+
			"the deployed ring -- timing not run ***\n", disagreed, controlIters)
		os.Exit(1)
	}

	bench("keygen (s, C)", func() { h.RnlKeygen(mBlind, n, q, p) })
	bench("agree, reconciler (+hint)", func() { h.RnlAgree(sA, cB, q, p, pp, n, keyBits, nil) })
	bench("agree, receiver", func() { h.RnlAgree(sB, cA, q, p, pp, n, keyBits, hint) })
	bench("RnlPolyMul alone (NTT)", func() { h.RnlPolyMul(mBlind, sA, q, n) })
	bench("m_blind derivation (rand+add)", func() { h.RnlPolyAdd(mBase, h.RnlRandPoly(n, q), q) })
	bench("full two-party handshake", func() {
		mb := h.RnlPolyAdd(mBase, h.RnlRandPoly(n, q), q)
		sa, ca := h.RnlKeygen(mb, n, q, p)
		sb, cb := h.RnlKeygen(mb, n, q, p)
		_, hh := h.RnlAgree(sa, cb, q, p, pp, n, keyBits, nil)
		h.RnlAgree(sb, ca, q, p, pp, n, keyBits, hh)
	})

	fmt.Printf("\n  A handshake is 4 RnlPolyMul calls plus the sampling; " +
		"Herradura_tests.go's\n  rnlSizes stops at 256, the RETIRED ring " +
		"(TODO #223, #225).\n")
}
