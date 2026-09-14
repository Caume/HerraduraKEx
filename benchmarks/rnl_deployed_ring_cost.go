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
// RECORDED (ARM64 SBC), per operation:
//
//	keygen (s, C)                     0.235 ms
//	agree, reconciler side (+hint)    0.249 ms
//	agree, receiver side              0.226 ms
//	RnlPolyMul alone (NTT)            0.197 ms
//	m_blind derivation (rand+add)     0.642 ms
//	full two-party handshake          1.517 ms   (659 /s)
//
// THE FINDING, and Go is where it surfaces.  In C and in Python the handshake
// is the NTT; here it is not.  m_blind derivation is 0.642 ms of a 1.517 ms
// handshake -- more than all four RnlPolyMul calls together, and 21x the same
// step in C (0.030 ms).  RnlRandPoly reads THREE BYTES per iteration of its
// rejection loop, ~1028 crypto/rand.Read calls per polynomial at n = 1024.
// Measured on its own, same byte count either way:
//
//	1028 x rand.Read(3)      0.613 ms
//	   1 x rand.Read(3084)   0.012 ms      50x
//
// so 0.613 of the 0.642 ms is per-call overhead, not entropy and not
// arithmetic.  The fix pattern is twenty lines below it in the same file:
// RnlCBDPoly draws its whole buffer in one call.  Python's _rnl_rand_poly and
// Java's rnlRandPoly share the shape; C alone amortises it, through a buffered
// FILE * rather than by design.  Only in Go does it dominate, because only
// here is the NTT fast enough for it to show.  Filed as TODO #293 rather than
// fixed here -- this item measures, and that is a change to a shipped
// primitive in three languages.
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
