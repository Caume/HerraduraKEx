// Fuzz/der_diff/go/main.go — the Go parser's side of the DER parser
// differential (TODO #404; CliTest/test_der_reader_diff.sh drives it).
//
// stdin: one case per line, the DER bytes in hex.  stdout: one line per case,
// "OK v/w/z ..." (value in minimal hex, encoded width, lead) or
// "ERR <message hex>".  The steps and texts are herradura_cli.go's
// derParseLabeled for the label "L": DerSeqCheck (TODO #405), then DerSeqScan
// and DerParseSeq, which cannot fail after it (a failure is printed as EXC).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	. "herradurakex/herradura"
)

func verdict(d []byte) string {
	if msg := DerSeqCheck("L", d); msg != "" {
		return msg
	}
	enc, kind, bad := DerSeqScan(d)
	if kind != 0 {
		return fmt.Sprintf("EXC DerSeqScan kind %d (item %d) after DerSeqCheck passed", kind, bad)
	}
	ints, err := DerParseSeq(d)
	if err != nil {
		return "EXC DerParseSeq after DerSeqCheck passed: " + err.Error()
	}
	var b strings.Builder
	b.WriteString("\x00OK")
	for i, v := range ints {
		fmt.Fprintf(&b, " %s/%d/%d", new(big.Int).SetBytes(v).Text(16), enc.Width[i], enc.Lead[i])
	}
	return b.String()
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		d, err := hex.DecodeString(sc.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex")
			os.Exit(2)
		}
		if v := verdict(d); strings.HasPrefix(v, "\x00OK") {
			fmt.Fprintln(w, v[1:])
		} else {
			fmt.Fprintf(w, "ERR %s\n", hex.EncodeToString([]byte(v)))
		}
	}
}
