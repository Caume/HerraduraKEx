// Fuzz/der_diff/go/main.go — the Go parser's side of the DER parser
// differential (TODO #404; CliTest/test_der_reader_diff.sh drives it).
//
// stdin: one case per line, the DER bytes in hex.  stdout: one line per case,
// "OK v/w/z ..." (value in minimal hex, encoded width, lead) or
// "ERR <message hex>".  The steps and texts are herradura_cli.go's
// derParseLabeled for the label "L": DerSeqTrailing, DerSeqScan, DerParseSeq.
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
	const label = "L"
	if t, err := DerSeqTrailing(d); err == nil && t > 0 {
		return fmt.Sprintf("malformed PEM '%s': %d bytes after the DER SEQUENCE", label, t)
	}
	enc, kind, bad := DerSeqScan(d)
	switch kind {
	case 1:
		return fmt.Sprintf("malformed PEM '%s': DER length not in its shortest form", label)
	case 2:
		return fmt.Sprintf("malformed PEM '%s': field %d is a negative INTEGER", label, bad)
	case 3:
		return fmt.Sprintf("malformed PEM '%s': field %d is an empty INTEGER", label, bad)
	}
	ints, err := DerParseSeq(d)
	if err != nil {
		return err.Error()
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
