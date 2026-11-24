// Fuzz/pem_diff/go/main.go — the Go reader's side of the PEM reader
// differential (TODO #403; CliTest/test_pem_reader_diff.sh drives it).
//
// stdin: one case per line, the file's bytes in hex.  stdout: one line per
// case, "OK <label hex> <der hex>" or "ERR <message hex>".  The bytes go to
// PemUnwrap as herradura_cli.go reads them: string(os.ReadFile(path)).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	. "herradurakex/herradura"
)

func h(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		in, err := hex.DecodeString(sc.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex")
			os.Exit(2)
		}
		label, der, err := PemUnwrap(string(in))
		if err != nil {
			fmt.Fprintf(w, "ERR %s\n", h([]byte(err.Error())))
		} else {
			fmt.Fprintf(w, "OK %s %s\n", h([]byte(label)), h(der))
		}
	}
}
