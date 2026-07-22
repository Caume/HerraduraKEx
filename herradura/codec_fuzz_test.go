package herradura

import "testing"

// Native Go 1.18+ fuzz targets for the PEM/DER codec (TODO #130).
// Run: cd herradura && go test -fuzz=FuzzPemUnwrap -fuzztime=60s
//      cd herradura && go test -fuzz=FuzzDerParseSeq -fuzztime=60s

func FuzzPemUnwrap(f *testing.F) {
	f.Add("-----BEGIN TEST-----\nMAcCASoCAgEA\n-----END TEST-----\n")
	f.Add("")
	f.Add("-----BEGIN -----")
	f.Add("-----BEGIN X-----\n-----END X-----\n")
	f.Fuzz(func(t *testing.T, pem string) {
		// Must never panic on any input, well-formed or not.
		_, _, _ = PemUnwrap(pem)
	})
}

func FuzzDerParseSeq(f *testing.F) {
	f.Add([]byte{0x30, 0x07, 0x02, 0x01, 0x2a, 0x02, 0x02, 0x01, 0x00})
	f.Add([]byte{0x30, 0x40})     // claims a 64-byte body with none present
	f.Add([]byte{0x30, 0x00})     // empty SEQUENCE
	f.Add([]byte{0x02, 0x01, 0x00}) // not a SEQUENCE
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = DerParseSeq(der)
	})
}
