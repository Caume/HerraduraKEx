/*  herradura/codec.go — Base64, PEM, and minimal DER codec
    v1.5.27: Go port of HerraduraCli/herradura_codec.h.

    PEM output is byte-for-byte compatible with Python (76-char base64 lines,
    matching base64.encodebytes) and the C herradura_codec.h implementation.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    Dual-licensed MIT / GPL v3.0 — see repository root LICENSE files.
*/

package herradura

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// PEM label constants — must match Python herradura.py and herradura_codec.h
// ---------------------------------------------------------------------------

const (
	PemHkexGfPriv    = "HERRADURA HKEX-GF PRIVATE KEY"
	PemHkexGfPub     = "HERRADURA HKEX-GF PUBLIC KEY"
	PemHkexRnlPriv   = "HERRADURA HKEX-RNL PRIVATE KEY"
	PemHkexRnlPub    = "HERRADURA HKEX-RNL PUBLIC KEY"
	PemHpksPriv      = "HERRADURA HPKS PRIVATE KEY"
	PemHpksPub       = "HERRADURA HPKS PUBLIC KEY"
	PemHpksNlPriv    = "HERRADURA HPKS-NL PRIVATE KEY"
	PemHpksNlPub     = "HERRADURA HPKS-NL PUBLIC KEY"
	PemHpkePriv      = "HERRADURA HPKE PRIVATE KEY"
	PemHpkePub       = "HERRADURA HPKE PUBLIC KEY"
	PemHpkeNlPriv    = "HERRADURA HPKE-NL PRIVATE KEY"
	PemHpkeNlPub     = "HERRADURA HPKE-NL PUBLIC KEY"
	PemHpksSternPriv = "HERRADURA HPKS-STERN PRIVATE KEY"
	PemHpksSternPub  = "HERRADURA HPKS-STERN PUBLIC KEY"
	PemHpkeSternPriv = "HERRADURA HPKE-STERN PRIVATE KEY"
	PemHpkeSternPub  = "HERRADURA HPKE-STERN PUBLIC KEY"
	PemSessionKey    = "HERRADURA SESSION KEY"
	PemRnlResponse   = "HERRADURA HKEX-RNL RESPONSE"
	PemSignature     = "HERRADURA SIGNATURE"
	PemCiphertext    = "HERRADURA CIPHERTEXT"
	PemDigest        = "HERRADURA DIGEST"

	PemZkpRnlProof = "HERRADURA ZKP-RNL PROOF"
	PemZkpNlPriv   = "HERRADURA ZKP-NL PRIVATE KEY"
	PemZkpNlPub    = "HERRADURA ZKP-NL PUBLIC KEY"
	PemZkpNlProof  = "HERRADURA ZKP-NL PROOF"
)

// ---------------------------------------------------------------------------
// Base64  (76-char lines — matching Python base64.encodebytes)
// ---------------------------------------------------------------------------

// b64Encode returns data encoded as base64 with 76-character lines, each
// terminated by '\n'.  Output matches Python base64.encodebytes and the C
// b64_encode in herradura_codec.h.
func b64Encode(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.Grow(len(raw) + len(raw)/76 + 2)
	for len(raw) > 76 {
		sb.WriteString(raw[:76])
		sb.WriteByte('\n')
		raw = raw[76:]
	}
	if len(raw) > 0 {
		sb.WriteString(raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// b64Decode decodes a PEM body under the one base64 grammar every CLI reads
// (TODO #398): the alphabet A-Z a-z 0-9 + /, with space, tab, CR and LF allowed
// anywhere between characters (RFC 7468's lax form).  Padding is REQUIRED: the
// characters number a multiple of 4 and '=' is only the last one or two of them.
// The bits the padding leaves over must be zero, so one DER has one body.
// Hand-written rather than encoding/base64, whose StdEncoding accepts non-zero
// trailing bits, so that C, Go, Python and Java run the same loop and refuse the
// same files with the same words.
func b64Decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	bits, pad, chars := 0, 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c == '=' {
			pad++
			if pad > 2 || chars%4 < 2 {
				return nil, errB64Pad
			}
			chars++
			continue
		}
		v := b64Val(c)
		if v < 0 {
			return nil, errB64Char
		}
		if pad > 0 {
			return nil, errB64Pad
		}
		chars++
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
		}
	}
	if chars%4 != 0 {
		return nil, errB64Len
	}
	if pad > 0 && acc&(1<<uint(bits)-1) != 0 {
		return nil, errB64Bits
	}
	return out, nil
}

var (
	errB64Char = errors.New("PEM body is not valid base64: invalid character")
	errB64Pad  = errors.New("PEM body is not valid base64: misplaced padding")
	errB64Len  = errors.New("PEM body is not valid base64: length is not a multiple of 4")
	errB64Bits = errors.New("PEM body is not valid base64: non-zero bits after the last byte")
)

func b64Val(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}

// ---------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------

// PemWrap wraps der as a PEM block with the given label.
// Output is compatible with Python pem_wrap and C pem_wrap in herradura_codec.h.
func PemWrap(label string, der []byte) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN ")
	sb.WriteString(label)
	sb.WriteString("-----\n")
	sb.WriteString(b64Encode(der))
	sb.WriteString("-----END ")
	sb.WriteString(label)
	sb.WriteString("-----\n")
	return sb.String()
}

// PemLabelMax is the longest PEM label any reader accepts (TODO #400).
const PemLabelMax = 79

func pemWS(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// PemUnwrap parses the one PEM block that is the whole of pem, returning the
// label and DER bytes.  One framing for every reader (TODO #400), the same scan
// in C, Python and Java: only whitespace (space, tab, CR, LF) before the BEGIN
// line and after the END line, so a file holds exactly one block; the BEGIN
// line is `-----BEGIN <label>-----`, then only spaces or tabs, the label 1 to 79
// printable ASCII characters; the END line starts a line and repeats the label; the body
// decodes under b64Decode's grammar (TODO #398) to at least one byte.
func PemUnwrap(pem string) (label string, der []byte, err error) {
	t, end := pem, len(pem)
	p := 0
	for p < end && pemWS(t[p]) {
		p++
	}
	if !strings.HasPrefix(t[p:], "-----BEGIN ") {
		if strings.Contains(t[p:], "-----BEGIN ") {
			return "", nil, errors.New("PEM: text before the BEGIN line")
		}
		return "", nil, errors.New("PEM: missing BEGIN marker")
	}
	p += 11
	ls := p
	for p < end && t[p] != '\r' && t[p] != '\n' && !strings.HasPrefix(t[p:], "-----") {
		if t[p] < 0x20 || t[p] > 0x7E {
			return "", nil, errors.New("PEM: malformed BEGIN line")
		}
		p++
	}
	label = t[ls:p]
	if !strings.HasPrefix(t[p:], "-----") || len(label) == 0 || len(label) > PemLabelMax {
		return "", nil, errors.New("PEM: malformed BEGIN line")
	}
	p += 5
	for p < end && (t[p] == ' ' || t[p] == '\t') {
		p++
	}
	if p >= end || (t[p] != '\r' && t[p] != '\n') {
		return "", nil, errors.New("PEM: malformed BEGIN line")
	}
	body := p
	fi := strings.Index(t[body:], "-----END ")
	if fi < 0 {
		return "", nil, errors.New("PEM: missing END marker")
	}
	foot := body + fi
	if t[foot-1] != '\r' && t[foot-1] != '\n' {
		return "", nil, errors.New("PEM: malformed END line")
	}
	p = foot + 9
	es := p
	for p < end && t[p] != '\r' && t[p] != '\n' && !strings.HasPrefix(t[p:], "-----") {
		p++
	}
	if !strings.HasPrefix(t[p:], "-----") {
		return "", nil, errors.New("PEM: malformed END line")
	}
	if el := t[es:p]; el != label {
		if len(el) > PemLabelMax {
			el = el[:PemLabelMax]
		}
		// Echoed with every byte outside 0x20-0x7E as '?' (TODO #403): the END
		// label was never screened, and raw it reached stderr differently per CLI.
		shown := []byte(el)
		for i, c := range shown {
			if c < 0x20 || c > 0x7E {
				shown[i] = '?'
			}
		}
		return "", nil, fmt.Errorf("PEM: END label '%s' does not match BEGIN label '%s'", shown, label)
	}
	p += 5
	for p < end && pemWS(t[p]) {
		p++
	}
	if p != end {
		return "", nil, errors.New("PEM: text after the END line")
	}
	der, err = b64Decode(t[body:foot])
	if err != nil {
		return "", nil, err
	}
	if len(der) == 0 {
		return "", nil, errors.New("PEM: empty body")
	}
	return label, der, nil
}

// ---------------------------------------------------------------------------
// DER  (minimal subset: INTEGER 0x02 and SEQUENCE 0x30)
// ---------------------------------------------------------------------------

func derEncLen(n int) ([]byte, error) {
	switch {
	case n < 0x80:
		return []byte{byte(n)}, nil
	case n < 0x100:
		return []byte{0x81, byte(n)}, nil
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}, nil
	case n < 0x1000000:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}, nil
	case int64(n) < 0x100000000:
		return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, nil
	default:
		return nil, errors.New("DER: length too large to encode")
	}
}

func derDecLen(buf []byte) (length int, consumed int, err error) {
	if len(buf) == 0 {
		return 0, 0, errors.New("DER: empty length field")
	}
	b := buf[0]
	if b < 0x80 {
		return int(b), 1, nil
	}
	nb := int(b & 0x7f)
	if nb > 4 || nb+1 > len(buf) {
		return 0, 0, errors.New("DER: length field too large")
	}
	v := 0
	for i := 0; i < nb; i++ {
		v = (v << 8) | int(buf[1+i])
	}
	return v, 1 + nb, nil
}

// DerIntEnc encodes val (big-endian unsigned integer bytes) as a DER INTEGER.
// A 0x00 sign byte is prepended when val[0]&0x80 (matches Python der_int and
// C der_int_enc).
func DerIntEnc(val []byte) ([]byte, error) {
	sign := len(val) > 0 && (val[0]&0x80 != 0)
	content := len(val)
	if sign {
		content++
	}
	lenb, err := derEncLen(content)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(lenb)+content)
	out[0] = 0x02
	copy(out[1:], lenb)
	off := 1 + len(lenb)
	if sign {
		out[off] = 0x00
		off++
	}
	copy(out[off:], val)
	return out, nil
}

// DerSeqEnc wraps already-encoded DER items in a SEQUENCE (tag 0x30).
func DerSeqEnc(items ...[]byte) ([]byte, error) {
	body := 0
	for _, it := range items {
		body += len(it)
	}
	lenb, err := derEncLen(body)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(lenb)+body)
	out[0] = 0x30
	copy(out[1:], lenb)
	off := 1 + len(lenb)
	for _, it := range items {
		copy(out[off:], it)
		off += len(it)
	}
	return out, nil
}

// derReadLen reads the DER length field at d[p], no further than lim
// (TODO #405): 0 when well formed and minimal (v the length, c the bytes it
// took), 1 truncated, 2 longer than 4 bytes, 3 not in its shortest form.
func derReadLen(d []byte, p, lim int) (v, c, fault int) {
	if p >= lim {
		return 0, 0, 1
	}
	b := d[p]
	if b < 0x80 {
		return int(b), 1, 0
	}
	nb := int(b & 0x7f)
	if nb > 4 {
		return 0, 0, 2
	}
	if nb > lim-p-1 {
		return 0, 0, 1
	}
	x := 0
	for i := 0; i < nb; i++ {
		x = x<<8 | int(d[p+1+i])
	}
	if nb == 0 || d[p+1] == 0 || (nb == 1 && x < 0x80) {
		return x, 1 + nb, 3
	}
	return x, 1 + nb, 0
}

var derLenText = [...]string{"", "DER length field truncated", "DER length field longer than 4 bytes",
	"DER length not in its shortest form"}

// DerSeqCheck is the DER reader's refusal, specified (TODO #405, SPEC.md
// section 10.2): one left-to-right walk of a SEQUENCE of INTEGERs, the first
// fault met is the refusal, in the text all four CLIs print.  It returns ""
// for a well-formed SEQUENCE; DerSeqScan and DerParseSeq cannot fail after it.
func DerSeqCheck(label string, der []byte) string {
	where := fmt.Sprintf("malformed PEM '%s': ", label)
	if len(der) == 0 || der[0] != 0x30 {
		return where + "not a DER SEQUENCE"
	}
	v, c, f := derReadLen(der, 1, len(der))
	if f != 0 {
		return where + derLenText[f]
	}
	off := 1 + c
	if v > len(der)-off {
		return where + "DER SEQUENCE body truncated"
	}
	if v < len(der)-off {
		return where + fmt.Sprintf("%d bytes after the DER SEQUENCE", len(der)-off-v)
	}
	for n := 0; off < len(der); n++ {
		if der[off] != 0x02 {
			return where + fmt.Sprintf("field %d is not an INTEGER (tag 0x%02x)", n, der[off])
		}
		if v, c, f = derReadLen(der, off+1, len(der)); f != 0 {
			return where + derLenText[f]
		}
		off += 1 + c
		if v > len(der)-off {
			return where + fmt.Sprintf("field %d runs past the DER SEQUENCE", n)
		}
		if v == 0 {
			return where + fmt.Sprintf("field %d is an empty INTEGER", n)
		}
		if der[off]&0x80 != 0 {
			return where + fmt.Sprintf("field %d is a negative INTEGER", n)
		}
		off += v
	}
	return ""
}

// DerEnc is how each INTEGER of a DER SEQUENCE is ENCODED (TODO #373), which
// DerParseSeq's sign-byte strip forgets: Width[i] is item i's encoded width
// (content length less a 0x00 the set top bit needs) and Lead[i] is 1 when it
// starts with a 0x00 the sign does not need, 2 when with a sign byte.
type DerEnc struct {
	Width []int
	Lead  []uint8
}

func derLenMinimal(buf []byte) bool {
	if len(buf) == 0 || buf[0] < 0x80 {
		return true
	}
	nb := int(buf[0] & 0x7f)
	if nb == 0 || nb+1 > len(buf) || buf[1] == 0 {
		return false
	}
	return nb > 1 || buf[1] >= 0x80
}

// DerSeqScan reports the first encoding fault of a DER SEQUENCE of INTEGERs
// (TODO #373): kind 1 a length not in its shortest form, 2 item bad negative
// (top bit set, no sign byte), 3 item bad empty; kind -1 a structure
// DerParseSeq refuses anyway.  Every CLI refuses 1-3, so a SEQUENCE has one
// encoding of its lengths and signs.
func DerSeqScan(der []byte) (enc DerEnc, kind int, bad int) {
	if len(der) == 0 || der[0] != 0x30 {
		return enc, -1, 0
	}
	bodyLen, consumed, err := derDecLen(der[1:])
	if err != nil {
		return enc, -1, 0
	}
	if !derLenMinimal(der[1:]) {
		return enc, 1, 0
	}
	offset := 1 + consumed
	if bodyLen > len(der)-offset {
		return enc, -1, 0
	}
	end := offset + bodyLen
	for n := 0; offset < end; n++ {
		if der[offset] != 0x02 {
			return enc, -1, 0
		}
		offset++
		if offset >= end {
			return enc, -1, 0
		}
		vlen, c, err := derDecLen(der[offset:end])
		if err != nil {
			return enc, -1, 0
		}
		if !derLenMinimal(der[offset:end]) {
			return enc, 1, 0
		}
		offset += c
		if vlen > end-offset {
			return enc, -1, 0
		}
		if vlen == 0 {
			return enc, 3, n
		}
		if der[offset]&0x80 != 0 {
			return enc, 2, n
		}
		sign := vlen > 1 && der[offset] == 0 && der[offset+1]&0x80 != 0
		w := vlen
		if sign {
			w--
		}
		enc.Width = append(enc.Width, w)
		var lead uint8
		if sign {
			lead = 2
		} else if vlen > 1 && der[offset] == 0 {
			lead = 1
		}
		enc.Lead = append(enc.Lead, lead)
		offset += vlen
	}
	return enc, 0, 0
}

// DerParseSeq parses a DER SEQUENCE of INTEGERs.
// Each returned slice points into der; leading 0x00 sign bytes are stripped
// so callers receive the true unsigned big-endian bytes (matching Python
// der_parse_seq and C der_parse_seq).
func DerParseSeq(der []byte) ([][]byte, error) {
	if len(der) == 0 || der[0] != 0x30 {
		return nil, errors.New("DER: not a SEQUENCE")
	}
	bodyLen, consumed, err := derDecLen(der[1:])
	if err != nil {
		return nil, fmt.Errorf("DER SEQUENCE length: %w", err)
	}
	offset := 1 + consumed
	end := offset + bodyLen
	if end > len(der) {
		return nil, errors.New("DER: SEQUENCE body truncated")
	}
	if end < len(der) { // TODO #372: nothing may follow the SEQUENCE
		return nil, fmt.Errorf("DER: %d bytes after the DER SEQUENCE", len(der)-end)
	}

	var out [][]byte
	for offset < end {
		if der[offset] != 0x02 {
			return nil, fmt.Errorf("DER: expected INTEGER tag at offset %d, got 0x%02x", offset, der[offset])
		}
		offset++
		vlen, c, err := derDecLen(der[offset:end])
		if err != nil {
			return nil, fmt.Errorf("DER INTEGER length: %w", err)
		}
		offset += c
		if vlen > end-offset {
			return nil, errors.New("DER: INTEGER length exceeds SEQUENCE body")
		}
		vp := der[offset : offset+vlen]
		// strip leading 0x00 sign byte
		if len(vp) > 1 && vp[0] == 0x00 {
			vp = vp[1:]
		}
		out = append(out, vp)
		offset += vlen
	}
	return out, nil
}
