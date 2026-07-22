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

// b64Decode strips whitespace then decodes standard base64.
func b64Decode(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(clean)
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

// PemUnwrap parses a single PEM block, returning the label and DER bytes.
func PemUnwrap(pem string) (label string, der []byte, err error) {
	const beginMark = "-----BEGIN "
	bi := strings.Index(pem, beginMark)
	if bi < 0 {
		return "", nil, errors.New("PEM: missing BEGIN marker")
	}
	rest := pem[bi+len(beginMark):]

	ei := strings.Index(rest, "-----")
	if ei < 0 {
		return "", nil, errors.New("PEM: malformed BEGIN line")
	}
	label = rest[:ei]
	rest = rest[ei+5:]
	rest = strings.TrimLeft(rest, "\r\n")

	endIdx := strings.Index(rest, "-----END ")
	if endIdx < 0 {
		return "", nil, errors.New("PEM: missing END marker")
	}
	der, err = b64Decode(rest[:endIdx])
	if err != nil {
		return "", nil, fmt.Errorf("PEM: base64 decode: %w", err)
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
