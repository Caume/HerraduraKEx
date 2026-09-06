#!/usr/bin/env bash
# CliTest/lib_malformed.sh — shared malformed-PEM cases for TODO #239 / #240.
#
# Every case here rewrites ONE DER INTEGER item of an otherwise-genuine PEM to a
# value that used to size an allocation unchecked, and requires the CLI under
# test to reject it cleanly: non-zero exit, a one-line diagnostic, and NOT a
# traceback, an out-of-memory abort, or a plain "Verification FAILED" (which
# would mean the reader accepted the field and merely failed the crypto).
#
# It lives in a lib rather than in one script because two consumers need the
# same table (TODO #221 and #229 set the lib_*.sh precedent, and ci.yml's
# coverage guard skips lib_*.sh):
#
#   test_weak_key_rejection.sh   — the C CLI only, so it also runs under the
#                                  sanitizers job, where TODO #239's stack
#                                  overflow is visible.
#   test_malformed_pem_matrix.sh — all four CLIs, because the bounds are a wire
#                                  contract: an artifact one CLI refuses must
#                                  not be one another accepts (TODO #240).
#
# Fixtures are generated ONCE with the Python CLI and fed to every language, so
# the suite also proves the four agree about a Python-produced artifact.
#
# The caller must define pass() and fail(), each taking a description.

# Rewrite item $3 of a DER SEQUENCE PEM to the integer $4.
hkx_mal_craft() {
    HCODEC_DIR="$HKX_MAL_CODEC_DIR" python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ['HCODEC_DIR'])
from codec import der_int, der_seq, pem_wrap, pem_unwrap, der_parse_seq

in_path, out_path, idx, value = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
label, der = pem_unwrap(open(in_path).read())
items = list(der_parse_seq(der))
items[idx] = value
open(out_path, 'w').write(pem_wrap(label, der_seq(*[der_int(x) for x in items])))
PYEOF
}

# hkx_mal_fixtures <dir> — genuine artifacts every language can read.
hkx_mal_fixtures() {
    local d="$1"
    local PY="python3 $HKX_MAL_ROOT/HerraduraCli/herradura.py"
    HKX_MAL_CODEC_DIR="$HKX_MAL_ROOT/HerraduraCli"

    echo "ring message" > "$d/rmsg.txt"
    $PY genpkey --algo hpks-stern --out "$d/rm1.pem" 2>/dev/null
    $PY genpkey --algo hpks-stern --out "$d/rm2.pem" 2>/dev/null
    $PY pkey --in "$d/rm1.pem" --pubout --out "$d/rm1_pub.pem" 2>/dev/null
    $PY pkey --in "$d/rm2.pem" --pubout --out "$d/rm2_pub.pem" 2>/dev/null
    $PY sign --algo hpks-ring --key "$d/rm1.pem" --ring "$d/rm1_pub.pem,$d/rm2_pub.pem" \
        --in "$d/rmsg.txt" --out "$d/rsig.pem" 2>/dev/null
    # Plain Stern-F, for the round count that TODO #236 bounded in C only.
    $PY sign --algo hpks-stern --key "$d/rm1.pem" --in "$d/rmsg.txt" \
        --out "$d/ssig.pem" 2>/dev/null

    $PY genpkey --algo hpke-stern-kem --out "$d/kem.pem" 2>/dev/null

    echo "xmss message" > "$d/xmsg.txt"
    $PY genpkey --algo hpks-xmss --xmss-height 2 --out "$d/x.pem" 2>/dev/null
    $PY pkey --in "$d/x.pem" --pubout --out "$d/x_pub.pem" 2>/dev/null
    $PY sign --algo hpks-xmss --key "$d/x.pem" --in "$d/xmsg.txt" --out "$d/xsig.pem" 2>/dev/null

    # A 256-bit symmetric key via HKEX-GF, for the duplex ciphertext.
    $PY genpkey --algo hkex-gf --out "$d/da.pem" 2>/dev/null
    $PY genpkey --algo hkex-gf --out "$d/db.pem" 2>/dev/null
    $PY pkey --in "$d/db.pem" --pubout --out "$d/db_pub.pem" 2>/dev/null
    $PY kex --algo hkex-gf --our "$d/da.pem" --their "$d/db_pub.pem" --out "$d/dk.pem" 2>/dev/null
    printf 'duplex plaintext spanning several 16-byte rate blocks, well over 32 bytes' \
        > "$d/dmsg.txt"
    $PY enc --algo hske-duplex --ad ctx --key "$d/dk.pem" \
        --in "$d/dmsg.txt" --out "$d/dct.pem" 2>/dev/null
}

# HKX_MAL_VLIMIT caps address space so a missing bound fails fast instead of
# swapping the host to death.  It is deliberately empty for the JVM, which
# reserves far more virtual address space than it commits: a `ulimit -v` tight
# enough to be useful stops java from starting at all, and a CLI that never
# starts exits non-zero — which a rejection test would have scored as a PASS.
# Java gets -Xmx in its command line instead.  See _hkx_mal_control.
_hkx_mal_run() {
    if [ -n "${HKX_MAL_VLIMIT:-}" ]; then
        ( ulimit -v "$HKX_MAL_VLIMIT" 2>/dev/null || true
          timeout "${HKX_MAL_TIMEOUT:-120}" "$@" ) 2>&1
    else
        timeout "${HKX_MAL_TIMEOUT:-120}" "$@" 2>&1
    fi
}

# _hkx_mal_control <desc> <cmd...> — assert the CLI handles the GENUINE artifact.
# Returns non-zero if it does not, and the caller must then skip that section's
# rejection cases: "the CLI exited non-zero" only means "rejected" if the CLI is
# known to work on the good input.  Without this the whole suite goes green when
# a CLI cannot start.
_hkx_mal_control() {
    local desc="$1"; shift
    local out rc
    out=$(_hkx_mal_run "$@") && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "$desc"
        return 0
    fi
    fail "$desc: exited $rc — $(echo "$out" | tail -1)"
    fail "$desc: SKIPPING this section's rejection cases — they cannot be trusted"
    return 1
}

# _hkx_mal_expect <desc> <cmd...> — assert a malformed artifact is REJECTED:
# non-zero exit, and neither a crash nor a verifier verdict.
_hkx_mal_expect() {
    local desc="$1"; shift
    local out rc
    out=$(_hkx_mal_run "$@") && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "$desc: CLI exited 0"
    elif echo "$out" | grep -qE 'Traceback \(most recent call last\)|fatal error: out of memory|MemoryError|Exception in thread|OutOfMemoryError|java.lang.[A-Za-z]*Error'; then
        fail "$desc: crashed instead of rejecting — $(echo "$out" | head -1)"
    elif [ "$(echo "$out" | tail -1)" = "Verification FAILED" ]; then
        fail "$desc: reached the verifier instead of being rejected"
    else
        pass "$desc"
    fi
}

# hkx_mal_suite <lang> <cli command...> — run every case this language supports.
# Each section asserts the genuine artifact first and skips its rejection cases
# if that control fails, so a broken CLI cannot produce a wall of PASS lines.
hkx_mal_suite() {
    local lang="$1"; shift
    local d="$HKX_MAL_DIR"
    local -a CLI=("$@")
    local bad="$d/bad_$lang.pem"
    local case idx val

    # ── HPKS-RING: k, rounds, n and the payload length (no Java ring reader) ──
    if [ "$lang" != java ]; then
        if _hkx_mal_control "[$lang] ring: genuine signature verifies" \
            "${CLI[@]}" verify --algo hpks-ring --pubkey "$d/rm1_pub.pem" \
            --ring "$d/rm1_pub.pem,$d/rm2_pub.pem" --in "$d/rmsg.txt" --sig "$d/rsig.pem"; then
            # item 0 = k, 1 = rounds, 2 = n, 3 = the k*rounds entry blob.
            for case in "0 1073741824 k=2^30" \
                        "0 2147483647 k=2^31-1" \
                        "0 65 k=65 (> RING_MAX_K)" \
                        "0 1 k=1 (a ring needs 2)" \
                        "1 1073741824 rounds=2^30" \
                        "1 0 rounds=0" \
                        "2 2147483647 n=2^31-1" \
                        "1 1 payload longer than k*rounds"; do
                set -- $case
                idx="$1" val="$2"; shift 2
                hkx_mal_craft "$d/rsig.pem" "$bad" "$idx" "$val"
                _hkx_mal_expect "[$lang] ring rejects $*" \
                    "${CLI[@]}" verify --algo hpks-ring --pubkey "$d/rm1_pub.pem" \
                    --ring "$d/rm1_pub.pem,$d/rm2_pub.pem" --in "$d/rmsg.txt" --sig "$bad"
            done
        fi
    fi

    # ── HPKS-Stern-F: the round count TODO #236 bounded in C only ──
    if _hkx_mal_control "[$lang] stern: genuine signature verifies" \
        "${CLI[@]}" verify --algo hpks-stern --pubkey "$d/rm1_pub.pem" \
        --in "$d/rmsg.txt" --sig "$d/ssig.pem"; then
        for val in 1073741824 2147483647 0; do
            hkx_mal_craft "$d/ssig.pem" "$bad" 1 "$val"
            _hkx_mal_expect "[$lang] stern rejects rounds=$val" \
                "${CLI[@]}" verify --algo hpks-stern --pubkey "$d/rm1_pub.pem" \
                --in "$d/rmsg.txt" --sig "$bad"
        done
        # item 0 is the key width.  The C reader sizes every blob from its own
        # KEYBITS and used to ignore the field entirely, so a signature the
        # other three refuse was one it verified (TODO #240).
        for val in 2147483647 0 255; do
            hkx_mal_craft "$d/ssig.pem" "$bad" 0 "$val"
            _hkx_mal_expect "[$lang] stern rejects n=$val" \
                "${CLI[@]}" verify --algo hpks-stern --pubkey "$d/rm1_pub.pem" \
                --in "$d/rmsg.txt" --sig "$bad"
        done
    fi

    # ── HPKE-Stern-KEM: the QC-MDPC row weight d (item 5) ──
    if _hkx_mal_control "[$lang] kem: genuine private key decodes" \
        "${CLI[@]}" pkey --in "$d/kem.pem" --pubout --out /dev/null; then
        for val in 16 2147483647; do
            hkx_mal_craft "$d/kem.pem" "$bad" 5 "$val"
            _hkx_mal_expect "[$lang] kem rejects row weight d=$val" \
                "${CLI[@]}" pkey --in "$bad" --pubout --out /dev/null
        done
    fi

    # ── HPKS-XMSS: the key height (item 1) and the signature depth (item 3) ──
    if _hkx_mal_control "[$lang] xmss: genuine key decodes" \
        "${CLI[@]}" pkey --in "$d/x.pem" --pubout --out /dev/null; then
        for val in 0 31 2147483647; do
            hkx_mal_craft "$d/x.pem" "$bad" 1 "$val"
            _hkx_mal_expect "[$lang] xmss rejects key height h=$val" \
                "${CLI[@]}" pkey --in "$bad" --pubout --out /dev/null
        done
    fi
    if _hkx_mal_control "[$lang] xmss: genuine signature verifies" \
        "${CLI[@]}" verify --algo hpks-xmss --pubkey "$d/x_pub.pem" \
        --in "$d/xmsg.txt" --sig "$d/xsig.pem"; then
        for val in 0 31 2147483647; do
            hkx_mal_craft "$d/xsig.pem" "$bad" 3 "$val"
            _hkx_mal_expect "[$lang] xmss rejects signature depth=$val" \
                "${CLI[@]}" verify --algo hpks-xmss --pubkey "$d/x_pub.pem" \
                --in "$d/xmsg.txt" --sig "$bad"
        done
    fi

    # ── HSKE-NL-V2-Duplex: the declared ciphertext length (item 2) ──
    if [ "$lang" != java ]; then
        if _hkx_mal_control "[$lang] duplex: genuine ciphertext decrypts" \
            "${CLI[@]}" dec --algo hske-duplex --ad ctx --key "$d/dk.pem" \
            --in "$d/dct.pem" --out /dev/null; then
            for val in 1 4294967296; do
                hkx_mal_craft "$d/dct.pem" "$bad" 2 "$val"
                _hkx_mal_expect "[$lang] duplex rejects declared ct length $val" \
                    "${CLI[@]}" dec --algo hske-duplex --ad ctx --key "$d/dk.pem" \
                    --in "$bad" --out /dev/null
            done
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Packed (non-DER) framings — TODO #275.
#
# Eight PEM labels do not use DER at all.  They frame fields at fixed offsets
# whose sizes are DERIVED from a 4-byte big-endian `n` header rather than
# carried as lengths:
#
#   HERRADURA ZKP-NL PRIVATE KEY / PUBLIC KEY / PROOF
#   HERRADURA ZKP-NL-PP SIGNATURE
#   HERRADURA ZKP-RNL PROOF
#   HERRADURA HCRED PRIVATE KEY / PUBLIC KEY / PROOF
#
# hkx_mal_craft cannot reach them: it decodes a DER SEQUENCE of INTEGERs,
# rewrites one, and re-encodes.  So the four-CLI matrix above had structurally
# zero coverage here, and a case that was never written is not a case that
# fails.  hkx_mal_poke is the second craft helper that closes that, and it is
# simpler than its DER sibling precisely because the framing is positional:
# no re-encode, just an integer written at a byte offset.
#
# What the cases are aimed at.  These labels DO have fields that size an
# allocation — `n`, `rounds`, and HCRED's `W` — and the round count is the one
# that is not merely a robustness matter.  A ZKP verifier loops over rounds and
# reports success when every round checks out; at rounds == 0 that loop runs
# zero times and the function returns "verified" for ANY message under ANY
# public key.  Three of the four CLIs accepted an 89-byte PEM of eight null
# bytes as a valid nl-zkboo signature before this table existed.
#
# A note on the `n` values chosen, because it is a real constraint and not
# arbitrary.  The per-language maxima differ for REPRESENTATION reasons, not
# policy: C's ZKP_NL_MAX_N is 64 (uint64 shares) and Go's ZkpNlMaxN is 32
# (uint32 shares), so widths 33..64 are legitimately read by C, Python and Java
# and refused by Go.  Cases therefore use 0, 65 and 2^32-1 — outside every
# language's band — so that a rejection is a four-way agreement rather than an
# accident of which implementation is under test.

# Rewrite a big-endian unsigned integer of $4 bytes at byte offset $3 of the
# raw (non-DER) PEM body of $1, writing the result to $2.
hkx_mal_poke() {
    HCODEC_DIR="$HKX_MAL_CODEC_DIR" python3 - "$1" "$2" "$3" "$4" "$5" <<'PYEOF'
import os, sys
sys.path.insert(0, os.environ['HCODEC_DIR'])
from codec import pem_wrap, pem_unwrap

in_path, out_path = sys.argv[1], sys.argv[2]
off, width, value = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
label, body = pem_unwrap(open(in_path).read())
b = bytearray(body)
if off + width > len(b):
    sys.exit(f"hkx_mal_poke: offset {off}+{width} past body ({len(b)} bytes)")
b[off:off + width] = value.to_bytes(width, 'big')
open(out_path, 'w').write(pem_wrap(label, bytes(b)))
PYEOF
}

# hkx_mal_fixtures_packed <dir> — genuine artifacts for the eight packed labels.
# HCRED and the Stern issuer key are the slow ones, so everything is generated
# once with the Python CLI and shared across languages, as the DER table does.
hkx_mal_fixtures_packed() {
    local d="$1"
    local PY="python3 $HKX_MAL_ROOT/HerraduraCli/herradura.py"
    HKX_MAL_CODEC_DIR="$HKX_MAL_ROOT/HerraduraCli"

    echo "zkp message" > "$d/zmsg.txt"

    # ZKP-NL: private key, public key, ZKBoo proof, ZKB++ signature.
    $PY genpkey --algo hpks-zkp-nl --out "$d/zk.pem" 2>/dev/null
    $PY pkey --in "$d/zk.pem" --pubout --out "$d/zk_pub.pem" 2>/dev/null
    $PY sign --algo nl-zkboo --key "$d/zk.pem" --in "$d/zmsg.txt" \
        --out "$d/zkboo.pem" 2>/dev/null
    $PY sign --algo nl-zkbpp --key "$d/zk.pem" --in "$d/zmsg.txt" \
        --out "$d/zkbpp.pem" 2>/dev/null

    # ZKP-RNL: a Ring-LWR Sigma proof over an hkex-rnl key.
    $PY genpkey --algo hkex-rnl --out "$d/rs.pem" 2>/dev/null
    $PY pkey --in "$d/rs.pem" --pubout --out "$d/rs_pub.pem" 2>/dev/null
    $PY sign --algo rnl-sigma --key "$d/rs.pem" --in "$d/zmsg.txt" \
        --out "$d/rnlsig.pem" 2>/dev/null

    # HCRED is deliberately NOT here — see hkx_mal_hcred_fixtures.
}

# hkx_mal_hcred_fixtures <lang> <dir> <cli command...> — HCRED artifacts made by
# the CLI UNDER TEST, not by Python.
#
# Every other fixture in this file is generated once with the Python CLI and fed
# to all four, which is a feature: it proves the four agree about a
# Python-produced artifact.  HCRED cannot work that way, and the reason is a
# recorded asymmetry rather than an oversight: its width is a RUNTIME argument in
# Python and Go (both demo at n=32) but a COMPILE-TIME constant of 256 in C
# (HCRED_N) and Java (Hcred.N).  So no single HCRED artifact is readable by all
# four, and a shared fixture makes the C and Java sections fail their own
# controls — correctly, but it means those two get no rejection coverage at all.
#
# Generating per-language restores that coverage.  What it gives up is the
# cross-language claim, which for HCRED does not exist to give up.
# --rounds 4 keeps it cheap (~0.5 s compiled, ~2 s in Python); the reader's
# bounds are what is under test here, not soundness.
hkx_mal_hcred_fixtures() {
    local lang="$1" d="$2"; shift 2
    local -a CLI=("$@")
    "${CLI[@]}" genpkey --algo hcred --out "$d/hc_$lang.pem" >/dev/null 2>&1 &&
    "${CLI[@]}" pkey --in "$d/hc_$lang.pem" --pubout \
        --out "$d/hc_pub_$lang.pem" >/dev/null 2>&1 &&
    "${CLI[@]}" cred-issue --our "$d/rm1.pem" --in "$d/hc_pub_$lang.pem" \
        --rounds 4 --out "$d/cred_$lang.pem" >/dev/null 2>&1 &&
    "${CLI[@]}" cred-prove --in "$d/hc_$lang.pem" --msg nonce --rounds 4 \
        --out "$d/hcproof_$lang.pem" >/dev/null 2>&1
}

# hkx_mal_suite_packed <lang> <cli command...>
hkx_mal_suite_packed() {
    local lang="$1"; shift
    local d="$HKX_MAL_DIR"
    local -a CLI=("$@")
    local bad="$d/badp_$lang.pem"
    local case off w val

    # ── ZKP-NL public key: n sizes the two nb-byte field reads ──
    if _hkx_mal_control "[$lang] zkp-nl: genuine proof verifies" \
        "${CLI[@]}" verify --algo nl-zkboo --pubkey "$d/zk_pub.pem" \
        --in "$d/zmsg.txt" --sig "$d/zkboo.pem"; then
        for val in 0 65 4294967295; do
            hkx_mal_poke "$d/zk_pub.pem" "$bad" 0 4 "$val"
            _hkx_mal_expect "[$lang] zkp-nl pubkey rejects n=$val" \
                "${CLI[@]}" verify --algo nl-zkboo --pubkey "$bad" \
                --in "$d/zmsg.txt" --sig "$d/zkboo.pem"
        done
        # n=1 is the case a length check alone cannot catch: nb = ceil(n/8) is
        # 1 for every n in 1..8, so the body is exactly as long as it should be
        # and only comparing the proof's n against the key's n rejects it.
        hkx_mal_poke "$d/zk_pub.pem" "$bad" 0 4 1
        _hkx_mal_expect "[$lang] zkp-nl pubkey rejects n=1 (aliases nb with n=8)" \
            "${CLI[@]}" verify --algo nl-zkboo --pubkey "$bad" \
            --in "$d/zmsg.txt" --sig "$d/zkboo.pem"

        # ── ZKBoo proof: n at offset 0, rounds at offset 4 ──
        for val in 0 65 4294967295; do
            hkx_mal_poke "$d/zkboo.pem" "$bad" 0 4 "$val"
            _hkx_mal_expect "[$lang] zkboo proof rejects n=$val" \
                "${CLI[@]}" verify --algo nl-zkboo --pubkey "$d/zk_pub.pem" \
                --in "$d/zmsg.txt" --sig "$bad"
        done
        # rounds=0 is the forgery: the verifier's per-round loop runs zero
        # times and reports success for any message under any key.
        for val in 0 1073741824 4294967295; do
            hkx_mal_poke "$d/zkboo.pem" "$bad" 4 4 "$val"
            _hkx_mal_expect "[$lang] zkboo proof rejects rounds=$val" \
                "${CLI[@]}" verify --algo nl-zkboo --pubkey "$d/zk_pub.pem" \
                --in "$d/zmsg.txt" --sig "$bad"
        done
        # The first round's len_p1 sits at 8 + 96 + 1 = 105.  Setting it to
        # 0xffff overruns the body; a reader that checks only "does l1 fit"
        # and not "do len_p2's own two bytes still fit" reads past the end.
        hkx_mal_poke "$d/zkboo.pem" "$bad" 4 4 1
        hkx_mal_poke "$bad" "$bad" 105 2 65535
        _hkx_mal_expect "[$lang] zkboo proof rejects len_p1 past body" \
            "${CLI[@]}" verify --algo nl-zkboo --pubkey "$d/zk_pub.pem" \
            --in "$d/zmsg.txt" --sig "$bad"
    fi

    # ── ZKB++ signature: same two header fields, different per-round layout ──
    if _hkx_mal_control "[$lang] zkbpp: genuine signature verifies" \
        "${CLI[@]}" verify --algo nl-zkbpp --pubkey "$d/zk_pub.pem" \
        --in "$d/zmsg.txt" --sig "$d/zkbpp.pem"; then
        for case in "0 0 n=0" "0 65 n=65" "0 4294967295 n=2^32-1" \
                    "4 0 rounds=0" "4 4294967295 rounds=2^32-1"; do
            set -- $case
            off="$1" val="$2"; shift 2
            hkx_mal_poke "$d/zkbpp.pem" "$bad" "$off" 4 "$val"
            _hkx_mal_expect "[$lang] zkbpp rejects $*" \
                "${CLI[@]}" verify --algo nl-zkbpp --pubkey "$d/zk_pub.pem" \
                --in "$d/zmsg.txt" --sig "$bad"
        done
    fi

    # ── ZKP-RNL proof: n sizes three n-coefficient polynomials ──
    if _hkx_mal_control "[$lang] rnl-sigma: genuine signature verifies" \
        "${CLI[@]}" verify --algo rnl-sigma --pubkey "$d/rs_pub.pem" \
        --in "$d/zmsg.txt" --sig "$d/rnlsig.pem"; then
        # 32 is in range for the reader but wrong for the key's 1024-coefficient
        # ring, so it is caught by the n cross-check rather than by a bound.
        for val in 0 32 2147483647 4294967295; do
            hkx_mal_poke "$d/rnlsig.pem" "$bad" 0 4 "$val"
            _hkx_mal_expect "[$lang] rnl-sigma rejects n=$val" \
                "${CLI[@]}" verify --algo rnl-sigma --pubkey "$d/rs_pub.pem" \
                --in "$d/zmsg.txt" --sig "$bad"
        done
    fi

    # ── HCRED: per-language fixtures; see hkx_mal_hcred_fixtures ──
    if ! hkx_mal_hcred_fixtures "$lang" "$d" "${CLI[@]}"; then
        echo "NOTE: [$lang] HCRED fixtures could not be generated — section skipped"
        return 0
    fi
    local hpub="$d/hc_pub_$lang.pem" hprf="$d/hcproof_$lang.pem"
    local hcred="$d/cred_$lang.pem"

    # n sizes C_poly, m_poly, seed_H and the syndrome.  33 is in range for the
    # reader but wrong for the artifact, so it exercises the length check
    # rather than the bound.
    if _hkx_mal_control "[$lang] hcred: genuine public key is issuable" \
        "${CLI[@]}" cred-issue --our "$d/rm1.pem" --in "$hpub" \
        --rounds 4 --out /dev/null; then
        for val in 0 33 2147483647 4294967295; do
            hkx_mal_poke "$hpub" "$bad" 0 4 "$val"
            _hkx_mal_expect "[$lang] hcred pubkey rejects n=$val" \
                "${CLI[@]}" cred-issue --our "$d/rm1.pem" --in "$bad" \
                --rounds 4 --out /dev/null
        done
    fi

    # HCRED PROOF: n at 0, W at 4, rounds at 8.  rounds=0 is the same vacuous
    # acceptance as the ZKBoo case above, in a second protocol.
    if _hkx_mal_control "[$lang] hcred: genuine proof verifies" \
        "${CLI[@]}" cred-verify --cred "$hcred" --issuer "$d/rm1_pub.pem" \
        --pubkey "$hpub" --proof "$hprf" --msg nonce; then
        for case in "0 0 n=0" "0 33 n=33" "0 4294967295 n=2^32-1" \
                    "4 0 W=0" "4 4294967295 W=2^32-1" \
                    "8 0 rounds=0" "8 4294967295 rounds=2^32-1"; do
            set -- $case
            off="$1" val="$2"; shift 2
            hkx_mal_poke "$hprf" "$bad" "$off" 4 "$val"
            _hkx_mal_expect "[$lang] hcred proof rejects $*" \
                "${CLI[@]}" cred-verify --cred "$hcred" \
                --issuer "$d/rm1_pub.pem" --pubkey "$hpub" \
                --proof "$bad" --msg nonce
        done
    fi
}
