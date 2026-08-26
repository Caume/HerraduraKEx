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
