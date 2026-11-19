#!/usr/bin/env bash
# CliTest/test_key_params.sh — TODO #379: genpkey's key parameter sets.
#
# Every key size `genpkey` makes now comes from one curated table,
# spec/generate_spec.py's key parameter sets, generated into all four CLIs.  A
# row is chosen by `--bits` (kept for compatibility) or by `--level` (the
# strength the parameters are sized for).  Before the table, the audit found:
# Go PANICKED at --bits 0 / 7 / 100 on hkex-rnl, hcred and Stern, hung on
# `oprf --bits 7` and silently wrote 256-bit classical keys for any unlisted
# width; Python died with IndexError / OverflowError / E_WIDTH tracebacks; Java
# ignored --bits on every algorithm but hpks-zkp-nl; C had no --bits at all.
#
# Sections (CLIs: py c go java):
#   1. accept-control: genpkey with neither flag writes the default row's width
#      in every CLI, and every CLI reads it back at that width.
#   2. every row by --bits: a CLI the row lists accepts it, writes that width
#      (warning on stderr exactly when it is narrower than the default), and
#      every CLI the row lists reads the key back at that width; a CLI the row
#      does not list refuses it by name ("not yet supported by this CLI"); a
#      withdrawn row is refused everywhere.
#   3. every --level name for every algorithm: a row with that level is taken
#      (or refused as in 2), a missing level is refused by name.
#   4. --bits values no row lists, and malformed --level names, are refused.
#   5. both flags together, and either flag on a fixed-parameter algorithm.
#   6. invariants written out here rather than read from the table, so a table
#      edit that loosens them fails: the GF family refuses --level 128,
#      hkex-rnl refuses 512, hkex-rnl --level 128 is n = 1024 everywhere, and
#      Python and Go take the GF family at 32 and 64 bits.
# Each refusal must exit 1 or 2 with its message, write no output and not crash.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go java

declare -A CLI=(
    [py]="python3 $ROOT/HerraduraCli/herradura.py"
    [c]="$ROOT/HerraduraCli/herradura_cli"
    [go]="$ROOT/HerraduraCli/herradura_cli_go"
    [java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
)
LANGS=(py c go java)
bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

# The table, from the generated spec: algo bits level default ports withdrawn
python3 - "$ROOT/spec/herradura-protocol-spec.json" > "$TMP/rows" <<'EOF'
import json, sys
ps = json.load(open(sys.argv[1]))["key_parameter_sets"]
for r in ps["rows"]:
    print(r["algo"], r["bits"], r["level"] or "-", int(r["default"]),
          ",".join(r["ports"]) or "-", int(bool(r["withdrawn"])))
print("#levels", " ".join(ps["levels"]))
print("#fixed", " ".join(ps["fixed_algos"]))
print("#own", " ".join(ps["own_bits_rule"]))
EOF
LEVELS=$(sed -n 's/^#levels //p' "$TMP/rows")
FIXED=$(sed -n 's/^#fixed //p' "$TMP/rows")
OWN=$(sed -n 's/^#own //p' "$TMP/rows")
grep -v '^#' "$TMP/rows" > "$TMP/table"
ALGOS=$(awk '{print $1}' "$TMP/table" | sort -u)
[ -n "$ALGOS" ] || { echo "FAIL no parameter-set rows in the spec"; exit 1; }

has_port() { case ",$1," in *",$2,"*) return 0 ;; *) return 1 ;; esac; }
dflt_bits() { awk -v a="$1" '$1==a && $4==1 {print $2}' "$TMP/table"; }

# width as `pkey --text` reports it (bits or n); empty for a key with neither
width_of() {  # cli key
    ${CLI[$1]} pkey --text --in "$2" 2>/dev/null \
        | awk -F: '/^(bits|n) +:/ {gsub(/ /, "", $2); print $2; exit}'
}

# accept: cli label want_bits want_warn(1/0/-) args...
accept() {
    local c=$1 label=$2 want=$3 warn=$4; shift 4
    local k="$TMP/k.pem"; rm -f "$k"
    ${CLI[$c]} genpkey "$@" --out "$k" >/dev/null 2>"$TMP/err"; local rc=$?
    if [ $rc -ne 0 ] || [ ! -s "$k" ]; then
        fail "$label ($c): not accepted (rc=$rc): $(head -c 200 "$TMP/err")"; return 1
    fi
    if [ "$want" -gt 0 ]; then
        local got; got=$(width_of "$c" "$k")
        if [ "$got" != "$want" ]; then fail "$label ($c): wrote width '$got', want $want"; return 1; fi
    fi
    if [ "$warn" = 1 ] && ! grep -q "is a demonstration width" "$TMP/err"; then
        fail "$label ($c): narrower than the default but no demo-width warning"; return 1
    fi
    if [ "$warn" = 0 ] && grep -q "is a demonstration width" "$TMP/err"; then
        fail "$label ($c): demo-width warning on a default-or-wider width"; return 1
    fi
    pass; cp "$k" "$TMP/accepted.pem"; return 0
}

# refuse: cli label message args...
refuse() {
    local c=$1 label=$2 want=$3; shift 3
    local k="$TMP/r.pem"; rm -f "$k"
    ${CLI[$c]} genpkey "$@" --out "$k" >/dev/null 2>"$TMP/err"; local rc=$?
    if [ $rc -eq 0 ]; then fail "$label ($c): accepted (exit 0)"
    elif [ $rc -gt 2 ] || grep -qE 'Traceback|panic:|Exception in thread' "$TMP/err"; then
        fail "$label ($c): crashed (rc=$rc): $(head -c 200 "$TMP/err")"
    elif ! grep -qF -- "$want" "$TMP/err"; then
        fail "$label ($c): refused, but not with '$want': $(head -c 200 "$TMP/err")"
    elif [ -e "$k" ]; then fail "$label ($c): refused but wrote output"
    else pass; fi
}

# every CLI a row lists reads the accepted key back at its width
cross_read() {  # label ports want
    local label=$1 ports=$2 want=$3 r got
    for r in "${LANGS[@]}"; do
        has_port "$ports" "$r" || continue
        got=$(width_of "$r" "$TMP/accepted.pem")
        if [ "$got" = "$want" ]; then pass; else fail "$label: read by $r at width '$got', want $want"; fi
    done
}

# ── 1. accept-control: the default row, no flags ────────────────────────────
for a in $ALGOS; do
    d=$(dflt_bits "$a"); ports=$(awk -v a="$a" '$1==a && $4==1 {print $5}' "$TMP/table")
    for c in "${LANGS[@]}"; do
        accept "$c" "genpkey $a (default)" "$d" 0 --algo "$a" \
            && [ "$d" -gt 0 ] && cross_read "genpkey $a (default, by $c)" "$ports" "$d"
    done
done

# ── 2. every row by --bits ──────────────────────────────────────────────────
while read -r a b lvl dflt ports wd; do
    [ "$b" -gt 0 ] || continue
    case " $OWN " in *" $a "*) continue ;; esac
    d=$(dflt_bits "$a"); [ "$b" -lt "$d" ] && warn=1 || warn=0
    for c in "${LANGS[@]}"; do
        if [ "$wd" = 1 ]; then
            refuse "$c" "genpkey $a --bits $b" "for --algo $a is withdrawn" --algo "$a" --bits "$b"
        elif has_port "$ports" "$c"; then
            accept "$c" "genpkey $a --bits $b" "$b" "$warn" --algo "$a" --bits "$b" \
                && cross_read "genpkey $a --bits $b (by $c)" "$ports" "$b"
        else
            refuse "$c" "genpkey $a --bits $b" "is not yet supported by this CLI" --algo "$a" --bits "$b"
        fi
    done
done < "$TMP/table"

# ── 3. every --level for every algorithm ────────────────────────────────────
for a in $ALGOS; do
    d=$(dflt_bits "$a")
    for l in $LEVELS; do
        row=$(awk -v a="$a" -v l="$l" '$1==a && $3==l' "$TMP/table")
        for c in "${LANGS[@]}"; do
            if [ -z "$row" ]; then
                refuse "$c" "genpkey $a --level $l" "--level $l is not available for --algo $a" --algo "$a" --level "$l"
                continue
            fi
            set -- $row; b=$2; ports=$5
            if has_port "$ports" "$c"; then
                [ "$b" -gt 0 ] && [ "$b" -lt "$d" ] && warn=1 || warn=0
                accept "$c" "genpkey $a --level $l" "$b" "$warn" --algo "$a" --level "$l"
            else
                refuse "$c" "genpkey $a --level $l" "is not yet supported by this CLI" --algo "$a" --level "$l"
            fi
        done
    done
done

# ── 4. unlisted --bits values and malformed --level names ───────────────────
for a in $ALGOS; do
    case " $OWN " in *" $a "*) continue ;; esac
    listed=$(awk -v a="$a" '$1==a && $2>0 {print $2}' "$TMP/table" | tr '\n' ' ')
    for v in 0 7 100 512 1024 2048 abc -64 +64 064 "64 " "" 0x40; do
        case " $listed " in *" $v "*) continue ;; esac
        if [ -z "$listed" ]; then want="--bits does not apply to --algo $a"
        else want="--bits must be one of"; fi
        for c in "${LANGS[@]}"; do
            refuse "$c" "genpkey $a --bits '$v'" "$want" --algo "$a" --bits "$v"
        done
    done
done
for v in "" Demo 64 128bit low; do
    for c in "${LANGS[@]}"; do
        refuse "$c" "genpkey hpks --level '$v'" "--level must be one of" --algo hpks --level "$v"
    done
done

# ── 5. both flags; either flag on a fixed-parameter algorithm ───────────────
for c in "${LANGS[@]}"; do
    refuse "$c" "genpkey hpks --bits 256 --level demo" "give --bits or --level, not both" \
        --algo hpks --bits 256 --level demo
    for a in $FIXED; do
        refuse "$c" "genpkey $a --bits 256" "--algo $a has fixed parameters" --algo "$a" --bits 256
        refuse "$c" "genpkey $a --level demo" "--algo $a has fixed parameters" --algo "$a" --level demo
    done
done

# ── 6. invariants not read from the table ───────────────────────────────────
for c in "${LANGS[@]}"; do
    for a in hkex-gf hpks hpke oprf; do
        refuse "$c" "invariant: $a --level 128" "--level 128 is not available for --algo $a" --algo "$a" --level 128
    done
    refuse "$c" "invariant: hkex-rnl --bits 512" "is withdrawn" --algo hkex-rnl --bits 512
    accept "$c" "invariant: hkex-rnl --level 128" 1024 0 --algo hkex-rnl --level 128
done
for c in py go; do
    for a in hkex-gf hpks hpke-nl3; do
        for b in 32 64; do accept "$c" "invariant: $a --bits $b" "$b" 1 --algo "$a" --bits "$b"; done
    done
done

echo
echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
[ "$PASS" -gt 0 ] || exit 2
[ "$FAIL" -eq 0 ] || exit 1
