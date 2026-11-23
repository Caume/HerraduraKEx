#!/usr/bin/env bash
# CliTest/test_file_modes.sh — TODO #395: every file a CLI creates is mode 0600.
#
# Until #395 no CLI set a file mode.  C used fopen(path, "w"), Go os.WriteFile
# with 0644, Python open(path, "w"), Java Files.write, so under the usual 022
# umask every private key, decrypted PEM, shared secret and plaintext the CLIs
# wrote was readable by every local user (CodeQL cpp/cleartext-storage-file on
# pkey --decrypt, PR #377).  Now each CLI's few write helpers create the file
# with mode 0600 (C hkx_fopen_out, Go os.WriteFile(..., 0600), Python
# _open_out, Java createFile with rw-------).  The rule covers EVERY output,
# public ones included, so nothing needs classifying.  A file that already
# exists keeps its mode, as O_CREAT and OpenSSL do.
#
# Each CLI, under umask 022:
#   0. control: a file `touch` creates is 644, so a 600 below is the CLI's doing
#      and the mode check can tell the two apart.
#   1. one cell per write path: PEM writer (private key, public key, session
#      key from kex, plaintext PEM from pkey --decrypt), raw binary writer
#      (rand --out, twk --out), the DRBG state PEM, encfile / decfile, the
#      WOTS .idx sidecar.
#   2. an existing 0644 file overwritten by genpkey keeps 0644, and its
#      content WAS replaced (so the keep is not a failed write).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/CliTest/lib_build.sh"
hkx_require_built c go java

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL+1)); }

bash "$ROOT/bindings/java/build.sh" >/dev/null 2>&1 || { echo "FAIL Java build" >&2; exit 1; }

declare -A CLI=(
    [py]="python3 $ROOT/HerraduraCli/herradura.py"
    [c]="$ROOT/HerraduraCli/herradura_cli"
    [go]="$ROOT/HerraduraCli/herradura_cli_go"
    [java]="java -cp $ROOT/bindings/java herradurakex.HerraduraCli"
)
LANGS=(py c go java)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
umask 022

# mode_is <want> <file> <name>
mode_is() {
    local got
    if [ ! -f "$2" ]; then fail "$3: $2 was not written"; return; fi
    got=$(stat -c %a "$2")
    if [ "$got" = "$1" ]; then pass; else fail "$3: mode $got, want $1"; fi
}
# run <name> <cmd...>: a cell's command must succeed before its mode is read
run() {
    local name=$1; shift
    "$@" >/dev/null 2>"$TMP/err" || { fail "$name: exit $?: $(head -c 300 "$TMP/err")"; return 1; }
}

for L in "${LANGS[@]}"; do
    X=${CLI[$L]}
    D="$TMP/$L"; mkdir -p "$D"

    touch "$D/control"
    mode_is 644 "$D/control" "control: touch under umask 022 ($L)"

    run "genpkey ($L)" $X genpkey --algo hkex-gf --out "$D/a.pem" \
        && mode_is 600 "$D/a.pem" "genpkey private key ($L)"
    run "pkey --pubout ($L)" $X pkey --in "$D/a.pem" --pubout --out "$D/a_pub.pem" \
        && mode_is 600 "$D/a_pub.pem" "pkey --pubout public key ($L)"
    run "genpkey peer ($L)" $X genpkey --algo hkex-gf --out "$D/b.pem"
    run "pkey peer ($L)" $X pkey --in "$D/b.pem" --pubout --out "$D/b_pub.pem"
    run "kex ($L)" $X kex --algo hkex-gf --our "$D/a.pem" --their "$D/b_pub.pem" --out "$D/sk.pem" \
        && mode_is 600 "$D/sk.pem" "kex session key ($L)"
    run "genpkey --passphrase ($L)" $X genpkey --algo hkex-gf --passphrase pw --kdf-iterations 1 \
            --out "$D/enc.pem" \
        && mode_is 600 "$D/enc.pem" "genpkey encrypted private key ($L)"
    run "pkey --decrypt ($L)" $X pkey --decrypt --passphrase pw --in "$D/enc.pem" --out "$D/dec.pem" \
        && mode_is 600 "$D/dec.pem" "pkey --decrypt plaintext key ($L)"
    head -c 32 /dev/urandom > "$D/seed.bin"
    run "rand ($L)" $X rand --seed "$D/seed.bin" --bytes 32 --state "$D/drbg.pem" --out "$D/r.bin" \
        && mode_is 600 "$D/r.bin" "rand --out ($L)" \
        && mode_is 600 "$D/drbg.pem" "rand --state DRBG state ($L)"
    head -c 32 /dev/urandom > "$D/blk"
    run "twk ($L)" $X twk --key "$D/sk.pem" --encrypt --in "$D/blk" --out "$D/t.bin" \
        && mode_is 600 "$D/t.bin" "twk --out ($L)"
    printf 'file modes' > "$D/plain.bin"
    run "encfile ($L)" $X encfile --algo hske-nla1 --key "$D/sk.pem" --in "$D/plain.bin" --out "$D/f.hkx" \
        && mode_is 600 "$D/f.hkx" "encfile --out ($L)"
    run "decfile ($L)" $X decfile --algo hske-nla1 --key "$D/sk.pem" --in "$D/f.hkx" --out "$D/f.out" \
        && mode_is 600 "$D/f.out" "decfile plaintext ($L)" \
        && { cmp -s "$D/plain.bin" "$D/f.out" && pass || fail "decfile round trip ($L)"; }
    run "genpkey wots ($L)" $X genpkey --algo hpks-wots --out "$D/w.pem" \
        && run "sign wots ($L)" $X sign --algo hpks-wots --key "$D/w.pem" --in "$D/plain.bin" --out "$D/w.sig" \
        && mode_is 600 "$D/w.pem.idx" "WOTS .idx sidecar ($L)"

    # 2. an existing file keeps its mode, and was really rewritten
    echo stale > "$D/old.pem"; chmod 644 "$D/old.pem"
    run "genpkey over existing ($L)" $X genpkey --algo hkex-gf --out "$D/old.pem" \
        && mode_is 644 "$D/old.pem" "existing 0644 file keeps its mode ($L)" \
        && { grep -q "BEGIN HERRADURA" "$D/old.pem" && pass || fail "existing file was not rewritten ($L)"; }
done

echo "Results: $PASS PASS / $FAIL FAIL (languages: ${LANGS[*]})"
hkx_require_asserted "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
