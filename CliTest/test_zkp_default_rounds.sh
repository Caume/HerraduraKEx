#!/usr/bin/env bash
# CliTest/test_zkp_default_rounds.sh — TODO #142: mechanically confirm each CLI's
# nl-zkboo/nl-zkbpp `sign` defaults to 219 rounds (128-bit ZKBoo soundness) when
# --rounds is omitted, rather than a demo-strength round count. A prior audit found
# the Go CLI silently defaulted to 4 rounds (~20% forgery probability) with no way
# to reach production strength; this test re-detects that class of regression
# mechanically instead of requiring another manual audit.
#
# The ZKP-NL proof PEM wire format is shared byte-for-byte across all three CLIs
# (see HerraduraCli/codec.py:265 encode_zkp_nl_proof, herradura_cli.c:247, and
# herradura_cli.go's encodeZkpNlProof): 4 bytes big-endian n, then 4 bytes
# big-endian round count R, then R proof rounds. Round count is decoded directly
# from those 8 header bytes rather than fully parsing the proof.
set -euo pipefail

CLI_PY="python3 $(dirname "$0")/../HerraduraCli/herradura.py"
CLI_C="$(dirname "$0")/../HerraduraCli/herradura_cli"
CLI_GO="$(dirname "$0")/../HerraduraCli/herradura_cli_go"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
EXPECTED_ROUNDS=219

decode_rounds() {
    # Reads a ZKP-NL / ZKB++ proof PEM (any of the three implementations'
    # output) and prints the round count encoded in its 8-byte header.
    local path="$1" decoder="$2"
    python3 -c "
import sys
sys.path.insert(0, '$(dirname "$0")/../HerraduraCli')
from codec import $decoder
with open('$path') as f:
    rounds, _n = $decoder(f.read())
print(len(rounds))
"
}

check_rounds() {
    local label="$1" proof_path="$2" decoder="$3"
    local got
    got=$(decode_rounds "$proof_path" "$decoder")
    if [ "$got" -eq "$EXPECTED_ROUNDS" ]; then
        echo "PASS $label (rounds=$got)"
        PASS=$((PASS+1))
    else
        echo "FAIL $label: expected $EXPECTED_ROUNDS rounds, got $got"
        FAIL=$((FAIL+1))
    fi
}

printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' > "$TMP/msg.bin"

for name in python c go; do
    case "$name" in
        python) CLI="$CLI_PY" ;;
        c)      CLI="$CLI_C" ;;
        go)     CLI="$CLI_GO" ;;
    esac
    $CLI genpkey --algo hpks-zkp-nl --out "$TMP/${name}_zkpnl.pem"

    $CLI sign --algo nl-zkboo --key "$TMP/${name}_zkpnl.pem" \
              --in "$TMP/msg.bin" --out "$TMP/${name}_zkboo_default.pem"
    check_rounds "$name nl-zkboo default rounds" "$TMP/${name}_zkboo_default.pem" decode_zkp_nl_proof

    $CLI sign --algo nl-zkbpp --key "$TMP/${name}_zkpnl.pem" \
              --in "$TMP/msg.bin" --out "$TMP/${name}_zkbpp_default.pem"
    check_rounds "$name nl-zkbpp default rounds" "$TMP/${name}_zkbpp_default.pem" decode_zkp_nl_pp_proof
done

echo ""
echo "Results: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
