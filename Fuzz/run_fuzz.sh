#!/usr/bin/env bash
# Fuzz/run_fuzz.sh — time-boxed manual fuzzing run for TODO #130.
#
# No CI exists in this repo (see CLAUDE.md: tests are run manually), so this
# script is the documented invocation point for all four fuzz surfaces:
# C codec (libFuzzer), Go codec (native go test -fuzz), Python codec
# (hypothesis), and CLI argument parsing (black-box argv fuzzer, all 3 CLIs).
#
# Usage: ./Fuzz/run_fuzz.sh [SECONDS_PER_TARGET]   (default: 30)
#
# Requires: clang (with -fsanitize=fuzzer support) for the C targets,
# go1.18+ for the Go target, python3-hypothesis for the Python target.
# All three are standard apt packages (clang, golang, python3-hypothesis).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"
SECS="${1:-30}"

echo "=== C codec: libFuzzer (b64_decode, der_parse_seq, pem_unwrap) ==="
for t in fuzz_b64_decode fuzz_der_parse_seq fuzz_pem_unwrap; do
    echo "-- $t --"
    clang -fsanitize=fuzzer,address,undefined -g -O1 -I.. -o "$t" "$t.c"
    mkdir -p "corpus/${t#fuzz_}"
    ./"$t" -max_total_time="$SECS" -close_fd_mask=3 "corpus/${t#fuzz_}"
    rm -f "$t"
done

echo
echo "=== Go codec: native fuzz (FuzzPemUnwrap, FuzzDerParseSeq) ==="
( cd "$REPO" && go test ./herradura/ -run=xxx -fuzz=FuzzPemUnwrap   -fuzztime="${SECS}s" )
( cd "$REPO" && go test ./herradura/ -run=xxx -fuzz=FuzzDerParseSeq -fuzztime="${SECS}s" )

echo
echo "=== Python codec: hypothesis (der_parse_seq, pem_unwrap) ==="
python3 fuzz_codec_py.py

echo
echo "=== CLI argument parsing: all three CLIs (requires build_c.sh / build_go.sh already run) ==="
clang -fsanitize=address,undefined -g -O1 -o herradura_cli_asan "$REPO/HerraduraCli/herradura_cli.c"
python3 fuzz_cli_args.py --seconds "$SECS"
rm -f herradura_cli_asan

echo
echo "=== Fuzzing run complete ==="
