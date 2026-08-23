# CliTest/lib_build.sh — shared "is the CLI binary actually built?" policy.
# TODO #229.
#
# Until v3.0.2 the four compiled artifacts (HerraduraCli/herradura_cli,
# HerraduraCli/herradura_cli_go, and the two _arm binaries) were tracked in git,
# so a fresh clone always had them and the not-built guards in these scripts
# never fired. Untracking them makes those guards live for the first time, and
# as written they were unsafe:
#
#     if [ ! -x "$bin" ]; then echo "SKIP: ..."; exit 0; fi
#
# That exits 0. A developer who runs `bash CliTest/test_aead.sh` before
# `./build_c.sh` gets a SKIP line and a success status from a script that
# asserted nothing — a green result with no coverage behind it. CI never saw
# this because every job builds first, so it would have been a silent *local*
# regression.
#
# The policy here has two halves.
#
#   1. A run that asserts nothing must never exit 0. Skipping is fine when a
#      script compares several languages and one is unavailable; skipping
#      *everything* is not a pass, it is a run that did not happen.
#   2. Distinguish "you forgot to build" from "you cannot build". If gcc is
#      installed and herradura_cli is missing, that is an omission and the
#      script says so and fails. If gcc is absent the skip is legitimate — the
#      test genuinely cannot run here — but it still does not count as a pass.
#
# Set HKX_ALLOW_SKIP=1 to downgrade the all-skipped exit to 0, for environments
# that deliberately test only one language. It is opt-in on purpose: the default
# has to be the safe one, because the failure mode being prevented is a green
# checkmark that means nothing.
#
# Usage — an all-or-nothing script (needs both compiled CLIs):
#
#     . "$(dirname "$0")/lib_build.sh"
#     hkx_require_built c go
#
# Usage — a script that compares whichever languages are present:
#
#     . "$(dirname "$0")/lib_build.sh"
#     hkx_available c || hkx_note_skip "C CLI" "$(hkx_why c)"
#     ...
#     hkx_require_asserted "$pass" "$fail"

_hkx_root() { (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd); }

# hkx_bin <lang> — path to the compiled CLI for c|go, empty otherwise.
hkx_bin() {
    case "$1" in
        c)  echo "$(_hkx_root)/HerraduraCli/herradura_cli" ;;
        go) echo "$(_hkx_root)/HerraduraCli/herradura_cli_go" ;;
        *)  echo "" ;;
    esac
}

# hkx_toolchain <lang> — the command that would build it.
hkx_toolchain() {
    case "$1" in
        c)    echo gcc ;;
        go)   echo go ;;
        java) echo javac ;;
        *)    echo "" ;;
    esac
}

# hkx_builder <lang> — the script that builds it.
hkx_builder() {
    case "$1" in
        c)    echo ./build_c.sh ;;
        go)   echo ./build_go.sh ;;
        java) echo bash\ bindings/java/build.sh ;;
        *)    echo "" ;;
    esac
}

# hkx_available <lang> — true when the compiled CLI is present and executable.
hkx_available() {
    local b; b="$(hkx_bin "$1")"
    [ -n "$b" ] && [ -x "$b" ]
}

# hkx_why <lang> — one-line reason a language is unavailable, naming the fix.
# Distinguishes a missing build from a missing toolchain (see policy above).
hkx_why() {
    local lang="$1" tool builder
    tool="$(hkx_toolchain "$lang")"
    builder="$(hkx_builder "$lang")"
    if command -v "$tool" >/dev/null 2>&1; then
        echo "not built — $tool is installed, run $builder"
    else
        echo "not built and $tool is not installed"
    fi
}

# hkx_note_skip <name> <reason> — uniform, greppable skip line.
hkx_note_skip() { echo "SKIP $1 ($2)"; }

# hkx_require_built <lang>... — for scripts that cannot do anything useful
# without every listed CLI. Prints what is missing and why, then exits 2.
# Exit 2 rather than 1 so a human can tell "did not run" from "assertions
# failed"; CI only cares that it is non-zero.
hkx_require_built() {
    local lang missing=()
    for lang in "$@"; do
        hkx_available "$lang" || missing+=("$lang")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0

    echo "SKIP $(basename "$0"): needs the $* CLI(s); missing:" >&2
    for lang in "${missing[@]}"; do
        echo "  $lang — $(hkx_why "$lang")" >&2
    done
    if [ "${HKX_ALLOW_SKIP:-0}" = "1" ]; then
        echo "HKX_ALLOW_SKIP=1 — reporting success for a run that asserted nothing." >&2
        exit 0
    fi
    echo "Nothing was asserted, so this is not a pass." \
         "Build the missing CLI(s), or set HKX_ALLOW_SKIP=1 to override." >&2
    exit 2
}

# hkx_require_asserted <pass> <fail> — for scripts that skip per-language and
# tally as they go. Call before the final exit: a run where every check was
# skipped must not read as a pass.
hkx_require_asserted() {
    local pass="$1" fail="$2"
    [ "$((pass + fail))" -gt 0 ] && return 0
    if [ "${HKX_ALLOW_SKIP:-0}" = "1" ]; then
        echo "HKX_ALLOW_SKIP=1 — every check was skipped; reporting success anyway." >&2
        return 0
    fi
    echo "FAIL $(basename "$0"): every check was skipped — nothing was asserted." >&2
    echo "Build the missing CLI(s), or set HKX_ALLOW_SKIP=1 to override." >&2
    exit 2
}
