#!/usr/bin/env python3
"""Hypothesis-based fuzz tests for HerraduraCli/codec.py (TODO #130).

atheris (the more typical Python fuzzing library, wrapping libFuzzer) has no
prebuilt wheel and no working build path for this project's Python version on
this host; hypothesis is pure-Python, well-maintained, and already packaged
for arm64 (python3-hypothesis), so it's used instead. It isn't coverage-guided
like atheris/libFuzzer, but property-based random generation over the same
input space still exercises the malformed/adversarial cases this TODO cares
about (truncated lengths, bad tags, garbage base64, non-UTF8-ish text).

The property under test throughout: parsing arbitrary bytes/text must never
raise anything other than ValueError (or return successfully) -- an
uncaught IndexError, TypeError, etc. indicates a missing bounds/type check.

Usage: python3 Fuzz/fuzz_codec_py.py
       (or: cd Fuzz && python3 -m pytest fuzz_codec_py.py -q, if pytest is available)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "HerraduraCli"))

from hypothesis import given, settings, strategies as st, HealthCheck
import codec


@given(st.binary(min_size=0, max_size=256))
@settings(max_examples=20000, suppress_health_check=[HealthCheck.too_slow])
def fuzz_der_parse_seq(data: bytes):
    try:
        codec.der_parse_seq(data)
    except ValueError:
        pass  # expected outcome for malformed input


@given(st.text(min_size=0, max_size=512))
@settings(max_examples=20000, suppress_health_check=[HealthCheck.too_slow])
def fuzz_pem_unwrap(text: str):
    try:
        codec.pem_unwrap(text)
    except ValueError:
        pass


# Structured strategy biased toward PEM-shaped strings, to reach the base64
# decode path more often than fully random text would.
_pem_like = st.builds(
    lambda label, body, malform: (
        f"-----BEGIN {label}-----\n{body}\n-----END {label if not malform else label + 'X'}-----\n"
    ),
    label=st.text(alphabet=st.characters(whitelist_categories=("Lu", "Nd"), max_codepoint=0x7A), min_size=0, max_size=40),
    body=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n", max_size=256),
    malform=st.booleans(),
)


@given(_pem_like)
@settings(max_examples=20000, suppress_health_check=[HealthCheck.too_slow])
def fuzz_pem_unwrap_structured(text: str):
    try:
        codec.pem_unwrap(text)
    except ValueError:
        pass


def main():
    print("Fuzzing codec.der_parse_seq (random bytes)...")
    fuzz_der_parse_seq()
    print("Fuzzing codec.pem_unwrap (random text)...")
    fuzz_pem_unwrap()
    print("Fuzzing codec.pem_unwrap (PEM-shaped text)...")
    fuzz_pem_unwrap_structured()
    print("ALL FUZZ RUNS PASSED (no uncaught non-ValueError exceptions)")


if __name__ == "__main__":
    main()
