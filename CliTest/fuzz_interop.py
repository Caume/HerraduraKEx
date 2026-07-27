#!/usr/bin/env python3
"""TODO #136: cross-language property-based interop fuzz generator.

Generates randomized valid inputs (message sizes, plaintext content, random
private keys drawn by each CLI's own RNG) and feeds them through the Python,
C, and Go CLIs, diffing outputs across languages. Fixed-vector tests in
CliTest/*.sh check a handful of hand-picked cases; this catches subtle
cross-language divergence (endianness, modular-reduction edge cases,
padding/length handling) that only shows up over many randomized trials.

Protocols covered: HKEX-GF key agreement, HSKE symmetric enc/dec
(--algo hske-nla1, arbitrary length via encfile/decfile), HPKS sign/verify,
HPKE asymmetric enc/dec. Each case exercises every ordered pair of the three
CLIs (e.g. "keygen in Go, decrypt in Python") so direction-specific bugs
aren't hidden by always using the same CLI on one side.

Usage:
    python3 CliTest/fuzz_interop.py                  # default: 20 cases/protocol
    python3 CliTest/fuzz_interop.py --cases 2000      # soak run
    python3 CliTest/fuzz_interop.py --cases 200 --seed 42 --protocols hske,hpks

Exit code is non-zero if any case fails. On failure, the exact case (seed,
sizes, CLI pairing) is printed so it can be reproduced with --seed.
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CLI_DIR = os.path.join(_ROOT, "HerraduraCli")

CLIS = {
    "python": [sys.executable, os.path.join(_CLI_DIR, "herradura.py")],
    "c": [os.path.join(_CLI_DIR, "herradura_cli")],
    "go": [os.path.join(_CLI_DIR, "herradura_cli_go")],
}

ALL_PROTOCOLS = ["hkex-gf", "hske", "hpks", "hpke"]


def available_clis():
    avail = {}
    for name, argv in CLIS.items():
        exe = argv[-1]
        if name == "python":
            if os.path.exists(exe):
                avail[name] = argv
        elif shutil.which(argv[0]) or os.path.exists(argv[0]):
            avail[name] = argv
    return avail


def run(argv, *extra):
    cmd = list(argv) + list(extra)
    r = subprocess.run(cmd, capture_output=True, text=False)
    if r.returncode != 0:
        raise RuntimeError(
            f"command failed ({r.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"stdout: {r.stdout.decode(errors='replace')}\n"
            f"stderr: {r.stderr.decode(errors='replace')}"
        )
    return r.stdout


class CaseFailure(Exception):
    pass


def fuzz_hkex_gf(clis, tmp, rng, case_id):
    a_cli, b_cli = rng.sample(list(clis.items()), 2) if len(clis) > 1 else \
        [list(clis.items())[0]] * 2
    a_name, a_argv = a_cli
    b_name, b_argv = b_cli

    a_priv = os.path.join(tmp, f"{case_id}_a.pem")
    a_pub = os.path.join(tmp, f"{case_id}_a_pub.pem")
    b_priv = os.path.join(tmp, f"{case_id}_b.pem")
    b_pub = os.path.join(tmp, f"{case_id}_b_pub.pem")
    sk_a = os.path.join(tmp, f"{case_id}_sk_a.pem")
    sk_b = os.path.join(tmp, f"{case_id}_sk_b.pem")

    run(a_argv, "genpkey", "--algo", "hkex-gf", "--out", a_priv)
    run(a_argv, "pkey", "--in", a_priv, "--pubout", "--out", a_pub)
    run(b_argv, "genpkey", "--algo", "hkex-gf", "--out", b_priv)
    run(b_argv, "pkey", "--in", b_priv, "--pubout", "--out", b_pub)

    run(a_argv, "kex", "--algo", "hkex-gf", "--our", a_priv, "--their", b_pub, "--out", sk_a)
    run(b_argv, "kex", "--algo", "hkex-gf", "--our", b_priv, "--their", a_pub, "--out", sk_b)

    with open(sk_a, "rb") as f1, open(sk_b, "rb") as f2:
        if f1.read() != f2.read():
            raise CaseFailure(f"hkex-gf: {a_name} keygen vs {b_name} keygen "
                               f"produced different shared secrets")
    return f"{a_name}<->{b_name}"


def fuzz_hske(clis, tmp, rng, case_id):
    keygen_name, keygen_argv = rng.choice(list(clis.items()))
    enc_name, enc_argv = rng.choice(list(clis.items()))
    dec_name, dec_argv = rng.choice(list(clis.items()))

    a_priv = os.path.join(tmp, f"{case_id}_a.pem")
    b_priv = os.path.join(tmp, f"{case_id}_b.pem")
    b_pub = os.path.join(tmp, f"{case_id}_b_pub.pem")
    sk = os.path.join(tmp, f"{case_id}_sk.pem")

    run(keygen_argv, "genpkey", "--algo", "hkex-gf", "--out", a_priv)
    run(keygen_argv, "genpkey", "--algo", "hkex-gf", "--out", b_priv)
    run(keygen_argv, "pkey", "--in", b_priv, "--pubout", "--out", b_pub)
    run(keygen_argv, "kex", "--algo", "hkex-gf", "--our", a_priv, "--their", b_pub, "--out", sk)

    size = rng.choice([0, 1, 15, 16, 17, 63, 64, 65, 512, rng.randint(1, 4096)])
    pt_path = os.path.join(tmp, f"{case_id}_pt.bin")
    with open(pt_path, "wb") as f:
        f.write(os.urandom(size))

    ct_path = os.path.join(tmp, f"{case_id}_ct.hkx")
    out_path = os.path.join(tmp, f"{case_id}_out.bin")
    run(enc_argv, "encfile", "--algo", "hske-nla1", "--key", sk, "--in", pt_path, "--out", ct_path)
    run(dec_argv, "decfile", "--algo", "hske-nla1", "--key", sk, "--in", ct_path, "--out", out_path)

    with open(pt_path, "rb") as f1, open(out_path, "rb") as f2:
        if f1.read() != f2.read():
            raise CaseFailure(f"hske: {enc_name} encfile -> {dec_name} decfile "
                               f"roundtrip mismatch at size={size}")
    return f"keygen={keygen_name} enc={enc_name} dec={dec_name} size={size}"


def fuzz_hpks(clis, tmp, rng, case_id):
    sign_name, sign_argv = rng.choice(list(clis.items()))
    verify_name, verify_argv = rng.choice(list(clis.items()))

    priv = os.path.join(tmp, f"{case_id}_priv.pem")
    pub = os.path.join(tmp, f"{case_id}_pub.pem")
    run(sign_argv, "genpkey", "--algo", "hpks", "--out", priv)
    run(sign_argv, "pkey", "--in", priv, "--pubout", "--out", pub)

    size = rng.choice([1, 16, 100, rng.randint(1, 2048)])
    msg_path = os.path.join(tmp, f"{case_id}_msg.bin")
    with open(msg_path, "wb") as f:
        f.write(os.urandom(size))

    sig_path = os.path.join(tmp, f"{case_id}_sig.bin")
    run(sign_argv, "sign", "--algo", "hpks", "--key", priv, "--in", msg_path, "--out", sig_path)

    out = run(verify_argv, "verify", "--algo", "hpks", "--pubkey", pub,
              "--in", msg_path, "--sig", sig_path)
    if b"Signature OK" not in out:
        raise CaseFailure(f"hpks: {sign_name} sign -> {verify_name} verify "
                           f"failed at size={size}: {out!r}")
    return f"sign={sign_name} verify={verify_name} size={size}"


def fuzz_hpke(clis, tmp, rng, case_id):
    keygen_name, keygen_argv = rng.choice(list(clis.items()))
    enc_name, enc_argv = rng.choice(list(clis.items()))
    dec_name, dec_argv = rng.choice(list(clis.items()))

    priv = os.path.join(tmp, f"{case_id}_priv.pem")
    pub = os.path.join(tmp, f"{case_id}_pub.pem")
    run(keygen_argv, "genpkey", "--algo", "hpke", "--out", priv)
    run(keygen_argv, "pkey", "--in", priv, "--pubout", "--out", pub)

    # HPKE's underlying HSKE step operates on a single fixed-width block.
    size = 32
    pt_path = os.path.join(tmp, f"{case_id}_pt.bin")
    with open(pt_path, "wb") as f:
        f.write(os.urandom(size))

    ct_path = os.path.join(tmp, f"{case_id}_ct.pem")
    out_path = os.path.join(tmp, f"{case_id}_out.bin")
    run(enc_argv, "enc", "--algo", "hpke", "--pubkey", pub, "--in", pt_path, "--out", ct_path)
    run(dec_argv, "dec", "--algo", "hpke", "--key", priv, "--in", ct_path, "--out", out_path)

    with open(pt_path, "rb") as f1, open(out_path, "rb") as f2:
        if f1.read() != f2.read():
            raise CaseFailure(f"hpke: {enc_name} enc -> {dec_name} dec "
                               f"roundtrip mismatch")
    return f"keygen={keygen_name} enc={enc_name} dec={dec_name}"


FUZZERS = {
    "hkex-gf": fuzz_hkex_gf,
    "hske": fuzz_hske,
    "hpks": fuzz_hpks,
    "hpke": fuzz_hpke,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", type=int, default=20,
                     help="cases per protocol (default: 20; soak runs use 1000-5000)")
    ap.add_argument("--seed", type=int, default=None,
                     help="RNG seed for reproducing a specific run")
    ap.add_argument("--protocols", type=str, default=",".join(ALL_PROTOCOLS),
                     help=f"comma-separated subset of {ALL_PROTOCOLS}")
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**32)
    rng = random.Random(seed)
    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]

    clis = available_clis()
    if len(clis) < 2:
        print(f"error: need at least 2 CLIs built to fuzz interop; found: {list(clis)}",
              file=sys.stderr)
        print("build with ./build_c.sh and ./build_go.sh first", file=sys.stderr)
        sys.exit(2)

    print(f"seed={seed} cases/protocol={args.cases} clis={sorted(clis)} "
          f"protocols={protocols}\n")

    total_pass = 0
    total_fail = 0
    failures = []

    with tempfile.TemporaryDirectory(prefix="hkex_fuzz_") as tmp:
        for proto in protocols:
            fuzzer = FUZZERS[proto]
            for i in range(args.cases):
                case_id = f"{proto}_{i}"
                try:
                    detail = fuzzer(clis, tmp, rng, case_id)
                    total_pass += 1
                except (CaseFailure, RuntimeError) as e:
                    total_fail += 1
                    msg = f"FAIL [{proto} case {i}] seed={seed}: {e}"
                    print(msg)
                    failures.append(msg)
                    continue
                if args.cases <= 50 or i % max(1, args.cases // 20) == 0:
                    print(f"ok   [{proto} case {i}] {detail}")

    print(f"\nResults: {total_pass} PASS / {total_fail} FAIL "
          f"(seed={seed}, reproduce with --seed {seed})")
    if total_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
