#!/usr/bin/env python3
"""Randomized CLI-argument fuzzing driver for all three HerraduraCli
implementations (TODO #130, work item 4): malformed flags, truncated/garbage
input files, and oversized values, run against real subcommands.

Not coverage-guided (these are whole-process CLI invocations, not in-process
libFuzzer/hypothesis targets) -- this is closer to a directed AFL-style
"black-box argv fuzzer": generate plausible-but-broken invocations, run them,
and flag anything that dies from a signal (SIGSEGV/SIGABRT/SIGBUS) rather
than exiting cleanly. All three CLIs use a graceful `die()`/`exit(1)` path on
recognized errors, so any signal is a genuine bug, not expected behavior.

The C binary is built with -fsanitize=address,undefined (see
Fuzz/herradura_cli_asan) so memory-safety bugs surface as ASan aborts instead
of silently corrupting memory and returning 0.

Usage: python3 Fuzz/fuzz_cli_args.py [--trials N] [--seconds S]
"""
import argparse
import os
import random
import signal
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CLIS = {
    "c":      [os.path.join(REPO, "Fuzz", "herradura_cli_asan")],
    "go":     [os.path.join(REPO, "HerraduraCli", "herradura_cli_go")],
    "python": [sys.executable, os.path.join(REPO, "HerraduraCli", "herradura.py")],
}

SUBCOMMANDS = ["genpkey", "pkey", "kex", "enc", "dec", "sign", "verify",
               "encfile", "decfile", "dgst", "rand", "fpe", "twk"]
ALGOS = ["hkex-gf", "hkex-rnl", "hpks", "hpks-nl", "hpke", "hpke-nl",
          "hpks-stern", "hpke-stern", "hske", "hske-nla1", "hske-duplex",
          "hfscx-256", "", "not-an-algo", "hkex-gf\x00", "A" * 4096]
FLAGS = ["--algo", "--in", "--out", "--key", "--pubkey", "--sig", "--ad",
         "--kdf", "--digest", "--ring", "--bits", "--aead"]


def random_file_pool(tmpdir, count=12):
    """A mix of garbage, truncated-real, and edge-case byte strings, written
    to files so CLI --in/--key/--pubkey/--sig arguments can point at them."""
    paths = []
    rng = random.Random(42)

    def write(name, data):
        p = os.path.join(tmpdir, name)
        with open(p, "wb") as f:
            f.write(data)
        paths.append(p)

    write("empty", b"")
    write("random_small", bytes(rng.randrange(256) for _ in range(rng.randint(1, 64))))
    write("random_large", bytes(rng.randrange(256) for _ in range(4096)))
    write("null_bytes", b"\x00" * 128)
    write("pem_header_only", b"-----BEGIN TEST-----\n")
    write("pem_no_end", b"-----BEGIN TEST-----\nAAAA\n")
    write("pem_huge_body", b"-----BEGIN TEST-----\n" + b"A" * 100000 + b"\n-----END TEST-----\n")
    write("pem_bad_label_len", b"-----BEGIN " + b"X" * 500 + b"-----\nAAAA\n-----END " + b"X" * 500 + b"-----\n")
    write("text_garbage", "not a pem at all ☃�".encode("utf-8", errors="surrogateescape"))
    write("der_claims_huge_seq", bytes([0x30, 0x82, 0xff, 0xff]) + b"\x00" * 16)
    write("truncated_der_int", bytes([0x30, 0x10, 0x02, 0x82, 0xff, 0xff]))
    write("path_traversal_name", b"ignored")  # content unused; used as a path idea below
    for i in range(max(0, count - len(paths))):
        write(f"extra_{i}", bytes(rng.randrange(256) for _ in range(rng.randint(0, 512))))
    return paths


def build_argv(cli_prefix, tmpdir, files, rng):
    sub = rng.choice(SUBCOMMANDS)
    argv = list(cli_prefix) + [sub]
    nflags = rng.randint(0, 5)
    for _ in range(nflags):
        flag = rng.choice(FLAGS)
        if flag == "--algo":
            argv += [flag, rng.choice(ALGOS)]
        elif flag == "--bits":
            argv += [flag, rng.choice(["256", "0", "-1", "99999999999999999999", "abc"])]
        elif flag == "--aead":
            argv += [flag]
        elif flag in ("--in", "--key", "--pubkey", "--sig"):
            choice = rng.choice(files + [os.path.join(tmpdir, "does_not_exist"),
                                          "/etc/passwd", ""])
            argv += [flag, choice]
        elif flag == "--out":
            argv += [flag, os.path.join(tmpdir, f"out_{rng.randrange(10000)}")]
        else:
            argv += [flag, rng.choice(["", "x" * 64, "\x00", "-1"])]
    return argv


def run_one(argv, timeout=5):
    try:
        proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("timeout", None, b"")
    except FileNotFoundError:
        return ("missing_binary", None, b"")
    except ValueError:
        return ("bad_argv", None, b"")  # e.g. embedded NUL -- not a CLI bug, just an invalid argv
    if proc.returncode < 0:
        return ("signal", -proc.returncode, proc.stderr[-2000:])
    return ("exit", proc.returncode, proc.stderr[-2000:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--seconds", type=float, default=None)
    args = ap.parse_args()

    rng = random.Random(1234)
    crashes = []
    with tempfile.TemporaryDirectory() as tmpdir:
        files = random_file_pool(tmpdir)
        import time
        start = time.time()
        trials = 0
        while True:
            if args.seconds is not None and time.time() - start > args.seconds:
                break
            if args.seconds is None and trials >= args.trials:
                break
            for name, prefix in CLIS.items():
                argv = build_argv(prefix, tmpdir, files, rng)
                kind, code, stderr = run_one(argv)
                trials += 1
                if kind == "signal":
                    sig_name = signal.Signals(code).name if code else "?"
                    crashes.append((name, argv, sig_name, stderr))
                    print(f"CRASH [{name}] signal={sig_name}: {argv}")
                    print(f"  stderr tail: {stderr[-400:]!r}")
                elif kind == "timeout":
                    crashes.append((name, argv, "timeout", b""))
                    print(f"TIMEOUT [{name}]: {argv}")

    print()
    print(f"Ran {trials} trials across {len(CLIS)} CLIs.")
    if crashes:
        print(f"{len(crashes)} CRASH(ES)/TIMEOUT(S) FOUND")
        return 1
    print("NO CRASHES FOUND")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
