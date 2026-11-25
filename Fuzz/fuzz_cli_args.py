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
import json
import os
import re
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
         "--kdf", "--digest", "--ring", "--bits", "--aead",
         # TODO #367: the slots that take a PEER's artifact, which is where a
         # "valid DER, wrong arity" file panicked the Go CLI.
         "--our", "--their", "--our-kem", "--their-kem"]
FILE_FLAGS = ("--in", "--key", "--pubkey", "--sig", "--our", "--their",
              "--our-kem", "--their-kem")

# A process that exits with a code but printed one of these crashed all the
# same: a Go panic exits 2 with a goroutine dump, an uncaught Python exception
# exits 1 with a traceback.  Matching only signals missed both (TODO #367).
CRASH_RE = re.compile(rb"^panic: |^goroutine \d+ \[|Traceback \(most recent call last\)"
                      rb"|fatal error: |runtime: out of memory|AddressSanitizer", re.M)


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
    # TODO #367: structurally valid PEM/DER with the wrong number of items, for
    # every DER-SEQUENCE label the spec lists -- the shape that reached unchecked
    # indexing in the Go and Python decoders.  0, min-1 and max+1 small INTEGERs.
    sys.path.insert(0, os.path.join(REPO, "HerraduraCli"))
    from codec import der_int, der_seq, pem_wrap
    spec = json.load(open(os.path.join(REPO, "spec", "herradura-protocol-spec.json")))
    for row in spec["pem_der_items"]:
        for k in sorted({0, row["min"] - 1, row["max"] + 1} - {-1}):
            body = der_seq(*[der_int(v) for v in ([256, 7, 1 << 31, 0, 1] * 4)[:k]])
            tag = row["label"].replace("HERRADURA ", "").replace(" ", "_").lower()
            write(f"arity_{tag}_{k}", pem_wrap(row["label"], body).encode())
    for i in range(max(0, count - len(paths))):
        write(f"extra_{i}", bytes(rng.randrange(256) for _ in range(rng.randint(0, 512))))
    return paths


# TODO #367: a well-formed invocation whose artifact slots all point at
# wrong-arity files.  Purely random argv almost never names a subcommand, a
# valid --algo and the flags that algo reads all at once, so it never reached
# the decoders where the Go panics were (a 2-minute run against the pre-fix
# build found none); this mode does, within seconds.
STRUCTURED = [
    ("kex", ["hkex-gf", "hkex-rnl", "hybrid-rnl-stern"], ["--our", "--their", "--our-kem", "--their-kem"]),
    ("enc", ["hpke", "hpke-nl", "hpke-nl3", "hpke-stern-kem", "hske", "hske-nla1"], ["--pubkey", "--key"]),
    ("dec", ["hpke", "hpke-nl", "hpke-nl3", "hpke-stern-kem", "hske", "hske-nla1", "hske-duplex"], ["--key", "--in"]),
    ("sign", ["hpks", "hpks-nl", "hpks-stern", "rnl-sigma", "hpks-xmss", "hpks-wots"], ["--key"]),
    ("verify", ["hpks", "hpks-nl", "hpks-stern", "rnl-sigma", "hpks-xmss", "hpks-wots"], ["--pubkey", "--sig"]),
    ("pkey", [""], ["--in"]),
]


def build_structured_argv(cli_prefix, tmpdir, files, rng):
    sub, algos, slots = rng.choice(STRUCTURED)
    arity = [f for f in files if os.path.basename(f).startswith("arity_")]
    argv = list(cli_prefix) + [sub]
    algo = rng.choice(algos)
    if algo:
        argv += ["--algo", algo]
    for flag in slots:
        argv += [flag, rng.choice(arity)]
    if sub in ("enc", "sign", "verify"):
        argv += ["--in", files[0]]       # the empty file: a valid message
    if sub == "verify":
        argv += ["--min-rounds", "1"]
    argv += ["--out", os.path.join(tmpdir, f"out_{rng.randrange(10000)}")]
    return argv


def build_argv(cli_prefix, tmpdir, files, rng):
    if rng.random() < 1 / 3:
        return build_structured_argv(cli_prefix, tmpdir, files, rng)
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
        elif flag in FILE_FLAGS:
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
    if CRASH_RE.search(proc.stderr):
        return ("crash_output", proc.returncode, proc.stderr[-2000:])
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
                elif kind == "crash_output":
                    crashes.append((name, argv, f"exit {code}", stderr))
                    print(f"CRASH [{name}] exit={code} with a crash trace: {argv}")
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
