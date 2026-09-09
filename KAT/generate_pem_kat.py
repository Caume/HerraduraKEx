#!/usr/bin/env python3
"""TODO #227: fixed wire-format (PEM) Known-Answer-Test artifacts for the CLI layer.

TODO #226 pinned the *suite* layer — ring multiplication, rounding, reconciliation,
hint packing, the KDF.  It did not pin the CLI layer, and that is where every bug
TODO #223 shipped actually lived:

  * `loadKey` (Go) and `_decode_session_key` (Python) read an HKEX-RNL RESPONSE
    PEM's ring-dimension field as the derived key width.
  * C's hybrid response encoder wrote a hardcoded n=256 into that field.
  * Python's and Go's hybrid combiners serialised K1 at the ring dimension.

None of those touch the suite primitives, so #226's vectors are blind to them.
The existing CLI tests were blind too: `test_encrypt.sh` pins `--bits 64`, where
the ring dimension and the key width are the same number, so nothing there could
distinguish the two.

This script emits byte-exact PEM artifacts under `KAT/pem/`.  The point is that
each CLI must **consume** them and reproduce an expected output — consumption is
the direction the bugs broke.  Producing a keypair cannot be pinned this way at
all, because `genpkey` draws its secrets and nonces from os.urandom; here those
are fixed inputs, derived by the same deterministic expansion TODO #226 uses.

Artifacts per ring size:

    <tag>_alice_priv.pem     HKEX-RNL PRIVATE KEY  (s_A, m_blind, n, n_A)
    <tag>_alice_pub.pem      HKEX-RNL PUBLIC KEY   (C_A, m_blind, n, n_A)
    <tag>_bob_priv.pem       HKEX-RNL PRIVATE KEY  (s_B, m_blind, n, n_A)
    <tag>_bob_response.pem   HKEX-RNL RESPONSE     (K_B, C_B, hint, n, len, n_B)
    <tag>_alice_session.pem  HERRADURA SESSION KEY  — what Alice must derive
    <tag>_hske_ct.pem        HSKE ciphertext under the key read from the RESPONSE

And, ring-size-independent (TODO #284) -- HPKE-Stern-KEM, at the deployed
BIKE-128 parameters.  ONE WIDTH ONLY: C compiles for a single QCMDPC_R, so
there is no small-r companion as the ring sizes above have:

    kem_priv.pem             HPKE-STERN-KEM PRIVATE KEY  (sup0, sup1, h0, h1)
    kem_pub.pem              HPKE-STERN-KEM PUBLIC KEY   (h_pub)
    kem_ct.pem               a ciphertext that DECODES, plus message_kem.bin
    kem_reject_ct.pem        a ciphertext this key CANNOT decode, plus
                             message_kem_reject.bin -- the IMPLICIT-REJECTION
                             output, and the reason this set exists

Before TODO #284 there was no pinned Stern-KEM artifact anywhere in KAT/, and
TODO #276 had just rewritten that wire format completely (r 523 -> 12323, so
every field width moved).  Round-trip and interop tests cannot cover it: they
pass as long as the four languages change TOGETHER.  TODO #277 is the precedent
-- C's PRF counter placement disagreed with the other three for the life of the
protocol, and only a vector found it.

kem_reject_ct.pem is the half that earns the set.  Since TODO #235 a decoding
failure is SILENT: the FO transform returns HFSCX-256-DS(0x11, z || C), `dec`
exits 0 and writes a full-width output, and a wrong K is indistinguishable from
a right one.  CliTest/test_stern_kem.sh checks that the CLIs agree with EACH
OTHER on that key, which catches a divergence but not a DRIFT -- all four moving
together is invisible to it by construction.  message_kem_reject.bin pins it to
a FIXED VALUE instead.  The ciphertext is a well-formed encapsulation to a
DIFFERENT key (the same construction #235's own tests use), so it exercises the
rejection path rather than the DER reader.

And, ring-size-independent (TODO #268):

    enc_priv_zero_{ct,tag}.pem  envelopes with a leading 0x00 in the salt, the
                             nonce, and the ciphertext / tag respectively --
                             the case a minimal DER INTEGER cannot carry and
                             two of the four CLIs rejected (TODO #280)
    enc_priv.pem             HERRADURA ENCRYPTED PRIVATE KEY wrapping
                             n1024_alice_priv.pem under the passphrase below

That one pins the passphrase envelope's bytes.  Unlike KAT/hcred_kkw.json it is
regenerate-and-diff checkable rather than verify-only, because the two random
inputs -- the PBKDF2 salt and the AEAD nonce -- are arguments the primitive
accepts, so fixing them fixes the artifact.  What it pins is the whole chain:
PBKDF2-HFSCX-256's iteration convention, the AEAD's ad="" case, and the DER
field widths.  Its expected plaintext is n1024_alice_priv.pem itself, already
pinned above, so a CLI that decrypts it must reproduce a file this directory
already contains -- byte-for-byte.

The last one is the direct regression test for the `loadKey` width bug: a CLI that
reads the RESPONSE PEM's ring dimension as the key width encrypts at the wrong
width and produces a different ciphertext.

Its first run found a second defect the CLI tests were blind to (TODO #228): below
n=256 the four CLIs disagreed about how wide an HKEX-RNL session key even is.  That
is settled — it is 256 bits at every ring dimension, the contributory KDF's output
width — and both ring sizes below are now asserted by `CliTest/test_kat_pem.sh`.

Usage:
    python3 KAT/generate_pem_kat.py            # (re)write KAT/pem/
    python3 KAT/generate_pem_kat.py --check     # verify the checked-in files
"""
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_PEM_DIR = os.path.join(_HERE, "pem")
_CLI_DIR = os.path.join(_ROOT, "HerraduraCli")

sys.path.insert(0, _CLI_DIR)
_cwd = os.getcwd()
os.chdir(_CLI_DIR)          # primitives.py resolves the suite relative to itself
try:
    import herradura as cli
finally:
    os.chdir(_cwd)

suite = cli._suite_mod

# The same deterministic expansion TODO #226 uses, so both KATs describe the same
# handshake and a mismatch between them is itself a signal.
_gen_spec = importlib.util.spec_from_file_location(
    "generate_kat", os.path.join(_HERE, "generate_kat.py"))
_gen = importlib.util.module_from_spec(_gen_spec)
_gen_spec.loader.exec_module(_gen)

RNLQ, RNLP, RNLPP, RNLB = suite.RNLQ, suite.RNLP, suite.RNLPP, suite.RNLB

# Fixed nonces. Real ones come from os.urandom; a KAT supplies them as inputs.
N_A = bytes(range(0x40, 0x60))          # 32 bytes: 40 41 .. 5f
N_B = bytes(range(0xA0, 0xC0))          # 32 bytes: a0 a1 .. bf
MESSAGE = b"HerraduraKEx TODO #227 wire-format KAT message!!"


def build(n: int, tag: str) -> dict:
    """One full handshake, rendered as the PEMs the CLIs exchange."""
    # Two different widths, and TODO #228 was the four CLIs disagreeing about
    # which one the session key uses.  `raw_bits` is how many bits reconciliation
    # can extract from an n-coefficient ring — n below 256, capped at 256 above.
    # `sess_bits` is the width of what the contributory KDF returns, which is an
    # HFSCX-256 digest and therefore 256 at every ring dimension.  They coincide
    # at n >= 256, which is exactly why n=1024 never showed the bug.
    raw_bits = cli._rnl_key_bits(n)
    sess_bits = cli._rnl_session_bits(n)

    m_base = suite._rnl_m_poly(n)
    a_rand = _gen.det_rand_poly(b"HerraduraKEx-TODO226-a_rand-" + tag.encode(), n, RNLQ)
    m_blind = suite._rnl_poly_add(m_base, a_rand, RNLQ)
    s_a = _gen.det_cbd_poly(b"HerraduraKEx-TODO226-alice-s-" + tag.encode(), n, RNLB, RNLQ)
    s_b = _gen.det_cbd_poly(b"HerraduraKEx-TODO226-bob-s-" + tag.encode(), n, RNLB, RNLQ)

    c_a = cli._rnl_derive_C(m_blind, s_a, n)
    c_b = cli._rnl_derive_C(m_blind, s_b, n)

    # Bob's step: reconcile against Alice's C, publish K_B and the hint.
    k_bob, hint = suite._rnl_agree(s_b, c_a, RNLQ, RNLP, RNLPP, n, raw_bits)
    k_bob_int = cli._rnl_contributory_kdf(k_bob.uint, raw_bits, N_A, N_B)
    # `--kdf none` is the default and applies no post-hash, so this is the raw
    # contributory output; a CLI defaulting differently would diverge here.

    # Alice's step: same reconciliation from the other side, same KDF inputs.
    k_alice = suite._rnl_agree(s_a, c_b, RNLQ, RNLP, RNLPP, n, raw_bits, hint)
    k_alice_int = cli._rnl_contributory_kdf(k_alice.uint, raw_bits, N_A, N_B)
    assert k_alice_int == k_bob_int, f"TODO #227: session keys disagree at n={n}"

    # HSKE under the key as read from the RESPONSE PEM — the loadKey width probe.
    key_ba = suite.BitArray(sess_bits, k_bob_int)
    pt_int = int.from_bytes(MESSAGE[: sess_bits // 8].ljust(sess_bits // 8, b"\0"), "big")
    ct = suite.fscx_revolve(suite.BitArray(sess_bits, pt_int), key_ba, sess_bits // 4)

    return {
        f"{tag}_alice_priv.pem": cli._encode_rnl_privkey(s_a, m_blind, n, N_A),
        f"{tag}_alice_pub.pem": cli._encode_rnl_pubkey(c_a, m_blind, n, N_A),
        f"{tag}_bob_priv.pem": cli._encode_rnl_privkey(s_b, m_blind, n, N_A),
        f"{tag}_bob_response.pem": cli._encode_rnl_response(k_bob_int, c_b, hint, n, N_B),
        f"{tag}_alice_session.pem": cli._encode_session_key(k_alice_int, sess_bits),
        f"{tag}_hske_ct.pem": cli._encode_sym_ct("hske", ct.uint, sess_bits),
    }


# TODO #268's envelope.  Salt and nonce are the fixed inputs a KAT supplies in
# place of os.urandom; the iteration count is the demo default, kept low so
# --check stays fast (the count travels in the PEM, so a reader honours it).
ENC_PASSPHRASE = "HerraduraKEx TODO #268 KAT passphrase"
ENC_SALT = bytes(range(0x10, 0x20))            # 16 bytes: 10 11 .. 1f
ENC_NONCE = bytes(range(0x60, 0x80))           # 32 bytes: 60 61 .. 7f
ENC_ITERATIONS = 1000


# TODO #280's leading-zero envelopes.  The four fixed-width fields (salt, nonce,
# ciphertext, tag) travel as DER INTEGERs, and a field whose first byte is 0x00
# encodes one significant byte SHORT of its width -- the writer emits it, and a
# reader that strips a sign byte unconditionally and then asserts an exact width
# rejects it.  That was C and Go for the life of the envelope, on about one key
# in 64.  ENC_SALT and ENC_NONCE above both start with a nonzero byte, so the
# original vector could never have caught it; these two can, and between them
# they put a leading zero in all FOUR fields:
#
#   zero_ct   salt[0] = nonce[0] = ct[0]  = 0x00   -> the plaintext-length branch
#   zero_tag  salt[0] = nonce[0] = tag[0] = 0x00   -> the field-width branch
#
# The salt and nonce are chosen; the two nonce counters are SEARCHED values (the
# first that make the ciphertext's and the tag's leading byte zero) and are
# pinned here so regeneration is deterministic.  They wrap the n64 key rather
# than the n1024 one purely for speed: the search is one AEAD per candidate.
ENC_ZERO_SALT = bytes([0x00]) + bytes(range(0x11, 0x20))   # 16 bytes: 00 11 .. 1f
ENC_ZERO_CT_NONCE = bytes([0x00]) + (39).to_bytes(31, "big")
ENC_ZERO_TAG_NONCE = bytes([0x00]) + (2).to_bytes(31, "big")


def build_envelope(plain_pem: str, salt: bytes = None, nonce_b: bytes = None) -> str:
    """The passphrase envelope over `plain_pem`, with the randomness pinned."""
    salt = ENC_SALT if salt is None else salt
    nonce_b = ENC_NONCE if nonce_b is None else nonce_b
    key_bytes = cli._pbkdf2_hfscx256(
        ENC_PASSPHRASE.encode("utf-8"), salt, ENC_ITERATIONS)
    key = suite.BitArray(suite.KEYBITS, int.from_bytes(key_bytes, "big"))
    nonce = suite.BitArray(suite.KEYBITS, int.from_bytes(nonce_b, "big"))
    pt = plain_pem.encode("utf-8")
    _n, ct, tag = suite.hske_nl_aead_encrypt(key, pt, b"", nonce)
    der = cli.der_seq(
        cli.der_int(int.from_bytes(salt, "big"), len(salt)),
        cli.der_int(ENC_ITERATIONS),
        cli.der_int(nonce.uint, suite.KEYBITS // 8),
        cli.der_int(int.from_bytes(ct, "big"), max(1, len(ct))),
        cli.der_int(int.from_bytes(tag, "big"), 32),
        cli.der_int(len(pt)))
    return cli.pem_wrap(cli._LABEL_ENC_PRIV, der)


# TODO #284's HPKE-Stern-KEM artifacts.  qcmdpc_keygen and qcmdpc_encap both
# take a seed, so the randomness here is an ARGUMENT rather than os.urandom --
# the condition enc_priv.pem satisfies and hcred_kkw.json cannot.  That makes
# this set regenerate-and-diff checkable at the suite layer, so --check is a
# real assertion and not merely a re-render.
KEM_KEY_SEED = 0x5445524E4B454D31    # "TERNKEM1"
KEM_OTHER_SEED = 0x5445524E4B454D32  # "TERNKEM2" -- the key we do NOT hold
KEM_ENC_SEED = 0x454E434150534431    # "ENCAPSD1"
KEM_REJECT_ENC_SEED = 0x454E434150534432
KEM_MESSAGE = b"HerraduraKEx TODO #284 Stern-KEM KAT!!"


def build_kem() -> dict:
    """One decodable encapsulation and one that must be implicitly rejected."""
    kb = suite.KEYBITS // 8
    pt = KEM_MESSAGE[:kb].ljust(kb, b"\0")
    pt_ba = suite.BitArray(suite.KEYBITS, int.from_bytes(pt, "big"))

    sup0, sup1, h0, h1, h_pub = suite.qcmdpc_keygen(KEM_KEY_SEED)
    # A second keypair we do NOT hold, purely to address the rejection case to.
    _o0, _o1, _oh0, _oh1, other_pub = suite.qcmdpc_keygen(KEM_OTHER_SEED)

    # (a) the decodable case.
    syn, k_int = suite.qcmdpc_encap(h_pub, KEM_ENC_SEED)
    k_back = suite.qcmdpc_decap_bgf(syn, sup0, sup1, h0)
    assert k_back == k_int, "TODO #284: the pinned encapsulation does not decode"
    ct = suite.fscx_revolve(pt_ba, suite.BitArray(suite.KEYBITS, k_int),
                            suite.I_VALUE)

    # (b) the implicit-rejection case: a well-formed ciphertext addressed to
    # other_pub, decapsulated with OUR key.  It must not decode, and the key it
    # yields must be the FO transform's pseudorandom one.
    rej_syn, rej_k_sender = suite.qcmdpc_encap(other_pub, KEM_REJECT_ENC_SEED)
    assert suite.qcmdpc_bgf_decode(rej_syn, h0, sup0, sup1) is None or \
        suite.qcmdpc_decap_bgf(rej_syn, sup0, sup1, h0) != rej_k_sender, \
        "TODO #284: the rejection ciphertext decoded under the wrong key"
    rej_k = suite.qcmdpc_decap_bgf(rej_syn, sup0, sup1, h0)
    assert rej_k != rej_k_sender, "TODO #284: rejection case agreed with the sender"
    rej_ct = suite.fscx_revolve(pt_ba, suite.BitArray(suite.KEYBITS, rej_k_sender),
                                suite.I_VALUE)
    # What `dec` must WRITE for it: the inverse revolve under the rejection key.
    # Garbage by construction -- that is the point, and it is pinned garbage.
    rej_out = suite.fscx_revolve(rej_ct, suite.BitArray(suite.KEYBITS, rej_k),
                                 suite.R_VALUE)

    return {
        "kem_priv.pem": cli._encode_kem_privkey(sup0, sup1, h0, h1),
        "kem_pub.pem": cli._encode_kem_pubkey(h_pub),
        "kem_ct.pem": cli._encode_kem_ct(syn, ct.uint),
        "kem_reject_ct.pem": cli._encode_kem_ct(rej_syn, rej_ct.uint),
        "message_kem.bin": pt,
        "message_kem_reject.bin": rej_out.uint.to_bytes(kb, "big"),
    }


def build_all() -> dict:
    out = {}
    out.update(build(suite.RNLN, "n1024"))
    out.update(build(64, "n64"))
    out["enc_priv.pem"] = build_envelope(out["n1024_alice_priv.pem"])
    out["enc_priv_zero_ct.pem"] = build_envelope(
        out["n64_alice_priv.pem"], ENC_ZERO_SALT, ENC_ZERO_CT_NONCE)
    out["enc_priv_zero_tag.pem"] = build_envelope(
        out["n64_alice_priv.pem"], ENC_ZERO_SALT, ENC_ZERO_TAG_NONCE)
    # The plaintext the ciphertext decrypts to, as a file the tests can diff.
    # Both plaintexts are session-key-width, i.e. 256 bits at either ring.
    kb = cli._rnl_session_bits(suite.RNLN) // 8
    out["message_n1024.bin"] = MESSAGE[:kb].ljust(kb, b"\0")
    kb64 = cli._rnl_session_bits(64) // 8
    out["message_n64.bin"] = MESSAGE[:kb64].ljust(kb64, b"\0")
    out.update(build_kem())
    return out


def main() -> int:
    artifacts = build_all()
    check = "--check" in sys.argv
    if not check:
        os.makedirs(_PEM_DIR, exist_ok=True)
    rc = 0
    for name, body in sorted(artifacts.items()):
        path = os.path.join(_PEM_DIR, name)
        data = body if isinstance(body, bytes) else body.encode()
        if check:
            if not os.path.exists(path):
                sys.stderr.write(f"KAT/pem/{name} is missing — rerun "
                                  "python3 KAT/generate_pem_kat.py\n")
                rc = 1
                continue
            with open(path, "rb") as f:
                if f.read() != data:
                    sys.stderr.write(f"KAT/pem/{name} is stale — rerun "
                                      "python3 KAT/generate_pem_kat.py\n")
                    rc = 1
        else:
            with open(path, "wb") as f:
                f.write(data)
    if check:
        if rc == 0:
            print(f"KAT/pem/ is up to date ({len(artifacts)} artifacts).")
        return rc
    print(f"Wrote {len(artifacts)} artifacts to {_PEM_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
