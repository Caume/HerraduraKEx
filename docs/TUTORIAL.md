# Herradura Cryptographic Suite — Integration Tutorial

This guide shows how to use the Herradura suite as a library in your own C, Go, or Python project.

The suite implements four protocol families plus a hash primitive:

| Protocol | Classical | NL/PQC variant | Code-based PQC |
|----------|-----------|----------------|----------------|
| Key exchange | HKEX-GF | HKEX-RNL (Ring-LWR) | — |
| Symmetric encryption | HSKE | HSKE-NL-A1, HSKE-NL-A2 | — |
| Schnorr signature | HPKS | HPKS-NL | HPKS-Stern-F |
| El Gamal encryption | HPKE | HPKE-NL | HPKE-Stern-F |
| Hash / MAC | — | HFSCX-256 | — |
| OPRF | — | 2HashDH over GF(2^256) | — |
| aPAKE | — | HKEX-RNL + ZKBoo + OPRF | — |

**Security note:** The classical protocols (HKEX-GF, HSKE, HPKS, HPKE) are vulnerable to quantum
attacks. Use the NL/PQC or code-based variants for new deployments. See [Security notes](#security-notes).

**Background reading:** If you are new to the cryptographic concepts used here (finite fields,
Diffie-Hellman, lattices, zero-knowledge proofs, etc.), read
[docs/INTRODUCTION.md](INTRODUCTION.md) first — it covers every prerequisite in plain language
with toy examples and verified references.

---

## Contents

1. [CLI quickstart](#cli-quickstart)
2. [C integration](#c-integration)
3. [Go integration](#go-integration)
4. [Python integration](#python-integration)
5. [ZKP Protocols](#zkp-protocols)
6. [OPRF and aPAKE](#oprf-and-apake)
7. [Protocol reference](#protocol-reference)
8. [Parameter reference](#parameter-reference)
9. [Security notes](#security-notes)

---

## CLI quickstart

The three CLIs (`herradura.py`, `herradura_cli`, `herradura_cli_go`) share identical
subcommands and PEM wire formats.  PEM files produced by one implementation are
byte-for-byte compatible with all others.  The Python CLI requires no build step and
is the easiest starting point.

```bash
CLI="python3 HerraduraCli/herradura.py"
# C CLI:  ./HerraduraCli/herradura_cli
# Go CLI: ./HerraduraCli/herradura_cli_go
```

### Key generation and inspection

```bash
# Generate a private key (hkex-gf, hpks, hpke, hkex-rnl, hpks-stern, …)
$CLI genpkey --algo hkex-gf --out alice.pem
$CLI genpkey --algo hkex-gf --out bob.pem

# Extract the public key
$CLI pkey --in alice.pem --pubout --out alice_pub.pem

# Print key parameters in human-readable form
$CLI pkey --in alice.pem --text
```

### Key exchange (HKEX-GF)

```bash
$CLI kex --algo hkex-gf --our alice.pem --their bob_pub.pem   --out alice_sk.pem
$CLI kex --algo hkex-gf --our bob.pem   --their alice_pub.pem --out bob_sk.pem
# alice_sk.pem and bob_sk.pem contain the same 256-bit session key.
```

### Symmetric encryption / decryption (HSKE)

```bash
echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" > msg.bin   # 32-byte (256-bit) message

$CLI enc --algo hske --key alice_sk.pem --in msg.bin       --out ct.pem
$CLI dec --algo hske --key alice_sk.pem --in ct.pem        --out recovered.bin
# cmp msg.bin recovered.bin  →  identical
```

Use `--algo hske-nla1` or `--algo hske-nla2` for the unauthenticated NL/PQC modes.

### Authenticated encryption (HSKE-NL-AEAD)

Add `--aead` to any `hske-nla1` enc/dec command.  The `--ad` flag supplies
associated data (authenticated but not encrypted).

```bash
# Encrypt with AEAD (nonce embedded in ct.pem alongside ciphertext and tag)
$CLI enc --algo hske-nla1 --aead --ad "header-v1" \
         --key alice_sk.pem --in msg.bin --out ct_aead.pem

# Decrypt (--ad must match exactly; fails if ct, tag, or AD is tampered with)
$CLI dec --algo hske-nla1 --ad "header-v1" \
         --key alice_sk.pem --in ct_aead.pem --out recovered.bin
# cmp msg.bin recovered.bin  →  identical
```

The C and Go CLIs accept the same `--aead` and `--ad` flags.  AEAD PEMs are
cross-language compatible — see `CliTest/test_aead.sh` for a 9-way interop test.

`hske-nla1 --aead` operates on a single 32-byte block.  For **arbitrary-length**
single-pass authenticated encryption, use the `hske-duplex` algorithm (a
MonkeyDuplex sponge AEAD over `nl_fscx_revolve_v2`):

```bash
# Encrypt arbitrary-length input; nonce, ciphertext, and 32-byte tag in ct.pem
$CLI enc --algo hske-duplex --ad "header-v1" \
         --key alice_sk.pem --in large_msg.bin --out ct_duplex.pem

# Decrypt (--ad must match; fails on any ciphertext / tag / AD tampering)
$CLI dec --algo hske-duplex --ad "header-v1" \
         --key alice_sk.pem --in ct_duplex.pem --out recovered.bin
```

`hske-duplex` requires a 256-bit key and is supported identically by the
Python, C, and Go CLIs — see `CliTest/test_duplex.sh` for the 9-way interop
matrix (plus empty-plaintext and tamper-rejection cases).

### Signing and verification (HPKS)

```bash
$CLI genpkey --algo hpks --out sign_key.pem
$CLI pkey    --in sign_key.pem --pubout --out sign_pub.pem

$CLI sign   --algo hpks --key sign_key.pem --in msg.bin --out sig.pem
$CLI verify --algo hpks --pubkey sign_pub.pem --in msg.bin --sig sig.pem
# Prints: Signature OK
```

### El Gamal encryption (HPKE)

```bash
$CLI genpkey --algo hpke --out enc_key.pem
$CLI pkey    --in enc_key.pem --pubout --out enc_pub.pem

$CLI enc --algo hpke --key enc_pub.pem  --in msg.bin --out ct.pem
$CLI dec --algo hpke --key enc_key.pem  --in ct.pem  --out recovered.bin
```

### Key exchange (HKEX-RNL, PQC, two rounds)

HKEX-RNL requires two steps: Bob responds first, then Alice completes.

```bash
$CLI genpkey --algo hkex-rnl --out alice_rnl.pem
$CLI pkey    --in alice_rnl.pem --pubout --out alice_rnl_pub.pem
$CLI genpkey --algo hkex-rnl --out bob_rnl.pem

# Round 1 — Bob sees Alice's public key and produces a RESPONSE PEM
$CLI kex --algo hkex-rnl --our bob_rnl.pem --their alice_rnl_pub.pem \
         --out bob_resp.pem

# Round 2 — Alice sees Bob's response and derives the session key
$CLI kex --algo hkex-rnl --our alice_rnl.pem --their bob_resp.pem \
         --out alice_sk_rnl.pem
# Both bob_resp.pem and alice_sk_rnl.pem hold the same session key.
```

See `CliTest/` for full integration test scripts covering all algorithms
and cross-language interoperability.

---

## C integration

`herradura.h` is a **header-only library** — every function is `static inline`.
Copy `herradura.h` into your project (or keep it in the repo and use `-I`) then:

```c
#include "herradura.h"
```

No additional source files, no link flags, no build system changes.

On embedded targets without `/dev/urandom`, seed `HDrbg` from any available
hardware entropy source (ADC noise, TRNG peripheral, etc.) and use
`drbg_generate` in place of `fopen("/dev/urandom", "rb")` throughout.

### Build

```bash
gcc -O2 myapp.c -o myapp
# or, pointing at the repo:
gcc -O2 -I/path/to/HerraduraKEx myapp.c -o myapp
```

### HKEX-GF key exchange (classical)

```c
#include "herradura.h"
#include <stdio.h>

int main(void) {
    FILE *urnd = fopen("/dev/urandom", "rb");

    BitArray alice_priv, alice_pub;
    BitArray bob_priv,   bob_pub;
    BitArray alice_shared, bob_shared;

    ba_rand(&alice_priv, urnd);
    ba_rand(&bob_priv,   urnd);

    hkex_gf_pubkey(&alice_priv, &alice_pub);   /* publish alice_pub */
    hkex_gf_pubkey(&bob_priv,   &bob_pub);     /* publish bob_pub   */

    hkex_gf_agree(&alice_priv, &bob_pub,   &alice_shared);
    hkex_gf_agree(&bob_priv,   &alice_pub, &bob_shared);
    /* alice_shared == bob_shared */

    fclose(urnd);
}
```

### HSKE symmetric encryption (classical)

```c
BitArray plaintext, key, ciphertext, recovered;

ba_rand(&plaintext, urnd);
/* key = alice_shared from HKEX-GF above */

hske_encrypt(&plaintext,  &key, &ciphertext);
hske_decrypt(&ciphertext, &key, &recovered);
/* ba_equal(&plaintext, &recovered) == 1 */
```

### HPKS Schnorr signature (classical)

```c
BitArray msg, R, s;
ba_rand(&msg, urnd);

hpks_sign(&msg, &alice_priv, &R, &s, urnd);    /* sign   */
int ok = hpks_verify(&msg, &alice_pub, &R, &s); /* verify */
```

### HPKE El Gamal encryption (classical)

```c
BitArray plaintext, R_ephem, ciphertext, recovered;
ba_rand(&plaintext, urnd);

hpke_encrypt(&plaintext,  &alice_pub,  &R_ephem, &ciphertext, urnd);
hpke_decrypt(&ciphertext, &R_ephem, &alice_priv, &recovered);
```

### HPKS-NL Schnorr signature (NL/PQC)

Same key type as HPKS.  The only difference is the challenge hash: NL-FSCX v1
replaces the linear FSCX revolve, hardening the challenge against preimage attacks.
The public key is still a GF(2^256)* element; DLP protection is unchanged.

```c
BitArray msg_nl, k_nl, R_nl, e_nl, s_nl;
ba_rand(&msg_nl, urnd);
ba_rand(&k_nl,   urnd);                              /* per-signature nonce */

gf_pow_ba(&R_nl, &GF_GEN, &k_nl);                   /* R = g^k             */
nl_fscx_revolve_v1_ba(&e_nl, &R_nl, &msg_nl, I_VALUE); /* NL challenge e   */
ba_mul_mod_ord(&(BitArray){0}, &alice_priv, &e_nl);  /* ae = a·e            */
BitArray ae_nl, s_nl2;
ba_mul_mod_ord(&ae_nl, &alice_priv, &e_nl);
ba_sub_mod_ord(&s_nl2, &k_nl, &ae_nl);              /* s = k - a·e mod ord */

/* Verify: g^s · C^e == R (same check as HPKS; challenge recomputed with NL) */
BitArray e_v, gs, Ce, lhs;
nl_fscx_revolve_v1_ba(&e_v, &R_nl, &msg_nl, I_VALUE);
gf_pow_ba(&gs, &GF_GEN, &s_nl2);
gf_pow_ba(&Ce, &alice_pub, &e_v);
gf_mul_ba(&lhs, &gs, &Ce);
int ok_nl = ba_equal(&lhs, &R_nl);  /* 1 if valid */

explicit_bzero(&k_nl,  sizeof(k_nl));
explicit_bzero(&ae_nl, sizeof(ae_nl));
```

### HPKE-NL El Gamal encryption (NL/PQC)

Same key type as HPKE.  The symmetric sub-protocol uses NL-FSCX v2 (bijective)
instead of the linear FSCX revolve, hardening the ciphertext against key recovery.

```c
BitArray r_nl, R_nl2, enc_nl, ct_nl, dec_nl, pt_nl;
ba_rand(&r_nl, urnd);

gf_pow_ba(&R_nl2,  &GF_GEN,      &r_nl);    /* ephemeral R = g^r          */
gf_pow_ba(&enc_nl, &alice_pub,   &r_nl);    /* enc key = C^r              */
nl_fscx_revolve_v2_ba(&ct_nl, &plaintext, &enc_nl, I_VALUE);  /* encrypt  */

gf_pow_ba(&dec_nl, &R_nl2, &alice_priv);    /* dec key = R^a              */
nl_fscx_revolve_v2_inv_ba(&pt_nl, &ct_nl, &dec_nl, I_VALUE);  /* decrypt  */
/* ba_equal(&pt_nl, &plaintext) == 1 */
/* Transmit R_nl2 alongside ct_nl; Alice decrypts with her private key. */

explicit_bzero(&r_nl,   sizeof(r_nl));
explicit_bzero(&enc_nl, sizeof(enc_nl));
explicit_bzero(&dec_nl, sizeof(dec_nl));
```

### HSKE-NL-A1 counter-mode encryption (NL/PQC)

Counter-mode stream cipher based on NL-FSCX v1.  A fresh random nonce must be
transmitted alongside the ciphertext so the recipient can reproduce the keystream.

```c
BitArray key;       /* 256-bit key (e.g. from HKEX-GF or HKEX-RNL) */
BitArray plaintext;
BitArray N_a1, base_a1, seed_a1, ks, ciphertext, recovered;

ba_rand(&key, urnd);
ba_rand(&plaintext, urnd);

ba_rand(&N_a1, urnd);                        /* fresh per-session nonce     */
ba_xor(&base_a1, &key, &N_a1);              /* session base = K XOR N      */
ba_rnl_kdf_seed(&seed_a1, &base_a1);         /* seed = ROL(base,n/8) XOR DC */

/* Counter = 0 for first block; XOR counter into base_a1 for subsequent blocks */
nl_fscx_revolve_v1_ba(&ks, &seed_a1, &base_a1, I_VALUE);  /* keystream block 0 */
ba_xor(&ciphertext, &plaintext, &ks);       /* encrypt */
ba_xor(&recovered,  &ciphertext, &ks);      /* decrypt */
/* ba_equal(&plaintext, &recovered) == 1 */

explicit_bzero(&seed_a1, sizeof(seed_a1));
explicit_bzero(&base_a1, sizeof(base_a1));
```

### HSKE-NL-A2 symmetric encryption (NL/PQC)

Bijective revolve-mode encryption based on NL-FSCX v2.  Unlike A1, no nonce is
needed — the same key encrypts and decrypts via a dedicated inverse function.

```c
BitArray key2, plaintext2, ciphertext2, recovered2;

ba_rand(&key2,       urnd);
ba_rand(&plaintext2, urnd);

nl_fscx_revolve_v2_ba    (&ciphertext2, &plaintext2, &key2, R_VALUE);  /* encrypt */
nl_fscx_revolve_v2_inv_ba(&recovered2,  &ciphertext2, &key2, R_VALUE); /* decrypt */
/* ba_equal(&plaintext2, &recovered2) == 1 */
```

### HSKE-NL-AEAD authenticated encryption (NL/PQC)

Authenticated encryption with associated data built on HSKE-NL-A1.  A fresh
random 256-bit nonce must be generated for every encryption; the 32-byte tag
authenticates both the ciphertext and the associated data (AD).  Decryption is
verify-then-decrypt and returns 0 if the tag does not match.

```c
#include "herradura.h"
#include <string.h>

BitArray aead_key, aead_nonce;
ba_rand(&aead_key,   urnd);
ba_rand(&aead_nonce, urnd);   /* must never be reused with the same key */

const uint8_t *pt  = (const uint8_t *)"hello AEAD";
size_t         pt_len = 10;
const uint8_t *ad  = (const uint8_t *)"header-v1";
size_t         ad_len = 9;

uint8_t ct[10], tag[32], recovered[10];

hske_nl_aead_encrypt(&aead_key, &aead_nonce, ad, ad_len, pt, pt_len, ct, tag);

int ok = hske_nl_aead_decrypt(&aead_key, &aead_nonce,
                               ad, ad_len, ct, pt_len, tag, recovered);
/* ok == 1 and memcmp(pt, recovered, pt_len) == 0 */
/* ok == 0 if ct, tag, ad, or nonce is tampered with */
```

### HKEX-RNL key exchange (Ring-LWR, PQC)

```c
#include "herradura.h"

/* Both parties agree on a shared public polynomial m_blind. */
rnl_poly_t m_poly, a_poly, m_blind;
rnl_m_poly(m_poly);
rnl_rand_poly(a_poly, urnd);
for (int i = 0; i < RNL_N; i++)
    m_blind[i] = (m_poly[i] + a_poly[i]) % RNL_Q;

/* Each party generates a secret and public polynomial. */
int32_t sA[RNL_N], CA[RNL_N];
int32_t sB[RNL_N], CB[RNL_N];
rnl_keygen(sA, CA, m_blind, urnd);
rnl_keygen(sB, CB, m_blind, urnd);

/* Key agreement with Peikert reconciliation. */
uint8_t  hintA[RNL_N / 8];
BitArray kA, kB;
rnl_agree(&kA, sA, CB, hintA, NULL);  /* Alice sends hintA to Bob */
rnl_agree(&kB, sB, CA, NULL, hintA);  /* Bob uses Alice's hint   */
/* kA == kB (raw key bits) */

/* KDF: ROL(K, n/8) breaks step-1 degeneracy; NL-FSCX-v1 finalizes. */
BitArray seed, sk;
ba_rol_k(&seed, &kA, KEYBITS / 8);
nl_fscx_revolve_v1_ba(&sk, &seed, &kA, I_VALUE);
```

### HPKS-Stern-F signature (code-based PQC)

```c
#include "herradura.h"

BitArray seed, e;
uint8_t  syndr[SDF_SYNBYTES];

stern_f_keygen(&seed, &e, syndr, urnd);  /* keygen: (seed, e) private; syndr public */

SternSig sig;
BitArray msg;
ba_rand(&msg, urnd);
hpks_stern_f_sign(&sig, &msg, &e, &seed, urnd);           /* sign   */
int ok = hpks_stern_f_verify(&sig, &msg, &seed, syndr);   /* verify */
```

### HPKE-Stern-F KEM (code-based PQC, demo)

Niederreiter KEM: the ciphertext is a syndrome `H·e'^T`; the session key is
`hash(seed, e')`.  Decapsulation requires recovering `e'` from the syndrome —
this is the syndrome decoding problem.  The demo uses `hpke_stern_f_decap_known`
which takes the plaintext error vector directly; **production requires a
QC-MDPC or similar decoder** to recover `e'` from the syndrome.

```c
#include "herradura.h"

/* Keygen: same as HPKS-Stern-F — seed is private, syndrome is public. */
BitArray seed2, e2;
uint8_t  syndr2[SDF_SYNBYTES];
stern_f_keygen(&seed2, &e2, syndr2, urnd);

/* Encapsulate: generate fresh error e', compute ct = H·e'^T, derive K. */
BitArray K_enc, e_prime;
uint8_t  ct[SDF_SYNBYTES];
hpke_stern_f_encap(&K_enc, ct, &e_prime, &seed2, urnd);
/* Send ct to the recipient; keep e_prime secret (demo only). */

/* Decapsulate (demo — known e'): re-derive K from seed and e'. */
BitArray K_dec;
hpke_stern_f_decap_known(&K_dec, &e_prime, &seed2);
/* ba_equal(&K_enc, &K_dec) == 1 */
/* Production: recover e_prime from ct using a QC-MDPC decoder first. */
```

### HPKS-WOTS-F / HPKS-XMSS-F (hash-based stateful signatures)

> **Statefulness warning:** A WOTS-F leaf key must **never** be reused.  Sign
> only one message per leaf index.  XMSS-F is the recommended multi-signature
> variant — it tracks the Merkle tree so each signing call advances the leaf
> counter automatically.

**WOTS-F** (one-time, single leaf):

```c
#include "herradura.h"

/* Keygen: master_seed is the long-term secret; leaf_idx=0 for a one-time key. */
uint8_t master_seed[KEYBYTES];
ba_rand_bytes(master_seed, KEYBYTES, urnd);

BitArray sk[WOTS_L], pk[WOTS_L];
hpks_wots_keygen(sk, pk, master_seed, /*leaf_idx=*/0);

const uint8_t msg[] = "hello world";
BitArray sig[WOTS_L];
hpks_wots_sign(sig, msg, sizeof msg - 1, master_seed, /*leaf_idx=*/0);

int ok = hpks_wots_verify(msg, sizeof msg - 1, sig, pk);   /* 1 = valid */
/* Do NOT reuse leaf_idx=0 — use a fresh leaf_idx for every message. */
```

**XMSS-F** (multi-signature, Merkle tree):

```c
/* Keygen: h=4 builds a tree with 2^4=16 leaves (16 one-time slots). */
uint8_t root[KEYBYTES];
uint8_t *flat_leaves;
size_t   num_leaves;
hpks_xmss_keygen(root, &flat_leaves, &num_leaves, master_seed, /*h=*/4);

/* Sign at leaf_idx=0, then 1, 2, … (never repeat an index). */
HpksXmssSig sig0;
hpks_xmss_sign(&sig0, msg, sizeof msg - 1, master_seed,
                flat_leaves, num_leaves, /*leaf_idx=*/0);

int ok2 = hpks_xmss_verify(msg, sizeof msg - 1, &sig0, root); /* 1 = valid */
hpks_xmss_sig_free(&sig0);   /* frees auth_path */
free(flat_leaves);
```

### HFSCX-256 hash and MAC

Merkle-Damgård hash built on NL-FSCX v1; returns 32 bytes.  Pass `iv = NULL`
for a bare digest; pass `iv = key XOR _HFSCX256_IV` for a keyed MAC.

```c
#include <string.h>

const uint8_t msg[] = "hello";
uint8_t digest[KEYBYTES];

/* Bare hash */
hfscx_256(msg, sizeof msg - 1, NULL, digest);

/* Keyed MAC: iv = key XOR _HFSCX256_IV */
uint8_t mac_iv[KEYBYTES];
for (int i = 0; i < KEYBYTES; i++)
    mac_iv[i] = alice_shared.b[i] ^ _HFSCX256_IV[i];
hfscx_256(msg, sizeof msg - 1, mac_iv, digest);
```

### HDRBG (forward-secure DRBG)

Fast-key-erasure DRBG built on NL-FSCX v1.  Suitable for constrained targets
where `/dev/urandom` is unavailable, or for deterministic test vectors.
Seed from a full-entropy source (≥ 32 bytes recommended); reseed after at most
`DRBG_MAX_BLOCKS` (2^20) output blocks.

```c
#include "herradura.h"

HDrbg drbg;

/* Seed from OS entropy (or any full-entropy source). */
uint8_t seed_bytes[32];
FILE *urnd2 = fopen("/dev/urandom", "rb");
fread(seed_bytes, 1, sizeof seed_bytes, urnd2);
fclose(urnd2);

drbg_seed(&drbg,
          seed_bytes, sizeof seed_bytes,  /* entropy */
          NULL, 0);                        /* personalization (optional) */

/* Generate output. */
uint8_t out[64];
int ok = drbg_generate(&drbg, out, sizeof out);   /* 1 on success */
/* ok == 0 means DRBG_MAX_BLOCKS reached — call drbg_reseed first. */

/* Reseed with fresh entropy to forward-securely advance the state. */
uint8_t fresh[32];
/* ... fill fresh from entropy source ... */
drbg_reseed(&drbg, fresh, sizeof fresh);

explicit_bzero(seed_bytes, sizeof seed_bytes);
explicit_bzero(fresh, sizeof fresh);
```

### OPRF (2HashDH oblivious PRF)

The OPRF protocol lets a client evaluate `F(k, x) = gf_pow(H(x), k)` without
revealing `x` to the server or `k` to the client.

```c
#include "herradura.h"

FILE *urnd = fopen("/dev/urandom", "rb");
BitArray oprf_k, oprf_r, oprf_alpha, oprf_beta, oprf_F, oprf_check;

/* Key generation (server side) */
oprf_keygen(&oprf_k, urnd);

/* Blinding (client side) */
const char *input = "my-password";
oprf_blind((const uint8_t *)input, strlen(input), &oprf_r, &oprf_alpha, urnd);

/* Evaluation (server side) */
oprf_eval(&oprf_beta, &oprf_alpha, &oprf_k);

/* Unblinding (client side): yields F(k, input) */
oprf_unblind(&oprf_F, &oprf_beta, &oprf_r);

/* Direct evaluation (server, no blinding) — result matches */
oprf_direct(&oprf_check, (const uint8_t *)input, strlen(input), &oprf_k);
/* memcmp(oprf_F.b, oprf_check.b, KEYBYTES) == 0 */
```

`oprf_blind` retries internally until the random blinding factor `r` is coprime
to ORD = 2^256−1 (expected two attempts on average, since ORD has small factors
3, 5, 17, 257, 641).

All OPRF functions are declared in `herradura.h`; the PEM wire format for OPRF
keys is identical across C, Go, and Python CLIs.

### Complete runnable example

See [`docs/examples/c/hello_herradura.c`](examples/c/hello_herradura.c).

---

## Go integration

The library lives in the `herradura/` subdirectory of the repo as `package herradura`
(module path `herradurakex/herradura`).

### Using the library from the same module

The root `go.mod` already declares `module herradurakex`.  Any `.go` file in the
repo can import the package with:

```go
import "herradurakex/herradura"
```

or use a dot-import (all names imported directly into the calling package):

```go
import . "herradurakex/herradura"
```

### Vendoring into your own module

Copy the `herradura/` directory into your project and add or update your `go.mod`:

```
require yourmodule/herradura v0.0.0
replace yourmodule/herradura => ./herradura
```

Then import as `yourmodule/herradura`.

### HKEX-GF key exchange (classical)

```go
import (
    "fmt"
    "math/big"
    . "herradurakex/herradura"
)

func main() {
    const n = 256
    poly := GfPoly[n]
    g    := big.NewInt(GfGen)

    alicePriv := NewRandBitArray(n)
    bobPriv   := NewRandBitArray(n)

    alicePub := NewBitArray(n, GfPow(g, &alicePriv.Val, poly, n))
    bobPub   := NewBitArray(n, GfPow(g, &bobPriv.Val,   poly, n))

    aliceShared := NewBitArray(n, GfPow(&bobPub.Val,   &alicePriv.Val, poly, n))
    bobShared   := NewBitArray(n, GfPow(&alicePub.Val, &bobPriv.Val,   poly, n))
    /* aliceShared.Equal(bobShared) */
}
```

### HSKE symmetric encryption (classical)

```go
const iValue = n / 4
const rValue = 3 * n / 4

plaintext  := NewRandBitArray(n)
ciphertext := FscxRevolve(plaintext,  aliceShared, iValue)
recovered  := FscxRevolve(ciphertext, aliceShared, rValue)
/* plaintext.Equal(recovered) */
```

### HPKS Schnorr signature (classical)

```go
import "math/big"

ord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(n)), big.NewInt(1)) /* 2^n - 1 */

msg := NewRandBitArray(n)
kS  := NewRandBitArray(n)                                         /* per-signature nonce */
RS  := NewBitArray(n, GfPow(g, &kS.Val, poly, n))                /* commitment R = g^k  */
eS  := FscxRevolve(RS, msg, n/4)                                  /* challenge e         */
sS  := new(big.Int).Mod(new(big.Int).Sub(&kS.Val,
           new(big.Int).Mul(&alicePriv.Val, &eS.Val)), ord)       /* response s = k-a·e  */

/* Verify: g^s · C^e == R */
lhs := GfMul(GfPow(g, sS, poly, n), GfPow(&alicePub.Val, &eS.Val, poly, n), poly, n)
ok  := lhs.Cmp(&RS.Val) == 0
```

### HPKE El Gamal encryption (classical)

```go
rHpke  := NewRandBitArray(n)                                         /* ephemeral scalar   */
RHpke  := NewBitArray(n, GfPow(g, &rHpke.Val, poly, n))             /* ephemeral pubkey   */
encKey := NewBitArray(n, GfPow(&alicePub.Val, &rHpke.Val, poly, n)) /* enc key = C^r      */
ct     := FscxRevolve(plaintext, encKey, n/4)                        /* ciphertext         */

decKey := NewBitArray(n, GfPow(&RHpke.Val, &alicePriv.Val, poly, n)) /* dec key = R^a     */
dec    := FscxRevolve(ct, decKey, 3*n/4)                              /* recovered = P      */
/* dec.Equal(plaintext) */
/* Transmit RHpke alongside ct; Alice decrypts with her private key. */
```

### HPKS-NL Schnorr signature (NL/PQC)

Same key type as HPKS.  The challenge hash uses `NlFscxRevolveV1` instead of
`FscxRevolve`, hardening the challenge against preimage attacks.

```go
msgNl := NewRandBitArray(n)
kNl   := NewRandBitArray(n)                                          /* per-signature nonce */

RNl  := NewBitArray(n, GfPow(g, &kNl.Val, poly, n))                 /* R = g^k             */
eNl  := NlFscxRevolveV1(RNl, msgNl, n/4)                            /* NL challenge e      */
sNl  := new(big.Int).Mod(new(big.Int).Sub(&kNl.Val,
            new(big.Int).Mul(&alicePriv.Val, &eNl.Val)), ord)        /* s = k - a·e         */

/* Verify: g^s · C^e == R */
eV  := NlFscxRevolveV1(RNl, msgNl, n/4)
lhs := GfMul(GfPow(g, sNl, poly, n), GfPow(&alicePub.Val, &eV.Val, poly, n), poly, n)
okNl := lhs.Cmp(&RNl.Val) == 0
```

### HPKE-NL El Gamal encryption (NL/PQC)

Same key type as HPKE.  The symmetric sub-protocol uses `NlFscxRevolveV2`
(bijective) instead of `FscxRevolve`, hardening ciphertext against key recovery.

```go
rNl    := NewRandBitArray(n)
RNl2   := NewBitArray(n, GfPow(g, &rNl.Val, poly, n))               /* ephemeral R = g^r  */
encNl  := NewBitArray(n, GfPow(&alicePub.Val, &rNl.Val, poly, n))   /* enc key = C^r      */
ctNl   := NlFscxRevolveV2(plaintext, encNl, n/4)                     /* encrypt            */

decNl  := NewBitArray(n, GfPow(&RNl2.Val, &alicePriv.Val, poly, n)) /* dec key = R^a      */
ptNl   := NlFscxRevolveV2Inv(ctNl, decNl, n/4)                      /* decrypt            */
/* ptNl.Equal(plaintext) */
/* Transmit RNl2 alongside ctNl; Alice decrypts with her private key. */
```

### HSKE-NL-A1 counter-mode encryption (NL/PQC)

```go
key       := NewRandBitArray(n)
plaintext := NewRandBitArray(n)

nA1    := NewRandBitArray(n)
baseA1 := NewBitArray(n, new(big.Int).Xor(&key.Val, &nA1.Val))
bA1    := NewBitArray(n, new(big.Int).Xor(&baseA1.Val, big.NewInt(0))) /* counter = 0 */
ks     := NlFscxRevolveV1(RnlKdfSeed(baseA1), bA1, n/4)
ct     := NewBitArray(n, new(big.Int).Xor(&plaintext.Val, &ks.Val))
dec    := NewBitArray(n, new(big.Int).Xor(&ct.Val, &ks.Val))
/* dec.Equal(plaintext) */
/* Transmit nA1 alongside ct so the recipient can reproduce the keystream. */
```

### HSKE-NL-A2 symmetric encryption (NL/PQC)

Bijective revolve-mode encryption based on NL-FSCX v2.  Unlike A1, no nonce is
needed — the same key encrypts and decrypts via a dedicated inverse function.

```go
key2       := NewRandBitArray(n)
plaintext2 := NewRandBitArray(n)

ct2  := NlFscxRevolveV2(plaintext2, key2, 3*n/4)    /* encrypt (R_VALUE = 3n/4) */
dec2 := NlFscxRevolveV2Inv(ct2, key2, 3*n/4)        /* decrypt */
/* dec2.Equal(plaintext2) */
```

### HSKE-NL-AEAD authenticated encryption (NL/PQC)

Authenticated encryption with associated data built on HSKE-NL-A1.  Returns
`(ct []byte, tag []byte)` on encrypt; returns `(pt []byte, ok bool)` on decrypt.
Decryption is verify-then-decrypt; `ok` is false if the tag does not match.

```go
import h "herradurakex/herradura"

aeadKey   := h.NewRandBitArray(n)
aeadNonce := h.NewRandBitArray(n)   // must never be reused with the same key

pt := []byte("hello AEAD")
ad := []byte("header-v1")

ct, tag := h.HskeNlAeadEncrypt(aeadKey, aeadNonce, ad, pt)

recovered, ok := h.HskeNlAeadDecrypt(aeadKey, aeadNonce, ad, ct, tag)
// ok == true and bytes.Equal(pt, recovered)
// ok == false if ct, tag, ad, or nonce is tampered with
```

### HKEX-RNL key exchange (Ring-LWR, PQC)

```go
mBase  := RnlMPoly(n)
aRand  := RnlRandPoly(n, RnlQ)
mBlind := RnlPolyAdd(mBase, aRand, RnlQ)

sA, CA := RnlKeygen(mBlind, n, RnlQ, RnlP)
sB, CB := RnlKeygen(mBlind, n, RnlQ, RnlP)

kA, hintA := RnlAgree(sA, CB, RnlQ, RnlP, RnlPP, n, n, nil)
kB, _      := RnlAgree(sB, CA, RnlQ, RnlP, RnlPP, n, n, hintA)
/* kA.Equal(kB) */

// KDF
skA := NlFscxRevolveV1(kA.RotateLeft(n/8), kA, n/4)
```

### HPKS-Stern-F signature (code-based PQC)

```go
seed, e, syn := SternFKeygen(n)
msg := NewRandBitArray(n)
sig := HpksSternFSign(msg, e, seed, SdfRounds)
ok  := HpksSternFVerify(msg, sig, seed, syn)
```

### HPKE-Stern-F KEM (code-based PQC, demo)

Niederreiter KEM: ciphertext is a syndrome; session key is `hash(seed, e')`.
**Production requires a QC-MDPC decoder** to recover `e'` from the syndrome.
`HpkeSternFEncap` also returns `ePrime` for the demo decapsulation path.

```go
// Keygen: same as HPKS-Stern-F
seed2, _, _ := SternFKeygen(n)

// Encapsulate: returns (K, ct, ePrime)
//   K      — session key
//   ct     — syndrome *big.Int (send to recipient)
//   ePrime — plaintext error (keep secret; needed for demo decap)
Kenc, ct2, ePrime := HpkeSternFEncap(seed2, n)

// Decapsulate (demo — known ePrime)
Kdec := HpkeSternFDecapKnown(ePrime, seed2)
// bytes.Equal(Kenc.Bytes(), Kdec.Bytes())
// Production: recover ePrime from ct2 with a QC-MDPC decoder first.
_ = ct2
```

### HPKS-WOTS-F / HPKS-XMSS-F (hash-based stateful signatures)

> **Statefulness warning:** A WOTS-F leaf key must **never** be reused.  Sign
> only one message per leaf index.  XMSS-F is the recommended multi-signature
> variant; advance the leaf counter monotonically across restarts.

```go
import h "herradurakex/herradura"
import "crypto/rand"

masterSeed := make([]byte, 32)
rand.Read(masterSeed)

msg := []byte("hello world")

// --- WOTS-F (one-time) ---
_, pk0 := h.HpksWotsKeygen(masterSeed, 0)     // sk, pk for leaf 0
sig0   := h.HpksWotsSign(msg, masterSeed, 0)
ok     := h.HpksWotsVerify(msg, sig0, pk0)    // true
// Never call HpksWotsSign again with the same masterSeed and leaf index 0.

// --- XMSS-F (multi-signature, h=4 → 16 one-time slots) ---
kp    := h.HpksXmssKeygen(masterSeed, 4)     // builds 2^4-leaf Merkle tree
xsig  := h.HpksXmssSign(msg, kp, 0)          // sign at leaf 0
ok2   := h.HpksXmssVerify(msg, xsig, kp.Root)
_ = ok; _ = ok2
// Next signing call uses HpksXmssSign(msg2, kp, 1), then leaf 2, etc.
```

### HFSCX-256 hash and MAC

```go
data := []byte("hello")

/* Bare hash */
digest := Hfscx256(data, nil)

/* Keyed MAC: iv = key XOR Hfscx256IV */
keyBytes := aliceShared.Bytes()
macIV := make([]byte, 32)
for i := range macIV {
    macIV[i] = keyBytes[i] ^ Hfscx256IV[i]
}
mac := Hfscx256(data, macIV)
```

### HDRBG (forward-secure DRBG)

```go
import h "herradurakex/herradura"
import "crypto/rand"

// Seed from OS entropy.
entropy := make([]byte, 32)
rand.Read(entropy)

d := h.DrbgSeed(entropy, nil) // nil personalization

// Generate output.
out, ok := d.DrbgGenerate(64) // ok == false if DRBG_MAX_BLOCKS exceeded
_ = ok

// Reseed to forward-securely advance the state.
fresh := make([]byte, 32)
rand.Read(fresh)
d.DrbgReseed(fresh)
```

### OPRF (2HashDH oblivious PRF)

```go
import h "herradurakex/herradura"

// Key generation (server side)
k, _ := h.OprfKeygen(256)

// Blinding (client side)
r, alpha, _ := h.OprfBlind([]byte("my-password"), 256)

// Evaluation (server side)
beta := h.OprfEval(alpha, k, 256)

// Unblinding (client side): yields F(k, input)
F := h.OprfUnblind(beta, r, 256)

// Direct evaluation — result matches
check := h.OprfDirect([]byte("my-password"), k, 256)
// F.Cmp(check) == 0
```

`OprfBlind` retries internally until `r` is coprime to ORD = 2^256−1.
All return values are `*big.Int`.

### Complete runnable example

```bash
go run docs/examples/go/hello_herradura.go
```

See [`docs/examples/go/hello_herradura.go`](examples/go/hello_herradura.go).

---

## Python integration

### Importing the module

The filename contains spaces, so a plain `import` statement will not work.
Use `importlib` instead:

```python
import importlib.util, pathlib

_path = pathlib.Path("/path/to/HerraduraKEx/Herradura cryptographic suite.py")
_spec = importlib.util.spec_from_file_location("herradura", _path)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
```

After this, every public name is accessible as `h.<name>`.

### HKEX-GF key exchange (classical)

```python
n    = h.KEYBITS          # 256
poly = h.GF_POLY[n]
g    = h.GF_GEN           # 3

alice_priv = h.BitArray.random(n)
bob_priv   = h.BitArray.random(n)

alice_pub = h.BitArray(n, h.gf_pow(g, alice_priv.uint, poly, n))
bob_pub   = h.BitArray(n, h.gf_pow(g, bob_priv.uint,   poly, n))

alice_shared = h.BitArray(n, h.gf_pow(bob_pub.uint,   alice_priv.uint, poly, n))
bob_shared   = h.BitArray(n, h.gf_pow(alice_pub.uint, bob_priv.uint,   poly, n))
assert alice_shared == bob_shared
```

### HSKE symmetric encryption (classical)

```python
plaintext  = h.BitArray.random(n)
ciphertext = h.fscx_revolve(plaintext,  alice_shared, h.I_VALUE)
recovered  = h.fscx_revolve(ciphertext, alice_shared, h.R_VALUE)
assert plaintext == recovered
```

### HPKS-NL Schnorr signature (NL/PQC)

Same key type as HPKS.  The challenge uses `nl_fscx_revolve_v1` instead of
`fscx_revolve`, hardening against challenge preimage attacks.

```python
poly = h.GF_POLY[n]
ord_ = (1 << n) - 1                              # group order 2^n - 1

msg_nl = h.BitArray.random(n)
k_nl   = h.BitArray.random(n)                    # per-signature nonce

R_nl   = h.BitArray(n, h.gf_pow(h.GF_GEN, k_nl.uint, poly, n))   # R = g^k
e_nl   = h.nl_fscx_revolve_v1(R_nl, msg_nl, h.I_VALUE)            # NL challenge
s_nl   = (k_nl.uint - alice_priv.uint * e_nl.uint) % ord_         # s = k - a·e

# Verify: g^s · C^e == R
e_v   = h.nl_fscx_revolve_v1(R_nl, msg_nl, h.I_VALUE)
lhs   = h.gf_mul(h.gf_pow(h.GF_GEN, s_nl, poly, n),
                 h.gf_pow(alice_pub.uint, e_v.uint, poly, n), poly, n)
assert lhs == R_nl.uint
```

### HPKE-NL El Gamal encryption (NL/PQC)

Same key type as HPKE.  The symmetric layer uses `nl_fscx_revolve_v2` (bijective)
instead of the linear FSCX revolve, hardening ciphertext against key recovery.

```python
r_nl    = h.BitArray.random(n)
R_nl2   = h.BitArray(n, h.gf_pow(h.GF_GEN, r_nl.uint, poly, n))   # R = g^r
enc_nl  = h.BitArray(n, h.gf_pow(alice_pub.uint, r_nl.uint, poly, n))  # C^r
ct_nl   = h.nl_fscx_revolve_v2(plaintext, enc_nl, h.I_VALUE)       # encrypt

dec_nl  = h.BitArray(n, h.gf_pow(R_nl2.uint, alice_priv.uint, poly, n))  # R^a
pt_nl   = h.nl_fscx_revolve_v2_inv(ct_nl, dec_nl, h.I_VALUE)       # decrypt
assert pt_nl == plaintext
# Transmit R_nl2 alongside ct_nl; Alice decrypts with her private key.
```

### HSKE-NL-A1 counter-mode encryption (NL/PQC)

```python
key   = h.BitArray.random(n)
nonce = h.BitArray.random(n)
pt    = h.BitArray.random(n)

base  = h.BitArray(n, key.uint ^ nonce.uint)
seed  = h.BitArray(n, base.rotated(n // 8).uint ^ h._RNL_KDF_DC_256)
ks    = h.nl_fscx_revolve_v1(seed, h.BitArray(n, base.uint ^ 0), n // 4)  # counter=0
ct    = h.BitArray(n, pt.uint ^ ks.uint)
dec   = h.BitArray(n, ct.uint ^ ks.uint)
assert dec == pt
# Transmit nonce alongside ct so the recipient can reproduce the keystream.
```

### HSKE-NL-A2 symmetric encryption (NL/PQC)

```python
key       = h.BitArray.random(n)
plaintext = h.BitArray.random(n)

ciphertext = h.nl_fscx_revolve_v2(plaintext, key, h.R_VALUE)
recovered  = h.nl_fscx_revolve_v2_inv(ciphertext, key, h.R_VALUE)
assert plaintext == recovered
```

### HSKE-NL-AEAD authenticated encryption (NL/PQC)

Authenticated encryption with associated data built on HSKE-NL-A1.  Returns
`(nonce, ct, tag)` on encrypt; returns the plaintext or `None` on decrypt.
Decryption is verify-then-decrypt using `hmac.compare_digest`.

```python
aead_key = h.BitArray.random(n)
pt = b"hello AEAD"
ad = b"header-v1"

# encrypt — nonce is generated internally if not supplied
nonce, ct, tag = h.hske_nl_aead_encrypt(aead_key, pt, ad)

# decrypt — returns plaintext or None if tag/ct/ad/nonce is tampered with
recovered = h.hske_nl_aead_decrypt(aead_key, nonce, ct, tag, ad)
assert recovered == pt

# tamper detection
assert h.hske_nl_aead_decrypt(aead_key, nonce,
                               bytes([ct[0] ^ 1]) + ct[1:], tag, ad) is None
```

### HKEX-RNL key exchange (Ring-LWR, PQC)

```python
m_base  = h._rnl_m_poly(n)
a_rand  = h._rnl_rand_poly(n, h.RNLQ)
m_blind = h._rnl_poly_add(m_base, a_rand, h.RNLQ)

# hkex_rnl_keygen / hkex_rnl_agree are public aliases (v1.7.4+)
sA, CA = h.hkex_rnl_keygen(m_blind, n, h.RNLQ, h.RNLP, h.RNLB)
sB, CB = h.hkex_rnl_keygen(m_blind, n, h.RNLQ, h.RNLP, h.RNLB)

kA, hint_A = h.hkex_rnl_agree(sA, CB, h.RNLQ, h.RNLP, h.RNLPP, n, n)
kB         = h.hkex_rnl_agree(sB, CA, h.RNLQ, h.RNLP, h.RNLPP, n, n, hint=hint_A)
assert kA == kB

# KDF
skA = h.nl_fscx_revolve_v1(kA.rotated(n // 8), kA, n // 4)
```

### HPKS-Stern-F signature (code-based PQC)

```python
seed, e_int, syndrome = h.stern_f_keygen(n)
msg = h.BitArray.random(n)
sig = h.hpks_stern_f_sign(msg, e_int, seed, syndrome, n)
ok  = h.hpks_stern_f_verify(msg, sig, seed, syndrome, n)
```

### HPKE-Stern-F KEM (code-based PQC, demo)

Niederreiter KEM: ciphertext is a syndrome; session key is `hash(seed, e')`.
`hpke_stern_f_encap_with_e` returns the plaintext error for the demo
decapsulation path.  **Production requires a QC-MDPC decoder** to recover
`e'` from the syndrome; `hpke_stern_f_decap(ct, 0, seed)` attempts brute-force
but refuses if `C(n, t) > 2^32`.

```python
# Keygen: same as HPKS-Stern-F — seed private, syndrome public.
seed2, _, _ = h.stern_f_keygen(n)

# Encapsulate — returns (K, ct, e_prime)
#   K       — session key (BitArray)
#   ct      — syndrome int (send to recipient)
#   e_prime — plaintext error int (keep secret; needed for demo decap)
K_enc, ct2, e_prime = h.hpke_stern_f_encap_with_e(seed2, n)

# Decapsulate (demo — known e_prime)
K_dec = h.hpke_stern_f_decap(ct2, e_prime, seed2, n)
assert K_enc == K_dec
# Production: recover e_prime from ct2 with a QC-MDPC decoder, then call
# hpke_stern_f_decap(ct2, e_prime, seed2, n).
```

### HPKS-WOTS-F / HPKS-XMSS-F (hash-based stateful signatures)

> **Statefulness warning:** A WOTS-F leaf key must **never** be reused.  Sign
> only one message per leaf index.  XMSS-F is the recommended multi-signature
> variant; persist the next unused leaf index across restarts.

```python
import os

master_seed = os.urandom(32)
msg = b"hello world"

# --- WOTS-F (one-time, single leaf) ---
sk0, pk0 = h.hpks_wots_keygen(master_seed, leaf_idx=0)
sig0, _  = h.hpks_wots_sign(msg, master_seed, leaf_idx=0)
ok       = h.hpks_wots_verify(msg, sig0, pk0)   # True
# Never call hpks_wots_sign with the same master_seed and leaf_idx=0 again.

# --- XMSS-F (multi-signature, h=4 → 16 one-time slots) ---
ms, root, leaf_hashes = h.hpks_xmss_keygen(master_seed, h=4)
xsig = h.hpks_xmss_sign(msg, ms, leaf_hashes, leaf_idx=0)
ok2  = h.hpks_xmss_verify(msg, xsig, root)      # True
# Next message: hpks_xmss_sign(msg2, ms, leaf_hashes, leaf_idx=1), etc.
```

### HFSCX-256 hash and MAC

```python
data = b"hello"

# Bare hash
digest = h.hfscx_256(data)

# Keyed MAC: iv = key XOR IV
mac_iv = h.BitArray(n, alice_shared.uint ^ int.from_bytes(h._HFSCX256_IV_BYTES, 'big'))
mac = h.hfscx_256(data, iv=mac_iv)
```

### HDRBG (forward-secure DRBG)

```python
import importlib, importlib.util, pathlib, os

# Seed from OS entropy.
entropy = os.urandom(32)

d = h.drbg_seed(entropy, personalization=None)

# Generate output.
out = h.drbg_generate(d, 64)

# Reseed to forward-securely advance the state.
fresh = os.urandom(32)
h.drbg_reseed(d, fresh)
```

### OPRF (2HashDH oblivious PRF)

```python
# Key generation (server side)
k = h.oprf_keygen()                      # random element of GF(2^256)*

# Blinding (client side)
r, alpha = h.oprf_blind(b"my-password")  # alpha = H(x)^r

# Evaluation (server side)
beta = h.oprf_eval(alpha, k)             # beta = alpha^k

# Unblinding (client side): yields F(k, x) = H(x)^k
F = h.oprf_unblind(beta, r)             # F = beta^{r^{-1}}

# Direct evaluation (same result, no blinding)
check = h.oprf_direct(b"my-password", k)
assert F == check
```

`oprf_blind` retries internally until `r` is coprime to ORD = 2^256−1.
All scalars are Python `int`; the hash-to-field function is `HFSCX-256`.

### aPAKE (augmented password-authenticated key exchange)

The aPAKE construction combines HKEX-RNL (Ring-LWR channel), ZKBoo (zero-knowledge
proof of password knowledge), and OPRF (server-side augmentation).  The server
database stores an OPRF output — not a password hash — so a stolen database cannot
be attacked offline without also compromising the OPRF key.

```python
# --- Registration (server side) ---
oprf_key = h.oprf_keygen()
record = h.hpake_register("alice", "s3cr3t", oprf_key)
# record = {"salt": <int>, "B": <int>, "y": <int>}
# Store record in your user database; oprf_key stays on the server.

# --- Login (both sides) ---
session_key = h.hpake_login_demo(record, "s3cr3t", oprf_key)
# Returns 32-byte session key on success, None on failure.
assert session_key is not None

wrong_pw = h.hpake_login_demo(record, "wrong", oprf_key)
assert wrong_pw is None
```

`hpake_register` and `hpake_login_demo` are defined in
`Herradura cryptographic suite.py`.  Equivalent library APIs exist in C and Go
(see below).  The Python CLI (`herradura.py`) exposes the same flow via
`pake-register` and `pake-demo` subcommands — see the
[OPRF and aPAKE](#oprf-and-apake) section for CLI examples.

Demo parameters: `_HPAKE_ZKP_N = 32`, `_HPAKE_ROUNDS = 16`.

### NumPy acceleration

The NTT-based polynomial multiply used by HKEX-RNL runs roughly 10× faster when
NumPy is installed.  The module auto-detects it:

```python
import numpy  # install via: pip install numpy
# Now h._NUMPY == True and _rnl_poly_mul uses the vectorised path automatically.
```

### Complete runnable example

```bash
python3 docs/examples/python/hello_herradura.py
```

See [`docs/examples/python/hello_herradura.py`](examples/python/hello_herradura.py).

---

## ZKP Protocols

Zero-knowledge proof (ZKP) constructions allow a prover to demonstrate knowledge
of a secret (a Ring-LWR signing key, an NL-FSCX preimage) without revealing it.
Combined with the Fiat-Shamir heuristic they yield non-interactive signatures.

**When to use ZKP vs. conventional signatures:**

- Use **ZKP-RNL** when you need an anonymous credential: the verifier learns only
  that the signer holds *a* valid key, not which key relative to other keys.
  Post-quantum hardness follows Ring-LWR.  Proof size is 1,056 bytes at n=256 —
  smaller than ML-DSA-44 (2,420 bytes).
- Use **ZKP-NL** when the secret is an NL-FSCX preimage — e.g. to prove knowledge
  of the input to the one-way function without revealing it.  CLI defaults to n=8
  (35.5 KB proof at R=219); production at n=256 yields 920 KB pending ZKB++
  optimisation.
- Use **HPKS-Stern-F** for conventional signatures where a formal reduction to
  syndrome decoding hardness is required (78 KB, production-ready).

See `SecurityProofs-3.md §11.10` for completeness, soundness, and zero-knowledge
proofs of both constructions.

### ZKP-RNL (Ring-LWR Σ-protocol)

The signer reuses an **HKEX-RNL key pair** (`m_blind`, secret `s`, public `C`).
Proof components: commitment polynomial `w`, sparse ternary challenge `c`,
response polynomial `z`.  Parameters at n=256: γ=8192, t=16 challenge positions.

#### C

```c
#include "herradura.h"

/* Keygen: use HKEX-RNL keygen — same key type */
rnl_poly_t m_blind, s, C_pub;
rnl_m_poly(m_blind);
rnl_keygen(s, C_pub, m_blind, urnd);

/* Sign */
rnl_poly_t w, z;
int        c[RNL_N];
int ok = rnl_sigma_sign(s, m_blind, C_pub, RNL_N, msg, msglen, urnd, w, c, z);

/* Verify — only needs public key */
ok = rnl_sigma_verify(m_blind, C_pub, RNL_N, msg, msglen, w, c, z);
```

#### Go

```go
import h "herradurakex/herradura"

// Keygen: same as HKEX-RNL
n      := h.RnlN
mBlind := h.RnlMPoly(n)
sA, CA := h.RnlKeygen(mBlind, n, h.RnlQ, h.RnlP)

// Sign
w, c, z, err := h.RnlSigmaSign(sA, mBlind, CA, n, msg)

// Verify
ok := h.RnlSigmaVerify(mBlind, CA, n, msg, w, c, z)
```

#### Python

```python
# Keygen: same as HKEX-RNL
m_blind = h._rnl_m_poly(n)
s, C_pub = h.hkex_rnl_keygen(m_blind, n, h.RNLQ, h.RNLP, h.RNLB)

# Sign
w, c, z = h._rnl_sigma_sign(s, m_blind, C_pub, n, msg)

# Verify
ok = h._rnl_sigma_verify(m_blind, C_pub, n, msg, w, c, z)
```

### ZKP-NL (NL-FSCX ZKBoo)

Proves knowledge of `A` satisfying `F1(A, B) = y` via MPC-in-the-head.
The key pair is `(A secret, B and y public)`.  Default parameters: n=8 (toy demo),
R=4 rounds (soundness error (1/3)^4 ≈ 1.2%).  Use R=219 for 128-bit soundness.

#### C

```c
#include "herradura.h"

/* Keygen */
uint32_t A, B, y;
zkp_nl_keygen(ZKP_NL_DEFAULT_N, urnd, &A, &B, &y);  /* A secret; B, y public */

/* Prove */
int rounds = ZKP_NL_DEMO_ROUNDS;    /* 4; use ZKP_NL_PROD_ROUNDS=219 for production */
ZkpNlRound *proof = zkp_nl_prove(A, B, y, ZKP_NL_DEFAULT_N, rounds, msg, msglen);

/* Verify */
int ok = zkp_nl_verify(B, y, ZKP_NL_DEFAULT_N, rounds, msg, msglen, proof);
zkp_nl_proof_free(proof, rounds);
```

#### Go

```go
import h "herradurakex/herradura"

// Keygen
A, B, y, _ := h.ZkpNlKeygen(h.ZkpNlDefaultN)

// Prove (demo rounds=4; use h.ZkpNlProdRounds=219 for production)
proof, _ := h.ZkpNlProve(A, B, y, h.ZkpNlDefaultN, h.ZkpNlDemoRounds, msg)

// Verify
ok := h.ZkpNlVerify(B, y, h.ZkpNlDefaultN, h.ZkpNlDemoRounds, msg, proof)
```

#### Python

```python
# Keygen
A, B, y = h._zkp_nl_keygen(n)     # A secret; B, y public

# Prove (rounds=4 demo; 219 for 128-bit soundness)
proof = h._zkp_nl_prove(A, B, y, n, rounds=4, msg=msg)

# Verify
ok = h._zkp_nl_verify(B, y, n, rounds=4, msg=msg, proof=proof)
```

### CLI usage

```bash
# ZKP-RNL — key type: hkex-rnl, algo: rnl-sigma
python3 HerraduraCli/herradura.py genpkey --algo hkex-rnl --out priv.pem
python3 HerraduraCli/herradura.py pkey    --in priv.pem --pubout --out pub.pem
python3 HerraduraCli/herradura.py sign    --algo rnl-sigma --key priv.pem \
        --in msg.bin --out sig.pem
python3 HerraduraCli/herradura.py verify  --algo rnl-sigma --pubkey pub.pem \
        --in msg.bin --sig sig.pem

# C and Go CLIs share identical subcommands
./HerraduraCli/herradura_cli     sign   --algo rnl-sigma --key priv.pem --in msg.bin --out sig.pem
./HerraduraCli/herradura_cli_go  sign   --algo rnl-sigma --key priv.pem --in msg.bin --out sig.pem

# ZKP-NL — key type: hpks-zkp-nl, algo: nl-zkboo
python3 HerraduraCli/herradura.py genpkey --algo hpks-zkp-nl --out zkpnl.pem
python3 HerraduraCli/herradura.py pkey    --in zkpnl.pem --pubout --out zkpnl_pub.pem
# Python CLI accepts --rounds; C CLI hardcodes 219 rounds; Go CLI hardcodes 4 rounds
python3 HerraduraCli/herradura.py sign   --algo nl-zkboo --key zkpnl.pem \
        --rounds 4 --in msg.bin --out proof.pem
python3 HerraduraCli/herradura.py verify --algo nl-zkboo --pubkey zkpnl_pub.pem \
        --in msg.bin --sig proof.pem
./HerraduraCli/herradura_cli sign    --algo nl-zkboo --key zkpnl.pem --in msg.bin --out proof.pem
./HerraduraCli/herradura_cli verify  --algo nl-zkboo --pubkey zkpnl_pub.pem --in msg.bin --sig proof.pem
```

Proof PEM files are cross-language compatible: a proof produced by the Python CLI
verifies under the C and Go CLIs and vice versa.  See `CliTest/test_zkp_interop.sh`
for a 14-way cross-language interop test.

### Proof-size and performance comparison

| Construction | Proof / signature size | Hardness | Notes |
|---|---|---|---|
| HPKS | 64 B | DLP in GF(2^256) — quantum-broken | Fastest |
| ZKP-RNL (n=256) | **1,056 B** | Ring-LWR (heuristic) | Best lattice compactness |
| ML-DSA-44 (reference) | 2,420 B | Module-LWE | NIST standard |
| HPKS-Stern-F (rounds=219) | 78 KB | SD(N,t) + NL-FSCX v1 PRF | **Demo params** (N=256, ~30–40 bits); 128-bit needs N≥17000 |
| ZKP-NL (n=8, R=219) | 35.5 KB | NL-FSCX OWF | CLI default; toy parameters |
| ZKP-NL (n=256, R=219) | 920 KB | NL-FSCX OWF | Awaits ZKB++ (~180 KB est.) |

ZKP-RNL is the most compact lattice-based signing option in the suite.
For NL-FSCX witness statements, ZKP-NL is the only applicable construction.

---

## Threshold Signing (HPKS-T)

HPKS-T is an n-of-n MuSig2-style threshold Schnorr signature over GF(2^256)*.
All n signers must participate in each round; the resulting signature is identical
in size to a single-party HPKS-NL signature and verifiable with the same code.

Keys are standard `hpks` or `hpks-nl` private key PEMs.  The workflow is a
4-phase interactive protocol driven by a coordinator (any party).

### 4-phase CLI workflow

**Phase 1 — Each signer generates a nonce and commitment:**

```bash
# signer Alice
python3 herradura.py threshold-commit \
  --key alice.pem --commit-out alice_commit.pem --nonce-out alice_nonce.pem

# signer Bob
python3 herradura.py threshold-commit \
  --key bob.pem --commit-out bob_commit.pem --nonce-out bob_nonce.pem
```

Alice shares `alice_commit.pem` with the coordinator.  `alice_nonce.pem` is secret
and must be kept private until phase 3, then securely deleted.

**Phase 2 — Coordinator aggregates commitments and broadcasts challenge:**

```bash
python3 herradura.py threshold-aggregate \
  --commits alice_commit.pem bob_commit.pem \
  --in message.bin \
  --out aggregate.pem
```

The coordinator broadcasts `aggregate.pem` to all signers.

**Phase 3 — Each signer produces a partial signature scalar:**

```bash
# Alice
python3 herradura.py threshold-respond \
  --key alice.pem \
  --commits alice_commit.pem bob_commit.pem \
  --aggregate aggregate.pem \
  --nonce alice_nonce.pem \
  --out alice_partial.pem

# Bob
python3 herradura.py threshold-respond \
  --key bob.pem \
  --commits alice_commit.pem bob_commit.pem \
  --aggregate aggregate.pem \
  --nonce bob_nonce.pem \
  --out bob_partial.pem
```

**Phase 4 — Coordinator combines partial sigs into the final signature:**

```bash
python3 herradura.py threshold-combine \
  --aggregate aggregate.pem \
  --partials alice_partial.pem bob_partial.pem \
  --out final_sig.pem
```

**Verify:**

```bash
python3 herradura.py verify --algo hpks-t --in message.bin --sig final_sig.pem
```

No `--pubkey` flag is needed: the aggregate public key C_agg is embedded in
`final_sig.pem` (HPKST SIGNATURE PEM).

### C CLI equivalent

The C CLI uses repeated `--commit` / `--partial` flags instead of `nargs+`:

```bash
herradura_cli threshold-commit --key alice.pem \
  --commit-out alice_commit.pem --nonce-out alice_nonce.pem

herradura_cli threshold-aggregate \
  --commit alice_commit.pem --commit bob_commit.pem \
  --in message.bin --out aggregate.pem

herradura_cli threshold-respond --key alice.pem \
  --commit alice_commit.pem --commit bob_commit.pem \
  --aggregate aggregate.pem --nonce alice_nonce.pem --out alice_partial.pem

herradura_cli threshold-combine \
  --aggregate aggregate.pem \
  --partial alice_partial.pem --partial bob_partial.pem \
  --out final_sig.pem

herradura_cli verify --algo hpks-t --in message.bin --sig final_sig.pem
```

The Go CLI (`herradura_cli_go`) uses the same `--commit` / `--partial` repeated-flag
convention as the C CLI.

### Cross-language interoperability

Commitment, aggregate, partial, and signature PEMs produced by any CLI are byte-for-byte
compatible with all other CLIs.  The test `CliTest/test_threshold_interop.sh` verifies
9 combinations (3 sign-CLIs × 3 verify-CLIs, plus a mixed-phase scenario).

### Security notes

- **Nonce reuse is catastrophic.** A nonce file must never be used twice with the
  same private key.  Securely delete `*_nonce.pem` after phase 3.
- **Rogue-key protection.** The μ_j coefficient binds each signer's public key to the
  full set L via HFSCX-256(L ‖ C_j), preventing a rogue-key attack.
- **n-of-n only.** HPKS-T requires all n signers; threshold-of-n (t < n) is not
  supported.
- **NL-FSCX challenge.** The challenge hash uses `nl_fscx_revolve_v1(R, msg, n/4)`,
  giving the same security properties as HPKS-NL single-party signing.

### Library API

The all-in-one library functions collapse all four CLI phases into a single call
and are intended for demos, tests, and single-process multi-party simulations.
For real multi-party deployments use the CLI phases so each signer runs
independently.

#### C

```c
#include "herradura.h"

FILE *urnd = fopen("/dev/urandom", "rb");

/* Key pairs: each signer holds a private scalar and its GF public key. */
BitArray secrets[3], pubkeys[3];
for (int j = 0; j < 3; j++) {
    ba_rand(&secrets[j], urnd);
    gf_pow_ba(&pubkeys[j], &GF_GEN_BA, &secrets[j]);
}

BitArray msg;
ba_rand(&msg, urnd);

/* Sign: all secrets and pubkeys known to the coordinator in a demo. */
BitArray C_agg, R, s;
hpkst_sign(secrets, pubkeys, 3, &msg, NULL /* auto-generate nonces */, &C_agg, &R, &s, urnd);

/* Verify: identical to single-party HPKS-NL verify. */
int ok = hpkst_verify(&C_agg, &R, &s, &msg);  /* 1 if valid */

fclose(urnd);
```

#### Go

```go
import (
    "math/big"
    h "herradurakex/herradura"
)

n   := 3
g   := big.NewInt(h.GfGen)
poly := h.GfPoly[256]

secrets := make([]*big.Int, n)
pubkeys := make([]*big.Int, n)
for j := range secrets {
    k := h.NewRandBitArray(256)
    secrets[j] = &k.Val
    pubkeys[j]  = h.GfPow(g, secrets[j], poly, 256)
}

msg := h.NewRandBitArray(256)

// Sign (returns aggregate pubkey, nonce, scalar)
cAgg, R, s := h.HpkstSign(secrets, pubkeys, msg.Bytes())

// Verify (identical to single-party HPKS-NL verify)
ok := h.HpkstVerify(cAgg, R, s, msg.Bytes())
```

#### Python

```python
n_sig = 3
poly  = h.GF_POLY[n]

secrets = [h.BitArray.random(n).uint for _ in range(n_sig)]
pubkeys = [h.BitArray(n, h.gf_pow(h.GF_GEN, a_j, poly, n)) for a_j in secrets]

msg = h.BitArray.random(n)

# Sign — returns (C_agg, R, s) BitArrays
C_agg, R, s = h.hpkst_sign(secrets, pubkeys, msg)

# Verify — identical to single-party HPKS-NL verify
ok  = h.hpkst_verify(C_agg, R, s, msg)
bad = h.hpkst_verify(C_agg, R, h.BitArray(n, s.uint ^ 1), msg)  # tamper → False
assert ok and not bad
```

---

## OPRF and aPAKE

### OPRF overview

The **2HashDH OPRF** (Oblivious Pseudo-Random Function) lets a client compute
`F(k, x) = gf_pow(H(x), k)` without learning the server key `k` and without
the server learning the input `x`.

```
client                           server
------                           ------
r ← coprime random scalar
alpha = H(x)^r          ─── alpha ──►   beta = alpha^k
F = beta^{r^{-1}}       ◄── beta ────
```

`H` maps arbitrary bytes to a non-zero GF(2^256)* element via HFSCX-256.
The blinding factor `r` must be coprime to ORD = 2^256−1; all three
implementations retry automatically (expected two attempts on average).

### OPRF CLI usage (Python, C, Go)

All three CLIs share the same subcommands and PEM wire format:

```bash
# --- Python CLI ---
# 1. Generate OPRF server key
python3 HerraduraCli/herradura.py genpkey --algo oprf --out server.pem

# 2. Client blinds its input
python3 HerraduraCli/herradura.py oprf-blind --input "my-password" --out state.pem

# 3. Server evaluates (state.pem contains alpha; server.pem contains k)
python3 HerraduraCli/herradura.py oprf-eval --key server.pem --in state.pem --out eval.pem

# 4. Client unblinds to obtain F(k, x) as 64-char hex
python3 HerraduraCli/herradura.py oprf-unblind --state state.pem --eval eval.pem

# --- C CLI (identical subcommands) ---
./HerraduraCli/herradura_cli genpkey   --algo oprf --out server.pem
./HerraduraCli/herradura_cli oprf-blind  --input "my-password" --out state.pem
./HerraduraCli/herradura_cli oprf-eval   --key server.pem --in state.pem --out eval.pem
./HerraduraCli/herradura_cli oprf-unblind --state state.pem --eval eval.pem

# --- Go CLI (identical subcommands) ---
./HerraduraCli/herradura_cli_go genpkey    --algo oprf --out server.pem
./HerraduraCli/herradura_cli_go oprf-blind  --input "my-password" --out state.pem
./HerraduraCli/herradura_cli_go oprf-eval   --key server.pem --in state.pem --out eval.pem
./HerraduraCli/herradura_cli_go oprf-unblind --state state.pem --eval eval.pem
```

PEM files produced by any implementation are byte-for-byte compatible with the
others.  See `CliTest/test_oprf_interop.sh` for a 6-way cross-language
interop test (Python/C/Go key × blind × eval × unblind).

### aPAKE library API (C)

The C library exposes `hpake_register` and `hpake_login_demo` in `herradura.h`.
The `HpakeRecord` struct (32-byte salt, two `uint32_t` ZKBoo values) is the
server-side record; store it in your database alongside the OPRF key.

```c
#include "herradura.h"

FILE *urnd = fopen("/dev/urandom", "rb");
BitArray oprf_key;
oprf_keygen(&oprf_key, urnd);         /* server OPRF key — keep secret */

/* Registration (server side) */
HpakeRecord rec;
hpake_register(&rec,
               (const uint8_t *)"s3cr3t", 6,
               &oprf_key, urnd);
/* Store rec and oprf_key on the server; never store the password. */

/* Login (both sides — demo collapses into one call) */
uint8_t session_key[KEYBYTES];
int ok = hpake_login_demo(session_key, &rec,
                           (const uint8_t *)"s3cr3t", 6,
                           &oprf_key, urnd);
/* ok == 1 and session_key holds the 32-byte derived key */

int bad = hpake_login_demo(session_key, &rec,
                            (const uint8_t *)"wrong", 5,
                            &oprf_key, urnd);
/* bad == 0 — wrong password rejected */

fclose(urnd);
```

Demo parameters: `HPAKE_ZKP_N = 32`, `HPAKE_ROUNDS = 16`.

### aPAKE library API (Go)

The Go package exposes `HpakeRegister` and `HpakeLoginDemo`.  `HpakeRecord` is
the server-side record type; `OprfKeygen` produces the server OPRF key.

```go
import (
    "fmt"
    h "herradurakex/herradura"
)

// Key generation (server side, one time)
oprfKey, _ := h.OprfKeygen(256)

// Registration (server side)
rec, _ := h.HpakeRegister([]byte("s3cr3t"), oprfKey)
// Store rec (*HpakeRecord) in your database; keep oprfKey secret.

// Login (both sides — demo collapses into one call)
sessionKey, _ := h.HpakeLoginDemo(rec, []byte("s3cr3t"), oprfKey)
// sessionKey is a 32-byte slice on success, nil on wrong password.
fmt.Printf("session key: %x\n", sessionKey)

wrongKey, _ := h.HpakeLoginDemo(rec, []byte("wrong"), oprfKey)
// wrongKey == nil — wrong password rejected
```

Demo parameters: `HpakeZkpN = 32`, `HpakeRounds = 16`.

### aPAKE CLI usage (Python CLI)

The aPAKE CLI flow requires the Python CLI.  The C and Go CLIs support OPRF
but not the `pake-register` / `pake-demo` subcommands; use the library APIs
above for C and Go aPAKE integration.

```bash
# 1. Generate OPRF server key (one time)
python3 HerraduraCli/herradura.py genpkey --algo oprf --out server.pem

# 2. Register a user (stores PAKE RECORD PEM — no plaintext password)
python3 HerraduraCli/herradura.py pake-register \
    --key server.pem --username alice --password s3cr3t --out record.pem

# 3. Demo login (runs both sides in one command for testing)
python3 HerraduraCli/herradura.py pake-demo \
    --key server.pem --username alice --password s3cr3t
```

`pake-demo` reads the record generated by the most recent `pake-register` for
the given username and prints the session key on success, or reports rejection
for a wrong password.  See `CliTest/test_pake.sh` for the full integration test.

---

## Protocol reference

### Classical protocols

| Protocol | Key exchange | Encryption | Signature |
|----------|-------------|------------|-----------|
| HKEX-GF | `gf_pow(g, priv, poly, n)` → pub | — | — |
| HSKE | — | `fscx_revolve(pt, key, I_VALUE)` | — |
| HPKS | — | — | Schnorr over GF(2^n)* |
| HPKE | — | El Gamal + FSCX revolve | — |

### NL/PQC protocols

| Protocol | Primitive | Direction |
|----------|-----------|-----------|
| HSKE-NL-A1 | `nl_fscx_revolve_v1` | counter-mode (one-way) |
| HSKE-NL-A2 | `nl_fscx_revolve_v2` / `_inv` | revolve-mode (invertible) |
| HSKE-NL-AEAD | HSKE-NL-A1 + HFSCX-256 MAC | authenticated encryption (recommended) |
| HKEX-RNL | Ring-LWR polynomial arithmetic | key exchange |
| HPKS-NL | `nl_fscx_revolve_v1` as Schnorr challenge | signature |
| HPKE-NL | `nl_fscx_revolve_v2` / `_inv` | El Gamal encryption |

### Code-based PQC

| Protocol | Security | Status |
|----------|----------|--------|
| HPKS-Stern-F | SD(N,t) + NL-FSCX v1 PRF | Demo params (rounds=32); production needs rounds≥219 |
| HPKE-Stern-F | SD(N,t) | Demo only; decap requires QC-MDPC decoder for production |

### Hash-based stateful signatures

| Protocol | Hard problem | Availability | Notes |
|----------|-------------|--------------|-------|
| HPKS-WOTS-F | Second-preimage of HFSCX-256 | C, Go, Python | One-time: one message per leaf index; reuse breaks security |
| HPKS-XMSS-F | Second-preimage of HFSCX-256 | C, Go, Python | Multi-use: 2^h slots per master seed; persist leaf counter |

### ZKP protocols

| Construction | Key type | Sign / prove | Verify | Proof size |
|---|---|---|---|---|
| ZKP-RNL (Ring-LWR Σ-protocol) | `hkex-rnl` | `rnl_sigma_sign` | `rnl_sigma_verify` | 1,056 B (n=256) |
| ZKP-NL (NL-FSCX ZKBoo) | `hpks-zkp-nl` | `zkp_nl_prove` | `zkp_nl_verify` | 35.5 KB (n=8, R=219) |

### OPRF and aPAKE

| Protocol | Key type | Hard problem | Availability |
|----------|----------|--------------|--------------|
| OPRF (2HashDH) | `oprf` | DLP in GF(2^256) | C, Go, Python, all CLIs |
| aPAKE | `oprf` | DLP + Ring-LWR + NL-FSCX OWF | C, Go, Python (library); Python CLI only |

The OPRF output is `F(k, x) = gf_pow(H(x), k)` where `H` is HFSCX-256 hash-to-field.
The aPAKE protocol uses HKEX-RNL for the key exchange channel, ZKBoo for the
zero-knowledge proof of password knowledge, and the OPRF to augment the server
record (demo parameters: `_HPAKE_ZKP_N = 32`, `_HPAKE_ROUNDS = 16`).

### Hash primitive

| Primitive | Hard problem | Output |
|-----------|-------------|--------|
| HFSCX-256 | NL-FSCX v1 one-wayness | 256 bits (32 bytes) |

Merkle-Damgård construction: each 32-byte message block is fed through
`nl_fscx_revolve_v1(state, block, 64)` with the previous state as the chaining
variable.  ISO 7816-4 padding appends `0x80` then zeros to a 32-byte boundary,
followed by a length block.  The domain IV is the 32-byte ASCII string
`HFSCX-256/HERRADURA-SUITE\0\0\0\0\0\0\0`.

### C high-level wrappers (added in v1.7.4)

```c
/* HKEX-GF */
void hkex_gf_pubkey(const BitArray *priv, BitArray *pub);
void hkex_gf_agree (const BitArray *my_priv, const BitArray *their_pub, BitArray *shared);

/* HSKE */
void hske_encrypt(const BitArray *pt,  const BitArray *key, BitArray *ct);
void hske_decrypt(const BitArray *ct,  const BitArray *key, BitArray *pt);

/* HPKS */
void hpks_sign  (const BitArray *msg, const BitArray *priv, BitArray *R, BitArray *s, FILE *urnd);
int  hpks_verify(const BitArray *msg, const BitArray *pub,  const BitArray *R, const BitArray *s);

/* HPKE */
void hpke_encrypt(const BitArray *pt, const BitArray *pub, BitArray *R, BitArray *ct, FILE *urnd);
void hpke_decrypt(const BitArray *ct, const BitArray *R,   const BitArray *priv, BitArray *pt);

/* PQC (existing, unchanged) */
void stern_f_keygen      (BitArray *seed, BitArray *e, uint8_t *syndr, FILE *urnd);
void hpks_stern_f_sign   (SternSig *sig, const BitArray *msg, const BitArray *e,
                           const BitArray *seed, FILE *urnd);
int  hpks_stern_f_verify (const SternSig *sig, const BitArray *msg,
                           const BitArray *seed, const uint8_t *syndr);

/* OPRF (2HashDH) */
void oprf_keygen (BitArray *k, FILE *urnd);
void oprf_blind  (const uint8_t *x, size_t xlen,
                  BitArray *r, BitArray *alpha, FILE *urnd);
void oprf_eval   (BitArray *beta, const BitArray *alpha, const BitArray *k);
void oprf_unblind(BitArray *F, const BitArray *beta, const BitArray *r);
void oprf_direct (BitArray *F, const uint8_t *x, size_t xlen, const BitArray *k);
```

---

## Parameter reference

| Parameter | C macro | Go constant | Python constant | Value |
|-----------|---------|-------------|-----------------|-------|
| Key size (bits) | `KEYBITS` | — | `KEYBITS` | 256 |
| FSCX encrypt steps | `I_VALUE` | `iValue = n/4` | `I_VALUE` | 64 |
| FSCX decrypt steps | `R_VALUE` | `rValue = 3*n/4` | `R_VALUE` | 192 |
| RLWR modulus q | `RNL_Q` | `RnlQ` | `RNLQ` | 65537 |
| RLWR public modulus p | `RNL_P` | `RnlP` | `RNLP` | 4096 |
| RLWR reconciliation pp | `RNL_PP` | `RnlPP` | `RNLPP` | 4 |
| RLWR polynomial degree | `RNL_N` | (= key bits) | (= `KEYBITS`) | 256 |
| RLWR secret distribution | `RNL_ETA` | — | `RNLB` | 1 (CBD) |
| Stern error weight | `SDF_T` | `SdfT` | `SDFT` | 16 (N=256; T=N/16) |
| Stern ZKP rounds (demo) | `SDF_ROUNDS` | `SdfRounds` | `SDFR` | 32 (N=256) |
| GF generator | `GF_GEN` (BitArray) | `GfGen = 3` | `GF_GEN = 3` | 3 |
| HFSCX-256 domain IV | `_HFSCX256_IV[32]` | `Hfscx256IV` | `_HFSCX256_IV_BYTES` | `b'HFSCX-256/HERRADURA-SUITE\x00…'` |
| OPRF field order | `ORD` (2^256−1) | computed from `n=256` | computed from `KEYBITS` | 2^256−1 |
| aPAKE ZKBoo width | — | — | `_HPAKE_ZKP_N` | 32 (demo) |
| aPAKE ZKP rounds | — | — | `_HPAKE_ROUNDS` | 16 (demo) |

Stern-F parameters scale with N: T = N/16, rows = N/4.  C/Go/Python support
N ∈ {32, 64, 128, 256}; assembly and Arduino targets are fixed at N=32 (T=2, rounds=4).

---

## Security notes

### Classical protocols (HKEX-GF, HSKE, HPKS, HPKE)

- **HKEX-GF, HPKS, HPKE** rest on the discrete logarithm problem in GF(2^256)*.
  Shor's algorithm solves DLP in polynomial time on a quantum computer.
- **HSKE** is vulnerable to linear key recovery from a single known-plaintext pair.

Use these protocols for compatibility testing, educational purposes, or in threat
models that exclude quantum adversaries.

### NL/PQC protocols (HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL)

- **HKEX-GF / HKEX-RNL raw shared secret:** The raw output of `hkex_gf_agree`
  (a GF(2^n) element) and `rnl_agree` (a Ring-LWR reconciliation value) both
  retain algebraic structure and non-uniform bit distribution.  Post-hash through
  HFSCX-256 before using the value as a symmetric key.  In the CLI, pass
  `--kdf hfscx-256` to `kex`; in library code call `hfscx_256` / `Hfscx256` /
  `hfscx_256` directly.  Both parties must apply the same step.
- **HKEX-RNL** is conjectured quantum-resistant, based on Ring-LWR hardness.
  It has not been formally reduced from NIST-standardised parameters.
- **HKEX-RNL unauthenticated hint:** The Peikert reconciliation hint vector
  (`m_blind`, 64 bytes at n=256) is transmitted from Bob to Alice unauthenticated.
  An active adversary who can tamper with the channel can flip hint bits to steer
  the reconciled key toward a value of their choosing.  **HKEX-RNL provides key
  agreement only; the caller is responsible for authenticating the transcript**
  (e.g. via HPKS-NL, or a MAC over `b_pub ‖ m_blind`) before using the derived key.
- **HPKS-NL and HPKE-NL** still use GF(2^256)* DLP for the public key; the NL
  extension hardens only the symmetric sub-protocol.  They are not fully PQC.
- **HSKE-NL-A1/A2** are symmetric-only and do not depend on any public-key assumption.
- **HSKE-NL-AEAD nonce reuse is catastrophic.**  Reusing a (key, nonce) pair with
  different plaintexts exposes the XOR of the two plaintexts and invalidates all
  confidentiality guarantees.  Always generate the nonce from a cryptographic RNG;
  in library code `BitArray.random(256)` / `NewRandBitArray(256)` / `ba_rand` do
  this.  The Python `hske_nl_aead_encrypt` function auto-generates the nonce when
  none is supplied.
- **HSKE-NL-AEAD does not provide key commitment** in the standard sense — a
  malicious server holding a different key cannot be distinguished from a MAC
  failure.  For applications requiring key commitment (e.g. OPAQUE/aPAKE), apply
  an additional commitment step or use the OPRF-based aPAKE construction instead.

### Code-based PQC (HPKS-Stern-F, HPKE-Stern-F)

- **HPKS-Stern-F** has a complete security reduction to SD(N,t) + NL-FSCX v1 PRF
  (Theorem 17, `SecurityProofs-2.md §11.8.4`).  SD(N,t) is NP-complete and believed
  quantum-hard (BMvT 1978).
- **Demo parameters** use `SDF_ROUNDS=32` (soundness error (2/3)^32 ≈ 2^-19).
  Production requires `rounds ≥ 219` for 128-bit soundness.
- **HPKE-Stern-F decapsulation** in the demo uses a known error vector (`e'`).
  A production deployment requires a QC-MDPC or similar decoder.

### OPRF and aPAKE

- **OPRF security** rests on the DLP in GF(2^256)* — the same assumption as
  HKEX-GF.  It is **not** quantum-resistant; a quantum adversary who breaks DLP
  can recover the server key `k` from any blinded query.
- **ORD = 2^256−1 is composite** with small factors (3, 5, 17, 257, 641, …).
  Roughly 50% of random 256-bit scalars share a factor with ORD and cannot be
  inverted.  All three implementations retry until `gcd(r, ORD) = 1`.  Never
  supply a static or low-entropy blinding factor; always generate `r` from a
  cryptographic RNG.
- **OPRF blinding factor leakage:** The client's blinding factor `r` must be kept
  secret.  If `r` is leaked, the server can recover `x` from `alpha = H(x)^r`.
- **aPAKE demo parameters** (`_HPAKE_ZKP_N = 32`, `_HPAKE_ROUNDS = 16`) are for
  testing only.  The ZKBoo soundness error with these parameters is not suitable
  for production — use `_HPAKE_ROUNDS ≥ 219` for 128-bit soundness.
- **aPAKE OPRF key compromise:** If the OPRF key `k` is stolen, an attacker can
  compute `F(k, pw)` for any guessed password offline.  The aPAKE record stores
  the OPRF output, not the raw password hash, to prevent offline dictionary attacks
  on a stolen database *alone* — but the OPRF key must still be protected.

### Constant-time status

- **C and assembly targets** implement branchless GF multiply, branchless
  `stern_apply_perm`, and constant-time equality checks.
- **Python** is a reference implementation and is **not** constant-time.
  Do not use the Python target in production where timing side-channels matter.
- **Go** avoids data-dependent branching in critical paths but has not undergone
  formal constant-time verification.
