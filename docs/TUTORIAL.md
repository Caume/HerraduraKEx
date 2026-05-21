# Herradura Cryptographic Suite — Integration Tutorial

This guide shows how to use the Herradura suite as a library in your own C, Go, or Python project.

The suite implements four protocol families:

| Protocol | Classical | NL/PQC variant | Code-based PQC |
|----------|-----------|----------------|----------------|
| Key exchange | HKEX-GF | HKEX-RNL (Ring-LWR) | — |
| Symmetric encryption | HSKE | HSKE-NL-A1, HSKE-NL-A2 | — |
| Schnorr signature | HPKS | HPKS-NL | HPKS-Stern-F |
| El Gamal encryption | HPKE | HPKE-NL | HPKE-Stern-F |

**Security note:** The classical protocols (HKEX-GF, HSKE, HPKS, HPKE) are vulnerable to quantum
attacks. Use the NL/PQC or code-based variants for new deployments. See [Security notes](#security-notes).

---

## Contents

1. [C integration](#c-integration)
2. [Go integration](#go-integration)
3. [Python integration](#python-integration)
4. [Protocol reference](#protocol-reference)
5. [Parameter reference](#parameter-reference)
6. [Security notes](#security-notes)

---

## C integration

`herradura.h` is a **header-only library** — every function is `static inline`.
Copy `herradura.h` into your project (or keep it in the repo and use `-I`) then:

```c
#include "herradura.h"
```

No additional source files, no link flags, no build system changes.

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

### HSKE-NL-A2 symmetric encryption (NL/PQC)

```python
key       = h.BitArray.random(n)
plaintext = h.BitArray.random(n)

ciphertext = h.nl_fscx_revolve_v2(plaintext, key, h.R_VALUE)
recovered  = h.nl_fscx_revolve_v2_inv(ciphertext, key, h.R_VALUE)
assert plaintext == recovered
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
| HKEX-RNL | Ring-LWR polynomial arithmetic | key exchange |
| HPKS-NL | `nl_fscx_revolve_v1` as Schnorr challenge | signature |
| HPKE-NL | `nl_fscx_revolve_v2` / `_inv` | El Gamal encryption |

### Code-based PQC

| Protocol | Security | Status |
|----------|----------|--------|
| HPKS-Stern-F | SD(N,t) + NL-FSCX v1 PRF | Demo params (rounds=32); production needs rounds≥219 |
| HPKE-Stern-F | SD(N,t) | Demo only; decap requires QC-MDPC decoder for production |

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
| Stern error weight | `SDF_T` | `SdfT` | `SDFT` | 16 |
| Stern ZKP rounds (demo) | `SDF_ROUNDS` | `SdfRounds` | `SDFR` | 32 |
| GF generator | `GF_GEN` (BitArray) | `GfGen = 3` | `GF_GEN = 3` | 3 |

---

## Security notes

### Classical protocols (HKEX-GF, HSKE, HPKS, HPKE)

- **HKEX-GF, HPKS, HPKE** rest on the discrete logarithm problem in GF(2^256)*.
  Shor's algorithm solves DLP in polynomial time on a quantum computer.
- **HSKE** is vulnerable to linear key recovery from a single known-plaintext pair.

Use these protocols for compatibility testing, educational purposes, or in threat
models that exclude quantum adversaries.

### NL/PQC protocols (HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL)

- **HKEX-RNL** is conjectured quantum-resistant, based on Ring-LWR hardness.
  It has not been formally reduced from NIST-standardised parameters.
- **HPKS-NL and HPKE-NL** still use GF(2^256)* DLP for the public key; the NL
  extension hardens only the symmetric sub-protocol.  They are not fully PQC.
- **HSKE-NL-A1/A2** are symmetric-only and do not depend on any public-key assumption.

### Code-based PQC (HPKS-Stern-F, HPKE-Stern-F)

- **HPKS-Stern-F** has a complete security reduction to SD(N,t) + NL-FSCX v1 PRF
  (Theorem 17, `SecurityProofs-2.md §11.8.4`).  SD(N,t) is NP-complete and believed
  quantum-hard (BMvT 1978).
- **Demo parameters** use `SDF_ROUNDS=32` (soundness error (2/3)^32 ≈ 2^-19).
  Production requires `rounds ≥ 219` for 128-bit soundness.
- **HPKE-Stern-F decapsulation** in the demo uses a known error vector (`e'`).
  A production deployment requires a QC-MDPC or similar decoder.

### Constant-time status

- **C and assembly targets** implement branchless GF multiply, branchless
  `stern_apply_perm`, and constant-time equality checks.
- **Python** is a reference implementation and is **not** constant-time.
  Do not use the Python target in production where timing side-channels matter.
- **Go** avoids data-dependent branching in critical paths but has not undergone
  formal constant-time verification.
