/* herradura_shim.c — thin extern "C" shim around herradura.h's static-inline
 * classical protocol API (HKEX-GF, HSKE, HPKS, HPKE), built as a shared
 * library for ctypes (Python) and cgo (Go) bindings.
 *
 * herradura.h exposes its API as `static`/`static inline` functions for
 * header-only single-TU consumption; those have internal linkage and cannot
 * be dlopen'd or linked against directly. This file gives each function a
 * fixed-width byte-buffer signature (32-byte KEYBYTES arrays) and external
 * linkage so it can cross an FFI boundary. Randomness is read from
 * /dev/urandom internally; callers never pass a FILE*.
 *
 * Scope: the classical v1.4.0 quartet only (HKEX-GF/HSKE/HPKS/HPKE). NL/PQC
 * and Stern-F protocols are out of scope for TODO #137 — see TODO.md.
 */

#include <stdio.h>
#include <string.h>
#include "../../herradura.h"
#include "herradura_shim.h"

#define HFFI_EXPORT __attribute__((visibility("default")))

static FILE *hffi_urandom(void)
{
    static __thread FILE *f = NULL;
    if (!f) {
        f = fopen("/dev/urandom", "rb");
        if (!f) {
            fputs("herradura_shim: could not open /dev/urandom\n", stderr);
        }
    }
    return f;
}

/* HKEX-GF */

HFFI_EXPORT void hffi_hkex_gf_pubkey(const uint8_t priv[KEYBYTES], uint8_t pub_out[KEYBYTES])
{
    BitArray priv_ba, pub_ba;
    memcpy(priv_ba.b, priv, KEYBYTES);
    hkex_gf_pubkey(&priv_ba, &pub_ba);
    memcpy(pub_out, pub_ba.b, KEYBYTES);
}

/* Returns 1 on success, 0 if their_pub is degenerate (see TODO #131). */
HFFI_EXPORT int hffi_hkex_gf_agree(const uint8_t my_priv[KEYBYTES],
                                    const uint8_t their_pub[KEYBYTES],
                                    uint8_t shared_out[KEYBYTES])
{
    BitArray priv_ba, pub_ba, shared_ba;
    memcpy(priv_ba.b, my_priv, KEYBYTES);
    memcpy(pub_ba.b, their_pub, KEYBYTES);
    int ok = hkex_gf_agree(&priv_ba, &pub_ba, &shared_ba);
    if (ok) memcpy(shared_out, shared_ba.b, KEYBYTES);
    return ok;
}

/* HSKE */

HFFI_EXPORT void hffi_hske_encrypt(const uint8_t pt[KEYBYTES], const uint8_t key[KEYBYTES],
                                    uint8_t ct_out[KEYBYTES])
{
    BitArray pt_ba, key_ba, ct_ba;
    memcpy(pt_ba.b, pt, KEYBYTES);
    memcpy(key_ba.b, key, KEYBYTES);
    hske_encrypt(&pt_ba, &key_ba, &ct_ba);
    memcpy(ct_out, ct_ba.b, KEYBYTES);
}

HFFI_EXPORT void hffi_hske_decrypt(const uint8_t ct[KEYBYTES], const uint8_t key[KEYBYTES],
                                    uint8_t pt_out[KEYBYTES])
{
    BitArray ct_ba, key_ba, pt_ba;
    memcpy(ct_ba.b, ct, KEYBYTES);
    memcpy(key_ba.b, key, KEYBYTES);
    hske_decrypt(&ct_ba, &key_ba, &pt_ba);
    memcpy(pt_out, pt_ba.b, KEYBYTES);
}

/* HPKS (Schnorr) */

HFFI_EXPORT void hffi_hpks_sign(const uint8_t msg[KEYBYTES], const uint8_t priv[KEYBYTES],
                                 uint8_t R_out[KEYBYTES], uint8_t s_out[KEYBYTES])
{
    BitArray msg_ba, priv_ba, R_ba, s_ba;
    memcpy(msg_ba.b, msg, KEYBYTES);
    memcpy(priv_ba.b, priv, KEYBYTES);
    hpks_sign(&msg_ba, &priv_ba, &R_ba, &s_ba, hffi_urandom());
    memcpy(R_out, R_ba.b, KEYBYTES);
    memcpy(s_out, s_ba.b, KEYBYTES);
}

HFFI_EXPORT int hffi_hpks_verify(const uint8_t msg[KEYBYTES], const uint8_t pub[KEYBYTES],
                                  const uint8_t R[KEYBYTES], const uint8_t s[KEYBYTES])
{
    BitArray msg_ba, pub_ba, R_ba, s_ba;
    memcpy(msg_ba.b, msg, KEYBYTES);
    memcpy(pub_ba.b, pub, KEYBYTES);
    memcpy(R_ba.b, R, KEYBYTES);
    memcpy(s_ba.b, s, KEYBYTES);
    return hpks_verify(&msg_ba, &pub_ba, &R_ba, &s_ba);
}

/* HPKE (El Gamal) */

HFFI_EXPORT int hffi_hpke_encrypt(const uint8_t pt[KEYBYTES], const uint8_t pub[KEYBYTES],
                                   uint8_t R_out[KEYBYTES], uint8_t ct_out[KEYBYTES])
{
    BitArray pt_ba, pub_ba, R_ba, ct_ba;
    memcpy(pt_ba.b, pt, KEYBYTES);
    memcpy(pub_ba.b, pub, KEYBYTES);
    int ok = hpke_encrypt(&pt_ba, &pub_ba, &R_ba, &ct_ba, hffi_urandom());
    if (ok) {
        memcpy(R_out, R_ba.b, KEYBYTES);
        memcpy(ct_out, ct_ba.b, KEYBYTES);
    }
    return ok;
}

HFFI_EXPORT int hffi_hpke_decrypt(const uint8_t ct[KEYBYTES], const uint8_t R[KEYBYTES],
                                   const uint8_t priv[KEYBYTES], uint8_t pt_out[KEYBYTES])
{
    BitArray ct_ba, R_ba, priv_ba, pt_ba;
    memcpy(ct_ba.b, ct, KEYBYTES);
    memcpy(R_ba.b, R, KEYBYTES);
    memcpy(priv_ba.b, priv, KEYBYTES);
    int ok = hpke_decrypt(&ct_ba, &R_ba, &priv_ba, &pt_ba);
    if (ok) memcpy(pt_out, pt_ba.b, KEYBYTES);
    return ok;
}

HFFI_EXPORT int hffi_keybytes(void) { return KEYBYTES; }
