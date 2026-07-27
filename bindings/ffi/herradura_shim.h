/* herradura_shim.h — extern "C" declarations for libherradura_ffi, the
 * shared library built from herradura_shim.c. Used by the Go cgo binding;
 * the Python ctypes binding calls the same symbols by name without this
 * header. See herradura_shim.c for behavior notes. */
#ifndef HERRADURA_SHIM_H
#define HERRADURA_SHIM_H

#include <stdint.h>

#define HFFI_KEYBYTES 32

#ifdef __cplusplus
extern "C" {
#endif

void hffi_hkex_gf_pubkey(const uint8_t priv[HFFI_KEYBYTES], uint8_t pub_out[HFFI_KEYBYTES]);
int  hffi_hkex_gf_agree(const uint8_t my_priv[HFFI_KEYBYTES],
                         const uint8_t their_pub[HFFI_KEYBYTES],
                         uint8_t shared_out[HFFI_KEYBYTES]);

void hffi_hske_encrypt(const uint8_t pt[HFFI_KEYBYTES], const uint8_t key[HFFI_KEYBYTES],
                        uint8_t ct_out[HFFI_KEYBYTES]);
void hffi_hske_decrypt(const uint8_t ct[HFFI_KEYBYTES], const uint8_t key[HFFI_KEYBYTES],
                        uint8_t pt_out[HFFI_KEYBYTES]);

void hffi_hpks_sign(const uint8_t msg[HFFI_KEYBYTES], const uint8_t priv[HFFI_KEYBYTES],
                     uint8_t R_out[HFFI_KEYBYTES], uint8_t s_out[HFFI_KEYBYTES]);
int  hffi_hpks_verify(const uint8_t msg[HFFI_KEYBYTES], const uint8_t pub[HFFI_KEYBYTES],
                       const uint8_t R[HFFI_KEYBYTES], const uint8_t s[HFFI_KEYBYTES]);

int hffi_hpke_encrypt(const uint8_t pt[HFFI_KEYBYTES], const uint8_t pub[HFFI_KEYBYTES],
                       uint8_t R_out[HFFI_KEYBYTES], uint8_t ct_out[HFFI_KEYBYTES]);
int hffi_hpke_decrypt(const uint8_t ct[HFFI_KEYBYTES], const uint8_t R[HFFI_KEYBYTES],
                       const uint8_t priv[HFFI_KEYBYTES], uint8_t pt_out[HFFI_KEYBYTES]);

int hffi_keybytes(void);

#ifdef __cplusplus
}
#endif

#endif /* HERRADURA_SHIM_H */
