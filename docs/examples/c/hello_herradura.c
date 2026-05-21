/*  hello_herradura.c — Minimal C integration example for the Herradura suite.
 *
 *  Build:
 *    gcc -O2 -I../../.. hello_herradura.c -o hello_herradura
 *
 *  Run:
 *    ./hello_herradura
 *
 *  Demonstrates HKEX-GF key exchange and HSKE symmetric encryption using the
 *  header-only herradura.h library.  No other source files or link flags needed.
 */

#include <stdio.h>
#include "../../../herradura.h"

int main(void)
{
    FILE *urnd = fopen("/dev/urandom", "rb");
    if (!urnd) { perror("/dev/urandom"); return 1; }

    /* ── HKEX-GF: Diffie-Hellman over GF(2^256)* ──────────────────────── */
    printf("=== HKEX-GF key exchange ===\n");

    BitArray alice_priv, alice_pub, bob_priv, bob_pub;
    BitArray alice_shared, bob_shared;

    ba_rand(&alice_priv, urnd);
    ba_rand(&bob_priv,   urnd);

    hkex_gf_pubkey(&alice_priv, &alice_pub);   /* Alice: pub = g^priv  */
    hkex_gf_pubkey(&bob_priv,   &bob_pub);     /* Bob:   pub = g^priv  */

    hkex_gf_agree(&alice_priv, &bob_pub,   &alice_shared); /* Alice: bob_pub^alice_priv */
    hkex_gf_agree(&bob_priv,   &alice_pub, &bob_shared);   /* Bob:   alice_pub^bob_priv */

    ba_print_hex("Alice shared: ", &alice_shared);
    ba_print_hex("Bob   shared: ", &bob_shared);
    puts(ba_equal(&alice_shared, &bob_shared)
         ? "✓ shared secrets agree" : "✗ shared secrets differ!");

    /* ── HSKE: symmetric encryption with the derived shared key ──────── */
    printf("\n=== HSKE symmetric encryption ===\n");

    BitArray plaintext, ciphertext, recovered;
    ba_rand(&plaintext, urnd);

    hske_encrypt(&plaintext,  &alice_shared, &ciphertext);
    hske_decrypt(&ciphertext, &alice_shared, &recovered);

    ba_print_hex("Plaintext : ", &plaintext);
    ba_print_hex("Ciphertext: ", &ciphertext);
    ba_print_hex("Recovered : ", &recovered);
    puts(ba_equal(&plaintext, &recovered)
         ? "✓ decryption correct" : "✗ decryption failed!");

    /* ── HPKS: Schnorr signature ─────────────────────────────────────── */
    printf("\n=== HPKS Schnorr signature ===\n");

    BitArray msg, R, s;
    ba_rand(&msg, urnd);

    hpks_sign(&msg, &alice_priv, &R, &s, urnd);
    puts(hpks_verify(&msg, &alice_pub, &R, &s)
         ? "✓ signature verified" : "✗ signature invalid!");

    /* ── HPKE: El Gamal encryption ───────────────────────────────────── */
    printf("\n=== HPKE El Gamal encryption ===\n");

    BitArray ct_hpke, R_hpke, dec_hpke;
    ba_rand(&plaintext, urnd);

    hpke_encrypt(&plaintext, &alice_pub, &R_hpke, &ct_hpke, urnd);
    hpke_decrypt(&ct_hpke, &R_hpke, &alice_priv, &dec_hpke);

    ba_print_hex("Plaintext : ", &plaintext);
    ba_print_hex("Ciphertext: ", &ct_hpke);
    ba_print_hex("Decrypted : ", &dec_hpke);
    puts(ba_equal(&plaintext, &dec_hpke)
         ? "✓ decryption correct" : "✗ decryption failed!");

    fclose(urnd);
    return 0;
}
