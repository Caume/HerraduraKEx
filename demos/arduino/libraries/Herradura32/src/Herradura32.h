/*  Herradura32 -- the Herradura KEx 32-bit Arduino library (TODO #425)
    Every primitive and protocol routine of the Arduino target, the check()
    [FAIL] counter and demo_finish().  Each sketch in demos/arduino/<name>/
    includes it and runs ONE algorithm end to end.  This was "Herradura
    cryptographic suite.ino", one sketch running every demo, until TODO #425.
    KEYBITS = 32.

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Arduino IDE: copy demos/arduino/libraries/Herradura32 into your sketchbook's
    libraries/ folder, then open any demos/arduino/<name>/<name>.ino.
    build_arduino.sh passes this directory to avr-g++ with -I instead.

    Version history (from the single-sketch suite):
    v1.5.13: HSKE-NL-A1 seed fix: seed=_rol32(base,4); ks=nl_fscx_revolve_v1(seed,base,I).
             When A=B=base, fscx(base,base)=0; ROL by n/8=4 activates non-linearity from step 1.
    v1.5.10: HKEX-RNL KDF seed fix: seed=ROL32(K,4); sk=nl_fscx_revolve_v1(seed,K,I).
    v1.5.9: HSKE-NL-A1 per-session nonce (lcg_next XOR K); nl_fscx_revolve_v2_inv delta precompute.
    v1.5.7: m_inv_32 uses precomputed rotation table (0x6DB6DB6D) — replaces 15-step loop.
    v1.5.6: rnl_rand_poly bias fix — 3-byte rejection sampling (threshold=0xFF00FF).
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(n log n)).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.0: NL-FSCX v2, HSKE-NL-A1/A2, HKEX-RNL (N=32), HPKS-NL, HPKE-NL.
    v1.4.0: HKEX replaced with HKEX-GF; Schnorr HPKS; El Gamal HPKE.
      - HPKS: Schnorr; s=(k-a*e) mod ORD; verify g^s*C^e==R.
      - HPKE: El Gamal + fscx_revolve; enc_key=C^r; dec_key=R^a.
      - Security: CDH in GF(2^32)*; for demo only; use n>=256 in production.
*/

#ifndef HERRADURA32_H
#define HERRADURA32_H

#include <Arduino.h>

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */
#define V1_MODE_STEPS (3 * KEYBITS / 4) /* 24: NL-FSCX v1's modes, as the four ports (TODO #349) */

/* GF(2^32) polynomial: x^32 + x^22 + x^2 + x + 1 */
#define GF_POLY32 0x00400007UL
#define GF_GEN    3UL

/* NUMS domain constant for KDF seed (SHA-256 H0) */
#define RNL_KDF_DC 0x6A09E667UL

/* HKEX-RNL parameters (N=32 matches KEYBITS=32) */
/* RNL_N stays 32 on AVR: DEMO ONLY.  The C/Go/Python/Java builds moved to
   RNL_N = 1024 in TODO #223 because n = 256 is worth only ~32 Core-SVP bits, but a
   1024-coefficient int32 ring is 4 KB per polynomial and will not fit AVR SRAM.
   32 is far below any security claim; keys are not interoperable with those targets. */
#define RNL_N   32
#define RNL_Q   65537L
#define RNL_P   4096L
#define RNL_PP  4L
#define RNL_ETA 1  /* CBD eta: secret coeffs drawn from CBD(1) in {-1,0,1} mod q */

/* ZKP-RNL: Lyubashevsky Sigma-protocol (n=32) */
#define SIGMA_GAMMA 4096
#define SIGMA_T     4
#define SIGMA_BOUND 4092      /* gamma - t */
#define SIGMA_SLACK 32
#define SIGMA_RANGE 8193      /* 2*gamma + 1 */

/* ZKP-NL: minimal ZKBoo concept demo (n=8 bits, R=4 rounds) */
#define ZKP_NL_N   8
#define ZKP_NL_R   4

typedef unsigned long uint32;

/* ------------------------------------------------------------------ */
/* FSCX primitives                                                     */
/* ------------------------------------------------------------------ */

uint32 rol32(uint32 x) { return (x << 1) | (x >> 31); }
uint32 ror32(uint32 x) { return (x >> 1) | (x << 31); }

uint32 fscx(uint32 a, uint32 b) {
    return a ^ b ^ rol32(a) ^ rol32(b) ^ ror32(a) ^ ror32(b);
}

uint32 fscx_revolve(uint32 a, uint32 b, int steps) {
    for (int i = 0; i < steps; i++) a = fscx(a, b);
    return a;
}

/* ------------------------------------------------------------------ */
/* GF(2^32) arithmetic                                                 */
/* ------------------------------------------------------------------ */

uint32 gf_mul_32(uint32 a, uint32 b) {
    uint32 r = 0;
    for (int i = 0; i < 32; i++) {
        if (b & 1) r ^= a;
        uint32 carry = a >> 31;
        a <<= 1;
        if (carry) a ^= GF_POLY32;
        b >>= 1;
    }
    return r;
}

uint32 gf_pow_32(uint32 base, uint32 exp) {
    uint32 r = 1;
    while (exp) {
        if (exp & 1) r = gf_mul_32(r, base);
        base = gf_mul_32(base, base);
        exp >>= 1;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* LCG PRNG for nonces                                                 */
/* ------------------------------------------------------------------ */

uint32 lcg_state = 0xDEADBEEEUL;

uint32 lcg_next() {
    lcg_state = lcg_state * 1664525UL + 1013904223UL;
    return lcg_state;
}

/* ------------------------------------------------------------------ */
/* Hex printing helpers                                                */
/* ------------------------------------------------------------------ */

static void printHex(uint32 val) {
    char buf[9];
    for (int i = 7; i >= 0; i--) {
        buf[i] = "0123456789ABCDEF"[val & 0xF];
        val >>= 4;
    }
    buf[8] = '\0';
    Serial.println(buf);
}

/* Labels live in flash (F()): with them in .data the strings alone took 3.4 KB
   of the ATmega2560's 8 KB, leaving ~360 bytes of stack, and the demo hung in
   its first rnl_poly_mul (TODO #350). */
static void printHexLine(const __FlashStringHelper *label, uint32 val) {
    Serial.print(label);
    printHex(val);
}

/* TODO #350: the demo's single verdict point, the analogue of the four ports'
   [FAIL] gate (TODO #233) and of the AVR harness's verdict() (TODO #234).  A
   failing branch prints a line carrying "[FAIL]" and is counted; loop() prints
   *** OK / *** FAILED at the end of each pass, which run_arduino.sh's
   gate_check() reads back -- a pass that never finishes fails it too. */
static int g_failures = 0;

static void check(bool ok, const __FlashStringHelper *pass,
                  const __FlashStringHelper *fail) {
    if (!ok) g_failures++;
    Serial.println(ok ? pass : fail);
}

/* ------------------------------------------------------------------ */
/* NL-FSCX primitives (v1.5.0)                                        */
/* ------------------------------------------------------------------ */

/* M^{-1}(X) = XOR of ROL(X,k) for k in bits of 0x6DB6DB6D.
   Table = {0,2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30} (n=32). */
static uint32 _rol32(uint32 v, int k) { return (v << k) | (v >> (32 - k)); }
uint32 m_inv_32(uint32 x) {
    return x
        ^ _rol32(x, 2)  ^ _rol32(x, 3)
        ^ _rol32(x, 5)  ^ _rol32(x, 6)
        ^ _rol32(x, 8)  ^ _rol32(x, 9)
        ^ _rol32(x, 11) ^ _rol32(x, 12)
        ^ _rol32(x, 14) ^ _rol32(x, 15)
        ^ _rol32(x, 17) ^ _rol32(x, 18)
        ^ _rol32(x, 20) ^ _rol32(x, 21)
        ^ _rol32(x, 23) ^ _rol32(x, 24)
        ^ _rol32(x, 26) ^ _rol32(x, 27)
        ^ _rol32(x, 29) ^ _rol32(x, 30);
}

/* delta(B) = ROL32(B * floor((B+1)/2), 8) */
uint32 nl_fscx_delta_v2(uint32 B) {
    uint32 raw = B * ((B + 1) >> 1);          /* mod 2^32 */
    return (raw << 8) | (raw >> 24);           /* ROL32 by 8 */
}

/* NL-FSCX v1: fscx(A,B) XOR ROL32(A+B, 8) */
uint32 nl_fscx_v1(uint32 a, uint32 b) {
    uint32 s = a + b;
    return fscx(a, b) ^ ((s << 8) | (s >> 24));
}

uint32 nl_fscx_revolve_v1(uint32 a, uint32 b, int steps) {
    for (int i = 0; i < steps; i++) a = nl_fscx_v1(a, b);
    return a;
}

/* Refuses NL-FSCX v2 keys whose delta(B) has a short cyclic arc,
 * arc(delta(B)) <= n/4 = 8, which contains the affine class delta(B) in
 * {0, 2^31} (see herradura.h's nl_v2_key_is_valid, TODO #169, #354).  About
 * 2^-12 of keys at n = 32.
 *
 * Failure-mode convention (TODO #169 item 3): this target has no CLI, so
 * there is no keygen boundary to reject at. Mirroring the C/Go/Python
 * suites — which never call the guard from inside nl_fscx_v2/nl_fscx_revolve_v2
 * either, only from their CLI's keygen path — nl_v2_key_is_valid here is a
 * plain 0/1 return-code predicate that the demo/protocol call sites do not
 * invoke. It is exercised solely by a visible test-harness assertion
 * (Herradura_tests.ino's v2_weak_key_reject check, item 4), identical in
 * spirit to the C suite's test [45]. This keeps the convention consistent
 * across all three unguarded targets without adding a new abort-in-hot-path
 * behavior that doesn't exist even at the reference (C/Go/Python) layer. */
uint8_t nl_v2_key_is_valid(uint32 b) {
    /* valid iff arc(delta(B)) > n/4 = 8 (TODO #354): z = ~delta, and each pass
     * z &= ROL(z, 1) shortens every cyclic run of ones by one, so z survives the
     * 3n/4 - 1 = 23 passes iff delta has a zero run of 24 or more. */
    uint32 z = ~nl_fscx_delta_v2(b);
    for (uint8_t i = 0; i < 23; i++) z &= (z << 1) | (z >> 31);
    return z == 0;
}

/* NL-FSCX v2: (fscx(A,B) + delta(B)) mod 2^32 */
uint32 nl_fscx_v2(uint32 a, uint32 b) {
    return fscx(a, b) + nl_fscx_delta_v2(b);  /* mod 2^32 */
}

/* NL-FSCX v2 inverse: B XOR M^{-1}((Y - delta(B)) mod 2^32) */
uint32 nl_fscx_v2_inv(uint32 y, uint32 b) {
    return b ^ m_inv_32(y - nl_fscx_delta_v2(b));
}

uint32 nl_fscx_revolve_v2(uint32 a, uint32 b, int steps) {
    for (int i = 0; i < steps; i++) a = nl_fscx_v2(a, b);
    return a;
}

uint32 nl_fscx_revolve_v2_inv(uint32 y, uint32 b, int steps) {
    uint32 delta = nl_fscx_delta_v2(b);  /* precompute once — b is constant */
    for (int i = 0; i < steps; i++) y = b ^ m_inv_32(y - delta);
    return y;
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL: Ring-LWR helpers  (N=32, q=65537, p=4096, pp=2, B=1)   */
/* ------------------------------------------------------------------ */

static uint32_t rnl_mod_pow(uint32_t base, uint32_t exp, uint32_t m) {
    uint64_t r = 1, b = base % m;
    for (; exp; exp >>= 1) { if (exp & 1) r = r * b % m; b = b * b % m; }
    return (uint32_t)r;
}

static void rnl_ntt(long *a, int n, long q, int invert) {
    int i, j = 0, length, k;
    uint32_t w, wn;
    for (i = 1; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { long t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (length = 2; length <= n; length <<= 1) {
        w = rnl_mod_pow(3, (uint32_t)(q - 1) / (uint32_t)length, (uint32_t)q);
        if (invert) w = rnl_mod_pow(w, (uint32_t)(q - 2), (uint32_t)q);
        for (i = 0; i < n; i += length) {
            wn = 1;
            for (k = 0; k < length >> 1; k++) {
                long u = a[i + k];
                long v = (long)((uint64_t)a[i + k + (length >> 1)] * wn % (uint32_t)q);
                a[i + k]                 = (u + v) % q;
                a[i + k + (length >> 1)] = (u - v + q) % q;
                wn = (uint32_t)((uint64_t)wn * w % (uint32_t)q);
            }
        }
    }
    if (invert) {
        uint32_t inv_n = rnl_mod_pow((uint32_t)n, (uint32_t)(q - 2), (uint32_t)q);
        for (i = 0; i < n; i++) a[i] = (long)((uint64_t)a[i] * inv_n % (uint32_t)q);
    }
}

/* Negacyclic poly multiply: h = f*g in Z_q[x]/(x^N+1) via NTT. O(N log N). */
static void rnl_poly_mul(long *h, const long *f, const long *g) {
    static long fa[RNL_N], ga[RNL_N], ha[RNL_N];
    uint32_t psi     = rnl_mod_pow(3, (RNL_Q - 1) / (2 * RNL_N), RNL_Q);
    uint32_t psi_inv = rnl_mod_pow(psi, RNL_Q - 2, RNL_Q);
    uint32_t pw = 1, pw_inv = 1;
    int i;
    for (i = 0; i < RNL_N; i++) {
        fa[i] = (long)((uint64_t)f[i] * pw % RNL_Q);
        ga[i] = (long)((uint64_t)g[i] * pw % RNL_Q);
        pw    = (uint32_t)((uint64_t)pw * psi % RNL_Q);
    }
    rnl_ntt(fa, RNL_N, RNL_Q, 0);
    rnl_ntt(ga, RNL_N, RNL_Q, 0);
    for (i = 0; i < RNL_N; i++) ha[i] = (long)((uint64_t)fa[i] * ga[i] % RNL_Q);
    rnl_ntt(ha, RNL_N, RNL_Q, 1);
    for (i = 0; i < RNL_N; i++) {
        h[i]   = (long)((uint64_t)ha[i] * pw_inv % RNL_Q);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % RNL_Q);
    }
}

static void rnl_poly_add(long *h, const long *f, const long *g) {
    for (int i = 0; i < RNL_N; i++) h[i] = (f[i] + g[i]) % RNL_Q;
}

/* round: out[i] = round(in[i] * to_p / from_q) mod to_p */
static void rnl_round(long *out, const long *in, long from_q, long to_p) {
    for (int i = 0; i < RNL_N; i++)
        out[i] = (long)(((long long)in[i] * to_p + from_q / 2) / from_q % to_p);
}

/* lift: out[i] = (in[i] * to_q + from_p/2) / from_p mod to_q  (centered rounding) */
static void rnl_lift(long *out, const long *in, long from_p, long to_q) {
    for (int i = 0; i < RNL_N; i++)
        out[i] = (long)(((long long)in[i] * to_q + from_p / 2) / from_p % to_q);
}

/* m(x) = 1 + x + x^{N-1} */
static void rnl_m_poly(long *p) {
    for (int i = 0; i < RNL_N; i++) p[i] = 0;
    p[0] = p[1] = p[RNL_N - 1] = 1;
}

static void rnl_rand_poly(long *p) {
    static const uint32 threshold = 0xFF00FFu; /* (1<<24) - (1<<24)%RNL_Q */
    for (int i = 0; i < RNL_N; ) {
        uint32 v = lcg_next() & 0xFFFFFFu;
        if (v < threshold) p[i++] = (long)(v % (uint32)RNL_Q);
    }
}

/* CBD(eta=1): coeff = (raw&1) - ((raw>>1)&1), stored mod q. Zero-mean {-1,0,1}. */
static void rnl_cbd_poly(long *p) {
    for (int i = 0; i < RNL_N; i++) {
        uint32 raw = lcg_next();
        int a = (int)(raw & 1);
        int b = (int)((raw >> 1) & 1);
        p[i] = (long)((a - b + (long)RNL_Q) % (long)RNL_Q);
    }
}

/* extract N bits from rounded poly into a uint32 key */
static uint32 rnl_bits_to_key(const long *bits_poly) {
    uint32 key = 0;
    for (int i = 0; i < RNL_N; i++)
        if (bits_poly[i] >= RNL_PP / 2)
            key |= (1UL << i);
    return key;
}

/* keygen: s = small poly, C = round_p(m_blind * s) */
static void rnl_keygen(long *s, long *C, const long *m_blind) {
    static long ms[RNL_N];
    rnl_cbd_poly(s);
    rnl_poly_mul(ms, m_blind, s);
    rnl_round(C, ms, RNL_Q, RNL_P);
}

/* 2-bit Peikert hint for first RNL_N/2 coefficients, packed 2 bits/coeff. */
static uint32 rnl_hint(const long *K_poly) {
    uint32 hint = 0;
    for (int i = 0; i < RNL_N / 2; i++) {
        unsigned long c = (unsigned long)K_poly[i];
        unsigned long r = (unsigned long)((8UL * c + (unsigned long)(RNL_Q / 4))
                                          / (unsigned long)RNL_Q) & 3UL;
        hint |= (uint32)(r << (unsigned)(i * 2));
    }
    return hint;
}

static uint32 rnl_reconcile(const long *K_poly, uint32 hint) {
    const unsigned long qq = (unsigned long)(RNL_Q / 4);
    uint32 key = 0;
    for (int i = 0; i < RNL_N / 2; i++) {
        unsigned long c = (unsigned long)K_poly[i];
        unsigned long h = (hint >> (unsigned)(i * 2)) & 3UL;
        unsigned long b = (4UL * c + (2UL * h + 1UL) * qq) / (unsigned long)RNL_Q
                          & 3UL;
        key |= (uint32)(b << (unsigned)(i * 2));
    }
    return key;
}

/* agree: reconciler path (hint_out != NULL) or receiver path (hint_in != NULL). */
static uint32 rnl_agree(const long *s, const long *C_other,
                         const uint32 *hint_in, uint32 *hint_out) {
    static long c_lifted[RNL_N], k_poly[RNL_N];
    rnl_lift(c_lifted, C_other, RNL_P, RNL_Q);
    rnl_poly_mul(k_poly, s, c_lifted);
    if (!hint_in) {
        *hint_out = rnl_hint(k_poly);
        return rnl_reconcile(k_poly, *hint_out);
    }
    return rnl_reconcile(k_poly, *hint_in);
}

/* ------------------------------------------------------------------ */
/* HPKS-Stern-F / HPKE-Stern-F (v1.5.18, code-based PQC)             */
/* N=32, t=2, rows=16, rounds=4. Security <= SD(32,2) + NL-FSCX PRF. */
/* ------------------------------------------------------------------ */

#define SDF_N      32
#define SDF_T      2
#define SDF_NROWS  16
#define SDF_ROUNDS 4

/* HFSCX-32: two-step MD hash at 32-bit word size, Matyas-Meyer-Oseas compression
 * (v11.0.0, TODO #351; Davies-Meyer from v1.9.0 to v10.x).
 * C(s,m)=nl(m,s,24)^m; IV=0xA3C5E7B9, LB=0xA3C5E799.  The chaining value is v1's
 * B: under DM x was B, and x in {0, 2^31} made the round affine-nilpotent (§11.75). */
static uint32 hfscx_32(uint32 x) {
    uint32 s = nl_fscx_revolve_v1(x, 0xA3C5E7B9UL, V1_MODE_STEPS) ^ x;
    return nl_fscx_revolve_v1(0xA3C5E799UL, s, V1_MODE_STEPS) ^ 0xA3C5E799UL;
}

/* HFSCX-32's MMO chain one word at a time (TODO #348, v12.0.0):
 * absorb(s, w) = nl(w, s, 24) ^ w from s = IV, then final(s) = nl(LB, s, 24) ^ LB.
 * hfscx_32(x) is final(absorb(IV, x)).  Every input below starts with a tag word
 * and has a fixed word count at its call site.  The item is v1's A and the
 * chaining value its B, so no party chooses B (§11.75). */
#define HFSCX32_IV    0xA3C5E7B9UL
#define HFSCX32_LB    0xA3C5E799UL
#define HPKS_NL32_TAG 0x30000000UL   /* HPKS-NL Schnorr challenge          */
#define STERN32_TAG   0x31000000UL   /* Stern-F chain hash; low byte = ds   */
static uint32 hfscx32_absorb(uint32 s, uint32 w) {
    return nl_fscx_revolve_v1(w, s, V1_MODE_STEPS) ^ w;
}
static uint32 hfscx32_final(uint32 s) {
    return nl_fscx_revolve_v1(HFSCX32_LB, s, V1_MODE_STEPS) ^ HFSCX32_LB;
}

/* HPKS-NL challenge e = HFSCX-32(TAG, R, msg).  NL-FSCX v1(R, msg, n/4) until
 * v11.x, with the signer's msg as v1's B (TODO #348). */
static uint32 hpks_nl_challenge_32(uint32 R, uint32 msg) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, HPKS_NL32_TAG);
    h = hfscx32_absorb(h, R);
    return hfscx32_final(hfscx32_absorb(h, msg));
}

/* Stern chain hash = HFSCX-32(TAG|ds, items...).  Until v11.x each item was
 * absorbed as v1(h ^ v, ROL(v, 4), n/4), with the item as v1's B (TODO #348). */
static uint32 stern_hash1_32(uint32 ds, uint32 v) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, STERN32_TAG | ds);
    return hfscx32_final(hfscx32_absorb(h, v));
}

static uint32 stern_hash2_32(uint32 ds, uint32 a, uint32 b) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, STERN32_TAG | ds);
    h = hfscx32_absorb(h, a);
    return hfscx32_final(hfscx32_absorb(h, b));
}

static uint32 stern_matrix_row_32(uint32 seed, int row) {
    /* HFSCX-32 finalization removes range compression (TODO #88, v1.9.35) */
    return hfscx_32(nl_fscx_revolve_v1(_rol32(seed ^ (uint32)row, 4), seed, I_VALUE));
}

static uint32 stern_syndrome_32(uint32 seed, uint32 e) {
    uint32 synd = 0;
    for (int row = 0; row < SDF_NROWS; row++) {
        uint32 v = stern_matrix_row_32(seed, row) & e;
        v ^= v >> 16; v ^= v >> 8; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
        if (v & 1) synd |= (1UL << row);
    }
    return synd;
}

static void stern_gen_perm_32(uint8_t *perm, uint32 pi_seed) {
    uint32 key = _rol32(pi_seed, 4), st = pi_seed;
    for (int i = 0; i < SDF_N; i++) perm[i] = (uint8_t)i;
    for (int i = SDF_N - 1; i > 0; i--) {
        st = nl_fscx_v1(st, key);
        int j = (int)(st % (uint32)(i + 1));
        uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
    }
}

/* Branchless: mask = -(bit) is 0 or 0xFFFFFFFF; no branch on secret bits. */
static uint32 stern_apply_perm_32(const uint8_t *perm, uint32 v) {
    uint32 out = 0;
    for (int i = 0; i < SDF_N; i++) {
        uint32 bit  = (v >> i) & 1u;
        uint32 mask = (uint32)(-(int32_t)bit);  /* 0x00000000 or 0xFFFFFFFF */
        out |= mask & (1UL << perm[i]);
    }
    return out;
}

static uint32 stern_rand_error_32(void) {
    uint8_t idx[SDF_N];
    uint32 j;
    for (int i = 0; i < SDF_N; i++) idx[i] = (uint8_t)i;
    j = lcg_next() % (uint32)SDF_N;
    { uint8_t t = idx[SDF_N-1]; idx[SDF_N-1] = idx[j]; idx[j] = t; }
    j = lcg_next() % (uint32)(SDF_N - 1);
    { uint8_t t = idx[SDF_N-2]; idx[SDF_N-2] = idx[j]; idx[j] = t; }
    return (1UL << idx[SDF_N-1]) | (1UL << idx[SDF_N-2]);
}

/* Exact-weight-t test for the N=32/t=2 port, factored out by TODO #298 because
 * the check now runs on respA ^ respB rather than on respA alone and the
 * open-coded "v &= v-1" chain appeared five times. */
static int stern_wt_is_t_32(uint32 v) {
    if (!v) return 0;
    v &= v - 1; if (!v) return 0;
    v &= v - 1; return v == 0;
}

typedef struct {
    uint32 c0[SDF_ROUNDS], c1[SDF_ROUNDS], c2[SDF_ROUNDS];
    uint32 b[SDF_ROUNDS];
    uint32 respA[SDF_ROUNDS];  /* sr (b=0) or pi_seed (b=1,2) */
    uint32 respB[SDF_ROUNDS];  /* sy (b=0) or r   (b=1) or y  (b=2) */
} SternSig32;

static void stern_fs_challenges_32(uint32 *chals, uint32 msg,
                                    const uint32 *c0,
                                    const uint32 *c1,
                                    const uint32 *c2) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, STERN32_TAG);   /* ds = 0 */
    h = hfscx32_absorb(h, msg);
    for (int i = 0; i < SDF_ROUNDS; i++) {
        h = hfscx32_absorb(h, c0[i]);
        h = hfscx32_absorb(h, c1[i]);
        h = hfscx32_absorb(h, c2[i]);
    }
    h = hfscx32_final(h);
    for (int i = 0; i < SDF_ROUNDS; i++) {
        h = nl_fscx_v1(h, (uint32)i);
        chals[i] = h % 3;
    }
}

static void hpks_stern_f_sign_32(SternSig32 *sig, uint32 msg,
                                   uint32 e, uint32 seed) {
    static uint8_t perm[SDF_N];
    static uint32 r_tmp[SDF_ROUNDS],  y_tmp[SDF_ROUNDS];
    static uint32 pi_tmp[SDF_ROUNDS], sr_tmp[SDF_ROUNDS], sy_tmp[SDF_ROUNDS];
    for (int i = 0; i < SDF_ROUNDS; i++) {
        uint32 r  = lcg_next();            /* UNIFORM since v8.0.0, TODO #298 */
        uint32 y  = e ^ r;
        uint32 pi = lcg_next();
        stern_gen_perm_32(perm, pi);
        uint32 sr = stern_apply_perm_32(perm, r);
        uint32 sy = stern_apply_perm_32(perm, y);
        uint32 hr = stern_syndrome_32(seed, r);
        sig->c0[i] = stern_hash2_32(1, pi, hr);
        sig->c1[i] = stern_hash1_32(2, sr);
        sig->c2[i] = stern_hash1_32(3, sy);
        r_tmp[i] = r;  y_tmp[i] = y;
        pi_tmp[i] = pi; sr_tmp[i] = sr; sy_tmp[i] = sy;
    }
    stern_fs_challenges_32(sig->b, msg, sig->c0, sig->c1, sig->c2);
    for (int i = 0; i < SDF_ROUNDS; i++) {
        uint32 bv = sig->b[i];
        if      (bv == 0) { sig->respA[i] = sr_tmp[i]; sig->respB[i] = sy_tmp[i]; }
        else if (bv == 1) { sig->respA[i] = pi_tmp[i]; sig->respB[i] = r_tmp[i];  }
        else              { sig->respA[i] = pi_tmp[i]; sig->respB[i] = y_tmp[i];  }
    }
}

static int hpks_stern_f_verify_32(const SternSig32 *sig, uint32 msg,
                                    uint32 seed, uint32 synd) {
    static uint8_t perm[SDF_N];
    uint32 chals[SDF_ROUNDS];
    stern_fs_challenges_32(chals, msg, sig->c0, sig->c1, sig->c2);
    for (int i = 0; i < SDF_ROUNDS; i++)
        if (chals[i] != sig->b[i]) return 0;
    for (int i = 0; i < SDF_ROUNDS; i++) {
        uint32 bv = sig->b[i], ra = sig->respA[i], rb = sig->respB[i];
        if (bv == 0) {
            if (stern_hash1_32(2, ra) != sig->c1[i]) return 0;
            if (stern_hash1_32(3, rb) != sig->c2[i]) return 0;
            /* wt(sigma(r) ^ sigma(y)) = wt(e).  Until v8.0.0 this tested ra
             * alone -- the blinding value -- and nothing bound wt(e) at all
             * (TODO #298). */
            if (!stern_wt_is_t_32(ra ^ rb)) return 0;
        } else if (bv == 1) {
            uint32 hr = stern_syndrome_32(seed, rb);
            if (stern_hash2_32(1, ra, hr) != sig->c0[i]) return 0;
            stern_gen_perm_32(perm, ra);
            if (stern_hash1_32(2, stern_apply_perm_32(perm, rb)) != sig->c1[i]) return 0;
        } else {
            uint32 hy = stern_syndrome_32(seed, rb);
            if (stern_hash2_32(1, ra, hy ^ synd) != sig->c0[i]) return 0;
            stern_gen_perm_32(perm, ra);
            if (stern_hash1_32(3, stern_apply_perm_32(perm, rb)) != sig->c2[i]) return 0;
        }
    }
    return 1;
}

static uint32 hpke_stern_f_encap_32(uint32 seed, uint32 *ct_out, uint32 *e_out) {
    uint32 e_p  = stern_rand_error_32();
    *e_out  = e_p;
    *ct_out = stern_syndrome_32(seed, e_p);
    return stern_hash2_32(4, seed, e_p);
}

static uint32 hpke_stern_f_decap_32(uint32 seed, uint32 e_p) {
    return stern_hash2_32(4, seed, e_p);
}

/* ------------------------------------------------------------------ */
/* HPKS-Stern-Ring (TODO #424): ONE Stern proof over the ring, the    */
/* construction of SPEC.md §11.2 at N=32 with the 32-bit primitives:  */
/* H~ = diag([H_0|s_0], [H_1|s_1]) over the ring sorted by (seed,     */
/* syndrome); the signer j proves z = (0..e_j..0 ; unit(j)) in        */
/* ker H~ and in S (one block of weight t, its indicator set), hidden */
/* by a block shuffle tau and per-block pi_b.  c0 = H1(ps, H~ r),     */
/* c1 = H2(salt1, PI r), c2 = H3(salt2, PI y); D = H0(2, k, rounds,   */
/* msg, ring, commitments); b from H6(D, ctr) bytes, 255 rejected.    */
/* Per round the unopened commitment then 8 opening words:            */
/*   b=0: c0, s1, s2, PI r (3), PI y (3)                              */
/*   b=1: c2, ps, s1, r (3), 0,0,0     b=2: c1, ps, s2, y (3), 0,0,0  */
/* Replaced the OR-composition, forgeable with no member's key.       */
/* H_ds(w..) = HFSCX-32(0x32000000|ds, w..); not interoperable with   */
/* the 256-bit ports.  DEMO ONLY: N=32 and 4 rounds have no security. */
/* ------------------------------------------------------------------ */

#define RING_K        2
#define RING32_TAG    0x32000000UL
#define RING_VERSION  2
#define RING_RW       9                         /* words per round: unopened + 8 */
#define RING_DW       (8 + 3 * SDF_ROUNDS)      /* digest input words */
typedef struct { uint32 D; uint32 rw[SDF_ROUNDS][RING_RW]; } SternRing32;

static uint32 ring_seed[RING_K], ring_syn[RING_K];
static uint8_t ring_perm[RING_K][SDF_N];
static uint32 ring_tau;
static uint32 ring_dbuf[RING_DW];

static uint32 ring_hash_32(uint32 ds, const uint32 *w, int n) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, RING32_TAG | ds);
    for (int i = 0; i < n; i++) h = hfscx32_absorb(h, w[i]);
    return hfscx32_final(h);
}
/* Sort the two members by (seed, syndrome); -1 for a duplicate, else 1 if swapped. */
static int ring_canon_32(uint32 sa, uint32 ya, uint32 sb, uint32 yb) {
    int sw = (sa > sb) || (sa == sb && ya > yb);
    if (sa == sb && ya == yb) return -1;
    ring_seed[0] = sw ? sb : sa; ring_syn[0] = sw ? yb : ya;
    ring_seed[1] = sw ? sa : sb; ring_syn[1] = sw ? ya : yb;
    return sw;
}
static void ring_perms_32(uint32 ps) {
    uint32 w[2] = { ps, 0 };
    ring_tau = ring_hash_32(4, w, 1) & 1u;
    for (int b = 0; b < RING_K; b++) {
        w[1] = (uint32)b;
        stern_gen_perm_32(ring_perm[b], ring_hash_32(5, w, 2));
    }
}
static void ring_apply_32(const uint32 *v, uint32 *out) {
    out[2] = 0;
    for (uint32 b = 0; b < RING_K; b++) {
        out[b ^ ring_tau] = stern_apply_perm_32(ring_perm[b], v[b]);
        out[2] |= ((v[2] >> b) & 1u) << (b ^ ring_tau);
    }
}
static uint32 ring_htilde_32(const uint32 *v) {
    uint32 out = 0;
    for (uint32 b = 0; b < RING_K; b++) {
        uint32 m = (uint32)(-(int32_t)((v[2] >> b) & 1u));
        out |= (stern_syndrome_32(ring_seed[b], v[b]) ^ (ring_syn[b] & m)) << (16 * b);
    }
    return out;
}
static int ring_in_S_32(const uint32 *v) {
    if (v[2] == 1) return stern_wt_is_t_32(v[0]) && v[1] == 0;
    if (v[2] == 2) return stern_wt_is_t_32(v[1]) && v[0] == 0;
    return 0;
}
static void ring_challenges_32(uint32 D, uint32 *b) {
    uint32 w[2] = { D, 0 };
    int n = 0;
    while (n < SDF_ROUNDS) {
        uint32 h = ring_hash_32(6, w, 2);
        for (int i = 0; i < 4 && n < SDF_ROUNDS; i++, h >>= 8)
            if ((h & 0xFFu) != 0xFFu) b[n++] = (h & 0xFFu) % 3u;
        w[1]++;
    }
}
static uint32 ring_digest_32(uint32 msg) {
    ring_dbuf[0] = RING_VERSION; ring_dbuf[1] = RING_K; ring_dbuf[2] = SDF_ROUNDS;
    ring_dbuf[3] = msg;
    ring_dbuf[4] = ring_seed[0]; ring_dbuf[5] = ring_syn[0];
    ring_dbuf[6] = ring_seed[1]; ring_dbuf[7] = ring_syn[1];
    return ring_hash_32(0, ring_dbuf, RING_DW);
}
static int hpks_stern_ring_sign_32(SternRing32 *sig, uint32 msg, uint32 e, int j,
                                   uint32 sa, uint32 ya, uint32 sb, uint32 yb) {
    static uint32 r[SDF_ROUNDS][3], y[SDF_ROUNDS][3], pr[SDF_ROUNDS][3], py[SDF_ROUNDS][3];
    static uint32 ps[SDF_ROUNDS], s1[SDF_ROUNDS], s2[SDF_ROUNDS];
    uint32 z[3], b[SDF_ROUNDS], h[2], w[4];
    int sw = ring_canon_32(sa, ya, sb, yb), i, q;
    if (sw < 0) return 0;
    j ^= sw;
    z[j] = e; z[1 - j] = 0; z[2] = 1u << j;
    for (i = 0; i < SDF_ROUNDS; i++) {
        r[i][0] = lcg_next(); r[i][1] = lcg_next(); r[i][2] = lcg_next() & 3u;
        ps[i] = lcg_next(); s1[i] = lcg_next(); s2[i] = lcg_next();
        for (q = 0; q < 3; q++) y[i][q] = z[q] ^ r[i][q];
        ring_perms_32(ps[i]);
        ring_apply_32(r[i], pr[i]); ring_apply_32(y[i], py[i]);
        h[0] = ps[i]; h[1] = ring_htilde_32(r[i]);
        ring_dbuf[8 + 3 * i] = ring_hash_32(1, h, 2);
        w[0] = s1[i]; for (q = 0; q < 3; q++) w[1 + q] = pr[i][q];
        ring_dbuf[9 + 3 * i] = ring_hash_32(2, w, 4);
        w[0] = s2[i]; for (q = 0; q < 3; q++) w[1 + q] = py[i][q];
        ring_dbuf[10 + 3 * i] = ring_hash_32(3, w, 4);
    }
    sig->D = ring_digest_32(msg);
    ring_challenges_32(sig->D, b);
    for (i = 0; i < SDF_ROUNDS; i++) {
        uint32 *o = sig->rw[i];
        memset(o, 0, sizeof sig->rw[i]);
        if (b[i] == 0) {
            o[0] = ring_dbuf[8 + 3 * i]; o[1] = s1[i]; o[2] = s2[i];
            for (q = 0; q < 3; q++) { o[3 + q] = pr[i][q]; o[6 + q] = py[i][q]; }
        } else {
            o[0] = ring_dbuf[(b[i] == 1 ? 10 : 9) + 3 * i]; o[1] = ps[i];
            o[2] = b[i] == 1 ? s1[i] : s2[i];
            for (q = 0; q < 3; q++) o[3 + q] = b[i] == 1 ? r[i][q] : y[i][q];
        }
    }
    return 1;
}
static int hpks_stern_ring_verify_32(const SternRing32 *sig, uint32 msg,
                                     uint32 sa, uint32 ya, uint32 sb, uint32 yb) {
    uint32 b[SDF_ROUNDS], h[2], w[4], p[3], v[3];
    int i, q;
    if (ring_canon_32(sa, ya, sb, yb) < 0) return 0;
    ring_challenges_32(sig->D, b);
    for (i = 0; i < SDF_ROUNDS; i++) {
        const uint32 *o = sig->rw[i];
        uint32 *c = &ring_dbuf[8 + 3 * i];
        if (b[i] == 0) {
            if ((o[5] | o[8]) >> 2) return 0;
            for (q = 0; q < 3; q++) v[q] = o[3 + q] ^ o[6 + q];
            if (!ring_in_S_32(v)) return 0;
            c[0] = o[0];
            w[0] = o[1]; for (q = 0; q < 3; q++) w[1 + q] = o[3 + q];
            c[1] = ring_hash_32(2, w, 4);
            w[0] = o[2]; for (q = 0; q < 3; q++) w[1 + q] = o[6 + q];
            c[2] = ring_hash_32(3, w, 4);
        } else {
            if ((o[6] | o[7] | o[8]) || (o[5] >> 2)) return 0;
            ring_perms_32(o[1]);
            ring_apply_32(&o[3], p);
            h[0] = o[1]; h[1] = ring_htilde_32(&o[3]);
            c[0] = ring_hash_32(1, h, 2);
            w[0] = o[2]; for (q = 0; q < 3; q++) w[1 + q] = p[q];
            if (b[i] == 1) { c[1] = ring_hash_32(2, w, 4); c[2] = o[0]; }
            else           { c[2] = ring_hash_32(3, w, 4); c[1] = o[0]; }
        }
    }
    return ring_digest_32(msg) == sig->D;
}

/* ------------------------------------------------------------------ */
/* ZKP-RNL: Lyubashevsky Ring-LWR Sigma-protocol (n=32)               */
/* Requires Arduino Mega or Due (8+ KB SRAM).                         */
/* ------------------------------------------------------------------ */

/* Scratch polys shared between sign and verify. */
static long sig_y[RNL_N], sig_w[RNL_N], sig_c[RNL_N], sig_z[RNL_N];
static long sig_pos[SIGMA_T];
static long sig_tmp0[RNL_N], sig_tmp1[RNL_N], sig_tmp2[RNL_N];
static long sig_tmp3[RNL_N], sig_tmp4[RNL_N];

/* Derive SIGMA_T-sparse ternary challenge polynomial into sig_c. */
static void sigma_challenge(const long *m, const long *C_pub,
                             const long *w, uint32 msg) {
    int i, k;
    uint32 seed = hfscx_32((uint32)RNL_N);
    for (i = 0; i < RNL_N; i++) seed = hfscx_32(seed ^ (uint32)m[i]);
    for (i = 0; i < RNL_N; i++) seed = hfscx_32(seed ^ (uint32)C_pub[i]);
    for (i = 0; i < RNL_N; i++) seed = hfscx_32(seed ^ (uint32)w[i]);
    seed = hfscx_32(seed ^ msg);
    for (i = 0; i < RNL_N; i++) sig_c[i] = 0;
    k = 0;
    uint32 idx = 0;
    while (k < SIGMA_T) {
        uint32 h2 = hfscx_32((idx << 16) ^ seed);
        idx++;
        int pos = (int)(h2 & 31u);
        int dup = 0;
        for (int jj = 0; jj < k; jj++) if (sig_pos[jj] == (long)pos) { dup = 1; break; }
        if (!dup) sig_pos[k++] = (long)pos;
    }
    for (int jj = 0; jj < SIGMA_T; jj++) {
        uint32 h2 = hfscx_32(((uint32)jj << 24) ^ seed);
        sig_c[(int)sig_pos[jj]] = (h2 & 1u) ? (long)(RNL_Q - 1L) : 1L;
    }
}

/* Rejection-sampling Sigma-prover. Returns 1=ok, 0=exhausted (>200 attempts). */
static int rnl_sigma_sign(const long *m, const long *s,
                           const long *C_pub, uint32 msg) {
    int i, attempt;
    for (attempt = 0; attempt < 200; attempt++) {
        for (i = 0; i < RNL_N; i++) {
            uint32 v    = lcg_next() % (uint32)SIGMA_RANGE;
            sig_y[i]    = (long)v - (long)SIGMA_GAMMA;
            sig_tmp0[i] = sig_y[i] < 0 ? sig_y[i] + RNL_Q : sig_y[i];
        }
        rnl_poly_mul(sig_tmp1, m, sig_tmp0);
        for (i = 0; i < RNL_N; i++)
            sig_w[i] = sig_tmp1[i] > RNL_Q / 2 ? sig_tmp1[i] - RNL_Q : sig_tmp1[i];
        sigma_challenge(m, C_pub, sig_w, msg);
        rnl_poly_mul(sig_tmp2, sig_c, s);
        int ok = 1;
        for (i = 0; i < RNL_N; i++) {
            long c_i = sig_tmp2[i] > RNL_Q / 2 ? sig_tmp2[i] - RNL_Q : sig_tmp2[i];
            long z   = sig_y[i] + c_i;
            if ((z < 0 ? -z : z) > (long)SIGMA_BOUND) { ok = 0; break; }
            sig_z[i] = z;
        }
        if (ok) return 1;
    }
    return 0;
}

/* Three-step verifier. Returns 1=accept, 0=reject. */
static int rnl_sigma_verify(const long *m, const long *C_pub, uint32 msg) {
    int i;
    for (i = 0; i < RNL_N; i++) {
        long az = sig_z[i] < 0 ? -sig_z[i] : sig_z[i];
        if (az > (long)SIGMA_BOUND) return 0;
    }
    for (i = 0; i < RNL_N; i++) sig_tmp0[i] = sig_c[i];
    sigma_challenge(m, C_pub, sig_w, msg);
    for (i = 0; i < RNL_N; i++) if (sig_c[i] != sig_tmp0[i]) return 0;
    for (i = 0; i < RNL_N; i++) sig_c[i] = sig_tmp0[i];
    for (i = 0; i < RNL_N; i++)
        sig_tmp2[i] = sig_z[i] < 0 ? sig_z[i] + RNL_Q : sig_z[i];
    rnl_lift(sig_tmp1, C_pub, RNL_P, RNL_Q);
    rnl_poly_mul(sig_tmp3, m, sig_tmp2);
    rnl_poly_mul(sig_tmp4, sig_c, sig_tmp1);
    for (i = 0; i < RNL_N; i++) {
        long wq  = sig_w[i] < 0 ? sig_w[i] + RNL_Q : sig_w[i];
        long raw = sig_tmp3[i] - sig_tmp4[i] - wq;
        raw = ((raw % RNL_Q) + RNL_Q) % RNL_Q;
        if (raw > RNL_Q / 2) raw -= RNL_Q;
        if ((raw < 0 ? -raw : raw) > (long)SIGMA_SLACK) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* ZKP-NL: minimal ZKBoo concept demo (n=8 bits, R=4 rounds)         */
/* PRG/commitments use hfscx_32 — concept illustration only.          */
/* ------------------------------------------------------------------ */

static uint32  zkp_coms[ZKP_NL_R][3];
static uint8_t zkp_e[ZKP_NL_R];
static uint32  zkp_sh1[ZKP_NL_R], zkp_tp1[ZKP_NL_R], zkp_out1[ZKP_NL_R];
static uint32  zkp_sh2[ZKP_NL_R], zkp_tp2[ZKP_NL_R], zkp_out2[ZKP_NL_R];
static uint8_t zkp_gv1[ZKP_NL_R][ZKP_NL_N - 1];
static uint8_t zkp_gv2[ZKP_NL_R][ZKP_NL_N - 1];

static int zkp_prg_bit(uint32 tape, int gate) {
    return (int)(hfscx_32(tape ^ (uint32)gate) & 1u);
}

static uint32 zkp_commit(uint32 tape, uint32 share, uint32 out_share,
                          const uint8_t *gv) {
    int i;
    uint32 h = hfscx_32(tape ^ share ^ out_share);
    for (i = 0; i < ZKP_NL_N - 1; i++) h = hfscx_32(h ^ (uint32)gv[i]);
    return h;
}

/* F1(A,B) at 8 bits: FSCX_8(A,B) XOR ROL8((A+B) mod 256, 2). */
static uint32 zkp_nl_f1_8(uint32 A, uint32 B) {
    uint32 a = A & 0xFFu, b = B & 0xFFu;
    uint32 lin = (a ^ b ^ ((a<<1)|(a>>7)) ^ ((b<<1)|(b>>7))
                  ^ ((a>>1)|(a<<7)) ^ ((b>>1)|(b<<7))) & 0xFFu;
    uint32 s   = (a + b) & 0xFFu;
    return (lin ^ (((s<<2)|(s>>6)) & 0xFFu)) & 0xFFu;
}

/* 3-party ripple-carry evaluation of F1 at 8 bits.
   sh0^sh1^sh2=A (XOR shares); *o0^*o1^*o2=F1(A,B). */
static void zkp_eval(uint32 s0, uint32 s1, uint32 s2,
                     uint32 t0, uint32 t1, uint32 t2, uint32 B,
                     uint32 *o0, uint32 *o1, uint32 *o2,
                     uint8_t *gva, uint8_t *gvb, uint8_t *gvc) {
    uint32 sh[3] = { s0 & 0xFFu, s1 & 0xFFu, s2 & 0xFFu };
    uint32 tp[3] = { t0, t1, t2 };
    uint8_t *gv[3] = { gva, gvb, gvc };
    uint8_t carry[ZKP_NL_N + 1][3];
    int i, p;
    for (p = 0; p < 3; p++) carry[0][p] = 0;
    for (i = 0; i < ZKP_NL_N - 1; i++) {
        int Bi = (int)((B >> i) & 1u);
        int ai[3], ci[3], ri[3], ao[3];
        for (p = 0; p < 3; p++) {
            ai[p] = (int)((sh[p] >> i) & 1u);
            ci[p] = (int)(carry[i][p]);
            ri[p] = zkp_prg_bit(tp[p], i);
        }
        for (p = 0; p < 3; p++) {
            int p1 = (p + 1) % 3;
            ao[p] = (ai[p]&ci[p]) ^ (ai[p]&ci[p1]) ^ (ai[p1]&ci[p]) ^ ri[p] ^ ri[p1];
            gv[p][i] = (uint8_t)(ai[p] | (ci[p] << 1) | (ao[p] << 2));
        }
        for (p = 0; p < 3; p++)
            carry[i+1][p] = (uint8_t)((Bi & ai[p]) ^ ao[p] ^ (Bi & ci[p]));
    }
    uint32 sum_s[3] = { 0u, 0u, 0u };
    for (i = 0; i < ZKP_NL_N; i++) {
        int Bi = (int)((B >> i) & 1u);
        for (p = 0; p < 3; p++) {
            int sb = (int)((sh[p] >> i) & 1u) ^ Bi ^ (int)(carry[i][p]);
            sum_s[p] ^= (uint32)sb << i;
        }
    }
    uint32 Bc = (B ^ ((B<<1)|(B>>7)) ^ ((B>>1)|(B<<7))) & 0xFFu;
    uint32 out[3];
    for (p = 0; p < 3; p++) {
        uint32 rot = ((sum_s[p] << 2) | (sum_s[p] >> 6)) & 0xFFu;
        uint32 lin = (sh[p] ^ ((sh[p]<<1)|(sh[p]>>7)) ^ ((sh[p]>>1)|(sh[p]<<7))) & 0xFFu;
        if (p == 0) lin ^= Bc;
        out[p] = (lin ^ rot) & 0xFFu;
    }
    *o0 = out[0]; *o1 = out[1]; *o2 = out[2];
}

/* Prove knowledge of A such that F1(A,B)=y; proof stored in module statics. */
static void zkp_nl_prove_8(uint32 A, uint32 B, uint32 y, uint32 msg) {
    static uint32  all_sh[ZKP_NL_R][3], all_tp[ZKP_NL_R][3], all_out[ZKP_NL_R][3];
    static uint8_t all_gv[ZKP_NL_R][3][ZKP_NL_N - 1];
    int j, p, i;
    for (j = 0; j < ZKP_NL_R; j++) {
        uint32 s0 = lcg_next() & 0xFFu;
        uint32 s1 = lcg_next() & 0xFFu;
        uint32 s2 = (A ^ s0 ^ s1) & 0xFFu;
        all_sh[j][0] = s0; all_sh[j][1] = s1; all_sh[j][2] = s2;
        for (p = 0; p < 3; p++) all_tp[j][p] = lcg_next();
        zkp_eval(s0, s1, s2,
                 all_tp[j][0], all_tp[j][1], all_tp[j][2], B & 0xFFu,
                 &all_out[j][0], &all_out[j][1], &all_out[j][2],
                 all_gv[j][0], all_gv[j][1], all_gv[j][2]);
        for (p = 0; p < 3; p++)
            zkp_coms[j][p] = zkp_commit(all_tp[j][p], all_sh[j][p],
                                         all_out[j][p], all_gv[j][p]);
    }
    uint32 h = hfscx_32(msg ^ B ^ y);
    for (j = 0; j < ZKP_NL_R; j++)
        for (p = 0; p < 3; p++) h = hfscx_32(h ^ zkp_coms[j][p]);
    for (j = 0; j < ZKP_NL_R; j++) {
        h = hfscx_32(h ^ (uint32)j);
        zkp_e[j] = (uint8_t)(h % 3u);
    }
    for (j = 0; j < ZKP_NL_R; j++) {
        int e = (int)(zkp_e[j]);
        int p1 = (e + 1) % 3, p2 = (e + 2) % 3;
        zkp_sh1[j]  = all_sh[j][p1];  zkp_tp1[j]  = all_tp[j][p1];
        zkp_out1[j] = all_out[j][p1];
        zkp_sh2[j]  = all_sh[j][p2];  zkp_tp2[j]  = all_tp[j][p2];
        zkp_out2[j] = all_out[j][p2];
        for (i = 0; i < ZKP_NL_N - 1; i++) {
            zkp_gv1[j][i] = all_gv[j][p1][i];
            zkp_gv2[j][i] = all_gv[j][p2][i];
        }
    }
}

/* Verify ZKBoo proof from module statics. Returns 1=accept, 0=reject. */
static int zkp_nl_verify_8(uint32 B, uint32 y, uint32 msg) {
    int j;
    uint32 h = hfscx_32(msg ^ B ^ y);
    for (j = 0; j < ZKP_NL_R; j++)
        for (int p = 0; p < 3; p++) h = hfscx_32(h ^ zkp_coms[j][p]);
    for (j = 0; j < ZKP_NL_R; j++) {
        h = hfscx_32(h ^ (uint32)j);
        if ((uint8_t)(h % 3u) != zkp_e[j]) return 0;
    }
    for (j = 0; j < ZKP_NL_R; j++) {
        int e = (int)(zkp_e[j]);
        int p1 = (e + 1) % 3, p2 = (e + 2) % 3;
        if (zkp_commit(zkp_tp1[j], zkp_sh1[j], zkp_out1[j], zkp_gv1[j]) != zkp_coms[j][p1]) return 0;
        if (zkp_commit(zkp_tp2[j], zkp_sh2[j], zkp_out2[j], zkp_gv2[j]) != zkp_coms[j][p2]) return 0;
        uint8_t c1 = 0, c2 = 0;
        for (int i = 0; i < ZKP_NL_N - 1; i++) {
            int Bi   = (int)((B >> i) & 1u);
            int a1   = (int)((zkp_sh1[j] >> i) & 1u);
            int a2   = (int)((zkp_sh2[j] >> i) & 1u);
            int r1   = zkp_prg_bit(zkp_tp1[j], i);
            int r2   = zkp_prg_bit(zkp_tp2[j], i);
            int exp_ao1 = (a1&c1) ^ (a1&c2) ^ (a2&c1) ^ r1 ^ r2;
            if (((zkp_gv1[j][i] >> 2) & 1) != exp_ao1) return 0;
            c1 = (uint8_t)((Bi & a1) ^ exp_ao1 ^ (Bi & c1));
            int ao2 = (zkp_gv2[j][i] >> 2) & 1;
            c2 = (uint8_t)((Bi & a2) ^ ao2    ^ (Bi & c2));
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Fixed test vectors                                                  */
/* ------------------------------------------------------------------ */

const uint32 A_PRIV = 0xDEADBEEFUL;
const uint32 B_PRIV = 0xCAFEBABFUL;
const uint32 K      = 0x5A5A5A5AUL;
const uint32 PLAIN  = 0xDEADC0DEUL;

/* ------------------------------------------------------------------ */
/* 78.A — FPE at 32-bit: B = hfscx_32(hfscx_32(key) ^ context)       */
/* 78.B — Tweakable: B = hfscx_32(hfscx_32(key ^ sector) ^ bidx)     */
/* 78.J — Accumulator-32: leaf/node using hfscx_32                    */
/* 78.H — Masked HSKE-32: linearity masking for DPA resistance         */
/* 78.C — Ratchet-32: forward-secret state advance                    */
/* ------------------------------------------------------------------ */

static uint32 fpe_encrypt_32(uint32 pt, uint32 key, uint32 context) {
    uint32 B = hfscx_32(hfscx_32(key) ^ context);
    return nl_fscx_revolve_v2(pt, B, I_VALUE);
}
static uint32 fpe_decrypt_32(uint32 ct, uint32 key, uint32 context) {
    uint32 B = hfscx_32(hfscx_32(key) ^ context);
    return nl_fscx_revolve_v2_inv(ct, B, I_VALUE);
}

static uint32 twk_encrypt_32(uint32 block, uint32 key, uint32 sector, uint32 bidx) {
    uint32 B = hfscx_32(hfscx_32(key ^ sector) ^ bidx);
    return nl_fscx_revolve_v2(block, B, I_VALUE);
}
static uint32 twk_decrypt_32(uint32 block, uint32 key, uint32 sector, uint32 bidx) {
    uint32 B = hfscx_32(hfscx_32(key ^ sector) ^ bidx);
    return nl_fscx_revolve_v2_inv(block, B, I_VALUE);
}

/* 78.H: fscx_revolve_masked_32(A, B, mask, steps) */
static uint32 fscx_revolve_masked_32(uint32 A, uint32 B, uint32 mask, int steps) {
    uint32 fm = fscx_revolve(A ^ mask, B, steps);
    uint32 fz = fscx_revolve(mask,     0, steps);
    return fm ^ fz;
}
static uint32 hske_encrypt_masked_32(uint32 pt, uint32 key, uint32 mask) {
    return fscx_revolve_masked_32(pt, key, mask, I_VALUE);
}
static uint32 hske_decrypt_masked_32(uint32 ct, uint32 key, uint32 mask) {
    return fscx_revolve_masked_32(ct, key, mask, R_VALUE);
}

/* 78.C: 32-bit ratchet domain constant: 'N','L','-','F' */
static const uint32 RATCHET_DOMAIN_32 = 0x4E4C2D46UL;

static uint32 ratchet_advance_32(uint32 state, uint32 *msg_key_out) {
    *msg_key_out = nl_fscx_revolve_v1(state, 1, 1);
    return nl_fscx_revolve_v1(state, RATCHET_DOMAIN_32, 1);
}

/* Leaf: hfscx_32(0x00000000 ^ data); Node: hfscx_32(hfscx_32(0x01000000 ^ l) ^ r) */
static uint32 haccum_leaf_32(uint32 data)             { return hfscx_32(0x00000000UL ^ data); }
static uint32 haccum_node_32(uint32 left, uint32 right) { return hfscx_32(hfscx_32(0x01000000UL ^ left) ^ right); }
static uint32 haccum_root_32(const uint32 *leaves, int n) {
    /* power-of-2 pad; for small n only */
    uint32 nodes[16]; int sz = 1, i;
    while (sz < n && sz < 8) sz <<= 1;
    for (i = 0; i < n && i < sz; i++) nodes[i] = leaves[i];
    for (; i < sz; i++) nodes[i] = 0;
    while (sz > 1) {
        for (i = 0; i < sz / 2; i++) nodes[i] = haccum_node_32(nodes[2*i], nodes[2*i+1]);
        sz /= 2;
    }
    return nodes[0];
}

/* ------------------------------------------------------------------ */
/* OPRF (80) — 2HashDH OPRF over GF(2^32)* (DEMO n=32, TODO #80)     */
/* ORD = 2^32-1; r=7 coprime to ORD; r_inv = 7^{-1} mod ORD          */
/* ------------------------------------------------------------------ */

static uint32 oprf_hash_to_field_32(uint32 x) {
    uint32 h = hfscx_32(x);
    return h ? h : 1;   /* zero-guard: 0 -> 1 (negligible probability) */
}
/* Client blind: alpha = H(x)^r.  r_scalar returned so caller can unblind. */
static uint32 oprf_blind_32(uint32 x, uint32 r_scalar) {
    return gf_pow_32(oprf_hash_to_field_32(x), r_scalar);
}
/* Server eval: beta = alpha^k. */
static uint32 oprf_eval_32(uint32 alpha, uint32 k) {
    return gf_pow_32(alpha, k);
}
/* Client unblind: F = beta^{r_inv}.  r_inv must be r^{-1} mod (2^32-1). */
static uint32 oprf_unblind_32(uint32 beta, uint32 r_inv) {
    return gf_pow_32(beta, r_inv);
}
/* Direct PRF (server-side, non-oblivious): F = H(x)^k. */
static uint32 oprf_direct_32(uint32 x, uint32 k) {
    return gf_pow_32(oprf_hash_to_field_32(x), k);
}

/* ------------------------------------------------------------------ */
/* demo_finish: the TODO #350 [FAIL] gate at the end of each pass.     */
/* loop() repeats, so each pass is scored on its own.                 */
/* ------------------------------------------------------------------ */
static void demo_finish(void) {
    if (g_failures) {
        Serial.print(F("*** FAILED: "));
        Serial.print(g_failures);
        Serial.println(F(" check(s) reported [FAIL] ***"));
    } else {
        Serial.println(F("*** OK: no check reported [FAIL] ***"));
    }
    g_failures = 0;   /* loop() repeats; score each pass on its own */

    delay(10000);
}

#endif /* HERRADURA32_H */
