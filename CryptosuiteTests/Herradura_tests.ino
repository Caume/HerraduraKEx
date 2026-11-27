/*  Herradura KEx — Security Tests (Arduino, 32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, NL-FSCX, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL,
    HPKS-Stern-F, HPKE-Stern-F, HPKS-Stern-Ring, ZKP-NL, FPE, Tweakable cipher,
    Accumulator

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Any Arduino board with Serial support.
    Upload via Arduino IDE. Monitor at 9600 baud.

    v1.9.117: ported tests [13]-[17] from Herradura_tests.s/.asm (TODO #147),
    at the same reduced 32-bit parameters already used for the other tests.
      - [13] HPKS-Stern-Ring ring-sign+verify, k=2, N=32, rounds=4 (one Stern
        proof over the ring since TODO #424; was the OR-composition).
      - [14] ZKP-NL (NL-FSCX ZKBoo) prove+verify, n=8, R=4.
      - [15] FPE (78.A) encrypt/decrypt round-trip.
      - [16] Tweakable cipher (78.B) encrypt/decrypt round-trip.
      - [17] Accumulator (78.J) 4-leaf Merkle proof.
    v1.5.18: added Stern-F tests [11]-[12]. N=32, t=2, rounds=4.
      - [11] HPKS-Stern-F sign+verify correctness.
      - [12] HPKE-Stern-F encap+decap KEM correctness.
    v1.5.10: HKEX-RNL KDF seed fix: seed=ROL32(K,4); sk=nl_fscx_revolve_v1(seed,K,I).
    v1.5.7: m_inv_32 uses precomputed rotation table (0x6DB6DB6D) — replaces 15-step loop.
    v1.5.4: NTT-based negacyclic polynomial multiplication (O(N log N)).
    v1.5.3: HKEX-RNL secret sampler upgraded to CBD(eta=1); zero-mean distribution.
    v1.5.0: added PQC extension tests [5]-[10].
      - [5] NL-FSCX v2 inverse roundtrip.
      - [6] HSKE-NL-A2 revolve-mode correctness.
      - [7] HKEX-RNL key agreement (N=32).
      - [8] HPKS-NL Schnorr correctness (NL challenge).
      - [9] HPKE-NL encrypt+decrypt correctness.
      - [10] HPKS-NL Eve resistance.
    v1.4.0: HKEX-GF; Schnorr HPKS; El Gamal HPKE.
*/

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

#define GF_POLY32 0x00400007UL
#define GF_GEN    3UL

#define RNL_KDF_DC 0x6A09E667UL     /* NUMS domain constant for KDF seed (SHA-256 H0) */

#define RNL_N   32
#define RNL_Q   65537L
#define RNL_P   4096L
#define RNL_PP  4L
#define RNL_ETA 1  /* CBD eta: secret coeffs drawn from CBD(1) in {-1,0,1} mod q */

typedef unsigned long uint32;

/* ------------------------------------------------------------------ */
/* LCG PRNG                                                            */
/* ------------------------------------------------------------------ */

uint32 prng_state = 0x12345678UL;

/* TODO #234: the single point where a test's PASS/FAIL verdict reaches the
   UART.  Counting here rather than at each of the 18 call sites is what makes
   the gate survive a test being added later -- the AVR analogue of #233's
   `#define printf hprintf` in C.  Scanning the output stream would not work
   here: the marker is split across two Serial calls ("  [" then "FAIL]"), so
   the literal "[FAIL]" never appears in any single write. */
static int g_failures = 0;

static void verdict(bool ok) {
    if (!ok) g_failures++;
    Serial.println(ok ? "PASS]" : "FAIL]");
}

uint32 prng_next() {
    prng_state = prng_state * 1664525UL + 1013904223UL;
    return prng_state;
}

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
/* GF(2^32) arithmetic                                                */
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
/* NL-FSCX primitives (v1.5.0)                                        */
/* ------------------------------------------------------------------ */

/* M^{-1}(X) = XOR of ROL(X,k) for k in bits of 0x6DB6DB6D (n=32) */
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

uint32 nl_fscx_delta_v2(uint32 B) {
    uint32 raw = B * ((B + 1) >> 1);
    return (raw << 8) | (raw >> 24);
}

uint32 nl_fscx_v1(uint32 a, uint32 b) {
    uint32 s = a + b;
    return fscx(a, b) ^ ((s << 8) | (s >> 24));
}

uint32 nl_fscx_revolve_v1(uint32 a, uint32 b, int steps) {
    for (int i = 0; i < steps; i++) a = nl_fscx_v1(a, b);
    return a;
}

/* test copy of the suite's guard (TODO #169 item 2, #354) */
uint8_t nl_v2_key_is_valid(uint32 b) {
    /* valid iff arc(delta(B)) > n/4 = 8 (TODO #354): z = ~delta, and each pass
     * z &= ROL(z, 1) shortens every cyclic run of ones by one, so z survives the
     * 3n/4 - 1 = 23 passes iff delta has a zero run of 24 or more. */
    uint32 z = ~nl_fscx_delta_v2(b);
    for (uint8_t i = 0; i < 23; i++) z &= (z << 1) | (z >> 31);
    return z == 0;
}

uint32 nl_fscx_v2(uint32 a, uint32 b) {
    return fscx(a, b) + nl_fscx_delta_v2(b);
}

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
/* HKEX-RNL helpers                                                    */
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
static void rnl_poly_mul(long *h, const long *f, const long *g) {
    static long fa[RNL_N], ga[RNL_N], ha[RNL_N];
    uint32_t psi     = rnl_mod_pow(3, (RNL_Q - 1) / (2 * RNL_N), (uint32_t)RNL_Q);
    uint32_t psi_inv = rnl_mod_pow(psi, (uint32_t)(RNL_Q - 2), (uint32_t)RNL_Q);
    uint32_t pw = 1, pw_inv = 1;
    int i;
    for (i = 0; i < RNL_N; i++) {
        fa[i] = (long)((uint64_t)f[i] * pw % (uint32_t)RNL_Q);
        ga[i] = (long)((uint64_t)g[i] * pw % (uint32_t)RNL_Q);
        pw    = (uint32_t)((uint64_t)pw * psi % (uint32_t)RNL_Q);
    }
    rnl_ntt(fa, RNL_N, RNL_Q, 0);
    rnl_ntt(ga, RNL_N, RNL_Q, 0);
    for (i = 0; i < RNL_N; i++) ha[i] = (long)((uint64_t)fa[i] * ga[i] % (uint32_t)RNL_Q);
    rnl_ntt(ha, RNL_N, RNL_Q, 1);
    for (i = 0; i < RNL_N; i++) {
        h[i]   = (long)((uint64_t)ha[i] * pw_inv % (uint32_t)RNL_Q);
        pw_inv = (uint32_t)((uint64_t)pw_inv * psi_inv % (uint32_t)RNL_Q);
    }
}

static void rnl_poly_add(long *h, const long *f, const long *g) {
    for (int i = 0; i < RNL_N; i++) h[i] = (f[i] + g[i]) % RNL_Q;
}

static void rnl_round(long *out, const long *in, long from_q, long to_p) {
    for (int i = 0; i < RNL_N; i++)
        out[i] = (long)(((long long)in[i] * to_p + from_q / 2) / from_q % to_p);
}

static void rnl_lift(long *out, const long *in, long from_p, long to_q) {
    for (int i = 0; i < RNL_N; i++)
        out[i] = (long)(((long long)in[i] * to_q + from_p / 2) / from_p % to_q);
}

static void rnl_m_poly(long *p) {
    for (int i = 0; i < RNL_N; i++) p[i] = 0;
    p[0] = p[1] = p[RNL_N - 1] = 1;
}

/* CBD(eta=1): coeff = (raw&1) - ((raw>>1)&1), stored mod q. Zero-mean {-1,0,1}. */
static void rnl_cbd_poly(long *p) {
    for (int i = 0; i < RNL_N; i++) {
        uint32 raw = prng_next();
        int a = (int)(raw & 1);
        int b = (int)((raw >> 1) & 1);
        p[i] = (long)((a - b + (long)RNL_Q) % (long)RNL_Q);
    }
}

static void rnl_rand_poly(long *p) {
    static const uint32 threshold = 0xFF00FFu; /* (1<<24) - (1<<24)%RNL_Q */
    for (int i = 0; i < RNL_N; ) {
        uint32 v = prng_next() & 0xFFFFFFu;
        if (v < threshold) p[i++] = (long)(v % (uint32)RNL_Q);
    }
}

static uint32 rnl_bits_to_key(const long *bits_poly) {
    uint32 key = 0;
    for (int i = 0; i < RNL_N; i++)
        if (bits_poly[i] >= RNL_PP / 2)
            key |= (1UL << i);
    return key;
}

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
/* HPKS-Stern-F / HPKE-Stern-F helpers (v1.5.18, N=32, t=2)          */
/* ------------------------------------------------------------------ */

#define SDF_N      32
#define SDF_T      2
#define SDF_NROWS  16
#define SDF_ROUNDS 4

/* The suite's HFSCX-32 MMO chain, one word at a time (TODO #348, v12.0.0):
 * absorb(s, w) = nl(w, s, 24) ^ w from s = IV, then nl(LB, s, 24) ^ LB.  The
 * Stern hash is HFSCX-32(TAG|ds, items...).  Until v11.x this harness modelled
 * it as an NL-FSCX v1 chain with the item as v1's B and no domain tag. */
#define HFSCX32_STEPS 24             /* 3n/4 at n = 32 */
#define HFSCX32_IV    0xA3C5E7B9UL
#define HFSCX32_LB    0xA3C5E799UL
#define HPKS_NL32_TAG 0x30000000UL
#define STERN32_TAG   0x31000000UL
static uint32 hfscx32_absorb(uint32 s, uint32 w) {
    return nl_fscx_revolve_v1(w, s, HFSCX32_STEPS) ^ w;
}
static uint32 hfscx32_final(uint32 s) {
    return nl_fscx_revolve_v1(HFSCX32_LB, s, HFSCX32_STEPS) ^ HFSCX32_LB;
}
static uint32 hpks_nl_challenge_32(uint32 R, uint32 msg) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, HPKS_NL32_TAG);
    h = hfscx32_absorb(h, R);
    return hfscx32_final(hfscx32_absorb(h, msg));
}

static uint32 stern_hash1_32(uint32 ds, uint32 v) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, STERN32_TAG | ds);
    return hfscx32_final(hfscx32_absorb(h, v));
}

static uint32 stern_hash2_32(uint32 ds, uint32 a, uint32 b) {
    uint32 h = hfscx32_absorb(HFSCX32_IV, STERN32_TAG | ds);
    h = hfscx32_absorb(h, a);
    return hfscx32_final(hfscx32_absorb(h, b));
}

/* H[row] = HFSCX-32(v1(ROL(seed^row, 4), seed, 8)), as the suite and the ARM
 * and i386 harnesses: hfscx_32(x) = final(absorb(IV, x)).  This copy lacked the
 * HFSCX-32 finalization of TODO #88 until #424's pinned ring vector differed. */
static uint32 stern_matrix_row_32(uint32 seed, int row) {
    return hfscx32_final(hfscx32_absorb(HFSCX32_IV,
        nl_fscx_revolve_v1(_rol32(seed ^ (uint32)row, 4), seed, I_VALUE)));
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

static uint32 stern_apply_perm_32(const uint8_t *perm, uint32 v) {
    uint32 out = 0;
    for (int i = 0; i < SDF_N; i++)
        if ((v >> i) & 1) out |= (1UL << perm[i]);
    return out;
}

static uint32 stern_rand_error_32(void) {
    uint8_t idx[SDF_N];
    uint32 j;
    for (int i = 0; i < SDF_N; i++) idx[i] = (uint8_t)i;
    j = prng_next() % (uint32)SDF_N;
    { uint8_t t = idx[SDF_N-1]; idx[SDF_N-1] = idx[j]; idx[j] = t; }
    j = prng_next() % (uint32)(SDF_N - 1);
    { uint8_t t = idx[SDF_N-2]; idx[SDF_N-2] = idx[j]; idx[j] = t; }
    return (1UL << idx[SDF_N-1]) | (1UL << idx[SDF_N-2]);
}

typedef struct {
    uint32 c0[SDF_ROUNDS], c1[SDF_ROUNDS], c2[SDF_ROUNDS];
    uint32 b[SDF_ROUNDS];
    uint32 respA[SDF_ROUNDS];
    uint32 respB[SDF_ROUNDS];
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


/* Exact-weight-t test, factored out by TODO #298: the check now runs on
 * respA ^ respB rather than on respA alone. */
static int stern_wt_is_t_32(uint32 v) {
    if (!v) return 0;
    v &= v - 1; if (!v) return 0;
    v &= v - 1; return v == 0;
}

static void hpks_stern_f_sign_32(SternSig32 *sig, uint32 msg,
                                   uint32 e, uint32 seed) {
    static uint8_t perm[SDF_N];
    static uint32 r_tmp[SDF_ROUNDS],  y_tmp[SDF_ROUNDS];
    static uint32 pi_tmp[SDF_ROUNDS], sr_tmp[SDF_ROUNDS], sy_tmp[SDF_ROUNDS];
    for (int i = 0; i < SDF_ROUNDS; i++) {
        uint32 r  = prng_next();           /* UNIFORM since v8.0.0, TODO #298 */
        uint32 y  = e ^ r;
        uint32 pi = prng_next();
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
            /* wt(sigma(r) ^ sigma(y)) = wt(e) -- TODO #298 */
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
/* HPKS-Stern-Ring helpers (TODO #424; k=2, N=32, rounds=4): ONE      */
/* Stern proof over diag([H_0|s_0], [H_1|s_1]), the construction of   */
/* SPEC.md §11.2 -- a copy of the suite's, held to it by the pinned   */
/* vector in [13], which the ARM and i386 harnesses pin too.          */
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
        r[i][0] = prng_next(); r[i][1] = prng_next(); r[i][2] = prng_next() & 3u;
        ps[i] = prng_next(); s1[i] = prng_next(); s2[i] = prng_next();
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
/* ZKP-NL (NL-FSCX ZKBoo) helpers (n=8, rounds=4)                      */
/* 3-party MPC-in-the-head proof of knowledge of A s.t. F1(A,B) == y,  */
/* with a 32-bit XOR/rotate commit + PRG substituted for HFSCX-256     */
/* (same reduction already used by the Stern-F/Stern-Ring hashes).     */
/* ------------------------------------------------------------------ */

#define ZKPNL_N      8
#define ZKPNL_ROUNDS 4
#define ZKPNL_MASK   ((1UL << ZKPNL_N) - 1)

static uint32 zkpnl_rol(uint32 x, int r) {
    r = ((r % ZKPNL_N) + ZKPNL_N) % ZKPNL_N;
    x &= ZKPNL_MASK;
    return r ? ((x << r) | (x >> (ZKPNL_N - r))) & ZKPNL_MASK : x;
}

static uint32 zkpnl_commit_32(int j, int p, uint32 tape, uint32 out_share) {
    uint32 h = (uint32)j ^ ((uint32)p << 16) ^ tape;
    h = nl_fscx_revolve_v1(h, _rol32(tape, 4), I_VALUE);
    return nl_fscx_revolve_v1(h ^ out_share, _rol32(out_share, 4), I_VALUE);
}

static int zkpnl_prg_bit(uint32 tape, int gate_id) {
    uint32 h = nl_fscx_revolve_v1(tape ^ (uint32)gate_id,
                                   _rol32(tape, 4) ^ (uint32)gate_id, I_VALUE);
    return (int)(h & 1);
}

static uint32 zkpnl_f1(uint32 A, uint32 B) {
    uint32 lin = (A ^ B ^ zkpnl_rol(A, 1) ^ zkpnl_rol(B, 1)
                  ^ zkpnl_rol(A, ZKPNL_N - 1) ^ zkpnl_rol(B, ZKPNL_N - 1)) & ZKPNL_MASK;
    return (lin ^ zkpnl_rol((A + B) & ZKPNL_MASK, ZKPNL_N / 4)) & ZKPNL_MASK;
}

static void zkpnl_keygen_32(uint32 *A_out, uint32 *B_out, uint32 *y_out) {
    uint32 A = prng_next() & ZKPNL_MASK;
    uint32 B = prng_next() & ZKPNL_MASK;
    *A_out = A; *B_out = B; *y_out = zkpnl_f1(A, B);
}

/* 3-party ZKBoo evaluation of nl_fscx_v1(A, B) over the shares sh[0..2]. */
static void zkpnl_eval_3p(uint32 s0, uint32 s1, uint32 s2,
                           uint32 t0, uint32 t1, uint32 t2, uint32 B,
                           uint32 *out0, uint32 *out1, uint32 *out2,
                           uint8_t gv0[ZKPNL_N - 1], uint8_t gv1[ZKPNL_N - 1],
                           uint8_t gv2[ZKPNL_N - 1]) {
    uint32 sh[3] = { s0, s1, s2 };
    uint32 tp[3] = { t0, t1, t2 };
    uint8_t *gv[3] = { gv0, gv1, gv2 };
    uint32 carry[ZKPNL_N][3];
    int i, p;
    memset(carry, 0, sizeof(carry));

    for (i = 0; i < ZKPNL_N - 1; i++) {
        int Bi = (int)((B >> i) & 1);
        int ai[3], ci[3], ri[3], ao[3];
        for (p = 0; p < 3; p++) {
            ai[p] = (int)((sh[p] >> i) & 1); ci[p] = (int)carry[i][p];
            ri[p] = zkpnl_prg_bit(tp[p], i);
        }
        for (p = 0; p < 3; p++) {
            int p1 = (p + 1) % 3;
            ao[p] = (ai[p] & ci[p]) ^ (ai[p] & ci[p1]) ^ (ai[p1] & ci[p]) ^ ri[p] ^ ri[p1];
            gv[p][i] = (uint8_t)(ai[p] | (ci[p] << 1) | (ao[p] << 2));
        }
        for (p = 0; p < 3; p++)
            carry[i + 1][p] = (uint32)((Bi & ai[p]) ^ ao[p] ^ (Bi & ci[p]));
    }

    uint32 sum_s[3] = { 0, 0, 0 };
    for (i = 0; i < ZKPNL_N; i++) {
        int Bi = (int)((B >> i) & 1);
        for (p = 0; p < 3; p++) {
            int sb = (int)((sh[p] >> i) & 1) ^ Bi ^ (int)carry[i][p];
            sum_s[p] ^= (uint32)sb << i;
        }
    }

    uint32 rot_s[3], lin_s[3];
    uint32 Bc = (B ^ zkpnl_rol(B, 1) ^ zkpnl_rol(B, ZKPNL_N - 1)) & ZKPNL_MASK;
    for (p = 0; p < 3; p++) {
        rot_s[p] = zkpnl_rol(sum_s[p], ZKPNL_N / 4);
        lin_s[p] = (sh[p] ^ zkpnl_rol(sh[p], 1) ^ zkpnl_rol(sh[p], ZKPNL_N - 1)) & ZKPNL_MASK;
    }
    lin_s[0] ^= Bc;

    *out0 = (lin_s[0] ^ rot_s[0]) & ZKPNL_MASK;
    *out1 = (lin_s[1] ^ rot_s[1]) & ZKPNL_MASK;
    *out2 = (lin_s[2] ^ rot_s[2]) & ZKPNL_MASK;
}

typedef struct {
    uint32  com0, com1, com2;
    int     e;
    uint32  sh_p1, sh_p2, tp_p1, tp_p2, out_p1, out_p2;
    uint8_t gv_p1[ZKPNL_N - 1], gv_p2[ZKPNL_N - 1];
} ZkpNlRound32;

static void zkpnl_prove_32(ZkpNlRound32 *proof, uint32 A, uint32 B, uint32 y, uint32 msg) {
    uint32 s0[ZKPNL_ROUNDS], s1[ZKPNL_ROUNDS], s2[ZKPNL_ROUNDS];
    uint32 t0[ZKPNL_ROUNDS], t1[ZKPNL_ROUNDS], t2[ZKPNL_ROUNDS];
    uint32 out0[ZKPNL_ROUNDS], out1[ZKPNL_ROUNDS], out2[ZKPNL_ROUNDS];
    static uint8_t gv0[ZKPNL_ROUNDS][ZKPNL_N - 1], gv1[ZKPNL_ROUNDS][ZKPNL_N - 1],
                   gv2[ZKPNL_ROUNDS][ZKPNL_N - 1];
    uint32 com0[ZKPNL_ROUNDS], com1[ZKPNL_ROUNDS], com2[ZKPNL_ROUNDS];
    int j;

    for (j = 0; j < ZKPNL_ROUNDS; j++) {
        s0[j] = prng_next() & ZKPNL_MASK;
        s1[j] = prng_next() & ZKPNL_MASK;
        s2[j] = (A ^ s0[j] ^ s1[j]) & ZKPNL_MASK;
        t0[j] = prng_next(); t1[j] = prng_next(); t2[j] = prng_next();
        zkpnl_eval_3p(s0[j], s1[j], s2[j], t0[j], t1[j], t2[j], B,
                       &out0[j], &out1[j], &out2[j], gv0[j], gv1[j], gv2[j]);
        com0[j] = zkpnl_commit_32(j, 0, t0[j], out0[j]);
        com1[j] = zkpnl_commit_32(j, 1, t1[j], out1[j]);
        com2[j] = zkpnl_commit_32(j, 2, t2[j], out2[j]);
    }

    /* Fiat-Shamir seed over all commitments + public statement + message */
    uint32 seed = msg ^ B ^ y;
    for (j = 0; j < ZKPNL_ROUNDS; j++) {
        seed = nl_fscx_revolve_v1(seed ^ com0[j], _rol32(com0[j], 4), I_VALUE);
        seed = nl_fscx_revolve_v1(seed ^ com1[j], _rol32(com1[j], 4), I_VALUE);
        seed = nl_fscx_revolve_v1(seed ^ com2[j], _rol32(com2[j], 4), I_VALUE);
    }

    for (j = 0; j < ZKPNL_ROUNDS; j++) {
        uint32 h = nl_fscx_v1(seed, (uint32)j);
        int e = (int)(h % 3), p1 = (e + 1) % 3, p2 = (e + 2) % 3;
        uint32 sh_arr[3]  = { s0[j], s1[j], s2[j] };
        uint32 tp_arr[3]  = { t0[j], t1[j], t2[j] };
        uint32 out_arr[3] = { out0[j], out1[j], out2[j] };
        uint8_t *gv_arr[3] = { gv0[j], gv1[j], gv2[j] };

        proof[j].com0 = com0[j]; proof[j].com1 = com1[j]; proof[j].com2 = com2[j];
        proof[j].e = e;
        proof[j].sh_p1  = sh_arr[p1];  proof[j].sh_p2  = sh_arr[p2];
        proof[j].tp_p1  = tp_arr[p1];  proof[j].tp_p2  = tp_arr[p2];
        proof[j].out_p1 = out_arr[p1]; proof[j].out_p2 = out_arr[p2];
        memcpy(proof[j].gv_p1, gv_arr[p1], ZKPNL_N - 1);
        memcpy(proof[j].gv_p2, gv_arr[p2], ZKPNL_N - 1);
    }
}

static int zkpnl_verify_32(const ZkpNlRound32 *proof, uint32 B, uint32 y, uint32 msg) {
    uint32 seed = msg ^ B ^ y;
    int j;
    for (j = 0; j < ZKPNL_ROUNDS; j++) {
        seed = nl_fscx_revolve_v1(seed ^ proof[j].com0, _rol32(proof[j].com0, 4), I_VALUE);
        seed = nl_fscx_revolve_v1(seed ^ proof[j].com1, _rol32(proof[j].com1, 4), I_VALUE);
        seed = nl_fscx_revolve_v1(seed ^ proof[j].com2, _rol32(proof[j].com2, 4), I_VALUE);
    }
    for (j = 0; j < ZKPNL_ROUNDS; j++) {
        uint32 h = nl_fscx_v1(seed, (uint32)j);
        int e = (int)(h % 3);
        if (e != proof[j].e) return 0;
        int p1 = (e + 1) % 3, p2 = (e + 2) % 3;

        uint32 c_p1 = zkpnl_commit_32(j, p1, proof[j].tp_p1, proof[j].out_p1);
        uint32 c_p2 = zkpnl_commit_32(j, p2, proof[j].tp_p2, proof[j].out_p2);
        uint32 coms[3] = { proof[j].com0, proof[j].com1, proof[j].com2 };
        if (c_p1 != coms[p1] || c_p2 != coms[p2]) return 0;

        int carry_p1 = 0, carry_p2 = 0, i;
        for (i = 0; i < ZKPNL_N - 1; i++) {
            int ai_p1 = (int)((proof[j].sh_p1 >> i) & 1), ai_p2 = (int)((proof[j].sh_p2 >> i) & 1);
            int ci_p1 = carry_p1, ci_p2 = carry_p2;
            int Bi    = (int)((B >> i) & 1);
            int ri_p1 = zkpnl_prg_bit(proof[j].tp_p1, i), ri_p2 = zkpnl_prg_bit(proof[j].tp_p2, i);

            int exp_ao_p1 = (ai_p1 & ci_p1) ^ (ai_p1 & ci_p2) ^ (ai_p2 & ci_p1) ^ ri_p1 ^ ri_p2;
            if (((proof[j].gv_p1[i] >> 2) & 1) != exp_ao_p1) return 0;

            carry_p1 = (Bi & ai_p1) ^ exp_ao_p1 ^ (Bi & ci_p1);
            int ao_p2 = (proof[j].gv_p2[i] >> 2) & 1;
            carry_p2 = (Bi & ai_p2) ^ ao_p2 ^ (Bi & ci_p2);
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* FPE (78.A) helpers — bijective encryption via nl_fscx_revolve_v2    */
/* with a tweak B derived from (key, context).                        */
/* ------------------------------------------------------------------ */

static uint32 fpe_derive_b_32(uint32 key, uint32 ctx) {
    return nl_fscx_revolve_v1(key ^ ctx, _rol32(key, 4) ^ ctx, I_VALUE);
}

static uint32 fpe_encrypt_32(uint32 pt, uint32 key, uint32 ctx) {
    uint32 B = fpe_derive_b_32(key, ctx);
    return nl_fscx_revolve_v2(pt, B, I_VALUE);
}

static uint32 fpe_decrypt_32(uint32 ct, uint32 key, uint32 ctx) {
    uint32 B = fpe_derive_b_32(key, ctx);
    return nl_fscx_revolve_v2_inv(ct, B, I_VALUE);
}

/* ------------------------------------------------------------------ */
/* Tweakable wide-block cipher (78.B) helpers — per-(sector,block)     */
/* tweak B, so identical plaintext blocks encrypt differently.        */
/* ------------------------------------------------------------------ */

static uint32 twk_derive_b_32(uint32 key, uint32 sector, uint32 bidx) {
    uint32 mix = key ^ sector ^ _rol32(bidx, 4);
    return nl_fscx_revolve_v1(mix, _rol32(mix, 4), I_VALUE);
}

static uint32 twk_encrypt_32(uint32 block, uint32 key, uint32 sector, uint32 bidx) {
    uint32 B = twk_derive_b_32(key, sector, bidx);
    return nl_fscx_revolve_v2(block, B, I_VALUE);
}

static uint32 twk_decrypt_32(uint32 ct, uint32 key, uint32 sector, uint32 bidx) {
    uint32 B = twk_derive_b_32(key, sector, bidx);
    return nl_fscx_revolve_v2_inv(ct, B, I_VALUE);
}

/* ------------------------------------------------------------------ */
/* Cryptographic Accumulator (78.J) helpers — 4-leaf Merkle tree with  */
/* domain-separated leaf/node mixing (0x00/0x01, RFC 6962 convention). */
/* ------------------------------------------------------------------ */

static uint32 haccum_leaf_32(uint32 data) {
    return nl_fscx_revolve_v1(data ^ 0x00u, _rol32(data, 4), I_VALUE);
}

static uint32 haccum_node_32(uint32 left, uint32 right) {
    uint32 h = nl_fscx_revolve_v1(left ^ 0x01u, _rol32(left, 4), I_VALUE);
    return nl_fscx_revolve_v1(h ^ right, _rol32(right, 4), I_VALUE);
}

/* ------------------------------------------------------------------ */
/* Test functions — classical [1-4]                                    */
/* ------------------------------------------------------------------ */

void test_hkex_gf() {
    Serial.println("[1] HKEX-GF correctness: g^{ab} == g^{ba}  [CLASSICAL]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a = prng_next() | 1;
        uint32 b = prng_next() | 1;
        uint32 C   = gf_pow_32(GF_GEN, a);
        uint32 C2  = gf_pow_32(GF_GEN, b);
        uint32 skA = gf_pow_32(C2, a);
        uint32 skB = gf_pow_32(C,  b);
        if (skA == skB) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

void test_hske() {
    Serial.println("[2] HSKE symmetric encryption correctness  [CLASSICAL]");
    int pass = 0;
    for (int i = 0; i < 100; i++) {
        uint32 p   = prng_next();
        uint32 key = prng_next();
        uint32 enc = fscx_revolve(p,   key, I_VALUE);
        uint32 dec = fscx_revolve(enc, key, R_VALUE);
        if (dec == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 100 passed  [");
    verdict(pass == 100);
    Serial.println();
}

void test_hpks() {
    Serial.println("[3] HPKS Schnorr correctness: g^s*C^e == R  [CLASSICAL]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a  = prng_next() | 1;
        uint32 p  = prng_next();
        uint32 k  = prng_next();
        uint32 C  = gf_pow_32(GF_GEN, a);
        uint32 R  = gf_pow_32(GF_GEN, k);
        uint32 e  = fscx_revolve(R, p, I_VALUE);
        uint64_t ae = ((uint64_t)a * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s  = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs = gf_pow_32(GF_GEN, s);
        uint32 Ce = gf_pow_32(C, e);
        if (gf_mul_32(gs, Ce) == R) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

void test_hpke() {
    Serial.println("[4] HPKE El Gamal encrypt+decrypt: D == P  [CLASSICAL]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a       = prng_next() | 1;
        uint32 p       = prng_next();
        uint32 r       = prng_next() | 1;
        uint32 C       = gf_pow_32(GF_GEN, a);
        uint32 R       = gf_pow_32(GF_GEN, r);
        uint32 enc_key = gf_pow_32(C, r);
        uint32 E       = fscx_revolve(p, enc_key, I_VALUE);
        uint32 dec_key = gf_pow_32(R, a);
        uint32 D       = fscx_revolve(E, dec_key, R_VALUE);
        if (D == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

/* ------------------------------------------------------------------ */
/* Test functions — PQC extension [5-10]                              */
/* ------------------------------------------------------------------ */

void test_nl_fscx_v2_inverse() {
    Serial.println("[5] NL-FSCX v2 inverse roundtrip: nl_v2_inv(nl_v2(A,B),B) == A  [PQC-EXT]");
    int pass = 0;
    for (int i = 0; i < 50; i++) {
        uint32 a = prng_next();
        uint32 b = prng_next();
        if (nl_fscx_v2_inv(nl_fscx_v2(a, b), b) == a) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 50 passed  [");
    verdict(pass == 50);
    Serial.println();
}

void test_hske_nl_a2() {
    Serial.println("[6] HSKE-NL-A2 revolve-mode: nl_v2_inv_revolve(nl_v2_revolve(P,K,r),K,r)==P  [PQC-EXT]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 p = prng_next();
        uint32 k = prng_next();
        uint32 E = nl_fscx_revolve_v2(p, k, R_VALUE);
        uint32 D = nl_fscx_revolve_v2_inv(E, k, R_VALUE);
        if (D == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

void test_hkex_rnl() {
    Serial.println("[7] HKEX-RNL key agreement: KA == KB  [PQC-EXT]");
    static long m_base[RNL_N], a_rand[RNL_N], m_blind[RNL_N];
    static long s_A[RNL_N], s_B[RNL_N], C_A[RNL_N], C_B[RNL_N];
    int ok_raw = 0, ok_sk = 0;
    int trials = 10;
    for (int t = 0; t < trials; t++) {
        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, C_A, m_blind);
        rnl_keygen(s_B, C_B, m_blind);
        uint32 hint_A;
        uint32 KA = rnl_agree(s_A, C_B, NULL, &hint_A);   /* reconciler */
        uint32 KB = rnl_agree(s_B, C_A, &hint_A, NULL);   /* receiver */
        if (KA == KB) {
            ok_raw++;
            uint32 skA = nl_fscx_revolve_v1(_rol32(KA, 4) ^ RNL_KDF_DC, KA, I_VALUE);
            uint32 skB = nl_fscx_revolve_v1(_rol32(KB, 4) ^ RNL_KDF_DC, KB, I_VALUE);
            if (skA == skB) ok_sk++;
        }
    }
    Serial.print("    raw agree="); Serial.print(ok_raw);
    Serial.print("/"); Serial.print(trials);
    Serial.print("  sk agree="); Serial.print(ok_sk);
    Serial.print("/"); Serial.print(trials);
    /* TODO #234: this used to pass at >= 80% raw agreement, on the theory
       that Ring-LWR rounding noise costs a trial now and then, and it never
       looked at ok_sk at all -- so a run could print "sk agree=0/10" and
       still pass.  Peikert reconciliation carries an explicit hint bit, and
       1,000,000 trials of the same n=32 construction (measured on the ARM
       harness) produced no disagreement at all: DFR <= 3e-6 at 95%.  The
       slack was hiding a silent statistic, not absorbing real noise. */
    Serial.print("  [");
    verdict(ok_raw == trials && ok_sk == trials);
    Serial.println();
}

void test_hpks_nl() {
    Serial.println("[8] HPKS-NL Schnorr correctness: g^s*C^e == R (NL challenge)  [PQC-EXT]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a  = prng_next() | 1;
        uint32 p  = prng_next();
        uint32 k  = prng_next();
        uint32 C  = gf_pow_32(GF_GEN, a);
        uint32 R  = gf_pow_32(GF_GEN, k);
        uint32 e  = hpks_nl_challenge_32(R, p);  /* NL challenge (TODO #348) */
        uint64_t ae = ((uint64_t)a * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s  = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs = gf_pow_32(GF_GEN, s);
        uint32 Ce = gf_pow_32(C, e);
        if (gf_mul_32(gs, Ce) == R) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

void test_hpke_nl() {
    Serial.println("[9] HPKE-NL encrypt+decrypt: D == P (NL-FSCX v2)  [PQC-EXT]");
    int pass = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a       = prng_next() | 1;
        uint32 p       = prng_next();
        uint32 r       = prng_next() | 1;
        uint32 C       = gf_pow_32(GF_GEN, a);
        uint32 R       = gf_pow_32(GF_GEN, r);
        uint32 enc_key = gf_pow_32(C, r);
        uint32 E       = nl_fscx_revolve_v2(p, enc_key, I_VALUE);
        uint32 dec_key = gf_pow_32(R, a);
        uint32 D       = nl_fscx_revolve_v2_inv(E, dec_key, I_VALUE);
        if (D == p) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    verdict(pass == 20);
    Serial.println();
}

void test_hpks_nl_eve() {
    Serial.println("[10] HPKS-NL Eve resistance: random forgery fails  [PQC-EXT]");
    int wins = 0;
    for (int i = 0; i < 20; i++) {
        uint32 a     = prng_next() | 1;
        uint32 C     = gf_pow_32(GF_GEN, a);
        uint32 decoy = prng_next();
        uint32 R_eve = gf_pow_32(GF_GEN, prng_next());
        uint32 e_eve = hpks_nl_challenge_32(R_eve, decoy);
        uint32 s_eve = prng_next();
        uint32 gs    = gf_pow_32(GF_GEN, s_eve);
        uint32 Ce    = gf_pow_32(C, e_eve);
        if (gf_mul_32(gs, Ce) == R_eve) wins++;
    }
    Serial.print("    "); Serial.print(wins); Serial.print(" / 20 Eve wins (expected 0)  [");
    verdict(wins == 0);
    Serial.println();
}

/* ------------------------------------------------------------------ */
/* Test functions — Stern-F [11-12]                                   */
/* ------------------------------------------------------------------ */

void test_hpks_stern_f() {
    Serial.println("[11] HPKS-Stern-F sign+verify correctness (N=32, t=2, rounds=4)  [PQC-STERN]");
    int pass = 0;
    for (int t = 0; t < 5; t++) {
        uint32 seed = prng_next();
        uint32 e    = stern_rand_error_32();
        uint32 synd = stern_syndrome_32(seed, e);
        uint32 msg  = prng_next();
        static SternSig32 sig;
        hpks_stern_f_sign_32(&sig, msg, e, seed);
        if (hpks_stern_f_verify_32(&sig, msg, seed, synd)) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 5 passed  [");
    verdict(pass == 5);
    Serial.println();
}

void test_hpke_stern_f() {
    Serial.println("[12] HPKE-Stern-F encap+decap: K_enc == K_dec  [PQC-STERN]");
    int pass = 0;
    for (int t = 0; t < 5; t++) {
        uint32 seed = prng_next();
        uint32 e_p, ct;
        uint32 K_enc = hpke_stern_f_encap_32(seed, &ct, &e_p);
        uint32 K_dec = hpke_stern_f_decap_32(seed, e_p);
        if (K_enc == K_dec) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 5 passed  [");
    verdict(pass == 5);
    Serial.println();
}

/* ------------------------------------------------------------------ */
/* Test functions — Stern-Ring / ZKP-NL / FPE / Tweakable / Accum      */
/* [13-17]                                                             */
/* ------------------------------------------------------------------ */

/* [13]: per trial an accept-control (sign, verify, and verify with the ring
 * in the other order), then three refusals of the same signature: one changed
 * opening word, another message, and a signature made with a wrong secret.
 * The last is exact: a wrong witness still in S passes every b=0 and b=1
 * round, so it is refused iff some round drew b=2; with no b=2 round it is
 * reported n/a, never as a pass or a fail.  Then the pinned vector: from
 * prng_state = 0x52494E47 two keys, a signature by member 1 of 0x4D534721,
 * its digest D and the XOR of every signature word (all three 32-bit ports). */
static uint32 ring_fold_32(const SternRing32 *s) {
    uint32 x = s->D;
    for (int i = 0; i < SDF_ROUNDS; i++)
        for (int q = 0; q < RING_RW; q++) x ^= s->rw[i][q];
    return x;
}

void test_hpks_stern_ring() {
    Serial.println(F("[13] HPKS-Stern-Ring: one Stern proof over a k=2 ring, sign/verify and refusals (3 trials, N=32, rounds=4)  [PQC-STERN]"));
    static SternRing32 rsig, wsig;
    int acc = 0, ref = 0, ws_ref = 0, ws_na = 0, ws_bad = 0, kat_ok;
    for (int t = 0; t < 3; t++) {
        uint32 sa = prng_next(), ea = stern_rand_error_32();
        uint32 sb = prng_next(), eb = stern_rand_error_32();
        uint32 ya = stern_syndrome_32(sa, ea), yb = stern_syndrome_32(sb, eb);
        uint32 msg = prng_next(), e2, b[SDF_ROUNDS];
        int j = t % RING_K, has2 = 0;
        if (hpks_stern_ring_sign_32(&rsig, msg, j ? eb : ea, j, sa, ya, sb, yb)
            && hpks_stern_ring_verify_32(&rsig, msg, sa, ya, sb, yb)
            && hpks_stern_ring_verify_32(&rsig, msg, sb, yb, sa, ya)) acc++;
        rsig.rw[t][3] ^= 1u << t;
        int r1 = !hpks_stern_ring_verify_32(&rsig, msg, sa, ya, sb, yb);
        rsig.rw[t][3] ^= 1u << t;
        int r2 = !hpks_stern_ring_verify_32(&rsig, msg ^ 1u, sa, ya, sb, yb);
        if (r1 && r2) ref++;
        do e2 = stern_rand_error_32(); while (e2 == (j ? eb : ea));
        hpks_stern_ring_sign_32(&wsig, msg, e2, j, sa, ya, sb, yb);
        ring_challenges_32(wsig.D, b);
        for (int i = 0; i < SDF_ROUNDS; i++) if (b[i] == 2) has2 = 1;
        if (!hpks_stern_ring_verify_32(&wsig, msg, sa, ya, sb, yb)) ws_ref++;
        else if (has2) ws_bad++;
        else ws_na++;
    }
    {
        /* Not restored afterwards: this harness never reseeds (no entropy on
         * an AVR), so its stream is one fixed vector either way. */
        prng_state = 0x52494E47UL;
        uint32 sa = prng_next(), ea = stern_rand_error_32();
        uint32 sb = prng_next(), eb = stern_rand_error_32();
        uint32 ya = stern_syndrome_32(sa, ea), yb = stern_syndrome_32(sb, eb);
        kat_ok = hpks_stern_ring_sign_32(&rsig, 0x4D534721UL, eb, 1, sa, ya, sb, yb)
              && rsig.D == 0x4FB8B39FUL && ring_fold_32(&rsig) == 0x2E765CEFUL
              && hpks_stern_ring_verify_32(&rsig, 0x4D534721UL, sa, ya, sb, yb);
    }
    Serial.print(F("    ")); Serial.print(acc); Serial.print(F(" / 3 ring-verified (either order), "));
    Serial.print(ref); Serial.println(F(" / 3 refused a changed word and another message"));
    Serial.print(F("    wrong secret: ")); Serial.print(ws_ref); Serial.print(F(" refused, "));
    Serial.print(ws_na); Serial.print(F(" n/a (no b=2 round), ")); Serial.print(ws_bad);
    Serial.println(F(" accepted with a b=2 round"));
    Serial.print(F("    pinned vector (D = 4fb8b39f): ")); Serial.print(kat_ok ? F("matches") : F("DIFFERS"));
    Serial.print(F("  ["));
    verdict(acc == 3 && ref == 3 && ws_bad == 0 && kat_ok);
    Serial.println();
}

void test_zkp_nl() {
    Serial.println("[14] ZKP-NL (NL-FSCX ZKBoo): prove+verify (3 trials, n=8, R=4)  [PQC-EXT]");
    int pass = 0;
    for (int t = 0; t < 3; t++) {
        uint32 A, B, y;
        zkpnl_keygen_32(&A, &B, &y);
        uint32 msg = prng_next();
        static ZkpNlRound32 proof[ZKPNL_ROUNDS];
        zkpnl_prove_32(proof, A, B, y, msg);
        if (zkpnl_verify_32(proof, B, y, msg)) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 3 zk-verified  [");
    verdict(pass == 3);
    Serial.println();
}

void test_fpe() {
    Serial.println("[15] FPE (78.A): encrypt/decrypt round-trip (3 trials)  [NEW]");
    int pass = 0;
    for (int t = 0; t < 3; t++) {
        uint32 pt  = prng_next();
        uint32 key = prng_next();
        uint32 ctx = prng_next();
        uint32 ct  = fpe_encrypt_32(pt, key, ctx);
        uint32 dec = fpe_decrypt_32(ct, key, ctx);
        if (dec == pt) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 3 round-trips correct  [");
    verdict(pass == 3);
    Serial.println();
}

void test_tweakable() {
    Serial.println("[16] Tweakable cipher (78.B): encrypt/decrypt round-trip (3 trials)  [NEW]");
    int pass = 0;
    for (int t = 0; t < 3; t++) {
        uint32 block  = prng_next();
        uint32 key    = prng_next();
        uint32 sector = prng_next();
        uint32 bidx   = (uint32)t;
        uint32 ct  = twk_encrypt_32(block, key, sector, bidx);
        uint32 dec = twk_decrypt_32(ct, key, sector, bidx);
        if (dec == block) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 3 round-trips correct  [");
    verdict(pass == 3);
    Serial.println();
}

void test_accumulator() {
    Serial.println("[17] Accumulator (78.J): 4-leaf Merkle proof (1 trial)  [NEW]");
    uint32 leaves[4], leafh[4];
    for (int i = 0; i < 4; i++) {
        leaves[i] = prng_next();
        leafh[i]  = haccum_leaf_32(leaves[i]);
    }
    uint32 n01  = haccum_node_32(leafh[0], leafh[1]);
    uint32 n23  = haccum_node_32(leafh[2], leafh[3]);
    uint32 root = haccum_node_32(n01, n23);

    int idx = 2;                    /* prove membership of leaf 2 */
    uint32 path[2] = { leafh[3], n01 };
    uint32 cur = leafh[idx];
    int cidx = idx;
    for (int d = 0; d < 2; d++) {
        cur = (cidx % 2 == 0) ? haccum_node_32(cur, path[d])
                               : haccum_node_32(path[d], cur);
        cidx >>= 1;
    }
    int ok = (cur == root);
    Serial.print("    "); Serial.print(ok ? 1 : 0); Serial.print(" / 1 proof correct  [");
    verdict(ok);
    Serial.println();
}

void test_v2_weak_key_reject() {
    Serial.println("[18] v2_weak_key_reject: NL-FSCX v2 short-arc weak-key screen (n=32, 1 trial)  [NEW]");
    int ok = nl_v2_key_is_valid(0x5A5A5A5AUL)     /* accept-control: ordinary key, arc 30 */
             && nl_v2_key_is_valid(0xB8C5D000UL)  /* accept-control: arc 9, just above n/4 (#354) */
             && !nl_v2_key_is_valid(0x00020000UL) /* 2^17: delta(K)=0 at n=32 (TODO #169) */
             && !nl_v2_key_is_valid(1UL)          /* B = 1: delta = 2^8, arc 1 (#354) */
             && !nl_v2_key_is_valid(0x5CF46C00UL);/* arc 8 = n/4: refused (#354) */
    Serial.print("    "); Serial.print(ok ? 1 : 0); Serial.print(" / 1 weak-key checks correct  [");
    verdict(ok);
    Serial.println();
}

/* ------------------------------------------------------------------ */
/* Arduino entry points                                                */
/* ------------------------------------------------------------------ */

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    Serial.println("=== Herradura KEx - Security Tests (Arduino, 32-bit) ===");
    Serial.println();

    test_hkex_gf();
    test_hske();
    test_hpks();
    test_hpke();
    test_nl_fscx_v2_inverse();
    test_hske_nl_a2();
    test_hkex_rnl();
    test_hpks_nl();
    test_hpke_nl();
    test_hpks_nl_eve();
    test_hpks_stern_f();
    test_hpke_stern_f();
    test_hpks_stern_ring();
    test_zkp_nl();
    test_fpe();
    test_tweakable();
    test_accumulator();
    test_v2_weak_key_reject();

    /* TODO #234: the firmware never exits -- simavr runs it under `timeout`
       and run_arduino.sh discards the status -- so the gate has to travel out
       over the UART.  run_arduino.sh fails the job on a FAILED line, and also
       on the OK line never arriving, which is what a hang or a reset before
       the end of a pass looks like. */
    if (g_failures) {
        Serial.print(F("*** FAILED: "));
        Serial.print(g_failures);
        Serial.println(F(" check(s) reported [FAIL] ***"));
    } else {
        Serial.println(F("*** OK: no check reported [FAIL] ***"));
    }
    g_failures = 0;   /* loop() repeats; score each pass on its own */

    delay(30000);
}
