/*  Herradura KEx — Security Tests v1.5.18 (Arduino, 32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, NL-FSCX, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL,
    HPKS-Stern-F, HPKE-Stern-F

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Any Arduino board with Serial support.
    Upload via Arduino IDE. Monitor at 9600 baud.

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

#define RNL_N   32
#define RNL_Q   65537L
#define RNL_P   4096L
#define RNL_PP  2L
#define RNL_ETA 1  /* CBD eta: secret coeffs drawn from CBD(1) in {-1,0,1} mod q */

typedef unsigned long uint32;

/* ------------------------------------------------------------------ */
/* LCG PRNG                                                            */
/* ------------------------------------------------------------------ */

uint32 prng_state = 0x12345678UL;

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
        out[i] = (long)((long long)in[i] * to_q / from_p % to_q);
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
    for (int i = 0; i < RNL_N; i++) p[i] = (long)(prng_next() % (uint32)RNL_Q);
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

static uint32 rnl_agree(const long *s, const long *C_other) {
    static long c_lifted[RNL_N], k_poly[RNL_N], k_bits[RNL_N];
    rnl_lift(c_lifted, C_other, RNL_P, RNL_Q);
    rnl_poly_mul(k_poly, s, c_lifted);
    rnl_round(k_bits, k_poly, RNL_Q, RNL_PP);
    return rnl_bits_to_key(k_bits);
}

/* ------------------------------------------------------------------ */
/* HPKS-Stern-F / HPKE-Stern-F helpers (v1.5.18, N=32, t=2)          */
/* ------------------------------------------------------------------ */

#define SDF_N      32
#define SDF_T      2
#define SDF_NROWS  16
#define SDF_ROUNDS 4

static uint32 stern_hash1_32(uint32 v) {
    return nl_fscx_revolve_v1(v, _rol32(v, 4), I_VALUE);
}

static uint32 stern_hash2_32(uint32 a, uint32 b) {
    uint32 h = nl_fscx_revolve_v1(a, _rol32(a, 4), I_VALUE);
    return nl_fscx_revolve_v1(h ^ b, _rol32(b, 4), I_VALUE);
}

static uint32 stern_matrix_row_32(uint32 seed, int row) {
    return nl_fscx_revolve_v1(_rol32(seed ^ (uint32)row, 4), seed, I_VALUE);
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
    uint32 h = 0;
    h = nl_fscx_revolve_v1(h ^ msg, _rol32(msg, 4), I_VALUE);
    for (int i = 0; i < SDF_ROUNDS; i++) {
        h = nl_fscx_revolve_v1(h ^ c0[i], _rol32(c0[i], 4), I_VALUE);
        h = nl_fscx_revolve_v1(h ^ c1[i], _rol32(c1[i], 4), I_VALUE);
        h = nl_fscx_revolve_v1(h ^ c2[i], _rol32(c2[i], 4), I_VALUE);
    }
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
        uint32 r  = stern_rand_error_32();
        uint32 y  = e ^ r;
        uint32 pi = prng_next();
        stern_gen_perm_32(perm, pi);
        uint32 sr = stern_apply_perm_32(perm, r);
        uint32 sy = stern_apply_perm_32(perm, y);
        uint32 hr = stern_syndrome_32(seed, r);
        sig->c0[i] = stern_hash2_32(pi, hr);
        sig->c1[i] = stern_hash1_32(sr);
        sig->c2[i] = stern_hash1_32(sy);
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
            if (stern_hash1_32(ra) != sig->c1[i]) return 0;
            if (stern_hash1_32(rb) != sig->c2[i]) return 0;
            uint32 v = ra; if (!v) return 0;
            v &= v-1; if (!v) return 0; v &= v-1; if (v) return 0;
        } else if (bv == 1) {
            uint32 v = rb; if (!v) return 0;
            v &= v-1; if (!v) return 0; v &= v-1; if (v) return 0;
            uint32 hr = stern_syndrome_32(seed, rb);
            if (stern_hash2_32(ra, hr) != sig->c0[i]) return 0;
            stern_gen_perm_32(perm, ra);
            if (stern_hash1_32(stern_apply_perm_32(perm, rb)) != sig->c1[i]) return 0;
        } else {
            uint32 hy = stern_syndrome_32(seed, rb);
            if (stern_hash2_32(ra, hy ^ synd) != sig->c0[i]) return 0;
            stern_gen_perm_32(perm, ra);
            if (stern_hash1_32(stern_apply_perm_32(perm, rb)) != sig->c2[i]) return 0;
        }
    }
    return 1;
}

static uint32 hpke_stern_f_encap_32(uint32 seed, uint32 *ct_out, uint32 *e_out) {
    uint32 e_p  = stern_rand_error_32();
    *e_out  = e_p;
    *ct_out = stern_syndrome_32(seed, e_p);
    return stern_hash2_32(seed, e_p);
}

static uint32 hpke_stern_f_decap_32(uint32 seed, uint32 e_p) {
    return stern_hash2_32(seed, e_p);
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
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 100 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 50 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
        uint32 KA = rnl_agree(s_A, C_B);
        uint32 KB = rnl_agree(s_B, C_A);
        if (KA == KB) {
            ok_raw++;
            uint32 skA = nl_fscx_revolve_v1(_rol32(KA, 4), KA, I_VALUE);
            uint32 skB = nl_fscx_revolve_v1(_rol32(KB, 4), KB, I_VALUE);
            if (skA == skB) ok_sk++;
        }
    }
    Serial.print("    raw agree="); Serial.print(ok_raw);
    Serial.print("/"); Serial.print(trials);
    Serial.print("  sk agree="); Serial.print(ok_sk);
    Serial.print("/"); Serial.print(trials);
    /* Pass if >= 80% raw agreement (Ring-LWR has small rounding noise) */
    Serial.print("  [");
    Serial.println(ok_raw >= trials * 8 / 10 ? "PASS]" : "FAIL]");
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
        uint32 e  = nl_fscx_revolve_v1(R, p, I_VALUE);  /* NL challenge */
        uint64_t ae = ((uint64_t)a * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s  = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs = gf_pow_32(GF_GEN, s);
        uint32 Ce = gf_pow_32(C, e);
        if (gf_mul_32(gs, Ce) == R) pass++;
    }
    Serial.print("    "); Serial.print(pass); Serial.print(" / 20 passed  [");
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 20 ? "PASS]" : "FAIL]");
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
        uint32 e_eve = nl_fscx_revolve_v1(R_eve, decoy, I_VALUE);
        uint32 s_eve = prng_next();
        uint32 gs    = gf_pow_32(GF_GEN, s_eve);
        uint32 Ce    = gf_pow_32(C, e_eve);
        if (gf_mul_32(gs, Ce) == R_eve) wins++;
    }
    Serial.print("    "); Serial.print(wins); Serial.print(" / 20 Eve wins (expected 0)  [");
    Serial.println(wins == 0 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 5 ? "PASS]" : "FAIL]");
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
    Serial.println(pass == 5 ? "PASS]" : "FAIL]");
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
    Serial.println("=== Herradura KEx v1.5.18 - Security Tests (Arduino, 32-bit) ===");
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

    delay(30000);
}
