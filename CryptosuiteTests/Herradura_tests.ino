/*  Herradura KEx — Security Tests v1.5.3 (Arduino, 32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, NL-FSCX, HSKE-NL-A2, HKEX-RNL, HPKS-NL, HPKE-NL

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Any Arduino board with Serial support.
    Upload via Arduino IDE. Monitor at 9600 baud.

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

uint32 m_inv_32(uint32 x) {
    return fscx_revolve(x, 0, KEYBITS / 2 - 1);
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
    for (int i = 0; i < steps; i++) y = nl_fscx_v2_inv(y, b);
    return y;
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL helpers                                                    */
/* ------------------------------------------------------------------ */

static void rnl_poly_mul(long *h, const long *f, const long *g) {
    static long tmp[RNL_N];
    for (int i = 0; i < RNL_N; i++) tmp[i] = 0;
    for (int i = 0; i < RNL_N; i++) {
        if (!f[i]) continue;
        for (int j = 0; j < RNL_N; j++) {
            int k = i + j;
            long long prod = (long long)f[i] * g[j] % RNL_Q;
            if (k < RNL_N)
                tmp[k] = (tmp[k] + prod) % RNL_Q;
            else
                tmp[k - RNL_N] = ((tmp[k - RNL_N] - prod) % RNL_Q + RNL_Q) % RNL_Q;
        }
    }
    for (int i = 0; i < RNL_N; i++) h[i] = tmp[i];
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
            uint32 skA = nl_fscx_revolve_v1(KA, KA, I_VALUE);
            uint32 skB = nl_fscx_revolve_v1(KB, KB, I_VALUE);
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
/* Arduino entry points                                                */
/* ------------------------------------------------------------------ */

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    Serial.println("=== Herradura KEx v1.5.3 - Security Tests (Arduino, 32-bit) ===");
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

    delay(30000);
}
