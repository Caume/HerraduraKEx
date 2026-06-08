/*  Herradura Cryptographic Suite v1.9.10 — Arduino (32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL,
    HPKS-Stern-F, HPKE-Stern-F, ZKP-RNL, ZKP-NL
    KEYBITS = 32

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Arduino Uno/Mega/Leonardo or any board with Serial support.
    Upload via Arduino IDE or: arduino --upload --board arduino:avr:uno ...
    Monitor: 9600 baud serial monitor.

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

#define KEYBITS  32
#define I_VALUE  (KEYBITS / 4)        /* 8  */
#define R_VALUE  (3 * KEYBITS / 4)    /* 24 */

/* GF(2^32) polynomial: x^32 + x^22 + x^2 + x + 1 */
#define GF_POLY32 0x00400007UL
#define GF_GEN    3UL

/* NUMS domain constant for KDF seed (SHA-256 H0) */
#define RNL_KDF_DC 0x6A09E667UL

/* HKEX-RNL parameters (N=32 matches KEYBITS=32) */
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

static void printHexLine(const char *label, uint32 val) {
    Serial.print(label);
    printHex(val);
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

/* HFSCX-32-DM: two-step MD hash at 32-bit word size, Davies-Meyer compression (v1.9.0).
 * C_DM(s,m)=nl(s,m,8)^s; IV=0xA3C5E7B9, LB=0xA3C5E799 */
static uint32 hfscx_32(uint32 x) {
    uint32 prev = 0xA3C5E7B9UL;
    uint32 s = nl_fscx_revolve_v1(prev, x, 8) ^ prev;
    return nl_fscx_revolve_v1(s, 0xA3C5E799UL, 8) ^ s;
}

static uint32 stern_hash1_32(uint32 ds, uint32 v) {
    uint32 h = nl_fscx_revolve_v1(ds ^ v, _rol32(v, 4), I_VALUE);
    return hfscx_32(h);
}

static uint32 stern_hash2_32(uint32 ds, uint32 a, uint32 b) {
    uint32 h = nl_fscx_revolve_v1(ds ^ a, _rol32(a, 4), I_VALUE);
    return hfscx_32(nl_fscx_revolve_v1(h ^ b, _rol32(b, 4), I_VALUE));
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
            uint32 v = ra; if (!v) return 0;
            v &= v-1; if (!v) return 0; v &= v-1; if (v) return 0;
        } else if (bv == 1) {
            uint32 v = rb; if (!v) return 0;
            v &= v-1; if (!v) return 0; v &= v-1; if (v) return 0;
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
/* Arduino entry points                                                */
/* ------------------------------------------------------------------ */

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    Serial.println("=== Herradura Cryptographic Suite v1.9.10 (Arduino, 32-bit) ===");
    Serial.println();

    printHexLine("a_priv : ", A_PRIV);
    printHexLine("b_priv : ", B_PRIV);
    printHexLine("K      : ", K);
    printHexLine("PLAIN  : ", PLAIN);
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HKEX-GF [CLASSICAL]                                              */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HKEX-GF [CLASSICAL -- not PQC; Shor breaks DLP]");
    uint32 C    = gf_pow_32(GF_GEN, A_PRIV);
    uint32 C2   = gf_pow_32(GF_GEN, B_PRIV);
    uint32 skeyA = gf_pow_32(C2, A_PRIV);
    uint32 skeyB = gf_pow_32(C,  B_PRIV);
    printHexLine("C        : ", C);
    printHexLine("C2       : ", C2);
    printHexLine("skeyA    : ", skeyA);
    printHexLine("skeyB    : ", skeyB);
    Serial.println(skeyA == skeyB ? "+ session keys agree!" : "- session keys differ!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE [CLASSICAL]                                                 */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HSKE [CLASSICAL -- not PQC; linear key recovery]");
    uint32 hskeE = fscx_revolve(PLAIN, K, I_VALUE);
    uint32 hskeD = fscx_revolve(hskeE, K, R_VALUE);
    printHexLine("E (Alice) : ", hskeE);
    printHexLine("D (Bob)   : ", hskeD);
    Serial.println(hskeD == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS Schnorr [CLASSICAL]                                        */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKS Schnorr [CLASSICAL -- not PQC; DLP + linear challenge]");
    {
        uint32 k   = lcg_next() | 1;
        uint32 R   = gf_pow_32(GF_GEN, k);
        uint32 e   = fscx_revolve(R, PLAIN, I_VALUE);
        uint64_t ae = ((uint64_t)A_PRIV * (uint64_t)e) % 0xFFFFFFFFULL;
        uint32 s   = (uint32)(((uint64_t)k + 0xFFFFFFFFULL - ae) % 0xFFFFFFFFULL);
        uint32 gs  = gf_pow_32(GF_GEN, s);
        uint32 Ce  = gf_pow_32(C, e);
        uint32 lhs = gf_mul_32(gs, Ce);
        printHexLine("R (g^k)   : ", R);
        printHexLine("s (resp)  : ", s);
        printHexLine("g^s*C^e   : ", lhs);
        Serial.println(lhs == R ? "+ HPKS Schnorr verified!" : "- HPKS Schnorr FAILED!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE El Gamal [CLASSICAL]                                       */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKE El Gamal [CLASSICAL -- not PQC; DLP + linear HSKE]");
    {
        uint32 r        = lcg_next() | 1;
        uint32 R        = gf_pow_32(GF_GEN, r);
        uint32 enc_key  = gf_pow_32(C, r);
        uint32 hpkeE    = fscx_revolve(PLAIN, enc_key, I_VALUE);
        uint32 dec_key  = gf_pow_32(R, A_PRIV);
        uint32 hpkeD    = fscx_revolve(hpkeE, dec_key, R_VALUE);
        printHexLine("R (g^r)   : ", R);
        printHexLine("E (Bob)   : ", hpkeE);
        printHexLine("D (Alice) : ", hpkeD);
        Serial.println(hpkeD == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1]      */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HSKE-NL-A1 [PQC-HARDENED -- counter-mode with NL-FSCX v1]");
    {
        uint32 N    = lcg_next();              /* per-session nonce            */
        uint32 base = K ^ N;                   /* session key base = K XOR N   */
        uint32 ks   = nl_fscx_revolve_v1(_rol32(base, 4) ^ RNL_KDF_DC, base, I_VALUE);
        uint32 E    = PLAIN ^ ks;
        uint32 D    = E ^ ks;
        printHexLine("N (nonce) : ", N);
        printHexLine("E (Alice) : ", E);
        printHexLine("D (Bob)   : ", D);
        Serial.println(D == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]      */
    /* CAUTION: deterministic -- same (P, K) always yields the same E. */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]");
    {
        uint32 E = nl_fscx_revolve_v2(PLAIN, K, R_VALUE);
        uint32 D = nl_fscx_revolve_v2_inv(E, K, R_VALUE);
        printHexLine("E (Alice) : ", E);
        printHexLine("D (Bob)   : ", D);
        Serial.println(D == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HKEX-RNL [PQC -- Ring-LWR key exchange, N=32]                  */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HKEX-RNL [PQC -- Ring-LWR key exchange; N=32, q=65537]");
    uint32 sk_rnl_saved = 0;
    static long m_base[RNL_N], a_rand[RNL_N], m_blind[RNL_N];
    static long s_A[RNL_N], s_B[RNL_N], C_A[RNL_N], C_B[RNL_N];
    {
        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, C_A, m_blind);
        rnl_keygen(s_B, C_B, m_blind);
        uint32 hint_A;
        uint32 KA = rnl_agree(s_A, C_B, NULL, &hint_A);   /* reconciler */
        uint32 KB = rnl_agree(s_B, C_A, &hint_A, NULL);   /* receiver */
        uint32 skA = nl_fscx_revolve_v1(_rol32(KA, 4) ^ RNL_KDF_DC, KA, I_VALUE);
        uint32 skB = nl_fscx_revolve_v1(_rol32(KB, 4) ^ RNL_KDF_DC, KB, I_VALUE);
        printHexLine("sk (Alice): ", skA);
        printHexLine("sk (Bob)  : ", skB);
        if (KA == KB) {
            Serial.println("+ raw key bits agree; session key established!");
        } else {
            Serial.println("- raw key disagrees (rounding noise -- retry)");
        }
        sk_rnl_saved = skA;
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge]          */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKS-NL [NL-hardened Schnorr -- NL-FSCX v1 challenge]");
    {
        uint32 k_nl = lcg_next();
        uint32 R_nl = gf_pow_32(GF_GEN, k_nl);
        uint32 e_nl = nl_fscx_revolve_v1(R_nl, PLAIN, I_VALUE);
        uint64_t ae_nl = ((uint64_t)A_PRIV * (uint64_t)e_nl) % 0xFFFFFFFFULL;
        uint32 s_nl = (uint32)(((uint64_t)k_nl + 0xFFFFFFFFULL - ae_nl) % 0xFFFFFFFFULL);
        uint32 gs_nl = gf_pow_32(GF_GEN, s_nl);
        uint32 Ce_nl = gf_pow_32(C, e_nl);
        uint32 lhs_nl = gf_mul_32(gs_nl, Ce_nl);
        printHexLine("R (g^k)   : ", R_nl);
        printHexLine("s (resp)  : ", s_nl);
        printHexLine("g^s*C^e   : ", lhs_nl);
        Serial.println(lhs_nl == R_nl ? "+ HPKS-NL verified!" : "- HPKS-NL FAILED!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption]        */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKE-NL [NL-hardened El Gamal -- NL-FSCX v2 encryption]");
    uint32 E_nl_saved = 0, R_nl2_saved = 0;
    {
        uint32 r_nl    = lcg_next() | 1;
        uint32 R_nl2   = gf_pow_32(GF_GEN, r_nl);
        uint32 enc_nl  = gf_pow_32(C, r_nl);
        uint32 E_nl    = nl_fscx_revolve_v2(PLAIN, enc_nl, I_VALUE);
        uint32 dec_nl  = gf_pow_32(R_nl2, A_PRIV);
        uint32 D_nl    = nl_fscx_revolve_v2_inv(E_nl, dec_nl, I_VALUE);
        printHexLine("E (Bob)   : ", E_nl);
        printHexLine("D (Alice) : ", D_nl);
        Serial.println(D_nl == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
        E_nl_saved  = E_nl;
        R_nl2_saved = R_nl2;
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKS-Stern-F [PQC -- Fiat-Shamir Stern ZKP signature, N=32]     */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKS-Stern-F [PQC -- Fiat-Shamir Stern ZKP, N=32, t=2, rounds=4]");
    uint32 sf_seed = 0, sf_synd = 0, sf_e = 0;
    {
        static SternSig32 sf_sig;
        sf_seed = lcg_next();
        sf_e    = stern_rand_error_32();
        sf_synd = stern_syndrome_32(sf_seed, sf_e);
        hpks_stern_f_sign_32(&sf_sig, PLAIN, sf_e, sf_seed);
        int ok = hpks_stern_f_verify_32(&sf_sig, PLAIN, sf_seed, sf_synd);
        printHexLine("seed     : ", sf_seed);
        printHexLine("error e  : ", sf_e);
        printHexLine("syndrome : ", sf_synd);
        Serial.println(ok ? "+ HPKS-Stern-F verified!" : "- HPKS-Stern-F FAILED!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HPKE-Stern-F [PQC -- Niederreiter KEM, N=32, t=2]               */
    /* ---------------------------------------------------------------- */
    Serial.println("--- HPKE-Stern-F [PQC -- Niederreiter KEM, N=32, t=2]");
    uint32 sf_K_enc_saved = 0;
    {
        uint32 e_prime, ct;
        sf_K_enc_saved = hpke_stern_f_encap_32(sf_seed, &ct, &e_prime);
        uint32 K_dec   = hpke_stern_f_decap_32(sf_seed, e_prime);
        printHexLine("ct       : ", ct);
        printHexLine("K (enc)  : ", sf_K_enc_saved);
        printHexLine("K (dec)  : ", K_dec);
        Serial.println(sf_K_enc_saved == K_dec
            ? "+ HPKE-Stern-F KEM keys agree!"
            : "- HPKE-Stern-F KEM keys differ!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* EVE bypass tests                                                 */
    /* ---------------------------------------------------------------- */
    Serial.println("*** EVE bypass TESTS ***");

    Serial.println("*** HPKE-NL -- Eve uses wrong key (C XOR R instead of C^r)");
    {
        uint32 eve_key = C ^ R_nl2_saved;
        uint32 D_eve   = nl_fscx_revolve_v2_inv(E_nl_saved, eve_key, I_VALUE);
        Serial.println(D_eve == PLAIN
            ? "+ Eve decrypted (Eve wins)!"
            : "- Eve could not decrypt (CDH + NL protection)");
    }

    Serial.println("*** HKEX-RNL -- Eve random guess does not match shared key");
    {
        uint32 eve_guess = lcg_next();
        Serial.println(eve_guess == sk_rnl_saved
            ? "+ Eve guessed HKEX-RNL key (astronomically unlikely)!"
            : "- Eve random guess does not match shared key (Ring-LWR protection)");
    }

    Serial.println("*** HPKS-Stern-F -- Eve forges signature (random data)");
    {
        static SternSig32 eve_sig;
        for (int i = 0; i < SDF_ROUNDS; i++) {
            eve_sig.c0[i] = lcg_next(); eve_sig.c1[i] = lcg_next();
            eve_sig.c2[i] = lcg_next(); eve_sig.b[i]  = lcg_next() % 3;
            eve_sig.respA[i] = lcg_next(); eve_sig.respB[i] = lcg_next();
        }
        int ok = hpks_stern_f_verify_32(&eve_sig, PLAIN, sf_seed, sf_synd);
        Serial.println(ok
            ? "+ Eve forged signature (soundness failure)!"
            : "- Eve forge rejected (SD soundness)");
    }

    Serial.println("*** HPKE-Stern-F -- Eve random guess vs KEM key");
    {
        uint32 eve_K = lcg_next();
        Serial.println(eve_K == sf_K_enc_saved
            ? "+ Eve guessed KEM key (astronomically unlikely)!"
            : "- Eve random K does not match KEM key (SD protection)");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* ZKP-RNL [Lyubashevsky Ring-LWR Sigma-protocol; n=32, t=4]       */
    /* ---------------------------------------------------------------- */
    Serial.println("--- ZKP-RNL [Ring-LWR Sigma-protocol; N=32, gamma=4096, t=4]");
    {
        int ok = rnl_sigma_sign(m_blind, s_A, C_A, PLAIN);
        if (ok) ok = rnl_sigma_verify(m_blind, C_A, PLAIN);
        Serial.println(ok ? "+ ZKP-RNL proof verified!" : "- ZKP-RNL FAILED");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* ZKP-NL [ZKBoo MPC-in-the-head; n=8 bits, R=4 rounds]            */
    /* ---------------------------------------------------------------- */
    Serial.println("--- ZKP-NL [ZKBoo concept demo; n=8, R=4 rounds]");
    {
        uint32 A_nl = lcg_next() & 0xFFu;
        uint32 B_nl = lcg_next() & 0xFFu;
        uint32 y_nl = zkp_nl_f1_8(A_nl, B_nl);
        zkp_nl_prove_8(A_nl, B_nl, y_nl, PLAIN);
        int ok = zkp_nl_verify_8(B_nl, y_nl, PLAIN);
        printHexLine("A (wit)   : ", A_nl);
        printHexLine("B (pub)   : ", B_nl);
        printHexLine("y=F1(A,B) : ", y_nl);
        Serial.println(ok ? "+ ZKP-NL proof verified!" : "- ZKP-NL FAILED");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* FPE (78.A)                                                       */
    /* ---------------------------------------------------------------- */
    Serial.println("--- FPE (78.A) [format-preserving encrypt/decrypt; 32-bit]");
    {
        uint32 fpe_key = 0xABCD1234UL;
        uint32 fpe_ctx = 0x00000042UL; /* record 66 */
        uint32 fpe_ct  = fpe_encrypt_32(PLAIN, fpe_key, fpe_ctx);
        uint32 fpe_rec = fpe_decrypt_32(fpe_ct, fpe_key, fpe_ctx);
        printHexLine("plain  : ", PLAIN);
        printHexLine("cipher : ", fpe_ct);
        printHexLine("recover: ", fpe_rec);
        Serial.println(fpe_rec == PLAIN ? "+ FPE round-trip correct" : "- FPE round-trip FAILED");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* Tweakable cipher (78.B)                                          */
    /* ---------------------------------------------------------------- */
    Serial.println("--- Tweakable cipher (78.B) [sector/block tweak; 32-bit]");
    {
        uint32 twk_key = 0x12345678UL;
        uint32 twk_ct  = twk_encrypt_32(PLAIN, twk_key, 7, 3);
        uint32 twk_rec = twk_decrypt_32(twk_ct, twk_key, 7, 3);
        printHexLine("plain  : ", PLAIN);
        printHexLine("cipher : ", twk_ct);
        printHexLine("recover: ", twk_rec);
        Serial.println(twk_rec == PLAIN ? "+ Tweakable cipher correct" : "- Tweakable cipher FAILED");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* Accumulator (78.J)                                               */
    /* ---------------------------------------------------------------- */
    Serial.println("--- Accumulator (78.J) [Merkle root + membership; 32-bit]");
    {
        uint32 leaves[4] = {
            haccum_leaf_32(0xAAAAAAAAUL),
            haccum_leaf_32(0xBBBBBBBBUL),
            haccum_leaf_32(0xCCCCCCCCUL),
            haccum_leaf_32(0xDDDDDDDDUL),
        };
        uint32 root = haccum_root_32(leaves, 4);
        /* manual proof for index 2: sibling is leaves[3], parent's sibling is node(l[0],l[1]) */
        uint32 sib0 = leaves[3];
        uint32 sib1 = haccum_node_32(leaves[0], leaves[1]);
        uint32 cur  = haccum_node_32(leaves[2], sib0);
        cur         = haccum_node_32(sib1, cur);
        printHexLine("root         : ", root);
        printHexLine("verify (idx2): ", cur);
        Serial.println(cur == root ? "+ Accumulator proof correct" : "- Accumulator proof FAILED");
    }
    Serial.println();

    /* Masked HSKE (78.H)                                               */
    /* ---------------------------------------------------------------- */
    Serial.println("--- Masked HSKE (78.H) [GF(2)-linearity masking; 32-bit]");
    {
        uint32 plain32 = 0xDEADC0DEUL;
        uint32 key32   = 0xCAFEBABEUL;
        uint32 mask32  = 0xA5A5A5A5UL;
        uint32 ct32    = hske_encrypt_masked_32(plain32, key32, mask32);
        uint32 rec32   = hske_decrypt_masked_32(ct32,    key32, mask32);
        printHexLine("cipher : ", ct32);
        printHexLine("recover: ", rec32);
        Serial.println(rec32 == plain32 ? "+ Masked HSKE correct" : "- Masked HSKE FAILED");
    }
    Serial.println();

    /* Ratchet (78.C)                                                   */
    /* ---------------------------------------------------------------- */
    Serial.println("--- Ratchet (78.C) [forward-secret; 32-bit; 5 steps]");
    {
        uint32 state32 = 0x12345678UL;
        uint32 mk0 = 0, mk;
        bool unique = true;
        for (int i = 0; i < 5; i++) {
            state32 = ratchet_advance_32(state32, &mk);
            if (i == 0) mk0 = mk;
            else if (mk == mk0) unique = false;
        }
        Serial.println(unique ? "- Ratchet: 5 distinct message keys"
                              : "+ Ratchet: duplicate message keys!");
    }
    Serial.println();

    delay(10000);
}
