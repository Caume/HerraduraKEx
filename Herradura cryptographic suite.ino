/*  Herradura Cryptographic Suite v1.5.22 — Arduino (32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL,
    HPKS-Stern-F, HPKE-Stern-F
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

/* HKEX-RNL parameters (N=32 matches KEYBITS=32) */
#define RNL_N   32
#define RNL_Q   65537L
#define RNL_P   4096L
#define RNL_PP  2L
#define RNL_ETA 1  /* CBD eta: secret coeffs drawn from CBD(1) in {-1,0,1} mod q */

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

/* lift: out[i] = in[i] * to_q / from_p mod to_q */
static void rnl_lift(long *out, const long *in, long from_p, long to_q) {
    for (int i = 0; i < RNL_N; i++)
        out[i] = (long)((long long)in[i] * to_q / from_p % to_q);
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

/* Peikert hint: 1-bit per coeff packed to uint32 (n=32 fits exactly). */
static uint32 rnl_hint(const long *K_poly) {
    uint32 hint = 0;
    for (int i = 0; i < RNL_N; i++) {
        unsigned long c = (unsigned long)K_poly[i];
        unsigned long r = (unsigned long)((4UL * c + (unsigned long)(RNL_Q / 2))
                                          / (unsigned long)RNL_Q) % 4UL;
        if (r % 2UL) hint |= (1UL << i);
    }
    return hint;
}

/* Reconcile K_poly bits using Peikert hint. */
static uint32 rnl_reconcile(const long *K_poly, uint32 hint) {
    const unsigned long qh = (unsigned long)(RNL_Q / 2);
    uint32 key = 0;
    for (int i = 0; i < RNL_N; i++) {
        unsigned long c = (unsigned long)K_poly[i];
        unsigned long h = (hint >> i) & 1UL;
        if ((unsigned long)((2UL * c + h * qh + qh) / (unsigned long)RNL_Q)
                % (unsigned long)RNL_PP)
            key |= (1UL << i);
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
/* Fixed test vectors                                                  */
/* ------------------------------------------------------------------ */

const uint32 A_PRIV = 0xDEADBEEFUL;
const uint32 B_PRIV = 0xCAFEBABFUL;
const uint32 K      = 0x5A5A5A5AUL;
const uint32 PLAIN  = 0xDEADC0DEUL;

/* ------------------------------------------------------------------ */
/* Arduino entry points                                                */
/* ------------------------------------------------------------------ */

void setup() {
    Serial.begin(9600);
    while (!Serial) { ; }
}

void loop() {
    Serial.println("=== Herradura Cryptographic Suite v1.5.22 (Arduino, 32-bit) ===");
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
        uint32 ks   = nl_fscx_revolve_v1(_rol32(base, 4), base, I_VALUE);  /* seed=ROL(base,n/8=4) */
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
    {
        static long m_base[RNL_N], a_rand[RNL_N], m_blind[RNL_N];
        static long s_A[RNL_N], s_B[RNL_N], C_A[RNL_N], C_B[RNL_N];
        rnl_m_poly(m_base);
        rnl_rand_poly(a_rand);
        rnl_poly_add(m_blind, m_base, a_rand);
        rnl_keygen(s_A, C_A, m_blind);
        rnl_keygen(s_B, C_B, m_blind);
        uint32 hint_A;
        uint32 KA = rnl_agree(s_A, C_B, NULL, &hint_A);   /* reconciler */
        uint32 KB = rnl_agree(s_B, C_A, &hint_A, NULL);   /* receiver */
        uint32 skA = nl_fscx_revolve_v1(_rol32(KA, 4), KA, I_VALUE);
        uint32 skB = nl_fscx_revolve_v1(_rol32(KB, 4), KB, I_VALUE);
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

    delay(10000);
}
