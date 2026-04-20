/*  Herradura Cryptographic Suite v1.5.3 — Arduino (32-bit)
    HKEX-GF, HSKE, HPKS, HPKE, HSKE-NL-A1/A2, HKEX-RNL, HPKS-NL, HPKE-NL
    KEYBITS = 32

    Copyright (C) 2024-2026 Omar Alejandro Herrera Reyna
    MIT License / GPL v3.0 — choose either.

    Target: Arduino Uno/Mega/Leonardo or any board with Serial support.
    Upload via Arduino IDE or: arduino --upload --board arduino:avr:uno ...
    Monitor: 9600 baud serial monitor.

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

/* M^{-1}(X) = fscx_revolve(X, 0, KEYBITS/2 - 1) */
uint32 m_inv_32(uint32 x) {
    return fscx_revolve(x, 0, KEYBITS / 2 - 1);
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
    for (int i = 0; i < steps; i++) y = nl_fscx_v2_inv(y, b);
    return y;
}

/* ------------------------------------------------------------------ */
/* HKEX-RNL: Ring-LWR helpers  (N=32, q=65537, p=4096, pp=2, B=1)   */
/* ------------------------------------------------------------------ */

/* Negacyclic poly multiply: h = f*g in Z_q[x]/(x^N+1) */
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
    for (int i = 0; i < RNL_N; i++) p[i] = (long)(lcg_next() % (uint32)RNL_Q);
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

/* agree: K = bits of round_pp(s * lift(C_other)) */
static uint32 rnl_agree(const long *s, const long *C_other) {
    static long c_lifted[RNL_N], k_poly[RNL_N], k_bits[RNL_N];
    rnl_lift(c_lifted, C_other, RNL_P, RNL_Q);
    rnl_poly_mul(k_poly, s, c_lifted);
    rnl_round(k_bits, k_poly, RNL_Q, RNL_PP);
    return rnl_bits_to_key(k_bits);
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
    Serial.println("=== Herradura Cryptographic Suite v1.5.3 (Arduino, 32-bit) ===");
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
        /* counter=0: B = K XOR 0 = K */
        uint32 ks = nl_fscx_revolve_v1(K, K, I_VALUE);
        uint32 E  = PLAIN ^ ks;
        uint32 D  = E ^ ks;
        printHexLine("E (Alice) : ", E);
        printHexLine("D (Bob)   : ", D);
        Serial.println(D == PLAIN ? "+ plaintext correctly decrypted" : "- decryption failed!");
    }
    Serial.println();

    /* ---------------------------------------------------------------- */
    /* HSKE-NL-A2 [PQC-HARDENED -- revolve-mode with NL-FSCX v2]      */
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
        uint32 KA = rnl_agree(s_A, C_B);
        uint32 KB = rnl_agree(s_B, C_A);
        uint32 skA = nl_fscx_revolve_v1(KA, KA, I_VALUE);
        uint32 skB = nl_fscx_revolve_v1(KB, KB, I_VALUE);
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
    Serial.println();

    delay(10000);
}
