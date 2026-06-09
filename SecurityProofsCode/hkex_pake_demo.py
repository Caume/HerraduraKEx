#!/usr/bin/env python3
"""
hkex_pake_demo.py — PAKE-ZKBoo: PQC Password-Authenticated Key Exchange (TODO #78.D)

Implements and demonstrates a PAKE construction using only native HerraduraKEx
primitives:
  HKEX-RNL  — post-quantum channel (Ring-LWR key exchange)
  ZKP-NL    — zero-knowledge proof of password knowledge (ZKBoo over nl_fscx_v1)
  HFSCX-256 — password hashing and session KDF

────────────────────────────────────────────────────────────────────────────────
PROTOCOL

  Registration (client-side, one time):
    1. salt    = random(32 bytes)
    2. pw_key  = hfscx_256(password ‖ salt)           [256-bit hash]
    3. zkp_A   = hfscx_256(pw_key ‖ "ZKP-A") & mask  [ZKP_N-bit witness]
    4. B       = random ZKP_N-bit nonce
    5. y       = nl_fscx_v1(zkp_A, B)                 [one-step NL-FSCX commitment]
    Store on server: (username, salt, B, y)            password and pw_key never leave client

  Login (3 messages):

    Msg 1  client → server:  (username, m_blind, C_client)
           client generates ephemeral HKEX-RNL keypair (s_c, C_c); m_blind is public.

    Msg 2  server → client:  (salt, B, y, C_server)
           server generates ephemeral HKEX-RNL keypair (s_s, C_s) using client's m_blind;
           sends credential fields from stored record.

    Msg 3  client → server:  (hint, proof)
           client re-derives: pw_key = hfscx_256(password ‖ salt)
                              zkp_A  = hfscx_256(pw_key ‖ "ZKP-A") & mask
           verifies pw_verifier locally: nl_fscx_v1(zkp_A, B) == y  (fast wrong-pw abort)
           runs HKEX-RNL reconciliation: K_raw_c, hint = rnl_agree(s_c, C_s)
           runs ZKBoo: proof = zkp_nl_prove(zkp_A, B, y, msg = K_raw_c ‖ "PAKE-AUTH-v1")
           session_key = hfscx_256(K_raw_c.bytes ‖ "PAKE-SESSION-v1")

    Finalize (server):
           runs HKEX-RNL: K_raw_s = rnl_agree(s_s, C_c, hint=hint)
           verifies ZKBoo: zkp_nl_verify(B, y, msg = K_raw_s ‖ "PAKE-AUTH-v1", proof)
           session_key = hfscx_256(K_raw_s.bytes ‖ "PAKE-SESSION-v1")

────────────────────────────────────────────────────────────────────────────────
SECURITY PROPERTIES

  1. Server storage: (salt, B, y) — server never holds password or pw_key.
  2. Channel: HKEX-RNL (Ring-LWR, conjectured quantum-resistant).
  3. Authentication: ZKBoo proves knowledge of zkp_A s.t. nl_fscx_v1(zkp_A, B) = y.
     The proof is zero-knowledge (server learns nothing about zkp_A beyond the relation).
  4. Session binding: ZKBoo msg = K_raw ‖ domain — proof is freshly bound to each session's
     raw key; replaying a proof from a past session with a different K_raw fails.
  5. Implicit hint authentication: an active MITM who tampers with the hint changes K_raw,
     making the ZKBoo proof verification fail (different msg bytes). Not formally proven.
  6. Forward secrecy: each session uses fresh HKEX-RNL ephemeral keys.

────────────────────────────────────────────────────────────────────────────────
OPEN GAPS (block production deployment)

  A. OFFLINE DICTIONARY ATTACK: an attacker who steals (salt, B, y) from the server
     can brute-force passwords by computing hfscx_256(p ‖ salt) for candidates p and
     checking nl_fscx_v1(derived_zkp_A, B) == y.  This makes the construction a PAKE
     (symmetric), NOT an aPAKE (augmented).  Mitigation requires OPRF (TODO #78.G).

  B. NO FORMAL SECURITY PROOF: no reduction to any standard PAKE model (aPAKE, SIM-BMP,
     UC-security).  ZKBoo gives computational ZK and soundness for one NL-FSCX gate; the
     composition with HKEX-RNL and HFSCX-256 is unanalyzed.

  C. DEMO PARAMETER LIMITATION: demo uses ZKP_N=32 (32-bit witness) for Python speed.
     Full 256-bit witness security requires C or NumPy-optimised ZKBoo (~1.3 s vs ~16 s
     pure Python).  In demo mode, security of authentication = min(password_entropy, 32 bits).

  D. DEMO ROUNDS: DEMO_ROUNDS=16 gives soundness error (2/3)^16 ≈ 0.15%.
     Production requires _ZKP_NL_PROD_ROUNDS=219 for 128-bit soundness.

  DEPLOYMENT STATUS: research prototype.  Demonstrates the construction and documents
  open gaps.  Not production-ready.

────────────────────────────────────────────────────────────────────────────────
Runtime: ~8 s (2 login flows, ZKP_N=32, DEMO_ROUNDS=16, no NumPy).
"""

import importlib.util, os, sys, time
from pathlib import Path

# ── Load suite ────────────────────────────────────────────────────────────────

_SUITE_PATH = Path(__file__).parent.parent / "Herradura cryptographic suite.py"
_spec = importlib.util.spec_from_file_location("herradura_suite", _SUITE_PATH)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BitArray             = _mod.BitArray
hfscx_256            = _mod.hfscx_256
nl_fscx_v1           = _mod.nl_fscx_v1
nl_fscx_revolve_v1   = _mod.nl_fscx_revolve_v1
zkp_nl_prove         = _mod.zkp_nl_prove
zkp_nl_verify        = _mod.zkp_nl_verify
_rnl_keygen          = _mod._rnl_keygen
_rnl_agree           = _mod._rnl_agree
_rnl_m_poly          = _mod._rnl_m_poly
_rnl_rand_poly       = _mod._rnl_rand_poly
_rnl_poly_add        = _mod._rnl_poly_add
_RNL_KDF_DC_256      = _mod._RNL_KDF_DC_256
KEYBITS              = _mod.KEYBITS       # 256
RNLQ                 = _mod.RNLQ          # 65537
RNLP                 = _mod.RNLP          # 4096
RNLPP                = _mod.RNLPP         # 4
RNLB                 = _mod.RNLB          # 1
_ZKP_NL_PROD_ROUNDS  = _mod._ZKP_NL_PROD_ROUNDS  # 219

# ── Parameters ────────────────────────────────────────────────────────────────

ZKP_N        = 32   # ZKBoo witness bit-width (demo; production: 256 with C/NumPy)
DEMO_ROUNDS  = 16   # ZKBoo rounds (soundness error (2/3)^16 ≈ 0.15%; production: 219)
PAKE_VERSION = b"PAKE-ZKBoo-v1"
_ZKP_A_LABEL = b"ZKP-A"
_SESSION_KEY_LABEL = b"PAKE-SESSION-v1"
_AUTH_MSG_LABEL    = b"PAKE-AUTH-v1"

SEP  = "═" * 72
SEP2 = "─" * 72


# ── Password key derivation ───────────────────────────────────────────────────

def _derive_pw_key(password: bytes, salt: bytes) -> bytes:
    """hfscx_256(password ‖ salt) → 32-byte key."""
    return hfscx_256(password + salt)


def _derive_zkp_witness(pw_key: bytes) -> int:
    """Domain-separated ZKP_N-bit witness from pw_key."""
    mask = (1 << ZKP_N) - 1
    h = hfscx_256(pw_key + _ZKP_A_LABEL)
    return int.from_bytes(h, 'big') & mask


# ── HKEX-RNL helpers ─────────────────────────────────────────────────────────

def _rnl_new_pair(m_blind):
    """Fresh HKEX-RNL ephemeral keypair using shared m_blind."""
    return _rnl_keygen(m_blind, KEYBITS, RNLQ, RNLP, RNLB)


def _rnl_session_kdf(K_raw: BitArray) -> bytes:
    """KDF matching suite main(): nl_fscx_revolve_v1 round."""
    sk = nl_fscx_revolve_v1(
        BitArray(KEYBITS, K_raw.rotated(KEYBITS // 8).uint ^ _RNL_KDF_DC_256),
        K_raw, KEYBITS // 4)
    return sk.bytes


def _session_key(K_raw: BitArray) -> bytes:
    """Final session key: hfscx_256(KDF(K_raw) ‖ label)."""
    return hfscx_256(_rnl_session_kdf(K_raw) + _SESSION_KEY_LABEL)


def _auth_msg(K_raw: BitArray) -> bytes:
    """ZKBoo message binding: session-unique bytes."""
    return K_raw.bytes + _AUTH_MSG_LABEL


# ── Registration ─────────────────────────────────────────────────────────────

def pake_register(username: str, password: bytes) -> dict:
    """
    Client-side registration.  Call once per user; send record to server.
    Server stores: (username, salt, B, y).  Password and pw_key are never transmitted.
    """
    salt    = os.urandom(32)
    pw_key  = _derive_pw_key(password, salt)
    zkp_A   = _derive_zkp_witness(pw_key)
    mask    = (1 << ZKP_N) - 1
    B       = int.from_bytes(os.urandom(ZKP_N // 8), 'big') & mask
    y       = nl_fscx_v1(BitArray(ZKP_N, zkp_A), BitArray(ZKP_N, B)).uint
    return {'username': username, 'salt': salt, 'B': B, 'y': y}


# ── Login: 3-message exchange + server finalize ───────────────────────────────

def pake_client_msg1(username: str) -> tuple[dict, dict]:
    """
    Msg 1: client → server.
    Returns (client_state, msg1).
    msg1 = {'username', 'm_blind', 'C_client'}
    """
    m_base  = _rnl_m_poly(KEYBITS)
    a_rand  = _rnl_rand_poly(KEYBITS, RNLQ)
    m_blind = _rnl_poly_add(m_base, a_rand, RNLQ)
    s_c, C_c = _rnl_new_pair(m_blind)
    state = {'s_c': s_c, 'm_blind': m_blind, 'C_c': C_c}
    msg1  = {'username': username, 'm_blind': m_blind, 'C_client': C_c}
    return state, msg1


def pake_server_msg2(record: dict, msg1: dict) -> tuple[dict, dict]:
    """
    Msg 2: server → client.
    Server generates fresh HKEX-RNL key using client's m_blind.
    Returns (server_state, msg2).
    msg2 = {'salt', 'B', 'y', 'C_server'}
    """
    m_blind  = msg1['m_blind']
    s_s, C_s = _rnl_new_pair(m_blind)
    state = {'s_s': s_s, 'C_c': msg1['C_client'], 'record': record}
    msg2  = {
        'salt':     record['salt'],
        'B':        record['B'],
        'y':        record['y'],
        'C_server': C_s,
    }
    return state, msg2


def pake_client_msg3(
    client_state: dict,
    msg2: dict,
    password: bytes,
) -> tuple[bytes | None, dict | None]:
    """
    Msg 3: client → server.
    Derives pw_key, runs HKEX-RNL reconciliation, generates ZKBoo proof.
    Returns (session_key, msg3) on success, (None, None) if wrong password.
    msg3 = {'hint', 'proof'}
    """
    salt = msg2['salt']
    B    = msg2['B']
    y    = msg2['y']

    pw_key = _derive_pw_key(password, salt)
    zkp_A  = _derive_zkp_witness(pw_key)

    # Fast local pw_verifier check — aborts before ZKBoo if wrong password
    y_check = nl_fscx_v1(BitArray(ZKP_N, zkp_A), BitArray(ZKP_N, B)).uint
    if y_check != y:
        return None, None

    # HKEX-RNL: client acts as reconciler (generates hint)
    K_raw_c, hint = _rnl_agree(
        client_state['s_c'], msg2['C_server'],
        RNLQ, RNLP, RNLPP, KEYBITS, KEYBITS,
    )

    # ZKBoo: prove knowledge of zkp_A s.t. nl_fscx_v1(zkp_A, B) = y
    # msg_bytes binds the proof to this session's raw key
    proof = zkp_nl_prove(
        zkp_A, B, y, ZKP_N, DEMO_ROUNDS, _auth_msg(K_raw_c)
    )

    msg3 = {'hint': hint, 'proof': proof}
    return _session_key(K_raw_c), msg3


def pake_server_verify(server_state: dict, msg3: dict) -> bytes | None:
    """
    Server verifies msg3: reconciles HKEX-RNL key using client's hint,
    verifies ZKBoo proof.
    Returns session_key bytes on success, None on failure.
    """
    record = server_state['record']
    B, y   = record['B'], record['y']

    # HKEX-RNL: server acts as receiver (uses client's hint)
    K_raw_s = _rnl_agree(
        server_state['s_s'], server_state['C_c'],
        RNLQ, RNLP, RNLPP, KEYBITS, KEYBITS,
        msg3['hint'],
    )

    # ZKBoo verify
    ok = zkp_nl_verify(
        B, y, ZKP_N, DEMO_ROUNDS,
        _auth_msg(K_raw_s), msg3['proof'],
    )
    if not ok:
        return None
    return _session_key(K_raw_s)


# ── Proof size helper ─────────────────────────────────────────────────────────

def _proof_bytes(proof: list) -> int:
    return sum(
        len(r['com_0']) + len(r['com_1']) + len(r['com_2']) +
        len(r['view_p1']) + len(r['view_p2']) + 1
        for r in proof
    )


# ── Demo ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print("hkex_pake_demo.py — PAKE-ZKBoo: PQC Password-Authenticated Key Exchange (TODO #78.D)")
    print(f"  ZKP_N={ZKP_N} bits  DEMO_ROUNDS={DEMO_ROUNDS}  "
          f"soundness_err={(2/3)**DEMO_ROUNDS*100:.2f}%  "
          f"(production: ZKP_N=256 via C/NumPy, R={_ZKP_NL_PROD_ROUNDS})")
    print()

    t_total = time.monotonic()

    # ── §1 Registration ───────────────────────────────────────────────────
    print(SEP)
    print("§1 — Registration")
    print(SEP)
    print()

    PASSWORD_GOOD = b"correct horse battery staple"
    PASSWORD_BAD  = b"wrong password"
    USERNAME      = "alice"

    t0 = time.monotonic()
    record = pake_register(USERNAME, PASSWORD_GOOD)
    t_reg  = time.monotonic() - t0

    print(f"  username  : {record['username']}")
    print(f"  salt      : {record['salt'].hex()[:32]}…  (32 bytes, random)")
    print(f"  B (nonce) : 0x{record['B']:0{ZKP_N//4}x}  ({ZKP_N}-bit, random)")
    print(f"  y (verif) : 0x{record['y']:0{ZKP_N//4}x}  (nl_fscx_v1 commitment to zkp_A)")
    print(f"  time      : {t_reg*1000:.0f} ms")
    print()
    print("  Server stores: (username, salt, B, y).  Password and pw_key never transmitted.")
    print()

    # ── §2 Login: correct password ────────────────────────────────────────
    print(SEP)
    print("§2 — Login: correct password")
    print(SEP)
    print()

    t0 = time.monotonic()
    c_state, msg1 = pake_client_msg1(USERNAME)
    t1 = time.monotonic()
    s_state, msg2 = pake_server_msg2(record, msg1)
    t2 = time.monotonic()
    sk_client, msg3 = pake_client_msg3(c_state, msg2, PASSWORD_GOOD)
    t3 = time.monotonic()
    sk_server = pake_server_verify(s_state, msg3)
    t4 = time.monotonic()

    print(f"  Msg 1 (client → server): username + m_blind + C_client      [{(t1-t0)*1000:.0f} ms]")
    print(f"  Msg 2 (server → client): salt + B + y + C_server            [{(t2-t1)*1000:.0f} ms]")
    print(f"  Msg 3 (client → server): hint + proof ({_proof_bytes(msg3['proof'])} B)   [{(t3-t2)*1000:.0f} ms]")
    print(f"  Server verify                                                [{(t4-t3)*1000:.0f} ms]")
    print()

    if sk_client is not None and sk_client == sk_server:
        print(f"  + AUTHENTICATION PASSED")
        print(f"  session key (client): {sk_client.hex()}")
        print(f"  session key (server): {sk_server.hex()}")
        assert sk_client == sk_server, "session key mismatch (bug)"
        print(f"  Keys match: YES")
    else:
        print("  - AUTHENTICATION FAILED (unexpected)")
    print()

    # ── §3 Login: wrong password ──────────────────────────────────────────
    print(SEP)
    print("§3 — Login: wrong password")
    print(SEP)
    print()

    t0 = time.monotonic()
    c_state2, msg1b = pake_client_msg1(USERNAME)
    s_state2, msg2b = pake_server_msg2(record, msg1b)
    sk_client2, msg3b = pake_client_msg3(c_state2, msg2b, PASSWORD_BAD)
    t_bad = time.monotonic() - t0

    if sk_client2 is None:
        print(f"  + Client aborted early: pw_verifier mismatch (nl_fscx_v1 check failed).")
        print(f"    ZKBoo proof never generated.  Time: {t_bad*1000:.0f} ms.")
        print(f"    Server receives no msg3 — no round-trip needed.")
    else:
        # pw_verifier passed locally (should not happen with correct record) — server rejects
        sk_server2 = pake_server_verify(s_state2, msg3b)
        if sk_server2 is None:
            print(f"  + Server rejected ZKBoo proof for wrong password.  Time: {t_bad*1000:.0f} ms.")
        else:
            print("  - Wrong password accepted (BUG)")
    print()

    # ── §4 Security properties and open gaps ──────────────────────────────
    print(SEP)
    print("§4 — Security Properties and Open Gaps")
    print(SEP)
    print()
    print("  WHAT THIS CONSTRUCTION PROVIDES:")
    print("  1. Channel secrecy via HKEX-RNL (Ring-LWR, conjectured quantum-resistant).")
    print("  2. Zero-knowledge password authentication: ZKBoo proves knowledge of zkp_A")
    print("     s.t. nl_fscx_v1(zkp_A, B) = y, where zkp_A is domain-separated from")
    print("     pw_key = hfscx_256(password ‖ salt).  Password never leaves client.")
    print("  3. Session binding: proof msg = K_raw ‖ label — unique per session.")
    print("  4. Implicit hint authentication: MITM hint-tampering changes K_raw, breaking")
    print("     proof verification.  (Informal argument; no formal proof.)")
    print("  5. Forward secrecy: fresh HKEX-RNL ephemeral keypairs per session.")
    print()
    print("  OPEN GAPS (block production deployment):")
    print()
    print("  A. OFFLINE DICTIONARY ATTACK — this is a PAKE, not aPAKE:")
    print("     Attacker with (salt, B, y) can brute-force passwords by computing")
    print("     hfscx_256(p‖salt) for each candidate p and checking nl_fscx_v1()==y.")
    print("     Fix: augmented PAKE requires OPRF (TODO #78.G) to prevent offline attack.")
    print()
    print("  B. NO FORMAL SECURITY REDUCTION:")
    print("     No proof of security under any standard PAKE model (SIM-BMP, UC-PAKE).")
    print("     Composition of HKEX-RNL + ZKBoo + HFSCX-256 is unanalyzed.")
    print()
    print("  C. DEMO PARAMETER LIMITATION:")
    print(f"     ZKP_N={ZKP_N} bits (demo speed).  Authentication security = min(pw_entropy, {ZKP_N} bits).")
    print(f"     Full {KEYBITS}-bit security requires ZKP_N={KEYBITS} with C or NumPy ZKBoo (~1.3 s).")
    print(f"     Alternative: 8 batched ZKP_N=32 proofs bind all 256 pw_key bits (8× slower).")
    print()
    print(f"  D. DEMO SOUNDNESS: R={DEMO_ROUNDS} → error (2/3)^{DEMO_ROUNDS} = {(2/3)**DEMO_ROUNDS:.4f}.")
    print(f"     Production: R={_ZKP_NL_PROD_ROUNDS} for 128-bit soundness.")

    elapsed = time.monotonic() - t_total
    print()
    print(SEP)
    print(f"Total runtime: {elapsed:.1f} s")
    print("END hkex_pake_demo.py")
    print(SEP)
    print()


if __name__ == "__main__":
    main()
