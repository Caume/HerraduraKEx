#!/usr/bin/env python3
# SecurityProofsCode/nl_fscx_ligero.py
#
# TODO #122 Batch 4 — Ligero-style IOP-based ZKP for NL-FSCX v1 (v1.9.87)
#
# Batch 3 (nl_fscx_sparse_circuit.py) concluded that per-bit-sharing MPCitH
# (ZKBoo/ZKB++) cannot reach the ~180 KB Picnic-range target at n=256 because
# proof size is dominated by the 32-byte per-party share and commitment
# overhead, replicated across parallel repetitions.  The revised open
# direction was an IOP-based proof (Ligero, Ames et al. CCS 2017) that avoids
# per-bit sharing and needs NO parallel repetition: soundness comes from
# Reed-Solomon column sampling and field-sized algebraic tests.
#
# This script implements a self-contained "Ligero-lite" argument of knowledge
# for the statement
#
#     y = F1^r(A, B)        (A secret, B and y public)
#
# where F1 is one step of NL-FSCX v1 (linear FSCX layer XOR a rotated modular
# sum), the same statement family as zkp_nl_prove/hpks-nl-zkboo.
#
# Protocol (non-interactive via Fiat-Shamir):
#   1. Arithmetize over GF(2^16): GF(2) embeds in GF(2^16), so XOR/rotation
#      are LINEAR; the only quadratic constraints are the carry-chain AND
#      gates (a_i AND c_i per bit, B public) and booleanity of the secret
#      input bits (v^2 = v forces v in {0,1}).
#   2. Extended witness W = [vars | x-copies | y-copies | z-copies] arranged
#      into an m x l matrix; each row Reed-Solomon-encoded to length N;
#      columns Merkle-committed.
#   3. Three tests, each checked at t random columns:
#      - proximity  : random row-combo must be a codeword (degree < l)
#      - linear     : random combo of sparse linear constraints A.W = b
#      - quadratic  : random combo of gate rows, Ux o Uy - Uz vanishes on
#                     the l message points
#      The algebraic combos are repeated sigma = ceil(lambda/16) times
#      because each combo only gives 2^-16 soundness over GF(2^16).
#
# Soundness model (documented, conservative):
#   - query phase: a word e-far from the code (e = floor((N-l)/3), within the
#     e < d/3 regime of Ligero Thm 4.2) escapes t column checks with
#     probability <= (1 - e/N)^t; t is chosen so this is <= 2^-lambda.
#   - algebraic phase: each of the sigma repetitions of the linear/quadratic
#     combo tests fails to catch a violated constraint with probability
#     ~ 2^-16 (plus degree/field terms (2l)/2^16); sigma = ceil(lambda/16).
#
# No external dependencies (hashlib + os only), matching the other
# SecurityProofsCode scripts.

import hashlib
import os
import time

SEP = "─" * 70


# ── §0  GF(2^16) arithmetic via log/exp tables ────────────────────────────────

GF_BITS = 16
GF_SIZE = 1 << GF_BITS          # 65536
GF_POLY = 0x1100B               # x^16 + x^12 + x^3 + x + 1 (irreducible)

_EXP = [0] * (2 * GF_SIZE)
_LOG = [0] * GF_SIZE


def _gf_mul_slow(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & GF_SIZE:
            a ^= GF_POLY
        b >>= 1
    return r


def _build_tables():
    """Find a generator and fill EXP/LOG tables."""
    order = GF_SIZE - 1
    factors = [3, 5, 17, 257]        # 65535 = 3 * 5 * 17 * 257
    g = 2
    while True:
        ok = True
        for f in factors:
            e, x = order // f, 1
            for _ in range(e):
                x = _gf_mul_slow(x, g)
            if x == 1:
                ok = False
                break
        if ok:
            break
        g += 1
    x = 1
    for i in range(order):
        _EXP[i] = x
        _LOG[x] = i
        x = _gf_mul_slow(x, g)
    for i in range(order, 2 * GF_SIZE):
        _EXP[i] = _EXP[i - order]


_build_tables()


def gmul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def ginv(a):
    return _EXP[(GF_SIZE - 1) - _LOG[a]]


# ── §1  Arithmetization of y = F1^r(A, B) over GF(2^16) ──────────────────────
#
# Witness variables (all GF(2)-valued, embedded in GF(2^16)):
#   a[t][i]  — bit i of state A^t, t = 0..r  (A^0 = secret input)
#   c[t][i]  — carry bit i of step t's adder, t = 0..r-1, i = 1..n-1
#
# Every linear constraint has O(1) terms (state bits are explicit variables,
# so no affine-form accumulation across steps).

def rol(x, s, n):
    m = (1 << n) - 1
    s %= n
    return ((x << s) | (x >> (n - s))) & m


def f1_ref(A, B, n):
    m = (1 << n) - 1
    lin = (A ^ B ^ rol(A, 1, n) ^ rol(B, 1, n) ^
           rol(A, n - 1, n) ^ rol(B, n - 1, n)) & m
    return (lin ^ rol((A + B) & m, n // 4, n)) & m


def revolve_ref(A, B, n, r):
    for _ in range(r):
        A = f1_ref(A, B, n)
    return A


class Circuit:
    """Sparse constraint system for y = F1^r(A, B), B public."""

    def __init__(self, n, r, B, y):
        self.n, self.r, self.B, self.y = n, r, B, y
        nv = 0
        self.a = [[None] * n for _ in range(r + 1)]
        self.c = [[None] * n for _ in range(r)]
        for t in range(r + 1):
            for i in range(n):
                self.a[t][i] = nv
                nv += 1
        for t in range(r):
            for i in range(1, n):
                self.c[t][i] = nv
                nv += 1
        self.n_vars = nv

        # Quadratic gates: (x_terms, y_terms, z_terms) — each a sparse
        # affine form [(var, coef), ...] + const, meaning val(x)*val(y)=val(z).
        # lin[]: sparse linear constraints  sum coef*var = rhs.
        self.gates = []
        self.lin = []
        self._build()

    def _aff(self, terms, const=0):
        return (terms, const)

    def _build(self):
        n, r, B = self.n, self.r, self.B
        # Booleanity of the secret input bits: a0_i * a0_i = a0_i.
        # (Carries are boolean by induction; later state bits are XORs of
        #  boolean values, hence boolean.)
        for i in range(n):
            v = self.a[0][i]
            self.gates.append((self._aff([(v, 1)]), self._aff([(v, 1)]),
                               self._aff([(v, 1)])))
        for t in range(r):
            bt = B
            # carry chain: c_1 = b0*a0 (linear, since b0 public)
            b0 = bt & 1
            self.lin.append(([(self.c[t][1], 1)] +
                             ([(self.a[t][0], 1)] if b0 else []), 0))
            # c_{i+1} = b_i*a_i XOR (a_i AND c_i) XOR b_i*c_i,  i = 1..n-2
            for i in range(1, n - 1):
                bi = (bt >> i) & 1
                zt = [(self.c[t][i + 1], 1)]
                if bi:
                    zt += [(self.a[t][i], 1), (self.c[t][i], 1)]
                self.gates.append((self._aff([(self.a[t][i], 1)]),
                                   self._aff([(self.c[t][i], 1)]),
                                   self._aff(zt)))
            # state update: a^{t+1}_j = lin_j XOR s_{(j - n/4) mod n}
            #   lin_j = a_j ^ b_j ^ a_{j-1} ^ b_{j-1} ^ a_{j+1} ^ b_{j+1}
            #   s_i   = a_i ^ b_i ^ c_i          (c_0 = 0)
            for j in range(n):
                i = (j - n // 4) % n
                terms = [(self.a[t + 1][j], 1),
                         (self.a[t][j], 1),
                         (self.a[t][(j - 1) % n], 1),
                         (self.a[t][(j + 1) % n], 1),
                         (self.a[t][i], 1)]
                if i > 0:
                    terms.append((self.c[t][i], 1))
                const = (((bt >> j) & 1) ^ ((bt >> ((j - 1) % n)) & 1) ^
                         ((bt >> ((j + 1) % n)) & 1) ^ ((bt >> i) & 1))
                # collapse duplicate vars (GF(2): pairs cancel)
                cnt = {}
                for v, _ in terms:
                    cnt[v] = cnt.get(v, 0) ^ 1
                terms = [(v, 1) for v, one in cnt.items() if one]
                self.lin.append((terms, const))
        # output: a^r_i = y_i
        for i in range(n):
            self.lin.append(([(self.a[r][i], 1)], (self.y >> i) & 1))

    def witness(self, A):
        """Honest witness from secret input A."""
        n, r, B = self.n, self.r, self.B
        w = [0] * self.n_vars
        At = A
        for t in range(r + 1):
            for i in range(n):
                w[self.a[t][i]] = (At >> i) & 1
            if t == r:
                break
            # carries of A^t + B
            c = 0
            for i in range(n - 1):
                ai, bi = (At >> i) & 1, (B >> i) & 1
                c = (ai & bi) | ((ai ^ bi) & c)
                w[self.c[t][i + 1]] = c
            At = f1_ref(At, B, n)
        return w


# ── §2  Ligero-lite prover / verifier ────────────────────────────────────────

def _H(*args):
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return h.digest()


def _fs_elements(seed, count):
    """Fiat-Shamir: derive `count` GF(2^16) elements from seed."""
    out, ctr = [], 0
    while len(out) < count:
        d = _H(seed, ctr.to_bytes(4, 'big'))
        for k in range(0, 32, 2):
            if len(out) >= count:
                break
            out.append((d[k] << 8) | d[k + 1])
        ctr += 1
    return out


def _fs_indices(seed, count, bound):
    """Fiat-Shamir: `count` distinct column indices in [0, bound)."""
    out, seen, ctr = [], set(), 0
    while len(out) < count:
        d = _H(seed, b'col', ctr.to_bytes(4, 'big'))
        for k in range(0, 32, 4):
            v = int.from_bytes(d[k:k + 4], 'big') % bound
            if v not in seen:
                seen.add(v)
                out.append(v)
                if len(out) >= count:
                    break
        ctr += 1
    return out


class RSEncoder:
    """Reed-Solomon: interpolate on points 1..l, evaluate on points 1..N.
    (Point 0 is avoided so all barycentric weights are invertible.)"""

    def __init__(self, l, N):
        assert N < GF_SIZE
        self.l, self.N = l, N
        self.pts = list(range(1, N + 1))
        # Lagrange basis over message points, evaluated at all N points:
        # basis[i][j] = L_i(pts[j])   (precomputed once, O(l*N))
        mpts = self.pts[:l]
        self._dinv = []
        self._coeff_cache = {}
        self.basis = []
        for i in range(l):
            denom = 1
            for k in range(l):
                if k != i:
                    denom = gmul(denom, mpts[i] ^ mpts[k])
            dinv = ginv(denom)
            self._dinv.append(dinv)
            row = []
            for j in range(N):
                if j < l:
                    row.append(1 if j == i else 0)
                    continue
                num = 1
                xj = self.pts[j]
                for k in range(l):
                    if k != i:
                        num = gmul(num, xj ^ mpts[k])
                row.append(gmul(num, dinv))
            self.basis.append(row)

    def encode(self, msg):
        """msg: l field elements -> N codeword symbols (systematic)."""
        l, N = self.l, self.N
        cw = list(msg) + [0] * (N - l)
        for j in range(l, N):
            acc = 0
            for i in range(l):
                mi = msg[i]
                if mi:
                    acc ^= gmul(mi, self.basis[i][j])
            cw[j] = acc
        return cw

    def lag_coeffs(self, x):
        """Lagrange coefficient vector at point x (cached): interpolant
        value = sum_i coeffs[i] * msg[i]."""
        c = self._coeff_cache.get(x)
        if c is not None:
            return c
        l = self.l
        mpts = self.pts[:l]
        if x in mpts:
            c = [0] * l
            c[mpts.index(x)] = 1
        else:
            full = 1
            for k in range(l):
                full = gmul(full, x ^ mpts[k])
            c = [gmul(gmul(full, ginv(x ^ mpts[i])), self._dinv[i])
                 for i in range(l)]
        self._coeff_cache[x] = c
        return c

    def interp_eval(self, msg, xs):
        """Evaluate the degree<l interpolant of msg at arbitrary points xs."""
        out = []
        for x in xs:
            c = self.lag_coeffs(x)
            acc = 0
            for i, mi in enumerate(msg):
                if mi:
                    acc ^= gmul(c[i], mi)
            out.append(acc)
        return out


def _merkle_build(leaves):
    lvl = [_H(b'leaf', x) for x in leaves]
    tree = [lvl]
    while len(lvl) > 1:
        if len(lvl) & 1:
            lvl = lvl + [lvl[-1]]
        lvl = [_H(b'node', lvl[i], lvl[i + 1]) for i in range(0, len(lvl), 2)]
        tree.append(lvl)
    return tree


def _merkle_path(tree, idx):
    path = []
    for lvl in tree[:-1]:
        sib = idx ^ 1
        if sib >= len(lvl):
            sib = idx
        path.append(lvl[sib])
        idx >>= 1
    return path


def _merkle_verify(root, leaf_bytes, idx, path):
    h = _H(b'leaf', leaf_bytes)
    for sib in path:
        if idx & 1:
            h = _H(b'node', sib, h)
        else:
            h = _H(b'node', h, sib)
        idx >>= 1
    return h == root


def _params(L, lam):
    """Choose (l, N, t, sigma) minimizing proof bytes for witness length L."""
    import math
    best = None
    for lg in range(4, 13):
        l = 1 << lg
        for rate_inv in (4, 8):
            N = l * rate_inv
            if N >= GF_SIZE:
                continue
            e = (N - l) // 3
            # (1 - e/N)^t <= 2^-lam
            frac = 1.0 - e / N
            t = math.ceil(lam / (-math.log2(frac)))
            if t >= N:
                continue
            sigma = -(-lam // GF_BITS)
            m = _matrix_rows(L, l)
            b = _size_bytes(l, N, m, t, sigma)
            if best is None or b < best[0]:
                best = (b, l, N, t, sigma)
    _, l, N, t, sigma = best
    return l, N, t, sigma


def _matrix_rows(L_parts, l):
    """L_parts = (n_vars, n_gates): rows = var rows + 3 * gate rows."""
    nv, ng = L_parts
    return -(-nv // l) + 3 * (-(-ng // l))


def _size_bytes(l, N, m, t, sigma, pruned=False):
    """Byte-accurate proof size model (matches serialization below)."""
    import math
    root = 32
    polys = sigma * (l + (2 * l - 1) + (2 * l - 1)) * 2   # w, q, p coeffs
    cols = t * m * 2
    if pruned:
        depth = max(1, math.ceil(math.log2(max(2, N / t))) + 1)
    else:
        depth = math.ceil(math.log2(N))
    merkle = t * depth * 32
    return root + polys + cols + merkle


def ligero_prove(circ, w, lam=40):
    """Non-interactive Ligero-lite proof. Returns (proof_dict, stats)."""
    nv, ng = circ.n_vars, len(circ.gates)
    l, N, t, sigma = _params((nv, ng), lam)
    mw = -(-nv // l)
    gx = -(-ng // l)
    m = mw + 3 * gx

    def aff_val(aff):
        terms, const = aff
        v = const
        for var, coef in terms:
            v ^= gmul(coef, w[var])
        return v

    # Extended witness rows: [vars | x | y | z], zero-padded.
    rows = []
    flat = list(w) + [0] * (mw * l - nv)
    for i in range(mw):
        rows.append(flat[i * l:(i + 1) * l])
    for block in range(3):
        vals = [aff_val(g[block]) for g in circ.gates] + [0] * (gx * l - ng)
        for i in range(gx):
            rows.append(vals[i * l:(i + 1) * l])

    enc = RSEncoder(l, N)
    U = [enc.encode(row) for row in rows]

    # Merkle-commit columns
    cols_bytes = []
    for j in range(N):
        cols_bytes.append(b''.join(U[i][j].to_bytes(2, 'big')
                                   for i in range(m)))
    tree = _merkle_build(cols_bytes)
    root = tree[-1][0]

    # extended-witness index of each block entry
    def xw_index(block, g):
        return mw * l + block * gx * l + g

    proof = {'root': root, 'l': l, 'N': N, 't': t, 'sigma': sigma,
             'm': m, 'mw': mw, 'gx': gx,
             'w_polys': [], 'q_polys': [], 'p_polys': []}

    transcript = root
    for s in range(sigma):
        seed = _H(transcript, b'combo', s.to_bytes(2, 'big'))
        # (a) proximity: random combo of all m rows -> message poly (l elems)
        rho_w = _fs_elements(_H(seed, b'w'), m)
        wmsg = [0] * l
        for i in range(m):
            ri = rho_w[i]
            if ri:
                for j in range(l):
                    if rows[i][j]:
                        wmsg[j] ^= gmul(ri, rows[i][j])
        proof['w_polys'].append(wmsg)

        # (b) linear test: random combo of ALL linear constraints
        #     (gate-copy ties + circuit lin constraints + output)
        rho_l = _fs_elements(_H(seed, b'lin'),
                             len(circ.lin) + 3 * ng)
        R = [0] * (m * l)          # combo vector over extended witness
        rhs = 0
        ci = 0
        for terms, const in circ.lin:
            rc = rho_l[ci]
            ci += 1
            for var, coef in terms:
                R[var] ^= gmul(rc, coef)
            rhs ^= gmul(rc, const)
        # copy ties: xw(block,g) - aff = 0
        for block in range(3):
            for g in range(ng):
                rc = rho_l[ci]
                ci += 1
                R[xw_index(block, g)] ^= rc
                terms, const = circ.gates[g][block]
                for var, coef in terms:
                    R[var] ^= gmul(rc, coef)
                rhs ^= gmul(rc, const)
        # q(x) = sum_i r_i(x) u_i(x): compute q's evaluations on message pts
        # and on the tail; we ship q as evaluations on 2l-1 points 1..2l-1.
        qpts = enc.pts[:2 * l - 1]
        qevals = [0] * (2 * l - 1)
        for i in range(m):
            Ri = R[i * l:(i + 1) * l]
            if not any(Ri):
                continue
            r_ev = Ri + enc.interp_eval(Ri, qpts[l:])
            u_ev = rows[i] + enc.interp_eval(rows[i], qpts[l:])
            for j in range(2 * l - 1):
                if r_ev[j] and u_ev[j]:
                    qevals[j] ^= gmul(r_ev[j], u_ev[j])
        proof['q_polys'].append(qevals)

        # (c) quadratic test: p(x) = sum_g rho_g (ux uy - uz), must vanish on
        #     message points.  Row-aligned: combine per gate-row.
        rho_q = _fs_elements(_H(seed, b'quad'), gx)
        pevals = [0] * (2 * l - 1)
        for i in range(gx):
            rq = rho_q[i]
            if not rq:
                continue
            rx = rows[mw + i]
            ry = rows[mw + gx + i]
            rz = rows[mw + 2 * gx + i]
            x_ev = rx + enc.interp_eval(rx, qpts[l:])
            y_ev = ry + enc.interp_eval(ry, qpts[l:])
            z_ev = rz + enc.interp_eval(rz, qpts[l:])
            for j in range(2 * l - 1):
                v = gmul(x_ev[j], y_ev[j]) ^ z_ev[j]
                if v:
                    pevals[j] ^= gmul(rq, v)
        proof['p_polys'].append(pevals)

        transcript = _H(transcript, bytes(2 * s + 1),
                        b''.join(v.to_bytes(2, 'big') for v in qevals))

    # column openings
    idxs = _fs_indices(_H(transcript, b'open'), t, N)
    proof['col_idx'] = idxs
    proof['cols'] = [[U[i][j] for i in range(m)] for j in idxs]
    proof['paths'] = [_merkle_path(tree, j) for j in idxs]
    return proof


def ligero_verify(circ, proof, lam=40):
    nv, ng = circ.n_vars, len(circ.gates)
    l, N, t, sigma = proof['l'], proof['N'], proof['t'], proof['sigma']
    m, mw, gx = proof['m'], proof['mw'], proof['gx']
    el, en, et, es = _params((nv, ng), lam)
    if (l, N, t, sigma) != (el, en, et, es) or m != mw + 3 * gx:
        return False
    root = proof['root']
    enc = RSEncoder(l, N)
    enc2 = RSEncoder(2 * l - 1, N)
    qpts = enc.pts[:2 * l - 1]

    def xw_index(block, g):
        return mw * l + block * gx * l + g

    # Recompute FS transcript and per-repetition combo vectors
    transcript = root
    combos = []
    for s in range(sigma):
        seed = _H(transcript, b'combo', s.to_bytes(2, 'big'))
        rho_w = _fs_elements(_H(seed, b'w'), m)
        rho_l = _fs_elements(_H(seed, b'lin'), len(circ.lin) + 3 * ng)
        rho_q = _fs_elements(_H(seed, b'quad'), gx)

        R = [0] * (m * l)
        rhs = 0
        ci = 0
        for terms, const in circ.lin:
            rc = rho_l[ci]
            ci += 1
            for var, coef in terms:
                R[var] ^= gmul(rc, coef)
            rhs ^= gmul(rc, const)
        for block in range(3):
            for g in range(ng):
                rc = rho_l[ci]
                ci += 1
                R[xw_index(block, g)] ^= rc
                terms, const = circ.gates[g][block]
                for var, coef in terms:
                    R[var] ^= gmul(rc, coef)
                rhs ^= gmul(rc, const)
        qevals = proof['q_polys'][s]
        # linear test: sum of q over message points == combo rhs
        if len(qevals) != 2 * l - 1:
            return False
        acc = 0
        for j in range(l):
            acc ^= qevals[j]
        if acc != rhs:
            return False
        # quadratic test: p vanishes on message points
        pevals = proof['p_polys'][s]
        if len(pevals) != 2 * l - 1:
            return False
        for j in range(l):
            if pevals[j] != 0:
                return False
        combos.append((rho_w, R, rho_q))
        transcript = _H(transcript, bytes(2 * s + 1),
                        b''.join(v.to_bytes(2, 'big') for v in qevals))

    # column checks
    idxs = _fs_indices(_H(transcript, b'open'), t, N)
    if idxs != proof['col_idx']:
        return False
    for k, j in enumerate(idxs):
        col = proof['cols'][k]
        if len(col) != m:
            return False
        leaf = b''.join(col[i].to_bytes(2, 'big') for i in range(m))
        if not _merkle_verify(root, leaf, j, proof['paths'][k]):
            return False
        xj = enc.pts[j]
        for s in range(sigma):
            rho_w, R, rho_q = combos[s]
            # (a) proximity: w-combo poly at xj == sum rho_w[i] * col[i]
            wmsg = proof['w_polys'][s]
            wj = enc.interp_eval(wmsg, [xj])[0] if j >= l else wmsg[j]
            acc = 0
            for i in range(m):
                if rho_w[i] and col[i]:
                    acc ^= gmul(rho_w[i], col[i])
            if acc != wj:
                return False
            # (b) linear: q(xj) == sum_i r_i(xj) * col[i]
            qevals = proof['q_polys'][s]
            if j < 2 * l - 1:
                qj = qevals[j]
            else:
                qj = enc2.interp_eval(qevals, [xj])[0]
            acc = 0
            for i in range(m):
                Ri = R[i * l:(i + 1) * l]
                if not any(Ri):
                    continue
                rij = enc.interp_eval(Ri, [xj])[0] if j >= l else Ri[j]
                if rij and col[i]:
                    acc ^= gmul(rij, col[i])
            if acc != qj:
                return False
            # (c) quadratic: p(xj) == sum_g rho_g (X Y - Z) at column j
            pevals = proof['p_polys'][s]
            if j < 2 * l - 1:
                pj = pevals[j]
            else:
                pj = enc2.interp_eval(pevals, [xj])[0]
            acc = 0
            for i in range(gx):
                if not rho_q[i]:
                    continue
                v = gmul(col[mw + i], col[mw + gx + i]) ^ col[mw + 2 * gx + i]
                if v:
                    acc ^= gmul(rho_q[i], v)
            if acc != pj:
                return False
    return True


def proof_bytes(proof):
    """Serialized size of the proof (2 bytes per field element)."""
    b = 32                                          # root
    for key in ('w_polys', 'q_polys', 'p_polys'):
        for poly in proof[key]:
            b += 2 * len(poly)
    for col in proof['cols']:
        b += 2 * len(col)
    for path in proof['paths']:
        b += 32 * len(path)
    return b


# ── §3  Completeness and soundness tests ─────────────────────────────────────

def section3_tests():
    print(SEP)
    print("§3  Completeness and soundness (n=32, r=4, lambda=40 demo)")
    print(SEP)
    n, r, lam = 32, 4, 40
    A = int.from_bytes(os.urandom(n // 8), 'big')
    B = int.from_bytes(os.urandom(n // 8), 'big')
    y = revolve_ref(A, B, n, r)
    circ = Circuit(n, r, B, y)
    w = circ.witness(A)

    t0 = time.time()
    proof = ligero_prove(circ, w, lam)
    t1 = time.time()
    ok = ligero_verify(circ, proof, lam)
    t2 = time.time()
    print(f"  completeness: verify(honest proof) = {ok}   "
          f"(prove {t1-t0:.1f}s, verify {t2-t1:.1f}s)")
    assert ok

    # wrong public output
    circ_bad = Circuit(n, r, B, y ^ 1)
    ok_bad = ligero_verify(circ_bad, proof, lam)
    print(f"  soundness (wrong y):            verify = {ok_bad}  (want False)")
    assert not ok_bad

    # tampered witness bit: re-prove with a flipped carry
    w_bad = list(w)
    w_bad[circ.c[0][1]] ^= 1
    proof_bad = ligero_prove(circ, w_bad, lam)
    ok_tamper = ligero_verify(circ, proof_bad, lam)
    print(f"  soundness (tampered carry bit): verify = {ok_tamper}  (want False)")
    assert not ok_tamper

    # non-boolean input value (booleanity gate must catch it)
    w_nb = list(w)
    w_nb[circ.a[0][0]] = 7          # not in {0,1}
    proof_nb = ligero_prove(circ, w_nb, lam)
    ok_nb = ligero_verify(circ, proof_nb, lam)
    print(f"  soundness (non-boolean input):  verify = {ok_nb}  (want False)")
    assert not ok_nb

    print("  all §3 assertions PASS")
    return proof


# ── §4  Proof-size measurement and model validation ─────────────────────────

def section4_sizes(demo_proof):
    print(SEP)
    print("§4  Proof size: measured vs model, and n=256 evaluation")
    print(SEP)

    # validate the byte model against the measured demo proof
    l, N, t, sigma, m = (demo_proof['l'], demo_proof['N'], demo_proof['t'],
                         demo_proof['sigma'], demo_proof['m'])
    measured = proof_bytes(demo_proof)
    modeled = _size_bytes(l, N, m, t, sigma)
    print(f"  demo (n=32, r=4, lambda=40):  measured {measured} B, "
          f"model {modeled} B, delta {abs(measured-modeled)} B")

    # second validation point: a REAL lambda=128 proof at n=64, r=8
    n2, r2, lam2 = 64, 8, 128
    A2 = int.from_bytes(os.urandom(n2 // 8), 'big')
    B2 = int.from_bytes(os.urandom(n2 // 8), 'big')
    y2 = revolve_ref(A2, B2, n2, r2)
    circ2 = Circuit(n2, r2, B2, y2)
    t0 = time.time()
    proof2 = ligero_prove(circ2, circ2.witness(A2), lam2)
    t1 = time.time()
    ok2 = ligero_verify(circ2, proof2, lam2)
    t2 = time.time()
    assert ok2
    l2, N2, t2q, s2, m2 = (proof2['l'], proof2['N'], proof2['t'],
                           proof2['sigma'], proof2['m'])
    meas2 = proof_bytes(proof2)
    mod2 = _size_bytes(l2, N2, m2, t2q, s2)
    print(f"  full (n=64, r=8, lambda=128): measured {meas2} B, "
          f"model {mod2} B, delta {abs(meas2-mod2)} B, verify={ok2}   "
          f"(prove {t1-t0:.1f}s, verify {t2-t1:.1f}s)")

    print()
    print(f"  {'statement':>28} {'lam':>4} {'L':>7} {'m x l':>10} "
          f"{'t':>4} {'sig':>4} {'KB':>8} {'KB pruned':>10}")
    rows = [
        ("single step n=256 (r=1)", 256, 1, 128),
        ("revolve n=256, r=64",     256, 64, 128),
    ]
    for label, n, r, lam in rows:
        nv = n * (r + 1) + r * (n - 1)
        ng = r * (n - 2) + n
        l, N, t, sigma = _params((nv, ng), lam)
        m = _matrix_rows((nv, ng), l)
        b = _size_bytes(l, N, m, t, sigma)
        bp = _size_bytes(l, N, m, t, sigma, pruned=True)
        print(f"  {label:>28} {lam:>4} {nv+3*ng:>7} {m:>5}x{l:<4} "
              f"{t:>4} {sigma:>4} {b/1024:>8.1f} {bp/1024:>10.1f}")

    print()
    print("  Reference points (SecurityProofs-3.md §11.10.6):")
    print("    ZKBoo  revolve n=256, r=64 : ~920 KB")
    print("    ZKB++  revolve n=256, r=64 : ~464 KB   (Batch 1, v1.9.81)")
    print("    target (SPHINCS+/Picnic)   : ~180 KB")


# ── §5  Conclusion ───────────────────────────────────────────────────────────

def section5_conclusion():
    print(SEP)
    print("§5  Conclusion")
    print(SEP)
    print("""\
  (1) The Ligero-lite IOP argument removes the per-repetition cost that
      dominates ZKBoo/ZKB++: ONE encoded witness serves all soundness,
      with security amplified by column queries (t) and cheap field-sized
      algebraic-combo repetitions (sigma = ceil(lambda/16)).
  (2) Over GF(2^16), the NL-FSCX circuit arithmetizes with XOR/ROL as
      linear maps; only the carry-chain AND gates and input booleanity
      are quadratic — the circuit shape ZKB++ could not exploit becomes
      the cheap part here.
  (3) The measured/modeled sizes at n=256, r=64 land in the Picnic range
      (see §4), a further ~2-3x below ZKB++'s 464 KB, confirming the
      Batch 3 prediction that the 180 KB target needs an IOP scheme.
  (4) Remaining gaps to production: zero-knowledge masking rows (the
      prototype is an argument of knowledge without the ZK randomizers —
      adding them costs one extra row per test, a few KB), a hardened
      soundness analysis (this script uses the conservative e < d/3
      regime of Ligero Thm 4.2), and constant-time implementation.""")


def main():
    print(SEP)
    print("Ligero-style IOP-based ZKP for NL-FSCX v1 — TODO #122 Batch 4")
    print(SEP)
    print(f"  field GF(2^{GF_BITS}), poly 0x{GF_POLY:X}")
    demo_proof = section3_tests()
    section4_sizes(demo_proof)
    section5_conclusion()


if __name__ == '__main__':
    main()
