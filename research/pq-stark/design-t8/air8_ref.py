#!/usr/bin/env python3
"""Executable companion of AIR-SPEC.md (Track 8 S0): a plain-Python reference of Poseidon2-Gl-8 and of the M1 and M2
AIRs, used to check that the specification is self-consistent BEFORE the Rust (S2) and JS (S3) AIRs are written.

It checks, for the constraint lists exactly as numbered in AIR-SPEC.md (same order = the order of alpha folding):
  1. Poseidon2-Gl-8 reproduces Plonky3's test vector (goldilocks/src/poseidon2.rs) with the round order of sec. 2;
  2. honest traces satisfy every constraint on every row (M1: leaf indices 0, 2^30 - 1, random; M2 likewise);
  3. ROOT and NF from the trace equal an independent native computation of the relation;
  4. single-cell mutation completeness: every one of the n x width main-trace cells, changed alone, violates some
     constraint (M2: some constraint of its table or the bus multiset);
  5. the Plonky3 constraint degree of every constraint (trace-size-aware rule of p3-air: poly degree with periodic
     columns at n - n/32, transition selector 1, boundary selectors n - 1; degree = ceil((deg - 1)/(n - 1))), the
     maximum per table and the resulting ZK quotient chunk count, against bytes8.py's shapes.
This is not the Plonky3 AIR: S2 must still pass check_constraints and the differential test against p3-goldilocks.

Run: python3 air8_ref.py       (single thread, ~1 minute)
"""
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bytes8 as b8  # noqa: E402

p = 2 ** 64 - 2 ** 32 + 1
K = json.load(open(os.path.join(HERE, 'poseidon2-gl8-constants.json')))
TAG_NF = 0x76632E6E66763031          # ASCII "vc.nfv01", < p
IV = (0, 0, 0, TAG_NF)

M4 = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
ME = [[M4[i % 4][j % 4] * (2 if i // 4 == j // 4 else 1) for j in range(8)] for i in range(8)]
DG = K['matrix_diag_8']
MI = [[((DG[i] if i == j else 0) + 1) % p for j in range(8)] for i in range(8)]


def mv(M, x):
    return [sum(M[i][j] * x[j] for j in range(8)) % p for i in range(8)]


def perm(x):
    x = mv(ME, x)
    for r in range(4):
        x = mv(ME, [pow((x[i] + K['external_initial'][r][i]) % p, 7, p) for i in range(8)])
    for r in range(22):
        x = list(x)
        x[0] = pow((x[0] + K['internal'][r]) % p, 7, p)
        x = mv(MI, x)
    for r in range(4):
        x = mv(ME, [pow((x[i] + K['external_final'][r][i]) % p, 7, p) for i in range(8)])
    return x


def T(x):
    return x[:4]


def compress(left, right):
    return T(perm(list(left) + list(right)))


# ---------------------------------------------------------------- periodic columns (period 32), AIR-SPEC sec. 3.3
def periodic_row(r):
    """[rc0..rc7, F, Pt, C] at slot row r."""
    rc = [0] * 8
    F = Pt = C = 0
    if 1 <= r <= 4:
        rc, F = list(K['external_initial'][r - 1]), 1
    elif 5 <= r <= 26:
        rc, Pt = [K['internal'][r - 5]] + [0] * 7, 1
    elif 27 <= r <= 30:
        rc, F = list(K['external_final'][r - 27]), 1
    elif r == 31:
        C = 1
    return rc + [F, Pt, C]


PER = [periodic_row(r) for r in range(32)]


def slot_rows(inp):
    """32 rows (s[8], u[8]) of one permutation of `inp` (M1/T_hash layout, u zero where unused)."""
    rows = []
    s = list(inp)
    for r in range(32):
        rc, F, Pt, C = PER[r][:8], PER[r][8], PER[r][9], PER[r][10]
        u = [0] * 8
        if F:
            u = [pow((s[i] + rc[i]) % p, 3, p) for i in range(8)]
            nxt = mv(ME, [u[i] * u[i] % p * ((s[i] + rc[i]) % p) % p for i in range(8)])
        elif Pt:
            u[0] = pow((s[0] + rc[0]) % p, 3, p)
            nxt = mv(MI, [u[0] * u[0] % p * ((s[0] + rc[0]) % p) % p] + s[1:])
        elif not C:            # L row
            nxt = mv(ME, s)
        rows.append([list(s), u])
        if not C:
            s = nxt
    return rows


# ---------------------------------------------------------------- M1
def m1_witness(rng, leaf_index):
    nk = [rng.randrange(p) for _ in range(4)]
    r = [rng.randrange(p) for _ in range(4)]
    bits = [(leaf_index >> i) & 1 for i in range(30)]          # b_1 = LSB
    sibs = [[rng.randrange(p) for _ in range(4)] for _ in range(30)]
    return nk, r, bits, sibs


def m1_native(nk, r, bits, sibs):
    NF = T(perm(list(nk) + list(IV)))
    node = compress(NF, r)                                     # leaf
    for b, S in zip(bits, sibs):
        node = compress(S, node) if b else compress(node, S)
    return NF, node


def m1_trace(nk, r, bits, sibs):
    rows = []
    inp = list(nk) + list(IV)
    for k in range(32):
        sr = slot_rows(inp)
        if k == 0:
            cu = list(r) + [0]
        elif k <= 30:
            cu = list(sibs[k - 1]) + [bits[k - 1]]
        else:
            cu = [0] * 5
        sr[31][1][:5] = cu
        for i, (s, u) in enumerate(sr):
            rows.append(s + u + [1 if k == 0 else 0])
        out = sr[31][0][:4]
        b, sib = cu[4], cu[:4]
        inp = (sib + out) if b else (out + sib)
    return rows


# constraint descriptors: (name, degree terms, fn). degree terms: list of products of factor kinds
#   T trace/preprocessed column, P periodic, B boundary selector (first/last), X transition selector, 1 constant
def m1_constraints(pub):
    ROOT, NF = pub[0:4], pub[4:8]
    cs = []

    def add(name, terms, fn):
        cs.append((name, terms, fn))
    for i in range(8):                                                     # (A) S-box
        add(f'A{i} sbox', [['P', 'T'], ['P', 'T', 'T', 'T']],
            lambda L, N, P_, sel, i=i: ((P_[8] + (P_[9] if i == 0 else 0)) * (L[8 + i] - pow((L[i] + P_[i]) % p, 3, p))) % p)
    for i in range(8):                                                     # (B) unused u = 0
        def tau(P_, i=i):
            Lr = (1 - P_[8] - P_[9] - P_[10]) % p
            return Lr if i == 0 else (P_[9] + Lr) % p if i <= 4 else (P_[9] + Lr + P_[10]) % p
        add(f'B{i} u-zero', [['P', 'T']], lambda L, N, P_, sel, i=i, tau=tau: tau(P_) * L[8 + i] % p)
    for j in range(8):                                                     # (C) round
        def rnd(L, N, P_, sel, j=j):
            F, Pt, C = P_[8], P_[9], P_[10]
            Lr = (1 - F - Pt - C) % p
            fr = sum(ME[j][i] * L[8 + i] * L[8 + i] % p * ((L[i] + P_[i]) % p) for i in range(8))
            pr = MI[j][0] * L[8] * L[8] % p * ((L[0] + P_[0]) % p) + sum(MI[j][i] * L[i] for i in range(1, 8))
            lr = sum(ME[j][i] * L[i] for i in range(8))
            return ((1 - C) * N[j] - (F * fr + Pt * pr + Lr * lr)) % p
        add(f'C{j} round', [['P', 'T'], ['P', 'T', 'T', 'T'], ['P', 'T']], rnd)
    for j in range(8):                                                     # (D) chain
        def ch(L, N, P_, sel, j=j):
            u4 = L[12]
            w = (L[j] + u4 * (L[8 + j] - L[j])) if j < 4 else (L[8 + j - 4] + u4 * (L[j - 4] - L[8 + j - 4]))
            return sel['tr'] * P_[10] * (N[j] - w) % p
        add(f'D{j} chain', [['X', 'P', 'T'], ['X', 'P', 'T', 'T']], ch)
    add('E bit', [['P', 'T', 'T']], lambda L, N, P_, sel: P_[10] * L[12] * (L[12] - 1) % p)
    add('F0 z first', [['B', 'T']], lambda L, N, P_, sel: sel['first'] * (L[16] - 1) % p)
    add('F1 z step', [['X', 'T'], ['X', 'P', 'T']], lambda L, N, P_, sel: sel['tr'] * (N[16] - (1 - P_[10]) * L[16]) % p)
    add('F2 z bit', [['P', 'T', 'T']], lambda L, N, P_, sel: P_[10] * L[16] * L[12] % p)
    for k in range(4):
        add(f'G{k} iv', [['B', 'T']], lambda L, N, P_, sel, k=k: sel['first'] * (L[4 + k] - IV[k]) % p)
    for j in range(4):
        add(f'H{j} nf', [['P', 'T', 'T']], lambda L, N, P_, sel, j=j: P_[10] * L[16] * (L[j] - NF[j]) % p)
    for j in range(4):
        add(f'I{j} root', [['B', 'T']], lambda L, N, P_, sel, j=j: sel['last'] * (L[j] - ROOT[j]) % p)
    for i in range(5):
        add(f'J{i} last u', [['B', 'T']], lambda L, N, P_, sel, i=i: sel['last'] * L[8 + i] % p)
    return cs


def plonky3_degree(terms, n, period=32):
    d = {'T': n - 1, 'P': n - n // period, 'B': n - 1, 'X': 1, '1': 0}
    poly = max(sum(d[f] for f in t) for t in terms)
    return (poly - 1 + (n - 2)) // (n - 1) if poly else 0


def check_rows(rows, cs, pre=None, per_period=32, rowset=None):
    n = len(rows)
    bad = []
    for r in (range(n) if rowset is None else rowset):
        r %= n
        L, N = rows[r], rows[(r + 1) % n]
        P_ = PER[r % per_period] if per_period else []
        if pre is not None:
            L = L + pre[r]
            N = N + pre[(r + 1) % n]
        sel = dict(first=1 if r == 0 else 0, last=1 if r == n - 1 else 0, tr=0 if r == n - 1 else 1)
        for name, _, fn in cs:
            if fn(L, N, P_, sel) != 0:
                bad.append((r, name))
    return bad


def mutation_scan(rows, cs, extra=None, pre=None, per_period=32):
    """Every single-cell change must violate a local constraint (rows r-1, r) or `extra` (global, e.g. the bus)."""
    n, w = len(rows), len(rows[0])
    missed = []
    for r in range(n):
        for c in range(w):
            old = rows[r][c]
            rows[r][c] = (old + 1) % p
            hit = bool(check_rows(rows, cs, pre, per_period, rowset=(r - 1, r)))
            if not hit and extra is not None:
                hit = not extra(rows)
            rows[r][c] = old
            if not hit:
                missed.append((r, c))
    return missed


# ---------------------------------------------------------------- M2
def m2_traces(nk, r, bits, sibs):
    """T_hash (1024 x 24, pre lvl_h) and T_ctl (128 x 13, pre [lvl, f_null, f_leaf, f_root, f_used])."""
    ins, outs, bs = [], [], []
    inp, b = list(nk) + list(IV), 0
    for k in range(32):
        out = T(perm(inp))
        ins.append(inp)
        outs.append(out)
        bs.append(b)
        if k == 0:
            b, sib = 0, list(r)
        elif k <= 30:
            b, sib = bits[k - 1], list(sibs[k - 1])
        else:
            break
        inp = (sib + out) if b else (out + sib)
    th, th_pre = [], []
    for k in range(32):
        sr = slot_rows(ins[k])
        for s, u in sr:
            th.append(s + u + list(ins[k]))
            th_pre.append([k])
    tc, tc_pre = [], []
    for k in range(128):
        if k < 32:
            tc.append(list(ins[k]) + list(outs[k]) + [bs[k]])
            tc_pre.append([k, 1 if k == 0 else 0, 1 if k == 1 else 0, 1 if k == 31 else 0, 1])
        elif k == 32:
            tc.append(list(outs[31]) + [0] * 4 + [0] * 4 + [0])
            tc_pre.append([0, 0, 0, 0, 0])
        else:
            tc.append([0] * 13)
            tc_pre.append([0, 0, 0, 0, 0])
    return th, th_pre, tc, tc_pre


def thash_constraints():
    cs = []

    def add(name, terms, fn):
        cs.append((name, terms, fn))
    base = m1_constraints([0] * 12)
    for name, terms, fn in base[:8]:                                       # (A) S-box, as M1
        add(name, terms, fn)
    for i in range(8):                                                     # (B') unused u = 0 (u never used on C rows)
        def tau(P_, i=i):
            Lr = (1 - P_[8] - P_[9] - P_[10]) % p
            return (Lr + P_[10]) % p if i == 0 else (P_[9] + Lr + P_[10]) % p
        add(f"B'{i} u-zero", [['P', 'T']], lambda L, N, P_, sel, i=i, tau=tau: tau(P_) * L[8 + i] % p)
    for name, terms, fn in base[16:24]:                                    # (C) round, as M1
        add(name, terms, fn)
    for j in range(8):                                                     # (K) load
        add(f'K{j} load', [['P', 'T']], lambda L, N, P_, sel, j=j: (1 - P_[8] - P_[9] - P_[10]) * (L[j] - L[16 + j]) % p)
    for j in range(8):                                                     # (M) carry
        add(f'M{j} carry', [['P', 'T']], lambda L, N, P_, sel, j=j: (1 - P_[10]) * (N[16 + j] - L[16 + j]) % p)
    return cs


def tctl_constraints(pub):
    ROOT, NF = pub[0:4], pub[4:8]
    cs = []

    def add(name, terms, fn):
        cs.append((name, terms, fn))
    # main: in 0..7, out 8..11, b 12; pre appended: lvl 13, f_null 14, f_leaf 15, f_root 16, f_used 17
    for k in range(4):
        add(f'N1.{k} iv', [['T', 'T']], lambda L, N, P_, sel, k=k: L[14] * (L[4 + k] - IV[k]) % p)
    for j in range(4):
        add(f'N2.{j} nf', [['T', 'T']], lambda L, N, P_, sel, j=j: L[14] * (L[8 + j] - NF[j]) % p)
    for j in range(4):
        add(f'N3.{j} root', [['T', 'T']], lambda L, N, P_, sel, j=j: L[16] * (L[8 + j] - ROOT[j]) % p)
    add('N4 leaf/null bit', [['T', 'T']], lambda L, N, P_, sel: (L[14] + L[15]) * L[12] % p)
    add('N5 bit', [['T', 'T']], lambda L, N, P_, sel: L[12] * (L[12] - 1) % p)
    for j in range(4):
        add(f'N6.{j} chain-left', [['X', 'T', 'T']], lambda L, N, P_, sel, j=j: sel['tr'] * (1 - N[12]) * (N[j] - L[8 + j]) % p)
    for j in range(4):
        add(f'N7.{j} chain-right', [['X', 'T', 'T']], lambda L, N, P_, sel, j=j: sel['tr'] * N[12] * (N[4 + j] - L[8 + j]) % p)
    for j in range(4):
        add(f'N8.{j} pad out', [['T', 'T']], lambda L, N, P_, sel, j=j: (1 - L[17]) * L[8 + j] % p)
    add('N8.4 pad b', [['T', 'T']], lambda L, N, P_, sel: (1 - L[17]) * L[12] % p)
    for j in range(4):
        add(f'N8.{5 + j} pad sib', [['T', 'T']], lambda L, N, P_, sel, j=j: (1 - L[17]) * L[4 + j] % p)
    return cs


def bus_ok(th, th_pre, tc, tc_pre):
    recv = sorted(tuple([th_pre[i][0]] + th[i][16:24] + th[i][0:4]) for i in range(len(th)) if PER[i % 32][10])
    send = []
    for i in range(len(tc)):
        m = tc_pre[i][4]
        send += [tuple([tc_pre[i][0]] + tc[i][0:8] + tc[i][8:12])] * m
    return recv == sorted(send)


def main():
    rng = random.Random(20261030)
    res = {}
    tv = K['test_vector']
    ok = perm(tv['input']) == tv['output']
    print(f'1. Poseidon2-Gl-8 test vector (Plonky3 goldilocks/src/poseidon2.rs): {"PASS" if ok else "FAIL"}')
    res['poseidon2_test_vector'] = ok
    n = 1024
    m1_deg = None
    for label, idx in (('leaf 0', 0), ('leaf 2^30-1', 2 ** 30 - 1), ('leaf random', rng.randrange(2 ** 30))):
        nk, r, bits, sibs = m1_witness(rng, idx)
        NF, ROOT = m1_native(nk, r, bits, sibs)
        CTX = [rng.randrange(2 ** 56) for _ in range(4)]
        pub = ROOT + NF + CTX
        rows = m1_trace(nk, r, bits, sibs)
        cs = m1_constraints(pub)
        bad = check_rows(rows, cs)
        same = rows[n - 1][0:4] == ROOT and rows[31][0:4] == NF
        print(f'2. M1 {label}: {len(cs)} constraints, violations {len(bad)}; trace ROOT/NF == native: {same}')
        res[f'm1 {label}'] = dict(violations=len(bad), native_match=same)
        if label == 'leaf random':
            miss = mutation_scan(rows, cs)
            print(f'4. M1 single-cell mutation completeness: {n * len(rows[0]) - len(miss)} / {n * len(rows[0])} cells caught'
                  f'{"" if not miss else "; missed " + str(miss[:10])}')
            res['m1 mutation_missed'] = len(miss)
            # wrong public values are rejected
            for nm, pv in (('NF+1', ROOT + [(NF[0] + 1) % p] + NF[1:] + CTX), ('foreign ROOT', [(ROOT[0] + 1) % p] + ROOT[1:] + NF + CTX)):
                print(f'   M1 with {nm}: violations {len(check_rows(rows, m1_constraints(pv)))} (must be > 0)')
        m1_deg = {name: plonky3_degree(terms, n) for name, terms, _ in cs}
    mx = max(m1_deg.values())
    t = b8.M1[0]
    print(f'5. M1 Plonky3 degrees: max {mx} (bytes8 {t.max_deg}), constraints {len(m1_deg)} (bytes8 {t.num_constraints}), '
          f'ZK chunks {b8.num_chunks(replace_deg(t, mx), True)}; per group ' +
          ', '.join(f'{g}:{max(v for k, v in m1_deg.items() if k.startswith(g))}' for g in 'ABCDEFGHIJ'))
    res['m1_degrees'] = m1_deg
    assert mx == t.max_deg and len(m1_deg) == t.num_constraints

    # M2
    nk, r, bits, sibs = m1_witness(rng, rng.randrange(2 ** 30))
    NF, ROOT = m1_native(nk, r, bits, sibs)
    pub = ROOT + NF + [0] * 4
    th, th_pre, tc, tc_pre = m2_traces(nk, r, bits, sibs)
    ch, cc = thash_constraints(), tctl_constraints(pub)
    bh = check_rows(th, ch)
    bc = check_rows([a + b for a, b in zip(tc, tc_pre)], cc, per_period=0)
    bus = bus_ok(th, th_pre, tc, tc_pre)
    print(f'2. M2: T_hash {len(ch)} AIR constraints, violations {len(bh)}; T_ctl {len(cc)} AIR constraints, violations {len(bc)}; '
          f'bus multisets equal: {bus}; T_ctl row 31 out == ROOT: {tc[31][8:12] == ROOT}, row 0 out == NF: {tc[0][8:12] == NF}')
    res['m2'] = dict(thash_violations=len(bh), tctl_violations=len(bc), bus=bus)
    # mutation completeness, T_hash (bus as the global check) and T_ctl main columns
    mh = mutation_scan(th, ch, extra=lambda rows: bus_ok(rows, th_pre, tc, tc_pre))
    tcm = [a + b for a, b in zip(tc, tc_pre)]
    missed_c = []
    for rr in range(128):
        for c in range(13):
            old = tcm[rr][c]
            tcm[rr][c] = (old + 1) % p
            hit = bool(check_rows(tcm, cc, per_period=0, rowset=(rr - 1, rr)))
            if not hit:
                hit = not bus_ok(th, th_pre, [x[:13] for x in tcm], tc_pre)
            tcm[rr][c] = old
            if not hit:
                missed_c.append((rr, c))
    print(f'4. M2 single-cell mutation completeness: T_hash {1024 * 24 - len(mh)} / {1024 * 24}, '
          f'T_ctl {128 * 13 - len(missed_c)} / {128 * 13}' + (f'; missed {mh[:5]} {missed_c[:5]}' if mh or missed_c else ''))
    res['m2_mutation_missed'] = dict(thash=len(mh), tctl=len(missed_c))
    dh = {name: plonky3_degree(terms, 1024) for name, terms, _ in ch}
    dc = {name: plonky3_degree(terms, 128) for name, terms, _ in cc}
    th_t, tc_t = b8.M2
    # LogUp adds per AIR: 1 fraction constraint (degree 2 here) + 3 accumulator constraints (degree <= 2)
    print(f'5. M2 Plonky3 degrees: T_hash max {max(dh.values())} (bytes8 {th_t.max_deg}), {len(dh)} + 4 LogUp = '
          f'{len(dh) + 4} constraints (bytes8 {th_t.num_constraints}); T_ctl max {max(dc.values())} (bytes8 {tc_t.max_deg}), '
          f'{len(dc)} + 4 = {len(dc) + 4} (bytes8 {tc_t.num_constraints}); LogUp fraction constraint degree 2 '
          f'(frac x denominator, both degree 1; multiplicity C periodic / f_used preprocessed, degree 1)')
    assert max(dh.values()) == th_t.max_deg and len(dh) + 4 == th_t.num_constraints
    assert max(dc.values()) == tc_t.max_deg and len(dc) + 4 == tc_t.num_constraints
    res['m2_degrees'] = dict(thash=dh, tctl=dc)
    allok = (ok and all(v['violations'] == 0 and v['native_match'] for k, v in res.items() if k.startswith('m1 leaf'))
             and res['m1 mutation_missed'] == 0 and not bh and not bc and bus and not mh and not missed_c)
    print(f'ALL: {"PASS" if allok else "FAIL"}')
    res['all_pass'] = allok
    json.dump(res, open(os.path.join(HERE, 'air8_ref-output.json'), 'w'), indent=1)
    return allok


def replace_deg(t, d):
    from dataclasses import replace
    return replace(t, max_deg=d)


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
