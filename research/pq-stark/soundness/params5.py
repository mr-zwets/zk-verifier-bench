#!/usr/bin/env python3
"""Track 5 soundness calculator: round-by-round (RBR) Fiat-Shamir soundness of a DEEP-ALI STARK with batched FRI.

Replaces Track 4's "lambda_IOP = min(ALI, DEEP, eps_C, query)" model (research/pq-hash/params.py), whose commit term was
the *combined* BCIKS20 Thm 8.3 error eps_C, with per-round errors taken from published theorems. See SOUNDNESS.md.

Sources (theorem numbers as in the versions read for this work):
  [BCIKS]  Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, "Proximity Gaps for Reed-Solomon Codes", ECCC TR20-083 rev. 3
           (= ePrint 2020/654, J. ACM 2023). Thm 1.2 (eps_U = n/q, eps_J), Thm 1.5 (curves, l*eps), Thm 1.6 (affine
           spaces), Thm 7.2 (weighted curves, Johnson, explicit m), Thm 7.4 (weighted affine spaces, explicit m),
           Lemma 8.2 + its proof (sec. 8.2.1: one bad event E^(0) for batching, one E^(i+1) per fold), Thm 8.3.
  [ADK]    Atapoor, Delpech de Saint Guilhem, Kindi, "STARK-Based Signatures from the RPO Permutation", IACR
           Communications in Cryptology vol. 3 no. 2 (ePrint 2024/1553). Thm 2 (DEEP-ALI + batched FRI RBR knowledge
           soundness, list decoding), Thm 3 (same, unique decoding), Thm 1 (= Chiesa-Yogev Thm 31.3.1: RBR => state
           restoration, eps_SR <= (t + k) * eps_RBR).
  [BGKTTZ] Block, Garreta, Katz, Thaler, Tiwari, Zajac, "Fiat-Shamir Security of FRI and Related SNARKs", ASIACRYPT 2023
           (ePrint 2023/1071). Thm 6/7 (FRI / batched FRI RBR error max{(m+1/2)^7 |L0|^2 / (3 rho^1.5 |F|), (1-delta)^l}),
           Cor. 4/5 (BCS: eps_fs = Q * eps_rbr + 3(Q^2+1)/2^kappa), Thm 8 + Lemma 1 (delta-correlated IOPs: outer round
           errors are multiplied by 1/(2 eta sqrt(rho)), the Johnson list size).

Regimes:
  'JB'  list decoding, per-round errors of [ADK] Thm 2 (built on [BCIKS] Lemma 8.2, Thm 7.2/7.4). PROVEN.
  'UD'  unique decoding, per-round errors of [ADK] Thm 3 (built on [BCIKS] Thm 1.5/1.6 UD part). PROVEN, conservative.
  'DKT' SENSITIVITY ONLY: the linear-in-n Johnson line count C = 8 n (m+1/2)^3 / (3 rho) that Plonky3's p3-security uses
        (ePrint 2026/2056, Thm 5.12; 2026 preprint, not peer reviewed). Never used for a recommended set.

Batching variants: 'indep' (independent coefficients, Track 4) and 'powers' (one challenge and its powers, Plonky3).
For powers we use [BCIKS] Thm 7.2 (curves of degree t-1) in place of Thm 7.4 in the batching round: the [ADK]/[BCIKS]
proof is unchanged otherwise (BGKTTZ sec. 1, "this version ... incurs some soundness loss proportional to t").

Run:  python3 params5.py           report (tables in SOUNDNESS.md)
      python3 params5.py --json    machine-readable rows
Standard library only. Imports Track 4's byte/layout model from ../../pq-hash/params.py.
"""
import json
import math
import os
import sys
from dataclasses import dataclass, asdict, replace, field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'pq-hash'))
import params as t4  # noqa: E402  (Track 4 calculator: Params, fri_shape, proof_bytes, layouts)

P_GL = t4.P_GL
lg = math.log2


def log_q(e):
    return e * lg(P_GL)


# ============================================================== generic per-round bounds
def list_size_adk(m, rho, N):
    """[ADK] Thm 2 item 1: L = m / (rho - 2m/|D|)  (= 1/(2 eta sqrt(rho+)) up to the OOD expansion; cf. BGKTTZ Lemma 1)."""
    return m / (rho - 2.0 * m / N)


def A0(m, rho, N, lq):
    """[BCIKS] Thm 7.4 / [ADK] Thm 2 eps_3: (m+1/2)^7 |D|^2 / (3 rho^{3/2} q), as log2."""
    return 7 * lg(m + 0.5) + 2 * lg(N) - lg(3) - 1.5 * lg(rho) - lq


def B1(m, rho, N, lq):
    """[BCIKS] Thm 7.2/7.4 second term (weighted agreement): (2m+1)(M n + 1) / (sqrt(rho) q) with M n = |D0|, as log2."""
    return lg(2 * m + 1) + lg(N + 1) - 0.5 * lg(rho) - lq


def ladd(*xs):
    """log2(sum 2^x)."""
    mx = max(xs)
    return mx + lg(sum(2 ** (x - mx) for x in xs))


def deep_numerator(d, k, f, ell, combo=2, chunks=None):
    """[ADK] Thm 2 item 2 numerator max{d(k+ - 1) + (k-1), k + (f-1) ell + (k+ - 1)}, k+ = k + 2; with Plonky3's chunked
    form (c+1) k + combo - 1 (p3-security deep.rs) when `chunks` is given. Conservative max of all forms."""
    kp = k + 2
    v = max(d * (kp - 1) + (k - 1), k + (f - 1) * ell + (kp - 1))
    if chunks is not None:
        v = max(v, d * (k + combo - 1) + (k - 1), (chunks + 1) * k + combo - 1)
    return v


def dkt_line_log2(m, rho, N):
    """SENSITIVITY: ePrint 2026/2056 Thm 5.12 line count C = 8 n (m+1/2)^3 / (3 rho), as log2 (p3-security proximity.rs)."""
    return 3 + lg(N) + 3 * lg(m + 0.5) - lg(3) - lg(rho)


# ============================================================== Track 4 protocol (pq-hash SPEC.md)
# rounds: ALI (alpha_1..4 independent) | DEEP (z) | batch gamma_1..5 (independent) AND first fold beta_1, drawn in the
# SAME round from t3 (f0 is virtual, nothing is committed in between) | fold beta_2.. | query (after g-bit grinding).
def rounds_t4(p: t4.Params, regime: str):
    N, arities, sizes, _ = t4.fri_shape(p)
    n = 2 ** p.log_n
    rho = 2.0 ** -p.log_blowup
    lq = log_q(p.e)
    lqz = lg(P_GL ** p.e - P_GL)          # z uniform on F_q \ F_p (verifier rejects z in F_p)
    num = deep_numerator(t4.D, n, t4.SEG, n)
    r = {}
    if regime == 'JB':
        m = p.m
        L = list_size_adk(m, rho, N)
        r['ali'] = lq - lg(L)                                     # [ADK] Thm 2 item 1, independent alphas
        r['deep'] = lqz - 2 * lg(L) - lg(num)                     # item 2 (L^2, the conservative published charge)
        a0, b1 = A0(m, rho, N, lq), B1(m, rho, N, lq)
        batch = ladd(a0, b1)                                      # item 3 (+ Thm 7.4's second term, summed)
        folds = []
        for i, a in enumerate(arities):                           # item 4, with a_i * B1 (as BCIKS eps_C) for safety
            folds.append(ladd(lg(a - 1) + a0 + 2 * lg(sizes[i + 1] / N), lg(a) + b1))
        r['batch+fold1'] = -ladd(batch, folds[0])                 # merged round (union bound)
        for i in range(1, len(folds)):
            r[f'fold{i + 1}'] = -folds[i]
        r['query'] = -p.s * lg(math.sqrt(rho) * (1 + 1 / (2 * m)))  # item 5
    elif regime == 'UD':
        r['ali'] = lq                                             # [ADK] Thm 3 item 1: 1/|G|
        r['deep'] = lqz - lg(num)                                 # item 2
        batch = lg(N) - lq                                        # item 3: |D|/|G|  ([BCIKS] Thm 1.6, eps_U)
        folds = [lg(a - 1) + lg(N + 1) - lq for a in arities]     # item 4: (t-1)(|D|+1)/|G|
        r['batch+fold1'] = -ladd(batch, folds[0])
        for i in range(1, len(folds)):
            r[f'fold{i + 1}'] = -folds[i]
        rho_p = (n + 2) / N
        r['query'] = -p.s * lg((1 + rho_p) / 2)                    # item 5
    elif regime == 'DKT':                                         # sensitivity only
        m = p.m
        L = (m + 0.5) / math.sqrt(rho)
        C = dkt_line_log2(m, rho, N)
        r['ali'] = lq - lg(L)
        r['deep'] = lqz - lg(L) - lg(num)
        batch = lg(t4.M_D - 1) + C - lq
        folds = [lg(a - 1) + C - lq for a in arities]
        r['batch+fold1'] = -ladd(batch, folds[0])
        for i in range(1, len(folds)):
            r[f'fold{i + 1}'] = -folds[i]
        r['query'] = -p.s * lg(math.sqrt(rho) * (1 + 1 / (2 * m)))
    else:
        raise ValueError(regime)
    # grinding: g on the query round; g_c (if any) on every commit-phase challenge (Track 4 variant U128g)
    # (Track 4 convention: U128g's g_c nonces sit before alpha, z, gamma/beta_1 and every later beta)
    return {k: v + (p.g if k == 'query' else p.g_c) for k, v in r.items()}


def digest_bits(h, strict=False):
    """Merkle/RO collision term. Convention (Track 4, ethSTARK, Plonky3): 4h. strict: BGKTTZ Cor. 5's 3(Q^2+1)/2^(8h)
    must stay <= Q 2^-lambda for all Q <= 2^lambda  =>  lambda <= 4h - log2(3)/2."""
    return 4 * h - (0.5 * lg(3) if strict else 0)


def summarize(rounds, h):
    lam_iop = min(rounds.values())
    return dict(rounds={k: round(v, 2) for k, v in rounds.items()}, lam_iop=round(lam_iop, 2),
                binding=min(rounds, key=rounds.get),
                lam=round(min(lam_iop, digest_bits(h)), 2), lam_strict=round(min(lam_iop, digest_bits(h, True)), 2))


def t4_soundness(p, regime):
    return summarize(rounds_t4(p, regime), p.h)


def t4_min_queries(p, target, regime):
    lo, hi = 1, 3000
    if t4_soundness(replace(p, s=hi), regime)['lam_iop'] < target:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if t4_soundness(replace(p, s=mid), regime)['lam_iop'] >= target:
            hi = mid
        else:
            lo = mid + 1
    return replace(p, s=lo)


# ============================================================== Plonky3-style configuration
@dataclass
class P3:
    """Plonky3 (Oct 2026 main, 0d80373) uni-stark + TwoAdicFriPcs, Goldilocks, SHA-256 MMCS (32-byte digests).
    FriParameters fields: log_blowup, log_final_poly_len, max_log_arity, num_queries, batch_proof_of_work_bits,
    commit_proof_of_work_bits, query_proof_of_work_bits; uni-stark adds ood_pow_bits (before zeta). No PoW site exists
    before the constraint-folding challenge alpha (ALI)."""
    name: str
    regime: str               # 'JB' | 'UD' | 'DKT'
    e: int                    # extension degree (Plonky3 Goldilocks ships 2 and 5; 3 needs a BinomiallyExtendable<3> impl)
    log_n: int                # trace rows (before ZK doubling)
    log_blowup: int
    max_log_arity: int
    log_final_poly_len: int
    num_queries: int
    query_pow: int = 0
    commit_pow: int = 0
    batch_pow: int = 0
    ood_pow: int = 0
    m: int = 3
    zk: bool = False
    rand_cols: int = 0        # HidingFriPcs num_random_codewords (zk only)
    # AIR shape (reference: Track 4's MiMC-7 AIR written for Plonky3; selectors raise the degree to 4)
    width: int = 2
    pre_width: int = 0        # preprocessed columns (0: round constants as periodic columns)
    num_constraints: int = 4
    max_deg: int = 4
    max_combo: int = 2
    h: int = 32               # SHA-256, no truncation in Plonky3's MerkleTreeMmcs

    @property
    def k(self):              # committed degree bound (ZK doubles the trace domain, uni-stark prover.rs)
        return 2 ** (self.log_n + (1 if self.zk else 0))

    @property
    def N(self):
        return self.k * 2 ** self.log_blowup

    @property
    def chunks(self):         # p3-security deep.rs: c = 2^z * next_pow2(max(d + z, 2) - 1)
        z = 1 if self.zk else 0
        return (2 ** z) * (1 << (max(self.max_deg + z, 2) - 1 - 1).bit_length())

    @property
    def t(self):              # uni-stark security.rs num_batched_openings
        r = self.rand_cols if self.zk else 0
        main = 2 * (self.width + r)
        quot = self.chunks * (self.e + r)
        rnd = (self.e + r) if self.zk else 0
        return main + self.pre_width + quot + rnd

    def arities(self):
        total = self.log_n + (1 if self.zk else 0) - self.log_final_poly_len   # log2 reduction of the degree
        out = []
        while total > 0:
            a = min(self.max_log_arity, total)
            out.append(2 ** a)
            total -= a
        return out


def rounds_p3(c: P3):
    N, k = c.N, c.k
    rho = k / N
    lq = log_q(c.e)
    num = deep_numerator(c.max_deg, k, c.chunks, k, c.max_combo, c.chunks)
    ar = c.arities()
    sizes = [N]
    for a in ar:
        sizes.append(sizes[-1] // a)
    r = {}
    if c.regime == 'JB':
        L = list_size_adk(c.m, rho, N)
        r['ali'] = lq - lg(L) - lg(c.num_constraints)                 # powers of alpha
        r['deep'] = lq - 2 * lg(L) - lg(num) + c.ood_pow
        a0, b1 = A0(c.m, rho, N, lq), B1(c.m, rho, N, lq)
        r['batch'] = -(lg(c.t - 1) + ladd(a0, b1)) + c.batch_pow     # [BCIKS] Thm 7.2, curve of degree t-1
        for i, a in enumerate(ar):
            r[f'fold{i + 1}'] = -ladd(lg(a - 1) + a0 + 2 * lg(sizes[i + 1] / N), lg(a) + b1) + c.commit_pow
        r['query'] = -c.num_queries * lg(math.sqrt(rho) * (1 + 1 / (2 * c.m))) + c.query_pow
    elif c.regime == 'UD':
        r['ali'] = lq - lg(c.num_constraints)
        r['deep'] = lq - lg(num) + c.ood_pow
        r['batch'] = lq - lg(c.t - 1) - lg(N) + c.batch_pow          # [BCIKS] Thm 1.5 UD: (t-1) n / q
        for i, a in enumerate(ar):
            r[f'fold{i + 1}'] = lq - lg(a - 1) - lg(N + 1) + c.commit_pow
        rho_p = (k + max(2, c.max_combo)) / N
        r['query'] = -c.num_queries * lg((1 + rho_p) / 2) + c.query_pow
    elif c.regime == 'DKT':
        L = (c.m + 0.5) / math.sqrt(rho)
        C = dkt_line_log2(c.m, rho, N)
        r['ali'] = lq - lg(L) - lg(c.num_constraints)
        r['deep'] = lq - lg(L) - lg(num) + c.ood_pow
        r['batch'] = lq - lg(c.t - 1) - C + c.batch_pow
        for i, a in enumerate(ar):
            r[f'fold{i + 1}'] = lq - lg(a - 1) - C + c.commit_pow
        r['query'] = -c.num_queries * lg(math.sqrt(rho) * (1 + 1 / (2 * c.m))) + c.query_pow
    else:
        raise ValueError(c.regime)
    return r


def p3_soundness(c):
    return summarize(rounds_p3(c), c.h)


def p3_bytes(c: P3):
    """Plonky3-native proof bytes (bincode-ish, no compression): full Merkle paths per query per tree (no dedup), plus
    the deduplicated-multiproof figure a CashVM verifier would use (Track 4 format choice)."""
    N, ar = c.N, c.arities()
    E = 8 * c.e
    r = c.rand_cols if c.zk else 0
    trees = [('trace', (c.width + r) * 8)]
    if c.pre_width:
        trees.append(('pre', c.pre_width * 8))
    trees.append(('quotient', c.chunks * (c.e + r) * 8))
    if c.zk:
        trees.append(('random', (c.e + r) * 8))
    ld = int(lg(N))
    in_trees = [(nm, ld, leaf) for nm, leaf in trees]
    fri_trees, size = [], N
    for a in ar:
        fri_trees.append((f'fri{len(fri_trees)}', int(lg(size // a)), (a - 1) * E))   # sibling values only
        size //= a
    commits = (len(in_trees) - (1 if c.pre_width else 0) + len(fri_trees)) * c.h
    ood = c.t * E
    final = (2 ** c.log_final_poly_len) * E
    pow_w = 8 * (len(ar) + 3)
    pt = commits + ood + final + pow_w
    leaves = sum(t[2] for t in in_trees + fri_trees) * c.num_queries
    paths = sum(t[1] for t in in_trees + fri_trees) * c.h * c.num_queries
    dedup = sum(t4.exp_siblings(t[1], c.num_queries) for t in in_trees + fri_trees) * c.h
    return dict(native=round(pt + leaves + paths), dedup=round(pt + leaves + dedup), pt=pt, leaves=leaves,
                trees=[(t[0], t[1], t[2]) for t in in_trees + fri_trees], arities=ar)


def p3_fill(c: P3, target, cap=28, qcap=28):
    """Smallest grinding per site that brings each commit round to `target`, then the fewest queries at query_pow
    = min(qcap, ...). Returns None if a round would need more than `cap` bits (ALI has no PoW site at all)."""
    base = rounds_p3(replace(c, query_pow=0, commit_pow=0, batch_pow=0, ood_pow=0, num_queries=1))
    if base['ali'] < target:
        return None
    need = lambda key: max(0, math.ceil(target - base[key] - 1e-9))
    ood, bat = need('deep'), need('batch')
    com = max(need(k_) for k_ in base if k_.startswith('fold')) if any(k_.startswith('fold') for k_ in base) else 0
    if max(ood, bat, com) > cap:
        return None
    c = replace(c, ood_pow=ood, batch_pow=bat, commit_pow=com, query_pow=qcap)
    per_q = rounds_p3(replace(c, num_queries=1, query_pow=0))['query']
    s = max(1, math.ceil((target - qcap) / per_q - 1e-12))
    c = replace(c, num_queries=s)
    # drop query grinding to the smallest value that keeps the target with this s
    while c.query_pow > 0 and p3_soundness(replace(c, query_pow=c.query_pow - 1))['lam_iop'] >= target:
        c = replace(c, query_pow=c.query_pow - 1)
    return c


def p3_search(regime, e, target, log_n=16, zk=False, rand_cols=0, cap=28, qcap=28, score='dedup', max_lb=8, **air):
    best = None
    for lb in range(1, max_lb + 1):
        for la in range(1, 5):
            for lf in range(0, 9):
                if lf >= log_n:
                    continue
                for m in ((3, 4, 5, 6, 8, 10, 12, 16) if regime != 'UD' else (3,)):
                    c = P3('x', regime, e, log_n, lb, la, lf, 1, m=m, zk=zk, rand_cols=(rand_cols or e) if zk else 0, **air)
                    c = p3_fill(c, target, cap, qcap)
                    if c is None or p3_soundness(c)['lam'] < min(target, 4 * c.h):
                        continue
                    b = p3_bytes(c)[score]
                    work = 2 ** c.query_pow + 2 ** c.batch_pow + 2 ** c.ood_pow + len(c.arities()) * 2 ** c.commit_pow
                    key = (b, work)
                    if best is None or key < best[0]:
                        best = (key, c)
    return best[1] if best else None


def p3_best_lambda(regime, e, log_n=16, cap=28, **kw):
    """Highest integer target reachable (by p3_search) with every PoW site <= cap."""
    lo, hi = 60, 200
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        c = p3_search(regime, e, mid, log_n=log_n, cap=cap, **kw)
        if c:
            best, lo = (mid, c), mid + 1
        else:
            hi = mid - 1
    return best


# ============================================================== report
def t4_row(name, p, regime, target=None):
    s = t4_soundness(p, regime)
    b = t4.proof_bytes(p)['total']
    return dict(name=name, regime=regime, params=asdict(p), soundness=s, proof_bytes=b)


def fmt_rounds(s):
    return ', '.join(f'{k} {v:.2f}' for k, v in s['rounds'].items())


def fixes_for(p, target, regime):
    """Cheapest single-knob fixes that bring a Track 4 set to `target` (IOP part), with proof-byte effect."""
    out = []
    base = t4.proof_bytes(p)['total']
    q = t4_min_queries(p, target, regime)
    if q:
        out.append(('queries', f's {p.s} -> {q.s}', t4.proof_bytes(q)['total'] - base))
    for g in range(p.g, p.g + 9):
        pg = replace(p, g=g)
        if t4_soundness(pg, regime)['lam_iop'] >= target:
            out.append(('query grinding', f'g {p.g} -> {g}', 0))
            break
    return out


def main():
    rows = []
    P100 = replace(t4.Params('P100', 'JB', 3, 16, 7, 4, 8, 8, 22, 28, 0, 3, 25))
    P128 = replace(t4.Params('P128', 'JB', 3, 16, 5, 4, 8, 8, 43, 28, 0, 4, 32))
    U100 = t4.Params('U100', 'UDR', 2, 16, 4, 4, 8, 8, 79, 28, 0, 3, 25)
    U128g = t4.Params('U128g', 'UDR', 2, 16, 3, 4, 8, 8, 121, 28, 24, 3, 32)
    js = {}
    print('=' * 100)
    print('A. Track 4 sets under the per-round (RBR) bounds  [ADK Thm 2 (JB) / Thm 3 (UD); BCIKS Lemma 8.2 per-event split]')
    print('=' * 100)
    for nm, p, reg, tgt in (('P100', P100, 'JB', 100), ('P128', P128, 'JB', 128), ('U100', U100, 'UD', 100),
                            ('U128g', U128g, 'UD', 128)):
        s = t4_soundness(p, reg)
        old = t4.soundness(p)
        print(f'{nm} [{reg}] e={p.e} rho=2^-{p.log_blowup} m={p.m} s={p.s} g={p.g} g_c={p.g_c} h={p.h}: '
              f'lam_IOP {s["lam_iop"]} (binding: {s["binding"]}), lam {s["lam"]} (strict-digest {s["lam_strict"]}); '
              f'Track 4 model lam_IOP {old["lam_iop"]}')
        print('    ', fmt_rounds(s))
        print(f'     target {tgt}: {"MET" if s["lam_iop"] >= tgt else "SHORT by %.2f" % (tgt - s["lam_iop"])}; '
              f'proof {t4.proof_bytes(p)["total"]} B')
        if s['lam_iop'] < tgt:
            for f in fixes_for(p, tgt, reg):
                print('       fix:', f)
        js[nm] = dict(rbr=s, track4_model=old, bytes=t4.proof_bytes(p)['total'], params=asdict(p))
        dk = t4_soundness(p, 'DKT') if reg == 'JB' else None
        if dk:
            print(f'     sensitivity DKT26 (unreviewed): lam_IOP {dk["lam_iop"]} ({fmt_rounds(dk)})')
    # margins and the cost of a safety margin
    print('\n-- P128 safety margins: cheapest Track 4-format change for lam_IOP >= 128 + x (rho 2^-4..2^-6, m 3..8, g_c 0/4/8, g = 28)')
    for x in (0, 0.5, 1, 2, 4):
        best = None
        for m in range(3, 9):
            for lb in (4, 5, 6):
                for gc in (0, 4, 8):
                    q = t4_min_queries(replace(P128, m=m, log_blowup=lb, g_c=gc), 128 + x, 'JB')
                    if q:
                        b = t4.proof_bytes(q)['total']
                        if best is None or b < best[0]:
                            best = (b, q)
        q = best[1]
        print(f'   +{x} bits: rho=2^-{q.log_blowup} m={q.m} s={q.s} g_c={q.g_c}: {best[0]} B '
              f'({best[0] - t4.proof_bytes(P128)["total"]:+d} B vs P128); {fmt_rounds(t4_soundness(q, "JB"))}')
    print('\n-- strict digest reading (BGKTTZ Cor. 5 constant): h needed for 4h - 0.79 >= target')
    for tgt in (100, 128):
        h = math.ceil((tgt + 0.5 * lg(3)) / 4)
        print(f'   {tgt}: h >= {h} bytes ({"impossible with SHA-256 (32 B)" if h > 32 else "ok"})')

    print('\n' + '=' * 100)
    print('B. Track 4 format: cheapest provable sets under RBR bounds (search, n = 2^16, g = 28)')
    print('=' * 100)
    for reg, e, tgt, gc in (('JB', 3, 100, 0), ('JB', 3, 128, 0), ('UD', 2, 100, 0), ('UD', 3, 100, 0),
                            ('UD', 3, 128, 0), ('UD', 2, 128, 24), ('JB', 2, 100, 0)):
        best = None
        h = 32 if tgt > 112 else math.ceil(tgt / 4)
        for lb in range(2, 8):
            for k0 in (2, 4, 8):
                for k in (4, 8, 16):
                    for ldf in range(2, 9):
                        for m in ((3, 4, 5, 6) if reg == 'JB' else (3,)):
                            p = t4.Params('x', reg, e, 16, lb, k0, k, ldf, 1, 28, gc, m, h)
                            q = t4_min_queries(p, tgt, reg)
                            if q is None:
                                continue
                            b = t4.proof_bytes(q)['total']
                            if best is None or b < best[0]:
                                best = (b, q)
        if best:
            q = best[1]
            s = t4_soundness(q, reg)
            print(f'  {reg} e={e} {tgt}-bit g_c={gc}: {best[0]:>7} B  rho=2^-{q.log_blowup} k0={q.k0} k={q.k} df=2^{q.log_df} '
                  f'm={q.m} s={q.s} h={q.h}  lam_IOP={s["lam_iop"]} ({s["binding"]})')
            js[f'search_{reg}_e{e}_{tgt}_gc{gc}'] = dict(params=asdict(q), bytes=best[0], rbr=s)
        else:
            print(f'  {reg} e={e} {tgt}-bit g_c={gc}: infeasible')

    print('\n-- Track 4 format with commit-phase grinding g_c (one 8-byte nonce per commit challenge, as U128g) and m <= 16')
    for reg, e, tgt in (('JB', 3, 100), ('JB', 3, 128), ('JB', 2, 100), ('UD', 2, 100), ('UD', 3, 128)):
        best = None
        h = 32 if tgt > 112 else math.ceil(tgt / 4)
        for lb in range(2, 9):
            for k0 in (4, 8):
                for k in (8, 16):
                    for ldf in (5, 6, 7, 8):
                        for m in ((3, 4, 5, 6, 8, 10, 12, 16) if reg == 'JB' else (3,)):
                            for gc in (0, 4, 8, 12, 16, 20, 24, 28):
                                p = t4.Params('x', reg, e, 16, lb, k0, k, ldf, 1, 28, gc, m, h)
                                q = t4_min_queries(p, tgt, reg)
                                if q is None:
                                    continue
                                b = t4.proof_bytes(q)['total']
                                if best is None or (b, gc) < (best[0], best[1].g_c):
                                    best = (b, q)
        if best:
            q = best[1]
            s_ = t4_soundness(q, reg)
            print(f'  {reg} e={e} {tgt}-bit: {best[0]:>7} B  rho=2^-{q.log_blowup} k0={q.k0} k={q.k} df=2^{q.log_df} m={q.m} '
                  f's={q.s} g={q.g} g_c={q.g_c} h={q.h}  lam_IOP={s_["lam_iop"]} ({s_["binding"]}); {fmt_rounds(s_)}')
            js[f'search_gc_{reg}_e{e}_{tgt}'] = dict(params=asdict(q), bytes=best[0], rbr=s_)
        else:
            print(f'  {reg} e={e} {tgt}-bit: infeasible')

    print('\n' + '=' * 100)
    print('C. Plonky3-style FRI (Goldilocks, SHA-256 MMCS h=32), reference MiMC AIR (w=2, deg 4 with selectors, 4 constraints)')
    print('   per-site PoW cap 28 bits; score = dedup bytes (CashVM format), native = Plonky3 proof as serialized')
    print('=' * 100)
    p3rows = {}
    for label, reg, e, tgt, zk, h in (('P3-100', 'JB', 2, 100, False, 32), ('P3-100u', 'UD', 2, 100, False, 32),
                                      ('P3-100-zk', 'JB', 2, 100, True, 32), ('P3-100 e=3*', 'JB', 3, 100, False, 32),
                                      ('P3-100 e=3* h=25', 'JB', 3, 100, False, 25), ('P3-100 e=3* zk', 'JB', 3, 100, True, 32),
                                      ('P3-100 e=5', 'JB', 5, 100, False, 32), ('P3-100u e=3*', 'UD', 3, 100, False, 32),
                                      ('P3-128 (e=2)', 'JB', 2, 128, False, 32),
                                      ('P3-128u (e=2)', 'UD', 2, 128, False, 32), ('P3-128 e=5', 'JB', 5, 128, False, 32),
                                      ('P3-128 e=3*', 'JB', 3, 128, False, 32), ('P3-128u e=3*', 'UD', 3, 128, False, 32),
                                      ('P3-128u e=5', 'UD', 5, 128, False, 32),
                                      ('P3-128 e=5 zk', 'JB', 5, 128, True, 32), ('P3-128 e=3* zk', 'JB', 3, 128, True, 32),
                                      ('P3-100 DKT (sens.)', 'DKT', 2, 100, False, 32), ('P3-128 DKT e=2 (sens.)', 'DKT', 2, 128, False, 32)):
        c = p3_search(reg, e, tgt, zk=zk, h=h)
        if c is None:
            bl = p3_best_lambda(reg, e, zk=zk, h=h)
            print(f'  {label:22} [{reg}] e={e} target {tgt}: INFEASIBLE with <= 28-bit PoW per site; '
                  f'best reachable {bl[0] if bl else "-"} bits')
            if bl:
                cc = bl[1]
                print(f'      best: log_blowup={cc.log_blowup} max_log_arity={cc.max_log_arity} log_final_poly_len={cc.log_final_poly_len} '
                      f'num_queries={cc.num_queries} pow q/c/b/ood={cc.query_pow}/{cc.commit_pow}/{cc.batch_pow}/{cc.ood_pow} m={cc.m} '
                      f'bytes native {p3_bytes(cc)["native"]} dedup {p3_bytes(cc)["dedup"]}; {fmt_rounds(p3_soundness(cc))}')
                p3rows[label] = dict(feasible=False, best_lambda=bl[0], params=asdict(cc), bytes=p3_bytes(cc), rbr=p3_soundness(cc))
            continue
        s, b = p3_soundness(c), p3_bytes(c)
        print(f'  {label:22} [{reg}] e={e} zk={zk}: log_blowup={c.log_blowup} max_log_arity={c.max_log_arity} '
              f'log_final_poly_len={c.log_final_poly_len} num_queries={c.num_queries} query_pow={c.query_pow} '
              f'commit_pow={c.commit_pow} batch_pow={c.batch_pow} ood_pow={c.ood_pow} m={c.m} t={c.t}')
        print(f'      lam_IOP {s["lam_iop"]} ({s["binding"]}); bytes native {b["native"]}, dedup {b["dedup"]}; arities {b["arities"]}')
        print('      ', fmt_rounds(s))
        p3rows[label] = dict(feasible=True, params=asdict(c), bytes=b, rbr=s)
    js['plonky3'] = p3rows

    print('\n-- P3 e=2 best reachable lambda (cap 28 per site), JB and UD:')
    for reg in ('JB', 'UD'):
        bl = p3_best_lambda(reg, 2)
        print(f'   {reg}: {bl[0]} bits' if bl else f'   {reg}: none')
    print('\n-- P3 trace-length sensitivity (dedup bytes / native bytes), non-ZK')
    for tgt, reg, e in ((100, 'JB', 2), (100, 'UD', 2), (128, 'JB', 3), (128, 'JB', 5)):
        line = []
        for ln in (12, 14, 16, 18, 20):
            c = p3_search(reg, e, tgt, log_n=ln)
            line.append(f'2^{ln}: ' + (f'{p3_bytes(c)["dedup"]}/{p3_bytes(c)["native"]} (lb={c.log_blowup},a=2^{c.max_log_arity},s={c.num_queries})' if c else 'infeasible'))
        print(f'   {tgt} {reg} e={e}: ' + '; '.join(line))
    print('\n-- P3 with log_blowup <= 5 (prover memory: LDE 2^21 rows at n = 2^16), non-ZK')
    for label, reg, e, tgt in (('P3-100 e=2', 'UD', 2, 100), ('P3-100 e=2', 'JB', 2, 100), ('P3-100 e=3*', 'JB', 3, 100),
                               ('P3-128 e=3*', 'JB', 3, 128), ('P3-128 e=5', 'JB', 5, 128)):
        c = p3_search(reg, e, tgt, max_lb=5)
        s_, b = p3_soundness(c), p3_bytes(c)
        print(f'  {label:12} [{reg}] log_blowup={c.log_blowup} max_log_arity={c.max_log_arity} log_final_poly_len={c.log_final_poly_len} '
              f'num_queries={c.num_queries} query_pow={c.query_pow} commit_pow={c.commit_pow} batch_pow={c.batch_pow} ood_pow={c.ood_pow} m={c.m}: '
              f'lam_IOP {s_["lam_iop"]} ({s_["binding"]}); native {b["native"]} dedup {b["dedup"]}')
        js['plonky3'][f'{label} {reg} lb<=5'] = dict(params=asdict(c), bytes=b, rbr=s_)

    print('\n-- Track 4 format, recommended Track 5 sets: per-round requirement (bits before grinding) and grinding to add')
    for nm, p, tgt in (('T5-100', t4.Params('T5-100', 'JB', 3, 16, 8, 4, 16, 7, 19, 28, 0, 4, 25), 100),
                       ('T5-128', t4.Params('T5-128', 'JB', 3, 16, 8, 4, 8, 8, 26, 28, 0, 5, 32), 128),
                       ('P100', P100, 100), ('P128', P128, 128)):
        raw = rounds_t4(replace(p, g=0, g_c=0), 'JB')
        need = {k_: max(0, math.ceil(tgt - v - 1e-9)) for k_, v in raw.items()}
        print(f'  {nm}: raw ' + ', '.join(f'{k_} {v:.2f}' for k_, v in raw.items()) + f'; grinding needed {need}; '
              f'proof {t4.proof_bytes(p)["total"]} B (+{8 * sum(1 for k_ in need if k_ != "query" and need[k_])} B nonces if g_c per site)')
        js[f'rec_{nm}'] = dict(params=asdict(p), raw_rounds=raw, grinding_needed=need, bytes=t4.proof_bytes(p)['total'])
    print('\n-- P100 with h = 26 (strict digest reading): proof', t4.proof_bytes(replace(P100, h=26))['total'], 'B vs',
          t4.proof_bytes(P100)['total'])
    if '--json' in sys.argv:
        with open(os.path.join(HERE, 'params5-output.json'), 'w') as fh:
            json.dump(js, fh, indent=1, default=str)


if __name__ == '__main__':
    main()
