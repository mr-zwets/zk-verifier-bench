#!/usr/bin/env python3
"""Track 8 soundness calculator: round-by-round Fiat-Shamir soundness of p3-batch-stark (N tables, mixed heights,
preprocessed columns, LogUp) with the hiding two-adic FRI PCS, Goldilocks, cubic trinomial extension (D = 3).

Base (unchanged from Track 5, ../soundness/params5.py and SOUNDNESS.md, imported, not copied):
  ADK Thm 2 per round (list decoding, Johnson regime 'JB'), built on BCIKS Lemma 8.2 + Thm 7.2/7.4;
  Block et al. Cor. 5 for Fiat-Shamir (digest term 4h, strict reading 4h - log2(3)/2);
  the powers-batching adaptation (BCIKS Thm 7.2 with a curve of degree t-1 in the batching round) -- UNPUBLISHED,
  every figure below carries that label.

New charges (DESIGN-T8 sec. 6), one function each, every one a separate round term:
  1. multi-table ALI       sum_i L_i * |C_i| / |F|           (one alpha for all tables; |C_i| counts AIR + LogUp
                                                              constraints; design writes |C_i| - 1, we keep |C_i|,
                                                              which is >= and matches Track 5)
  2. DEEP                  sum_i L_i^2 * num_i / |F|          (one shared zeta; zeta^{n_max} != 1 and != -1 under ZK
                                                              covers every H_i because n_i | n_max)
  3. batching per height   sum_h (t_h - 1) * (A0(N) + B1(N))  (one alpha' ladder per LDE height, Plonky3
                                                              fri/verifier.rs open_inputs; design's conservative bound;
                                                              N = N_max for every height, conservative; N_h = sharp)
  4. roll-in rounds        fold round whose output height receives a shorter input: BCIKS Thm 7.2 charged with
                           a (curve of degree a: fold + beta^a * ro_h) instead of a - 1
  5. LogUp                 L * N * (W + 2) / |EF|, N = sum interactions x rows (Haboeck 2022/1530, p3-security
                           logup.rs), behind the lookup PoW; challenges after main + preprocessed commitments
  6. preprocessed          adds to t_h (bytes8.t_by_height), adds no round
  7. caps / injection      binding = SHA-256 collision resistance (digest term), no separate round term
L_i = ADK list size m / (rho - 2m/|D_i|) on table i's LDE domain; the query round is unchanged
(queries on shorter inputs use the reduced index idx >> (top - h), same rate).

Run:  python3 params8.py           lambda tables + size tables (writes tables8-output.txt and .json)
Standard library only. Imports ../soundness/params5.py (which imports ../../pq-hash/params.py) and ./bytes8.py.
"""
import json
import math
import os
import sys
from dataclasses import replace, asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'soundness'))
import params5 as p5  # noqa: E402
import bytes8 as b8   # noqa: E402

lg = math.log2
P_GL = b8.P_GL
M_RANGE = tuple(range(3, 25))


def log_q(D):
    return D * lg(P_GL)


# ============================================================== per-round terms (each returns -log2(eps) before PoW)
def term_logup(tables, s, m):
    lt = [t for t in tables if t.num_lookups]
    if not lt:
        return None
    rho = 2.0 ** -s.log_blowup
    Lmax = max(p5.list_size_adk(m, rho, 2 ** b8.lde_log_height(t, s)) for t in tables)
    N = sum(t.interactions_per_row * 2 ** t.log_n for t in lt)
    W = max(t.bus_width for t in lt)
    return log_q(s.D) - lg(Lmax * N * (W + 2))


def term_ali(tables, s, m):
    rho = 2.0 ** -s.log_blowup
    tot = sum(p5.list_size_adk(m, rho, 2 ** b8.lde_log_height(t, s)) * t.num_constraints for t in tables)
    return log_q(s.D) - lg(tot)


def term_deep(tables, s, m):
    rho = 2.0 ** -s.log_blowup
    tot = 0.0
    for t in tables:
        k = 2 ** (t.log_n + (1 if s.zk else 0))
        c = b8.num_chunks(t, s.zk)
        num = p5.deep_numerator(t.max_deg, k, c, k, 2, c)
        L = p5.list_size_adk(m, rho, 2 ** b8.lde_log_height(t, s))
        tot += L * L * num
    return log_q(s.D) - lg(tot)


def term_batch(tables, s, m, per_height=True, sharp=False):
    """Batching round. per_height: sum over LDE heights of (t_h - 1)(A0 + B1) (DESIGN-T8 6.3, one alpha' ladder
    per height). Conservative default: every height is charged at the TOP domain size N_max (A0 grows with |D|^2,
    so this over-charges the shorter heights); sharp=True uses each height's own N_h (reported as sensitivity).
    per_height=False: Plonky3 / Track 5 single-height formula, one ladder of length t at N_max (sensitivity)."""
    rho = 2.0 ** -s.log_blowup
    lq = log_q(s.D)
    th = b8.t_by_height(tables, s)
    top = max(th)
    if not per_height:
        th = {top: sum(th.values())}
    tot = 0.0
    for h, t in th.items():
        N = 2 ** (h if sharp else top)
        a0, b1 = p5.A0(m, rho, N, lq), p5.B1(m, rho, N, lq)
        tot += (t - 1) * (2 ** a0 + 2 ** b1)
    return -lg(tot)


def term_folds(tables, s, m, rollin_charge=True):
    rho = 2.0 ** -s.log_blowup
    lq = log_q(s.D)
    g = b8.fri_geometry(tables, s)
    N = 2 ** g['heights'][0]
    a0, b1 = p5.A0(m, rho, N, lq), p5.B1(m, rho, N, lq)
    out = []
    for r in g['rounds']:
        a = 2 ** r['log_arity']
        coef = a if (r['rollin'] and rollin_charge) else a - 1
        out.append(-p5.ladd(lg(coef) + a0 + 2 * (r['h_out'] - g['heights'][0]), lg(a) + b1))
    return out


def term_query(s, m):
    rho = 2.0 ** -s.log_blowup
    return -s.Q * lg(math.sqrt(rho) * (1 + 1 / (2 * m)))


def rounds(tables, s, m, per_height=True, rollin_charge=True, sharp=False):
    r = {}
    lu = term_logup(tables, s, m)
    if lu is not None:
        r['logup'] = lu + s.lookup_pow
    r['ali'] = term_ali(tables, s, m)                       # no PoW site before alpha in batch-stark
    r['deep'] = term_deep(tables, s, m) + s.ood_pow
    r['batch'] = term_batch(tables, s, m, per_height, sharp) + s.batch_pow
    for i, f in enumerate(term_folds(tables, s, m, rollin_charge)):
        r[f'fold{i + 1}'] = f + s.commit_pow
    r['query'] = term_query(s, m) + s.query_pow
    return r


def soundness(tables, s, per_height=True, rollin_charge=True, m=None, sharp=False):
    best = None
    for mm in ([m] if m else M_RANGE):
        r = rounds(tables, s, mm, per_height, rollin_charge, sharp)
        lam_iop = min(r.values())
        if best is None or lam_iop > best['lam_iop']:
            best = dict(m=mm, rounds={k: round(v, 2) for k, v in r.items()}, lam_iop=round(lam_iop, 2),
                        binding=min(r, key=r.get))
    h = s.digest
    best['lam'] = round(min(best['lam_iop'], p5.digest_bits(h)), 2)
    best['lam_strict'] = round(min(best['lam_iop'], p5.digest_bits(h, True)), 2)
    best['label'] = 'JB, powers-batching adaptation (unpublished)'
    return best


def min_pow(tables, s, target=128.0, m=None):
    """Smallest PoW per site (given m) that brings each round to `target`; ALI has no site."""
    sol = soundness(tables, s, m=m)
    mm = sol['m']
    raw = rounds(tables, replace(s, query_pow=0, commit_pow=0, batch_pow=0, ood_pow=0, lookup_pow=0), mm)
    need = {k: max(0, math.ceil(target - v - 1e-9)) for k, v in raw.items()}
    return dict(m=mm, raw={k: round(v, 2) for k, v in raw.items()}, need=need)


# ============================================================== consistency with Track 5 (single table == params5)
def track5_consistency():
    """M1 under Z128 with params5's single-table P3 model must give the same rounds (no mixed heights, no lookups)."""
    out = {}
    t, s = b8.M1[0], b8.Z128
    for m in (5,):
        c = p5.P3('Z128', 'JB', 3, t.log_n, s.log_blowup, s.max_log_arity, s.log_final_poly_len, s.Q,
                  query_pow=s.query_pow, commit_pow=s.commit_pow, batch_pow=s.batch_pow, m=m, zk=True,
                  rand_cols=s.rc, width=t.width, num_constraints=t.num_constraints, max_deg=t.max_deg)
        a = p5.rounds_p3(c)
        b = rounds(b8.M1, s, m)
        out[m] = dict(params5={k: round(v, 3) for k, v in a.items()}, params8={k: round(v, 3) for k, v in b.items()},
                      t5=c.t, t8=b8.proof_bytes(b8.M1, s)['t'],
                      max_abs_diff=round(max(abs(a[k] - b[k]) for k in a), 6))
    # Track 5 S128 (mimc, non-ZK) and S128z (fib, ZK) through params8's one-table path
    mimc = [b8.Table('mimc', 16, 3, num_constraints=5, max_deg=3)]
    fib = [b8.Table('fib', 16, 2, num_constraints=5, max_deg=2)]
    S128 = b8.FriSet('S128', log_blowup=8, max_log_arity=4, log_final_poly_len=8, Q=26, query_pow=26, commit_pow=15,
                     batch_pow=23, zk=False, rc=0, salt=0)
    S128z = b8.FriSet('S128z', log_blowup=8, max_log_arity=3, log_final_poly_len=8, Q=26, query_pow=27, commit_pow=13,
                      batch_pow=22, zk=True, rc=3, salt=2)
    out['S128'] = soundness(mimc, S128)
    out['S128z'] = soundness(fib, S128z)
    return out


# ============================================================== layout model (DESIGN-T8 sec. 5)
# Op-cost coefficients calibrated on Track 5 layout-b measurements (verifier/results/profile-b.json), arity-8 ZK
# vector fib-S128z-zkmin-0 and S128/P128-zkmin for the DEEP and final-polynomial slopes. MODEL, not measurement.
OPC = dict(q_x=15_200, deep_base=61_000, deep_per_t=2_320, fold_arity8=128_600, final_base=35_700,
           final_per_coef=942, merkle_per_block=None, fixed_base=3_630_000, air_m1=600_000)


def calibrate_merkle():
    """Merkle op-cost per SHA-256 block, from fib-S128z-zkmin-0 (13,227,317 op-cost) with bytes8.merkle_work."""
    fib = [b8.Table('fib', 16, 2, max_deg=2)]
    S128z = b8.FriSet('S128z', log_blowup=8, max_log_arity=3, log_final_poly_len=8, Q=26, zk=True, rc=3, salt=2)
    w = b8.merkle_work(fib, S128z)
    return 13_227_317 / w['sha_blocks'], w


def opcost_model(tables, s):
    per_block, _ = calibrate_merkle()
    b = b8.proof_bytes(tables, s)
    g = b8.fri_geometry(tables, s)
    t = b['t']
    nfold = sum((2 ** r['log_arity']) / 8 for r in g['rounds'])   # arity-8 fold units
    final = OPC['final_base'] + OPC['final_per_coef'] * 2 ** s.log_final_poly_len
    per_q = OPC['q_x'] + OPC['deep_base'] + OPC['deep_per_t'] * t + OPC['fold_arity8'] * nfold + final
    merkle = per_block * b8.merkle_work(tables, s)['sha_blocks']
    fixed = OPC['fixed_base'] + OPC['air_m1']
    return dict(per_query=round(per_q), queries=round(per_q * s.Q), merkle=round(merkle), fixed=round(fixed),
                total=round(per_q * s.Q + merkle + fixed))


def budget(unlocking, base=41):
    return (base + unlocking) * 800


IN_OVH = 43            # outpoint 36 + sequence 4 + unlocking-length compact size 3
TX_OVH = 10 + 250      # version, locktime, counts + outputs (NFT thread / payment), estimate
WIT_OVH = 1.0098       # witness push overhead measured in Track 5 (113,607 / 112,501)
LOADER = 120           # per-input loader / redeem push in multi-input layouts (Track 5 layout a: 59-236 B)


def layouts(redeem_m1=(13_000, 18_000), redeem_m2=(18_000, 24_000), code_a=(7_500, 9_000)):
    """Unlocking / transaction byte and op-cost estimates for the layouts of DESIGN-T8 sec. 5. MODEL (before
    building). Regimes are relay/standardness limits: per-input unlocking (10,000 B today) and tx size (100,000 B)."""
    out = {}
    s_b = b8.Z128
    b = b8.proof_bytes(b8.M1, s_b)
    p99 = sibling_p99_factor(b8.M1, s_b)
    oc = opcost_model(b8.M1, s_b)
    for R in redeem_m1:
        u = round(b['total'] * WIT_OVH + R + 3)
        u99 = round(u + p99 * b['total'])
        out[f'M1 b (one input), redeem {R}'] = dict(
            needs='per-input unlocking limit raised to 100,000 B; tx size limit unchanged',
            proof=b['total'], unlocking=u, unlocking_p99=u99, tx_bytes=u + IN_OVH + TX_OVH,
            op_libauth=oc['total'], op_bchn_adj=oc['total'] + 5_000, budget_base41=budget(u),
            pct_base41=round(100 * oc['total'] / budget(u), 1), pct_bchspec=round(100 * oc['total'] / budget(u, 10_000), 1),
            fits=u99 <= 100_000)
    for R in redeem_m1:
        tot = round(b['total'] * WIT_OVH + 3_200 + R + 3 + LOADER + 300)
        tx = tot + 2 * IN_OVH + TX_OVH
        out[f'M1 b2 (two inputs), redeem {R}'] = dict(
            needs='per-input unlocking limit raised to 100,000 B' + ('' if tx <= 100_000 else ' AND tx size limit raised'),
            proof=b['total'], unlocking_total=tot, tx_bytes=tx, fits_tx_100k=tx <= 100_000,
            split='input 0: redeem + PT + queries [0,Q_A); input 1: P2SH32 loader + queries [Q_A,Q) (+3.2 KB split)')
    s_g = replace(b8.Z128g, commit_pow=3)
    b2 = b8.proof_bytes(b8.M2, s_g)
    for R in redeem_m2:
        tot = round(b2['total'] * WIT_OVH + 3_200 + R + 3 + LOADER + 300)
        tx = tot + 2 * IN_OVH + TX_OVH
        out[f'M2 b2 (two inputs), redeem {R}'] = dict(
            needs='per-input unlocking limit raised to 100,000 B AND tx size limit raised' if tx > 100_000 else
                  'per-input unlocking limit raised to 100,000 B',
            proof=b2['total'], unlocking_total=tot, tx_bytes=tx, fits_two_inputs=tot <= 2 * 100_000 - 2_000,
            op_model=opcost_model(b8.M2, s_g)['total'])
    # a': today's standard rules, cap 5 (HEAD, FIN, 2 CODE, QRY inputs of 3 queries)
    for label, s_a in (('Z128 cap 5', b8.Z128c5), ('Z128-s (Q 23, qPoW 28) cap 5', b8.Z128s)):
        c5 = b8.proof_bytes(b8.M1, s_a)
        pq = b8.per_query_full_path_bytes(b8.M1, s_a)
        head = (2 ** s_a.cap) * 32 * 4 + c5['ood_values'] + c5['pow_witnesses']
        fin = c5['final_poly'] + 2_300
        per_input = 3
        nq = math.ceil(s_a.Q / per_input)
        for code in code_a:
            n_in = 1 + 1 + 2 + nq
            total = head + fin + 2 * code + s_a.Q * pq['total'] + n_in * (IN_OVH + LOADER) + TX_OVH
            out[f"M1 a' {label}, code {code}"] = dict(
                needs="today's standard rules (10,000 B unlocking, 100,000 B tx)", head=head, fin=fin,
                per_query=pq['total'], qry_input_bytes=per_input * pq['total'] + LOADER, qry_inputs=nq, inputs=n_in,
                total=total, one_tx=total <= 100_000,
                plan='1 tx' if total <= 100_000 else '2 txs (NFT thread binding H(consts))')
    return out


def sibling_p99_factor(tables, s, trials=400, seed=8):
    """Monte-Carlo spread of the multiproof sibling count: (p99 - mean) / proof size (single thread, light)."""
    import random
    rnd = random.Random(seed)
    rounds_ = b8.commitment_rounds(tables, s)
    g = b8.fri_geometry(tables, s)
    trees = [max(m.log_h for m in mats) for _, _, mats in rounds_] + [r['tree_h'] for r in g['rounds']]
    top = g['heights'][0]

    def count(idx, d):
        tot, cur = 0, set(i >> (top - d) for i in idx)
        for _ in range(d - s.cap):
            par = {}
            for i in cur:
                par.setdefault(i >> 1, set()).add(i & 1)
            tot += sum(1 for v in par.values() if len(v) == 1)
            cur = set(par)
        return tot
    xs = []
    for _ in range(trials):
        idx = [rnd.getrandbits(top) for _ in range(s.Q)]
        xs.append(sum(count(idx, d) for d in trees) * s.digest)
    xs.sort()
    mean = sum(xs) / len(xs)
    p99 = xs[int(0.99 * len(xs)) - 1]
    return (p99 - mean) / b8.proof_bytes(tables, s)['total']


# ============================================================== report
def fmt(r):
    return ', '.join(f'{k} {v:.2f}' for k, v in r.items())


def main():
    lines, js = [], {}

    def P(x=''):
        lines.append(x)
        print(x)

    P('Track 8 S0 tables (params8.py + bytes8.py). All lambda figures: JB, powers-batching adaptation (unpublished),')
    P('best m in 3..24; digest term 4h = 128 (birthday convention), strict reading 127.21. Sizes: expected values.')
    P()
    P('=' * 110)
    P('0. Consistency')
    P('=' * 110)
    st = b8.selftest(verbose=False)
    for nm in ('S128', 'S128z'):
        r = st[nm]
        P(f'  bytes8 vs Track 5 {nm:6}: measured {r["measured"]:,} B, model {r["model"]:,} B ({r["dev_pct"]:+.2f}%)  '
          f'[acceptance <= 1%: {"PASS" if abs(r["dev_pct"]) <= 1 else "FAIL"}]')
    P(f'  bytes8 over all {st["n"]} Track 5 vectors: mean {st["mean_dev_pct"]:+.3f}%, max |dev| {st["max_abs_dev_pct"]:.2f}% '
      f'(single proofs vary with the random query set; deterministic parts exact: {st["exact_parts_ok"]})')
    s1p = os.path.join(HERE, 's1-crosscheck.json')
    if os.path.exists(s1p):
        x = json.load(open(s1p))
        P(f'  bytes8 vs S1 p3b-v1 vectors ({x["n"]} real batch-stark proofs, S1 commit f1b1c3f; `bytes8.py --s1 <dir>`): '
          f'deterministic parts exact: {x["deterministic_exact"]}; fold schedules equal: {x["schedules_ok"]}; Z128 family '
          f'({x["z128_n"]}) total mean {x["z128_mean_dev_pct"]:+.2f}%, max |dev| {x["z128_max_abs_dev_pct"]:.2f}% (model >= real on average)')
        js['s1_crosscheck'] = {k: x[k] for k in x if k != 'rows'}
    cons = track5_consistency()
    P(f'  params8 one-table path vs params5 (M1, Z128, m=5): max |round diff| {cons[5]["max_abs_diff"]} bits; '
      f't params5 {cons[5]["t5"]} = bytes8 {cons[5]["t8"]}')
    P(f'  params8 on Track 5 S128 (mimc): lambda_IOP {cons["S128"]["lam_iop"]} (m={cons["S128"]["m"]}, Track 5 128.17); '
      f'S128z (fib): {cons["S128z"]["lam_iop"]} (m={cons["S128z"]["m"]}, Track 5 128.00)')
    js['consistency'] = dict(bytes8=dict((k, st[k]) for k in ('S128', 'S128z', 'n', 'mean_dev_pct', 'max_abs_dev_pct',
                                                               'exact_parts_ok', 'pass_1pct')), params=cons)

    P()
    P('=' * 110)
    P('1. Lambda tables')
    P('=' * 110)
    cases = [('M1 / Z128 (cap 0 and cap 5: identical soundness)', b8.M1, b8.Z128),
             ('M1 / Z128, batch PoW 12 (design B; shows why 20)', b8.M1, replace(b8.Z128, batch_pow=12)),
             ('M1 / Z128-s stretch (Q 23, query PoW 28, cap 5)', b8.M1, b8.Z128s),
             ('M2 / Z128-g (as designed: commit PoW 2)', b8.M2, b8.Z128g),
             ('M2 / Z128-g, commit PoW 3', b8.M2, replace(b8.Z128g, commit_pow=3))]
    js['lambda'] = {}
    for label, tables, s in cases:
        r = soundness(tables, s)
        P(f'  {label}')
        P(f'     lambda_IOP {r["lam_iop"]} (binding {r["binding"]}, m={r["m"]}); lambda {r["lam"]}, strict-digest {r["lam_strict"]}; '
          f'target 128: {"MET" if r["lam_iop"] >= 128 else "SHORT by %.2f" % (128 - r["lam_iop"])}')
        P(f'     rounds: {fmt(r["rounds"])}')
        mp = min_pow(tables, s)
        P(f'     raw (no PoW, m={mp["m"]}): {fmt(mp["raw"])}; PoW needed per site for 128: {mp["need"]}')
        js['lambda'][label] = dict(soundness=r, min_pow=mp, set=asdict(s))
    # sensitivity: what the single-height formulas would give for M2 (shows the size of new charges 3 and 4)
    s = replace(b8.Z128g, commit_pow=3)
    nv = soundness(b8.M2, s, per_height=False, rollin_charge=False)
    P(f'  M2 sensitivity (Z128-g, commit PoW 3) with Plonky3 single-height formulas (no per-height batching, roll-in as a-1): '
      f'lambda_IOP {nv["lam_iop"]} ({fmt(nv["rounds"])})')
    js['lambda']['M2 single-height sensitivity'] = nv
    sh = soundness(b8.M2, s, sharp=True)
    P(f'  M2 sensitivity (Z128-g, commit PoW 3), batching charged at each height\'s own N_h: lambda_IOP {sh["lam_iop"]} '
      f'(batch {sh["rounds"]["batch"]})')
    js['lambda']['M2 sharp-batch sensitivity'] = sh

    P()
    P('=' * 110)
    P('2. Size tables (proof bytes, expected value; p99 = expected + Monte-Carlo 99th-percentile sibling excess)')
    P('=' * 110)
    js['sizes'] = {}
    for label, tables, s in (('M1 / Z128 cap 0', b8.M1, b8.Z128), ('M1 / Z128 cap 5', b8.M1, b8.Z128c5),
                             ('M1 / Z128-s cap 5 (stretch)', b8.M1, b8.Z128s),
                             ('M2 / Z128-g cap 0', b8.M2, replace(b8.Z128g, commit_pow=3))):
        d = b8.describe(tables, s)
        b, c = d['bytes'], d['checks']
        p99 = sibling_p99_factor(tables, s)
        P(f'  {label}: proof {b["total"]:,} B (p99 ~{round(b["total"] * (1 + p99)):,} B), t={b["t"]} {b["t_by_height"]}, '
          f'heights {b["heights"]}, fold schedule {b["schedule"]}, per-query full path {d["per_query_full_path"]["total"]} B')
        P('     ' + ', '.join(f'{k} {b[k]:,}' for k in ('header', 'roots', 'ood_values', 'lookup_terminals', 'pow_witnesses',
                                                     'final_poly', 'input_leaves', 'input_salts', 'input_siblings',
                                                     'fri_leaves', 'fri_salts', 'fri_siblings', 'counts')))
        P(f'     checks: strict height {c["strict_height"]["ok"]} {c["strict_height"]["heights"]} > {d["fri"]["log_final_height"]}; '
          f'arity grid {c["arity_grid"]["ok"]}; hiding budget {c["hiding_budget"]["ok"]} '
          f'(min mask {min(x["mask"] for x in c["hiding_budget"]["rows"])} >= need {max(x["need"] for x in c["hiding_budget"]["rows"])}); '
          f'all {c["ok"]}')
        js['sizes'][label] = dict(bytes=b, checks=c, p99_factor=p99, per_query_full_path=d['per_query_full_path'],
                                  merkle=d['merkle'], tables=d['tables'])
    neg = b8.checks(b8.M2, b8.Z128)
    P(f'  negative check: M2 under plain Z128 (final 2^8): strict height {neg["strict_height"]["ok"]} '
      f'(T_ctl LDE 2^17 is not > 17) -> Z128-g is required, as the design says')
    js['sizes']['M2 / Z128 negative'] = neg['strict_height']

    P()
    P('=' * 110)
    P('3. Layout model (MODEL, before building; op-cost coefficients calibrated on Track 5 layout b)')
    P('=' * 110)
    oc = opcost_model(b8.M1, b8.Z128)
    P(f'  op-cost model M1/Z128 cap 0: per query {oc["per_query"]:,} x {b8.Z128.Q} = {oc["queries"]:,}; Merkle {oc["merkle"]:,}; '
      f'fixed {oc["fixed"]:,}; total {oc["total"]:,} (design: 0.70M/query, Merkle 7.1M, fixed 6.3M, 30-32M)')
    lay = layouts()
    for k, v in lay.items():
        P(f'  {k}: ' + ', '.join(f'{a}={b}' for a, b in v.items()))
    js['layouts'] = dict(opcost=oc, layouts=lay, opc=OPC)

    with open(os.path.join(HERE, 'tables8-output.txt'), 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    with open(os.path.join(HERE, 'tables8-output.json'), 'w') as fh:
        json.dump(js, fh, indent=1, default=str)


if __name__ == '__main__':
    main()
