#!/usr/bin/env python3
"""pq-hash design calculator: soundness, proof bytes and BCH layouts for a SHA-256 DEEP-FRI STARK.

Design-phase estimator behind SPEC.md (work/pq-hash/design, branch wip/pq-hash-design). It is a MODEL:
- soundness: closed-form per-round bounds (SPEC.md section 4):
    UDR  = unique decoding, BCIKS20 Thm 1.2/1.5/1.6 (eps_U = n/q per line, l*n/q per degree-l curve);
    JB   = Johnson regime, BCIKS20 Thm 8.3 (batched FRI, independent batching coefficients);
    JB25 = SENSITIVITY ONLY: BCHKS25 Thm 1.5 (linear-in-n Johnson gap for lines) applied per round as if it
           extended to curves/weighted agreement; that extension is NOT established here, so no set uses it;
    CONJ = ethSTARK-style conjecture, labelled, for comparison only.
  Fiat-Shamir: round-by-round accounting, lambda = min over rounds of (-log2 eps_round + grinding_round),
  capped by the Merkle digest's collision level 4*h bits.
- bytes: exact for the proof format of SPEC.md section 3 given the Merkle opening scheme; expectations for
  deduplicated multiproofs and pruned caps (uniform query indices).
- op-cost: a rough per-kernel model (OPC) for feasibility only. The Kernels phase replaces it.

Run:  python3 params.py           tables used in SPEC.md
      python3 params.py --json    machine-readable rows for the main sets
Standard library only.
"""
import json
import math
import sys
from dataclasses import dataclass, asdict, replace

P_GL = 2**64 - 2**32 + 1          # Goldilocks; 7 generates F_p^*, u^2-7 and u^3-7 are irreducible
LOG_P = math.log2(P_GL)

# ---------------------------------------------------------------- AIR (SPEC.md section 2)
W = 2            # trace columns X, Y
D = 3            # max constraint degree
SEG = D - 1      # composition segments H0, H1 (extension-valued)
M_C = 4          # constraints: 2 transition + 2 boundary
OOD = 5          # X(z), Y(z), X(gz), H0(z), H1(z)
M_D = 5          # DEEP quotients batched into f0


@dataclass
class Params:
    name: str
    regime: str          # 'UDR' | 'JB' | 'JB25' | 'CONJ'
    e: int               # extension degree over Goldilocks (2 or 3)
    log_n: int           # trace length n = 2^log_n
    log_blowup: int      # rho = 2^-log_blowup
    k0: int              # first fold arity (trace/comp leaves hold k0-cosets)
    k: int               # later fold arity
    log_df: int          # final polynomial degree < 2^log_df, sent as coefficients
    s: int               # queries
    g: int               # query-phase grinding bits
    g_c: int = 0         # grinding bits on every commit-phase challenge (variant only)
    m: int = 3           # Johnson multiplicity parameter (m >= 3)
    h: int = 32          # Merkle digest bytes (SHA-256 truncated to h bytes; need 4*h >= lambda)
    omit: bool = False   # optimisation O1: FRI leaves omit the value the verifier derives from the previous fold


def fri_shape(p: Params):
    N = 2 ** (p.log_n + p.log_blowup)
    arities, deg, a = [], 2 ** p.log_n, p.k0
    while deg > 2 ** p.log_df:
        a_eff = min(a, deg // 2 ** p.log_df)
        arities.append(a_eff)
        deg //= a_eff
        a = p.k
    sizes = [N]
    for a in arities:
        sizes.append(sizes[-1] // a)
    trees = [dict(name='trace', depth=int(math.log2(N // arities[0])), leaf=arities[0] * W * 8),
             dict(name='comp', depth=int(math.log2(N // arities[0])), leaf=arities[0] * SEG * p.e * 8)]
    for i in range(1, len(arities)):
        vals = arities[i] - (1 if p.omit else 0)
        trees.append(dict(name=f'fri{i}', depth=int(math.log2(sizes[i] // arities[i])), leaf=vals * p.e * 8))
    return N, arities, sizes, trees


def soundness(p: Params):
    N, arities, sizes, _ = fri_shape(p)
    n = 2 ** p.log_n
    rho = 2.0 ** -p.log_blowup
    log_q = p.e * LOG_P
    lg = math.log2
    r = {}
    if p.regime == 'UDR':
        r['ali'] = log_q - lg(M_C - 1)                      # powers of alpha
        r['deep'] = log_q - lg(D * n + 2 * N)               # identity at z; z or gz in L0
        r['batch'] = log_q - lg(N)                          # Thm 1.6 (affine space), independent gammas
        for i, a in enumerate(arities):                     # Thm 1.5, curve of degree a-1, folded blocklength
            r[f'fold{i+1}'] = log_q - lg((a - 1) * sizes[i + 1])
        delta = (1 - rho) / 2 - 1.0 / N
        r['query'] = -p.s * lg(1 - delta)
    elif p.regime in ('JB', 'JB25'):
        m = p.m
        L = (m + 0.5) / math.sqrt(rho)                      # GS list size, BCIKS20 (5.6): D_Y < (m+1/2)/sqrt(rho)
        r['ali'] = log_q - lg(L * M_C)
        r['deep'] = log_q - lg(L * L * (D * n + 2 * N))
        if p.regime == 'JB':
            eps_c = ((m + 0.5) ** 7 * N ** 2) / (2 * rho ** 1.5) + (2 * m + 1) * (N + 1) / math.sqrt(rho) * sum(arities)
            r['batch+folds'] = log_q - lg(eps_c)
        else:
            def a_line(nn):  # BCHKS25 Thm 1.5 with gamma <= 1 (upper bound)
                return (2 * (m + 0.5) ** 5 + 3 * (m + 0.5) * rho) / (3 * rho ** 1.5) * nn + (m + 0.5) / math.sqrt(rho)
            r['batch'] = log_q - lg((M_D - 1) * a_line(N))
            for i, a in enumerate(arities):
                r[f'fold{i+1}'] = log_q - lg((a - 1) * a_line(sizes[i]))
        r['query'] = -p.s * lg(math.sqrt(rho) * (1 + 1 / (2 * m)))
    elif p.regime == 'CONJ':
        r['ali'] = log_q - lg(M_C)
        r['deep'] = log_q - lg(D * n + 2 * N)
        r['batch+folds'] = log_q - lg(N * sum(arities))
        r['query'] = p.s * p.log_blowup
    else:
        raise ValueError(p.regime)
    out = {k_: v + (p.g if k_ == 'query' else p.g_c) for k_, v in r.items()}
    lam_iop = min(out.values())
    lam_hash = 4 * p.h                                       # Q^2 / 2^(8h)
    return dict(rounds={k_: round(v, 2) for k_, v in out.items()}, lam_iop=round(lam_iop, 2),
                lam=round(min(lam_iop, lam_hash), 2),
                limited_by=(min(out, key=out.get) if lam_iop <= lam_hash else 'digest'))


# ---------------------------------------------------------------- Merkle opening schemes
def exp_siblings(depth, s):
    """E[#siblings] of a deduplicated multiproof for s uniform leaves (with replacement), levels 1..depth."""
    return sum(2 ** l * ((1 - 2.0 ** -l) ** s - (1 - 2.0 ** (1 - l)) ** s) for l in range(1, depth + 1))


def exp_distinct(nodes, s):
    return nodes * (1 - (1 - 1.0 / nodes) ** s)


def pruned(depth, s, h, c):
    """Pruned cap at level c: touched level-c nodes + multiproof above c (TOP blob), paths below c (per query)."""
    top = (exp_distinct(2 ** c, s) + exp_siblings(c, s)) * h
    return top, (depth - c) * h


def best_pruned(depth, s, h, cmax=None):
    best = None
    for c in range(0, (depth if cmax is None else min(depth, cmax)) + 1):
        top, per_q = pruned(depth, s, h, c)
        tot = top + s * per_q
        if best is None or tot < best[0]:
            best = (tot, c, top, per_q)
    return best


def pt_bytes(p: Params):
    N, arities, sizes, trees = fri_shape(p)
    e8 = p.e * 8
    return dict(statement=16, roots=len(trees) * p.h, ood=OOD * e8, final=(2 ** p.log_df) * e8,
                nonces=8 * (1 + ((len(arities) + 3) if p.g_c else 0)))


def proof_bytes(p: Params, scheme='dedup'):
    N, arities, sizes, trees = fri_shape(p)
    pt = sum(pt_bytes(p).values())
    leaves = sum(t['leaf'] for t in trees) * p.s
    if scheme == 'path':
        sib = sum(t['depth'] for t in trees) * p.s * p.h
    elif scheme == 'dedup':
        sib = sum(exp_siblings(t['depth'], p.s) for t in trees) * p.h
    else:
        raise ValueError
    return dict(total=round(pt + leaves + sib), pt=pt, leaves=leaves, siblings=round(sib), arities=arities,
                trees=[(t['name'], t['depth'], t['leaf']) for t in trees], N=N)


# ---------------------------------------------------------------- op-cost model (ESTIMATES, replaced by Kernels)
OPC = dict(base_mulmod=600, base_mul_lazy=300, ext_mul={2: 2700, 3: 5400}, ext_add_coeff=250,
           merkle_level=1300, hash_iter=192, parse_elem=350, exp_base=20000, inv={2: 70000, 3: 110000})


def op_query(p: Params, levels):
    """Per-query op-cost (standard mode): index, x0/x0^-1, Merkle levels, leaf hash+parse, DEEP, folds, final."""
    N, arities, sizes, trees = fri_shape(p)
    e, em = p.e, OPC['ext_mul'][p.e]
    c = 1500 + 2 * OPC['exp_base'] + levels * OPC['merkle_level']
    for t in trees:
        c += 300 + (1 + (t['leaf'] + 8) // 64) * OPC['hash_iter'] + t['leaf'] + (t['leaf'] // 8) * OPC['parse_elem']
    per_pt = (W * e + SEG * e * e) * OPC['base_mul_lazy'] + 2 * em + 2 * 3 * em + 4 * e * OPC['ext_add_coeff']
    c += arities[0] * per_pt
    for a in arities:
        bf = (a // 2) * int(math.log2(a))
        c += bf * (e * OPC['base_mulmod'] + 2 * e * OPC['ext_add_coeff']) + a * em + 1500
    c += (2 ** p.log_df) * e * OPC['base_mulmod']
    return round(c)


OP_FIXED = 270000     # per input: code load + hash check, PT read, challenge re-derivation, OOD constants, one inversion
OP_HEAD = 200000      # head: transcript over PT, grinding, AIR identity at z, periodic column, final-poly bookkeeping

# ---------------------------------------------------------------- transaction model
CODE = 4000           # ESTIMATE of the verifier code blob, bytes (Build measures; +-1.5 KB moves totals by +-1.5 KB/tx)
R = 75                # shared P2SH32 redeem (cf. bn-native-sound R = 65 B), pushed last in every input
IN_OVH = 36 + 4 + 3   # outpoint, sequence, unlocking-length varint
OUT_P2SH32 = 8 + 1 + 35
OUT_TOKEN = 8 + 3 + (1 + 32 + 1 + 1 + 32) + 35
TX_OVH = 4 + 1 + 1 + 4
STD_UNLOCK, STD_TX, TXV5_UNLOCK = 10_000, 100_000, 100_000
MARGIN = 0.94         # liveness rule: op-cost <= 94% of the input's budget (as bn-native-sound)


def pack_tx(p: Params, s_t: int, multi: bool):
    """One standard transaction carrying s_t queries (SPEC.md section 6, roles HEAD/TOP/CODE/QRY).
    Every tree is opened with a pruned cap at level c_t = depth_t - b: query inputs carry leaves plus b
    siblings per tree; TOP blobs carry the touched level-c_t nodes plus the deduplicated multiproof above.
    b is chosen to minimise bytes subject to every input's op-cost fitting MARGIN of its own budget."""
    N, arities, sizes, trees = fri_shape(p)
    best = None
    for b in range(0, max(t['depth'] for t in trees) + 1):
        tops, levels = [], 0
        for t in trees:
            c = max(0, t['depth'] - b)
            top, pq = pruned(t['depth'], s_t, p.h, c)
            tops.append((t['name'], c, round(top)))
            levels += t['depth'] - c
        qb = sum(t['leaf'] for t in trees) + levels * p.h + 3
        data = sum(pt_bytes(p).values()) + 3 + sum(x[2] + 3 for x in tops) + CODE + 6
        cap = STD_UNLOCK - (R + 1) - 3
        opq = op_query(p, levels)
        top_op = sum(x[2] / p.h for x in tops) * OPC['merkle_level']     # multiproof merge in the TOP owners
        inputs, rem = [], data
        while rem > 0:
            take = min(rem, cap)
            inputs.append(dict(kind='data', bytes=take, q=0))
            rem -= take
        # spread TOP verification + HEAD work over the data inputs in proportion to their bytes
        dsum = sum(x['bytes'] for x in inputs)
        for x in inputs:
            x['op'] = OP_FIXED + (OP_HEAD + top_op) * x['bytes'] / dsum

        def room_q(x):  # how many more queries this input can take (bytes and op-cost)
            q = 0
            while True:
                L = x['bytes'] + (q + 1) * qb + R + 1
                if L - (R + 1) > cap or x['op'] + (q + 1) * opq > MARGIN * (41 + L) * 800:
                    return q
                q += 1
        qleft = s_t
        for x in inputs:
            q = min(room_q(x), qleft)
            x['q'] = q; x['bytes'] += q * qb; x['op'] += q * opq; qleft -= q
        guard = 0
        while qleft > 0 and guard < 200:
            x = dict(kind='query', bytes=0, q=0, op=OP_FIXED)
            q = min(max(room_q(x), 1), qleft)   # an op-short input takes one query and a filler
            x['q'] = q; x['bytes'] = q * qb; x['op'] += q * opq; qleft -= q
            inputs.append(x); guard += 1
        if qleft > 0:
            continue
        fill = 0
        for x in inputs:
            L = x['bytes'] + R + 1
            Lmin = math.ceil(x['op'] / (MARGIN * 800)) - 41
            x['fill'] = max(0, Lmin - L)
            x['unlocking'] = L + x['fill'] + (3 if x['fill'] else 0)
            fill += x['fill']
        if any(x['unlocking'] > STD_UNLOCK for x in inputs):
            continue
        tx = TX_OVH + sum(IN_OVH + x['unlocking'] for x in inputs) + OUT_P2SH32 + (OUT_TOKEN if multi else 0)
        cand = dict(queries=s_t, inputs=len(inputs), tx_bytes=round(tx), b=b, query_bytes=round(qb),
                    tops=tops, data_bytes=round(data), op_per_query=opq, fill=fill,
                    op_total=round(sum(x['op'] for x in inputs)),
                    budget_total=sum((41 + x['unlocking']) * 800 for x in inputs), ok=tx <= STD_TX)
        if best is None or cand['tx_bytes'] < best['tx_bytes']:
            best = cand
    return best


def layout_standard(p: Params, max_tx=6):
    for ntx in range(1, max_tx + 1):
        split = [p.s // ntx + (1 if i < p.s % ntx else 0) for i in range(ntx)]
        txs = [pack_tx(p, st, ntx > 1) for st in split]
        if all(t and t['ok'] for t in txs):
            return dict(transactions=ntx, inputs=sum(t['inputs'] for t in txs),
                        total_bytes=sum(t['tx_bytes'] for t in txs), txs=txs)
    return None


def layout_single(p: Params):
    """One input (TXv5-as-written, base 41; libauth bch-spec, base 10,000). Full multiproofs, code as redeem."""
    pb = proof_bytes(p, 'dedup')
    N, arities, sizes, trees = fri_shape(p)
    unlock = pb['total'] + 3 * (len(trees) + 4) + 3 * p.s + CODE + 3
    levels_per_q = pb['siblings'] / p.h / p.s
    op = OP_FIXED + OP_HEAD + p.s * op_query(p, round(levels_per_q * 1.5))   # +50% for multiproof merge glue
    tx = TX_OVH + IN_OVH + 2 + unlock + OUT_P2SH32
    return dict(unlocking=round(unlock), tx_bytes=round(tx), op_est=op,
                budget_txv5=(41 + unlock) * 800, budget_bchspec=(10000 + unlock) * 800,
                op_frac_txv5=round(op / ((41 + unlock) * 800), 3),
                fits=unlock <= TXV5_UNLOCK and tx <= STD_TX)


# ---------------------------------------------------------------- search
LDF_RANGE = range(2, 9)
def min_queries(p: Params, target):
    """Smallest s with lambda_IOP >= target (monotone in s), or None if the commit rounds cap it below target."""
    if soundness(replace(p, s=4000))['lam_iop'] < target:
        return None
    lo, hi = 1, 4000
    while lo < hi:
        mid = (lo + hi) // 2
        if soundness(replace(p, s=mid))['lam_iop'] >= target:
            hi = mid
        else:
            lo = mid + 1
    return replace(p, s=lo)


def search(regime, e, target, log_n=16, g=28, g_c=0, h=None, omit=False, score='single'):
    h = h or (32 if target > 112 else math.ceil(target / 4))
    best = None
    for lb in range(2, 8):
        for k0 in (2, 4, 8):
            for k in (4, 8, 16):
                for ldf in LDF_RANGE:
                    if ldf >= log_n:
                        continue
                    for m in ((3, 4, 5, 6) if regime in ('JB', 'JB25') else (3,)):
                        p = min_queries(Params('x', regime, e, log_n, lb, k0, k, ldf, 1, g, g_c, m, h, omit), target)
                        if p is None or soundness(p)['lam'] < target:
                            continue
                        b = proof_bytes(p)['total']
                        if best is None or b < best[0]:
                            best = (b, p)
    return best


# The sets of SPEC.md section 5 (s is filled by min_queries). Same arity schedule [4, 8, 8] for P100/P128.
SETS = [
    (Params('P100', 'JB', 3, 16, 7, 4, 8, 8, 0, 28, 0, 3, 25), 100),
    (Params('P128', 'JB', 3, 16, 5, 4, 8, 8, 0, 28, 0, 4, 32), 128),
    (Params('U100', 'UDR', 2, 16, 4, 4, 8, 8, 0, 28, 0, 3, 25), 100),
    (Params('U128g', 'UDR', 2, 16, 3, 4, 8, 8, 0, 28, 24, 3, 32), 128),
    (Params('B128', 'JB25', 3, 16, 7, 4, 8, 8, 0, 28, 0, 5, 32), 128),
    (Params('C100', 'CONJ', 2, 16, 7, 8, 16, 6, 0, 28, 0, 3, 25), 100),
    (Params('C128', 'CONJ', 3, 16, 7, 4, 16, 7, 0, 28, 0, 3, 32), 128),
]


def row(p, target):
    p = min_queries(p, target)
    return dict(params=asdict(p), soundness=soundness(p), bytes_path=proof_bytes(p, 'path')['total'],
                bytes=proof_bytes(p), pt=pt_bytes(p), layout_std=layout_standard(p), layout_single=layout_single(p),
                bytes_omit=proof_bytes(replace(p, omit=True))['total'])


def main():
    rows = [row(p, t) for p, t in SETS]
    if '--json' in sys.argv:
        print(json.dumps(rows, indent=1))
        return
    for r_ in rows:
        p = r_['params']
        print(f"== {p['name']}: {p['regime']} e={p['e']} n=2^{p['log_n']} rho=2^-{p['log_blowup']} k0={p['k0']} k={p['k']} "
              f"df=2^{p['log_df']} s={p['s']} g={p['g']} g_c={p['g_c']} m={p['m']} h={p['h']}")
        print('   soundness', r_['soundness'])
        b = r_['bytes']
        print(f"   proof bytes: dedup {b['total']} (PT {b['pt']} {r_['pt']}, leaves {b['leaves']}, siblings {b['siblings']}); "
              f"plain paths {r_['bytes_path']}; with O1 omit {r_['bytes_omit']}")
        print(f"   arities {b['arities']} N=2^{int(math.log2(b['N']))} trees {b['trees']}")
        ls = r_['layout_std']
        if ls:
            print(f"   (a) standard: {ls['transactions']} tx, {ls['inputs']} inputs, {ls['total_bytes']} B")
            for t in ls['txs']:
                print('       ', t)
        else:
            print('   (a) standard: no packing within 6 tx')
        print('   (b) single input:', r_['layout_single'])
    print('\n== sensitivity: optimum proof bytes (dedup) vs trace length, provable JB e=3, g=28')
    for tgt in (100, 128):
        line = []
        for ln in (10, 12, 14, 15, 16, 18, 20):
            b = search('JB', 3, tgt, log_n=ln)
            if not b:
                line.append(f"2^{ln}: infeasible"); continue
            ls, sg = layout_standard(b[1]), layout_single(b[1])
            line.append(f"2^{ln}: {b[0]} B s={b[1].s} rho=2^-{b[1].log_blowup} m={b[1].m}; (a) {(str(ls['transactions'])+' tx/'+str(ls['inputs'])+' in/'+str(ls['total_bytes'])+' B') if ls else 'no packing'}; (b) {sg['unlocking']} B {'fits' if sg['fits'] else 'over'}")
        print(f'  {tgt}-bit:'); [print('    ', x) for x in line]
    print('\n== sensitivity: grinding bits (P128 shape, n=2^16)')
    for g in (20, 24, 28, 32):
        b = search('JB', 3, 128, g=g)
        print(f'  g={g}: {b[0]} B s={b[1].s} rho=2^-{b[1].log_blowup} m={b[1].m} k0={b[1].k0} k={b[1].k} df=2^{b[1].log_df}')
    print('\n== search optimum per regime (n=2^16, g=28)')
    for reg, e, tgt, gc in (('JB', 3, 100, 0), ('JB', 3, 128, 0), ('UDR', 2, 100, 0), ('UDR', 3, 100, 0), ('UDR', 3, 128, 0),
                            ('UDR', 2, 128, 24), ('JB25', 2, 100, 0), ('JB25', 2, 128, 0), ('JB25', 3, 128, 0),
                            ('CONJ', 2, 100, 0), ('CONJ', 3, 128, 0)):
        b = search(reg, e, tgt, g_c=gc)
        if b:
            q = b[1]
            print(f'  {reg:5} e={e} {tgt}-bit g_c={gc}: {b[0]:>7} B  s={q.s} rho=2^-{q.log_blowup} k0={q.k0} k={q.k} '
                  f'df=2^{q.log_df} m={q.m} h={q.h}  lam={soundness(q)["lam"]} ({soundness(q)["limited_by"]})')
        else:
            print(f'  {reg:5} e={e} {tgt}-bit g_c={gc}: infeasible')


if __name__ == '__main__':
    main()
