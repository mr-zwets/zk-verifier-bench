#!/usr/bin/env python3
"""Track 8 byte model for p3-batch-stark proofs (SHA-256 / Goldilocks / cubic trinomial, Plonky3 0d80373).

Single source for the shapes used by params8.py (soundness) and for every proof-size figure of Track 8 S0.

What it models (each item was read from the pinned Plonky3 source, file named in the comment next to it):
  * per-matrix, per-query salts (hiding_mmcs.rs: salts[q][m]); FRI leaves are salted too (Track 5 cfg.rs);
  * quotient chunk count 2^zk * 2^ceil(log2(max(d+zk,2)-1)) (uni-stark symbolic.rs log_num_quotient_chunks);
  * commitment rounds in batch-stark order: [random], main, quotient, [preprocessed (vk)], [permutation]
    (batch-stark verifier/mod.rs commitments_with_opening_points);
  * mixed heights: FRI fold_schedule (fri config.rs), the strict input-height rule
    log_lde_height > log_final_poly_len + log_blowup (fri config.rs validate_input_height), roll-ins;
  * Merkle caps: 2^c digests per commitment, paths stop at the cap; the effective cap is lowered so that every
    injected matrix sits at or below it (merkle-tree mmcs/mod.rs: proof_levels = max(total - cap, last_injection));
  * hiding budget: mask_height = domain/2 >= 2*(D*points + Q) per matrix (fri hiding_pcs.rs hiding_budget);
  * pruned multiproofs (Plonky3 pruned.rs semantics): EXPECTED sibling count for Q uniform indices (exact
    occupancy formula), the only non-deterministic part of the size.

Wire format: p3b-v1 is defined by S1 (FORMAT.md). This model assumes the p3s-v1 conventions carried over
(FORMAT.md of Track 5): u16 sibling counts, 8-byte base elements, D*8-byte extension elements, PoW witness
present only when its bits are > 0, plus per batch proof: one extension element per lookup terminal, the
lookup / OOD PoW witnesses (if > 0 bits); degree_bits are verifying-key data (no header byte). S1's FORMAT.md
(groth16_cashscript wip/stark-usable, research/pq-stark-batch/prover/FORMAT.md) confirmed these conventions;
`python3 bytes8.py --s1 <vectors dir>` compares the model with S1's real p3b-v1 vectors (s1-crosscheck.json).

Run:  python3 bytes8.py            self-test against Track 5 (S128 78,393 B, S128z 112,501 B, all 45 vectors)
      python3 bytes8.py --shapes   print the Track 8 shapes (M1, M2) with checks
Standard library only.
"""
import json
import math
import os
import sys
from dataclasses import dataclass, field, replace, asdict

HERE = os.path.dirname(os.path.abspath(__file__))
P_GL = 2 ** 64 - 2 ** 32 + 1
lg = math.log2


# ============================================================== shapes
@dataclass
class Table:
    """One batch-stark instance (AIR). Widths in base columns, before ZK random columns."""
    name: str
    log_n: int                       # trace rows 2^log_n (before ZK doubling)
    width: int                       # main trace columns
    main_next: bool = True           # AIR reads the next row of the main trace
    pre_width: int = 0               # preprocessed columns (committed in the vk)
    pre_next: bool = False           # AIR reads the next preprocessed row
    num_constraints: int = 1         # all constraints folded by alpha, AIR + LogUp
    max_deg: int = 2                 # Plonky3 constraint degree (periodic-aware sizing, AIR-SPEC.md)
    num_lookups: int = 0             # LogUp fraction columns (permutation trace = num_lookups + 1 EF columns)
    interactions_per_row: int = 0    # LogUp denominator factors per row (sends + receives)
    bus_width: int = 0               # widest payload W
    public_values: int = 0
    periodic: int = 0                # periodic columns (no proof bytes, verifier evaluates them)


@dataclass
class FriSet:
    name: str
    D: int = 3                       # extension degree (CubicTrinomialExtensionField)
    log_blowup: int = 9
    max_log_arity: int = 3
    log_final_poly_len: int = 8
    Q: int = 24
    query_pow: int = 24
    commit_pow: int = 2
    batch_pow: int = 20
    ood_pow: int = 0
    lookup_pow: int = 0
    zk: bool = True
    rc: int = 3                      # random codewords (HidingFriPcs num_random_codewords, >= D)
    salt: int = 2                    # salt elements per matrix per row (MerkleTreeHidingMmcs SALT_ELEMS)
    cap: int = 0                     # Merkle cap height
    digest: int = 32


def num_chunks(t: Table, zk: bool) -> int:
    z = 1 if zk else 0
    return (2 ** z) * (1 << (max(t.max_deg + z, 2) - 1 - 1).bit_length())


def lde_log_height(t: Table, s: FriSet) -> int:
    return t.log_n + (1 if s.zk else 0) + s.log_blowup


@dataclass
class Matrix:
    table: str
    kind: str          # random | main | quotient | pre | perm
    log_h: int         # log2 LDE height
    width: int         # committed base columns (incl. random columns)
    salted: bool
    points: int        # opening points
    opened_per_point: int   # extension values per point (incl. random-codeword values)
    mask_log: int      # log2(domain.size()/2) for the hiding budget


def commitment_rounds(tables, s: FriSet):
    """Commitment rounds in batch-stark order. Returns [(round_name, in_proof, [Matrix])]."""
    rc = s.rc if s.zk else 0
    out = []
    if s.zk:
        out.append(('random', True, [Matrix(t.name, 'random', lde_log_height(t, s), s.D + rc, True, 1, s.D + rc,
                                            t.log_n) for t in tables]))
    out.append(('main', True, [Matrix(t.name, 'main', lde_log_height(t, s), t.width + rc, s.zk,
                                      2 if t.main_next else 1, t.width + rc, t.log_n) for t in tables]))
    q = []
    for t in tables:
        for _ in range(num_chunks(t, s.zk)):
            q.append(Matrix(t.name, 'quotient', lde_log_height(t, s), s.D + rc, s.zk, 1, s.D + rc, t.log_n))
    out.append(('quotient', True, q))
    pre = [Matrix(t.name, 'pre', lde_log_height(t, s), t.pre_width, s.zk, 2 if t.pre_next else 1, t.pre_width,
                  t.log_n) for t in tables if t.pre_width]
    if pre:
        out.append(('pre', False, pre))       # root lives in the verifying key
    perm = [Matrix(t.name, 'perm', lde_log_height(t, s), (t.num_lookups + 1) * s.D + rc, s.zk, 2,
                   (t.num_lookups + 1) * s.D + rc, t.log_n) for t in tables if t.num_lookups]
    if perm:
        out.append(('perm', True, perm))
    return out


# ============================================================== FRI geometry (ports of p3-fri config.rs)
def fold_schedule(input_log_heights, log_final_height, max_log_arity):
    hs = sorted(set(input_log_heights), reverse=True)
    if not hs or hs[0] <= log_final_height:
        return []
    h, nxt, sched = hs[0], 1, []
    while h > log_final_height:
        a = min(h - log_final_height, max_log_arity)
        if nxt < len(hs):
            a = min(a, h - hs[nxt])
        sched.append(a)
        h -= a
        if nxt < len(hs) and hs[nxt] == h:
            nxt += 1
    return sched


def fri_geometry(tables, s: FriSet):
    heights = sorted({lde_log_height(t, s) for t in tables}, reverse=True)
    lfh = s.log_blowup + s.log_final_poly_len
    sched = fold_schedule(heights, lfh, s.max_log_arity)
    rounds, h = [], heights[0]
    for a in sched:
        hn = h - a
        rounds.append(dict(h_in=h, log_arity=a, h_out=hn, tree_h=hn, rollin=(hn in heights[1:])))
        h = hn
    return dict(heights=heights, log_final_height=lfh, schedule=sched, rounds=rounds)


def checks(tables, s: FriSet):
    """Shape checks the verifying key must enforce (DESIGN-T8 sec. 2.3, 2.4, 6.4)."""
    g = fri_geometry(tables, s)
    lfh = g['log_final_height']
    out = {}
    strict = [(t.name, lde_log_height(t, s)) for t in tables]
    out['strict_height'] = dict(ok=all(h > lfh for _, h in strict) if s.log_final_poly_len > 0 else True,
                                rule=f'log_lde_height > log_final_poly_len + log_blowup = {lfh}',
                                heights={n: h for n, h in strict})
    out['arity_grid'] = dict(ok=all(a == s.max_log_arity for a in g['schedule']), schedule=g['schedule'],
                             note='every round folds by the full arity, every input height is reached exactly')
    hid = []
    if s.zk:
        for rname, _, mats in commitment_rounds(tables, s):
            for m in mats:
                need = 2 * (s.D * max(m.points, 1) + s.Q)
                hid.append(dict(round=rname, table=m.table, mask=2 ** m.mask_log, need=need, ok=2 ** m.mask_log >= need))
    out['hiding_budget'] = dict(ok=all(x['ok'] for x in hid), rows=hid,
                                rule='mask_height = domain.size()/2 >= 2*(D*points + Q)')
    out['rc_ge_D'] = dict(ok=(not s.zk) or s.rc >= s.D)
    out['ok'] = all(v['ok'] for v in out.values())
    return out


# ============================================================== Merkle multiproof expectation
def exp_siblings(Q, d, cap=0):
    """Expected number of sibling digests in a pruned multiproof for Q uniform (with replacement) leaf indices in a
    binary tree with 2^d leaves whose paths stop at cap height `cap`: sum over levels of the expected number of
    parents with exactly one occupied child (= 2*E[occupied parents] - E[occupied children])."""
    tot = 0.0
    for l in range(d - cap):
        N = 2 ** (d - l)
        P = N // 2
        occ = N * (1 - (1 - 1 / N) ** Q)
        occp = P * (1 - (1 - 1 / P) ** Q)
        tot += 2 * occp - occ
    return tot


def exp_nodes(Q, d, cap=0):
    """Expected number of 2-to-1 compressions the verifier computes (occupied parents per level, up to the cap)."""
    tot = 0.0
    for l in range(d - cap):
        P = 2 ** (d - l - 1)
        tot += P * (1 - (1 - 1 / P) ** Q)
    return tot


def exp_distinct(Q, N):
    return N * (1 - (1 - 1 / N) ** Q)


def effective_cap(cap, tree_h, min_matrix_h):
    proof_levels = max(tree_h - cap, tree_h - min_matrix_h)
    return tree_h - proof_levels


# ============================================================== proof bytes
def proof_bytes(tables, s: FriSet, header_bytes=None):
    """Byte breakdown of a batch-stark proof in the p3b-v1 model. Siblings are expected values."""
    E = 8 * s.D
    rounds = commitment_rounds(tables, s)
    g = fri_geometry(tables, s)
    R = len(g['rounds'])
    lookup_tables = [t for t in tables if t.num_lookups]
    capd = (2 ** s.cap) * s.digest
    b = {}
    b['header'] = 0 if header_bytes is None else header_bytes   # p3b-v1: degree_bits are VK data (S1 FORMAT.md)
    n_proof_commits = sum(1 for _, inp, _ in rounds if inp)
    # effective cap per input tree (mixed heights)
    tree_caps = {}
    for rname, _, mats in rounds:
        th = max(m.log_h for m in mats)
        tree_caps[rname] = effective_cap(s.cap, th, min(m.log_h for m in mats))
    b['roots'] = sum((2 ** tree_caps[r]) * s.digest for r, inp, _ in rounds if inp) + R * capd
    t_total = sum(m.points * m.opened_per_point for _, _, mats in rounds for m in mats)
    b['ood_values'] = t_total * E
    b['lookup_terminals'] = len(lookup_tables) * E
    pows = [s.batch_pow] + [s.commit_pow] * R + [s.query_pow] + [s.ood_pow] + ([s.lookup_pow] if lookup_tables else [])
    b['pow_witnesses'] = 8 * sum(1 for x in pows if x > 0)
    b['final_poly'] = (2 ** s.log_final_poly_len) * E
    b['input_leaves'] = s.Q * sum(m.width * 8 for _, _, mats in rounds for m in mats)
    b['input_salts'] = s.Q * sum(s.salt * 8 for _, _, mats in rounds for m in mats if m.salted)
    sib_in = 0.0
    for rname, _, mats in rounds:
        th = max(m.log_h for m in mats)
        sib_in += exp_siblings(s.Q, th, tree_caps[rname])
    b['input_siblings'] = sib_in * s.digest
    b['fri_leaves'] = s.Q * sum(((2 ** r['log_arity']) - 1) * E for r in g['rounds'])
    b['fri_salts'] = s.Q * R * s.salt * 8 if s.zk else 0
    sib_f = sum(exp_siblings(s.Q, r['tree_h'], min(s.cap, r['tree_h'])) for r in g['rounds'])
    b['fri_siblings'] = sib_f * s.digest
    b['counts'] = 2 * (len(rounds) + R)
    b['total'] = sum(v for k, v in b.items())
    for k in ('input_siblings', 'fri_siblings', 'total'):
        b[k] = round(b[k])
    b['t'] = t_total
    b['t_by_height'] = t_by_height(tables, s)
    b['schedule'] = g['schedule']
    b['heights'] = g['heights']
    b['n_commitments_in_proof'] = n_proof_commits + R
    return b


def t_by_height(tables, s: FriSet):
    """Batching ladder length per LDE height (Plonky3 open_inputs: one alpha' ladder per height)."""
    out = {}
    for _, _, mats in commitment_rounds(tables, s):
        for m in mats:
            out[m.log_h] = out.get(m.log_h, 0) + m.points * m.opened_per_point
    return dict(sorted(out.items(), reverse=True))


def per_query_full_path_bytes(tables, s: FriSet, hint=8):
    """Bytes of one query with full (non-deduplicated) cap-truncated paths: layout a' (QRY inputs) carries this.
    `hint` = the 8-byte per-query hint (T_q) of DESIGN-T8 sec. 5."""
    rounds = commitment_rounds(tables, s)
    g = fri_geometry(tables, s)
    E = 8 * s.D
    leaves = sum(m.width * 8 + (s.salt * 8 if m.salted else 0) for _, _, mats in rounds for m in mats)
    fri_leaf = sum(((2 ** r['log_arity']) - 1) * E + (s.salt * 8 if s.zk else 0) for r in g['rounds'])
    path = 0
    for rname, _, mats in rounds:
        th = max(m.log_h for m in mats)
        path += th - effective_cap(s.cap, th, min(m.log_h for m in mats))
    path += sum(r['tree_h'] - min(s.cap, r['tree_h']) for r in g['rounds'])
    return dict(leaves=leaves, fri_leaves=fri_leaf, path_digests=path, total=leaves + fri_leaf + path * s.digest + hint)


def merkle_work(tables, s: FriSet):
    """Expected verifier Merkle work for the whole proof: leaf hashes (SHA-256 blocks), node compressions."""
    rounds = commitment_rounds(tables, s)
    g = fri_geometry(tables, s)
    E = 8 * s.D
    leaf_blocks, leaf_hashes, nodes = 0.0, 0.0, 0.0
    top = g['heights'][0]
    for rname, _, mats in rounds:
        th = max(m.log_h for m in mats)
        c = effective_cap(s.cap, th, min(m.log_h for m in mats))
        for h in sorted({m.log_h for m in mats}, reverse=True):
            L = sum(m.width * 8 + (s.salt * 8 if m.salted else 0) for m in mats if m.log_h == h)
            k = exp_distinct(s.Q, 2 ** h)
            leaf_hashes += k
            leaf_blocks += k * math.ceil((L + 9) / 64)
            if h != th:
                nodes += k          # injection compression at that level
        nodes += exp_nodes(s.Q, th, c)
    for r in g['rounds']:
        L = (2 ** r['log_arity']) * E + (s.salt * 8 if s.zk else 0)
        k = exp_distinct(s.Q, 2 ** r['tree_h'])
        leaf_hashes += k
        leaf_blocks += k * math.ceil((L + 9) / 64)
        nodes += exp_nodes(s.Q, r['tree_h'], min(s.cap, r['tree_h']))
    return dict(leaf_hashes=leaf_hashes, leaf_blocks=leaf_blocks, node_compressions=nodes,
                sha_blocks=leaf_blocks + 2 * nodes)


# ============================================================== Track 8 shapes (AIR-SPEC.md is the source)
# M1: one table, Poseidon2-Gl-8, 17 main columns, 11 periodic, 53 constraints, degree 4 (AIR-SPEC sec. 3).
M1 = [Table('M1', 10, 17, main_next=True, num_constraints=53, max_deg=4, public_values=12, periodic=11)]
# M2: T_hash (2^10, 24 main + 1 preprocessed, 40 AIR + 4 LogUp constraints, degree 4) and T_ctl (2^7, 13 main +
# 5 preprocessed, 31 AIR + 4 LogUp constraints, degree 2), one global bus of width 13 (AIR-SPEC sec. 4).
M2 = [Table('T_hash', 10, 24, main_next=True, pre_width=1, num_constraints=44, max_deg=4, num_lookups=1,
            interactions_per_row=1, bus_width=13, public_values=0, periodic=11),
      Table('T_ctl', 7, 13, main_next=True, pre_width=5, num_constraints=35, max_deg=2, num_lookups=1,
            interactions_per_row=1, bus_width=13, public_values=12)]

Z128 = FriSet('Z128', cap=0)
Z128c5 = FriSet('Z128-cap5', cap=5)
Z128g = FriSet('Z128-g', log_final_poly_len=5, lookup_pow=8)
# stretch for today's rules (DESIGN-T8 sec. 5, a'): one query fewer, query PoW 28
Z128s = FriSet('Z128-s (Q23, qPoW28)', Q=23, query_pow=28, cap=5)

SETS = dict(Z128=Z128, Z128c5=Z128c5, Z128g=Z128g, Z128s=Z128s)


# ============================================================== Track 5 reproduction (acceptance)
T5_AIR_WIDTH = {'fib': 2, 'mimc': 3}


def track5_shape(v):
    """Rebuild a Track 5 (uni-stark, p3s-v1) vector as a 1-table shape. Track 5 has no OOD/lookup PoW, 1 header
    byte; the PoW witness bytes are taken from the vector (bits are not in summary.json)."""
    zk = bool(v['zk'])
    # max_deg is only used for the chunk count: pick it so that num_chunks equals the recorded one
    t = Table(v['air'], v['log_n'], T5_AIR_WIDTH[v['air']])
    t.max_deg = next(d for d in range(1, 20) if num_chunks(replace(t, max_deg=d), zk) == v['quotient_chunks'])
    s = FriSet(v['set'], D=v['ext'], log_blowup=v['log_blowup'], max_log_arity=v['max_log_arity'],
               log_final_poly_len=int(lg(v['final_poly_len'])), Q=v['queries'], query_pow=0, commit_pow=0,
               batch_pow=0, zk=zk, rc=v['random_codewords'] if zk else 0, salt=v['salt'] if zk else 0, cap=0,
               digest=v['digest_bytes'])
    return [t], s


def track5_model(v):
    tables, s = track5_shape(v)
    assert num_chunks(tables[0], s.zk) == v['quotient_chunks'], v['file']
    b = proof_bytes(tables, s, header_bytes=1)
    b['total'] += v['sizes']['pow_witnesses'] - b['pow_witnesses']
    b['pow_witnesses'] = v['sizes']['pow_witnesses']
    assert b['schedule'] == v['fri_log_arities'], (v['file'], b['schedule'], v['fri_log_arities'])
    return b


def selftest(verbose=True):
    rows = json.load(open(os.path.join(HERE, 'track5-summary.json')))
    out = []
    for v in rows:
        b = track5_model(v)
        meas = v['proof_bytes']
        dev = (b['total'] - meas) / meas * 100
        # deterministic parts must match exactly
        exact = {k: (b[k] if k not in ('input_salts',) else b['input_salts'] + b['fri_salts'], v['sizes'][k])
                 for k in ('header', 'roots', 'ood_values', 'final_poly', 'input_leaves', 'fri_leaves',
                           'counts', 'input_salts')}
        bad = {k: x for k, x in exact.items() if x[0] != x[1]}
        out.append(dict(file=v['file'], measured=meas, model=b['total'], dev_pct=round(dev, 3), exact_mismatch=bad,
                        sib_model=b['input_siblings'] + b['fri_siblings'],
                        sib_meas=v['sizes']['input_siblings'] + v['sizes']['fri_siblings']))
    key = {r['file']: r for r in out}
    s128, s128z = key['mimc-S128-0.json'], key['fib-S128z-zkmin-0.json']
    devs = [r['dev_pct'] for r in out]
    res = dict(S128=s128, S128z=s128z, n=len(out), mean_dev_pct=round(sum(devs) / len(devs), 3),
               max_abs_dev_pct=round(max(abs(d) for d in devs), 3), exact_parts_ok=all(not r['exact_mismatch'] for r in out),
               pass_1pct=abs(s128['dev_pct']) <= 1 and abs(s128z['dev_pct']) <= 1, rows=out)
    if verbose:
        print('Track 5 reproduction (p3s-v1 vectors, model = deterministic parts + expected multiproof siblings)')
        for nm, r in (('S128 (mimc-S128-0)', s128), ('S128z (fib-S128z-zkmin-0)', s128z)):
            print(f'  {nm:26} measured {r["measured"]:>7,} B  model {r["model"]:>7,} B  ({r["dev_pct"]:+.2f}%)  '
                  f'siblings model {r["sib_model"]:,} / measured {r["sib_meas"]:,} B')
        print(f'  all {res["n"]} vectors: mean deviation {res["mean_dev_pct"]:+.3f}%, max |dev| {res["max_abs_dev_pct"]:.3f}%, '
              f'deterministic parts exact: {res["exact_parts_ok"]}')
        print(f'  acceptance (S128 and S128z within 1%): {"PASS" if res["pass_1pct"] else "FAIL"}')
    return res


def s1_crosscheck(vdir):
    """Compare the model with S1's p3b-v1 vectors (Plonky3 batch test AIRs re-configured to SHA-256/Goldilocks/D3)."""
    import glob
    rows = []
    for f in sorted(glob.glob(os.path.join(vdir, '*', '*.json'))):
        v = json.load(open(f))
        if 'shape' not in v or 'sizes' not in v:
            continue
        sh, st = v['shape'], v['set']
        zk = bool(st['zk'])
        tables = []
        for ins in sh['instances']:
            t = Table(ins['label'], ins['log_n'], ins['width'], main_next=ins['opens_next'],
                      pre_width=ins['preprocessed_width'], pre_next=ins['preprocessed_next'],
                      num_lookups=ins['num_lookups'])
            t.max_deg = next(d for d in range(1, 40) if num_chunks(replace(t, max_deg=d), zk) == ins['num_chunks'])
            tables.append(t)
        s = FriSet(st['name'], D=st['ext'], log_blowup=st['log_blowup'], max_log_arity=st['max_log_arity'],
                   log_final_poly_len=st['log_final_poly_len'], Q=st['num_queries'], query_pow=st['query_pow_bits'],
                   commit_pow=st['commit_pow_bits'], batch_pow=st['batch_pow_bits'], ood_pow=st['ood_pow_bits'],
                   lookup_pow=st['lookup_pow_bits'], zk=zk, rc=st['num_random_codewords'] if zk else 0,
                   salt=st['salt'] if zk else 0, cap=st['cap_height'], digest=st['digest'])
        b = proof_bytes(tables, s)
        meas = v['sizes']['total']
        DET = ('header', 'roots', 'ood_values', 'lookup_terminals', 'pow_witnesses', 'final_poly', 'input_leaves',
               'input_salts', 'fri_leaves', 'fri_salts', 'counts')
        det = (meas - v['sizes']['input_siblings'] - v['sizes']['fri_siblings'], sum(b[k] for k in DET))
        rows.append(dict(file=os.path.relpath(f, vdir), measured=meas, model=b['total'],
                         dev_pct=round((b['total'] - meas) / meas * 100, 3), deterministic_exact=det[0] == det[1],
                         det_measured=det[0], det_model=det[1], schedule_ok=b['schedule'] == sh['log_arities']))
    devs = [r['dev_pct'] for r in rows]
    z = [r['dev_pct'] for r in rows if r['file'].startswith('Z128')]
    return dict(n=len(rows), z128_n=len(z), z128_mean_dev_pct=round(sum(z) / max(1, len(z)), 3),
                z128_max_abs_dev_pct=round(max((abs(d) for d in z), default=0), 3), mean_dev_pct=round(sum(devs) / max(1, len(devs)), 3),
                max_abs_dev_pct=round(max((abs(d) for d in devs), default=0), 3),
                deterministic_exact=all(r['deterministic_exact'] for r in rows),
                schedules_ok=all(r['schedule_ok'] for r in rows), rows=rows)


def describe(tables, s):
    b = proof_bytes(tables, s)
    c = checks(tables, s)
    pq = per_query_full_path_bytes(tables, s)
    return dict(set=asdict(s), tables=[asdict(t) | dict(chunks=num_chunks(t, s.zk), lde_log_height=lde_log_height(t, s))
                                       for t in tables],
                bytes=b, checks=c, per_query_full_path=pq, merkle=merkle_work(tables, s),
                rounds=[(r, inp, [asdict(m) for m in mats]) for r, inp, mats in commitment_rounds(tables, s)],
                fri=fri_geometry(tables, s))


def main():
    r = selftest()
    if '--s1' in sys.argv:
        x = s1_crosscheck(sys.argv[sys.argv.index('--s1') + 1])
        print(f'S1 p3b-v1 vectors: {x["n"]} proofs, mean deviation {x["mean_dev_pct"]:+.3f}%, max |dev| {x["max_abs_dev_pct"]:.2f}% '
              f'(Z128 family: {x["z128_n"]} proofs, mean {x["z128_mean_dev_pct"]:+.3f}%, max |dev| {x["z128_max_abs_dev_pct"]:.2f}%), '
              f'deterministic parts exact: {x["deterministic_exact"]}, fold schedules: {x["schedules_ok"]}')
        for row in x['rows']:
            if not row['deterministic_exact']:
                print('   mismatch', row)
        json.dump(x, open(os.path.join(HERE, 's1-crosscheck.json'), 'w'), indent=1)
    if '--shapes' in sys.argv or True:
        for label, tables, s in (('M1 / Z128 cap 0', M1, Z128), ('M1 / Z128 cap 5', M1, Z128c5),
                                 ('M2 / Z128-g cap 0', M2, Z128g), ('M2 / Z128 (negative check)', M2, Z128)):
            d = describe(tables, s)
            b, c = d['bytes'], d['checks']
            print(f'\n{label}: proof {b["total"]:,} B  t={b["t"]} t_by_height={b["t_by_height"]} heights={b["heights"]} '
                  f'schedule={b["schedule"]}')
            print('   ' + ', '.join(f'{k} {b[k]}' for k in ('header', 'roots', 'ood_values', 'lookup_terminals',
                                                         'pow_witnesses', 'final_poly', 'input_leaves', 'input_salts',
                                                         'input_siblings', 'fri_leaves', 'fri_salts', 'fri_siblings', 'counts')))
            print(f'   checks: strict-height {c["strict_height"]["ok"]} {c["strict_height"]["heights"]} '
                  f'({c["strict_height"]["rule"]}); arity grid {c["arity_grid"]["ok"]} {c["arity_grid"]["schedule"]}; '
                  f'hiding budget {c["hiding_budget"]["ok"]} (min mask {min(x["mask"] for x in c["hiding_budget"]["rows"])}, '
                  f'need {max(x["need"] for x in c["hiding_budget"]["rows"])}); per-query full path {d["per_query_full_path"]["total"]} B')
    return r


if __name__ == '__main__':
    main()
