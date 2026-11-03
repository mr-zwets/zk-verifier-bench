#!/usr/bin/env python3
"""Track 10 gate G0: per-round soundness with a field parameter, and a recomputation of RISC Zero and ZisK.

Three calculators, one file. All figures are bits = -log2(error) per round, plus the grinding sited before that
round's challenge; lambda = min over rounds. Nothing here is a proof.

  A. T8   Track 8's own accounting (params8.py, imported read-only), with the extension field as a parameter:
          [ADK] Thm 2 per round, [BCIKS20] Thm 7.4 (A0 + B1, quadratic in |D|) in batching and folds, and the
          UNPUBLISHED powers-batching adaptation ([BCIKS20] Thm 7.2 curve of degree t-1 in the batching round,
          Track 5 SOUNDNESS.md sec. 2.1). Fields: Gl^3, BabyBear^4/5, KoalaBear^4/5.
          For an external single-domain FRI STARK (RISC Zero, ZisK) the same per-round formulas are applied to the
          shape soundcalc records (trace N, rate, batch size B, constraints C, degree d, opening points, folds).
          The UD variant is [ADK] Thm 3.
  B. SC   An independent re-implementation of EF soundcalc's model (github.com/ethereum/soundcalc @ b325e30,
          2026-10-30; files proxgaps/{johnson_bound,unique_decoding}.py, pcs/{pcs,fri,stir}.py,
          circuits/deep_ali.py, lookups/logup.py, math_companion/{prelim,fri,stir}.tex). JBR: [BCHKS25] Thm 4.2
          (linear in |D|) for lines, times (B - 1) for powers; UDR: [BCHKS25] Thm 4.1 / Cor. 1.4.
          soundcalc's code was NOT executed (untrusted download); its committed reports are compared with this
          re-implementation instead. Values are printed unfloored; soundcalc floors every cell.
  C. HYB  Track 8's accounting (list size m/(rho - 2m/|D|), DEEP charged L^2, query sqrt(rho)(1 + 1/2m)) with
          [BCHKS25] Thm 4.2 in place of [BCIKS20] A0 + B1 in batching and folds. Separates "which proximity-gap
          theorem" from "which accounting".

Sources: [ADK] ePrint 2024/1553 (IACR CiC 3(2)); [BCIKS20] ePrint 2020/654 rev. 3 / ECCC TR20-083; [BCHKS25]
Ben-Sasson, Carmon, Haboeck, Kopparty, Saraf, "On Proximity Gaps for Reed-Solomon Codes", ePrint 2025/2055
(received 2025-11-06). The BCHKS25 theorem text was NOT read for this work (ePrint PDF returned 403); its formula is
taken from soundcalc's code and math companion, which cite Thm 4.1 / 4.2 / Cor. 1.4 and note a factor-2 typo in
Thm 4.2 "confirmed by the paper authors". Every BCHKS25 figure below is therefore [UNV against the paper].

Run:  python3 params10.py                     tables (writes params10-output.txt and .json next to this file)
      python3 params10.py --toml ZISK RISC0   also check the hard-coded configs against soundcalc's TOML files
Standard library only.
"""
import json
import math
import os
import sys
from dataclasses import dataclass, field, replace, asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'design-t8'))
sys.path.insert(0, os.path.join(HERE, '..', 'soundness'))
import params8 as p8   # noqa: E402  (read-only reuse; Track 8 S0/S8 calculator)
import params5 as p5   # noqa: E402
import bytes8 as b8    # noqa: E402

lg = math.log2
P_GL = 2 ** 64 - 2 ** 32 + 1
P_BB = 2 ** 31 - 2 ** 27 + 1
P_KB = 2 ** 31 - 2 ** 24 + 1
FIELDS = {'Gl3': ('Goldilocks^3', P_GL, 3), 'BB4': ('BabyBear^4', P_BB, 4), 'BB5': ('BabyBear^5', P_BB, 5),
          'KB4': ('KoalaBear^4', P_KB, 4), 'KB5': ('KoalaBear^5', P_KB, 5)}


def log_q(fk):
    _, p, D = FIELDS[fk]
    return D * lg(p)


def ladd(*xs):
    xs = [x for x in xs if x is not None]
    mx = max(xs)
    return mx + lg(sum(2 ** (x - mx) for x in xs))


# ====================================================================== A. Track 8 accounting, field-parametric
# Same functions as params8 (term_logup .. rounds), with log|EF| passed in instead of fixed to Goldilocks.
# hyb=True swaps BCIKS20 (A0 + B1) for BCHKS25 Thm 4.2 at the same m (calculator C).
def _prox(m, rho, Ndom, lq, hyb):
    """log2 of the per-line proximity-gap error at multiplicity m on a domain of size Ndom."""
    if hyb:
        return bchks_lin_J_m(rho, Ndom, lq, m)
    return ladd(p5.A0(m, rho, Ndom, lq), p5.B1(m, rho, Ndom, lq))


def t8_rounds(tables, s, m, fk, hyb=False):
    lq = log_q(fk)
    rho = 2.0 ** -s.log_blowup
    L = lambda t: p5.list_size_adk(m, rho, 2 ** b8.lde_log_height(t, s))  # noqa: E731
    r = {}
    lt = [t for t in tables if t.num_lookups]
    if lt:
        Lmax = max(L(t) for t in tables)
        N = sum(t.interactions_per_row * 2 ** t.log_n for t in lt)
        W = max(t.bus_width for t in lt)
        r['logup'] = lq - lg(Lmax * N * (W + 2)) + s.lookup_pow
    r['ali'] = lq - lg(sum(L(t) * t.num_constraints for t in tables))
    tot = 0.0
    for t in tables:
        k = 2 ** (t.log_n + (1 if s.zk else 0))
        c = b8.num_chunks(t, s.zk)
        tot += L(t) ** 2 * p5.deep_numerator(t.max_deg, k, c, k, 2, c)
    r['deep'] = lq - lg(tot) + s.ood_pow
    th = b8.t_by_height(tables, s)
    top = max(th)
    if hyb:
        bt = sum((t - 1) * 2 ** bchks_lin_J_m(rho, 2 ** top, lq, m) for t in th.values())
    else:
        a0, b1 = p5.A0(m, rho, 2 ** top, lq), p5.B1(m, rho, 2 ** top, lq)
        bt = sum((t - 1) * (2 ** a0 + 2 ** b1) for t in th.values())
    r['batch'] = -lg(bt) + s.batch_pow
    g = b8.fri_geometry(tables, s)
    h0 = g['heights'][0]
    a0, b1 = p5.A0(m, rho, 2 ** h0, lq), p5.B1(m, rho, 2 ** h0, lq)
    for i, rr in enumerate(g['rounds']):
        a = 2 ** rr['log_arity']
        coef = a if rr['rollin'] else a - 1
        if hyb:
            e = lg(coef) + bchks_lin_J_m(rho, 2 ** rr['h_out'], lq, m)
        else:
            e = ladd(lg(coef) + a0 + 2 * (rr['h_out'] - h0), lg(a) + b1)
        r[f'fold{i + 1}'] = -e + s.commit_pow
    r['query'] = -s.Q * lg(math.sqrt(rho) * (1 + 1 / (2 * m))) + s.query_pow
    return r


def best(rounds_fn, ms):
    out = None
    for m in ms:
        r = rounds_fn(m)
        lam = min(r.values())
        if out is None or lam > out['lam_iop']:
            out = dict(m=m, lam_iop=round(lam, 2), binding=min(r, key=r.get), rounds={k: round(v, 2) for k, v in r.items()})
    return out


def t8_soundness(tables, s, fk='Gl3', hyb=False, ms=p8.M_RANGE):
    s = replace(s, D=FIELDS[fk][2])
    out = best(lambda m: t8_rounds(tables, s, m, fk, hyb), ms)
    out['lam'] = round(min(out['lam_iop'], p5.digest_bits(s.digest)), 2)
    out['field'] = FIELDS[fk][0]
    out['label'] = ('HYB: T8 accounting with BCHKS25 Thm 4.2 [UNV vs paper]' if hyb else
                    'T8: JB, BCIKS20 Thm 7.2/7.4, powers-batching adaptation (unpublished)')
    return out


def t8_min_pow(tables, s, fk, target, ms=p8.M_RANGE):
    """Smallest PoW per site (at the m that maximises lambda) reaching `target` (ALI has no site)."""
    sol = t8_soundness(tables, s, fk, ms=ms)
    raw = t8_rounds(tables, replace(s, D=FIELDS[fk][2], query_pow=0, commit_pow=0, batch_pow=0, ood_pow=0,
                                    lookup_pow=0), sol['m'], fk)
    return dict(m=sol['m'], raw={k: round(v, 2) for k, v in raw.items()},
                need={k: max(0, math.ceil(target - v - 1e-9)) for k, v in raw.items()})


# ====================================================================== B. soundcalc model (re-implemented)
def sc_gap(rho, lqF, gap):
    """JBR gap eta (johnson_bound.py get_proximity_parameter): pinned, or sqrt(rho)/100 for |F| > 2^150, else
    max(rho/20, sqrt(rho)/100)."""
    if gap:
        return gap
    sr = math.sqrt(rho)
    return sr / 100 if lqF > 150 else max(rho / 20, sr / 100)


def sc_m(rho, eta):
    return max(math.ceil(math.sqrt(rho) / (2 * eta)), 3)


def bchks_lin_J(rho, dim, lqF, eta):
    """log2 of BCHKS25 Thm 4.2 (as coded in soundcalc johnson_bound.get_error_linear), dim = code dimension.
    ((2 m'^5 + 3 m' gamma rho) n / (3 rho^1.5) + m' / sqrt(rho)) / |F|, m' = m + 1/2, n = dim / rho,
    gamma = 1 - sqrt(rho) - eta."""
    sr = math.sqrt(rho)
    gamma = 1 - sr - eta
    ms = sc_m(rho, eta) + 0.5
    n = dim / rho
    return lg((2 * ms ** 5 + 3 * ms * gamma * rho) * n / (3 * rho * sr) + ms / sr) - lqF


def bchks_lin_J_m(rho, Ndom, lqF, m):
    """Same bound at an explicit multiplicity m >= 3 (eta = sqrt(rho)/(2m)), on a domain of size Ndom."""
    return bchks_lin_J(rho, Ndom * rho, lqF, math.sqrt(rho) / (2 * m))


def bchks_lin_U(rho, dim, lqF):
    """BCHKS25 Thm 4.1 / Cor. 1.4 as coded (unique_decoding.get_error_linear): ((1-rho)/2 * n + 1) / |F|."""
    return lg((1 - rho) / 2 * dim / rho + 1) - lqF


@dataclass
class Lookup:
    name: str
    rows_L: int
    rows_T: int
    S: int
    M: int
    g: int = 0


@dataclass
class ExtFri:
    """A single-domain DEEP-ALI + batched FRI STARK as soundcalc records it (one [[circuits]] TOML section)."""
    name: str
    fk: str
    N: int                      # trace_length
    rho: float
    B: int                      # batch_size
    C: int                      # num_constraints
    d: int                      # air_max_degree
    combo: int                  # opening_points (max_combo)
    Q: int
    folds: list
    early_stop: int
    gq: int = 0
    gc: int = 0
    gb: int = 0
    gap: float = None
    lookups: list = field(default_factory=list)
    src: str = ''


@dataclass
class ExtStir:
    name: str
    fk: str
    log_degree: int
    log_inv_rate: int
    ks: list                    # log folding factors
    queries: list
    ood: list
    gq: list
    B: int
    C: int
    d: int
    combo: int
    gb: int = 0
    gfold: int = 0
    gap: float = None
    lookups: list = field(default_factory=list)
    src: str = ''


def _lookups_sc(c, lqF):
    return {lk.name: lqF - lg(lk.M * (lk.rows_L + lk.rows_T) * lk.S) + lk.g for lk in c.lookups}


def _deep_ali_sc(c, N, rho, lqF, Lp):
    D = N / rho
    ali = lqF - lg(Lp * c.C)
    deep = -(lg(Lp * (c.d * (N + c.combo - 1) + (N - 1))) - lg(2 ** lqF - N - D))
    return {'ALI': ali, 'DEEP': deep}


def sc_fri(c: ExtFri, regime, eta=None):
    """soundcalc FRI_STARK circuit, regime 'UDR' or 'JBR'; eta overrides the gap (for the m sweep)."""
    lqF = log_q(c.fk)
    rho, N = c.rho, c.N
    r = _lookups_sc(c, lqF)
    if regime == 'UDR':
        pp, Lp = (1 - rho) / 2, 1.0
        lin = lambda dim: bchks_lin_U(rho, dim, lqF)  # noqa: E731
    else:
        eta = eta or sc_gap(rho, lqF, c.gap)
        pp, Lp = 1 - math.sqrt(rho) - eta, 1 / (2 * eta * math.sqrt(rho))
        lin = lambda dim: bchks_lin_J(rho, dim, lqF, eta)  # noqa: E731
    assert N + c.combo < (1 - pp) * N / rho, 'multi-point condition'
    r.update(_deep_ali_sc(c, N, rho, lqF, Lp))
    r['batching'] = -(lin(N) + lg(c.B - 1)) + c.gb          # get_error_powers = linear * (B - 1) in both regimes (code)
    acc, n = 1, int(N / rho)
    for i, k in enumerate(c.folds):
        acc *= k
        r[f'commit{i + 1}'] = -(lin(N / acc) + lg(k - 1)) + c.gc
        n //= k
    assert n == c.early_stop, (c.name, n, c.early_stop)
    r['query'] = -c.Q * lg(1 - pp) + c.gq
    return r


def sc_stir(c: ExtStir, regime, eta=None):
    lqF = log_q(c.fk)
    M = len(c.ks)
    mdeg = [c.log_degree]
    mu = [c.log_inv_rate]
    for k in c.ks:
        mdeg.append(mdeg[-1] - k)
        mu.append(mu[-1] + k - 1)

    def code(i, folded):
        return 2.0 ** -mu[i], 2 ** (mdeg[i] - (c.ks[i] if folded else 0))

    if regime == 'UDR':
        pp = lambda rho: (1 - rho) / 2                              # noqa: E731
        L = lambda rho: 1.0                                        # noqa: E731
        lin = lambda rho, dim: bchks_lin_U(rho, dim, lqF)          # noqa: E731
    else:
        e_of = lambda rho: eta or sc_gap(rho, lqF, c.gap)          # noqa: E731
        pp = lambda rho: 1 - math.sqrt(rho) - e_of(rho)            # noqa: E731
        L = lambda rho: 1 / (2 * e_of(rho) * math.sqrt(rho))       # noqa: E731
        lin = lambda rho, dim: bchks_lin_J(rho, dim, lqF, e_of(rho))  # noqa: E731
    powers = lambda rho, dim, B: lin(rho, dim) + lg(B - 1)          # noqa: E731
    delta = lambda i: min(pp(code(i, f)[0]) for f in (False, True))  # noqa: E731
    r = _lookups_sc(c, lqF)
    rho0, N0 = code(0, False)
    r.update(_deep_ali_sc(c, N0, rho0, lqF, L(rho0)))
    r['batching'] = -powers(rho0, N0, c.B) + c.gb
    r['fold0'] = -powers(*code(0, True), 2 ** c.ks[0]) + c.gfold
    for i in range(1, M):
        rho_i, _ = code(i, False)
        dom = 2 ** (mdeg[i] + mu[i])
        s = c.ood[i - 1]
        r[f'ood{i}'] = -(lg(L(rho_i) ** 2 / 2) + s * (mdeg[i] - lg(2 ** lqF - dom)))
        t = c.queries[i - 1]
        e = ladd(t * lg(1 - delta(i - 1)), powers(*code(i, False), t + s), powers(*code(i, True), 2 ** c.ks[i]))
        r[f'shift{i}'] = -e + c.gq[i - 1]
    r['fin'] = -c.queries[-1] * lg(1 - delta(M - 1)) + c.gq[-1]
    return r


def sc_fri_legacy(c: ExtFri, regime):
    """Hypothesis for the stale reports/risc0.md: (JBR) m = max(ceil(sqrt(rho)/eta), 3), i.e. without the factor 2
    that soundcalc's johnson_bound.py now adds ("typo confirmed by the paper authors"); (UDR) the BCIKS20 eps_U = n/|F|
    line error instead of BCHKS25's ((1-rho)/2 n + 1)/|F|. Only batching and commit rounds change."""
    lqF = log_q(c.fk)
    rho, N = c.rho, c.N
    if regime == 'UDR':
        lin = lambda dim: lg(dim / rho) - lqF  # noqa: E731
    else:
        eta = sc_gap(rho, lqF, c.gap)
        sr = math.sqrt(rho)
        ms = max(math.ceil(sr / eta), 3) + 0.5
        lin = lambda dim: lg((2 * ms ** 5 + 3 * ms * (1 - sr - eta) * rho) * (dim / rho) / (3 * rho * sr) + ms / sr) - lqF  # noqa: E731,E501
    r = {'batching': -(lin(N) + lg(c.B - 1)) + c.gb}
    acc = 1
    for i, k in enumerate(c.folds):
        acc *= k
        r[f'commit{i + 1}'] = -(lin(N / acc) + lg(k - 1)) + c.gc
    return r


def load_toml_circuits(path):
    """Every FRI_STARK / STIR circuit of a soundcalc TOML as ExtFri / ExtStir (data only, tomllib)."""
    import tomllib
    with open(path, 'rb') as fh:
        t = tomllib.load(fh)
    fk = {v[0]: k for k, v in FIELDS.items()}[t['zkevm']['field']]
    out = []
    for sec in t['circuits']:
        lks = [Lookup(l['name'], l['rows_L'], l['rows_T'], l.get('num_columns_S', 1), l.get('num_lookups_M', 1),
                      l.get('grinding_bits_lookup', 0)) for l in sec.get('lookups', [])]
        if sec['protocol_family'] == 'FRI_STARK':
            out.append(ExtFri(sec['name'], fk, sec['trace_length'], sec['rho'], sec['batch_size'], sec['num_constraints'],
                              sec['air_max_degree'], sec['opening_points'], sec['num_queries'], sec['fri_folding_factors'],
                              sec['fri_early_stop_degree'], sec.get('grinding_query_phase', 0),
                              sec.get('grinding_commit_phase', 0), sec.get('grinding_batching_phase', 0),
                              sec.get('gap_to_radius'), lks, src=path))
        elif sec['protocol_family'] == 'STIR':
            out.append(ExtStir(sec['name'], fk, sec['log_degree'], sec['log_inv_rate'], sec['folding_factors'],
                               sec['num_queries'], sec['num_ood_samples'], sec['grinding_bits_queries'],
                               sec['batch_size'], sec['num_constraints'], sec['air_max_degree'], sec['opening_points'],
                               sec['grinding_batching_phase'], sec['grinding_bits_folding'], sec.get('gap_to_radius'),
                               lks, src=path))
        else:
            out.append(sec['name'] + ' (' + sec['protocol_family'] + ', not modelled)')
    return t['zkevm'].get('version'), out


def sc(c, regime, eta=None):
    return (sc_stir if isinstance(c, ExtStir) else sc_fri)(c, regime, eta)


def sc_sweep_m(c, ms=range(3, 401)):
    """Best JBR lambda over the multiplicity m (eta = sqrt(rho_0)/(2m)) instead of the pinned gap."""
    rho0 = c.rho if isinstance(c, ExtFri) else 2.0 ** -c.log_inv_rate
    return best(lambda m: sc(c, 'JBR', math.sqrt(rho0) / (2 * m)), ms)


# ---------------------------------------------------------------------- A/C for the external FRI configs
def t8_ext_rounds(c: ExtFri, m, regime='JB', hyb=False):
    """Track 8 / [ADK] per-round formulas on a single-domain external FRI STARK (no ZK, one LDE height)."""
    lq = log_q(c.fk)
    rho, N = c.rho, c.N
    Dsz = N / rho
    h0 = lg(Dsz)
    num = max(c.d * (N + 1) + (N - 1), c.d * (N + c.combo - 1) + (N - 1))
    r = {}
    if regime == 'UD':                                   # [ADK] Thm 3, BCIKS20 Thm 1.5/1.6 UD part
        for lk in c.lookups:
            r[lk.name] = lq - lg((lk.M * lk.rows_L + lk.rows_T) * (lk.S + 2)) + lk.g
        r['ali'] = lq - lg(c.C)
        r['deep'] = lq - lg(num)
        r['batch'] = lq - lg((c.B - 1) * Dsz) + c.gb
        n = Dsz
        for i, a in enumerate(c.folds):
            r[f'fold{i + 1}'] = lq - lg((a - 1) * (Dsz + 1)) + c.gc
        rho_p = (N + c.combo) / Dsz
        r['query'] = -c.Q * lg((1 + rho_p) / 2) + c.gq
        return r
    L = p5.list_size_adk(m, rho, Dsz)
    for lk in c.lookups:
        r[lk.name] = lq - lg(L * (lk.M * lk.rows_L + lk.rows_T) * (lk.S + 2)) + lk.g
    r['ali'] = lq - lg(L * c.C)
    r['deep'] = lq - lg(L * L * num)
    if hyb:
        r['batch'] = -(lg(c.B - 1) + bchks_lin_J_m(rho, Dsz, lq, m)) + c.gb
    else:
        r['batch'] = -(lg(c.B - 1) + _prox(m, rho, Dsz, lq, False)) + c.gb
    a0, b1 = p5.A0(m, rho, Dsz, lq), p5.B1(m, rho, Dsz, lq)
    h = h0
    for i, a in enumerate(c.folds):
        h -= lg(a)
        if hyb:
            e = lg(a - 1) + bchks_lin_J_m(rho, 2 ** h, lq, m)
        else:
            e = ladd(lg(a - 1) + a0 + 2 * (h - h0), lg(a) + b1)
        r[f'fold{i + 1}'] = -e + c.gc
    r['query'] = -c.Q * lg(math.sqrt(rho) * (1 + 1 / (2 * m))) + c.gq
    return r


# ====================================================================== configurations
LK_ZF = [Lookup('Connection_gprod_[1]', 262144, 262144, 2, 18), Lookup('Lookup_gsum_[1000]', 262144, 262144, 5, 72),
         Lookup('Lookup_gsum_[250]', 262144, 262144, 1, 24), Lookup('Lookup_gsum_[500]', 262144, 0, 2, 8)]
LK_ZC = [Lookup('Connection_gprod_[1]', 262144, 262144, 2, 18), Lookup('Lookup_gsum_[1000]', 262144, 262144, 5, 36),
         Lookup('Lookup_gsum_[250]', 262144, 262144, 1, 12), Lookup('Lookup_gsum_[500]', 262144, 0, 2, 4)]
LK_ZR = [Lookup('Connection_gprod_[1]', 524288, 524288, 2, 18), Lookup('Lookup_gsum_[1000]', 524288, 524288, 5, 72),
         Lookup('Lookup_gsum_[250]', 524288, 524288, 1, 24), Lookup('Lookup_gsum_[500]', 524288, 0, 2, 8)]
SRC_Z = 'soundcalc@b325e30 soundcalc/zkvms/zisk/zisk.toml (ZisK v1.4.0-alpha)'
ZISK_FINAL = ExtFri('ZisK Final', 'Gl3', 2 ** 18, 1 / 16, 1122, 427, 8, 71, 51, [16, 16, 16, 8], 128, gq=27,
                    gap=1 / 300, lookups=LK_ZF, src=SRC_Z + ' [[circuits]] name="Final"')
ZISK_REC2 = ExtFri('ZisK Recursive2', 'Gl3', 2 ** 19, 1 / 4, 1156, 854, 5, 71, 106, [16, 16, 8, 8], 128, gq=24,
                   gap=0.004, lookups=LK_ZR, src=SRC_Z + ' name="Recursive2"')
ZISK_FC = ExtStir('ZisK Final_Compressed (STIR)', 'Gl3', 18, 5, [4, 3, 3], [41, 26, 22], [1, 1], [27, 26, 23],
                  649, 276, 8, 69, gap=1 / 300, lookups=LK_ZC, src=SRC_Z + ' name="Final_Compressed"')
SRC_R = 'soundcalc@b325e30 soundcalc/zkvms/risc0/risc0.toml (Sept 2024 notebook parameters)'
RISC0_MAIN = ExtFri('RISC Zero rv32im segment (soundcalc)', 'BB4', 2 ** 21, 1 / 4, 283, 256, 4, 9, 50,
                    [16, 16, 16, 16], 128, src=SRC_R)
# The succinct (recursion) circuit is not in soundcalc. Same QUERIES = 50, INV_RATE 4, BabyBear^4, no grinding
# (risc0 zkp/src/lib.rs). Shape [UNV]: 2^18 rows (recursion po2), 163 columns + 4 (Design A, unchecked), fold 16
# down to FRI_MIN_DEGREE 256 on a 2^20 domain. Only batching / folds depend on the shape; query does not.
RISC0_SUCC = ExtFri('RISC Zero succinct/recursion (shape UNV)', 'BB4', 2 ** 18, 1 / 4, 167, 256, 4, 9, 50,
                    [16, 16, 16], 256, src='risc0 main zkp/src/lib.rs (QUERIES 50, INV_RATE 4); shape from DESIGN-T10 [UNV]')
# soundcalc's risc0.toml @ b325e30 has no num_constraints (zkvm.py reads section["num_constraints"], so that TOML
# would not load at this commit; reports/risc0.md must predate it [UNV, soundcalc not executed]). The report's ALI
# cells (UDR 115, JBR 109) bound C to about 195..315; C = 256 is a PLACEHOLDER and ALI is not compared for RISC Zero.

SOUNDCALC_REPORT = {   # committed reports @ b325e30, floored bits (reports/zisk.md, reports/risc0.md)
    'ZisK Final': dict(UDR=dict(total=73, ALI=183, DEEP=170, batching=160, commit1=171, commit2=175, commit3=179,
                                commit4=183, query=73),
                       JBR=dict(total=128, ALI=174, DEEP=161, batching=128, commit1=138, commit2=142, commit3=146,
                                commit4=150, query=128)),
    'ZisK Recursive2': dict(UDR=dict(total=95, ALI=182, DEEP=170, batching=162, commit1=172, commit2=176, commit3=180,
                                     commit4=183, query=95),
                            JBR=dict(total=128, ALI=174, DEEP=162, batching=128, commit1=138, commit2=142, commit3=146,
                                     commit4=149, query=128)),
    'ZisK Final_Compressed (STIR)': dict(
        UDR=dict(total=44, ALI=183, DEEP=170, ood1=178, ood2=181, batching=160, fin=44, fold0=170, shift1=66, shift2=51),
        JBR=dict(total=128, ALI=174, DEEP=161, ood1=156, ood2=157, batching=128, fin=129, fold0=138, shift1=128,
                 shift2=128)),
    'RISC Zero rv32im segment (soundcalc)': dict(
        UDR=dict(total=33, DEEP=100, batching=92, commit1=100, commit2=104, commit3=108, commit4=112, query=33),
        JBR=dict(total=48, DEEP=93, batching=63, commit1=71, commit2=75, commit3=79, commit4=83, query=48)),
}
SC_LOOKUP_REPORT = {'ZisK Final': [167, 164, 168, 169], 'ZisK Recursive2': [166, 163, 167, 168],
                    'ZisK Final_Compressed (STIR)': [167, 165, 169, 170]}


def check_toml(paths):
    """Compare the hard-coded configs with soundcalc's TOML (data only, parsed with tomllib)."""
    import tomllib
    out = []
    want = {'Final': ZISK_FINAL, 'Recursive2': ZISK_REC2, 'Final_Compressed': ZISK_FC, 'main': RISC0_MAIN}
    for p in paths:
        with open(p, 'rb') as fh:
            t = tomllib.load(fh)
        for sec in t.get('circuits', []):
            c = want.get(sec['name'])
            if c is None or (sec['name'] == 'main' and 'risc0' not in p.lower()):
                continue
            diffs = []
            if isinstance(c, ExtFri):
                pairs = dict(trace_length=c.N, rho=c.rho, batch_size=c.B, air_max_degree=c.d, opening_points=c.combo,
                             num_queries=c.Q, fri_folding_factors=c.folds, fri_early_stop_degree=c.early_stop,
                             grinding_query_phase=c.gq, gap_to_radius=c.gap)
                if 'RISC' not in c.name:
                    pairs['num_constraints'] = c.C
            else:
                pairs = dict(log_degree=c.log_degree, log_inv_rate=c.log_inv_rate, folding_factors=c.ks,
                             num_queries=c.queries, num_ood_samples=c.ood, grinding_bits_queries=c.gq, batch_size=c.B,
                             num_constraints=c.C, air_max_degree=c.d, opening_points=c.combo, gap_to_radius=c.gap)
            for k, v in pairs.items():
                tv = sec.get(k)
                if isinstance(v, float) and tv is not None:
                    ok = abs(tv - v) < 1e-12
                else:
                    ok = tv == v
                if not ok:
                    diffs.append(f'{k}: here {v} toml {tv}')
            lk = [(l['name'], l['rows_L'], l['rows_T'], l['num_columns_S'], l['num_lookups_M'])
                  for l in sec.get('lookups', [])]
            mine = [(l.name, l.rows_L, l.rows_T, l.S, l.M) for l in c.lookups]
            if lk != mine:
                diffs.append(f'lookups differ: {lk} vs {mine}')
            out.append((c.name, diffs))
    return out


# ====================================================================== report
def fmt(r, nd=2):
    return ', '.join(f'{k} {v:.{nd}f}' for k, v in r.items())


def main(argv):
    lines, js = [], {}

    def P(x=''):
        lines.append(x)
        print(x)

    P('Track 10 G0: params10.py (field-parametric Track 8 accounting + soundcalc re-implementation).')
    P('Bits per round, unfloored unless marked; grinding added at its site. Labels: T8 = Track 8 accounting')
    P('(BCIKS20, powers-batching adaptation, unpublished); SC = soundcalc model (BCHKS25 Thm 4.1/4.2, powers = (B-1) x line,')
    P('[UNV vs the paper text]); HYB = T8 accounting with BCHKS25 Thm 4.2.')
    P()
    if '--toml' in argv:
        P('TOML check (hard-coded configs vs soundcalc TOML):')
        for nm, d in check_toml(argv[argv.index('--toml') + 1:]):
            P(f'  {nm}: {"identical" if not d else d}')
        P()

    # ---- 1. Track 8 reproduction
    P('=' * 110)
    P('1. Track 8 reproduction (field Gl^3): params10 vs params8, same inputs')
    P('=' * 110)
    js['track8'] = {}
    cases = [('M1 / Z128', b8.M1, b8.Z128), ('M1 / Z128-s', b8.M1, b8.Z128s),
             ('M2 / Z128-g cpow 3', b8.M2, replace(b8.Z128g, commit_pow=3)),
             ('M1 / Z128 batch PoW 12', b8.M1, replace(b8.Z128, batch_pow=12))]
    allok = True
    for label, tables, s in cases:
        a = p8.soundness(tables, s)
        b = t8_soundness(tables, s, 'Gl3')
        diff = max(abs(a['rounds'][k] - b['rounds'][k]) for k in a['rounds'])
        ok = a['lam_iop'] == b['lam_iop'] and a['m'] == b['m'] and diff < 1e-9
        allok &= ok
        P(f'  {label}: params8 lambda_IOP {a["lam_iop"]} (m={a["m"]}), params10 {b["lam_iop"]} (m={b["m"]}); '
          f'max |round diff| {diff:.2e}  [{"EXACT" if ok else "MISMATCH"}]')
        js['track8'][label] = dict(params8=a, params10=b, exact=ok)
    m1 = t8_soundness(b8.M1, b8.Z128, 'Gl3')
    P(f'  ACCEPTANCE: M1 Z128 lambda_IOP = {m1["lam_iop"]} (Track 8: 128.06): {"PASS" if m1["lam_iop"] == 128.06 and allok else "FAIL"}')
    js['track8']['acceptance'] = m1['lam_iop'] == 128.06 and allok
    P(f'     rounds: {fmt(m1["rounds"])}')
    hy = t8_soundness(b8.M1, b8.Z128, 'Gl3', hyb=True)
    P(f'  M1 Z128 under HYB (BCHKS25 Thm 4.2 in batch/folds): lambda_IOP {hy["lam_iop"]} (m={hy["m"]}, binding {hy["binding"]})')
    P(f'     rounds: {fmt(hy["rounds"])}')
    js['track8']['M1 Z128 HYB'] = hy

    P()
    P('  Field sweep, M1 / Z128 shape and PoW unchanged (T8 accounting):')
    js['field_sweep'] = {}
    for fk in FIELDS:
        r = t8_soundness(b8.M1, b8.Z128, fk)
        mp = t8_min_pow(b8.M1, b8.Z128, fk, 128)
        P(f'    {FIELDS[fk][0]:13} log|EF| {log_q(fk):6.1f}: lambda_IOP {r["lam_iop"]:6.2f} (m={r["m"]}, binding {r["binding"]}); '
          f'PoW needed for 128 {mp["need"]}')
        js['field_sweep'][fk] = dict(soundness=r, min_pow=mp)

    # ---- 1b. DESIGN-T10 Stage 0 checks (bridge shape of the RISC Zero design, kept for the record)
    P()
    P('  DESIGN-T10 Stage 0 acceptance (RISC Zero bridge shape: P2 2^18 x50, ALU 2^16 x60, W 2^13 x12; no ZK):')
    br = [b8.Table('P2', 18, 50, num_constraints=60, max_deg=4, num_lookups=2, interactions_per_row=4, bus_width=8,
                   periodic=27),
          b8.Table('ALU', 16, 60, pre_width=10, num_constraints=40, max_deg=3, num_lookups=2, interactions_per_row=6,
                   bus_width=8),
          b8.Table('W', 13, 12, pre_width=4, num_constraints=10, max_deg=2, num_lookups=1, interactions_per_row=2,
                   bus_width=8)]
    s100 = b8.FriSet('B100', log_blowup=6, max_log_arity=3, log_final_poly_len=5, Q=27, query_pow=24, commit_pow=16,
                     batch_pow=24, lookup_pow=8, zk=False, rc=0, salt=0)
    bb4 = t8_soundness(br, s100, 'BB4')
    bb5 = t8_soundness(br, replace(s100, Q=28), 'BB5')
    P(f'    BabyBear^4 lb6 Q27, PoW q24/c16/b24/l8: lambda_IOP {bb4["lam_iop"]} (binding {bb4["binding"]}) '
      f'-> "< 100 at PoW <= 24": {"PASS" if bb4["lam_iop"] < 100 else "FAIL"}')
    P(f'    BabyBear^5 lb6 Q28, same PoW:           lambda_IOP {bb5["lam_iop"]} (binding {bb5["binding"]}) '
      f'-> ">= 100": {"PASS" if bb5["lam_iop"] >= 100 else "FAIL"}')
    js['design_t10_stage0'] = dict(bb4=bb4, bb5=bb5)

    # ---- 2. external configs
    P()
    P('=' * 110)
    P('2. RISC Zero and ZisK: soundcalc model re-implemented (SC), compared with the committed soundcalc reports')
    P('=' * 110)
    js['external'] = {}
    ext = [RISC0_MAIN, RISC0_SUCC, ZISK_FINAL, ZISK_REC2, ZISK_FC]
    for c in ext:
        P(f'  {c.name}  [{c.src}]')
        e = dict()
        for reg in ('UDR', 'JBR'):
            r = sc(c, reg)
            lam = min(r.values())
            fl = {k: math.floor(v) for k, v in r.items()}
            rep = SOUNDCALC_REPORT.get(c.name, {}).get(reg)
            cmp_ = ''
            if rep:
                mism = {k: (fl.get(k), v) for k, v in rep.items() if k != 'total' and k in fl and fl[k] != v}
                if c.name in SC_LOOKUP_REPORT:
                    got = [fl[lk.name] for lk in c.lookups]
                    if got != SC_LOOKUP_REPORT[c.name]:
                        mism['lookups'] = (got, SC_LOOKUP_REPORT[c.name])
                cmp_ = (f'; soundcalc report total {rep["total"]}: ' +
                        ('every cell equal' if not mism and math.floor(lam) == rep['total'] else f'DIFF {mism}'))
            P(f'    SC {reg}: lambda {lam:.2f} (floor {math.floor(lam)}, binding {min(r, key=r.get)}){cmp_}')
            P(f'       {fmt({k: v for k, v in r.items() if not k.startswith(("Conn", "Lookup"))})}')
            e['SC_' + reg] = dict(rounds={k: round(v, 3) for k, v in r.items()}, lam=round(lam, 3),
                                  binding=min(r, key=r.get), report=rep)
        if c is RISC0_MAIN:
            for reg in ('UDR', 'JBR'):
                lgc = {k: math.floor(v) for k, v in sc_fri_legacy(c, reg).items()}
                rep = SOUNDCALC_REPORT[c.name][reg]
                ok = all(rep[k] == v for k, v in lgc.items())
                P(f'    stale-report hypothesis {reg} (pre-fix m / BCIKS20 eps_U): {lgc} -> '
                  f'{"matches every report cell" if ok else "does NOT match"}')
        sw = sc_sweep_m(c)
        P(f'    SC JBR, multiplicity m chosen by us (eta = sqrt(rho)/2m): lambda {sw["lam_iop"]} (m={sw["m"]}, binding {sw["binding"]})')
        e['SC_JBR_best_m'] = sw
        if isinstance(c, ExtFri):
            ms = range(3, 401)
            t8 = best(lambda m: t8_ext_rounds(c, m), ms)
            ud = t8_ext_rounds(c, 3, 'UD')
            hb = best(lambda m: t8_ext_rounds(c, m, hyb=True), ms)
            P(f'    T8 JB  (BCIKS20 7.2/7.4, ADK Thm 2): lambda {t8["lam_iop"]} (m={t8["m"]}, binding {t8["binding"]})')
            P(f'       {fmt({k: v for k, v in t8["rounds"].items() if not k.startswith(("Conn", "Lookup"))})}')
            P(f'    T8 UD  (ADK Thm 3):                   lambda {min(ud.values()):.2f} (binding {min(ud, key=ud.get)}); '
              f'query {ud["query"]:.2f}, batch {ud["batch"]:.2f}')
            P(f'    HYB JB (T8 accounting + BCHKS25 4.2): lambda {hb["lam_iop"]} (m={hb["m"]}, binding {hb["binding"]})')
            P(f'       {fmt({k: v for k, v in hb["rounds"].items() if not k.startswith(("Conn", "Lookup"))})}')
            # PoW the T8 accounting would need at the batching site to reach 128 (best m for that)
            need = None
            for m in ms:
                r = t8_ext_rounds(c, m)
                if min(v for k, v in r.items() if k != 'batch') >= 128:
                    need = dict(m=m, batch_pow=math.ceil(128 - r['batch']), batch_raw=round(r['batch'], 2))
                    break
            if need:
                P(f'    T8 JB: smallest m whose non-batching rounds all reach 128 is m={need["m"]}; its batching round is '
                  f'{need["batch_raw"]} -> {need["batch_pow"]} bits of batching PoW would be needed (the config has {c.gb})')
            else:
                P('    T8 JB: no m in 3..400 brings every non-batching round to 128 (fold rounds also fall short '
                  'when m is large enough for the query round), so no batching PoW alone repairs it')
            msc = sc_m(c.rho, sc_gap(c.rho, log_q(c.fk), c.gap))
            r38 = t8_ext_rounds(c, msc)
            P(f'    T8 JB at soundcalc\'s m={msc}: {fmt({k: v for k, v in r38.items() if not k.startswith(("Conn", "Lookup"))})}')
            e.update(T8_JB=t8, T8_UD={k: round(v, 2) for k, v in ud.items()}, HYB_JB=hb, T8_batch_pow_for_128=need)
        js['external'][c.name] = e
        P()

    # ---- 3. gap decomposition for ZisK Final
    P('=' * 110)
    P('3. Where the ZisK Final gap comes from (batching round, m = 38 = soundcalc\'s m at eta = 1/300)')
    P('=' * 110)
    c = ZISK_FINAL
    lq = log_q('Gl3')
    Dsz = c.N / c.rho
    m = 38
    a0, b1 = p5.A0(m, c.rho, Dsz, lq), p5.B1(m, c.rho, Dsz, lq)
    lin = bchks_lin_J(c.rho, c.N, lq, 1 / 300)
    P(f'  BCIKS20 Thm 7.4 line error A0 = (m+1/2)^7 |D|^2 / (3 rho^1.5 |F|): 2^{a0:.2f};  B1 = 2^{b1:.2f}')
    P(f'  BCHKS25 Thm 4.2 line error ((2m\'^5 + 3m\' gamma rho)|D| / (3 rho^1.5) + m\'/sqrt(rho)) / |F|: 2^{lin:.2f}')
    P(f'  ratio: {lin - ladd(a0, b1):+.2f} bits  (|D| = 2^{lg(Dsz):.0f}: one factor |D| = {lg(Dsz):.0f} bits, '
      f'(m+1/2)^2 / 2 = {lg((m + .5) ** 2 / 2):.1f} bits)')
    P(f'  times (B-1) = 1121 ({lg(1121):.2f} bits), no batching PoW: T8 batch {-(ladd(a0, b1) + lg(1121)):.2f}, '
      f'SC batch {-(lin + lg(1121)):.2f}')
    js['gap_final'] = dict(m=m, A0=a0, B1=b1, bchks_lin=lin)

    if '--zisk-all' in argv:
        P()
        P('=' * 110)
        P('4. Every ZisK circuit in soundcalc\'s zisk.toml: SC JBR (pinned gap), SC JBR best m, T8 JB (BCIKS20), SC UDR')
        P('=' * 110)
        ver, cs = load_toml_circuits(argv[argv.index('--zisk-all') + 1])
        rows = []
        for c in cs:
            if isinstance(c, str):
                P(f'  {c}')
                continue
            j = sc(c, 'JBR')
            u = sc(c, 'UDR')
            jb = sc_sweep_m(c)
            t8 = best(lambda m: t8_ext_rounds(c, m), range(3, 401)) if isinstance(c, ExtFri) else None
            rows.append(dict(name=c.name, sc_jbr=round(min(j.values()), 2), sc_jbr_bind=min(j, key=j.get),
                             sc_jbr_best=jb['lam_iop'], sc_udr=round(min(u.values()), 2),
                             t8_jb=t8['lam_iop'] if t8 else None, t8_bind=t8['binding'] if t8 else None))
        for r in sorted(rows, key=lambda r: r['sc_jbr']):
            P(f"  {r['name']:34} SC JBR {r['sc_jbr']:7.2f} ({r['sc_jbr_bind']:10}) best-m {r['sc_jbr_best']:7.2f}  "
              f"UDR {r['sc_udr']:6.2f}  T8 JB {r['t8_jb'] if r['t8_jb'] is not None else '   n/a'} "
              f"({r['t8_bind'] or 'STIR: no T8 model'})")
        mn = min(rows, key=lambda r: r['sc_jbr'])
        t8rows = [r for r in rows if r['t8_jb'] is not None]
        mt = min(t8rows, key=lambda r: r['t8_jb'])
        P(f'  ZisK {ver}: {len(rows)} circuits; min SC JBR {mn["sc_jbr"]} ({mn["name"]}); '
          f'min T8 JB {mt["t8_jb"]} ({mt["name"]}); min SC UDR {min(r["sc_udr"] for r in rows)}')
        js['zisk_all'] = dict(version=ver, rows=rows)

    with open(os.path.join(HERE, 'params10-output.txt'), 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    with open(os.path.join(HERE, 'params10-output.json'), 'w') as fh:
        json.dump(js, fh, indent=1, default=str)


if __name__ == '__main__':
    main(sys.argv[1:])
