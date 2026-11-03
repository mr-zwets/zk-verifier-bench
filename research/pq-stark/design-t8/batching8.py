#!/usr/bin/env python3
"""Batching-round figures for research/pq-stark/BATCHING-PROOF.md (Track 8, powers-of-one-challenge batching).

Recomputes, from the published theorem statements and nothing else, the batching-round error of Plonky3's
powers batching for the as-built Track 8 shapes, under four accountings:

  track8   sum_h (t_h - 1)(A0(N_max) + B1(N_max))                  params8.term_batch (the figure Track 8 reports)
  thm72    max_h (t_h - 1) max(A0(N_h), B1(N_h))                   BCIKS20 rev.3 Thm 7.2, mu = 1, M = 1, RBR max
  indep    A0(N_max)                                               ADK Thm 2 eps_3 (independent coefficients; BCIKS Thm 7.4)
  bchks    max_h (t_h - 1) * a_BCHKS(N_h) / q                      BCHKS25 Thm 4.2 at the same proximity (sensitivity)

plus the M1 fold1 and M2 roll-in fold1 terms under Track 8's charge, under Thm 7.2 read exactly, and under
BCHKS25 Cor. 4.4 (sensitivity). Standard library only; cross-checks A0/B1 against ../soundness/params5.py.

Run:  python3 batching8.py            (writes batching8-output.json next to this file)
"""
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'soundness'))
import params5 as p5  # noqa: E402

lg = math.log2
P = 2 ** 64 - 2 ** 32 + 1          # Goldilocks
LQ = 3 * lg(P)                     # q = p^3 (cubic trinomial extension); log2 q = 191.99999999990...
LOG_BLOWUP = 9                     # Z128 / Z128-g: rho = 2^-9
RHO = 2.0 ** -LOG_BLOWUP
M_JB = 5                           # params8 optimum for both M1 and M2 (asbuilt8-output.txt)
BATCH_POW = 20
COMMIT_POW = {'M1': 2, 'M2': 3}

# Ladder lengths t_h per LDE log-height, from the as-built shapes (SOUNDNESS-T8 Lemma 3; bytes8.t_by_height).
SHAPES = {
    'M1': {20: 94},
    'M2': {20: 127, 17: 85},
}
# First fold round: (log arity, log height in, log height out, roll-in?)
FOLD1 = {'M1': (3, 20, 17, False), 'M2': (3, 20, 17, True)}


def A0(N):
    """log2 of (m+1/2)^7 N^2 / (3 rho^{3/2} q): BCIKS Thm 7.2 first term per unit of curve degree."""
    return 7 * lg(M_JB + 0.5) + 2 * lg(N) - lg(3) - 1.5 * lg(RHO) - LQ


def B1(Nw):
    """log2 of (2m+1)(Nw + 1) / (sqrt(rho) q) where Nw = M*n (= |D0| in FRI rounds, = n in the batching round)."""
    return lg(2 * M_JB + 1) + lg(Nw + 1) - 0.5 * lg(RHO) - LQ


def ladd(*xs):
    mx = max(xs)
    return mx + lg(sum(2 ** (x - mx) for x in xs))


def bchks_a(n, K, gamma, printed_m=True):
    """log2 of BCHKS25 Thm 4.2's per-unit-degree bound (the bracket, before the factor M):
       (2(m+1/2)^5 + 3(m+1/2) gamma rho') / (3 rho'^{3/2}) * n + (m+1/2)/sqrt(rho'),
    with rho' = (K-1)/n (dimension K = k+1, 'slightly reduced rate') and
    m = max(ceil(sqrt(rho')/eta), 3) as printed in Thm 4.2 (printed_m) or ceil(sqrt(rho')/(2 eta)) as in Thm 1.5,
    eta = 1 - sqrt(rho') - gamma. Returns (log2 bound, m used, eta)."""
    rp = (K - 1) / n
    eta = 1 - math.sqrt(rp) - gamma
    assert eta > 0
    mm = max(math.ceil(math.sqrt(rp) / (eta if printed_m else 2 * eta)), 3)
    val = (2 * (mm + 0.5) ** 5 + 3 * (mm + 0.5) * gamma * rp) / (3 * rp ** 1.5) * n + (mm + 0.5) / math.sqrt(rp)
    return lg(val), mm, eta


def main():
    out = {'q_log2': LQ, 'rho': RHO, 'm': M_JB, 'batch_pow': BATCH_POW,
           'alpha0': math.sqrt(RHO) * (1 + 1 / (2 * M_JB))}
    # cross-check against params5 (Track 5 calculator, used unchanged by Track 8)
    for N in (2 ** 17, 2 ** 20):
        assert abs(A0(N) - p5.A0(M_JB, RHO, N, LQ)) < 1e-9
        assert abs(B1(N) - p5.B1(M_JB, RHO, N, LQ)) < 1e-9
    gamma = 1 - out['alpha0']     # the proximity used through the whole FRI chain (alpha0 = sqrt(rho)(1 + 1/2m))
    for nm, th in SHAPES.items():
        top = max(th)
        Ntop = 2 ** top
        r = {'t_h': th}
        # Track 8's charge (params8.term_batch default): sum over heights, every height at N_max, A0 + B1
        tr = lg(sum((t - 1) * (2 ** A0(Ntop) + 2 ** B1(Ntop)) for t in th.values()))
        r['track8_raw'] = -tr
        r['track8'] = -tr + BATCH_POW
        # Thm 7.2 read exactly (mu = 1, M = 1, own domain N_h), RBR error = max over heights (sec. 4 of the doc)
        per_h = {h: lg(t - 1) + max(A0(2 ** h), B1(2 ** h)) for h, t in th.items()}
        r['thm72_per_height_raw'] = {h: -v for h, v in per_h.items()}
        r['thm72_max_raw'] = -max(per_h.values())
        r['thm72_sum_raw'] = -ladd(*per_h.values())
        r['thm72_max'] = r['thm72_max_raw'] + BATCH_POW
        # independent coefficients (ADK Thm 2 eps_3 = A0 alone; Track 8 reports A0 + B1 per height: 142.87 / 141.87)
        r['indep_adk_eps3'] = -A0(Ntop) + BATCH_POW
        r['indep_track8'] = -lg(len(th) * (2 ** A0(Ntop) + 2 ** B1(Ntop))) + BATCH_POW
        r['powers_cost_bits'] = r['indep_track8'] - r['track8']
        # BCHKS25 Thm 4.2 at the same gamma (sensitivity only)
        for printed in (True, False):
            per = {}
            for h, t in th.items():
                n = 2 ** h
                K = n >> LOG_BLOWUP
                a, mm, eta = bchks_a(n, K, gamma, printed)
                per[h] = dict(log2_err=lg(t - 1) + a - LQ, m=mm, eta=eta)
            key = 'bchks_thm42_printed_m' if printed else 'bchks_thm42_thm15_m'
            r[key] = dict(per_height={h: round(-v['log2_err'], 2) for h, v in per.items()},
                          m={h: v['m'] for h, v in per.items()},
                          raw=round(-max(v['log2_err'] for v in per.values()), 2),
                          with_pow=round(-max(v['log2_err'] for v in per.values()) + BATCH_POW, 2))
        # fold1
        la, hin, hout, roll = FOLD1[nm]
        a = 2 ** la
        coef = a if roll else a - 1
        t8 = -ladd(lg(coef) + A0(Ntop) + 2 * (hout - top), lg(a) + B1(Ntop))
        ex = -(lg(coef) + max(A0(2 ** hout), B1(Ntop)))     # Thm 7.2: l * max(A0(n_out), B(M n = |D0|))
        n = 2 ** hout
        bk, mm, _ = bchks_a(n, n >> LOG_BLOWUP, gamma, True)
        r['fold1'] = dict(arity=a, curve_degree=coef, rollin=roll,
                          track8=round(t8 + COMMIT_POW[nm], 2), track8_raw=round(t8, 2),
                          thm72_exact=round(ex + COMMIT_POW[nm], 2),
                          bchks_cor44=round(-(lg(coef) + bk - LQ) + COMMIT_POW[nm], 2), bchks_m=mm)
        r['query'] = round(-24 * lg(math.sqrt(RHO) * (1 + 1 / (2 * M_JB))) + 24, 2)
        out[nm] = {k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()}
    # unique-decoding comparison for M1 (why Track 8 needs the Johnson regime: the query round)
    rho_plus = RHO  # (k+2)/N differs by 2^-19; irrelevant at this precision
    out['M1_unique_decoding'] = dict(batch_raw=round(-(lg(93) + 20 - LQ), 2),
                                     query_with_pow=round(-24 * lg((1 + rho_plus) / 2) + 24, 2))
    path = os.path.join(HERE, 'batching8-output.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
