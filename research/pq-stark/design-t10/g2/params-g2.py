#!/usr/bin/env python3
"""Track 10 gate G2: choose the shape-twin parameter set with params10 (T8 accounting, JB) and bytes8.

Shape twin (stand-in for the ZisK-bridge outer proof, per G0/G1):
  2T  P2   2^18 rows, M1's Poseidon2-Gl-8 AIR lengthened (17 cols, 53 constraints, deg 4, 12 publics, 11 periodic)
      MA   2^16 rows, dummy Gl^3 mul-add d = a*b + c (12 cols, 3 constraints, deg 2)
  1T  one 2^18-row table holding both (29 cols, 56 constraints, deg 4): the only shape the existing a' generator takes
Search: log_blowup, final poly length, Q; PoW per site <= 24; lambda_IOP >= 128 under T8 (BCIKS20, powers adaptation).
Prints candidates sorted by modelled a' bytes (full paths, cap 5) and b2 bytes (multiproof, cap 0); also SC/HYB.
Run from a scratch copy (imports params10 read-only; writes nothing).  usage: python3 params-g2.py [--zk 0|1]
"""
import math, os, sys
from dataclasses import replace
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import params10 as P10   # noqa: E402
b8 = P10.b8
T = b8.Table

def shapes():
    p2 = T('P2', 18, 17, main_next=True, num_constraints=53, max_deg=4, public_values=12, periodic=11)
    ma = T('MA', 16, 12, main_next=False, num_constraints=3, max_deg=2)
    one = T('P2MA', 18, 29, main_next=True, num_constraints=56, max_deg=4, public_values=12, periodic=11)
    return {'2T': [p2, ma], '1T': [one]}

def run(zk=True, target=128.0):
    rows = []
    for nm, tabs in shapes().items():
        for lb in range(3, 9):
            for lf in (3, 5, 8):
                for cap in (0, 5):
                    base = b8.FriSet(f'{nm}', log_blowup=lb, log_final_poly_len=lf, Q=1, query_pow=24, commit_pow=0,
                                     batch_pow=0, zk=zk, cap=cap)
                    # smallest Q at query PoW 24 reaching the target; then the smallest batch/commit PoW
                    for Q in range(10, 120):
                        s = replace(base, Q=Q, batch_pow=24, commit_pow=24)
                        r = P10.t8_soundness(tabs, s)
                        if r['lam_iop'] >= target:
                            break
                    else:
                        continue
                    s = replace(base, Q=Q, batch_pow=24, commit_pow=24)
                    for bp in range(0, 25):
                        if P10.t8_soundness(tabs, replace(s, batch_pow=bp))['lam_iop'] >= target: break
                    s = replace(s, batch_pow=bp)
                    for cp in range(0, 25):
                        if P10.t8_soundness(tabs, replace(s, commit_pow=cp))['lam_iop'] >= target: break
                    s = replace(s, commit_pow=cp)
                    ck = b8.checks(tabs, s)
                    if not all(v['ok'] for k, v in ck.items() if k not in ('ok', 'arity_grid')):
                        continue
                    t8 = P10.t8_soundness(tabs, s)
                    hy = P10.t8_soundness(tabs, s, hyb=True)
                    pb = b8.proof_bytes(tabs, s)
                    fq = b8.per_query_full_path_bytes(tabs, s)
                    lde = max(b8.lde_log_height(t, s) for t in tabs)
                    # rough prover memory: committed base columns x LDE height x 8 B (+ digest layers)
                    cols = sum(m.width * 2 ** m.log_h for _, _, ms in b8.commitment_rounds(tabs, s) for m in ms)
                    rows.append(dict(shape=nm, lb=lb, lf=lf, cap=cap, Q=Q, bpow=bp, cpow=cp, lam=t8['lam_iop'], m=t8['m'],
                                     bind=t8['binding'], hyb=hy['lam_iop'], proof=pb['total'], aprime_q=fq['total'],
                                     aprime=fq['total'] * Q, lde=lde, ldeGB=round(cols * 8 / 2**30, 1),
                                     sched=pb['schedule']))
    return rows

if __name__ == '__main__':
    zk = '--zk' not in sys.argv or sys.argv[sys.argv.index('--zk') + 1] == '1'
    rows = run(zk)
    for nm in ('2T', '1T'):
        for cap in (0, 5):
            print(f'=== shape {nm} zk={int(zk)} cap {cap}')
            for r in sorted([r for r in rows if r['shape'] == nm and r['cap'] == cap], key=lambda r: r['proof']):
                print(f"lb {r['lb']} lf {r['lf']} Q {r['Q']:3d} bPoW {r['bpow']:2d} cPoW {r['cpow']:2d} | T8 {r['lam']:.2f} ({r['bind']}, m {r['m']}) HYB {r['hyb']:.2f} | "
                      f"proof {r['proof']:7d} B  a'-full-paths {r['aprime']:7d} B ({r['aprime_q']} B/q) | LDE 2^{r['lde']} committed {r['ldeGB']} GB | sched {r['sched']}")
