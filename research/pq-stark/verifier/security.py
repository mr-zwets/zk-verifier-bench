#!/usr/bin/env python3
"""Security level of every prover vector set under the Soundness phase's bound (../soundness/params5.py, P3 model:
ADK/BCIKS per-round errors, BCIKS Thm 7.2 batching with powers (our adaptation, not a published statement), Fiat-Shamir
via Block et al. Cor. 5), for the exact FriParameters of each vector and each AIR's shape (width, constraint count,
constraint degree). JB = Johnson-bound list decoding (best m in 3..24), UD = unique decoding. lambda = min(lambda_IOP,
digest bits 4h, the usual birthday convention); lambda_strict_digest uses the strict Cor. 5 reading (4h - 0.79).
usage: python3 security.py <prover vectors dir> > security.json"""
import glob, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'soundness'))
import params5 as p5

AIR = {'mimc': dict(width=3, num_constraints=5, max_deg=3), 'fib': dict(width=2, num_constraints=5, max_deg=2)}
out = {}
for f in sorted(glob.glob(os.path.join(sys.argv[1], '*-0.json'))):
    v = json.load(open(f)); s = v['set']
    res = {}
    for reg in ['JB', 'UD']:
        best = None
        for m in (range(3, 25) if reg == 'JB' else [3]):
            c = p5.P3(name=s['name'], regime=reg, e=s['ext'], log_n=v['log_n'], log_blowup=s['log_blowup'], max_log_arity=s['max_log_arity'],
                      log_final_poly_len=s['log_final_poly_len'], num_queries=s['num_queries'], query_pow=s['query_pow_bits'],
                      commit_pow=s['commit_pow_bits'], batch_pow=s['batch_pow_bits'], m=m, zk=bool(s['zk']),
                      rand_cols=s['num_random_codewords'] if s['zk'] else 0, h=s.get('digest', 32), **AIR[v['air']])
            r = p5.p3_soundness(c)
            if best is None or r['lam'] > best[0]: best = (r['lam'], m, r)
        res[reg] = {'lambda': best[0], 'lambda_iop': best[2]['lam_iop'], 'lambda_strict_digest': best[2]['lam_strict'], 'binding': best[2]['binding'], 'm': best[1], 'rounds': best[2]['rounds']}
    est = v['plonky3_security_estimates']
    jb = res['JB']['lambda']
    target = 128 if est['conjectured_bits'] >= 128 and not s['name'].startswith(('P100', 'S100')) else 100
    if s['name'].startswith('C'):
        label = f"conjectured {est['conjectured_bits']} only (proven JB {jb})"
    elif jb >= target - 0.005:
        label = f"{jb} JB (proven, Soundness bound)"
    else:
        label = f"{jb} JB (below {target}; Plonky3 LDR estimator {est['proven_ldr_bits']})"
    out[os.path.basename(f)] = {**res, 'plonky3': est, 'target': target, 'label': label}
print(json.dumps(out, indent=1))
