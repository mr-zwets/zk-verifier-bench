#!/usr/bin/env python3
"""Tables for README.md from the raw runs.
   analyze.py BCHN_RUN ENGINES_RUN KERNELS_JSON  ->  markdown on stdout
BCHN_RUN: raw/<name>-timing.jsonl + raw/<name>-policy.jsonl (run-bchn.sh); ENGINES_RUN: raw/<name>-{bchd,libauth}-units-*.json
(run-engines.sh); KERNELS_JSON: gen.ts kernels.json (libauth op-cost and metrics per kernel)."""
import json, sys, os, statistics
here = os.path.dirname(os.path.abspath(__file__))
bn, en, kj = sys.argv[1], sys.argv[2], sys.argv[3]
raw = os.path.join(here, 'raw')
K = {k['id']: k for k in json.load(open(kj))}

def jl(p):
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
T = {r['id']: r for r in jl(f'{raw}/{bn}-timing.jsonl') if 'error' not in r}
P = {r['id']: r for r in jl(f'{raw}/{bn}-policy.jsonl')}
E = {}
for eng in ('bchd', 'libauth'):
    for f in ('today', 'txv5-100k', 'txv5-150k', 'txv5-100k-num', 'txv5-150k-num'):
        p = f'{raw}/{en}-{eng}-units-{f}.json'
        if os.path.exists(p):
            for r in json.load(open(p)):
                E[(eng, r['name'])] = r

ORDER = ['msig', 'roll', 'mix-msig-roll', 'mix-msig-hash-roll', 'invoke', 'hash', 'mul1', 'mod1', 'mul32', 'mulbig', 'copy', 'cat']
def bt(i):  # BCHN row -> (us per tx, ns per op-cost, ns per tx byte)
    r = T.get(i)
    if not r or not r.get('verifyStats'): return None
    us = r['nsPerTx'] / 1e3
    return dict(us=us, nsop=r['nsPerOpCost'], nsB=r['nsPerTx'] / r['txBytes'], spread=r['verifyStats']['spreadPct'], K=r['copies'], ok=r['asExpected'],
                op=r['opCostPerTx'], txB=r['txBytes'], unl=r['unlockingBytes'])
def f(x, d=1):
    return '–' if x is None else f'{x:,.{d}f}'

out = []
P_ = out.append
# ---------------------------------------------------------------- table 1: today, BCHN
ref = {i: bt(i) for i in ('l0fhm3', 'ap38fd', 'w57j6w', 'trxhzt')}
P_('### Today\'s limits, stock BCHN 29.1.0 — MEASURED (BCHN)\n')
P_('One input of 10,000 B unlocking per tx, and a 100 KB standard tx of 10 such inputs (9,950 B each). Op-cost is libauth consensus op-cost (hash iterations at 64) of the exact bytes; "fill" is standard op-cost / budget. Verify time is BCHN\'s own "Verify N txins" line, median of 11 `validateblocktemplate` reps of a block of K copies.\n')
P_('| kernel | mode | fill std / cons | µs per 10 KB input | ns / op-cost | ns / unlocking byte | ms per 100 KB tx (10 in) | ns / tx byte | testmempoolaccept (POLICY=1) |')
P_('|---|---|--:|--:|--:|--:|--:|--:|---|')
for g in ORDER:
    for m in ('std', 'cons'):
        i = f'{g}@today-L10000-{m}'; t = bt(i); x = bt(f'{g}@today-L9950-{m}-x10'); k = K.get(i)
        if not k: continue
        pol = P.get(i); pol_s = '–' if not pol else ('allowed' if pol.get('allowed') else f"rejected: {pol.get('rejectReason')}")
        polx = P.get(f'{g}@today-L9950-{m}-x10')
        if polx is not None: pol_s += '; tx: ' + ('allowed' if polx.get('allowed') else f"rejected: {polx.get('rejectReason')}")
        P_(f"| {g} | {m} | {k['fillStd']*100:.1f}% / {k['fillCons']*100:.1f}% | {f(t and t['us'])} | {f(t and t['nsop'],3)} | {f(t and t['us']*1e3/10000)} | {f(x and x['us']/1e3,2)} | {f(x and x['nsB'])} | {pol_s} |")
P_('')
P_('References from the same node (VM-limits benchmark vectors, Track 1):\n')
P_('| vector | what | tx B | µs per tx | ns / op-cost | ns / tx byte |')
P_('|---|---|--:|--:|--:|--:|')
desc = {'l0fhm3': 'packed 1-of-3 bare multisig, 100 kB standard tx (the CHIP\'s worst case)', 'ap38fd': 'max OP_ROLL (standard)', 'w57j6w': 'OP_RIPEMD160 of 10,000 B (nonstandard)', 'trxhzt': 'baseline 2×P2PKH'}
for i, t in ref.items():
    if t: P_(f"| {i} | {desc[i]} | {t['txB']:,} | {f(t['us'])} | {f(t['nsop'],3)} | {f(t['nsB'])} |")
P_('')
# ---------------------------------------------------------------- table 2: sweep within today's limits (BCHN)
P_('### Scaling inside today\'s limits — MEASURED (BCHN)\n')
P_('Standard kernels at 2,500 / 5,000 / 10,000 B unlocking (big items scale with L). A kernel that grows faster than linearly shows a rising ns per op-cost unit.\n')
P_('| kernel | ns/op-cost at 2.5k / 5k / 10k | µs per input at 2.5k / 5k / 10k | µs per input ÷ L, relative to 10k |')
P_('|---|---|---|---|')
for g in ORDER:
    ts = [bt(f'{g}@today-L{L}-std') for L in (2500, 5000, 10000)]
    if not all(ts): continue
    rel = [t['us'] / L / (ts[2]['us'] / 10000) for t, L in zip(ts, (2500, 5000, 10000))]
    P_(f"| {g} | {' / '.join(f(t['nsop'],3) for t in ts)} | {' / '.join(f(t['us']) for t in ts)} | {' / '.join(f(x,2) for x in rel)} |")
P_('')
# ---------------------------------------------------------------- table 3: raised limits
P_('### Raised per-input limits\n')
P_('bchd-fork and libauth: steady-state eval time per input, MEASURED on each engine. BCHN at 100 / 150 KB: EXTRAPOLATED = BCHN µs at 10 KB × (op-cost at L ÷ op-cost at 10 KB) × (bchd ns/op-cost at L ÷ bchd ns/op-cost at 10 KB). "linear" = the same without the bchd rate correction.\n')
P_('| kernel | mode | L | op-cost (cons) | fill std | bchd ms | bchd ns/op | bchd rate ÷ 10k | libauth ms | libauth ns/op | libauth rate ÷ 10k | BCHN ms EXTRAPOLATED (linear) | BCHN ns / unlocking byte |')
P_('|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|')
rows3 = []
for g in ORDER + ['mulwide']:
    for m in ('std', 'cons'):
        base = f'{g}@today-L10000-{m}'; tb = bt(base); kb = K.get(base)
        for prof, L in (('today', 10000), ('txv5-100k', 100000), ('txv5-150k', 150000), ('txv5-100k+num', 100000), ('txv5-150k+num', 150000)):
            i = f'{g}@{prof}-L{L}-{m}'; k = K.get(i)
            if not k: continue
            bd, la = E.get(('bchd', i)), E.get(('libauth', i))
            bd0, la0 = E.get(('bchd', base)), E.get(('libauth', base))
            bms = bd and bd['evalMedianNs'] / 1e6; bns = bd and bd['evalMedianNs'] / k['opCons']
            lms = la and la['evalMedianNs'] / 1e6; lns = la and la['evalMedianNs'] / k['opCons']
            bratio = bd and bd0 and (bd['evalMedianNs'] / k['opCons']) / (bd0['evalMedianNs'] / kb['opCons'])
            lratio = la and la0 and (la['evalMedianNs'] / k['opCons']) / (la0['evalMedianNs'] / kb['opCons'])
            ext = lin = None
            if tb and kb:
                lin = tb['us'] / 1e3 * k['opCons'] / kb['opCons']
                ext = lin * bratio if bratio else None
            rows3.append(dict(g=g, m=m, prof=prof, L=L, ext=ext, lin=lin, tb=tb))
            P_(f"| {g} | {m} | {prof} | {k['opCons']:,} | {k['fillStd']*100:.1f}% | {f(bms,2)} | {f(bns,3)} | {f(bratio,2)} | {f(lms,1)} | {f(lns,2)} | {f(lratio,2)} | {f(ext,2)} ({f(lin,2)}) | {f(ext and ext*1e6/L)} |")
P_('')
json.dump(rows3, open(os.path.join(raw, f'{en}-extrapolated.json'), 'w'), indent=1)
print('\n'.join(out))

# ---------------------------------------------------------------- table 4: BCHN-only extrapolation from the in-limit sweep
print('### BCHN-only extrapolation from the 5k→10k sweep — EXTRAPOLATED\n')
print('Per-input time on BCHN is linear in L between 5,000 and 10,000 B: t(L) = a + b·L. The loop body of these kernels does not depend on L (stack depth stays ≤ 1,000; operands are fixed), so the fit extends to raised limits unless a per-input limit other than the budget binds (msig at 150 KB: the 3,000 sigchecks/tx cap; use the bchd-corrected value there).\n')
print('| kernel | b (ns per unlocking byte) | a (µs) | 100 KB input, ms | 150 KB input, ms |')
print('|---|--:|--:|--:|--:|')
for g in ORDER:
    t = {L: bt(f'{g}@today-L{L}-std') for L in (5000, 10000)}
    if not all(t.values()): continue
    b = (t[10000]['us'] - t[5000]['us']) / 5000; a = t[10000]['us'] - b * 10000
    print(f"| {g} | {b*1e3:,.0f} | {a:,.0f} | {(a+b*1e5)/1e3:,.1f} | {(a+b*1.5e5)/1e3:,.1f}{' (cap binds: see above)' if g=='msig' else ''} |")
print('')
