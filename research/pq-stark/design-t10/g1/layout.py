# Re-implements pil2-proofman verifier/src/layout.rs (v1.4.0-alpha, 27b2fc2) segment math in Python.
import math, sys, struct
def levels(nb, ar, llv):
    if nb == 0: return 0
    return max(0, math.ceil(nb / math.log2(ar)) - llv)
def fri_layout(n_stages, n_const, n_evals, nbe, num_vals, ar, llv, steps, nq):
    ll = 0 if llv == 0 else ar**llv*4
    sw = (ar-1)*4
    segs = [('roots', 4*(n_stages+1)), ('evals', 3*n_evals)]
    names = ['const'] + ['cm%d' % (i+1) for i in range(len(num_vals))]
    for nm, w in zip(names, [n_const]+num_vals):
        lv = levels(nbe, ar, llv)
        segs.append((nm+'_vals', nq*w)); segs.append((nm+'_paths', nq*lv*sw)); segs.append((nm+'_lastlevel', ll))
    segs.append(('fri_roots', 4*(len(steps)-1)))
    for i in range(1, len(steps)):
        lv = levels(steps[i], ar, llv)
        segs.append(('fri%d_vals' % i, nq*(1 << (steps[i-1]-steps[i]))*3)); segs.append(('fri%d_paths' % i, nq*lv*sw)); segs.append(('fri%d_lastlevel' % i, ll))
    segs.append(('final_pol', 3*(1 << steps[-1]))); segs.append(('nonce', 1))
    return segs
def stir_layout(n_stages, n_const, n_evals, nbe, num_vals, ar, llv, ff, logdeg, logdom, nq):
    ll = 0 if llv == 0 else ar**llv*4
    sw = (ar-1)*4
    segs = [('roots', 4*(n_stages+1)), ('evals', 3*n_evals)]
    names = ['const'] + ['cm%d' % (i+1) for i in range(len(num_vals))]
    for nm, w in zip(names, [n_const]+num_vals):
        lv = levels(nbe, ar, llv)
        segs.append((nm+'_vals', nq[0]*w)); segs.append((nm+'_paths', nq[0]*lv*sw)); segs.append((nm+'_lastlevel', ll))
    m = len(ff)
    segs.append(('stir_roots', 4*m))
    for i in range(m):
        k = ff[i]; lb = logdom[i]-k; lv = levels(lb, ar, llv)
        segs.append(('stir%d_vals' % i, nq[i]*(1 << k)*3)); segs.append(('stir%d_paths' % i, nq[i]*lv*sw)); segs.append(('stir%d_lastlevel' % i, ll))
    hints = sum(2*(1+nq[i-1])*3 for i in range(1, m))
    segs.append(('stir_tail(betas,final_pol,nonces,ans,shake)', 3*(m-1) + 3*(1 << logdeg[m]) + m + hints))
    return segs
FINAL = fri_layout(2, 47, 130, 20, [48, 12, 21], 4, 2, [20, 16, 12, 8, 5], 54)
COMP = stir_layout(2, 47, 130, 19, [48, 12, 21], 2, 0, [3, 4], [15, 12, 8], [19, 18, 17], [54, 36])
if __name__ == '__main__':
    for name, segs in (('vadcop_final (FRI)', FINAL), ('vadcop_final_compressed (STIR, flat upper bound)', COMP)):
        tot = sum(w for _, w in segs)
        print('==', name, 'words', tot, 'bytes', tot*8)
        off = 0
        for n, w in segs:
            print('  %-48s off %7d  words %7d  bytes %8d' % (n, off, w, w*8)); off += w
