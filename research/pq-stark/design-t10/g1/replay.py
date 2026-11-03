# Independent Python replay of the ZisK v1.4.0-alpha Poseidon2 vadcop_final (FRI) proof:
# parse with layout.py offsets, replay the Poseidon2-16 transcript (pil2 fields/src/transcript.rs,
# verifier/src/replay.rs), check grinding (Poseidon2-8), every Merkle path of every query for all
# 4 stage trees + 4 FRI trees, the last-level partial trees against the roots (root_c == release vk),
# and the FRI fold-consistency/DEEP checks are left to the Rust verifier.
import sys, struct, math, time
sys.path.insert(0, sys.argv[1])
import p2, layout
P = p2.P
C = p2.parse(sys.argv[2])
fix = open(sys.argv[3], 'rb').read()
VK = [7235627588029747190, 4964294244843319518, 15944021041411876293, 9165814394267558940]  # keys.rs VADCOP_FINAL_VK_POSEIDON2
w = list(struct.unpack('<%dQ' % (len(fix)//8), fix))
minimal, npub = w[0], w[1]
pubs = w[2:2+npub]; body = w[2+npub:2+npub+46171]; tail = w[2+npub+46171:]
assert minimal == 0 and npub == 69 and len(tail) == 5 and tail[:4] == VK and tail[4] == 1, (minimal, npub, tail)
off = {}; o = 0
for n, sz in layout.FINAL: off[n] = (o, sz); o += sz
def seg(n): a, s = off[n]; return body[a:a+s]
perms = {16: 0, 8: 0}
def perm(s):
    perms[len(s)] += 1; return p2.perm([x % P for x in s], C[len(s)])
class T:
    RATE, W = 12, 16
    def __init__(s): s.state=[0]*16; s.pending=[]; s.out=[0]*16; s.oc=0
    def upd(s):
        inp = s.pending + [0]*(12-len(s.pending)) + s.state[:4]
        s.state = perm(inp); s.out = s.state; s.oc = 16; s.pending = []
    def put(s, xs):
        for x in xs:
            s.pending.append(x % P); s.oc = 0
            if len(s.pending) == 12: s.upd()
    def state4(s):
        if s.pending: s.upd()
        return s.state[:4]
    def get1(s):
        if s.oc == 0: s.upd()
        v = s.out[(16 - s.oc) % 16]; s.oc -= 1; return v
    def get3(s): return [s.get1() for _ in range(3)]
    def perms_idx(s, n, nb):
        nf = (n*nb - 1)//63 + 1; f = [s.get1() for _ in range(nf)]; out = []; cf = cb = 0
        for i in range(n):
            a = 0
            for j in range(nb):
                if (f[cf] >> cb) & 1: a += 1 << j
                cb += 1
                if cb == 63: cb = 0; cf += 1
            out.append(a)
        return out
def committed(t, vals):
    inner = T(); inner.put(vals); t.put(inner.state4())
roots = [seg('roots')[4*i:4*i+4] for i in range(3)]
evals = seg('evals')
t = T(); t.put(VK); committed(t, pubs); t.put(roots[0]); c0 = t.get3(); c1 = t.get3(); t.put(roots[1]); c2 = t.get3(); t.put(roots[2]); c3 = t.get3()
committed(t, evals); c4 = t.get3(); c5 = t.get3()
steps = [20, 16, 12, 8, 5]; froots = [seg('fri_roots')[4*i:4*i+4] for i in range(4)]
for r in froots: t.put(r); t.get3()
committed(t, seg('final_pol'))
q = t.get3(); nonce = seg('nonce')[0]
tq = T(); tq.put(q); tq.put([nonce]); queries = tq.perms_idx(54, 20)
pw = perm([q[0], q[1], q[2], nonce, 0, 0, 0, 0])[0]
pow_ok = pw < (1 << (64-22))
def lin(v):
    st = [0]*16; n = len(v); rem = n
    while rem > 0:
        if rem != n: st[12:16] = st[0:4]
        k = min(rem, 12); st[0:k] = v[n-rem:n-rem+k]; st[k:12] = [0]*(12-k)
        st = perm(st); rem -= k
    return st[:4]
def path(leafv, mp, idx, levels):
    v = lin(leafv)
    for L in range(levels):
        lvl = mp[L*12:(L+1)*12]; ci = idx % 4; idx //= 4; inp = []; p = 0
        for i in range(4):
            if i == ci: inp += v
            else: inp += lvl[4*p:4*p+4]; p += 1
        v = perm(inp)[:4]
    return v, idx
def partial_root(nodes):
    while len(nodes) > 4:
        nodes = [x for i in range(0, len(nodes), 16) for x in perm(nodes[i:i+16])[:4]]
    return perm(nodes + [0]*(16-len(nodes)))[:4] if len(nodes) > 4 else perm(nodes)[:4]
def ptree(nodes):
    # pil2 fields/src/merkle.rs partial_merkle_tree, arity 4, zero-padding each level
    while len(nodes) > 4:
        if len(nodes) % 16: nodes = nodes + [0]*(16 - len(nodes) % 16)
        nodes = [x for i in range(0, len(nodes), 16) for x in perm(nodes[i:i+16])[:4]]
    return nodes
ok_paths = 0; bad = 0
trees = [('const', 47, VK), ('cm1', 48, roots[0]), ('cm2', 12, roots[1]), ('cm3', 21, roots[2])]
for name, width, root in trees:
    vals = seg(name+'_vals'); mps = seg(name+'_paths'); ll = seg(name+'_lastlevel'); lv = 8
    for qi, qx in enumerate(queries):
        v, rest = path(vals[qi*width:(qi+1)*width], mps[qi*lv*12:(qi+1)*lv*12], qx, lv)
        if v == ll[rest*4:rest*4+4]: ok_paths += 1
        else: bad += 1
    rr = perm(ll[:16])[:4], perm(ll[16:32])[:4], perm(ll[32:48])[:4], perm(ll[48:64])[:4]
    r = perm(sum(rr, []))[:4]
    print('%-6s last-level root == %s: %s' % (name, 'vk' if name == 'const' else 'proof root', r == root))
for i in range(1, 5):
    width = (1 << (steps[i-1]-steps[i]))*3; lv = math.ceil(steps[i]/2) - 2
    vals = seg('fri%d_vals' % i); mps = seg('fri%d_paths' % i); ll = seg('fri%d_lastlevel' % i)
    for qi, qx in enumerate(queries):
        idx = qx % (1 << steps[i])
        v, rest = path(vals[qi*width:(qi+1)*width], mps[qi*lv*12:(qi+1)*lv*12], idx, lv)
        if v == ll[rest*4:rest*4+4]: ok_paths += 1
        else: bad += 1
    nn = 1 << steps[i]
    while nn > 16: nn = -(-nn // 4)
    r = ptree(ll[:4*nn])
    print('fri%d   last-level root == proof root: %s' % (i, r == froots[i-1]))
print('publics[0] (leaf flag) =', pubs[0], ' program_vk =', pubs[1:5], ' out0 =', pubs[5])
print('grinding ok (22 bits):', pow_ok, ' query[0..4] =', queries[:4])
print('merkle paths ok %d, bad %d (expected %d)' % (ok_paths, bad, 54*8))
print('Poseidon2 permutations used by this replay: width16 %d, width8 %d' % (perms[16], perms[8]))
