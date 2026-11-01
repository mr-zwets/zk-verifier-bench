import math
# Poseidon2-Gl-8 op-cost model (VM-limits: 100/instr + pushed bytes + a_len*b_len for MUL/MOD; SHA 192/block std)
I=100
def mulmod(a=8,b=8): return (I+a*b+(a+b)) + (I+(a+b)*8+8) + 2*(I+8)  # mul, mod, two fetches
sbox_full = 4*mulmod()             # x^7 strict
sbox_lazy = (I+64+16)+(I+128+24)+(I+576+48)+(I+384+56)+(I+56*8+8)+3*(I+8)
add = I+16+2*(I+8)
P = dict(sbox=86, rc_add=86, int_layers=22, ext_layers=9)
def perm(sb):
    s = P['sbox']*sb
    rc = P['rc_add']*(add+I+8)
    ext = P['ext_layers']*(40*add + 8*(I+16*8+8))
    inte = P['int_layers']*(8*mulmod()+15*add)
    raw = s+rc+ext+inte
    return raw
for nm,sb in [('strict',sbox_full),('lazy',sbox_lazy)]:
    r=perm(sb); print(nm, 'raw %.0fk'%(r/1e3), 'x1.3 stack %.0fk'%(r*1.3/1e3))
budget10k=(41+10000)*800; print('budget per 10KB input %.2fM'%(budget10k/1e6))
for lo,hi in [(0.45e6,0.9e6)]:
    for k in [0,2,4,5]:
        perms=(2**k-1)+(30-k)
        print('flush k=%d perms=%d op %.1f-%.1fM inputs %.1f-%.1f per-deposit perms %.1f'%(k,perms,perms*lo/1e6,perms*hi/1e6,perms*lo/budget10k,perms*hi/budget10k,perms/2**k))
# SMT nullifier path bytes
for n in [2**10,2**15,2**20,2**24]:
    s=math.log2(n)+1.33; print('n=2^%d siblings~%.1f bytes~%d'%(math.log2(n),s,8+32*s))
sha=I+2*192+32+ 4*(I+8)
print('SMT op per level (2 hashes + ~12 ops) ~%d, depth64 ~%.0fk'%(2*sha+12*I, 64*(2*sha+12*I)/1e3))
