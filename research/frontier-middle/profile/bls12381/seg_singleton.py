import json,sys
which=sys.argv[1]; which_file=which; which=which.replace('-worst','')
d=json.load(open(f'out-{which_file}.json'))
tl=d['timeline']
seg={}; order=[]
def add(k,v):
    if k not in seg: seg[k]=0; order.append(k)
    seg[k]+=v
cur='unlocking (push witnesses)'; ms=0; after=None; seen_vkx=False; n101=0
MS=('millerSingleR','outl67'); MUL=('fp12Mul','outl78','outl80')
tlseg=[]
for x in tl:
    tlseg.append(None)
    n=x['name']
    if x['phase']==0: add('unlocking (push witnesses)',x['cost']); tlseg[-1]='unlocking (push witnesses)'; continue
    if cur=='unlocking (push witnesses)': cur='OP_DEFINE prelude'
    if cur=='Fp12 products + conj' and ms==2 and after in MUL: cur='vk_x MSM (Straus loop + inverse + affine)'
    if cur=='Fp12 products + conj' and ms==4 and (after=='fp12Conj' or (which=='opt' and after=='outl80')): cur='final exp easy part'
    if n!='(top)':
        if cur=='OP_DEFINE prelude': cur='input checks (range, curve, twist)'
        if n in MS:
            ms+=1; cur=['','Miller (-A,B) + fused [|x|]B walk','Miller (alpha,beta)','Miller (vk_x,gamma)','Miller (C,delta)'][ms]
        elif cur.startswith('Miller'):
            if ms==1: cur='G2 subgroup check (psi endpoint)'
            else: cur='Fp12 products + conj'
        elif cur=='final exp easy part' and (n in ('cycSqr','powMinusX') or (n=='outl63' and n101>=2)): cur='final exp hard part'
        if cur=='final exp easy part' and n=='outl101': n101+=1
        after=n
    add(cur,x['cost']); tlseg[-1]=cur
tot=sum(seg.values())
for k in order: print(f'{k:45s} {seg[k]:>14,} {100*seg[k]/tot:6.2f}%')
print('total',f'{tot:,}', 'opCost', f"{d['operationCost']:,}")
json.dump({'segments':seg,'order':order},open(f'seg-{which_file}.json','w'),indent=1)

# code bytes of the main (top-frame) body by first-executing segment
mb={}
for k,v in d['topOff'].items():
    ph=int(k.split(':')[0])
    if ph!=1: continue
    sg=tlseg[v['tl']]; mb[sg]=mb.get(sg,0)+v['len']
lock_len=None
print('main/top-frame executed bytes by segment:', mb, 'sum', sum(mb.values()))
GROUPS={
 'Miller code': ['millerSingleR','line','pointAdd','fp6Mul01','fp2Half','fp2Scale','fp2Neg'],
 'final-exp code': ['powMinusX','cycSqr','fp4Square','fp12Frob2','fp6FrobOdd','fp6FrobEven','fp6MulByFp2','fp12Conj','fp6Neg','fp6Sqr'],
 'vk_x code': ['jacDoubleG1','jacAddAffineG1'],
 'input-check code': ['g1Check'],
 'field tower (shared)': ['P','sqrFp','mulFp','addFp','subFp','negFp','inverseFp','fp2Sqr','fp2Mul','fp2Add','fp2Sub','fp2MulXi','fp6Add','fp6Sub','fp6Mul','fp6MulByV','fp12Mul'],
}
fb={}
for df in d['defines']:
    g=next((k for k,v in GROUPS.items() if df['name'] in v), 'outlined fragments' if df['name'].startswith('outl') else 'other:'+df['name'])
    fb[g]=fb.get(g,0)+df['bodyLen']
print('OP_DEFINE body bytes by group:', fb, 'sum', sum(fb.values()), 'defines', len(d['defines']))
json.dump({'segments':seg,'order':order,'mainBytes':mb,'bodyBytes':fb,'tlseg':tlseg},open(f'seg-{which_file}.json','w'),indent=1)
