import json
def J(f): return json.load(open(f))
def fam(d,par,kids):
    return sum(v for k,v in d['edgeIncl'].items() if k.startswith(par+' > ') and k.split(' > ')[1] in kids)
for w in ['plain','opt']:
    d=J(f'out-{w}.json'); s=J(f'seg-{w}.json'); sw=J(f'seg-{w}-worst.json')
    e=d['edgeIncl']; inc=d['incl']; c=d['calls']
    print('=====',w,'opCost',f"{d['operationCost']:,}",'BCHN+',sum(x['bodyLen'] for x in d['defines']))
    M=inc['millerSingleR']
    sq=e.get('millerSingleR > fp12Mul',0); ln=e.get('millerSingleR > line',0); pa=e.get('millerSingleR > pointAdd',0); slf=e.get('millerSingleR > (self)',0)
    pd=M-sq-ln-pa-slf
    print(f' Miller total {M:,} = 4 pairs; f-squaring {sq:,} ({sq/256:,.0f}/iter); line eval {ln:,} ({ln/276:,.0f}/line, 276 lines); point dbl (inlined, fp2 children+outlined) {pd:,} ({pd/256:,.0f}/dbl); point add {pa:,} ({pa/20:,.0f}/add); loop self {slf:,}')
    dbl=(sq+pd)/256+ln/276+slf/256; add=pa/20+ln/276
    print(f'  per pair: {M/4:,.0f}; doubling step {dbl:,.0f}; addition step {add:,.0f}; 64 dbl + 5 add')
    pm=inc['powMinusX']; cs=inc['cycSqr']
    print(f' final exp: powMinusX x5 {pm:,} ({pm/5:,.0f} each); cycSqr {c.get("cycSqr")} calls {cs:,} ({cs/c["cycSqr"]:,.0f}); fp12Mul {c.get("fp12Mul")} calls {inc["fp12Mul"]:,} ({inc["fp12Mul"]/c["fp12Mul"]:,.0f}); inverseFp {inc["inverseFp"]:,}/{c["inverseFp"]}')
    for k in ['mulFp','addFp','subFp','P','sqrFp','negFp','inverseFp']:
        print(f'  leaf {k}: excl {d["excl"].get(k,0):,} calls {c.get(k)} avg {d["excl"].get(k,0)/max(1,c.get(k,1)):,.0f}')
    leaf=sum(d['excl'].get(k,0) for k in ['mulFp','addFp','subFp','P','sqrFp','negFp','inverseFp'])
    print(f'  leaf Fp total {leaf:,} ({100*leaf/d["operationCost"]:.1f}%); non-leaf (stack glue, invokes, loop) {d["operationCost"]-leaf:,}')
    print(' vkx worst', f"{sw['segments']['vk_x MSM (Straus loop + inverse + affine)']:,}", 'small', f"{s['segments']['vk_x MSM (Straus loop + inverse + affine)']:,}")
    print(' jac calls', c.get('jacDoubleG1'), c.get('jacAddAffineG1'), 'jacDbl avg', f"{inc['jacDoubleG1']/c['jacDoubleG1']:,.0f}", 'jacAdd avg', f"{inc['jacAddAffineG1']/c['jacAddAffineG1']:,.0f}")
dw=J('out-plain-worst.json'); print(' plain worst jac calls', dw['calls'].get('jacDoubleG1'), dw['calls'].get('jacAddAffineG1'), f"{dw['incl']['jacDoubleG1']:,}", f"{dw['incl']['jacAddAffineG1']:,}")
