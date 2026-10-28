import json,sys
def cls(op):
    if op<=0x60: return 'push'
    if op in (0x89,0x8a): return 'define/invoke'
    if 0x61<=op<=0x6a: return 'control'
    if 0x6b<=op<=0x7d: return 'stack'
    if 0x7e<=op<=0x88: return 'bytes'
    if op in (0x95,0x96,0x97): return 'mul/div/mod'
    if 0x8b<=op<=0xa5: return 'add/sub/cmp'
    if 0xa6<=op<=0xaf: return 'hash'
    return 'introspection/other'
def summarize(opTot):
    out={}
    for k,(c,n) in opTot.items():
        cl=cls(int(k,16)); o=out.setdefault(cl,[0,0]); o[0]+=c; o[1]+=n
    return out
res={}
for f in sys.argv[1:]:
    d=json.load(open(f))
    if 'inputs' in d:
        agg={}
        for i in d['inputs']:
            for k,v in summarize(i['opTot']).items(): a=agg.setdefault(k,[0,0]); a[0]+=v[0]; a[1]+=v[1]
    else: agg=summarize(d['opTot'])
    tot=sum(v[0] for v in agg.values()); ins=sum(v[1] for v in agg.values())
    res[f]={k:(v[0],round(100*v[0]/tot,1),v[1]) for k,v in sorted(agg.items(),key=lambda x:-x[1][0])}
    print(f, f'total {tot:,} instr {ins:,}')
    for k,(c,p,n) in res[f].items(): print(f'   {k:20s} {c:>14,} {p:5.1f}%  instr {n:,}  avg {c/n:,.0f}')
json.dump(res,open('opclass.json','w'),indent=1)
