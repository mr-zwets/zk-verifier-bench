import json,sys
G={'input':['fpRange'],'subgroup':['g2Double','g2AddAffine','psi'],'vkx':['jacAddG1','jacDoubleG1','g1ScalarMul','inverseFp'],
'miller':['millerSingle','line','pointAdd','fp6Mul01'],
'fe':['cycSqr','powMinusX','fp4Square','fp12Frob2','fp6FrobEven','fp6FrobOdd','fp6MulByFp2','fp12Conj','fp6Neg','fp6Sqr'],
'field':['P','mulFp','addFp','subFp','sqrFp','negFp','fp2Sqr','fp2Mul','fp2Add','fp2Sub','fp2Sc','fp2MulXi','fp2Scale','fp2Neg','fp2Half','fp6Mul','fp6MulByV','fp6Add','fp6Sub','fp12Mul']}
r=json.load(open(sys.argv[1])); out={}
for x in r:
    g=next((k for k,v in G.items() if x['name'] in v),'outlined')
    out[g]=out.get(g,0)+x['bytes']
print(out, sum(out.values()))
