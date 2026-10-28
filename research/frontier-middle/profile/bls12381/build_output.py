import json
J=lambda f: json.load(open(f))
def C(name, op, code, hint=0, notes=''):
    return {'name':name,'opCost':int(op),'codeBytes':int(code),'hintBytes':int(hint),'notes':notes}
entries=[]
# ---------- singletons ----------
for w,eid,total in [('opt','bch-groth16-bls12381-singleton-opcode-optimized',5999),('plain','bch-groth16-bls12381-singleton',7510)]:
    d=J(f'out-{w}.json'); s=J(f'seg-{w}.json'); sw=J(f'seg-{w}-worst.json'); seg=s['segments']; mb=s['mainBytes']
    body={x['name']:x['bodyLen'] for x in d['defines']}
    outl=sum(v for k,v in body.items() if k.startswith('outl')); nouts=sum(1 for k in body if k.startswith('outl'))
    bodies=sum(body.values()); hdr=mb['OP_DEFINE prelude']-bodies
    e=d['edgeIncl']; inc=d['incl']
    M=inc['millerSingleR']; sq=e['millerSingleR > fp12Mul']; ln=e['millerSingleR > line']; pa=e['millerSingleR > pointAdd']; slf=e['millerSingleR > (self)']; pd=M-sq-ln-pa-slf
    mseg=sum(v for k,v in seg.items() if k.startswith('Miller')); callsite=mseg-M
    msites=sum(v for k,v in mb.items() if k.startswith('Miller'))
    G=lambda names: sum(body.get(n,0) for n in names)
    fe_code=G(['powMinusX','cycSqr','fp4Square','fp12Frob2','fp6FrobOdd','fp6FrobEven','fp6MulByFp2','fp12Conj','fp6Neg','fp6Sqr'])
    tower=G(['P','sqrFp','mulFp','addFp','subFp','negFp','inverseFp','fp2Sqr','fp2Mul','fp2Add','fp2Sub','fp2MulXi','fp6Add','fp6Sub','fp6Mul','fp6MulByV','fp12Mul'])
    leaf=sum(d['excl'].get(k,0) for k in ['mulFp','addFp','subFp','P','sqrFp','negFp','inverseFp'])
    comps=[
     C('unlocking: push proof A,B,C + n0,n1', seg['unlocking (push witnesses)'], 0, 0, '397 B unlocking = 8 x 49 B coordinates + 2 public inputs; no prover hints'),
     C('OP_DEFINE prelude (define headers)', seg['OP_DEFINE prelude'], hdr, 0, f'{len(body)} OP_DEFINEs; libauth charges 100 each; BCHN-adjusted +{bodies:,} (body bytes) => {seg["OP_DEFINE prelude"]+bodies:,}. Body bytes are counted in the components that own them'),
     C('input checks: coordinate range, A/C on curve, B on twist', seg['input checks (range, curve, twist)'], mb['input checks (range, curve, twist)']+body['g1Check'], 0, 'no G1 subgroup check (cofactor malleability only)'),
     C('G2 subgroup check: psi(B) == [x]B endpoint of the (-A,B) walk', seg['G2 subgroup check (psi endpoint)'], mb['G2 subgroup check (psi endpoint)'], 0, 'the [|x|]B walk itself is inside Miller(-A,B); main bytes here include inline VK G2/psi constants first pushed in this span'),
     C('vk_x MSM: 2-scalar Straus/Shamir 255-bit loop + Fermat inverse + affine', seg['vk_x MSM (Straus loop + inverse + affine)'], mb['vk_x MSM (Straus loop + inverse + affine)']+G(['jacDoubleG1','jacAddAffineG1']), 0, f'bench vector n=(123,456): 8 dbl + 9 add; dense 254-bit inputs measured {sw["segments"]["vk_x MSM (Straus loop + inverse + affine)"]:,} (253 dbl x ~99k + 255 add x ~156k + inverse 6.07M + loop ~2.7M); 588 B of IC-table constants'),
     C('Miller x4 pairs: Fp12 squaring of f (generic fp12Mul, 64 per pair)', sq, G(['fp12Mul']) and 0, 0, f'{sq/256:,.0f} per squaring; 4 independent loops, so f is squared 256 times (a shared multi-Miller loop would square 64 times); fp12Mul body counted under field tower'),
     C('Miller x4 pairs: line evaluation (sparse mul014, 69 per pair)', ln, G(['line','fp6Mul01']), 0, f'276 lines x {ln/276:,.0f}'),
     C('Miller x4 pairs: G2 doubling (projective, inlined pointDouble, 64 per pair)', pd, 0, 0, f'{pd/256:,.0f} per doubling; also done for the 3 constant Q (beta, gamma, delta)'),
     C('Miller x4 pairs: G2 addition (5 per pair)', pa, G(['pointAdd']), 0, f'{pa/20:,.0f} per addition'),
     C('Miller x4 pairs: loop control/stack glue + call sites', slf+callsite, G(['millerSingleR','fp2Half','fp2Scale','fp2Neg'])+msites, 0, f'per pair {M/4:,.0f}: doubling iteration {(sq+pd+slf)/256+ln/276:,.0f}, addition step {pa/20+ln/276:,.0f}; millerSingleR body (inlines pointDouble/fp12Sqr/mul014) in codeBytes'),
     C('Fp12 product of the 4 Miller values + conjugate', seg['Fp12 products + conj'], mb['Fp12 products + conj'], 0, '3 fp12Mul (~1.37M each)'),
     C('final exp easy part: conj * inverse (fp12Inv, Fermat inverseFp) * frob2', seg['final exp easy part'], mb['final exp easy part'], 0, 'includes one 381-bit Fermat inverse (6.07M)'),
     C('final exp hard part (Hayashida-Scott): 5 x powMinusX + frobenius + ~10 fp12Mul', seg['final exp hard part'], mb['final exp hard part']+fe_code, 0, f'powMinusX {inc["powMinusX"]/5:,.0f} each = 64 cyclotomic squarings ({inc["cycSqr"]/d["calls"]["cycSqr"]:,.0f}) + 6 fp12Mul; finalExp is inlined into main'),
     C('field tower helper bodies (Fp/Fp2/Fp6/Fp12, P constant)', 0, tower, 0, f'op-cost counted inside the phase components (see cross-cut rows)'),
    ]
    if outl: comps.append(C(f'outlined fragments ({nouts} OP_DEFINE bodies from the outliner)', 0, outl, 0, 'op-cost counted inside callers; outlining adds ~0.9% op-cost (OP_INVOKE + id push per use)'))
    comps.append(C('[cross-cut, not additive] leaf Fp arithmetic: mulFp/addFp/subFp/sqrFp/negFp/inverseFp/P-const bodies', leaf, 0, 0, f'{100*leaf/d["operationCost"]:.1f}% of op-cost; mulFp {d["excl"]["mulFp"]:,} (52,368 x 6.5k), addFp {d["excl"]["addFp"]:,} (82,409 x 2.9k), subFp {d["excl"]["subFp"]:,} (60,302 x 3.4k), P {d["excl"]["P"]:,} (256,754 x 148), inverseFp 12.1M'))
    comps.append(C('[cross-cut, not additive] dispatch: OP_INVOKE + stack shuffles + loop control (everything outside leaf Fp bodies)', d['operationCost']-leaf, 0, 0, 'by opcode class: OP_INVOKE/DEFINE ~5.2-5.7%, stack ops ~8.7%, pushes ~12% (incl. 48-B P constant), MUL/MOD ~69.5%'))
    add=sum(c['opCost'] for c in comps if not c['name'].startswith('[')); cb=sum(c['codeBytes'] for c in comps)
    assert add==d['operationCost'], (w, add, d['operationCost'])
    lock=mb and sum(mb.values()); 
    print(w,'code bytes',cb,'locking',lock)
    entries.append({'id':eid,'totalBytes':total,'totalOpCost':d['operationCost'],'components':comps})
# ---------- SI-GLS ----------
d=J('out-sigls-valid.json'); dw=J('out-sigls-worst.json'); cu=d['custom']; cw=dw['custom']
S=lambda sec,c=cu: sum(v for k,v in c.items() if k.split('|')[0]==sec)
F=lambda sec,f,c=cu: c.get(f'{sec}|{f}',0)
info=d['info']; fb=info['funcs']; sec=info['sections']
comps=[
 C('unlocking pushes + P2SH32 redeem hash check (locking 35 B)', S('unlocking+p2sh'), 35, 0, 'HASH256 over the 12,793 B redeem'),
 C('OP_DEFINE prologue (12 functions)', S('prologue(OP_DEFINE)'), info['prologue']-sum(fb.values())+fb['P'], 0, f'BCHN-adjusted +{sum(x["bodyLen"] for x in d["defines"]):,}; function bodies are counted in their components'),
 C('transcript: SHA256(TAG||WS), rho, z (Fiat-Shamir)', S('transcript'), sec['transcript']-6579, 0, ''),
 C('input checks: word range (RD), n<r, nibble mask, A/C on curve, B on twist', S('parse+checks'), sec['parse+checks']+fb['RD']+fb['G1C'], 0, 'statement words in WS (A,B,C 384 + n0,n1 64 = 448 B) are proof/public inputs, not hints'),
 C('powers of z, Frobenius/line coefficient prep, S_c(+-z), Rconst(+-z)', S('powers'), sec['powers']+fb['EV'], 0, 'e(alpha,beta)*e(IC0,gamma) baked as one class Rconst'),
 C('vk_x replacement: GT-GLS folding of e(vk_x,gamma) (TP/TM tables at +-z, per-event nibble lookups, exact integer binding acc_k == n_k)', S('gls-tables')+S('loop:gls')+S('loop:digit'), sec['gls-tables']+fb['TM']+fb['TA'], 128, f'tables {S("gls-tables"):,} + lookups {S("loop:gls"):,} (worst-case witness {S("loop:gls",cw):,}) + digit {S("loop:digit"):,}; 128 B base-|x| nibble strings in WS; gls-tables code includes baked GLS factor constants'),
 C('loop setup (initial F+-)', S('loop-setup'), sec['loop-setup'], 0, ''),
 C('Miller (-A,B): B doublings incl. F+-^2 and line evaluation at +-z', S('loop:bdbl'), fb['AFFDBL']+fb['PROJDBL'], 1248, f'10 affine with witnessed slope ({F("loop:bdbl","AFFDBL")/10:,.0f} each) + 53 homogeneous projective ({F("loop:bdbl","PROJDBL")/53:,.0f} each); hint = 13 affine B slopes (10 dbl + 3 add) x 96 B'),
 C('Miller (C,delta): fixed-pair steps (baked slopes, on-chain x/c recursion, line at +-z)', S('loop:dstep')+F('loop:add','DSTEP'), fb['DSTEP']+6579, 0, f'68 steps x {(S("loop:dstep")+F("loop:add","DSTEP"))/68:,.0f}; codeBytes include the 6,579 B delta-slope pile baked in the redeem'),
 C('Miller (-A,B): B additions (2 projective + 3 affine) incl. S_c(-+z) c^-1 factor', S('loop:add')-F('loop:add','DSTEP'), fb['AFFADD']+fb['PROJADD'], 0, f'PROJADD {F("loop:add","PROJADD")/2:,.0f} each, AFFADD {F("loop:add","AFFADD")/3:,.0f} each'),
 C('SI-GLS checkpoint boundaries: 32 committed monic states, R <- R*rho + F+ S\'(-z) - F- S\'(z)', S('loop:bnd'), fb['BND'], 9216, f'{S("loop:bnd")/32:,.0f} per boundary (incl. RD range checks of 6 state words); hint = 32 states x 288 B'),
 C('loop control (event loop, schedule)', S('loop:loopend')+S('loop:entry'), sec['loop'], 0, '63 events'),
 C('terminal: slope/size consumption, psi endpoint G2 check [|x|]B = -psi(B), W = Frob(S_c)(+-z) residue term', S('terminal'), sec['terminal'], 288, 'hint = residue root s^c (6 words); replaces the whole final exponentiation'),
 C('quotient Horner over WQ + final Schwartz-Zippel identity (R == z q(z^2) M(z))', S('quotient'), sec['final'], 2256, f'47 quotient words (n_q depends on statement; worst witness {S("quotient",cw):,} op)'),
 C('cleanup', S('cleanup'), sec['cleanup'], 0, ''),
 C('push headers + tx overhead', 0, 0, 0, '9 B push headers + 63 B tx overhead (not code/hint)'),
]
add=sum(c['opCost'] for c in comps); assert add==d['operationCost'], (add,d['operationCost'])
print('sigls code', sum(c['codeBytes'] for c in comps), 'hint', sum(c['hintBytes'] for c in comps))
entries.append({'id':'bch-groth16-bls12381-sound-si-gls-single','totalBytes':26484,'totalOpCost':d['operationCost'],'components':comps})
# ---------- native ----------
d=J('out-native-valid.json'); dw=J('out-native-worst.json')
def agg(dd):
    a={}; inc={}; cal={}
    for i in dd['inputs']:
        for k,v in i['custom'].items():
            s,f=k.split('|'); a[f'in{i["input"]}:{s}|{f}']=v
        for k,v in i['incl'].items(): inc[k]=inc.get(k,0)+v
        for k,v in i['calls'].items(): cal[k]=cal.get(k,0)+v
    return a,inc,cal
a,inc,cal=agg(d); aw,incw,_=agg(dw)
T=sum(i['operationCost'] for i in d['inputs'])
SS=lambda pred,aa=a: sum(v for k,v in aa.items() if pred(k))
sec_=lambda k: k.split('|')[0]
fb=d['info']['funcs']
R_blob=SS(lambda k: sec_(k).endswith(':R+blob')); unl=SS(lambda k: sec_(k).endswith(':unlocking/p2sh'))
pin=SS(lambda k: sec_(k) in ('in0:start','in1:start','in2:start','in3:start')); params=SS(lambda k: sec_(k) in ('in1:after-pin+K','in2:after-pin+K','in3:after-pin+K'))
tr=SS(lambda k: sec_(k)=='in0:after-pin+K'); st=SS(lambda k: sec_(k)=='in0:after-transcript'); bind=SS(lambda k: sec_(k)=='in0:after-statement')
quo=SS(lambda k: sec_(k)=='in0:after-binding'); term=SS(lambda k: sec_(k)=='in3:after-work')
quow=SS(lambda k: sec_(k)=='in0:after-binding',aw); bindw=SS(lambda k: sec_(k)=='in0:after-statement',aw)
setup=inc['SETUP']; tbl=inc['TBL']
loopself=sum(i['edgeIncl'].get('LOOP > (self)',0) for i in d['inputs']); loopselfw=sum(i['edgeIncl'].get('LOOP > (self)',0) for i in dw['inputs'])
reads=inc.get('READ0',0)+inc.get('WSTART',0)+SS(lambda k: sec_(k)=='in0:after-setup')
setup_row=setup+SS(lambda k: sec_(k)=='in0:after-quotient+final' and k.split('|')[1]=='(self)')
affd=sum(i['edgeIncl'].get('AFFADD > DSTEP',0) for i in d['inputs']); affadd=inc['AFFADD']-affd
listed=[R_blob,unl,pin+params,tr,st,bind,quo,setup_row,reads,inc['AFFDBL'],inc['DSTEP'],affadd,inc['BND'],loopself,term]
other=T-sum(listed)
blob_funcs=sum(fb.values()); roles=d['info']['roles']
comps=[
 C('per-input covenant R (input count, identical lockings, load 6,465 B program from 2 carriers, SHA256 check, define+invoke) x4', R_blob+unl, 4*81+4*35, 0, f'R+blob {R_blob:,} + unlocking/P2SH {unl:,}; each input re-defines all 25 functions: BCHN-adjusted +12,826 per input (+51,304 total) => {T+51304:,}'),
 C('role entry: pin layout + K-block (delta constants) SHA256 checks + role params', pin+params, sum(roles), 0, 'codeBytes = all 4 role bodies (1,521/195/183/789), which also hold the head and terminal sections inline'),
 C('head transcript (input 0): hash of all 4 regions, rho, z', tr, 0, 96, 'hint = ZR claim 96 B'),
 C('statement checks (input 0): range, n<r, nibbles, A/C curve, B twist', st, fb['G1C']+fb['RD']+fb['RD6']+fb['RD2'], 416, 'statement region 864 B = proof/inputs 448 (not hint) + hints: nibbles 128 + residue root 288'),
 C('vk_x replacement: GT-GLS exact integer binding (input 0)', bind, fb['TA'], 0, f'worst witness {bindw:,}; table lookups during the loop are in loop control'),
 C('quotient Horner + final identity (input 0)', quo, 0, 2160, f'WQ 45 words at the fixture; worst n_q=116: {quow:,}'),
 C('SETUP per input x4: powers of z, GT-GLS tables (TBL), TM, EV', setup_row, fb['SETUP']+fb['TBL']+fb['TM']+fb['EV'], 0, f'{inc["SETUP"]/4:,.0f} per input, of which GLS tables {tbl/4:,.0f}; replicated in every input (multi-input overhead ~2.4M); SETUP body includes 1,152 B GLS factor constants'),
 C('state/witness reads + walk start', reads, fb['READ0']+fb['WSTART'], 0, ''),
 C('Miller (-A,B): 63 affine B doublings with witnessed slopes (incl. F+-^2, line at +-z)', inc['AFFDBL'], fb['AFFDBL'], 63*96, f'{inc["AFFDBL"]/63:,.0f} each; hint = 63 doubling slopes x 96 B'),
 C('Miller (C,delta): 68 fixed-pair steps (baked slopes, x/c recursion)', inc['DSTEP'], fb['DSTEP']+7104, 0, f'{inc["DSTEP"]/68:,.0f} each; codeBytes include 7,104 B of K blocks (delta walk point + 68 baked slopes) hosted in unlockings, SHA256-pinned'),
 C('Miller (-A,B): 5 affine B additions incl. c^-1 factor', affadd, fb['AFFADD'], 5*96, f'{affadd/5:,.0f} each (excl. the delta add step inside AFFADD, counted in the delta row); hint = 5 addition slopes'),
 C('SI-GLS checkpoint boundaries (32 committed states)', inc['BND'], fb['BND'], 9216, f'{inc["BND"]/32:,.0f} each; hint = 32 states x 288 B'),
 C('loop control incl. per-event GLS nibble lookups', loopself, fb['LOOP']+fb['WORK'], 0, f'worst witness {loopselfw:,}'),
 C('terminal (input 3): psi endpoint G2 check, W = Frob(S_c)(+-z) residue term, claim', term, 0, 0, 'residue root hint counted in statement row'),
 C('hand-over claims, FINW, other glue', other, fb['FINW']+fb['C48']+fb['P']+(6465-blob_funcs-sum(roles)), 768, 'hint = claims CL (3 x 240 + 48); codeBytes include blob define headers'),
 C('zero filler + push headers + tx overhead', 0, 0, 0, 'filler 311 B (budget only), push headers, 192 B tx overhead'),
]
add=sum(c['opCost'] for c in comps); assert add==T,(add,T)
print('native code', sum(c['codeBytes'] for c in comps), 'hint', sum(c['hintBytes'] for c in comps))
entries.append({'id':'bch-groth16-bls12381-sound-native','totalBytes':34229,'totalOpCost':T,'components':comps})
# ---------- minop ----------
d=J('out-minop-valid.json'); dw=J('out-minop-worst.json'); cu=d['custom']; cw=dw['custom']; sb=d['statBytes']
body={x['name']:x['bodyLen'] for x in d['defines']}
def m(k,name,hint=0,notes=''): return C(name, cu.get(k,0), sb.get(k,0), hint, notes)
comps=[
 C('unlocking: proof + inputs (twice) + hints', cu['unlocking (push witnesses)'], 0, 0, '747 B: coordinates 392, inputs ~10, hints 343-411 (rows below)'),
 m('OP_DEFINE prelude','OP_DEFINE prelude: 27 lazy-tower / Miller kernel bodies',0,f'bodies {sum(body.values()):,} B (fp12Sqr 247, line 270, fp6Mul01 138, pointDouble 183, pointAdd 213, fp12MulTorus 188, fp2Mul 223, fp6Mul 193, jac* 229, ...); BCHN-adjusted +{sum(body.values()):,}'),
 m('input checks (range, curve, twist)','input checks: range of 8 coords + 6 root limbs, A/C on curve, B on twist'),
 m('vk_x GLV 4-scalar Straus (+zInv witness check)','vk_x MSM: GLV 4-scalar 128-bit Straus over a baked 15-entry subset-sum table, mixed Jacobian-affine adds, witnessed zInv',49+7,f'bench vector (n=123,456) {cu["vk_x GLV 4-scalar Straus (+zInv witness check)"]:,}; dense 254-bit inputs {cw["vk_x GLV 4-scalar Straus (+zInv witness check)"]:,}; 1,440 B baked table; hint = zInv 49 B + k-decomposition (7 B at the bench vector, 68 B dense)'),
 m('Miller: f squaring (fp12Sqr)','Miller (batched, unrolled): shared f squaring (lazy fp12Sqr x64)',0,f'{cu["Miller: f squaring (fp12Sqr)"]/64:,.0f} each (vs 1.37M reduced-tower squaring in the plain singleton)'),
 m('Miller: B point doubling','Miller: G2 doubling of B (lazy, x64)',0,f'{cu["Miller: B point doubling"]/64:,.0f} each'),
 m('Miller: B point addition','Miller: G2 addition of B (x5)',0,''),
 m('Miller: (-A,B) line evaluation','Miller: (-A,B) line evaluation (sparse Fp12 mul, x69)',0,f'{cu["Miller: (-A,B) line evaluation"]/69:,.0f} each'),
 m('Miller: baked (vk_x,gamma)/(C,delta) line evaluation','Miller: baked (vk_x,gamma)/(C,delta) line evaluation (x138, coefficients inline)',0,f'{cu["Miller: baked (vk_x,gamma)/(C,delta) line evaluation"]/138:,.0f} each, same cost as a runtime line (baking removes only the G2 arithmetic); 40,556 of the 45,524 code bytes are 828 inline 48-B line coefficients'),
 m('Miller: c^-1 torus fold (residue)','residue: c^-|x| folds into the Miller loop (fp12MulTorus x6)',294,'hint = 6-limb torus root u (294 B)'),
 m('Miller: setup/glue','Miller setup/glue'),
 m('G2 subgroup check (psi endpoint)','G2 subgroup check psi(B) == [x]B on the walk endpoint'),
 m('residue terminal check (torus Frobenius + cross product)','residue terminal check [fF] = [frob(c)] (replaces final exponentiation)',0,''),
]
comps.append(C('[cross-cut, not additive] lazy field arithmetic leaves (fp2Mul unreduced, mulFp, subFp, mSqr, mSub, fp6Add, redFp)', sum(d['excl'].get(k,0) for k in ['fp2Mul','mulFp','subFp','mSqr','mSub','mAdd','fp6Add','redFp']), 0, 0, f'fp2Mul {d["excl"]["fp2Mul"]:,} (3,794 x 21.8k); opcode classes: MUL/MOD 60%, stack 17%, push 12%, add/sub 9%, OP_INVOKE 1.8%'))
add=sum(c['opCost'] for c in comps if not c['name'].startswith('[')); assert add==d['operationCost'],(add,d['operationCost'])
print('minop code', sum(c['codeBytes'] for c in comps), 'hint', sum(c['hintBytes'] for c in comps))
entries.insert(2,{'id':'bch-groth16-bls12381-singleton-minop','totalBytes':58841,'totalOpCost':d['operationCost'],'components':comps})
json.dump(entries,open('entries.json','w'),indent=1)
