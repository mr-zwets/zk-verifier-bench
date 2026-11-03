# Independent Python Poseidon2-Goldilocks per pil2-proofman fields/src/poseidon2.rs; constants parsed from poseidon2_constants.rs.
import re, sys
P = 2**64 - 2**32 + 1
def parse(path):
    src = open(path).read()
    out = {}
    for m in re.finditer(r'impl Poseidon2Constants<(\d+)> for Poseidon2_\d+ \{(.*?)\n\}', src, re.S):
        w = int(m.group(1)); body = m.group(2)
        def arr(name):
            a = re.search(name + r': &\'static \[u64\] = &\[(.*?)\];', body, re.S).group(1)
            return [int(x, 16) for x in re.findall(r'0x[0-9a-fA-F]+', a)]
        def c(name): return int(re.search(name + r': usize = (\d+);', body).group(1))
        out[w] = dict(DIAG=arr('DIAG'), RC=arr('RC'), HR=c('HALF_ROUNDS'), NP=c('N_PARTIAL_ROUNDS'), RATE=c('RATE'), CAP=c('CAPACITY'))
    return out
def m4(x):
    t0=x[0]+x[1]; t1=x[2]+x[3]; t2=2*x[1]+t1; t3=2*x[3]+t0; t4=4*t1+t3; t5=4*t0+t2; t6=t3+t5; t7=t2+t4
    return [t6%P,t5%P,t7%P,t4%P]
def ext(s):
    W=len(s); s=sum((m4(s[i:i+4]) for i in range(0,W,4)),[])
    if W>4:
        st=[sum(s[j*4+i] for j in range(W//4))%P for i in range(4)]
        s=[(x+st[i%4])%P for i,x in enumerate(s)]
    return s
def perm(s, C):
    W=len(s); s=ext(list(s)); HR, NP, RC, D = C['HR'], C['NP'], C['RC'], C['DIAG']
    assert len(RC) == 2*HR*W + NP and len(D) == W
    for r in range(HR):
        s=[pow((x+RC[r*W+i])%P,7,P) for i,x in enumerate(s)]; s=ext(s)
    for r in range(NP):
        s[0]=pow((s[0]+RC[HR*W+r])%P,7,P); sm=sum(s)%P
        s=[(x*D[i]+sm)%P for i,x in enumerate(s)]
    for r in range(HR):
        s=[pow((x+RC[HR*W+NP+r*W+i])%P,7,P) for i,x in enumerate(s)]; s=ext(s)
    return s
if __name__ == '__main__':
    C = parse(sys.argv[1])
    vec = {16:[9639188652563994454,12273372933164734616,2905147255612444119,17581461329934617288,14390794100096760072,5468485695976078057,2832370985856357627,1116111836864400812,14997632823506024332,3976503894892102369,14874978986912301676,12458748982184310703,103345454961107931,3354965064850558444,14413825288474057217,4214638127285300968],
           8:[14266028122062624699,5353147180106052723,15203350112844181434,17630919042639565165,16601551015858213987,10184091939013874068,16774100645754596496,12047415603622314780],
           4:[8466914293353944746,9589318970755021278,5769801005587200741,17288820341814263849],
           12:[138186169299091649,2237493815125627916,7098449130000758157,16681569560651424230,2885694034573886267,1987263728465303211,4895658260063552408,16782691522897809445,6250362358359317026,8723968546836371205,17025428646788054631,7660698892044183277]}
    for w in sorted(C):
        print(w, {k:(v if not isinstance(v,list) else len(v)) for k,v in C[w].items()}, 'vector', perm(list(range(w)),C[w])==vec[w])
