# expected pruned-multiproof sibling digests for Q uniform leaves in depth-d tree, cap c
def sib(Q,d,c=0):
    tot=0.0
    for l in range(d-c):           # level l: nodes 2^(d-l), parent-level 2^(d-l-1)
        N=2**(d-l); P=N//2
        occ=N*(1-(1-1/N)**Q)        # occupied nodes
        occp=P*(1-(1-1/P)**Q)       # occupied parents
        tot+=2*occp-occ             # parents with exactly one occupied child
    return tot
def proof(Q,lb=9,cols=17,chunks=8,lbits=10,rc=3,salt=2,D=3,arity_log=3,flen_log=8,cap=0,t=None):
    top=lbits+1+lb
    t = t if t else 2*(cols+rc)+chunks*(D+rc)+(D+rc)
    # fri rounds
    h=top; rounds=[]
    while h>flen_log+lb:
        a=min(arity_log,h-(flen_log+lb)); rounds.append((h,a)); h-=a
    leaves=(cols+rc+salt)*8 + chunks*(D+rc+salt)*8 + (D+rc+salt)*8
    fri_leaf=sum(((2**a-1)*D*8+salt*8) for h,a in rounds)
    sibs=3*sib(Q,top,cap)+sum(sib(Q,h-a,cap) for h,a in rounds)
    capdig=(3+len(rounds))*(2**cap)
    pt=(2**flen_log)*D*8 + t*D*8 + capdig*32 + 3*8 + 8
    total=pt+Q*(leaves+fri_leaf)+sibs*32
    return dict(t=t,rounds=rounds,pt=round(pt),leafq=leaves+fri_leaf,sibs=round(sibs),total=round(total),perq_capped=leaves+fri_leaf+ (3*(top-cap)+sum(h-a-cap for h,a in rounds))*32+8)
for args in [dict(Q=24),dict(Q=24,cap=5),dict(Q=21,lb=10),dict(Q=26,lb=8,arity_log=4,flen_log=7),
             dict(Q=26,lb=8,cols=57,chunks=4,arity_log=4,flen_log=7),dict(Q=21,lb=10,cols=57,chunks=4,arity_log=4,flen_log=7)]:
    print(args,proof(**args))
