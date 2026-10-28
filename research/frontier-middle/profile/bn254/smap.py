import json,sys
def parse(sm):
    out=[];prev=[0,0,0,0,0]
    for e in sm.split(';'):
        parts=e.split(':') if e else []
        cur=prev[:]
        for i,p in enumerate(parts):
            if p!='': cur[i]=int(p)
        out.append(tuple(cur)); prev=cur
    return out
if __name__=='__main__':
    a=json.load(open(sys.argv[1]));o=json.load(open(sys.argv[2]))
    sm=parse(a['debug']['sourceMap'])
    cost=dict((ip,c) for ip,c in o['topIp'])
    # segments by start line
    seg=[];last=None
    for ip in range(o['mainStart'],len(sm)):
        ln=sm[ip][0]
        if seg and seg[-1][2]==ln: seg[-1][1]=ip; seg[-1][3]+=cost.get(ip,0)
        else: seg.append([ip,ip,ln,cost.get(ip,0)])
    for s in seg: print(s[0],s[1],'line',s[2],'%.3fM'%(s[3]/1e6))
