#!/usr/bin/env python3
"""Independent scan of decrypted console cmd traffic.
Record format: >d (ts, 8B BE double) 4s (src) 4s (dst) I (payload len) + payload
Verified against capture/truth-decrypt.py:556-559.
"""
import struct, sys, collections, ipaddress

def read(path):
    recs=[]
    with open(path,'rb') as f:
        d=f.read()
    o=0
    while o+20<=len(d):
        ts,si,di,n=struct.unpack('>d4s4sI', d[o:o+20]); o+=20
        p=d[o:o+n]; o+=n
        if len(p)!=n: break
        recs.append((ts,str(ipaddress.IPv4Address(si)),str(ipaddress.IPv4Address(di)),p))
    return recs

def u16(b,o): return b[o]|(b[o+1]<<8)
def u16be(b,o): return (b[o]<<8)|b[o+1]

for path in sys.argv[1:]:
    recs=read(path)
    print("="*70); print(path, len(recs), "records", "span %.3f..%.3f s"%(recs[0][0],recs[-1][0]))
    combos=collections.Counter((u16(p,0),u16(p,2),len(p)) for _,_,_,p in recs)
    print(" (type,query,dgramlen) counts:")
    for k,v in sorted(combos.items()): print("   ", k, v)
    # declared vs actual
    print(" outer payload_size vs actual-8 mismatches:")
    mism=collections.Counter()
    for ts,s,d,p in recs:
        if len(p)<8: mism[("SHORT",len(p))]+=1; continue
        decl=u16(p,4); act=len(p)-8
        if decl!=act: mism[(decl,act)]+=1
    print("   ", dict(mism) if mism else "none")
    # generic header analysis for query type 0 with >=20 bytes
    print(" generic (svc,method,flags,gen_psize,tid,fragid_raw byte3/byte4,decl vs actual payload):")
    g=collections.Counter()
    for ts,s,d,p in recs:
        if len(p)<20 or u16(p,2)!=0: continue
        gt=p[11] if False else None
        magic=p[8]
        if magic!=0x7e: g[("NOMAGIC",magic)]+=1; continue
        svc=p[14]; meth=p[15]; flags=p[13]
        err=u16be(p,16); gps=u16be(p,18)
        tid=(p[10]<<8)|(p[11]>>4); fin=(p[11]>>3)&1; fid=((p[11]&7)<<8)|p[12]
        act=len(p)-20
        g[(svc,meth,flags,gps,act,tid,fin,fid)]+=1
    for k,v in sorted(g.items()): print("   ",k,v)
    if u16(recs[0][3],2)==0:
        print(" seq_id first/last:", u16(recs[0][3],6), u16(recs[-1][3],6))
