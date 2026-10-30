#!/usr/bin/env python3
"""TMF messages in the Prefix Trees of InterceptFuzz on OpenThread Nexus
(Appendix B: Table tab:tmf and the TMF paragraph).

Usage:  python3 tmf_table.py <results folder> [n_campaigns ...]
        default: all ten campaigns

Classification: each tree packet is an IEEE 802.15.4 frame. The decoder parses the
MAC header (incl. auxiliary security header; MIC and 2-byte FCS stripped), the 6LoWPAN
mesh/FRAG1 headers (FRAGN frames are skipped, they carry no headers), IPHC, NHC
extension headers (e.g. hop-by-hop with MPL option) and the UDP header (inline or NHC).
A packet is TMF if UDP src or dst port is 61631. Its CoAP header gives the code and the
Uri-Path (option 11). A request is a CoAP message with code 0.01-0.04 and a Uri-Path.
A request counts as answered if at least one child node of its edge carries a
parseable TMF message without a Uri-Path (i.e., a response).

Outputs: per URI the number of edges carrying a request, the number of campaigns in
which it occurs and the number of answered requests; the TMF share of all nodes in the
final trees (min-max); and the median number of TMF messages in the tree after
Phase I of each epoch (iter_0i/state_db_after_save_seeds.json).
"""
import json, glob, collections, statistics as st, sys, os
from common import OT, SETTINGS, runs as list_runs, find, iter_file, iterations, load_json, root_arg
TMF=0xF0BF
def mac_payload(p, fcs=2):
  if len(p)<3: return None
  fcf=p[0]|(p[1]<<8); i=2
  sec=(fcf>>3)&1; panc=(fcf>>6)&1; dam=(fcf>>10)&3; ver=(fcf>>12)&3; sam=(fcf>>14)&3
  seqsup=(fcf>>8)&1 if ver==2 else 0
  if not seqsup: i+=1
  al={0:0,2:2,3:8}
  if dam==1 or sam==1: return None
  if dam: i+=2+al[dam]
  if sam:
    if not panc: i+=2
    i+=al[sam]
  mic=0
  if sec:
    if i>=len(p): return None
    sc=p[i]; i+=1; lvl=sc&7; kim=(sc>>3)&3; fcsup=(sc>>5)&1 if ver==2 else 0
    if not fcsup: i+=4
    i+={0:0,1:1,2:5,3:9}[kim]
    mic={0:0,1:4,2:8,3:16,4:0,5:4,6:8,7:16}[lvl]
  end=len(p)-fcs-mic
  if end<=i: return None
  return p[i:end]
def lowpan_udp(p):
  i=0
  if i<len(p) and p[i]>>6==2:  # mesh header
    v=(p[i]>>5)&1; f=(p[i]>>4)&1; i+=1+(2 if v else 8)+(2 if f else 8)
  if i<len(p) and p[i]>>3==0x18: i+=4          # FRAG1
  elif i<len(p) and p[i]>>3==0x1C: return None  # FRAGN: no headers
  if i+1>=len(p) or p[i]>>5!=3: return None
  b0,b1=p[i],p[i+1]; i+=2
  tf=(b0>>3)&3; nh=(b0>>2)&1; hlim=b0&3
  cid=(b1>>7)&1; sac=(b1>>6)&1; sam=(b1>>4)&3; m=(b1>>3)&1; dac=(b1>>2)&1; dam=b1&3
  if cid: i+=1
  i+={0:4,1:3,2:1,3:0}[tf]
  if not nh: nxt=p[i]; i+=1
  if hlim==0: i+=1
  i+= (0 if (sac and sam==0) else {0:16,1:8,2:2,3:0}[sam])
  if m:
    i+= {0:16,1:6,2:4,3:1}[dam] if not dac else {0:6}.get(dam,0)
  else:
    i+= (0 if (dac and dam==0) else {0:16,1:8,2:2,3:0}[dam])
  if not nh:
    if nxt!=17 or i+8>len(p): return None
    s=(p[i]<<8)|p[i+1]; d=(p[i+2]<<8)|p[i+3]; i+=8
  else:
    while p[i]&0xF0==0xE0:   # NHC extension header (e.g. hop-by-hop with MPL option)
      enh=p[i]&1; i+=1
      if not enh: return None
      ln=p[i]; i+=1+ln
    b=p[i]
    if b&0xF8!=0xF0: return None
    mode=b&3; el=b&4; i+=1
    if mode==0: s=(p[i]<<8)|p[i+1]; d=(p[i+2]<<8)|p[i+3]; i+=4
    elif mode==1: s=(p[i]<<8)|p[i+1]; d=0xF000|p[i+2]; i+=3
    elif mode==2: s=0xF000|p[i]; d=(p[i+1]<<8)|p[i+2]; i+=3
    else: s=0xF0B0|(p[i]>>4); d=0xF0B0|(p[i]&15); i+=1
    if not el: i+=2
  return s,d,p[i:]
def coap(pl):
  if len(pl)<4 or pl[0]>>6!=1: return None
  tkl=pl[0]&15; code=pl[1]; i=4+tkl; opt=0; uri=[]
  while i<len(pl) and pl[i]!=0xFF:
    dl=pl[i]>>4; ln=pl[i]&15; i+=1
    if dl==13: dl=13+pl[i]; i+=1
    elif dl==14: dl=269+(pl[i]<<8|pl[i+1]); i+=2
    elif dl==15: return None
    if ln==13: ln=13+pl[i]; i+=1
    elif ln==14: ln=269+(pl[i]<<8|pl[i+1]); i+=2
    opt+=dl
    if opt==11: uri.append(bytes(pl[i:i+ln]).decode('latin1'))
    i+=ln
  return code,'/'.join(uri)
def classify(pkt,fcs=2):
  try:
    m=mac_payload(bytes(pkt),fcs)
    if m is None: return None
    u=lowpan_udp(m)
    if u is None: return None
    s,d,pl=u
    if s!=TMF and d!=TMF: return None
    return coap(pl) or ('?','')
  except (IndexError,KeyError): return None


def analyse(runs):
  edges=collections.Counter(); camps=collections.Counter(); ans=collections.Counter(); share=[]; per_ep=collections.defaultdict(list)
  for base in runs:
    tr=load_json(find(base,'state_db.json'))['transitions']
    kids=collections.defaultdict(list)
    for t in tr: kids[t['from_state']].append(t)
    ntmf=0; seen=set()
    for t in tr:
      c=classify(t['packet'])
      if c is None: continue
      ntmf+=1
      code,uri=c
      if uri and code!='?' and 1<=code<=4:
        edges[uri]+=1; seen.add(uri)
        nxt=kids.get(t['to_state'],[])
        if any((lambda cc: cc is not None and cc[0]!='?' and not cc[1])(classify(n['packet'])) for n in nxt): ans[uri]+=1
    for u in seen: camps[u]+=1
    share.append(100*ntmf/len(tr))
    for i in iterations(base):
      p=load_json(iter_file(base,i,'state_db_after_save_seeds.json'))['transitions']
      per_ep[i].append(sum(1 for t in p if classify(t['packet']) is not None))
  return edges,camps,ans,share,per_ep


if __name__ == '__main__':
  root = root_arg(sys.argv)
  runs = list_runs(os.path.join(root, OT), SETTINGS['5L'])
  ns = [int(x) for x in sys.argv[2:]] or [len(runs)]
  for n in ns:
    e, c, a, sh, pe = analyse(runs[:n])
    print(f'=== {n} campaigns: TMF share of final tree nodes {min(sh):.0f}-{max(sh):.0f}%')
    print('    Phase I TMF messages per epoch (median):', {i: st.median(v) for i, v in pe.items()})
    for u, k in e.most_common(16):
      print(f'   {u:8} edges {k:4}  campaigns {c[u]:2}  answered {a[u]}')
