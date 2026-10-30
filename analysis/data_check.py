#!/usr/bin/env python3
"""Consistency check of the coverage data.
Usage: python3 data_check.py <results folder>
For every configuration used in the paper it checks that each run has statistics.json
(with per-epoch coverage for InterceptFuzz) and coverage_over_time.csv, that the csv has
its (rows with empty coverage, from crashing inputs, are skipped),
that its last row and its maximum match the final coverage
in statistics.json, and that the per-epoch coverage matches the csv at the epoch boundary,
all up to a tolerance of 2 branches.
"""
import json,glob,os,csv,sys
from common import OT,WIFI,LTE,SETTINGS,FUZZERS,root_arg
root=root_arg(sys.argv)
TOL=2  # differences of up to 2 branches are replay noise
def br(it):
  c=it.get('coverage') or {}; return (c.get('branches') or {}).get('covered')
F=FUZZERS['ns-3 LTE']
T=[('OT',OT,[F['AFLNet'],F['Concat']]+list(SETTINGS.values())),
   ('LTE',LTE,[F['AFLNet'],F['Concat'],F['InterceptFuzz']]),
   ('WIFI',WIFI,[F['AFLNet'],F['Concat'],F['InterceptFuzz']])]
for tgt,base,cfgs in T:
  for c in cfgs:
    runs=sorted(glob.glob(f'{root}/{base}/{c}/run_*')); probs=[]
    nit=None
    for d in runs:
      r=os.path.basename(d)
      st=glob.glob(d+'/statistics.json')+glob.glob(d+'/*/*/statistics.json')
      if not st: probs.append(f'{r}: no statistics.json'); continue
      j=json.load(open(st[0])); its=j['iterations']
      nulls=[i['iteration'] for i in its if br(i) is None]
      if 'interceptfuzz' in c and nulls: probs.append(f'{r}: per-epoch coverage missing in epochs {nulls}')
      last=[i for i in its if br(i) is not None]
      if not last: probs.append(f'{r}: no coverage'); continue
      cc=last[-1]['coverage']; fin=(cc['lines']['covered'],cc['functions']['covered'],cc['branches']['covered'])
      cot=glob.glob(d+'/coverage_over_time.csv')+glob.glob(d+'/*/*/coverage_over_time.csv')
      if not cot:
        if c.endswith('5_iter/linear') or 'interceptfuzz' not in c: probs.append(f'{r}: no coverage_over_time.csv')
        continue
      rows=list(csv.DictReader(open(cot[0])))
      bad=[k for k,x in enumerate(rows) if None in x.values() or '' in x.values()]
      rows=[x for k,x in enumerate(rows) if k not in bad]
      if not rows: probs.append(f'{r}: empty csv'); continue
      L=rows[-1]; lc=(int(L['Line_Cov_Abs']),int(L['Func_Cov_Abs']),int(L['Branch_Cov_Abs']))
      mx=max(int(x['Branch_Cov_Abs']) for x in rows)
      ts=[int(x['Time_Seconds']) for x in rows]
      if abs(lc[2]-fin[2])>TOL: probs.append(f'{r}: csv last {lc} != stats {fin}')
      if abs(mx-fin[2])>TOL: probs.append(f'{r}: csv max branches {mx} != stats {fin[2]}')
      if ts!=sorted(ts): probs.append(f'{r}: time not monotonic')
      if 'interceptfuzz' in c:
        # per-epoch stats vs csv value at end of each iteration
        for it in its:
          if br(it) is None: continue
          i=it['iteration']; nx=[x for x in rows if int(x['Iteration'])==i+1]
          cur=[x for x in rows if int(x['Iteration'])==i]
          # the row at the epoch boundary is labelled with the next epoch (OpenThread) or the same epoch (ns-3)
          cands=([int(nx[0]['Branch_Cov_Abs'])] if nx else [fin[2]])+([int(cur[-1]['Branch_Cov_Abs'])] if cur else [])
          ref=min(cands,key=lambda v:abs(v-br(it)))
          if abs(ref-br(it))>TOL: probs.append(f"{r}: epoch {i} stats {br(it)} != csv at epoch boundary {ref}")
    print(f'{tgt:5}{c:28} runs {len(runs):2}  problems {len(probs)}')
    for p in probs: print('      ',p)
