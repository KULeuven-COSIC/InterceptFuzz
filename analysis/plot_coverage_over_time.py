#!/usr/bin/env python3
"""Coverage over time (Fig. 3).
Usage: python3 plot_coverage_over_time.py <results folder> {ot|wifi|lte} out.pdf [out.png]
Median and min-max over ten campaigns per fuzzer, sampled every minute.
Rows with empty coverage (crashing inputs) are skipped."""
import csv,glob,bisect,statistics as st,sys,matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt, matplotlib.ticker as mt
import os
from common import TARGETS, FUZZERS, BENIGN, runs as list_runs, find
CFG={'ot':dict(tgt='OpenThread Nexus',T=86400,bounds=[0,5760,17280,34560,57600,86400],ylim=(2100,7300),xt=[0,4,8,12,16,20,24]),
     'wifi':dict(tgt='ns-3 Wi-Fi',T=36000,bounds=[0,2400,7200,14400,24000,36000],ylim=(40380,41520),xt=[0,2,4,6,8,10]),
     'lte':dict(tgt='ns-3 LTE',T=36000,bounds=[0,2400,7200,14400,24000,36000],ylim=(34285,35150),xt=[0,2,4,6,8,10])}
if len(sys.argv)<4 or sys.argv[2] not in CFG: sys.exit(__doc__)
root,k,out=sys.argv[1],sys.argv[2],sys.argv[3:]; C=CFG[k]
C['base']=os.path.join(root,TARGETS[C['tgt']]); C['ben']=BENIGN[C['tgt']][0]
F=FUZZERS[C['tgt']]; SUB={'aflnet':F['AFLNet'],'sc':F['Concat'],'5L':F['InterceptFuzz']}
grid=list(range(0,C['T']+1,60))
plt.rcParams.update({'font.family':'serif','font.serif':['Times New Roman','Times','Nimbus Roman','DejaVu Serif'],'font.size':8,'axes.labelsize':8,'xtick.labelsize':7,'ytick.labelsize':7,'legend.fontsize':7,'pdf.fonttype':42,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':0.6})
fig,ax=plt.subplots(figsize=(3.45,2.2))
S=[('aflnet','AFLNet','#5f9e6e'),('sc','Concat','#eb6834'),('5L','InterceptFuzz (5L)','#2a78d6')]
for t in C['bounds'][1:-1]: ax.axvline(t/3600,color='#b5b4ad',lw=0.6,ls=(0,(2,2)),zorder=0)
lo_,hi_=C['ylim']
for i in range(5): ax.text((C['bounds'][i]+C['bounds'][i+1])/2/3600,lo_+0.012*(hi_-lo_),f'E{i+1}',ha='center',va='bottom',fontsize=6.5,color='#8a8980')
ax.axhline(C['ben'],color='#3d3d3a',lw=0.9,ls=(0,(1,1.2)),zorder=1,label='Benign trace')
for key,label,col in S:
  runs=[]
  for f in [find(x,'coverage_over_time.csv') for x in list_runs(C['base'],SUB[key])]:
    R=[(int(r['Time_Seconds']),int(r['Branch_Cov_Abs'])) for r in csv.DictReader(open(f)) if r['Branch_Cov_Abs']]  # empty rows: crashing inputs
    T=[t for t,_ in R]; V=[v for _,v in R]
    runs.append([C['ben'] if bisect.bisect_right(T,x)==0 else V[bisect.bisect_right(T,x)-1] for x in grid])
  assert runs,(key,'no runs')
  if len(runs)!=10: print(f'[!] {key}: {len(runs)} runs (the paper uses 10)')
  med=[st.median(c) for c in zip(*runs)]; lo=[min(c) for c in zip(*runs)]; hi=[max(c) for c in zip(*runs)]
  assert min(lo)>=lo_ and max(hi)<=hi_,(key,min(lo),max(hi))
  t=[x/3600 for x in grid]
  ax.fill_between(t,lo,hi,color=col,alpha=0.18,lw=0,step='post')
  LS={'aflnet':(0,(5,1.5,1,1.5)),'sc':(0,(4,1.5)),'5L':'-'}  # distinct line styles for grayscale print
  ax.step(t,med,where='post',color=col,lw=1.3,ls=LS[key],label=label)
  print(key,'final median',med[-1])
ax.set_xlim(0,C['T']/3600); ax.set_ylim(*C['ylim']); ax.set_xticks(C['xt'])
ax.set_xlabel('Fuzzing time (h)'); ax.set_ylabel('Covered branches')
ax.yaxis.set_major_formatter(mt.FuncFormatter(lambda v,p:f'{v:,.0f}'))
ax.grid(axis='y',color='#e6e5e0',lw=0.5); ax.set_axisbelow(True)
h,l=ax.get_legend_handles_labels(); h,l=h[1:]+h[:1],l[1:]+l[:1]
ax.legend(h,l,loc='lower center',frameon=False,bbox_to_anchor=(0.5,1.0),ncol=4,handlelength=1.4,columnspacing=0.9,handletextpad=0.4,borderaxespad=0.2)
fig.tight_layout(pad=0.3)
fig.canvas.draw(); lb=ax.get_legend().get_window_extent(); fb=fig.bbox
if not (lb.x0>=fb.x0 and lb.x1<=fb.x1 and lb.y1<=fb.y1): print('[!] legend exceeds the figure (Times font not installed?)')
for o in out: fig.savefig(o,dpi=200)
