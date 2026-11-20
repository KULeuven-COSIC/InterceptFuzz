#!/usr/bin/env python3
"""Coverage over time of all fuzzers: InterceptFuzz (5L), Concat and AFLNet as in
Fig. 3, plus AFLNet-pp and AFLNet-real when the results folder has runs of them.

Usage: python3 plot_coverage_all_fuzzers.py <results folder> {ot|wifi|lte} out.pdf [out.png]
Median (line) and min-max (band) over the campaigns, sampled every minute. Before its
first sample a campaign has the coverage of the benign trace. Rows with empty coverage
(crashing inputs) are skipped.
"""
import bisect, csv, os, statistics as st, sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt, matplotlib.ticker as mt
from common import TARGETS, BENIGN, all_fuzzers, runs, find

CFG = {'ot':   dict(tgt='OpenThread Nexus', T=86400, xt=[0, 4, 8, 12, 16, 20, 24]),
       'wifi': dict(tgt='ns-3 Wi-Fi',       T=36000, xt=[0, 2, 4, 6, 8, 10]),
       'lte':  dict(tgt='ns-3 LTE',         T=36000, xt=[0, 2, 4, 6, 8, 10])}
STYLE = {'InterceptFuzz': ('#2a78d6', '-'),
         'Concat':        ('#eb6834', (0, (4, 1.5))),
         'AFLNet':        ('#5f9e6e', (0, (5, 1.5, 1, 1.5))),
         'AFLNet-pp':     ('#8e5cc4', (0, (1, 1))),
         'AFLNet-real':   ('#7a6a55', (0, (6, 2)))}
LABEL = {'InterceptFuzz': 'InterceptFuzz (5L)', 'AFLNet': 'AFLNet (LibAFL)'}
ORDER = ['InterceptFuzz', 'Concat', 'AFLNet', 'AFLNet-pp', 'AFLNet-real']

if len(sys.argv) < 4 or sys.argv[2] not in CFG:
    sys.exit(__doc__)
root, key, outs = sys.argv[1], sys.argv[2], sys.argv[3:]
C = CFG[key]
base = os.path.join(root, TARGETS[C['tgt']])
ben = BENIGN[C['tgt']][0]
grid = list(range(0, C['T'] + 1, 60))
hours = [x / 3600 for x in grid]


def series(f):
    R = [(int(r['Time_Seconds']), int(r['Branch_Cov_Abs'])) for r in csv.DictReader(open(f)) if r['Branch_Cov_Abs']]
    T = [t for t, _ in R]; V = [v for _, v in R]
    return [ben if bisect.bisect_right(T, x) == 0 else V[bisect.bisect_right(T, x) - 1] for x in grid]


plt.rcParams.update({'font.family': 'serif', 'font.serif': ['Times New Roman', 'Times', 'Nimbus Roman', 'DejaVu Serif'],
                     'font.size': 9, 'axes.labelsize': 9, 'xtick.labelsize': 8, 'ytick.labelsize': 8,
                     'legend.fontsize': 8, 'pdf.fonttype': 42, 'axes.spines.top': False,
                     'axes.spines.right': False, 'axes.linewidth': 0.6})
fig, ax = plt.subplots(figsize=(5.2, 3.7))
ax.axhline(ben, color='#3d3d3a', lw=0.9, ls=(0, (1, 1.2)), zorder=1, label='Benign trace')
lo_all, hi_all = [ben], [ben]
fz = all_fuzzers(root, C['tgt'])
for name in [f for f in ORDER if f in fz]:
    files = [p for p in (find(x, 'coverage_over_time.csv') for x in runs(base, fz[name])) if p]
    if not files:
        print(f'[!] {name}: no coverage_over_time.csv, skipped'); continue
    S = [series(f) for f in files]
    med = [st.median(c) for c in zip(*S)]; lo = [min(c) for c in zip(*S)]; hi = [max(c) for c in zip(*S)]
    lo_all.append(min(lo)); hi_all.append(max(hi))
    col, ls = STYLE[name]
    ax.fill_between(hours, lo, hi, color=col, alpha=0.13, lw=0, step='post')
    ax.step(hours, med, where='post', color=col, lw=1.4, ls=ls, label=f'{LABEL.get(name, name)} ({len(S)})')
    print(f'{name:14} {len(S):2} runs, final median {med[-1]:,.0f} [{lo[-1]:,}-{hi[-1]:,}]')

span = max(hi_all) - min(lo_all)
ax.set_ylim(min(lo_all) - 0.03 * span, max(hi_all) + 0.04 * span)
ax.set_xlim(0, C['T'] / 3600); ax.set_xticks(C['xt'])
ax.set_xlabel('Fuzzing time (h)'); ax.set_ylabel('Covered branches')
ax.set_title(f"{C['tgt']} ({C['T'] // 3600} h)", fontsize=9.5, loc='left')
ax.yaxis.set_major_formatter(mt.FuncFormatter(lambda v, p: f'{v:,.0f}'))
ax.grid(axis='y', color='#e6e5e0', lw=0.5); ax.set_axisbelow(True)
h, l = ax.get_legend_handles_labels(); h, l = h[1:] + h[:1], l[1:] + l[:1]
ax.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, -0.17), frameon=False, handlelength=2.2, ncol=3, columnspacing=1.2)
fig.tight_layout(pad=0.4)
for o in outs:
    fig.savefig(o, dpi=220)
