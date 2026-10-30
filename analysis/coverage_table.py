#!/usr/bin/env python3
"""Table II (coverage per fuzzer and target) and the coverage columns of Table VI
(epoch settings on OpenThread Nexus).

Usage: python3 coverage_table.py <results folder>

Final coverage is the last iteration with coverage in each run's statistics.json.
Delta = median minus the coverage of the benign trace. p and A12 compare the branch
coverage of InterceptFuzz with each baseline (Table II) or of 5L with each other
setting (Table VI).
"""
import sys, statistics as st
from common import *

root = root_arg(sys.argv)
print('=== Table II ===')
for tgt, rel in TARGETS.items():
    data = {f: [final_stats(x) for x in runs(os.path.join(root, rel), sub)] for f, sub in FUZZERS[tgt].items()}
    print(f'-- {tgt} ({", ".join(f"{f}: {len(v)} runs" for f, v in data.items())})')
    ifb = [d['branches'] for d in data['InterceptFuzz']]
    for f, v in data.items():
        cells = []
        for k, (name, b) in enumerate(zip(('branches', 'lines', 'functions'), BENIGN[tgt])):
            vals = [d[name] for d in v]
            cells.append(f'{name} {med_range(vals)} (delta {fmt(r(st.median(vals)) - b)})')
        ex = [d['execs'] for d in v if d['execs'] is not None]
        stat = ''
        if f != 'InterceptFuzz':
            b = [d['branches'] for d in v]
            stat = f'  p {pfmt(mannwhitney_p(ifb, b))}, A12 = {a12(ifb, b):.2f}'
            for name in ('lines', 'functions'):
                x = [d[name] for d in data['InterceptFuzz']]; y = [d[name] for d in v]
                stat += f' | {name}: p {pfmt(mannwhitney_p(x, y))}'
        print(f'  {f:14} execs/s {med_range(ex) if ex else "-"} | ' + ' | '.join(cells) + stat)

print('\n=== Table VI (coverage columns, OpenThread Nexus) ===')
ot = os.path.join(root, OT)
cov = {k: [final_stats(x)['branches'] for x in runs(ot, rel)] for k, rel in SETTINGS.items()}
for k, v in cov.items():
    extra = '' if k == '5L' else f'  p {pfmt(mannwhitney_p(cov["5L"], v))}, A12 = {a12(cov["5L"], v):.2f}'
    print(f'  {k:4} {len(v)} runs  branches {med_range(v)}{extra}')
