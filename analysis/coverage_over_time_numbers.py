#!/usr/bin/env python3
"""Numbers in the text of RQ1/RQ3 that come from the coverage-over-time data of
OpenThread Nexus (InterceptFuzz 5L vs. Concat):

- median branch coverage of both fuzzers at the end of epochs 1 and 2 (1.6 h, 4.8 h)
- the time after which the median of InterceptFuzz stays above that of Concat
- the time at which each InterceptFuzz campaign reaches the final median of Concat

Usage: python3 coverage_over_time_numbers.py <results folder>
Coverage is sampled every minute, as in Fig. 3; before the first replayed input, a
campaign has the coverage of the benign trace.
"""
import bisect, csv, sys
from common import *

root = root_arg(sys.argv)
ot = os.path.join(root, OT)
F = FUZZERS['OpenThread Nexus']
BEN = BENIGN['OpenThread Nexus'][0]
GRID = range(0, 86400 + 1, 60)


def series(sub):
    out = []
    for run in runs(ot, sub):
        rows = csv.DictReader(open(find(run, 'coverage_over_time.csv')))
        out.append([(int(x['Time_Seconds']), int(x['Branch_Cov_Abs'])) for x in rows if x['Branch_Cov_Abs']])
    return out


def at(s, t):
    i = bisect.bisect_right([x for x, _ in s], t)
    return BEN if i == 0 else s[i - 1][1]


IF, SC = series(F['InterceptFuzz']), series(F['Concat'])
for h in (1.6, 4.8):
    t = int(h * 3600)
    print(f'after {h} h: InterceptFuzz {fmt(r(st.median([at(s, t) for s in IF])))}, '
          f'Concat {fmt(r(st.median([at(s, t) for s in SC])))} branches (median)')

mi = [st.median([at(s, t) for s in IF]) for t in GRID]
ms = [st.median([at(s, t) for s in SC]) for t in GRID]
last = max(i for i, (a, b) in enumerate(zip(mi, ms)) if a <= b)
print(f'median of InterceptFuzz stays above Concat from {GRID[last + 1] / 3600:.1f} h on')

target = r(st.median([final_stats(x)['branches'] for x in runs(ot, F['Concat'])]))
reach = [next((t / 3600 for t, v in s if v >= target), None) for s in IF]
hit = [x for x in reach if x is not None]
print(f'final median of Concat ({fmt(target)} branches) reached by {len(hit)}/{len(IF)} InterceptFuzz campaigns, '
      f'after a median of {st.median(hit):.1f} h [{min(hit):.1f}--{max(hit):.1f}]')
