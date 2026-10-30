#!/usr/bin/env python3
"""Table III (crash signatures on OpenThread Nexus), Table IV (ns-3 targets) and the
signature columns of Table VI (epoch settings).

Usage: python3 crash_tables.py <results folder>

Crashes are read from crash_summary.json of each run, which crashes/dedup_crashes.py
writes: it assigns every crashing input to a signature using the rule files in
crashes/ (ot_rules.json, ns-3_wifi_rules.json, ns-3_lte_rules.json). It includes the
crashes found by replaying the non-minimized queue on the ASan build.
On OpenThread Nexus, the rule names are the signature IDs of the paper (C1--C7);
on ns-3, the signatures are the rule categories "Crash N". The time to first exposure (TTE) is the time encoded in the name
of the first crashing input (time:<ms>), shifted by the start time of its epoch for
InterceptFuzz, whose epochs run as separate AFL++ instances.
"""
import sys, re, glob
from common import *

OT_SIG = ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7']


def summary(run):
    p = find(run, 'crash_summary.json')
    return load_json(p) if p else []


def is_signature(cat):
    return cat in OT_SIG or cat.startswith('Crash ')


def categories(run):
    return {e['category'] for e in summary(run) if is_signature(e['category'])}


def first_exposure(run):
    """signature -> hours until first exposure."""
    if find(run, 'crash_summary.json') is None:
        return {}
    offs = {}
    for it in iterations(run):
        fs = iter_file(run, it, 'fuzzer_stats')
        if fs is None:
            continue
        for line in open(fs):
            if line.startswith('start_time'):
                offs[it] = int(line.split(':')[1])
    t0 = min(offs.values()) if offs else None
    out = {}
    for e in summary(run):
        if not is_signature(e['category']):
            continue
        n = e['category']
        fn = os.path.basename(e.get('first_file') or e['file'])
        t = int(re.search(r'time:(\d+)', fn).group(1)) / 1000
        m = re.match(r'iter_(\d+)_', fn)
        if m:
            t += offs[int(m.group(1))] - t0
        out[n] = min(out.get(n, 1e18), t / 3600)
    return out


root = root_arg(sys.argv)
ot = os.path.join(root, OT)

print('=== Table III (OpenThread Nexus) ===')
per = {}
for f, sub in FUZZERS['OpenThread Nexus'].items():
    R = [first_exposure(x) for x in runs(ot, sub)]
    per[f] = [len([c for c in s if c in OT_SIG]) for s in R]
    print(f'-- {f} ({len(R)} runs)')
    for sig in OT_SIG:
        v = [s[sig] for s in R if sig in s]
        tte = f'median TTE {st.median(v):.1f} h' if v else ''
        print(f'   {sig}: {len(v)}/{len(R)} campaigns  {tte}')
    print(f'   signatures per campaign: median {fmt(st.median(per[f]))} [{min(per[f])}--{max(per[f])}], total exposures {sum(per[f])}')
print(f'   InterceptFuzz vs Concat, signatures per campaign: p {pfmt(mannwhitney_p(per["InterceptFuzz"], per["Concat"]))}')

print('\n=== Table IV (ns-3) ===')
for tgt in ('ns-3 Wi-Fi', 'ns-3 LTE'):
    print(f'-- {tgt}')
    cnt = {}
    for f, sub in FUZZERS[tgt].items():
        C = [categories(x) for x in runs(os.path.join(root, TARGETS[tgt]), sub)]
        cnt[f] = [len(c) for c in C]
        print(f'   {f:14} all campaigns {len(set().union(*C))}, per campaign {med_range(cnt[f], half_up=False)}')
    for b in ('Concat', 'AFLNet'):
        print(f'   InterceptFuzz vs {b}: p {pfmt(mannwhitney_p(cnt["InterceptFuzz"], cnt[b]))}, A12 = {a12(cnt["InterceptFuzz"], cnt[b]):.2f}')

print('\n=== Table VI (signature columns, OpenThread Nexus) ===')
for k, rel in SETTINGS.items():
    C = [categories(x) & set(OT_SIG) for x in runs(ot, rel)]
    n = [len(c) for c in C]
    print(f'   {k:4} per campaign {med_range(n, half_up=False)}, all campaigns {len(set().union(*C))}')
