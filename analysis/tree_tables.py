#!/usr/bin/env python3
"""Prefix Tree per epoch: Table V (OpenThread Nexus, 5L), Table VII (all four
epoch settings on OpenThread Nexus) and Table VIII (ns-3 targets, 5L).

Usage: python3 tree_tables.py <results folder>

For every epoch i, the trees are read from iter_<i>/ (gzip-compressed in results/):
  state_db_after_save_seeds.json  tree after Phase I (the tree that Phase II fuzzes)
  state_db_after_trimming.json    tree after Phase III
Columns: end of the epoch's Phase II (hours, from the schedule), nodes after
Phase I and Phase III (excluding the root), share of nodes removed by Phase III,
depth of the deepest node after Phase III, and branch coverage at the end of the
epoch (statistics.json). Also prints the total number of nodes added by Phase I
per campaign and, for RQ4, the number of child nodes of the benign-trace states
after the first tree extension (Phase III of epoch 2), excluding the edges of the
benign trace itself. Values are medians [min--max] over the campaigns.
"""
import sys
from common import *

CONFIGS = [('OpenThread Nexus', OT, k, rel, 24.0) for k, rel in SETTINGS.items()] + \
          [('ns-3 Wi-Fi', WIFI, '5L', SETTINGS['5L'], 10.0), ('ns-3 LTE', LTE, '5L', SETTINGS['5L'], 10.0)]


def load(path):
    return load_json(path)['transitions']


def depth(tr):
    par = {t['to_state']: t['from_state'] for t in tr}
    memo = {1: 0}

    def dp(n):
        if n not in memo:
            memo[n] = dp(par[n]) + 1
        return memo[n]
    return max((dp(n) for n in par), default=0)


def epoch_ends(n, linear, total):
    w = list(range(1, n + 1)) if linear else [1] * n
    return [total * sum(w[:k + 1]) / sum(w) for k in range(n)]


def benign_children(tr, benign):
    ch = {}
    for t in tr:
        ch.setdefault(t['from_state'], {})[tuple(t['packet'])] = t['to_state']
    nodes, cur = [1], 1
    for p in benign:
        nx = ch.get(cur, {}).get(tuple(p))
        if nx is None:
            break
        nodes.append(nx); cur = nx
    return sum(len(ch.get(n, {})) for n in nodes) - (len(nodes) - 1)


def campaign(run):
    stats = {i['iteration']: i for i in load_json(find(run, 'statistics.json'))['iterations']}
    E = []
    benign = None
    for i in iterations(run):
        bef = load(iter_file(run, i, 'state_db_before_save_seeds.json'))
        aft = load(iter_file(run, i, 'state_db_after_save_seeds.json'))
        trm = load(iter_file(run, i, 'state_db_after_trimming.json'))
        if benign is None:  # benign trace = the chain of the first Phase I tree
            nxt = {t['from_state']: t for t in aft}; benign = []; cur = 1
            while cur in nxt:
                benign.append(nxt[cur]['packet']); cur = nxt[cur]['to_state']
        br = ((stats.get(i, {}).get('coverage') or {}).get('branches') or {}).get('covered')
        E.append(dict(before=len(bef), ph1=len(aft), ph3=len(trm), rem=1 - len(trm) / len(aft), depth=depth(trm), br=br,
                      kids=benign_children(trm, benign)))
    return E


root = root_arg(sys.argv)
for tgt, rel_t, k, rel, hours in CONFIGS:
    C = [campaign(x) for x in runs(os.path.join(root, rel_t), rel)]
    n = len(C[0])
    ends = epoch_ends(n, k.endswith('L'), hours)
    print(f'=== {tgt}, {k} ({len(C)} campaigns) ===')
    for e in range(n):
        col = lambda f: [c[e][f] for c in C]
        rem = [100 * x for x in col('rem')]
        rem_s = f'{r(st.median(rem))}% [{r(min(rem))}--{r(max(rem))}]'
        br = [x for x in col('br') if x is not None]
        print(f'  {e + 1:2}  end {ends[e]:4.1f} h | Ph.I {med_range(col("ph1"))} | Ph.III {med_range(col("ph3"))} | '
              f'removed {rem_s} | depth {med_range(col("depth"))} | branches {med_range(br) if br else "-"}')
    added = [sum(ep['ph1'] - ep['before'] for ep in c) for c in C]
    print(f'  nodes added by Phase I per campaign: median {fmt(r(st.median(added)))}')
    if n > 1:
        print(f'  child nodes of benign-trace states after the first extension: median {fmt(st.median([c[1]["kids"] for c in C]))}')
    print()
