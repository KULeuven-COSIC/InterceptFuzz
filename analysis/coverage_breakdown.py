#!/usr/bin/env python3
"""Per-directory and per-file branch coverage on OpenThread Nexus
(Appendix B: Table tab:cov_breakdown and the numbers in its text).

Usage:  python3 coverage_breakdown.py <results folder>

Reads the gcovr JSON reports (coverage.json.gz) of AFLNet, Concat and
InterceptFuzz (5 epochs, linear). A branch counts as covered if its count > 0.
Directories are the subdirectories of src/core; "Other" is everything else.
Medians are rounded half-up. Prints the LaTeX rows of the table, the number of
branches covered only by InterceptFuzz / only by Concat across all campaigns
(branch key: file, line, function, branch number), the same comparison between
InterceptFuzz and AFLNet (branch key without the function name, as in the paper), and
the number of campaigns
that reach the DNS-SD server (more than 5 branches in dnssd_server.cpp).
"""
import gzip, json, glob, collections, statistics as st, re, sys, os
from decimal import Decimal, ROUND_HALF_UP
from common import OT as OT_REL, FUZZERS, runs, find, root_arg

root = root_arg(sys.argv)
OT = os.path.join(root, OT_REL)
G = {'AFLNet': FUZZERS['OpenThread Nexus']['AFLNet'],
     'SC': FUZZERS['OpenThread Nexus']['Concat'],
     'IF': FUZZERS['OpenThread Nexus']['InterceptFuzz']}
D = ['thread', 'meshcop', 'coap', 'net', 'mac', 'common', 'utils', 'crypto']
FILES = ['coap/coap.cpp', 'meshcop/secure_transport.cpp', 'thread/address_resolver.cpp',
         'thread/network_data_leader_ftd.cpp', 'coap/coap_message.cpp', 'meshcop/dataset_manager.cpp',
         'thread/tmf.cpp', 'thread/lowpan.cpp', 'net/dns_types.cpp', 'net/dnssd_server.cpp',
         'thread/mesh_forwarder.cpp', 'net/ip6_mpl.cpp',
         # further files with the largest differences between InterceptFuzz and AFLNet
         'thread/mle.cpp', 'thread/mle_ftd.cpp', 'thread/network_data.cpp', 'thread/router_table.cpp', 'thread/indirect_sender.cpp']

def load(sub):
  out = []
  for run in runs(OT, sub):
    f = find(run, 'coverage.json.gz')
    if f is None:
      raise SystemExit(f'{run}: no coverage.json.gz')
    d = json.load(gzip.open(f))
    tot = 0; dirs = collections.Counter(); fil = collections.Counter(); brs = set()
    for F in d['files']:
      path = F['file']; m = re.match(r'src/core/([^/]+)/', path); dk = m.group(1) if m else 'other'
      for L in F['lines']:
        for b in L.get('branches', []):
          if b['count'] > 0:
            tot += 1; dirs[dk] += 1; fil[path] += 1
            brs.add((path, L['line_number'], L.get('function_name'), b['branchno']))
    out.append(dict(f=f, tot=tot, dirs=dirs, fil=fil, brs=brs))
  return out

def r(x): return int(Decimal(str(x)).quantize(Decimal('1'), ROUND_HALF_UP))
def fmt(n): return f'{n:,}'
def cell(v): return f'{fmt(r(st.median(v)))} {{\\scriptsize [{fmt(min(v))}--{fmt(max(v))}]}}'
def sgn(dd): return ('$+$' if dd > 0 else '$-$' if dd < 0 else '') + fmt(abs(dd))
def row(name, vals):
  m = [r(st.median(v)) for v in vals]
  return f'\t\t\t{name} & ' + ' & '.join(cell(v) for v in vals) + f' & {sgn(m[2] - m[1])} & {sgn(m[2] - m[0])} \\\\'

res = {g: load(p) for g, p in G.items()}
for g, v in res.items(): print(f'% {g}: {len(v)} campaigns')
order = ['AFLNet', 'SC', 'IF']
for k in D: print(row(f'\\texttt{{{k}}}', [[x['dirs'][k] for x in res[g]] for g in order]))
print(row('Other', [[x['tot'] - sum(x['dirs'][k] for k in D) for x in res[g]] for g in order]))
print(row('\\textbf{Total}', [[x['tot'] for x in res[g]] for g in order]))
for fi in FILES:
  vals = [[sum(c for p, c in x['fil'].items() if p.endswith('/' + fi)) for x in res[g]] for g in order]
  print(row('\\texttt{' + fi.split('/')[1].replace('_', '\\_') + '}', vals))
u = {g: set().union(*(x['brs'] for x in res[g])) for g in order}
print(f"% branches only IF: {len(u['IF'] - u['SC'])}, only SC: {len(u['SC'] - u['IF'])}")
# The IF/AFLNet numbers in the paper use the branch key without the function name.
v = {g: {(p, l, b) for p, l, f, b in u[g]} for g in order}
print(f"% branches covered by IF but never by AFLNet: {len(v['IF'] - v['AFLNet'])}, of which also by SC: {len((v['IF'] - v['AFLNet']) & v['SC'])}; "
      f"covered by AFLNet but never by IF: {len(v['AFLNet'] - v['IF'])}  (key: file, line, branch number)")
for g in order:
  n = sum(1 for x in res[g] if sum(c for p, c in x['fil'].items() if p.endswith('dnssd_server.cpp')) > 5)
  print(f'% {g}: DNS-SD server reached in {n} of {len(res[g])} campaigns')
