"""Shared helpers for the analysis scripts of the InterceptFuzz paper.

All scripts take the results folder as their first argument: results/ for the
paper's campaigns (see results/README.md) or runs/ for campaigns run with this
artifact; both use the same layout. Statistics follow the paper: medians with
[min--max], rounded half-up, two-sided Mann-Whitney U test (normal approximation
with tie and continuity correction, i.e. scipy's default for samples of size 10),
and the Vargha-Delaney A12 effect size.
"""
import glob, gzip, json, math, os
from decimal import Decimal, ROUND_HALF_UP
import statistics as st

OT = 'openthread/BOTH/86400s'
WIFI = 'ns-3-dev/WIFI/36000s'
LTE = 'ns-3-dev/LTE/36000s'
TARGETS = {'OpenThread Nexus': OT, 'ns-3 Wi-Fi': WIFI, 'ns-3 LTE': LTE}
# fuzzer label -> sub-folder per target
FUZZERS = {t: {'AFLNet': 'aflnet', 'Concat': 'concat', 'InterceptFuzz': 'interceptfuzz/5_iter/linear'}
           for t in TARGETS}
# epoch settings of InterceptFuzz on OpenThread Nexus (Table VI)
SETTINGS = {'5L': 'interceptfuzz/5_iter/linear', '5U': 'interceptfuzz/5_iter/uniform',
            '10L': 'interceptfuzz/10_iter/linear', '10U': 'interceptfuzz/10_iter/uniform'}
# Coverage of a replay of the benign trace (branches, lines, functions), Table II and Fig. 3
BENIGN = {'OpenThread Nexus': (2634, 11162, 3312), 'ns-3 Wi-Fi': (40496, 46106, 13567),
          'ns-3 LTE': (34375, 40955, 12219)}


def root_arg(argv):
    if len(argv) < 2 or not os.path.isdir(argv[1]):
        raise SystemExit(f'usage: {os.path.basename(argv[0])} <results folder> ...')
    return argv[1]


def runs(root, rel):
    return sorted(glob.glob(os.path.join(root, rel, 'run_*')))


def run_base(run):
    """Folder with the run's files: the run itself (results/) or the nested
    <binary>/RUN_* folder that run_interceptfuzz.sh creates (runs/)."""
    if os.path.isfile(os.path.join(run, 'statistics.json')):
        return run
    hits = glob.glob(os.path.join(run, '*', 'RUN_*', 'statistics.json'))
    return os.path.dirname(hits[0]) if hits else run


def find(run, name):
    """Path of `name` in a run, also accepting the gzip-compressed variant."""
    base = run_base(run)
    for p in (os.path.join(base, name), os.path.join(base, name + '.gz'), os.path.join(base, 'logs', name)):
        if os.path.isfile(p):
            return p
    return None


def load_json(path):
    with (gzip.open(path, 'rt') if path.endswith('.gz') else open(path)) as f:
        return json.load(f)


def iter_file(run, it, name):
    """Per-epoch file of InterceptFuzz: iter_XX/<name> (results/) or
    iter_XX/artifacts/... (runs/)."""
    base = run_base(run)
    for p in (f'iter_{it:02d}/{name}', f'iter_{it:02d}/artifacts/{name}',
              f'iter_{it:02d}/artifacts/fuzz_out/default/{name}'):
        for q in (p, p + '.gz'):
            if os.path.isfile(os.path.join(base, q)):
                return os.path.join(base, q)
    return None


def iterations(run):
    base = run_base(run)
    return sorted(int(x.split('_')[-1]) for x in os.listdir(base) if x.startswith('iter_'))


def final_stats(run):
    """Final coverage (branches, lines, functions) and execs/s from statistics.json."""
    d = load_json(find(run, 'statistics.json'))
    its = [i for i in d['iterations'] if ((i.get('coverage') or {}).get('branches') or {}).get('covered') is not None]
    c = its[-1]['coverage']
    return dict(branches=c['branches']['covered'], lines=c['lines']['covered'],
                functions=c['functions']['covered'], execs=d.get('execs_per_sec'))


def r(x):
    return int(Decimal(str(x)).quantize(Decimal('1'), ROUND_HALF_UP))


def fmt(n):
    return f'{n:,}' if isinstance(n, int) else (f'{n:,.1f}'.rstrip('0').rstrip('.') if n % 1 else f'{int(n):,}')


def med_range(v, half_up=True):
    m = st.median(v)
    m = r(m) if half_up else m
    return f'{fmt(m)} [{fmt(min(v))}--{fmt(max(v))}]'


def mannwhitney_p(x, y):
    """Two-sided Mann-Whitney U p-value, normal approximation with tie and continuity correction."""
    n1, n2 = len(x), len(y)
    allv = sorted(x + y)
    ranks = {}
    i = 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j] == allv[i]:
            j += 1
        ranks[allv[i]] = (i + j + 1) / 2
        i = j
    r1 = sum(ranks[v] for v in x)
    u1 = r1 - n1 * (n1 + 1) / 2
    u = max(u1, n1 * n2 - u1)
    n = n1 + n2
    ties = {}
    for v in allv:
        ties[v] = ties.get(v, 0) + 1
    tie_term = sum(t ** 3 - t for t in ties.values())
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1))))
    if sigma == 0:
        return 1.0
    z = (u - n1 * n2 / 2 - 0.5) / sigma
    return min(1.0, math.erfc(z / math.sqrt(2)))


def pfmt(p):
    return '< 0.001' if p < 0.001 else f'= {p:.3f}'


def a12(x, y):
    """Probability that a value from x is larger than one from y (ties count half)."""
    return sum((a > b) + 0.5 * (a == b) for a in x for b in y) / (len(x) * len(y))
