# Results of the paper's campaigns

The campaigns behind every table and figure of the paper. There are two archives:

| Archive | Contents | Needed for |
|---|---|---|
| `interceptfuzz-results.tar.gz` | per-run statistics, coverage, crash signatures, Prefix Trees | all tables and Fig. 3 (`analysis/`) |
| `interceptfuzz-raw.tar.zst` | the replayable queue and crashing inputs of every run | measuring coverage again, triaging crashes again |
| `interceptfuzz-results-aflnet-ports.tar.gz` | the same as `interceptfuzz-results.tar.gz` for AFLNet-pp and AFLNet-real | the AFLNet-pp and AFLNet-real rows and curves |
| `interceptfuzz-raw-aflnet-ports.tar.zst` | the same as `interceptfuzz-raw.tar.zst` for AFLNet-pp and AFLNet-real | measuring their coverage again, triaging their crashes again |

The `-aflnet-ports` archives hold only the added fuzzers and unpack into the same folders
as the main archives. The archives are not committed (see `.gitignore`). They are attached
to the GitHub releases of this repository:

| Release | Archives |
|---|---|
| [`arxiv-v1`](https://github.com/KULeuven-COSIC/InterceptFuzz/releases/tag/arxiv-v1) | `interceptfuzz-results.tar.gz`, `interceptfuzz-raw.tar.zst` (the campaigns of the [arXiv paper](https://arxiv.org/abs/2611.03709)) |
| [`aflnet-ports-v1`](https://github.com/KULeuven-COSIC/InterceptFuzz/releases/tag/aflnet-ports-v1) | `interceptfuzz-results-aflnet-ports.tar.gz`, `interceptfuzz-raw-aflnet-ports.tar.zst` |

Download them into this folder:

```bash
REL=https://github.com/KULeuven-COSIC/InterceptFuzz/releases/download
wget -P results/ $REL/arxiv-v1/interceptfuzz-results.tar.gz
wget -P results/ $REL/arxiv-v1/interceptfuzz-raw.tar.zst                        # only to redo measurements
wget -P results/ $REL/aflnet-ports-v1/interceptfuzz-results-aflnet-ports.tar.gz  # optional
wget -P results/ $REL/aflnet-ports-v1/interceptfuzz-raw-aflnet-ports.tar.zst     # optional
```

or, with the GitHub CLI, `gh release download arxiv-v1 -D results/` and
`gh release download aflnet-ports-v1 -D results/`.

Unpack the results archive here and regenerate the tables and figures:

```bash
tar -xzf results/interceptfuzz-results.tar.gz -C results/
tar -xzf results/interceptfuzz-results-aflnet-ports.tar.gz -C results/   # optional
./analysis/make_paper_results.sh results paper_results
```

The raw archive is only needed to redo the measurements:

```bash
mkdir -p raw && tar --zstd -xf results/interceptfuzz-raw.tar.zst -C raw/
tar --zstd -xf results/interceptfuzz-raw-aflnet-ports.tar.zst -C raw/            # optional
```

## Campaigns

| Target | Duration | Fuzzer (folder) | Campaigns |
|---|---|---|---|
| OpenThread Nexus (`openthread/BOTH/86400s`) | 24 h | `interceptfuzz/5_iter/linear` (default), `interceptfuzz/5_iter/uniform`, `interceptfuzz/10_iter/linear`, `interceptfuzz/10_iter/uniform`, `concat`, `aflnet`, `aflnet-pp`, `aflnet-real` | 10 each |
| ns-3 Wi-Fi (`ns-3-dev/WIFI/36000s`) | 10 h | `interceptfuzz/5_iter/linear`, `concat`, `aflnet`, `aflnet-pp`, `aflnet-real` | 10 each |
| ns-3 LTE (`ns-3-dev/LTE/36000s`) | 10 h | `interceptfuzz/5_iter/linear`, `concat`, `aflnet`, `aflnet-pp`, `aflnet-real` | 10 each |

AFLNet-pp and AFLNet-real ran 4 campaigns at a time, 2 cores each.

## Layout

The layout is the same as `runs/`, which `run_docker.sh` writes:
`<target>/<ROLE|PROTOCOL>/<seconds>s/<fuzzer>[/<n>_iter/<schedule>]/run_<start time>/`.

Per run in the results archive:

| File | Contents |
|---|---|
| `statistics.json` | coverage (lines, functions, branches) per InterceptFuzz epoch or at the end, executions, number of states |
| `coverage_over_time.csv` | coverage of the coverage build over the campaign (replay of the queue in discovery order) |
| `crash_summary.json` | crash signatures: output of `analysis/crashes/dedup_crashes.py` run on the run's `all_crashes/`, which also contains the crashes from the ASan replay of the non-minimized queue. Paths are relative to the run in the raw archive. |
| `coverage.json.gz` | gcovr report with per-line and per-branch counts (OpenThread: AFLNet, Concat, InterceptFuzz 5L; Table IX) |
| `fuzzer_stats` | AFL++/LibAFL/AFLNet statistics (Concat, AFLNet, AFLNet-pp, AFLNet-real; for AFLNet-real its `start_time` gives the crash TTE) |
| `state_db.json.gz` | final Prefix Tree (InterceptFuzz) |
| `iter_XX/state_db_{before_save_seeds,after_save_seeds,after_trimming}.json.gz` | Prefix Tree before Phase I, after Phase I and after Phase III of epoch XX (InterceptFuzz) |
| `iter_XX/fuzzer_stats` | AFL++ statistics of epoch XX, including its start time (InterceptFuzz) |

Per run in the raw archive:

- `replayable_queue/`: the inputs the coverage was measured on. For InterceptFuzz, this is the queue before minimization.
- `all_crashes/`, `asan_crashes/`: the crashing inputs.

`experiments/recollect_coverage.sh` replays a queue on the coverage build again, and
`analysis/crashes/dedup_crashes.py` assigns the crashing inputs to signatures again.

The coverage of the benign trace (Table II, Fig. 3) comes from a separate replay of the
benign trace. It is set in `analysis/common.py`.
