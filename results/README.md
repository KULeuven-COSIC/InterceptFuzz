# Results of the paper's campaigns

The campaigns behind every table and figure of the paper. There are two archives:

| Archive | Contents | Needed for |
|---|---|---|
| `interceptfuzz-results.tar.gz` | per-run statistics, coverage, crash signatures, Prefix Trees | all tables and Fig. 3 (`analysis/`) |
| `interceptfuzz-raw.tar.zst` | the replayable queue and crashing inputs of every run | measuring coverage again, triaging crashes again |

Both archives are kept in this folder and are not committed (see `.gitignore`).
TODO: publish them (e.g. on Zenodo) and link them here.

Unpack the results archive here and regenerate the tables and figures:

```bash
tar -xzf results/interceptfuzz-results.tar.gz -C results/
./analysis/make_paper_results.sh results paper_results
```

The raw archive is only needed to redo the measurements:

```bash
mkdir -p raw && tar --zstd -xf results/interceptfuzz-raw.tar.zst -C raw/
```

## Campaigns

| Target | Duration | Fuzzer (folder) | Campaigns |
|---|---|---|---|
| OpenThread Nexus (`openthread/BOTH/86400s`) | 24 h | `interceptfuzz/5_iter/linear` (default), `interceptfuzz/5_iter/uniform`, `interceptfuzz/10_iter/linear`, `interceptfuzz/10_iter/uniform`, `concat`, `aflnet` | 10 each |
| ns-3 Wi-Fi (`ns-3-dev/WIFI/36000s`) | 10 h | `interceptfuzz/5_iter/linear`, `concat`, `aflnet` | 10 each |
| ns-3 LTE (`ns-3-dev/LTE/36000s`) | 10 h | `interceptfuzz/5_iter/linear`, `concat`, `aflnet` | 10 each |

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
| `fuzzer_stats` | AFL++/LibAFL statistics (Concat, AFLNet) |
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
