# Analysis

Scripts that turn a results folder into the tables and figures of the paper. Every
script takes the results folder as its first argument and prints its output; nothing is
written into the results. They need Python 3; the plot also needs matplotlib.

The results folder is either:

- `results/`: the paper's campaigns (see `results/README.md` for how to get them), or
- `runs/`: campaigns run with this artifact (`run_docker.sh`, `experiments/`). Both use
  the same layout.

To regenerate everything at once:

```bash
./analysis/make_paper_results.sh results paper_results
```

| Paper item | Script |
|---|---|
| Table I (integration effort) | counted manually from `targets/*/patches/interceptfuzz.patch`, no script |
| Table II (coverage), Table VI coverage columns | `coverage_table.py` |
| Table III (OpenThread crash signatures, TTE), Table IV (ns-3 signatures), Table VI signature columns | `crash_tables.py` |
| Tables V, VII, VIII (Prefix Tree per epoch), RQ3/RQ4 tree numbers in the text | `tree_tables.py` |
| RQ1/RQ3 numbers in the text taken from the coverage over time (when InterceptFuzz overtakes Concat, etc.) | `coverage_over_time_numbers.py` |
| Table IX (coverage breakdown) and the related appendix numbers (branches covered by only one fuzzer, DNS-SD) | `coverage_breakdown.py` |
| TMF numbers in the appendix text | `tmf_table.py` |
| Fig. 3 (coverage over time) | `plot_coverage_over_time.py <results> {ot,wifi,lte} out.pdf` |
| Coverage over time of all fuzzers, including AFLNet-pp and AFLNet-real | `plot_coverage_all_fuzzers.py <results> {ot,wifi,lte} out.pdf` |
| Consistency check of the coverage data | `data_check.py` |

AFLNet-pp and AFLNet-real (`aflnet-pp/`, `aflnet-real/` next to the other fuzzers) are
added to Tables II–IV whenever the results folder has runs of them; without them, the
output is that of the first paper version. For AFLNet-real, execs/s is execs_total divided
by the campaign length (its `fuzzer_stats` only has the speed at the end), and the TTE is
the time in the crashing input's name (`standalone_state_<unix ms>.bin`) minus `start_time`
in its `fuzzer_stats`.

`common.py` holds the shared parts:

- folder names, the fuzzers of the first paper version (`FUZZERS`) and the added ones (`EXTRA_FUZZERS`)
- statistics: medians with [min–max], the two-sided Mann-Whitney U test, and Vargha-Delaney Â12
- the coverage of the benign trace, which Table II and Fig. 3 use

## Crash signatures

`crashes/dedup_crashes.py` replays crashing inputs on a target binary and assigns each to a
signature with the rule files in `crashes/`. It writes the `crash_summary.json` that
`crash_tables.py` reads.

```bash
python3 analysis/crashes/dedup_crashes.py -d <run>/all_crashes -b <binary> \
    -r analysis/crashes/ot_rules.json -o <run>/crash_summary.json
```

`all_crashes/` holds the crashes of the campaign together with those found by replaying
its non-minimized queue on an AddressSanitizer build. The OpenThread signatures C3–C7
are memory errors (a SEGV and stack buffer overflows), which that replay exposes.

The ASan builds are made inside the target images (`targets/*/patches/asan.patch`), and
`crashes/asan_triage.sh` replays a queue on them and saves the crashing inputs:

```bash
# OpenThread
./build_openthread.sh -f asan
/workspace/analysis/crashes/asan_triage.sh \
    -t /workspace/openthread-asan/build/tests/fuzz/fuzz_test_form_join-fuzzer \
    -s <run>/replayable_queue -o <run>/asan_crashes

# ns-3 (Wi-Fi or LTE)
./build_ns-3-dev.sh -f asan -p WIFI
/workspace/analysis/crashes/asan_triage.sh \
    -t /workspace/ns-3-dev-asan/build/scratch/fuzz/ns3-dev-target-default \
    -s <run>/replayable_queue -o <run>/asan_crashes
```

`all_crashes/` is the union of the crashing inputs of the campaign (`replayable_crashes/`)
and those of the ASan replay (`asan_crashes/`). Create it before running `dedup_crashes.py`:

```bash
mkdir -p <run>/all_crashes
cp <run>/replayable_crashes/* <run>/asan_crashes/* <run>/all_crashes/
```

- **First match wins:** a rule matches if its text appears in the output of the crashing run, and the first matching rule in the file decides the signature.
- **OpenThread names:** `C1`–`C7` in `ot_rules.json` are the signatures of Table III. The `Excluded N` rules are signatures that are not reported in the paper. They stay in the file, so that every input keeps the signature it had in the paper.
- **ns-3 names:** every `Crash N` rule is a signature (Table IV).
