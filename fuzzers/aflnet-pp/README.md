# AFLNet on AFL++ ("AFLNet-pp")

AFLNet's algorithm ported onto the **same AFL++ version** (commit `247e8241`) used by
Concat and InterceptFuzz. The goal is a controlled comparison: AFLNet-pp and
Concat share the engine, compiler, instrumentation, harness, input format and
seeds. They differ only in the AFLNet algorithm.

## Files

| File | Purpose |
|---|---|
| `aflnet-pp.patch` | Patch against AFL++ `247e8241` |
| `build_aflnet_pp.sh` | Clones AFL++ into `./aflpp`, applies the patch, builds `afl-fuzz` |
| `run_aflnet_pp.sh` | `fuzzers/concat/run_concat.sh` with two changes: the AFLNet-pp `afl-fuzz` binary and the `AFLNET_*` settings |
| `targets/openthread/patches/aflnet-pp.patch` | Harness: the outbox tracing of AFLNet-real, plus Concat's libFuzzer entry point and `0xDEAD` parser |
| `targets/ns-3-dev/patches/aflnet-pp.patch` | The same for ns-3 (Wi-Fi and LTE), based on `aflnet.patch` |

## Usage

```bash
# inside the openthread container (/workspace)
./build_openthread.sh -f aflnet-pp
./run_openthread_fuzzing.sh -f aflnet-pp -T 3600

# inside the ns-3-dev container (/workspace)
./build_ns-3-dev.sh -f aflnet-pp -p WIFI      # or LTE
./run_ns-3-dev_fuzzing.sh -f aflnet-pp -p WIFI -T 3600
```

Seeds, output layout (`default/queue`, `replayable_queue/`, `logs/coverage_after_fuzzing.txt`,
`statistics.json`) and post-processing are exactly those of Concat. AFLNet's state
machine is written to `default/ipsm.dot`.

Settings (environment variables; AFLNet's option letters collide with AFL++'s):

| Variable | AFLNet option | Default in `run_aflnet_pp.sh` |
|---|---|---|
| `AFLNET_PROTOCOL=DELIM` | `-P` (region parser) | `DELIM` |
| `AFLNET_DELIM` | | `DEAD` |
| `AFLNET_STATE_AWARE` | `-E` | `1` |
| `AFLNET_REGION_MUTATION` | `-R` | `1` |
| `AFLNET_STATE_SELECTION` | `-q` | `3` (favor) |
| `AFLNET_SEED_SELECTION` | `-s` | `3` (favor) |
| `AFLNET_SEED_SCHEDULE` | `-h` | `2` (IPSM) if state aware, else `1` |

This is the same configuration as the AFLNet-real runs (`-E -R -q 3 -s 3`).

## What comes from where

**AFL++ (engine), unchanged:**
- mutation operators (havoc, including its splice-in-havoc operators)
- deterministic stages (incl. skipdet)
- power schedule (`perf_score`)
- coverage feedback and instrumentation
- fork server
- stage scheduling

**AFLNet, ported as in AFLNet (commit `96032f8`), nothing added:**
- regions per queue entry; for the initial seeds they are extracted by the protocol parser
- `kl_messages`, M1/M2/M3 selection, mutating only M2, and rebuilding the sequence in
  `common_fuzz_stuff` (incl. the `max_seed_region_count` cap)
- the IPSM state machine, `update_state_aware_variables`, region annotations
- state selection (`choose_target_state`) and seed selection (`choose_seed`), incl. its
  skip probabilities, `was_fuzzed_map`, and the `paths`/`fuzzs`/`selected_times`/
  `paths_discovered` bookkeeping
- the IPSM seed schedule: target state → `cull_queue` → seed, replacing AFL++'s queue
  selection
- AFLNet's `cull_queue` changes: initial seeds stay favored, and `pending_favored` is
  state-aware
- region-level havoc mutations (AFLNet's havoc cases 17–20, i.e. 4 of 21 choices)
- saving only the consumed messages of the whole sequence (queue entries, crashes, hangs)
- `replayable-new-ipsm-paths/`, `ipsm.dot`
- AFLNet's **removals**:
  - no trimming
  - no calibration retry in `fuzz_one`
  - no separate splice stage (AFLNet never enables it in IPSM mode; AFL++ only with `-u`,
    which is rejected)
  - in state-aware mode, `fuzz_one` doesn't apply AFL++'s favored-skip check; `choose_seed`
    does that instead

**Necessary adaptations (no new behaviour):**
- *Transport:* the in-process transport of AFLNet-real replaces sockets. The whole
  sequence is written to the test case before the run; the outbox is read afterwards into
  `response_buf`/`response_bytes`. Each frame is mapped to its message, so
  `response_bytes[i]` has AFLNet's cumulative meaning.
- *Region parser for `0xDEAD`:* a region is everything up to and including the
  delimiter, the same pattern as AFLNet's text protocols (e.g. RTSP's `\r\n\r\n`). State
  codes come from the outbox, like `-P THREAD` in AFLNet-real.
- *AFL++'s per-entry deterministic-stage state* (`skipdet` maps) is sized by the input
  length. Since M2 of an entry changes with the target state, that state is reset when the
  M2 length changes. Without the reset the maps would be overrun.
- *AFLNet-specific per-entry data* lives in a side table indexed by `queue_entry->id`
  (AFLNet's `q->index`).

**Not ported:**
- the socket transport
- state feedback in the bitmap (`-b 2/3`; AFLNet's default `-b 1` is what's used)
- the hybrid schedule (`-h 3`)
- parallel fuzzing (`-M`/`-S`)
- AFLNet's debug output (`regions/`, `replayable-queue/`)

These are rejected with an error where they map to AFL++ options: CmpLog `-c`, MOpt `-L`,
custom mutators, `-u`, explicit `-M`/`-S`. A single default instance runs as `-S default`,
exactly like Concat.

With `AFLNET_PROTOCOL` unset, the binary behaves as plain AFL++.

## Validation done

- builds with clang-18 without warnings; the patch applies to pristine AFL++ `247e8241`
- 4-minute AddressSanitizer run (state-aware, region mutations): no errors (234k execs,
  1,061 queue entries); 60 s in non-state-aware mode and 30 s in plain AFL++ mode, also clean
- `response_bytes[]` checked by hand against the outbox trace (exact)
- end-to-end through `build_openthread.sh` / `run_openthread_fuzzing.sh` (60 s): coverage
  and statistics produced like Concat, same coverage totals
