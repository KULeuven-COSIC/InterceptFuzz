# InterceptFuzz

Artifact for the InterceptFuzz paper: the fuzzer, the two fuzzers it is compared with, the
patched targets, and everything needed to rerun the evaluation in Docker.

| Fuzzer | Directory | What it does |
|---|---|---|
| **InterceptFuzz** | `fuzzers/interceptfuzz/` | Intercepts packets inside the running protocol stack and mutates them in place. Runs AFL++ over several iterations and carries the reached states over from one iteration to the next. |
| **Concat** | `fuzzers/concat/` | AFL++ on a whole packet sequence. Packets are separated by a `0xDEAD` delimiter. |
| **AFLNet** | `fuzzers/aflnet/` | AFLNet reimplemented on LibAFL (state-aware, with the in-process transport). |

| Target | Version | Harness | Paper experiment |
|---|---|---|---|
| OpenThread (Nexus simulation) | `01bce95b` | form/join test, all nodes malicious (`BOTH`) | 24 h |
| ns-3 Wi-Fi | ns-3-dev `be3db7b6` | minimal Wi-Fi scenario | 10 h |
| ns-3 LTE | ns-3-dev `be3db7b6` | minimal LTE scenario | 10 h |

## Requirements

- x86-64 Linux with Docker
- Disk space:
  - about 15 GB for the three images (base 7.2 GB, OpenThread +1.8 GB, ns-3 +2.8 GB)
  - about 2 GB for each campaign running at the same time (the target builds inside its container)
  - room for the results
- Two cores per campaign. The paper runs every configuration 10 times.

## Getting the code

The LibAFL components AFLNet builds on are a git submodule:

```bash
git clone --recursive <repository URL> InterceptFuzz
# or, in an existing clone:
git submodule update --init
```

## Building the images

```bash
./build_docker.sh              # base image + both target images
./build_docker.sh -t openthread
./build_docker.sh -t ns-3-dev
```

The images are:

- `interceptfuzz-base`: Ubuntu 22.04, clang-18, AFL++ `247e8241`, Rust, the AFLNet (LibAFL) binary, and the InterceptFuzz library.
- `interceptfuzz-openthread` and `interceptfuzz-ns-3-dev`: the target sources, with one patched tree per fuzzer plus a coverage tree.

The targets themselves are compiled when a campaign starts (`-b`). A shared ccache in
`.ccache/` makes later builds fast.

## Running a campaign

`run_docker.sh` starts one container. Anything other than `-t`/`-C`/`--coverage` is passed
on to the target's run script (`targets/<target>/run_*_fuzzing.sh`, see `-h`).

```bash
# OpenThread, 24 h
./run_docker.sh -t openthread -C 0-1 -f interceptfuzz -n 5 -D linear -T 86400 -b
./run_docker.sh -t openthread -C 2-3 -f concat -T 86400 -b
./run_docker.sh -t openthread -C 4-5 -f aflnet -T 86400 -b

# ns-3, 10 h
./run_docker.sh -t ns-3-dev -C 0-1 -f interceptfuzz -p WIFI -n 5 -D linear -T 36000 -b
./run_docker.sh -t ns-3-dev -C 2-3 -f concat -p LTE -T 36000 -b
./run_docker.sh -t ns-3-dev -C 4-5 -f aflnet -p WIFI -T 36000 -b
```

For a quick functional check, use `-T 120`.

InterceptFuzz options:

- `-n`: number of iterations.
- `-D`: how the time budget is split over the iterations (`linear` or `uniform`).

Concat starts from seeds generated from the initial state machine in
`targets/<target>/init_fsm/`. AFLNet starts from the packets the harness records in a
first, unmodified run.

## Reproducing the paper's experiments

`experiments/run_experiments.sh` runs every configuration of a target one after another on
the given cores. Start one instance per core pair to run campaigns in parallel:

```bash
# OpenThread (BOTH), 24 h:
#   InterceptFuzz {5,10} iterations x {linear,uniform}, Concat, AFLNet
./experiments/run_experiments.sh -t openthread -C 0-1 -n 10

# ns-3, 10 h: InterceptFuzz 5 iterations x {linear,uniform}, Concat, AFLNet
./experiments/run_experiments.sh -t ns-3-dev -p WIFI -C 2-3 -n 10
./experiments/run_experiments.sh -t ns-3-dev -p LTE  -C 4-5 -n 10
```

`-n` sets the number of repetitions. `-f <fuzzer>` restricts the run to one fuzzer.

## Results

Each campaign writes to `runs/<target>/<ROLE|PROTOCOL>/<seconds>s/<fuzzer>/[<n>_iter/<strategy>/]run_<timestamp>/`.
A run directory contains:

- `statistics.json`: line, function and branch coverage per iteration, the number of states, and execution counts.
- `coverage_over_time.csv`: coverage of the coverage build over the campaign.
- `replayable_queue/`: all generated inputs in a replayable format, named by discovery time.
- crashes, when there are any.
- the fuzzer's own output (`fuzzer_stats`, queue, …).

Coverage is measured with gcov/gcovr on a separate uninstrumented build (`*-cov`). Each
input is replayed there, so all fuzzers are measured the same way.

To collect the coverage of finished runs again (for example with other gcovr options):

```bash
./experiments/recollect_coverage.sh -t openthread -d runs/openthread/BOTH/86400s/concat -c 0-7 -- -r BOTH -b
./experiments/recollect_coverage.sh -t ns-3-dev -d runs/ns-3-dev/WIFI/36000s/aflnet -c 0-7 -- -p WIFI -b
```

InterceptFuzz records the final coverage of a campaign. To get the cumulative coverage
after each iteration (written to `iter_XX/artifacts/coverage_before_minimize.txt` and picked
up by `statistics.json`), run inside the target image:

```bash
docker run --rm -v "$PWD/runs/openthread:/workspace/results" --entrypoint bash interceptfuzz-openthread -c \
  "./build_openthread.sh -f coverage && \
   /workspace/fuzzers/interceptfuzz/scripts/collect_iteration_coverage.sh openthread /workspace/results/<path to RUN_* dir> && \
   python3 /workspace/common/analyze_fuzz_iteration.py /workspace/results/<path to RUN_* dir>"
```

## Reproducing the tables and figures

The campaigns of the paper are published as archives (see `results/README.md`).
`analysis/` regenerates every table and Fig. 3 from them, and works the same way on
your own campaigns in `runs/`:

```bash
./analysis/make_paper_results.sh results paper_results   # the paper's campaigns
./analysis/make_paper_results.sh runs    my_results      # your campaigns
```

## Repository layout

```
Dockerfile, build_docker.sh, run_docker.sh   base image and container helpers
fuzzers/
  interceptfuzz/   InterceptFuzz library (src/, include/, CMake package InterceptFuzz)
                   and campaign driver (scripts/run_interceptfuzz.sh)
  concat/          Concat driver and seed conversion
  aflnet/          AFLNet on LibAFL (Rust)
common/            coverage replay (gcovr), run statistics, coverage re-collection
third_party/
  butterfly/       LibAFL components for stateful fuzzing (git submodule)
  netfuzzbench-common/   packet-sequence input and mutators for LibAFL
targets/
  openthread/      Dockerfile, build/run scripts, initial FSM, patches per fuzzer
  ns-3-dev/        same for ns-3 (Wi-Fi and LTE)
experiments/       campaign queue and coverage re-collection used for the paper
analysis/          tables and figures of the paper, crash triage (crashes/)
results/           the paper's campaigns (downloaded, see results/README.md)
```

Each target has four patches:

- `interceptfuzz.patch`, `concat.patch`, `aflnet.patch`: the fuzzing harness and the interception hooks for that fuzzer.
- `coverage.patch`: the coverage build.

## Using InterceptFuzz on another stack

The InterceptFuzz library (`fuzzers/interceptfuzz`, installed in the base image) needs
three additions to a protocol stack. These are exactly what `targets/*/patches/interceptfuzz.patch` adds.

**1. Turn an existing integration test into the fuzz harness.**

```cpp
#include <InterceptFuzz/InterceptFuzz.hpp>

INTERCEPTFUZZ_TEST(FormJoin)
{
    ot::Nexus::TestFormJoin();   // the unmodified test scenario
}
```

**2. Call the fuzzer where packets enter the stack.** Use the first form for a mutable
buffer, and the second for packet objects that cannot be changed in place:

```cpp
#include <InterceptFuzz/InterceptFuzz.hpp>

// OpenThread: radio frame buffer
rxFrame.mLength = InterceptFuzz::intercept(rxFrame.mPsduBuffer, rxFrame.mLength, OT_RADIO_FRAME_MAX_SIZE);

// ns-3: immutable Packet
std::vector<uint8_t> bytes(packet->GetSize());
packet->CopyData(bytes.data(), bytes.size());
std::vector<uint8_t> fuzzed = InterceptFuzz::intercept_copy(bytes.data(), bytes.size(), max_len);
packet = Create<Packet>(fuzzed.data(), fuzzed.size());
```

**3. Link it.**

```cmake
find_package(InterceptFuzz CONFIG REQUIRED)
target_link_libraries(<stack library>  PUBLIC  InterceptFuzz::interceptfuzz)  # code with intercept() calls
target_link_libraries(<harness binary> PRIVATE InterceptFuzz::harness)        # adds -fsanitize=fuzzer
```

Compile the stack with AFL++ (`afl-clang-lto` or `afl-clang-fast`).
`fuzzers/interceptfuzz/scripts/run_interceptfuzz.sh -t <harness binary> -n <iterations> -T <seconds>`
runs a campaign. Set `INTERCEPTFUZZ_VERBOSE=1` to print every intercepted packet before
and after the fuzzer.

## License

See `LICENSE`. `third_party/` keeps the licenses of the respective projects.
