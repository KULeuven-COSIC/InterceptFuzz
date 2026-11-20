# AFLNet (real) for in-process targets

Upstream [AFLNet](https://github.com/aflnet/aflnet) (commit `96032f8`) patched with an
in-process transport, so that it can fuzz simulated stacks (the OpenThread Nexus harness)
instead of only socket servers. Apart from the transport, AFLNet is unchanged: the IPSM,
state/seed selection, M1/M2/M3 splitting, region-level mutations and the state feedback
in the bitmap behave the same way.

## Files

| File | Purpose |
|---|---|
| `aflnet-ipc.patch` | Patch against AFLNet `96032f8` (see below) |
| `build_aflnet_real.sh` | Clones AFLNet into `./aflnet`, applies the patch, builds `afl-fuzz` + `llvm_mode` |
| `run_aflnet_real.sh` | Runs one campaign and post-processes it like `fuzzers/aflnet/run_aflnet.sh` |
| `aflnet_ipc_tools.py` | Seed harvesting, format conversion, outbox trace dump |

The OpenThread side is `targets/openthread/patches/aflnet-real.patch`. It is selected with
`-f aflnet-real` in `build_openthread.sh` and `run_openthread_fuzzing.sh`. The ns-3 side
(Wi-Fi and LTE) is `targets/ns-3-dev/patches/aflnet-real.patch`, selected with
`-f aflnet-real` in `build_ns-3-dev.sh` and `run_ns-3-dev_fuzzing.sh`.

## What the patch changes

**Transport `-N ipc://`** (`afl-fuzz.c`). AFLNet normally sends the messages over a socket
*after* the target has been spawned. With `ipc://`:

1. Before the run (`ipc_deliver`), all messages are written to the test case file (`@@`) in
   the harness format. With `-P THREAD` it is `{[frame] DE AD}*`, the input format of
   Concat and AFLNet-pp: each message is split on `0xDEAD` exactly like the harness
   does and re-emitted with a canonical delimiter, so every injected frame maps to its
   message. With `-P THREAD_LENPREFIX` (the previous format) it is
   `[u32 BE total]{[u32 BE len][frame]}*` with every frame header recomputed.
   `AFLNET_IPC_MAX_FRAME` optionally caps frames (default in `run_aflnet_real.sh`: no cap, like
   Concat).
2. After the run (`ipc_collect`), the shared-memory outbox (`OUTBOX_SHMEM_ID`) is read into
   `response_buf`. `response_bytes[i]` is set to the outbox offset where the first frame of
   the next consumed message was injected, which is the cumulative meaning it has with
   sockets. `messages_sent` is the number of messages the target actually consumed.

Everything else reads only these three variables, exactly as it does with sockets.

**Protocol `-P THREAD`** (`aflnet.c`)

- Requests: a region is everything up to and including `0xDEAD`, a remainder without
  delimiter is the last region. This is the region parser of AFLNet-pp, the same pattern
  as AFLNet's text protocols (RTSP regions end with `\r\n\r\n`).
- `-P THREAD_LENPREFIX` (alias `OUTBOX`): `[u32 BE len][frame]` regions, header included.
  Needs a harness built with the old LV parser.
- States: the type byte of every outbox entry with direction `0x01`, plus 1. AFLNet reserves
  0 for the initial state, and MLE Link Request is type 0.

**Build**

- The LLVM pass is ported to the new pass manager, so it builds with clang-18, the same
  compiler the other fuzzers use. It still builds with the legacy pass manager on old LLVM.
- `MAP_SIZE_POW2` is configurable (default 18 here, 16 upstream). AFLNet uses the lower half
  of the bitmap for state transitions and the upper half for code coverage.
- The target **must** be compiled with this `afl-clang-fast` (AFL++ instrumentation would
  write into the state half and use a different fork server protocol).

## Outbox convention (harness side)

`[u32 total]{[u8 dir][u8 type][u32 BE len][payload]}*`. `aflnet-real.patch` writes:

| dir | LEADER / FED | BOTH |
|---|---|---|
| `0x01` | frames of the target node | original frame of any node (before replacement) |
| `0x02` | frames injected from the test case | frames injected from the test case |
| `0x00` | malicious node's frames passed through after the input ran out | — |

`type` comes from `thread_dissector::GetPacketType`, the same codes as the AFLNet (LibAFL) harness (`aflnet.patch`).

ns-3 (`aflnet-real.patch`, `aflnet-pp.patch`): every intercepted frame is traced
as for BOTH, since both nodes are targets and injectors. `0x01` is the frame the node wanted
to send (before injection), `0x02` the frame injected from the test case. `type` is the
code of `aflnet.patch`: the 802.11 frame type for Wi-Fi (the MAC header isn't fuzzed),
the RRC message type of the send function for LTE. `-P THREAD` is used as is: the parser
and the state extraction only depend on `0xDEAD` and the outbox format, not on Thread.

## Usage

```bash
./build_aflnet_real.sh                     # once (done in the Docker image)
# inside /workspace of the openthread image:
./build_openthread.sh -f aflnet-real
./run_openthread_fuzzing.sh -f aflnet-real -T 3600
# inside /workspace of the ns-3-dev image:
./build_ns-3-dev.sh -f aflnet-real -p WIFI     # or LTE
./run_ns-3-dev_fuzzing.sh -f aflnet-real -p WIFI -T 3600
```

Seeds are the same as for Concat and AFLNet-pp: by default they are generated from
`init_fsm/` with `fsm_to_delim_seeds.py`. `-j` selects another FSM, `-s` a
directory of `0xDEAD` seeds. `run_aflnet_real.sh` itself also accepts LV seeds
(`-s`). Given only `-R`, it harvests the malicious node's
own frames from one uninjected run. AFLNet runs with the ProFuzzBench defaults
`-E -R -q 3 -s 3`; add more with `-- -A -d` (forwarded to `run_aflnet_real.sh`).

The harness (`aflnet-real.patch`) is the AFLNet-pp harness (Concat's `0xDEAD`
parser plus the outbox tracing). The only difference is a plain `main()` instead of the
libFuzzer runtime, because the target has to be compiled with AFLNet's `afl-clang-fast`.

Results in the run directory:

- AFLNet's own output: `queue/`, `ipsm.dot`, `fuzzer_stats`, `replayable-queue/`, …
- `replayable_queue/` and `replayable_crashes/`: LV-format `standalone_state_<ms>.bin`
  files (what the coverage build reads; same conversion as `delim_to_lv_seeds.py`), named
  by discovery time like AFLNet (LibAFL).
- `cov_summary.txt` and `statistics.json`.

Debugging:

```bash
python3 aflnet_ipc_tools.py trace -t <fuzz target> -i <LV-format input>
python3 aflnet_ipc_tools.py trace -t <fuzz target> -i out/queue/id:000000* --aflnet
```
