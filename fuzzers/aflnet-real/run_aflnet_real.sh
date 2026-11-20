#!/bin/bash
# =============================================================================
# Run a campaign with the real AFLNet (in-process transport, -N ipc://) and
# post-process it like fuzzers/aflnet/run_aflnet.sh:
#   $OUT_DIR/                 AFLNet output (queue/, ipsm.dot, fuzzer_stats, ...)
#   $OUT_DIR/initial_seeds/   seeds given to AFLNet (0xDEAD-delimited, like Concat)
#   $OUT_DIR/replayable_queue/    harness-format inputs, standalone_state_<ms>.bin
#   $OUT_DIR/replayable_crashes/  harness-format crashes
#   $OUT_DIR/cov_summary.txt, coverage_over_time.csv, statistics.json
# =============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR"

AFLNET_DIR="${AFLNET_DIR:-$SCRIPT_DIR/aflnet}"
TOOLS="$SCRIPT_DIR/aflnet_ipc_tools.py"
COVERAGE_SCRIPT="${COVERAGE_SCRIPT:-/workspace/common/coverage_script_gcovr.sh}"
ANALYZE_SCRIPT="${ANALYZE_SCRIPT:-/workspace/common/analyze_fuzz_iteration.py}"

OUT_DIR=""
TIMEOUT=""
FUZZ_OVERWRITE=0
COV_TARGET=""
COV_ROOT=""
FUZZ_TARGET=""
SEED_DIR=""
DELIM_SEED_DIR=""
FSM_JSON=""
ROLE="${ROLE:-}"
PROTOCOL="THREAD"       # 0xDEAD framing; THREAD_LENPREFIX = old LV framing
MAX_FRAME=0             # no cap, like Concat / AFLNet-pp
FSM_TO_DELIM_SEEDS="${FSM_TO_DELIM_SEEDS:-/workspace/fuzzers/concat/fsm_to_delim_seeds.py}"
EXEC_TIMEOUT="3000+"
AFLNET_ARGS=(-E -R -q 3 -s 3)   # ProFuzzBench defaults (state-aware, region-level)
EXTRA_AFL_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") -o DIR -t BIN [OPTIONS]

Runs the real AFLNet (patched with the in-process 'ipc://' transport).

Mandatory Arguments:
  -o, --out-dir DIR      Output directory for the campaign
  -t, --fuzz-target PATH Fuzz target built with AFLNet's afl-clang-fast

Optional Arguments:
  -T, --timeout SECONDS  Stop AFLNet after X seconds (Default: infinite)
  -w, --overwrite        Delete existing data in OUT_DIR
  Seeds (at most one; default: harvest the malicious node's frames from one run):
  -j, --fsm PATH         FSM JSON (e.g. init_fsm/both.json); seeds are generated
                         with fsm_to_delim_seeds.py, exactly like Concat
  -i, --delim-seed DIR   0xDEAD-delimited seeds (Concat format), used as is
  -s, --seed DIR         Harness-format (LV) seeds
  -R, --role ROLE        LEADER, FED or BOTH (Default: \$ROLE); used to harvest seeds
  -P, --protocol NAME    THREAD (0xDEAD framing) or THREAD_LENPREFIX (Default: $PROTOCOL);
                         the harness must be built for the same framing
  -m, --max-frame N      Cap injected frames to N bytes, 0 = no cap (Default: $MAX_FRAME)
  -e, --exec-timeout MS  AFLNet -t value (Default: $EXEC_TIMEOUT)
  -A, --afl-arg ARG      Extra afl-fuzz argument (repeatable), e.g. -A -d
  -c, --cov-target PATH  Coverage (gcov) build of the target
  -r, --cov-root PATH    Coverage root directory
  -h, --help             Show this help message and exit

Environment: AFLNET_DIR (default: $AFLNET_DIR)
EOF
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--out-dir) OUT_DIR="$2"; shift ;;
        -T|--timeout) TIMEOUT="$2"; shift ;;
        -w|--overwrite) FUZZ_OVERWRITE=1 ;;
        -R|--role) ROLE="${2^^}"; shift ;;
        -s|--seed) SEED_DIR="$2"; shift ;;
        -i|--delim-seed) DELIM_SEED_DIR="$2"; shift ;;
        -j|--fsm) FSM_JSON="$2"; shift ;;
        -P|--protocol) PROTOCOL="$2"; shift ;;
        -m|--max-frame) MAX_FRAME="$2"; shift ;;
        -e|--exec-timeout) EXEC_TIMEOUT="$2"; shift ;;
        -A|--afl-arg) EXTRA_AFL_ARGS+=("$2"); shift ;;
        -c|--cov-target) COV_TARGET="$2"; shift ;;
        -r|--cov-root) COV_ROOT="$2"; shift ;;
        -t|--fuzz-target) FUZZ_TARGET="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[!] Error: Unknown parameter passed: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [[ -z "$OUT_DIR" || -z "$FUZZ_TARGET" ]]; then
    echo "[!] Error: -o / --out-dir and -t / --fuzz-target are required." >&2
    usage
    exit 1
fi
if [[ ! -x "$AFLNET_DIR/afl-fuzz" ]]; then
    echo "[!] Error: $AFLNET_DIR/afl-fuzz not found. Run build_aflnet_real.sh first." >&2
    exit 1
fi
if [[ -z "$SEED_DIR" && -z "$DELIM_SEED_DIR" && -z "$FSM_JSON" && -z "$ROLE" ]]; then
    echo "[!] Error: one of -j/--fsm, -i/--delim-seed, -s/--seed or -R/--role (or \$ROLE) is required." >&2
    exit 1
fi
case "$PROTOCOL" in
    THREAD) FRAMING=delim ;;
    THREAD_LENPREFIX|OUTBOX) FRAMING=lenprefix ;;
    *) echo "[!] Error: unsupported protocol $PROTOCOL" >&2; exit 1 ;;
esac
if [[ "$FRAMING" == lenprefix && ( -n "$FSM_JSON" || -n "$DELIM_SEED_DIR" ) ]]; then
    echo "[!] Error: -j / -i give 0xDEAD seeds; use -s or -R with $PROTOCOL." >&2
    exit 1
fi
TOOLS_CMD=(python3 "$TOOLS" --framing "$FRAMING")

# ------------------------------------------------------------------------------
# Output directory (AFLNet refuses non-empty output directories)
# ------------------------------------------------------------------------------
if [[ -d "$OUT_DIR" && -n "$(ls -A "$OUT_DIR")" ]]; then
    if [[ "$FUZZ_OVERWRITE" -eq 1 ]]; then
        echo "[*] Overwriting $OUT_DIR"
        find "$OUT_DIR" -mindepth 1 -delete
    else
        echo "[!] Error: '$OUT_DIR' is not empty. Use -w to overwrite." >&2
        exit 1
    fi
fi
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

TMP_DIR=$(mktemp -d -t aflnet_real_XXXXXX)
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# Seeds
# ------------------------------------------------------------------------------
SEEDS="$TMP_DIR/seeds"
if [[ -n "$FSM_JSON" ]]; then
    echo "[*] Generating 0xDEAD seeds from $FSM_JSON"
    mkdir -p "$SEEDS"
    python3 "$FSM_TO_DELIM_SEEDS" -i "$FSM_JSON" -o "$SEEDS"
elif [[ -n "$DELIM_SEED_DIR" ]]; then
    echo "[*] Using 0xDEAD seeds from $DELIM_SEED_DIR"
    cp -r "$DELIM_SEED_DIR" "$SEEDS"
elif [[ -n "$SEED_DIR" ]]; then
    echo "[*] Converting harness-format seeds from $SEED_DIR"
    "${TOOLS_CMD[@]}" from-harness "$SEED_DIR" "$SEEDS"
else
    echo "[*] Harvesting the initial seed from an uninjected run (role $ROLE)"
    "${TOOLS_CMD[@]}" harvest -t "$FUZZ_TARGET" -r "$ROLE" -o "$SEEDS/seed_0"
fi

# ------------------------------------------------------------------------------
# Fuzzing
# ------------------------------------------------------------------------------
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFLNET_IPC_MAX_FRAME="$MAX_FRAME"

AFL_CMD=("$AFLNET_DIR/afl-fuzz"
    -i "$SEEDS" -o "$OUT_DIR"
    -N ipc:// -P "$PROTOCOL"
    "${AFLNET_ARGS[@]}"
    -m none -t "$EXEC_TIMEOUT"
    "${EXTRA_AFL_ARGS[@]}"
    -- "$FUZZ_TARGET" @@)

echo "[*] Starting AFLNet campaign..."
echo "    Output Dir: $OUT_DIR"
if [[ -n "$TIMEOUT" ]]; then echo "    Timeout: $TIMEOUT seconds"; else echo "    Timeout: Infinite (Press Ctrl+C to stop)"; fi
echo "    Command: ${AFL_CMD[*]}"
echo ""

if [[ -n "$TIMEOUT" ]]; then
    # SIGINT lets AFLNet write its final stats before exiting
    timeout -s INT -k 60 "$TIMEOUT" "${AFL_CMD[@]}" || true
else
    "${AFL_CMD[@]}" || true
fi

# Keep the seeds next to the results (after AFLNet created the directory)
cp -r "$SEEDS" "$OUT_DIR/initial_seeds"

# ------------------------------------------------------------------------------
# Post-processing
# ------------------------------------------------------------------------------
echo ""
echo "[*] Converting AFLNet replayable inputs to the harness format..."
"${TOOLS_CMD[@]}" to-harness --max-frame "$MAX_FRAME" "$OUT_DIR/replayable-queue" "$OUT_DIR/replayable_queue"
if [[ -d "$OUT_DIR/replayable-crashes" ]]; then
    "${TOOLS_CMD[@]}" to-harness --max-frame "$MAX_FRAME" "$OUT_DIR/replayable-crashes" "$OUT_DIR/replayable_crashes"
fi

echo "[*] Gathering continuous coverage..."
if [[ -z "$COV_TARGET" || -z "$COV_ROOT" ]]; then
    echo "    [!] No coverage target / root given. Skipping coverage."
elif [[ -d "$OUT_DIR/replayable_queue" && -n "$(ls -A "$OUT_DIR/replayable_queue")" ]]; then
    mkdir -p "$TMP_DIR/queue"
    cp -p "$OUT_DIR"/replayable_queue/* "$TMP_DIR/queue/"
    COVERAGE_CMD=(
        "$COVERAGE_SCRIPT"
        -t "$COV_TARGET"
        -s "$TMP_DIR/queue"
        -o "$OUT_DIR/cov_summary.txt"
        -c "$OUT_DIR/coverage_over_time.csv"
        -r "$COV_ROOT"
    )
    echo "    -> Executing: ${COVERAGE_CMD[*]}"
    "${COVERAGE_CMD[@]}"
else
    echo "    [!] No replayable seeds found. Skipping coverage."
fi

if [[ -f "$ANALYZE_SCRIPT" ]]; then
    python3 "$ANALYZE_SCRIPT" "$OUT_DIR"
fi

echo "[*] AFLNet campaign post-processing complete!"
