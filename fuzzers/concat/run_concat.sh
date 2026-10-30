#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

############################################
# Ctrl+C / SIGTERM handling (kill whole group)
############################################
on_abort() {
  echo -e "\n[!] Ctrl+C (or SIGTERM) detected — stopping all children..."
  trap - INT TERM           # avoid recursive traps
  kill -TERM 0 2>/dev/null || true   # signal entire process group
  sleep 1
  kill -KILL 0 2>/dev/null || true
  exit 130
}
trap on_abort INT TERM

############################################
# Paths & Defaults
############################################
FSM_TO_DELIM_SEEDS="/workspace/fuzzers/concat/fsm_to_delim_seeds.py"
DELIM_TO_LV_SEEDS="/workspace/fuzzers/concat/delim_to_lv_seeds.py"
COVERAGE_SCRIPT_PATH="/workspace/common/coverage_script_gcovr.sh"
GCOV_WRAPPER_SCRIPT="/workspace/common/gcov-wrapper.sh"

TIMEOUT_SEC="3600" # Default 1 hour
USE_SUDO=0
TARGET=""
OUT_DIR=""
SEEDS_IN=""
FSM_JSON=""

# Coverage Defaults
COV_TARGET=""
COV_ROOT=""
GCOVR_FILTER_OPTS=()

AFL_STATIC_OPTS=()
FUZZER_EXTRA_OPTS=()
TARGET_EXTRA_OPTS=()
COV_SCRIPT_EXTRA_ARGS=()

############################################
# Usage
############################################
usage() {
  cat <<'EOF'
Usage: run_delim_fuzzer.sh -t /path/to/target -o /path/to/output [options]

Required:
  -t PATH    Target binary/executable to fuzz
  -o PATH    Output directory for AFL and artifacts

Input (Provide exactly ONE of these):
  -i PATH    Directory containing initial delimiter-based seeds
  -j PATH    Path to FSM JSON (will generate delim seeds automatically)

Common options:
  -T SEC     Fuzzing timeout in seconds (default: 3600)
  -s         Run target and fuzzer with 'sudo -E'
  -v         Verbose (set -x)

Fuzzer/Target flags:
  -A "FLAGS" Add custom flags for AFL. (e.g. -A "-M main")
  -F "FLAGS" Add custom flags for the target binary. (e.g. -F "--enable-foo")

Coverage flags (Optional):
  -c PATH    Coverage target binary/executable to gather the coverage from
  -r PATH    Coverage root folder
  -f "FLAGS" Coverage filter options. (e.g. -f "src/wifi/.*")
EOF
}

############################################
# Parse args
############################################
VERBOSE=0

while getopts ":t:o:i:j:T:c:r:f:A:F:sv" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    i) SEEDS_IN="$OPTARG" ;;
    j) FSM_JSON="$OPTARG" ;;
    T) TIMEOUT_SEC="$OPTARG" ;;
    c) COV_TARGET="$OPTARG" ;;
    r) COV_ROOT="$OPTARG" ;;
    f) read -r -a _tmpCovF <<<"$OPTARG"; GCOVR_FILTER_OPTS+=("${_tmpCovF[@]}") ;;
    A) read -r -a _tmpA <<<"$OPTARG"; FUZZER_EXTRA_OPTS+=("${_tmpA[@]}") ;;
    F) read -r -a _tmpF <<<"$OPTARG"; TARGET_EXTRA_OPTS+=("${_tmpF[@]}") ;;
    s) USE_SUDO=1 ;;
    v) VERBOSE=1 ;;
    :) echo "Missing value for -$OPTARG" >&2; usage; exit 2 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))
[[ ${VERBOSE} -eq 1 ]] && set -x

############################################
# Validation & Setup
############################################
[[ -n "$TARGET" ]] || { echo "Error: -t TARGET is required." >&2; usage; exit 2; }
[[ -n "$OUT_DIR" ]] || { echo "Error: -o OUT_DIR is required." >&2; usage; exit 2; }

if [[ -z "$SEEDS_IN" && -z "$FSM_JSON" ]]; then
    echo "Error: You must provide either -i (seeds dir) or -j (FSM JSON)." >&2
    usage; exit 2;
fi

# Set the sudo prefix based on the -s flag
SUDO_CMD=()
if [[ "$USE_SUDO" -eq 1 ]]; then
  SUDO_CMD=(sudo -E)
  COV_SCRIPT_EXTRA_ARGS+=(-S)
fi

if [[ ${#GCOVR_FILTER_OPTS[@]} -gt 0 ]]; then
    for filter in "${GCOVR_FILTER_OPTS[@]}"; do
        COV_SCRIPT_EXTRA_ARGS+=(-f "$filter")
    done
fi

mkdir -p "$OUT_DIR"
ITER_LOG_ROOT="${OUT_DIR}/logs"
mkdir -p "$ITER_LOG_ROOT"

echo "============================================"
echo "[*] Target: $TARGET"
echo "[*] Output Dir: $OUT_DIR"
echo "[*] Timeout: ${TIMEOUT_SEC}s"
echo "============================================"

############################################
# 1. Prepare Initial Seeds
############################################
if [[ -n "$FSM_JSON" ]]; then
    echo "[*] FSM JSON provided. Generating delimiter-based seeds..."
    SEEDS_IN="${OUT_DIR}/initial_delim_seeds"
    mkdir -p "$SEEDS_IN"
    
    # Run the script to generate delim seeds from the FSM
    python3 "$FSM_TO_DELIM_SEEDS" -i "$FSM_JSON" -o "$SEEDS_IN"
else
    echo "[*] Using provided initial seeds directory: $SEEDS_IN"
fi

############################################
# 2. Run AFL
############################################
echo "[*] Starting fuzzing session..."

AFL_CMD=("${SUDO_CMD[@]}" afl-fuzz "${AFL_STATIC_OPTS[@]}" "${FUZZER_EXTRA_OPTS[@]}" \
            -V "$TIMEOUT_SEC" -o "$OUT_DIR" -i "$SEEDS_IN" -- "${TARGET}" "@@" "${TARGET_EXTRA_OPTS[@]}")

echo "Running AFL command: ${AFL_CMD[*]}"
"${AFL_CMD[@]}" || true

############################################
# 3. Convert Queue to LV Format
############################################
# Assuming AFL names the main fuzzer instance 'default'. 
# If using -M main, adjust this to "${OUT_DIR}/main/queue"
QUEUE_DIR="${OUT_DIR}/default/queue"
REPLAYABLE_QUEUE_DIR="${OUT_DIR}/replayable_queue"

if [[ -d "$QUEUE_DIR" ]]; then
    echo "[*] Fuzzing complete. Converting AFL queue to LV format..."
    mkdir -p "$REPLAYABLE_QUEUE_DIR"
    python3 "$DELIM_TO_LV_SEEDS" -i "$QUEUE_DIR" -o "$REPLAYABLE_QUEUE_DIR"
else
    echo "[-] Warning: AFL queue directory ($QUEUE_DIR) not found. Did AFL run successfully?"
    exit 1
fi

CRASHES_DIR="${OUT_DIR}/default/crashes"
REPLAYABLE_CRASHES_DIR="${OUT_DIR}/replayable_crashes"

if [[ -d "$CRASHES_DIR" ]]; then
    echo "[*] Fuzzing complete. Converting AFL crashes to LV format..."
    mkdir -p "$REPLAYABLE_CRASHES_DIR"
    python3 "$DELIM_TO_LV_SEEDS" -i "$CRASHES_DIR" -o "$REPLAYABLE_CRASHES_DIR" || true
else
    echo "[-] Warning: AFL crashes directory ($CRASHES_DIR) not found."
fi

############################################
# 4. Collect Coverage
############################################
if [[ -n "$COV_TARGET" ]]; then
    echo "[*] Coverage target specified. Collecting coverage..."
    
    "${SUDO_CMD[@]}" "$COVERAGE_SCRIPT_PATH" \
        -r "$COV_ROOT" \
        -t "$COV_TARGET" \
        -s "$REPLAYABLE_QUEUE_DIR" \
        -o "${ITER_LOG_ROOT}/coverage_after_fuzzing.txt" \
        -c "${ITER_LOG_ROOT}/coverage_over_time.csv" \
        -w "$GCOV_WRAPPER_SCRIPT" \
        "${COV_SCRIPT_EXTRA_ARGS[@]}"
        
    echo "[+] Coverage collection finished! Log saved to ${ITER_LOG_ROOT}/coverage_after_fuzzing.txt"
fi

python3 /workspace/common/analyze_fuzz_iteration.py $OUT_DIR

echo "[+] All tasks completed successfully."