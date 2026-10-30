#!/bin/bash

# ==============================================================================
# 1. SAFETY SETTINGS
# ==============================================================================
set -euo pipefail

# 1. Find the directory of the script, resolving any symlinks
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# 2. Move into that directory
cd "$SCRIPT_DIR"

# ==============================================================================
# 2. INITIALIZE VARIABLES (Defaults & Mandatory Args)
# ==============================================================================
OUT_DIR=""
TIMEOUT=""
FUZZ_OVERWRITE=0
IGNORE_DIRECTION=0

# Default Paths
COV_TARGET=""
COV_ROOT=""
FUZZ_TARGET=""

# ==============================================================================
# 3. USAGE & HELP MENU
# ==============================================================================
usage() {
    cat <<EOF
Usage: $(basename "$0") -o DIR [OPTIONS]

Orchestrates a Continuous Stateful LibAFL Protocol Fuzzing Campaign.

Mandatory Arguments:
  -o, --out-dir DIR      Output directory for the campaign

Optional Arguments:
  -T, --timeout SECONDS  Stop the fuzzer automatically after X seconds (Default: Infinite)
  -w, --overwrite        Overwrite/delete existing data in the OUT_DIR
  -i, --ignore-direction Ignore packet direction checking (Executes for all packets)
  
Path Overrides:
  -c, --cov-target PATH  Path to the coverage target binary
                         (Default: $COV_TARGET)
  -r, --cov-root PATH    Path to the coverage root directory
                         (Default: $COV_ROOT)
  -t, --fuzz-target PATH Path to the fuzz target binary
                         (Default: $FUZZ_TARGET)

  -h, --help             Show this help message and exit

Examples:
  # Run a continuous campaign for 100 seconds
  ./$(basename "$0") -o /tmp/out_tmp/ -T 100
  
  # Run ignoring the packet direction
  ./$(basename "$0") -o /tmp/out_tmp/ -i
EOF
}

# ==============================================================================
# 4. FLAG PARSER
# ==============================================================================
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--out-dir) OUT_DIR="$2"; shift ;;
        -T|--timeout) TIMEOUT="$2"; shift ;;
        -w|--overwrite) FUZZ_OVERWRITE=1 ;;
        -i|--ignore-direction) IGNORE_DIRECTION=1 ;;
        -c|--cov-target) COV_TARGET="$2"; shift ;;
        -r|--cov-root) COV_ROOT="$2"; shift ;;
        -t|--fuzz-target) FUZZ_TARGET="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[!] Error: Unknown parameter passed: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

# Basic validation for the mandatory argument
if [[ -z "$OUT_DIR" ]]; then
    echo "[!] Error: -o / --out-dir is required." >&2
    usage
    exit 1
fi

# ==============================================================================
# 5. TEMPORARY DIRECTORY HANDLING
# ==============================================================================
TMP_QUEUE=$(mktemp -d -t replay_queue_XXXXXX)

cleanup() {
    echo "[*] Cleaning up temporary directory: $TMP_QUEUE"
    rm -rf "$TMP_QUEUE"
}
trap cleanup EXIT

# ==============================================================================
# 6. EXECUTION FLOW
# ==============================================================================

echo "[*] Starting Continuous Fuzzing Campaign..."
echo "    Output Dir: $OUT_DIR"
if [ -n "$TIMEOUT" ]; then echo "    Timeout: $TIMEOUT seconds"; else echo "    Timeout: Infinite (Press Ctrl+C to stop)"; fi
if [ "$FUZZ_OVERWRITE" -eq 1 ]; then echo "    Mode: OVERWRITING"; fi
if [ "$IGNORE_DIRECTION" -eq 1 ]; then echo "    Direction: IGNORED (Executes for all packets)"; fi
echo ""

# Pass the parsed variables to the cargo command via inline environment assignment
IGNORE_DIRECTION="$IGNORE_DIRECTION" FUZZ_TARGET="$FUZZ_TARGET" OVERWRITE="$FUZZ_OVERWRITE" OUT_DIR="$OUT_DIR" TIMEOUT="$TIMEOUT" cargo run --release || true

echo ""
echo "[*] Gathering continuous coverage..."

if [ -d "$OUT_DIR/replayable_queue" ] && [ "$(ls -A "$OUT_DIR/replayable_queue")" ]; then
    cp -r "$OUT_DIR"/replayable_queue/* "$TMP_QUEUE/"
    
    echo "    -> Calculating coverage from unified queue..."
    COVERAGE_CMD=(
        /workspace/common/coverage_script_gcovr.sh
        -t "$COV_TARGET"
        -s "$TMP_QUEUE"
        -o "$OUT_DIR/cov_summary.txt"
        -c "$OUT_DIR/coverage_over_time.csv"
        -r "$COV_ROOT"
    )

    echo "    -> Executing: ${COVERAGE_CMD[*]}"

    # 3. Execute the array
    "${COVERAGE_CMD[@]}"

else
    echo "    [!] No replayable seeds found. Skipping coverage."
fi

python3 /workspace/common/analyze_fuzz_iteration.py "$OUT_DIR"

# echo "[*] Gathering crash information..."
# CRASH_SUMMARY="$OUT_DIR/crash_summary.json"

# echo "Processing crashes for continuous run..."
# if [ -d "$OUT_DIR/crashes" ] && [ "$(ls -A "$OUT_DIR/crashes")" ]; then
#     dedup_crashes.py \
#         -d "$OUT_DIR/crashes/" \
#         -b "$FUZZ_TARGET" \
#         -r "$CRASH_RULES" \
#         -o "$CRASH_SUMMARY" \
#         -f "^standalone.*"
#     echo "    -> Deduplication complete. Saved to $CRASH_SUMMARY."
# else
#     echo "    -> No crashes to process."
# fi

echo "[*] Continuous Campaign Post-Processing Complete!"