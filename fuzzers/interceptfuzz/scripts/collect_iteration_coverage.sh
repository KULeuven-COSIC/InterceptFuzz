#!/bin/bash
# Coverage per InterceptFuzz iteration: replays the inputs of iterations 1..k
# cumulatively and writes iter_XX/artifacts/coverage_before_minimize.txt.
# Run inside the target container, e.g. with run_docker.sh --entrypoint bash.

COVERAGE_SCRIPT_PATH="/workspace/common/coverage_script_gcovr.sh"
GCOV_WRAPPER_SCRIPT="/workspace/common/gcov-wrapper.sh"

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <openthread|ns-3-dev> <RUN_DIR>"
    echo "Example: $0 openthread /workspace/results/BOTH/86400s/interceptfuzz/5_iter/linear/run_X/fuzz_test_form_join-fuzzer/RUN_X"
    echo "Note: RUN_DIR must contain a 'replayable_queue_before_minimize' subdirectory."
    exit 1
fi

case "$1" in
    openthread)
        COV_ROOT="/workspace/openthread-cov"
        COV_BIN="/workspace/openthread-cov/build/tests/fuzz/fuzz_test_form_join-fuzzer" ;;
    ns-3-dev)
        COV_ROOT="/workspace/ns-3-dev-cov"
        COV_BIN="/workspace/ns-3-dev-cov/build/scratch/fuzz/ns3-dev-target-default" ;;
    *) echo "Unknown target '$1'"; exit 1 ;;
esac
shift

BASE_DIR="$1"
REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE="$BASE_DIR/replayable_queue_before_minimize"
ITER_LOG_ROOT="$BASE_DIR"

if [ ! -d "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" ]; then
    echo "[-] Error: Directory $REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE does not exist."
    exit 1
fi

# Find all unique "iter_XX" prefixes in the directory, sort them naturally (-V)
PREFIXES=$(find "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" -maxdepth 1 -type f -name "iter_*" -exec basename {} \; | grep -Eo "^iter_[0-9]{2}" | sort -u -V)

if [ -z "$PREFIXES" ]; then
    echo "[-] No files starting with 'iter_XX' found in $REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE."
    exit 1
fi

echo "[*] Found the following iterations to process: $(echo $PREFIXES | tr '\n' ' ')"

IS_FIRST_RUN=true

for PREFIX in $PREFIXES; do
    echo "---------------------------------------------------"
    echo "[*] Running coverage script for $PREFIX..."
    
    # Setup output paths inside the base directory
    ITER_ARTIFACTS_DIR="${ITER_LOG_ROOT}/${PREFIX}/artifacts"
    mkdir -p "$ITER_ARTIFACTS_DIR"
    OUT_FILE="${ITER_ARTIFACTS_DIR}/coverage_before_minimize.txt"
    
    # Execute the coverage script using the native -p (PATTERN) flag
    if [ "$IS_FIRST_RUN" = true ]; then
        # First iteration: no -k (cleans existing coverage)
        "$COVERAGE_SCRIPT_PATH" \
            -r "$COV_ROOT" \
            -t "$COV_BIN" \
            -s "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" \
            -p "${PREFIX}*" \
            -o "$OUT_FILE" \
            -w "$GCOV_WRAPPER_SCRIPT"
            
        IS_FIRST_RUN=false
    else
        # Subsequent iterations: add -k (keeps accumulated coverage)
        "$COVERAGE_SCRIPT_PATH" \
            -r "$COV_ROOT" \
            -t "$COV_BIN" \
            -s "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" \
            -p "${PREFIX}*" \
            -o "$OUT_FILE" \
            -w "$GCOV_WRAPPER_SCRIPT" \
            -k
    fi
    
    echo "[+] ${PREFIX} coverage saved to ${OUT_FILE}"
done

echo "---------------------------------------------------"
echo "[*] All iterations processed successfully."