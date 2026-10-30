#!/bin/bash
# =============================================================================
# Re-collect the coverage of finished campaigns in parallel, one container per
# run, pinned round-robin to the given cores. Each run's replayable queue is
# replayed on the coverage build; coverage_over_time.csv and
# iterative_coverage_out.txt are (re)written into the run directory.
#
# RESULTS_DIR is a directory below runs/<target>/ on the host, e.g.
#   runs/openthread/BOTH/86400s/concat  or  runs/openthread/BOTH/86400s/interceptfuzz/5_iter/linear
# Example:
#   ./experiments/recollect_coverage.sh -t openthread -d runs/openthread/BOTH/86400s/concat -c 0-7 -- -r BOTH
#   ./experiments/recollect_coverage.sh -t ns-3-dev -d runs/ns-3-dev/WIFI/36000s/aflnet -c 0-7 -- -p WIFI
# Arguments after '--' go to common/collect_coverage.sh (inside the container).
# =============================================================================

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)

usage() {
    echo "Usage: $0 -t <openthread|ns-3-dev> -d <results_dir> -c <cores> [-- collect_coverage args]"
    exit 1
}

TARGET=""
RESULTS_DIR=""
CORE_SPEC=""
EXTRA_FLAGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -t) TARGET="$2"; shift 2 ;;
        -d) RESULTS_DIR="$2"; shift 2 ;;
        -c) CORE_SPEC="$2"; shift 2 ;;
        -h|--help) usage ;;
        --) shift; EXTRA_FLAGS+=("$@"); break ;;
        *) EXTRA_FLAGS+=("$1"); shift ;;
    esac
done

[ -z "$TARGET" ] || [ -z "$RESULTS_DIR" ] || [ -z "$CORE_SPEC" ] && usage

cd "$ROOT_DIR"
HOST_BASE="runs/$TARGET"
RESULTS_DIR="${RESULTS_DIR%/}"
if [[ "$RESULTS_DIR" != "$HOST_BASE"* || ! -d "$RESULTS_DIR" ]]; then
    echo "Error: '$RESULTS_DIR' must be an existing directory below $HOST_BASE/." >&2
    exit 1
fi

# Expand the core specification
CORES=()
IFS=',' read -ra RANGES <<< "$CORE_SPEC"
for item in "${RANGES[@]}"; do
    if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        for ((i=${BASH_REMATCH[1]}; i<=${BASH_REMATCH[2]}; i++)); do CORES+=("$i"); done
    elif [[ "$item" =~ ^[0-9]+$ ]]; then
        CORES+=("$item")
    else
        echo "Error: Invalid core format '$item'." >&2
        exit 1
    fi
done

shopt -s nullglob
idx=0
PIDS=()
for d in "$RESULTS_DIR"/run_*/*/RUN_* "$RESULTS_DIR"/run_*; do
    [ -d "$d" ] || continue
    if [ -d "$d/replayable_queue_before_minimize" ]; then
        QUEUE="$d/replayable_queue_before_minimize"
    elif [ -d "$d/replayable_queue" ]; then
        QUEUE="$d/replayable_queue"
    else
        continue
    fi

    c="${CORES[$idx]}"
    # host runs/<target>/X  ->  container /workspace/results/X
    CONT_D="/workspace/results/${d#$HOST_BASE/}"
    CONT_Q="/workspace/results/${QUEUE#$HOST_BASE/}"
    echo "[*] Core $c: $d"
    ./run_docker.sh -C "$c" -t "$TARGET" --coverage -B "$CONT_D" -s "$CONT_Q" "${EXTRA_FLAGS[@]}" \
        > "$d/recollect_coverage.log" 2>&1 &
    PIDS+=($!)

    idx=$(( (idx + 1) % ${#CORES[@]} ))
    # at most one container per core at a time
    if [ "$idx" -eq 0 ]; then wait "${PIDS[@]}"; PIDS=(); fi
done

wait
echo "[+] Coverage re-collection finished."
