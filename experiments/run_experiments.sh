#!/bin/bash
# =============================================================================
# Run the paper's fuzzing campaigns one after another on a set of CPU cores.
#
#   OpenThread (role BOTH), 24 h:  InterceptFuzz {5,10} iterations x {linear,uniform},
#                                  Concat, AFLNet
#   ns-3 (WIFI / LTE), 10 h:       InterceptFuzz 5 iterations x {linear,uniform},
#                                  Concat, AFLNet
#
# Each campaign runs in its own container (run_docker.sh) and builds the targets
# first (-b). The paper repeats every configuration 10 times; start several
# instances of this script on disjoint core sets to run campaigns in parallel,
# e.g.  ./experiments/run_experiments.sh -t openthread -C 0-1 &
#       ./experiments/run_experiments.sh -t openthread -C 2-3 &
# =============================================================================
set -e

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)

TARGET=""
PROTOCOL=""
CORES="0-1"
RUNS=1
TIMEOUT=""
ONLY=""

show_help() {
    echo "Usage: $0 -t <openthread|ns-3-dev> [-p <WIFI|LTE>] [OPTIONS]"
    echo ""
    echo "  -t TARGET    openthread or ns-3-dev"
    echo "  -p PROTOCOL  ns-3-dev only: WIFI or LTE"
    echo "  -C CORES     CPU cores for the containers (default: $CORES)"
    echo "  -n RUNS      Repetitions of every configuration (default: $RUNS)"
    echo "  -T SECONDS   Campaign duration (default: 86400 for openthread, 36000 for ns-3-dev)"
    echo "  -f FUZZER    Only run configurations of this fuzzer (interceptfuzz, concat, aflnet)"
    echo "  -h           Show this help"
}

while getopts ":t:p:C:n:T:f:h" opt; do
    case "$opt" in
        t) TARGET="${OPTARG,,}" ;;
        p) PROTOCOL="${OPTARG^^}" ;;
        C) CORES="$OPTARG" ;;
        n) RUNS="$OPTARG" ;;
        T) TIMEOUT="$OPTARG" ;;
        f) ONLY="${OPTARG,,}" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Configurations: "FUZZER [ITERATIONS STRATEGY]"
case "$TARGET" in
    openthread)
        TIMEOUT="${TIMEOUT:-86400}"
        TARGET_ARGS=(-r BOTH)
        CONFIGURATIONS=(
            "interceptfuzz 5 linear"
            "interceptfuzz 5 uniform"
            "interceptfuzz 10 linear"
            "interceptfuzz 10 uniform"
            "concat"
            "aflnet"
        )
        ;;
    ns-3-dev)
        if [[ "$PROTOCOL" != "WIFI" && "$PROTOCOL" != "LTE" ]]; then
            echo "Error: ns-3-dev needs -p WIFI or -p LTE."
            exit 1
        fi
        TIMEOUT="${TIMEOUT:-36000}"
        TARGET_ARGS=(-p "$PROTOCOL")
        CONFIGURATIONS=(
            "interceptfuzz 5 linear"
            "interceptfuzz 5 uniform"
            "concat"
            "aflnet"
        )
        ;;
    *)
        show_help
        exit 1
        ;;
esac

if [[ -n "$ONLY" ]]; then
    FILTERED=()
    for c in "${CONFIGURATIONS[@]}"; do
        [[ "${c%% *}" == "$ONLY" ]] && FILTERED+=("$c")
    done
    CONFIGURATIONS=("${FILTERED[@]}")
fi

TOTAL=$(( ${#CONFIGURATIONS[@]} * RUNS ))
CURRENT=1
cd "$ROOT_DIR"

echo "================================================="
echo "=== $TARGET ${PROTOCOL}: $TOTAL campaigns of ${TIMEOUT}s on cores $CORES"
echo "================================================="

for i in $(seq 1 "$RUNS"); do
    for config in "${CONFIGURATIONS[@]}"; do
        read -r FUZZER ITER STRATEGY <<< "$config"
        ARGS=(-f "$FUZZER" "${TARGET_ARGS[@]}" -T "$TIMEOUT" -b)
        [[ -n "$ITER" ]] && ARGS+=(-n "$ITER" -D "$STRATEGY")

        echo ""
        echo "[*] Campaign ${CURRENT}/${TOTAL} (repetition $i): $FUZZER ${ITER:+$ITER iterations, $STRATEGY}"
        ./run_docker.sh -C "$CORES" -t "$TARGET" "${ARGS[@]}"
        CURRENT=$((CURRENT + 1))
    done
done

echo ""
echo "=== All $TOTAL campaigns finished. Results: $ROOT_DIR/runs/$TARGET/"
