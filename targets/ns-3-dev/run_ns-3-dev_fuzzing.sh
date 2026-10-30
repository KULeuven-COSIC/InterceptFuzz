#!/bin/bash
# =============================================================================
# Run one fuzzing campaign on ns-3 (entrypoint of the ns-3-dev image).
# Results: /workspace/results/<PROTOCOL>/<TIMEOUT>s/<FUZZER>/...
# =============================================================================
set -e

PROJ_DIR="$PWD"
TARGET_BIN="ns3-dev-target-default"

FUZZER=""
PROTOCOL=""
TIMEOUT=3600
ITER=5
SEED_DIR=""
INIT_FSM_JSON=""
BUILD_FLAG=0
STRATEGY="linear"
EXTRA_RUN_ARGS=()

show_help() {
    echo "Usage: $0 -f <FUZZER> -p <PROTOCOL> [OPTIONS] [-- <EXTRA_ARGS>]"
    echo ""
    echo "Run a fuzzing campaign on ns-3 (Wi-Fi or LTE)."
    echo ""
    echo "Required Arguments:"
    echo "  -f, --fuzzer       Fuzzer to run: 'interceptfuzz', 'concat' or 'aflnet'"
    echo "  -p, --protocol     Target protocol: 'WIFI' or 'LTE'"
    echo ""
    echo "Optional Arguments:"
    echo "  -b, --build        Build the coverage and fuzzing targets before fuzzing"
    echo "  -T, --timeout      Campaign duration in seconds (default: 3600)"
    echo "  -n, --iter         InterceptFuzz: number of iterations (default: 5)"
    echo "  -D, --distribution InterceptFuzz: time split over iterations, 'linear' or 'uniform' (default: linear)"
    echo "  -s, --seed         Concat: directory of 0xDEAD-delimited seeds (default: generated from the FSM)"
    echo "  -j, --fsm          Concat: FSM JSON to generate the initial seeds from (default: init_fsm/<protocol>.json)"
    echo "  -h, --help         Show this help message and exit"
    echo ""
    echo "Any unrecognized argument, or anything after '--', is passed to the fuzzer's run script."
    echo ""
    echo "Examples:"
    echo "  $0 -f interceptfuzz -p WIFI -n 5 -D linear -T 36000 -b"
    echo "  $0 -f concat -p LTE -T 36000 -b"
    echo "  $0 -f aflnet -p WIFI -T 36000 -b"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--fuzzer) FUZZER="${2,,}"; shift 2 ;;
        -p|--protocol) PROTOCOL="${2^^}"; shift 2 ;;
        -T|--timeout) TIMEOUT="$2"; shift 2 ;;
        -n|--iter) ITER="$2"; shift 2 ;;
        -D|--distribution) STRATEGY="${2,,}"; shift 2 ;;
        -s|--seed) SEED_DIR="$2"; shift 2 ;;
        -j|--fsm) INIT_FSM_JSON="$2"; shift 2 ;;
        -b|--build) BUILD_FLAG=1; shift 1 ;;
        -h|--help) show_help; exit 0 ;;
        --) shift 1; EXTRA_RUN_ARGS+=("$@"); break ;;
        *) EXTRA_RUN_ARGS+=("$1"); shift 1 ;;
    esac
done

if [[ -z "$FUZZER" || -z "$PROTOCOL" ]]; then
    echo "Error: Fuzzer (-f) and Protocol (-p) are required."
    echo ""
    show_help
    exit 1
fi

if [[ "$PROTOCOL" != "WIFI" && "$PROTOCOL" != "LTE" ]]; then
    echo "Error: Invalid protocol '$PROTOCOL'. Supported: WIFI, LTE."
    exit 1
fi

if [[ "$STRATEGY" != "linear" && "$STRATEGY" != "uniform" ]]; then
    echo "Error: Invalid distribution '$STRATEGY'. Use 'linear' or 'uniform'."
    exit 1
fi

# =========================================================================
# Build (optional)
# =========================================================================
if [[ "$BUILD_FLAG" -eq 1 ]]; then
    echo "[*] Running: $PROJ_DIR/build_ns-3-dev.sh -p $PROTOCOL -f $FUZZER"
    "$PROJ_DIR/build_ns-3-dev.sh" -p "$PROTOCOL" -f "$FUZZER"
    echo "[+] Build completed successfully."
    echo ""
fi

# =========================================================================
# Output directory
# =========================================================================
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
BASE_OUT_DIR="/workspace/results"

if [[ "$FUZZER" == "interceptfuzz" ]]; then
    OUT_DIR="${BASE_OUT_DIR}/${PROTOCOL}/${TIMEOUT}s/${FUZZER}/${ITER}_iter/${STRATEGY}/run_${TIMESTAMP}"
else
    OUT_DIR="${BASE_OUT_DIR}/${PROTOCOL}/${TIMEOUT}s/${FUZZER}/run_${TIMESTAMP}"
fi

echo "========================================"
echo "[*] Fuzzer       : $FUZZER"
echo "[*] Protocol     : $PROTOCOL"
echo "[*] Timeout      : $TIMEOUT seconds"
if [[ ${#EXTRA_RUN_ARGS[@]} -gt 0 ]]; then
echo "[*] Extra Args   : ${EXTRA_RUN_ARGS[*]}"
fi
echo "[*] Output Dir   : $OUT_DIR"
echo "========================================"

mkdir -p "$OUT_DIR"

COV_BIN="$PROJ_DIR/ns-3-dev-cov/build/scratch/fuzz/$TARGET_BIN"
COV_SRC="$PROJ_DIR/ns-3-dev-cov"

case "$FUZZER" in
    interceptfuzz)
        echo "[*] Launching InterceptFuzz ($ITER iterations, $STRATEGY)..."
        TARG_BIN="$PROJ_DIR/ns-3-dev-interceptfuzz/build/scratch/fuzz/$TARGET_BIN"
        RUN_SCRIPT="$PROJ_DIR/fuzzers/interceptfuzz/scripts/run_interceptfuzz.sh"

        AFL_FUZZER_LOOPCOUNT=1 "$RUN_SCRIPT" \
            -t "$TARG_BIN" \
            -n "$ITER" \
            -T "$TIMEOUT" \
            -D "$STRATEGY" \
            -r "$COV_SRC" \
            -c "$COV_BIN" \
            -B "$OUT_DIR" \
            "${EXTRA_RUN_ARGS[@]}"
        ;;

    concat)
        if [[ -n "$INIT_FSM_JSON" && -n "$SEED_DIR" ]]; then
            echo "Error: Concat takes EITHER an FSM (-j/--fsm) OR a seed directory (-s/--seed), not both."
            exit 1
        elif [[ -z "$INIT_FSM_JSON" && -z "$SEED_DIR" ]]; then
            INIT_FSM_JSON="$PROJ_DIR/init_fsm/${PROTOCOL,,}.json"
        fi

        SEED_ARGS=()
        if [[ -n "$INIT_FSM_JSON" ]]; then
            SEED_ARGS=("-j" "$INIT_FSM_JSON")
        else
            SEED_ARGS=("-i" "$SEED_DIR")
        fi

        echo "[*] Launching Concat..."
        TARG_BIN="$PROJ_DIR/ns-3-dev-concat/build/scratch/fuzz/$TARGET_BIN"
        RUN_SCRIPT="$PROJ_DIR/fuzzers/concat/run_concat.sh"

        AFL_FUZZER_LOOPCOUNT=1 "$RUN_SCRIPT" \
            -t "$TARG_BIN" \
            -o "$OUT_DIR" \
            -T "$TIMEOUT" \
            -c "$COV_BIN" \
            -r "$COV_SRC" \
            "${SEED_ARGS[@]}" \
            "${EXTRA_RUN_ARGS[@]}"
        ;;

    aflnet)
        echo "[*] Launching AFLNet (LibAFL)..."
        TARG_BIN="$PROJ_DIR/ns-3-dev-aflnet/build/scratch/fuzz/$TARGET_BIN"
        RUN_SCRIPT="$PROJ_DIR/fuzzers/aflnet/run_aflnet.sh"

        AFL_FUZZER_LOOPCOUNT=1 PROTOCOL="$PROTOCOL" "$RUN_SCRIPT" \
            -o "$OUT_DIR" \
            -T "$TIMEOUT" \
            -c "$COV_BIN" \
            -r "$COV_SRC" \
            -t "$TARG_BIN" \
            -w \
            --ignore-direction \
            "${EXTRA_RUN_ARGS[@]}"
        ;;

    *)
        echo "Error: Unknown fuzzer '$FUZZER'."
        echo "Supported fuzzers: interceptfuzz, concat, aflnet"
        exit 1
        ;;
esac

echo "[+] Fuzzing session finished!"
echo "[+] Results saved to: $OUT_DIR"
