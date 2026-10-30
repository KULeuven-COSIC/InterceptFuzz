#!/bin/bash
set -e

# ==============================================================================
# Fixed internal paths (Shared)
# ==============================================================================
SCRIPT="/workspace/common/coverage_script_gcovr.sh"
WRAPPER="/workspace/common/gcov-wrapper.sh"

usage() {
    echo "Usage: docker run <image> [-p <protocol> | -r <role>] -B <base_dir> -s <seeds_dir> [OPTIONS] [-- <extra_args>]"
    echo ""
    echo "Required Target Options (Choose ONE):"
    echo "  -p    The target protocol (WIFI or LTE) for ns-3-dev"
    echo "  -r    The target role for openthread (BOTH)"
    echo ""
    echo "Required Output Options:"
    echo "  -B    The base directory for output files (CSV, TXT report)"
    echo "  -s    The exact seeds directory (e.g., /path/to/replayable_queue_before_minimize)"
    echo ""
    echo "Optional Execution Options:"
    echo "  -b, --build   Call the build script before calculating coverage"
    echo ""
    echo "Extra Arguments:"
    echo "  Any unrecognized arguments, or anything placed after '--', will be passed"
    echo "  directly to the underlying coverage script (e.g., -T 1 -d 7200 -X)."
    echo ""
    exit 1
}

PROTOCOL=""
ROLE=""
BASE_DIR=""
SEEDS_DIR=""
BUILD_FLAG=0
EXTRA_ARGS=()

# Parse arguments passed to the container
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -p) PROTOCOL="${2^^}"; shift 2 ;; # Force uppercase
        -r) ROLE="${2^^}"; shift 2 ;;     # Force uppercase
        -B) BASE_DIR="$2"; shift 2 ;;
        -s) SEEDS_DIR="$2"; shift 2 ;;
        -b|--build) BUILD_FLAG=1; shift 1 ;;
        -h|--help) usage ;;
        --) 
            shift 1
            EXTRA_ARGS+=("$@")
            break 
            ;;
        *) 
            # Collect any other flags for the coverage script
            EXTRA_ARGS+=("$1")
            shift 1 
            ;;
    esac
done

if [ -z "$BASE_DIR" ] || [ -z "$SEEDS_DIR" ]; then
    echo "[!] Error: Missing required -B or -s arguments."
    usage
fi

# ==============================================================================
# Dynamic System Configuration
# ==============================================================================
if [ -n "$PROTOCOL" ]; then
    SYSTEM="ns-3-dev"
    TARGET_CONFIG="Protocol: $PROTOCOL"
    
    if [[ "$PROTOCOL" != "WIFI" && "$PROTOCOL" != "LTE" ]]; then
        echo "[!] Error: Protocol must be either WIFI or LTE."
        exit 1
    fi
    
    BUILD_SCRIPT="/workspace/build_ns-3-dev.sh"
    TARGET_BIN="/workspace/ns-3-dev-cov/build/scratch/fuzz/ns3-dev-target-default"
    ROOT_DIR="/workspace/ns-3-dev-cov"
    
elif [ -n "$ROLE" ]; then
    SYSTEM="openthread"
    TARGET_CONFIG="Role: $ROLE"
    
    if [[ "$ROLE" != "BOTH" ]]; then
        echo "[!] Error: Role must be BOTH."
        exit 1
    fi
    
    BUILD_SCRIPT="/workspace/build_openthread.sh"
    TARGET_BIN="/workspace/openthread-cov/build/tests/fuzz/fuzz_test_form_join-fuzzer"
    ROOT_DIR="/workspace/openthread-cov"
else
    echo "[!] Error: You must specify either a protocol (-p) or a role (-r)."
    usage
fi

echo "======================================================================"
echo "[*] Initializing Coverage Container"
echo "[*] System     : $SYSTEM"
echo "[*] Target     : $TARGET_CONFIG"
echo "[*] Base Dir   : $BASE_DIR"
echo "[*] Seeds Dir  : $SEEDS_DIR"
echo "[*] Build Flag : $( [ $BUILD_FLAG -eq 1 ] && echo "YES" || echo "NO" )"
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
echo "[*] Extra Args : ${EXTRA_ARGS[*]}"
fi
echo "======================================================================"

# 1. Build the target environment (Optional)
if [ "$BUILD_FLAG" -eq 1 ]; then
    echo "[*] Building the coverage environment..."
    if [ ! -f "$BUILD_SCRIPT" ]; then
        echo "[!] Error: Build script not found at $BUILD_SCRIPT"
        exit 1
    fi

    # Ensure we are in the correct directory to run the build script
    cd "$(dirname "$BUILD_SCRIPT")"

    if [ "$SYSTEM" == "ns-3-dev" ]; then
        ./build_ns-3-dev.sh -f coverage -p "$PROTOCOL"
    else
        ./build_openthread.sh -f coverage -r "$ROLE"
    fi
else
    echo "[*] Skipping build step (use -b to build)..."
fi

# Manually set output paths based on the base directory
OUT_JSON="$BASE_DIR/coverage.json"
OUT_TXT="$BASE_DIR/iterative_coverage_out.txt"
OUT_CSV="$BASE_DIR/coverage_over_time.csv"

if [ ! -d "$SEEDS_DIR" ]; then
    echo "[!] Error: Seeds directory not found at $SEEDS_DIR"
    exit 1
fi

echo "[*] Starting coverage analysis..."

# 2. Execute the main coverage script
exec "$SCRIPT" \
    -t "$TARGET_BIN" \
    -s "$SEEDS_DIR" \
    -o "$OUT_TXT" \
    -r "$ROOT_DIR" \
    -c "$OUT_CSV" \
    -w "$WRAPPER" \
    "${EXTRA_ARGS[@]}"

# -j "$OUT_JSON" \