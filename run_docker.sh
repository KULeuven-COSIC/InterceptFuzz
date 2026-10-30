#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# =========================================================================
# Host Wrapper Argument Parsing
# =========================================================================
TARGET=""
CPUS=""
COVERAGE_MODE=0
CONTAINER_ARGS=()

show_help() {
    echo "Usage: $0 -t <TARGET> [HOST_OPTIONS] [--] [CONTAINER_ARGS]"
    echo ""
    echo "Host wrapper to launch the fuzzing Docker containers."
    echo ""
    echo "Host Options:"
    echo "  -t, --target   Target image to run: 'ns-3-dev' or 'openthread' (Required)"
    echo "  -C, --cpus     CPU cores to pin for Docker (e.g., '0-3' or '1,3')"
    echo "  --coverage     Re-collect coverage of an existing run instead of fuzzing"
    echo "                 (runs /workspace/common/collect_coverage.sh, see its -h)"
    echo "  -h, --help     Show this help message and exit"
    echo ""
    echo "Container Args:"
    echo "  Any other arguments are passed directly to the container's entrypoint script."
    echo ""
    echo "Examples:"
    echo "  $0 -t ns-3-dev -C 0-1 -f aflnet -p WIFI -T 36000 -b"
    echo "  $0 -t openthread -C 0-1 -f interceptfuzz -n 5 -D linear -T 86400 -b"
    echo "  $0 -t openthread --coverage -r BOTH -B /workspace/results/<run> -s /workspace/results/<run>/replayable_queue -b"
    echo ""
    echo "Results are written to ./runs/<target>/ (mounted as /workspace/results)."
}

# Intercept the host flags for Docker, pass everything else to the container
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="${2,,}" # Convert to lowercase
            shift 2
            ;;
        -C|--cpus)
            CPUS="$2"
            shift 2
            ;;
        --coverage)
            COVERAGE_MODE=1
            shift 1
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            # Save any other arguments to pass to the inner script
            CONTAINER_ARGS+=("$1")
            shift 1
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Error: Target (-t) is strictly required."
    show_help
    exit 1
fi

# =========================================================================
# Target-Specific Setup
# =========================================================================
if [[ "$TARGET" == "ns-3-dev" || "$TARGET" == "ns3" ]]; then
    IMAGE_NAME="interceptfuzz-ns-3-dev"
    HOST_RESULTS_DIR="$(pwd)/runs/ns-3-dev"
elif [[ "$TARGET" == "openthread" || "$TARGET" == "ot" ]]; then
    IMAGE_NAME="interceptfuzz-openthread"
    HOST_RESULTS_DIR="$(pwd)/runs/openthread"
else
    echo "Error: Unknown target '$TARGET'."
    echo "Supported targets: ns-3-dev, openthread"
    exit 1
fi

# =========================================================================
# Directory Setup
# =========================================================================
CONT_RESULTS_DIR="/workspace/results"
HOST_CCACHE_DIR="$(pwd)/.ccache"
mkdir -p "$HOST_CCACHE_DIR"

# Ensure the results directory exists on the host before running Docker.
mkdir -p "$HOST_RESULTS_DIR"

echo "========================================"
echo "[*] Target Image  : $IMAGE_NAME"
echo "[*] Host Results  : $HOST_RESULTS_DIR"
echo "[*] Cont Results  : $CONT_RESULTS_DIR"
echo "========================================"

# =========================================================================
# Docker Execution
# =========================================================================

# Build additional Docker arguments dynamically
DOCKER_ARGS=()
if [[ -n "$CPUS" ]]; then
    echo "[*] Pinning to CPU cores: $CPUS"
    DOCKER_ARGS+=("--cpuset-cpus=$CPUS")
fi
if [[ "$COVERAGE_MODE" -eq 1 ]]; then
    echo "[*] Coverage re-collection mode"
    DOCKER_ARGS+=("--entrypoint" "/workspace/common/collect_coverage.sh")
fi

echo "[*] Starting fuzzing container..."

# Run the container
#   "${DOCKER_ARGS[@]}"    : Dynamically adds --cpuset-cpus if you provided it
#   "${CONTAINER_ARGS[@]}" : Passes your fuzzer args (e.g., -f aflnet -p WIFI) to the entrypoint

# Interactive terminal only when there is one (campaign queues run detached)
TTY_ARGS=(-i)
[[ -t 0 && -t 1 ]] && TTY_ARGS=(-it)

docker run "${TTY_ARGS[@]}" --rm \
    -v "$HOST_RESULTS_DIR:$CONT_RESULTS_DIR" \
    -v "$HOST_CCACHE_DIR:/root/.cache/ccache" \
    --security-opt seccomp=unconfined \
    --shm-size=1g \
    -e AFL_NO_AFFINITY=1 \
    "${DOCKER_ARGS[@]}" \
    "$IMAGE_NAME" \
    "${CONTAINER_ARGS[@]}"