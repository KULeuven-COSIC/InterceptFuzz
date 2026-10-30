#!/bin/bash
# =============================================================================
# Configure and build the OpenThread (Nexus simulation) environments.
# Run from /workspace inside the openthread image.
#
#   openthread-cov            coverage build (gcov), always built
#   openthread-<FUZZER>       fuzzing build of the selected fuzzer
# =============================================================================
set -e

FUZZER=""
ROLE="BOTH"
CLEAN_BUILD=0
VERBOSE_MODE=0

show_help() {
    echo "Usage: $0 -f <FUZZER> [OPTIONS]"
    echo ""
    echo "Configure and build the OpenThread fuzzing and coverage environments."
    echo "Must be run from the directory containing the OpenThread environments (/workspace)."
    echo ""
    echo "Required Arguments:"
    echo "  -f, --fuzzer FUZZER  interceptfuzz, concat, aflnet, all, or coverage (coverage build only)"
    echo ""
    echo "Optional Arguments:"
    echo "  -r, --role ROLE      Malicious role; the paper uses BOTH (default: BOTH)"
    echo "  -c, --clean          Remove the 'build' directory before configuring"
    echo "  -v, --verbose        Enable verbose output (injects -DFUZZ_VERBOSE)"
    echo "  -h, --help           Show this help message and exit"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--fuzzer)  FUZZER="${2,,}"; shift 2 ;;
        -r|--role)    ROLE="${2^^}"; shift 2 ;;
        -c|--clean)   CLEAN_BUILD=1; shift 1 ;;
        -v|--verbose) VERBOSE_MODE=1; shift 1 ;;
        -h|--help)    show_help; exit 0 ;;
        *) echo "Error: Unknown parameter passed: $1"; show_help; exit 1 ;;
    esac
done

if [[ -z "$FUZZER" ]]; then
    echo "Error: Fuzzer (-f) is required."
    show_help
    exit 1
fi

if [[ "$ROLE" != "BOTH" ]]; then
    echo "Error: Invalid role '$ROLE'. The artifact supports BOTH (all nodes malicious)."
    exit 1
fi
FUZZING_MODE="MALICIOUS_${ROLE}"

case "$FUZZER" in
    interceptfuzz|concat|aflnet|coverage) DIRS=("openthread-$FUZZER") ;;
    all) DIRS=(openthread-interceptfuzz openthread-concat openthread-aflnet) ;;
    *) echo "Error: Unknown fuzzer '$FUZZER'."; show_help; exit 1 ;;
esac
[[ "$FUZZER" == "coverage" ]] && DIRS=()

for d in openthread-cov "${DIRS[@]}"; do
    if [[ ! -d "$d" ]]; then
        echo "Error: '$d' not found!"
        exit 1
    fi
done

echo "========================================"
echo "[*] Fuzzer        : $FUZZER"
echo "[*] Role          : $ROLE ($FUZZING_MODE)"
echo "[*] Clean Build   : $( [ $CLEAN_BUILD -eq 1 ] && echo "YES" || echo "NO" )"
echo "[*] Verbose Mode  : $( [ $VERBOSE_MODE -eq 1 ] && echo "YES" || echo "NO" )"
echo "========================================"

build_environment() {
    local dir_name="$1"
    local compiler_cxx="$2"
    local compiler_cc="$3"
    local flags_cxx="$4"
    local flags_ld="$5"
    local env_label="$6"
    local extra_cmake_args="$7"

    echo ""
    echo "========================================"
    echo "[*] Building $env_label in ./$dir_name"
    echo "========================================"

    cd "$dir_name"

    if [ "$CLEAN_BUILD" -eq 1 ]; then
        echo "[*] Cleaning previous build cache..."
        rm -rf build
    fi

    mkdir -p build
    cd build

    export CXX="$compiler_cxx"
    export CC="$compiler_cc"

    cmake -GNinja \
        -DCMAKE_C_COMPILER_LAUNCHER=ccache \
        -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
        -DCMAKE_C_FLAGS="$flags_cxx" \
        -DCMAKE_CXX_FLAGS="$flags_cxx" \
        -DCMAKE_EXE_LINKER_FLAGS="$flags_ld" \
        -DOT_COMPILE_WARNING_AS_ERROR=ON \
        -DOT_FUZZ_TARGETS=ON \
        -DOT_MULTIPLE_INSTANCE=ON \
        -DOT_PLATFORM=nexus \
        -DOT_THREAD_VERSION=1.4 \
        -DOT_APP_CLI=OFF \
        -DOT_APP_NCP=OFF \
        -DOT_APP_RCP=OFF \
        -DOT_PROJECT_CONFIG="$(pwd)/../tests/nexus/openthread-core-nexus-config.h" \
        ${extra_cmake_args} \
        ..

    ninja

    echo "--- ccache stats ---"
    ccache -s

    cd ../..
    echo "[+] Successfully built $env_label!"
}

FUZZ_CXXFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -D${FUZZING_MODE}"
COV_CXXFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -D${FUZZING_MODE} -O0 -g"
if [ "$VERBOSE_MODE" -eq 1 ]; then
    FUZZ_CXXFLAGS="$FUZZ_CXXFLAGS -DFUZZ_VERBOSE"
    COV_CXXFLAGS="$COV_CXXFLAGS -DFUZZ_VERBOSE"
fi
COV_LDFLAGS="-fuse-ld=lld"

# 1. Coverage environment (always required)
build_environment "openthread-cov" "clang++" "clang" \
                  "$COV_CXXFLAGS" "$COV_LDFLAGS" \
                  "Coverage Target (gcov/lld)" "-DOT_COVERAGE=ON"

# 2. Fuzzing environments: all three fuzzers use AFL++'s afl-clang-lto
for d in "${DIRS[@]}"; do
    build_environment "$d" "afl-clang-lto++" "afl-clang-lto" \
                      "$FUZZ_CXXFLAGS" "" \
                      "Fuzzing Target (${d#openthread-})"
done

echo ""
echo "========================================"
echo "[+] Selected environments built!"
echo "========================================"
