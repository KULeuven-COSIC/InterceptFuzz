#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Default values
FUZZER=""
PROTOCOL=""
CLEAN_BUILD=0
VERBOSE_MODE=0
MODULES=""
TARGET_SRC=""

# Function to display the help menu
show_help() {
    echo "Usage: $0 -f <FUZZER> -p <PROTOCOL> [OPTIONS]"
    echo ""
    echo "Configure and build the ns-3 fuzzing and coverage environments."
    echo "Must be run from the parent directory containing the ns-3 environments."
    echo ""
    echo "Required Arguments:"
    echo "  -f, --fuzzer FUZZER      interceptfuzz, concat, aflnet, aflnet-pp, aflnet-real, all,"
    echo "                           coverage (coverage build only)"
    echo "                           or asan (AddressSanitizer build only, for crash triage)"
    echo "  -p, --protocol PROTOCOL  Set the target protocol: WIFI or LTE"
    echo ""
    echo "Optional Arguments:"
    echo "  -c, --clean              Run './ns3 clean' before configuring (recommended when switching protocols)"
    echo "  -v, --verbose            Enable verbose output (injects -DFUZZ_VERBOSE to print hexdumps)"
    echo "  -h, --help               Show this help message and exit"
}

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--fuzzer)
            FUZZER="${2,,}" # Convert to lowercase
            shift 2
            ;;
        -p|--protocol)
            PROTOCOL="${2^^}" # Convert to uppercase
            shift 2
            ;;
        -c|--clean)
            CLEAN_BUILD=1
            shift 1
            ;;
        -v|--verbose)
            VERBOSE_MODE=1
            shift 1
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Error: Unknown parameter passed: $1"
            show_help
            exit 1
            ;;
    esac
done

if [[ -z "$FUZZER" || -z "$PROTOCOL" ]]; then
    echo "Error: Fuzzer (-f) and Protocol (-p) are strictly required."
    show_help
    exit 1
fi

# =========================================================================
# Validate Fuzzer & Directories
# =========================================================================
case "$FUZZER" in
    interceptfuzz|concat|aflnet|aflnet-pp|aflnet-real) DIRS=("ns-3-dev-$FUZZER") ;;
    all) DIRS=(ns-3-dev-interceptfuzz ns-3-dev-concat ns-3-dev-aflnet ns-3-dev-aflnet-pp ns-3-dev-aflnet-real) ;;
    coverage) DIRS=() ;;
    asan) DIRS=() ;;
    *) echo "Error: Unknown fuzzer target '$FUZZER'."; exit 1 ;;
esac

NEEDED=(ns-3-dev-cov "${DIRS[@]}")
[[ "$FUZZER" == "asan" ]] && NEEDED=(ns-3-dev-asan)

for d in "${NEEDED[@]}"; do
    if [[ ! -d "$d" ]]; then
        echo "Error: '$d' not found!"
        exit 1
    fi
done

# =========================================================================
# Validate Protocol
# =========================================================================
if [[ "$PROTOCOL" == "WIFI" ]]; then
    MODULES="wifi,internet,mobility,core,network"
    TARGET_SRC="fuzz/minimal_wifi_fuzz.cc"

elif [[ "$PROTOCOL" == "LTE" ]]; then
    MODULES="lte,point-to-point,internet,mobility,core,network"
    TARGET_SRC="fuzz/minimal_lte_fuzz.cc"
else
    echo "Error: Invalid protocol '$PROTOCOL'."
    exit 1
fi

echo "========================================"
echo "[*] Target Fuzzer   : $FUZZER"
echo "[*] Target Protocol : $PROTOCOL"
echo "[*] Enabled Modules : $MODULES"
echo "[*] Source File     : $TARGET_SRC"
echo "[*] Clean Build     : $( [ $CLEAN_BUILD -eq 1 ] && echo "YES" || echo "NO" )"
echo "[*] Verbose Mode    : $( [ $VERBOSE_MODE -eq 1 ] && echo "YES" || echo "NO" )"
echo "========================================"

# Function to execute a full build in a specific directory
build_environment() {
    local dir_name="$1"
    local compiler_cxx="$2"
    local compiler_cc="$3"
    local flags_cxx="$4"
    local flags_ld="$5"
    local env_label="$6"

    echo ""
    echo "========================================"
    echo "[*] Building $env_label in ./$dir_name"
    echo "========================================"

    cd "$dir_name"

    # Now that we are inside the directory, verify the target file exists here
    if [[ ! -f "$TARGET_SRC" ]]; then
        echo "Error: Target source file '$TARGET_SRC' not found in $dir_name!"
        echo "Please ensure the 'fuzz' folder and target files exist inside $dir_name."
        exit 1
    fi

    if [ "$CLEAN_BUILD" -eq 1 ]; then
        echo "[*] Cleaning previous build cache..."
        ./ns3 clean
    fi

    echo "[*] Staging target script..."
    rm -f scratch/fuzz/*.cc
    mkdir -p scratch/fuzz
    
    # We now copy directly from the local relative path
    cp "$TARGET_SRC" scratch/fuzz/target.cc

    echo "[*] Configuring ns-3..."
    # Apply flags
    export CXXFLAGS="$flags_cxx"
    export LDFLAGS="$flags_ld"
    export CXX="$compiler_cxx"
    export CC="$compiler_cc"

    ./ns3 configure \
      --enable-modules="$MODULES" \
      --disable-examples \
      --disable-tests \
      -- \
      -DCMAKE_CXX_FLAGS="$flags_cxx" \
      -DCMAKE_C_FLAGS="$flags_cxx" \
      -DCMAKE_EXE_LINKER_FLAGS="$flags_ld"

    echo "[*] Building..."
    ./ns3 build

    # Return to the parent directory for the next step
    cd ..
    echo "[+] Successfully built $env_label!"
}

# Setup Base Flags
FUZZ_CXXFLAGS=""
if [ "$VERBOSE_MODE" -eq 1 ]; then
    FUZZ_CXXFLAGS="-DFUZZ_VERBOSE"
fi

COV_CXXFLAGS="-DCMAKE_EXE_LINKER_FLAGS=\"-fuse-ld=lld\" --coverage -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O0 -g"
if [ "$VERBOSE_MODE" -eq 1 ]; then
    COV_CXXFLAGS="$COV_CXXFLAGS -DFUZZ_VERBOSE"
fi
COV_LDFLAGS="-fuse-ld=lld"

if [[ "$FUZZER" == "asan" ]]; then
    ASAN_CXXFLAGS="-DCMAKE_EXE_LINKER_FLAGS=\"-fuse-ld=lld\" -fsanitize=address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O0 -g"
    [ "$VERBOSE_MODE" -eq 1 ] && ASAN_CXXFLAGS="$ASAN_CXXFLAGS -DFUZZ_VERBOSE"
    build_environment "ns-3-dev-asan" "clang++" "clang" \
                      "$ASAN_CXXFLAGS" "-fuse-ld=lld" \
                      "AddressSanitizer Target"
    echo ""
    echo "[+] Built ns-3-dev-asan/build/scratch/fuzz/ns3-dev-target-default"
    exit 0
fi

# 1. Coverage environment (always required)
build_environment "ns-3-dev-cov" "clang++" "clang" \
                  "$COV_CXXFLAGS" "$COV_LDFLAGS" \
                  "Coverage Target (gcov/lld)"

# 2. Fuzzing environments. All fuzzers use AFL++'s afl-clang-fast, except
#    AFLNet-real: AFLNet's own afl-clang-fast keeps code coverage in the upper
#    half of the bitmap (the lower half holds AFLNet's state feedback).
AFLNET_REAL_DIR="${AFLNET_REAL_DIR:-$(pwd)/fuzzers/aflnet-real/aflnet}"
for d in "${DIRS[@]}"; do
    if [[ "$d" == "ns-3-dev-aflnet-real" ]]; then
        if [[ ! -x "$AFLNET_REAL_DIR/afl-clang-fast" ]]; then
            echo "Error: '$AFLNET_REAL_DIR/afl-clang-fast' not found! Run fuzzers/aflnet-real/build_aflnet_real.sh first."
            exit 1
        fi
        AFL_PATH="$AFLNET_REAL_DIR" build_environment "$d" \
                      "$AFLNET_REAL_DIR/afl-clang-fast++" "$AFLNET_REAL_DIR/afl-clang-fast" \
                      "$FUZZ_CXXFLAGS" "-fuse-ld=lld" \
                      "Fuzzing Target (aflnet-real)"
    else
        build_environment "$d" "afl-clang-fast++" "afl-clang-fast" \
                          "$FUZZ_CXXFLAGS" "" \
                          "Fuzzing Target (${d#ns-3-dev-})"
    fi
done

echo ""
echo "========================================"
echo "[+] Selected environments built!"
echo "========================================"
