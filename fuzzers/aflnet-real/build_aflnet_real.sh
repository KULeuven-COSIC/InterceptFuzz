#!/bin/bash
# =============================================================================
# Build the real AFLNet with the in-process transport (-N ipc://) and the
# THREAD protocol (-P THREAD). See README.md in this directory.
#
# Result: $AFLNET_DIR/afl-fuzz, $AFLNET_DIR/afl-clang-fast(++)
# =============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

AFLNET_REPO="${AFLNET_REPO:-https://github.com/aflnet/aflnet.git}"
AFLNET_COMMIT="${AFLNET_COMMIT:-96032f86d0005dfeeb41ea7b31103f1d1ff8f168}"
AFLNET_DIR="${AFLNET_DIR:-$SCRIPT_DIR/aflnet}"
PATCH="$SCRIPT_DIR/aflnet-ipc.patch"

# AFLNet uses the lower half of the bitmap for state transitions and the upper
# half for code coverage. 2^18 leaves 128K entries for code coverage instead of
# 32K with AFLNet's default of 16. Target and fuzzer MUST use the same value.
MAP_SIZE_POW2="${MAP_SIZE_POW2:-18}"

# The pass plugin must be built against the LLVM of the clang that compiles the
# target (afl-clang-fast calls 'clang' / 'clang++' from PATH, or $AFL_CC/$AFL_CXX).
if [[ -z "${LLVM_CONFIG:-}" ]]; then
    CLANG_MAJOR=$(clang --version 2>/dev/null | grep -oE 'version [0-9]+' | head -1 | grep -oE '[0-9]+' || true)
    if [[ -n "$CLANG_MAJOR" ]] && command -v "llvm-config-$CLANG_MAJOR" > /dev/null; then
        LLVM_CONFIG="llvm-config-$CLANG_MAJOR"
    else
        LLVM_CONFIG="llvm-config"
    fi
fi

CLEAN=0
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -c|--clean) CLEAN=1 ;;
        -h|--help)
            echo "Usage: $0 [-c|--clean]"
            echo "  Env: AFLNET_DIR (default: $AFLNET_DIR), MAP_SIZE_POW2 (default: 18), LLVM_CONFIG"
            exit 0 ;;
        *) echo "Unknown parameter: $1" >&2; exit 1 ;;
    esac
    shift
done

echo "========================================"
echo "[*] AFLNet dir     : $AFLNET_DIR"
echo "[*] AFLNet commit  : $AFLNET_COMMIT"
echo "[*] MAP_SIZE_POW2  : $MAP_SIZE_POW2"
echo "[*] LLVM_CONFIG    : $LLVM_CONFIG ($($LLVM_CONFIG --version))"
echo "[*] clang          : $(clang --version | head -1)"
echo "========================================"

LLVM_MAJOR=$($LLVM_CONFIG --version | cut -d. -f1)
CLANG_MAJOR=$(clang --version | grep -oE 'version [0-9]+' | head -1 | grep -oE '[0-9]+')
if [[ "$LLVM_MAJOR" != "$CLANG_MAJOR" ]]; then
    echo "[!] WARNING: llvm-config ($LLVM_MAJOR) and clang ($CLANG_MAJOR) differ;"
    echo "    the pass plugin will not load. Set LLVM_CONFIG or AFL_CC/AFL_CXX."
fi

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf "$AFLNET_DIR"
fi

if [[ ! -d "$AFLNET_DIR/.git" ]]; then
    git clone "$AFLNET_REPO" "$AFLNET_DIR"
    git -C "$AFLNET_DIR" checkout -q "$AFLNET_COMMIT"
    git -C "$AFLNET_DIR" apply "$PATCH"
    echo "[+] Applied $(basename "$PATCH")"
elif git -C "$AFLNET_DIR" apply --check "$PATCH" 2> /dev/null; then
    git -C "$AFLNET_DIR" apply "$PATCH"
    echo "[+] Applied $(basename "$PATCH")"
else
    echo "[*] Patch already applied (or tree modified); building as is."
fi

cd "$AFLNET_DIR"
# AFL_NO_X86: AFL 2.x's x86 self-test uses implicit int, which clang >= 16
# rejects; afl-gcc / afl-as are not used here (only llvm_mode).
export LLVM_CONFIG MAP_SIZE_POW2 AFL_NO_X86=1
# Plain compilers: llvm_mode's self-test expands "AFL_CC=$(CC)", which breaks
# with launcher-style values such as CC="ccache clang" (set in the base image).
export CC=clang CXX=clang++
make clean > /dev/null 2>&1 || true
make all
make -C llvm_mode

echo "[+] AFLNet built: $AFLNET_DIR/afl-fuzz, $AFLNET_DIR/afl-clang-fast"
