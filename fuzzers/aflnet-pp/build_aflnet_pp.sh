#!/bin/bash
# =============================================================================
# Build AFLNet on AFL++ ("AFLNet-pp"): AFL++ at the same commit as the AFL++
# used by Concat and InterceptFuzz, patched with the AFLNet algorithm.
# Only afl-fuzz is built; targets are compiled with the regular AFL++
# afl-clang-lto / afl-clang-fast (same instrumentation as Concat).
#
# Result: $AFLNET_PP_DIR/afl-fuzz
# =============================================================================
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

AFLPP_REPO="${AFLPP_REPO:-https://github.com/AFLplusplus/AFLplusplus}"
# Must match the AFL++ commit in the base Dockerfile
AFLPP_COMMIT="${AFLPP_COMMIT:-247e8241b4b56520f50846433ac9d10b338e8961}"
AFLNET_PP_DIR="${AFLNET_PP_DIR:-$SCRIPT_DIR/aflpp}"
PATCH="$SCRIPT_DIR/aflnet-pp.patch"

CLEAN=0
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -c|--clean) CLEAN=1 ;;
        -h|--help)
            echo "Usage: $0 [-c|--clean]"
            echo "  Env: AFLNET_PP_DIR (default: $AFLNET_PP_DIR), AFLPP_COMMIT"
            exit 0 ;;
        *) echo "Unknown parameter: $1" >&2; exit 1 ;;
    esac
    shift
done

echo "========================================"
echo "[*] AFLNet-pp dir : $AFLNET_PP_DIR"
echo "[*] AFL++ commit  : $AFLPP_COMMIT"
echo "========================================"

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf "$AFLNET_PP_DIR"
fi

if [[ ! -d "$AFLNET_PP_DIR/.git" ]]; then
    git clone "$AFLPP_REPO" "$AFLNET_PP_DIR"
    git -C "$AFLNET_PP_DIR" checkout -q "$AFLPP_COMMIT"
    git -C "$AFLNET_PP_DIR" apply "$PATCH"
    echo "[+] Applied $(basename "$PATCH")"
elif git -C "$AFLNET_PP_DIR" apply --check "$PATCH" 2> /dev/null; then
    git -C "$AFLNET_PP_DIR" apply "$PATCH"
    echo "[+] Applied $(basename "$PATCH")"
else
    echo "[*] Patch already applied (or tree modified); building as is."
fi

cd "$AFLNET_PP_DIR"
# Plain compilers (the base image sets CC="ccache clang"); only afl-fuzz is
# needed, NO_PYTHON/NO_NYX as nothing of that is used.
export CC=clang CXX=clang++
make afl-fuzz NO_PYTHON=1 NO_NYX=1

echo "[+] AFLNet-pp built: $AFLNET_PP_DIR/afl-fuzz"
