#!/usr/bin/env bash

# Replays a queue on an AddressSanitizer build and keeps the crashing inputs
# (the first one and the one with the fewest packets).
#
# ASan builds: ./build_openthread.sh -f asan  -> /workspace/openthread-asan/build/tests/fuzz/fuzz_test_form_join-fuzzer
#              ./build_ns-3-dev.sh -f asan -p WIFI|LTE -> /workspace/ns-3-dev-asan/build/scratch/fuzz/ns3-dev-target-default
TARGET=""

# ================= DEFAULTS =================
SEEDS_DIR=""
OUTPUT_DIR="asan_crashes"
TIMEOUT_SEC="2"
SUDO_CMD=""
# ============================================

draw_progress_bar() {
    local current="$1"
    local total="$2"
    local msg="${3:-}"

    local width=20
    local percent=$((100 * current / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))

    local bar_filled
    local bar_empty

    bar_filled="$(printf '%*s' "$filled" '' | tr ' ' '#')"
    bar_empty="$(printf '%*s' "$empty" '' | tr ' ' '.')"

    printf "\r[%s%s] %3d%% (%d/%d) %s\033[K" \
        "$bar_filled" "$bar_empty" "$percent" "$current" "$total" "$msg"
}

usage() {
    echo "Usage: $(basename "$0") -t <asan binary> -s <seeds_dir> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -t PATH      AddressSanitizer build of the target"
    echo "  -s DIR       Directory containing the queue/seeds to test"
    echo ""
    echo "Optional:"
    echo "  -o DIR       Directory to save crashing seeds (Default: 'asan_crashes')"
    echo "  -T SEC       Timeout for each seed execution (Default: 2 seconds)"
    echo "  -S           Run target with sudo"
    echo "  -h           Show this help message"
    exit 1
}

# Function to count packets in LV binary format:
# [4 bytes total length BE] [4 bytes pkt 1 len BE] [pkt 1 data] ...
count_packets() {
    local seed_file="$1"

    python3 - "$seed_file" <<'PY'
import sys
import struct

path = sys.argv[1]

try:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 4:
        print(0)
        sys.exit(0)

    # 4 bytes total length (Big-Endian)
    total_len = struct.unpack(">I", data[:4])[0]

    offset = 4
    packets = 0
    file_len = len(data)

    # Parse packet lengths.
    while offset + 4 <= file_len:
        pkt_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4

        # Malformed packet length.
        if offset + pkt_len > file_len:
            break

        offset += pkt_len
        packets += 1

    print(packets)

except Exception:
    # Preserve the original behavior for malformed/unreadable files.
    print(999999999)
PY
}

# ================= PARSE FLAGS =================
while getopts ":t:s:o:T:Sh" opt; do
    case "$opt" in
        t)
            TARGET="$OPTARG"
            ;;
        s)
            SEEDS_DIR="$OPTARG"
            ;;
        o)
            OUTPUT_DIR="$OPTARG"
            ;;
        T)
            TIMEOUT_SEC="$OPTARG"
            ;;
        S)
            SUDO_CMD="sudo -E"
            ;;
        h)
            usage
            ;;
        :)
            echo "Error: Option -$OPTARG requires an argument."
            usage
            ;;
        \?)
            echo "Error: Invalid option -$OPTARG"
            usage
            ;;
    esac
done

# ================= VALIDATION =================
if [ -z "$SEEDS_DIR" ]; then
    echo "Error: Seeds Directory (-s) is required."
    usage
fi

if [ ! -d "$SEEDS_DIR" ]; then
    echo "Error: Seeds directory '$SEEDS_DIR' does not exist."
    exit 1
fi

if [ ! -x "$TARGET" ]; then
    echo "Error: Target binary not found or not executable at:"
    echo "  $TARGET"
    echo "Build it first (see the header of this script)."
    exit 1
fi

if ! [[ "$TIMEOUT_SEC" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v t="$TIMEOUT_SEC" 'BEGIN { exit !(t > 0) }'; then
    echo "Error: Timeout must be a positive number."
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "Error: 'timeout' command not found."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: 'python3' command not found."
    exit 1
fi

if [ -n "$SUDO_CMD" ] && ! command -v sudo >/dev/null 2>&1; then
    echo "Error: 'sudo' command not found, but -S was specified."
    exit 1
fi

# ================= OUTPUT DIRECTORIES =================
mkdir -p "$OUTPUT_DIR/first" "$OUTPUT_DIR/shortest"

# ASan:
#   halt_on_error=1  -> stop immediately on sanitizer error
#   exitcode=42      -> use 42 as the process exit code
#   symbolize=0      -> don't spend time symbolizing output
export ASAN_OPTIONS="halt_on_error=1:exitcode=42:symbolize=0"

echo "============================================"
echo "[*] Target       : $TARGET"
echo "[*] Seeds Dir    : $SEEDS_DIR"
echo "[*] Output Dir   : $OUTPUT_DIR"
echo "[*] Timeout      : ${TIMEOUT_SEC}s"
if [ -n "$SUDO_CMD" ]; then
    echo "[*] Sudo         : enabled"
else
    echo "[*] Sudo         : disabled"
fi
echo "============================================"

# ================= GATHER SEEDS =================
# sort -V gives natural ordering where supported.
mapfile -t seeds < <(
    find "$SEEDS_DIR" -maxdepth 1 -type f ! -name ".*" -print | sort -V
)

total=${#seeds[@]}
count=0
crash_count=0

FIRST_CRASH=""
FIRST_CRASH_PKTS=0
MIN_PKTS=999999999
SHORTEST_CRASH=""

if [ "$total" -eq 0 ]; then
    echo "No seeds found in $SEEDS_DIR!"
    exit 1
fi

echo "Scanning queue for crashes..."

# ================= TEST SEEDS =================
for f in "${seeds[@]}"; do
    [ -f "$f" ] || continue

    count=$((count + 1))

    draw_progress_bar "$count" "$total" "Testing: $(basename "$f")"

    if [ -n "$SUDO_CMD" ]; then
        timeout --signal=KILL "$TIMEOUT_SEC" \
            sudo -E "$TARGET" "$f" \
            >/dev/null 2>&1
    else
        timeout --signal=KILL "$TIMEOUT_SEC" \
            "$TARGET" "$f" \
            >/dev/null 2>&1
    fi

    exit_code=$?

    # timeout returns:
    #   124 = command timed out
    #   137 = command was killed by SIGKILL
    #
    # ASan returns 42 because of exitcode=42.
    #
    # Other signal-based failures are treated as crashes.
    if [[ "$exit_code" -eq 42 ]] ||
       { [[ "$exit_code" -ge 128 ]] &&
         [[ "$exit_code" -ne 137 ]] &&
         [[ "$exit_code" -ne 124 ]]; }; then

        crash_count=$((crash_count + 1))

        pkts="$(count_packets "$f")"

        # Record first crash.
        if [ -z "$FIRST_CRASH" ]; then
            FIRST_CRASH="$f"
            FIRST_CRASH_PKTS="$pkts"
            cp -- "$f" "$OUTPUT_DIR/first/"
        fi

        # Track shortest crashing seed.
        if [ "$pkts" -lt "$MIN_PKTS" ]; then
            MIN_PKTS="$pkts"
            SHORTEST_CRASH="$f"
        fi
    fi
done

echo -e "\n\n============================================"

# ================= RESULTS =================
if [ "$crash_count" -gt 0 ]; then
    cp -- "$SHORTEST_CRASH" "$OUTPUT_DIR/shortest/"

    echo "[+] Done! Found $crash_count crashing seeds."
    echo "[+] First crash seed   : $(basename "$FIRST_CRASH") ($FIRST_CRASH_PKTS packets)"
    echo "    Saved to           : $OUTPUT_DIR/first/"
    echo "[+] Shortest crash seed: $(basename "$SHORTEST_CRASH") ($MIN_PKTS packets)"
    echo "    Saved to           : $OUTPUT_DIR/shortest/"

    # Generate summary.
    cat > "$OUTPUT_DIR/summary.txt" <<EOF
Total Crashing Seeds: $crash_count
First Crash: $(basename "$FIRST_CRASH") (Packets: $FIRST_CRASH_PKTS, Full Path: $FIRST_CRASH)
Shortest Crash: $(basename "$SHORTEST_CRASH") (Packets: $MIN_PKTS, Full Path: $SHORTEST_CRASH)
EOF

    echo "[+] Summary written to: $OUTPUT_DIR/summary.txt"
else
    echo "[-] Done. No crashes found in this queue."
    rm -rf -- "$OUTPUT_DIR" 2>/dev/null || true
fi
