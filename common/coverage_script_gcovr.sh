#!/bin/bash

# ================= DEFAULTS =================
ROOT_DIR="."
FILTERS=()
SUDO_CMD=""  
GCOV_WRAPPER_SCRIPT="/workspace/common/gcov-wrapper.sh"
CSV_FILE="coverage_over_time.csv"
PATTERN="*"
TRACK_MODE="none" # none, auto, count, time
INTERVAL_VAL=0
TOTAL_TIME=0
STRATEGY="uniform" # uniform, linear
LAST_COV_SEC=0
FILTER_CRASHES=false
KEEP_COVERAGE=false
OUT_JSON="coverage.json"
# ============================================

draw_progress_bar() {
    local current=$1
    local total=$2
    local msg=${3:-""} 

    local width=20
    local percent=$(( 100 * current / total ))
    local filled=$(( width * current / total ))
    local empty=$(( width - filled ))

    local bar_filled=$(printf "%${filled}s" | tr ' ' '#')
    local bar_empty=$(printf "%${empty}s" | tr ' ' '.')

    printf "\r[%s%s] %3d%% (%d/%d) %s\033[K" \
           "$bar_filled" "$bar_empty" "$percent" "$current" "$total" "$msg"
}

usage() {
    echo "Usage: $(basename "$0") -t <target> -s <seeds_dir> -o <output_file> [OPTIONS]"
    echo "Required:"
    echo "  -t <target>         Path to target binary"
    echo "  -s <seeds_dir>      Directory containing seeds"
    echo "  -o <output_file>    File to save the final coverage summary"
    echo ""
    echo "Optional:"
    echo "  -p <file_pattern>   Filename format to match seeds (Default: '*')"
    echo "  -w <wrapper_script> Path to gcov wrapper script"
    echo "  -c <csv_file>       Output CSV file for interval tracking (Default: coverage_over_time.csv)"
    echo "  -r <root_dir>       Root directory for coverage analysis (Default: '.')"
    echo "  -f <filter_regex>   Add a gcovr filter (can be used multiple times)"
    echo "  -a                  Enable AUTO interval (samples at Total / 50)"
    echo "  -i <number>         Enable COUNT interval (samples every N seeds)"
    echo "  -T <seconds>        Enable TIME interval (samples every X seconds of elapsed fuzzer time)"
    echo "  -D <seconds>        Total time allocated for all iterations (used to offset time for iter_XX seeds)"
    echo "  -d <strategy>       Time distribution strategy across iterations: 'uniform' or 'linear' (Default: uniform)"
    echo "  -X                  Exclude crashing seeds before gathering coverage"
    echo "  -k                  Keep existing coverage data instead of clearing it"
    echo "  -S                  Run target with sudo"
    echo "  -h                  Show this help message"
    echo "  -j                  Out json coverage report to coverage.json"
    exit 1
}

# Parse flags
while getopts ":t:s:o:c:p:w:r:f:i:T:D:d:j:aXkSh" opt; do
  case ${opt} in
    t) TARGET="$OPTARG" ;;
    s) SEEDS_DIR="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    c) CSV_FILE="$OPTARG" ;;
    p) PATTERN="$OPTARG" ;;
    w) GCOV_WRAPPER_SCRIPT="$OPTARG" ;;
    r) ROOT_DIR="$OPTARG" ;;
    f) FILTERS+=(--filter "$OPTARG") ;;
    i) TRACK_MODE="count"; INTERVAL_VAL="$OPTARG" ;;
    T) TRACK_MODE="time"; INTERVAL_VAL="$OPTARG" ;;
    D) TOTAL_TIME="$OPTARG" ;;
    d) STRATEGY="${OPTARG,,}" ;; # Convert to lowercase
    j) OUT_JSON="$OPTARG" ;;
    a) TRACK_MODE="auto" ;;
    X) FILTER_CRASHES=true ;;
    k) KEEP_COVERAGE=true ;;
    S) SUDO_CMD="sudo -E" ;;  
    h) usage ;;
    *) usage ;;
  esac
done

if [ -z "$TARGET" ] || [ -z "$SEEDS_DIR" ] || [ -z "$OUTPUT_FILE" ] || [ -z "$GCOV_WRAPPER_SCRIPT" ]; then
    echo "Error: Missing required arguments."
    usage
fi

if [[ "$STRATEGY" != "uniform" && "$STRATEGY" != "linear" ]]; then
    echo "Error: Strategy (-d) must be 'uniform' or 'linear'."
    exit 1
fi

cd "$ROOT_DIR" || exit

run_target() {
    $SUDO_CMD "$TARGET" "$1" > /dev/null 2>&1
    return $?
}

echo "Preparing seeds from $SEEDS_DIR..."
seeds=($(find "$SEEDS_DIR" -maxdepth 1 -type f -name "$PATTERN" ! -name ".*" | sort -V))
total=${#seeds[@]}

if [ "$total" -eq 0 ]; then
    echo "No seeds found in $SEEDS_DIR!"
    exit 1
fi

# ================= PRE-FILTERING PASS =================
if [ "$FILTER_CRASHES" = true ]; then
    echo "Pre-filtering crashing seeds..."
    valid_seeds=()
    count=0
    for f in "${seeds[@]}"; do
        count=$((count + 1))
        draw_progress_bar $count $total "Testing: $(basename "$f")"
        
        run_target "$f"
        exit_code=$?
        
        # Keep the seed only if it didn't crash via a fatal signal (>= 128)
        if [ $exit_code -lt 128 ]; then
            valid_seeds+=("$f")
        fi
    done
    echo ""
    
    # Update the arrays and totals for the main loop
    seeds=("${valid_seeds[@]}")
    new_total=${#seeds[@]}
    echo "Filtered out $((total - new_total)) crashing seeds. $new_total remaining."
    total=$new_total

    if [ "$total" -eq 0 ]; then
        echo "Error: All seeds crashed! Nothing left to process."
        exit 1
    fi
fi
# ======================================================

if [ "$KEEP_COVERAGE" = false ]; then
    echo "Clearing previous coverage data..."
    find . -name "*.gcda" -delete
else
    echo "Keeping existing coverage data..."
fi

# ================= FORMAT DETECTION & VALIDATION =================
if [ "$TRACK_MODE" != "none" ]; then
    FORMAT="OLD"
    
    # Smarter detection: scan queue to see if ANY seed contains 'time:'
    for s in "${seeds[@]}"; do
        if [[ "$(basename "$s")" == *time:* ]]; then
            FORMAT="NEW"
            break
        fi
    done

    # If it's the NEW format, calculate the max iterations for dynamic time scaling
    MAX_ITER=1
    if [ "$FORMAT" = "NEW" ] && [ "$TOTAL_TIME" -gt 0 ]; then
        for s in "${seeds[@]}"; do
            if [[ "$(basename "$s")" =~ iter_([0-9]+) ]]; then
                ITER_STR="${BASH_REMATCH[1]}"
                ITER_NUM=$((10#$ITER_STR))
                if [ "$ITER_NUM" -gt "$MAX_ITER" ]; then
                    MAX_ITER=$ITER_NUM
                fi
            fi
        done
        echo "Detected $MAX_ITER iteration(s). Using '$STRATEGY' time distribution over ${TOTAL_TIME}s."
    fi

    # If it's the OLD format, find the first valid timestamp to use as START_TS
    if [ "$FORMAT" = "OLD" ]; then
        START_TS=""
        for s in "${seeds[@]}"; do
            if [[ "$(basename "$s")" =~ _([0-9]+)\.bin$ ]]; then
                START_TS="${BASH_REMATCH[1]}"
                break
            fi
        done
        # Fallback if no timestamps exist at all
        if [ -z "$START_TS" ]; then
            START_TS=0
        fi
    fi

    # ================= CSV INITIALIZATION & RESUME LOGIC =================
    RESUME_MODE=false
    LAST_CSV_SEC=-1

    if [ -f "$CSV_FILE" ]; then
        # Check if the CSV has existing data to resume from
        LAST_LINE=$(tail -n 1 "$CSV_FILE" 2>/dev/null)
        if [[ "$LAST_LINE" != Iteration* ]] && [[ -n "$LAST_LINE" ]]; then
            RESUME_MODE=true
            LAST_CSV_SEC=$(echo "$LAST_LINE" | awk -F',' '{print $2}')
            
            # Basic validation to ensure it's a number
            if [[ "$LAST_CSV_SEC" =~ ^[0-9]+$ ]]; then
                LAST_COV_SEC=$LAST_CSV_SEC  # Sync internal tracker for intervals
                echo "Found existing CSV. Resuming coverage gathering AFTER ${LAST_CSV_SEC}s..."
            else
                LAST_CSV_SEC=-1
                RESUME_MODE=false
            fi
        fi
    fi

    if [ "$RESUME_MODE" = false ]; then
        # If no valid CSV exists, start fresh with headers
        echo "Iteration,Time_Seconds,Line_Cov_Pct,Line_Cov_Abs,Func_Cov_Pct,Func_Cov_Abs,Branch_Cov_Pct,Branch_Cov_Abs" > "$CSV_FILE"
    fi

    if [ "$TRACK_MODE" = "auto" ]; then
        INTERVAL_VAL=$(( total / 50 ))
        [ $INTERVAL_VAL -eq 0 ] && INTERVAL_VAL=1
        echo "Sampling coverage every $INTERVAL_VAL seeds (AUTO)..."
    elif [ "$TRACK_MODE" = "count" ]; then
        echo "Sampling coverage every $INTERVAL_VAL seeds (COUNT)..."
    elif [ "$TRACK_MODE" = "time" ]; then
        echo "Sampling coverage every $INTERVAL_VAL seconds of elapsed fuzzer time (TIME)..."
    fi
fi

if [ "$TRACK_MODE" = "none" ]; then
    echo "Interval tracking disabled. Executing seeds rapidly..."
fi

# ================= MAIN EXECUTION LOOP =================
count=0
for f in "${seeds[@]}"; do
    [ -f "$f" ] || continue
    count=$((count + 1))

    draw_progress_bar $count $total "Processing: $(basename "$f")"
    
    # We always execute the seed to build up internal .gcda state
    run_target "$f"

    if [ "$TRACK_MODE" != "none" ]; then
        CURRENT_FILE=$(basename "$f")
        ITER_NUM="1"
        ELAPSED_SEC=0
        
        # Super-fast native bash regex extraction
        if [ "$FORMAT" = "NEW" ]; then
            # Extract iteration (e.g., iter_01)
            if [[ "$CURRENT_FILE" =~ iter_([0-9]+) ]]; then
                ITER_STR="${BASH_REMATCH[1]}"
                ITER_NUM=$((10#$ITER_STR)) # Base-10 conversion to prevent octal errors
            fi
            
            # Extract time in ms
            if [[ "$CURRENT_FILE" =~ time:([0-9]+) ]]; then
                TIME_MS="${BASH_REMATCH[1]}"
                BASE_SEC=$(( TIME_MS / 1000 ))
                
                # Calculate the time offset based on strategy
                if [ "$ITER_NUM" -gt 0 ] && [ "$TOTAL_TIME" -gt 0 ]; then
                    if [ "$STRATEGY" = "linear" ]; then
                        # Sum(1..N) = N*(N+1)/2. 
                        # Sum of previous K-1 iterations: (K-1)*K/2
                        OFFSET=$(( (ITER_NUM - 1) * ITER_NUM * TOTAL_TIME / (MAX_ITER * (MAX_ITER + 1)) ))
                    else
                        # Uniform distribution: (K-1) * (Total / Max)
                        OFFSET=$(( (ITER_NUM - 1) * TOTAL_TIME / MAX_ITER ))
                    fi
                    ELAPSED_SEC=$(( OFFSET + BASE_SEC ))
                else
                    ELAPSED_SEC=$(( BASE_SEC ))
                fi
            else
                # Default to 0 for initial seeds like 'seed_0'
                ELAPSED_SEC=0
            fi
        else
            # Extract old absolute timestamp
            if [[ "$CURRENT_FILE" =~ _([0-9]+)\.bin$ ]]; then
                CURRENT_TS="${BASH_REMATCH[1]}"
                ELAPSED_SEC=$(( (CURRENT_TS - START_TS) / 1000 ))
            else
                # Default to 0 for initial seeds like 'seed_0'
                ELAPSED_SEC=0
            fi
        fi

        # Determine if it's time to run GCOVR based on the selected mode
        RUN_GCOVR=false
        
        if [ "$TRACK_MODE" = "count" ] || [ "$TRACK_MODE" = "auto" ]; then
            if (( count % INTERVAL_VAL == 0 )) || (( count == total )); then
                RUN_GCOVR=true
            fi
        elif [ "$TRACK_MODE" = "time" ]; then
            # Check if the elapsed time has passed our interval window
            if (( ELAPSED_SEC - LAST_COV_SEC >= INTERVAL_VAL )) || (( count == total )); then
                RUN_GCOVR=true
                LAST_COV_SEC=$ELAPSED_SEC
            fi
        fi

        # === RESUME OVERRIDE ===
        # If we haven't surpassed the CSV's latest entry, skip the heavy gcovr reporting
        if [ "$RESUME_MODE" = true ] && [ "$ELAPSED_SEC" -le "$LAST_CSV_SEC" ]; then
            RUN_GCOVR=false
        fi

        # Execute GCOVR
        if [ "$RUN_GCOVR" = true ]; then
            GCOVR_OUT=$(python3 -m gcovr \
                --root "$ROOT_DIR" \
                --gcov-executable "$GCOV_WRAPPER_SCRIPT" \
                "${FILTERS[@]}" \
                -j 1 \
                --gcov-suspicious-hits-threshold=0 \
                --merge-mode-functions=separate \
                -s)
            
            # Extract BOTH percentage and absolute covered values.
            # `gsub(/%|\(/, "")` removes the % and ( symbols.
            # `print $2 "," $3` outputs them already formatted for the CSV (e.g. "23.9,42208")
            LINE_STATS=$(echo "$GCOVR_OUT" | grep "^lines:" | awk '{gsub(/%|\(/, ""); print $2 "," $3}')
            FUNC_STATS=$(echo "$GCOVR_OUT" | grep "^functions:" | awk '{gsub(/%|\(/, ""); print $2 "," $3}')
            BRANCH_STATS=$(echo "$GCOVR_OUT" | grep "^branches:" | awk '{gsub(/%|\(/, ""); print $2 "," $3}')
            
            # Append to CSV
            echo "$ITER_NUM,$ELAPSED_SEC,$LINE_STATS,$FUNC_STATS,$BRANCH_STATS" >> "$CSV_FILE"
        fi
    fi
done
echo "" 

echo "Generating full coverage report..."
GCOVR_CMD=(
    python3 -m gcovr
    --root "$ROOT_DIR"
    --gcov-executable "$GCOV_WRAPPER_SCRIPT"
    "${FILTERS[@]}"
    -j 1
    --gcov-suspicious-hits-threshold=0
    -s
    --merge-mode-functions=separate
    --json
    ${OUT_JSON}
)
echo "Running the command: ${GCOVR_CMD[@]} > \"$OUTPUT_FILE\" 2>&1"
"${GCOVR_CMD[@]}" > "$OUTPUT_FILE" 2>&1

echo "Summary saved to $OUTPUT_FILE. Sneak peek into the results:"
tail -n 6 "$OUTPUT_FILE"

if [ -f "$CSV_FILE" ] && [ "$TRACK_MODE" != "none" ]; then
    echo "Multi-metric time-series CSV saved to $CSV_FILE"
fi