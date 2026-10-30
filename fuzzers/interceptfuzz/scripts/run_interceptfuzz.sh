#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

############################################
# Ctrl+C / SIGTERM handling (kill whole group)
############################################
on_abort() {
  echo -e "\n[!] Ctrl+C (or SIGTERM) detected — stopping all children..."
  trap - INT TERM           # avoid recursive traps
  kill -TERM 0 2>/dev/null || true   # signal entire process group
  # Give a brief moment for graceful shutdowns, then force
  sleep 1
  kill -KILL 0 2>/dev/null || true
  exit 130
}
trap on_abort INT TERM

############################################
# Defaults (tweak as you like)
############################################
ITERATIONS=10
INTERCEPTFUZZ_DIR="/workspace/fuzzers/interceptfuzz"

# Coverage Defaults
COV_TARGET=""
COV_ROOT=""
GCOVR_FILTER_OPTS=()

# RUN_SRSRAN_UL_FUZZING_SCRIPT="$INTERCEPTFUZZ_DIR/scripts/bash/run_srsran_ul_fuzzing.sh"
GCOV_WRAPPER_SCRIPT="/workspace/common/gcov-wrapper.sh"
STATE_DB_TRIM_SCRIPT="$INTERCEPTFUZZ_DIR/scripts/trim_state_db.py"
CREATE_REPLAYABLE_QUEUE="$INTERCEPTFUZZ_DIR/scripts/create_replayable_queue.py"
#PRUNE_PERCENTAGE=30
INIT_STATE_DB_PATH=""
INIT_SEEDS_PATH=""
# User supplies TOTAL seconds for all iterations via -T
TOTAL_TIME_SECONDS="36000"           # e.g., 7200 for 2 hours total
TIMEOUT_STRATEGY="uniform"             # 'uniform' or 'linear'
ENGINE="AFL"  # Default engine
USE_SUDO=0

AFL_STATIC_OPTS=()  # -g 8 -G 135 # static AFL options; edit as needed
LIBFUZZER_STATIC_OPTS=( -rss_limit_mb=3000 -workers=1 -jobs=500 -print_final_stats=1 -use_counters=1 -max_len=1024 -print_pcs=1 -timeout=30 -detect_leaks=0 )

FUZZER_EXTRA_OPTS=()
TARGET_EXTRA_OPTS=()

# Optional: bitmap size for afl-showmap (leave empty to not force). Set e.g. 262144 or 1048576.
MAP_SIZE="375694"

# Experiments location controls
EXPERIMENTS_BASE_DEFAULT="${INTERCEPTFUZZ_DIR}/experiments"
EXPERIMENTS_BASE="$EXPERIMENTS_BASE_DEFAULT"  # -B to change
RUN_TAG=""                                     # -N to set; auto timestamp if empty
EXPERIMENTS_ROOT_OVERRIDE=""                   # -E to fully override

COVERAGE_SCRIPT_PATH="/workspace/common/coverage_script_gcovr.sh"

############################################
# Usage
############################################
usage() {
  cat <<'EOF'
Usage: script.sh -t /path/to/target [options]

Required:
  -t PATH    Target binary/executable to fuzz

Common options:
  -e ENGINE  Fuzzing engine: AFL (default), LIBFUZZER 
  -n N       Number of iterations (default: 10)
  -T SEC     TOTAL time budget across ALL iterations, in seconds (default: 36000)
  -D STRAT   Timeout distribution strategy: 'uniform' or 'linear' (default: uniform)
  -M N       AFL bitmap size for afl-showmap (AFL_MAP_SIZE); unset to skip
  -I PATH    INIT_STATE_DB_PATH (optional; if unset, script decides default)
  -J DIR     INIT_SEEDS_PATH (optional; if unset, script decides default)
  -s         Run target and fuzzer with 'sudo -E'
  -v         Verbose (set -x)

Experiments location (refactored):
  -B DIR     Base experiments directory (default: ${INTERCEPTFUZZ_DIR}/experiments)
  -N NAME    Run tag (default: RUN_YYYY-MM-DD_HH-MM-SS)
  -E DIR     FULL override for EXPERIMENTS_ROOT (takes precedence over -B/-N)

Fuzzer flags:
  -A "FLAGS" Add custom flags for the fuzzer. You can repeat -A multiple times.
             Example: -A "-M main" -A "-p fast -m none"

Target flags:
  -F "FLAGS" Add custom flags for the target binary. You can repeat -F.
             Example: -F "--enable-foo -p 123"

Coverage flags:
  -c PATH    Coverage target binary/executable to gather the coverage from
  -r PATH    Coverage root folder
  -f "FLAGS" Coverage filter options. Ex. -f "srsenb.*" -f "srsepc/.*"

Notes:
- AFL calls target as:  TARGET @@ [TARGET_FLAGS...]
- LibFuzzer is BAD at handling the target flags. So, avoid using -F with LibFuzzer!
- Per-iteration snapshots under: <EXPERIMENTS_ROOT>/iter_artifacts/iter_XX/
- TOTAL time (-T) is split according to -D strategy.
EOF
}

############################################
# Parse args
############################################
VERBOSE=0
TARGET=""

# Added D: to the getopts string
while getopts ":t:e:n:T:D:M:B:N:E:A:F:I:J:c:r:f:s:v" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    e) ENGINE=$(echo "$OPTARG" | tr '[:lower:]' '[:upper:]') ;;
    n) ITERATIONS="$OPTARG" ;;
    T) TOTAL_TIME_SECONDS="$OPTARG" ;;
    D) TIMEOUT_STRATEGY="$OPTARG" ;;
    M) MAP_SIZE="$OPTARG" ;;
    B) EXPERIMENTS_BASE="$OPTARG" ;;
    N) RUN_TAG="$OPTARG" ;;
    E) EXPERIMENTS_ROOT_OVERRIDE="$OPTARG" ;;
    A)
       # Accept multiple -A; split OPTARG into an array safely
       read -r -a _tmpA <<<"$OPTARG"
       FUZZER_EXTRA_OPTS+=("${_tmpA[@]}")
       ;;
    F)
       # Collect target flags; can repeat -F
       read -r -a _tmpF <<<"$OPTARG"
       TARGET_EXTRA_OPTS+=("${_tmpF[@]}")
       ;;
    I) INIT_STATE_DB_PATH="$OPTARG" ;;
    J) INIT_SEEDS_PATH="$OPTARG" ;;
    c) COV_TARGET="$OPTARG" ;;
    r) COV_ROOT="$OPTARG" ;;
    f)
       # Collect coverage filters; can repeat -f
       read -r -a _tmpCovF <<<"$OPTARG"
       GCOVR_FILTER_OPTS+=("${_tmpCovF[@]}")
       ;;
    s) USE_SUDO=1 ;;
    v) VERBOSE=1 ;;
    :) echo "Missing value for -$OPTARG" >&2; usage; exit 2 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))
[[ ${VERBOSE} -eq 1 ]] && set -x

# Set the sudo prefix based on the -s flag
SUDO_CMD=()
if [[ "$USE_SUDO" -eq 1 ]]; then
  SUDO_CMD=(sudo -E)
fi

############################################
if [[ "$ENGINE" == "AFL" ]]; then
  TARGET_CMD=("$TARGET" "@@" "${TARGET_EXTRA_OPTS[@]}")
elif [[ "$ENGINE" == "LIBFUZZER" ]]; then
  TARGET_CMD=("$TARGET" "${TARGET_EXTRA_OPTS[@]}")
else
  echo "Unknown fuzzing ENGINE: $ENGINE" >&2
  exit 2
fi

############################################
# Fuzzing Logic
############################################
run_fuzz_engine() {
  local seeds_in="$1"
  local out_dir="$2"
  local timeout_sec="$3"
  local fuzz_config_path="$4"

  export INTERCEPTFUZZ_CONFIG_PATH="$fuzz_config_path"
  if [[ "$ENGINE" == "AFL" ]]; then
    AFL_CMD=("${SUDO_CMD[@]}" afl-fuzz "${AFL_STATIC_OPTS[@]}" "${FUZZER_EXTRA_OPTS[@]}" \
             -V "$timeout_sec" -o "$out_dir" -i "$seeds_in" -- "${TARGET}" "@@" "${TARGET_EXTRA_OPTS[@]}")
    echo "Running AFL command: ${AFL_CMD[@]}"
    "${AFL_CMD[@]}" || true
  elif [[ "$ENGINE" == "LIBFUZZER" ]]; then
    # LibFuzzer runs the binary directly
    # -artifact_prefix ensures crashes/artifacts go to the iteration folder
    LF_CMD=("${SUDO_CMD[@]}" timeout "$timeout_sec" "$TARGET" "$seeds_in" \
            "${LIBFUZZER_STATIC_OPTS[@]}" \
            "${FUZZER_EXTRA_OPTS[@]}" \
            -artifact_prefix="${out_dir}/")
    echo "Running LibFuzzer command: ${LF_CMD[@]}"
    "${LF_CMD[@]}" || true
  fi
}

############################################
# Run save seeds logic
############################################
run_save_seeds() {
  local input_seed_path="$1"
  local save_seeds_config_path="$2"

  export INTERCEPTFUZZ_CONFIG_PATH="$save_seeds_config_path"
  if [[ "$ENGINE" == "AFL" ]]; then
    echo "[*] Running save_seeds for AFL on input seed: $input_seed_path"
    "${SUDO_CMD[@]}" "$TARGET" "$input_seed_path" || true
  elif [[ "$ENGINE" == "LIBFUZZER" ]]; then
    echo "[*] Running save_seeds for LibFuzzer on input seed: $input_seed_path"
    echo "CMD:"${SUDO_CMD[@]}" $TARGET $input_seed_path -timeout=30"
    "${SUDO_CMD[@]}" "$TARGET" "$input_seed_path" -timeout=30 || true
  fi
}

############################################
# Seed Minimization Logic
############################################
minimize_seeds() {
  local in_dir="$1"
  local out_dir="$2"
  local log_dir="$3"

  echo "[*] Minimizing seeds from $in_dir to $out_dir"

  if [[ "$ENGINE" == "AFL" ]]; then
    # AFL uses the external afl-cmin tool
    echo "CMD: ${SUDO_CMD[@]} afl-cmin -e -i $in_dir -o $out_dir ${AFL_STATIC_OPTS[@]} -- ${TARGET_CMD[@]}"
    "${SUDO_CMD[@]}" afl-cmin -A -e -i "$in_dir" -o "$out_dir" ${AFL_STATIC_OPTS[@]} -- "${TARGET_CMD[@]}" |& tee "${log_dir}/minimize.log"
  elif [[ "$ENGINE" == "LIBFUZZER" ]]; then
    # LibFuzzer uses the built-in -merge=1 flag
    # Note: out_dir must exist for LibFuzzer merge
    echo "CMD: ${SUDO_CMD[@]} ${TARGET_CMD[@]} -merge=1 $out_dir $in_dir -artifact_prefix=${out_dir}/ -rss_limit_mb=3000 -timeout=30 -detect_leaks=0"
    "${SUDO_CMD[@]}" "${TARGET_CMD[@]}" -merge=1 "$out_dir" "$in_dir" -artifact_prefix="${out_dir}/" -rss_limit_mb=3000 -timeout=30 -detect_leaks=0 |& tee "${log_dir}/minimize.log"
  fi
}

############################################
# Checks & setup (paths that depend on target/run tag)
############################################
require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1" >&2; exit 1; }; }

require timeout
if [[ "$ENGINE" == "AFL" ]]; then
  require afl-fuzz
  require afl-cmin
  require afl-showmap
fi

[[ -n "${TARGET:-}" ]] || { echo "Error: -t TARGET is required." >&2; usage; exit 2; }
[[ -x "$TARGET" ]] || { echo "Error: TARGET not executable: $TARGET" >&2; exit 1; }

TARGET_NAME="$(basename "$TARGET")"
if [[ -z "$RUN_TAG" ]]; then
  RUN_TAG="RUN_$(date +%F_%H-%M-%S)"
fi

if [[ -n "$EXPERIMENTS_ROOT_OVERRIDE" ]]; then
  EXPERIMENTS_ROOT="$EXPERIMENTS_ROOT_OVERRIDE"
else
  EXPERIMENTS_ROOT="${EXPERIMENTS_BASE}/${TARGET_NAME}/${RUN_TAG}/"
fi
mkdir -m 0777 -p "$EXPERIMENTS_ROOT"

# Prepare Coverage Argument Array
COV_SCRIPT_EXTRA_ARGS=()
for filter in "${GCOVR_FILTER_OPTS[@]}"; do
    COV_SCRIPT_EXTRA_ARGS+=(-f "$filter")
done
if [[ "$USE_SUDO" -eq 1 ]]; then
    COV_SCRIPT_EXTRA_ARGS+=(-S)
fi


# Clean temp files on exit
TMP_FILES=()
cleanup() { for f in "${TMP_FILES[@]:-}"; do [[ -e "$f" ]] && rm -f -- "$f" || true; done; }
trap cleanup EXIT

############################################
# Compute per-iteration timeouts
############################################
# If -T not given, default back to 300s per iteration (old behavior).
if [[ -z "$TOTAL_TIME_SECONDS" ]]; then
  TOTAL_SECONDS=$(( ITERATIONS * 300 ))
else
  TOTAL_SECONDS="$TOTAL_TIME_SECONDS"
fi

declare -a PER_ITER_TIMEOUTS=()

if [[ "$TIMEOUT_STRATEGY" == "linear" ]]; then
  # Linear ramp weights: 1, 2, ..., ITERATIONS
  # Each iteration i gets: floor(TOTAL * i / sumW), and remaining seconds
  # are handed to the LAST iterations first (priority to later iterations).
  sumW=$(( ITERATIONS * (ITERATIONS + 1) / 2 ))
  acc_alloc=0
  for ((k=1; k<=ITERATIONS; k++)); do
    base=$(( (TOTAL_SECONDS * k) / sumW ))
    PER_ITER_TIMEOUTS+=( "$base" )
    acc_alloc=$(( acc_alloc + base ))
  done

  rem=$(( TOTAL_SECONDS - acc_alloc ))
  for ((k=ITERATIONS-1; k>=0 && rem>0; k--)); do
    PER_ITER_TIMEOUTS[$k]=$(( PER_ITER_TIMEOUTS[$k] + 1 ))
    rem=$(( rem - 1 ))
  done
else
  # Default: Equal time for each iteration
  base=$(( TOTAL_SECONDS / ITERATIONS ))
  rem=$(( TOTAL_SECONDS % ITERATIONS ))
  
  for ((k=0; k<ITERATIONS; k++)); do
    val=$base
    # Distribute remainder seconds to the first 'rem' iterations
    if [[ $k -lt $rem ]]; then
      val=$(( val + 1 ))
    fi
    PER_ITER_TIMEOUTS+=( "$val" )
  done
fi

############################################
# Summary
############################################
echo "============================================"
echo "[*] Target: $TARGET_NAME"
echo "[*] Experiments root: $EXPERIMENTS_ROOT"
echo "[*] Total time budget: ${TOTAL_SECONDS}s across ${ITERATIONS} iterations"
echo "[*] Timeout strategy: $TIMEOUT_STRATEGY"
echo "[*] Per-iteration timeouts (seconds): ${PER_ITER_TIMEOUTS[*]}"
if ((${#FUZZER_EXTRA_OPTS[@]})); then
  echo "[*] Extra fuzzer flags: ${FUZZER_EXTRA_OPTS[*]}"
fi
if ((${#TARGET_EXTRA_OPTS[@]})); then
  echo "[*] Extra target flags: ${TARGET_EXTRA_OPTS[*]}"
fi
if [[ -n "$COV_TARGET" ]]; then
    echo "[*] Coverage enabled. Target: $COV_TARGET"
fi
echo "============================================"

############################################
# Initial setup
############################################
STATE_DB_PATH="${EXPERIMENTS_ROOT}/state_db.json"
if [[ -n $INIT_STATE_DB_PATH ]]; then
  echo "[*] Using provided initial state DB: $INIT_STATE_DB_PATH"
  cp "$INIT_STATE_DB_PATH" "$STATE_DB_PATH"
else
  echo "[*] No initial state DB path provided; using default empty state DB."
  echo "{\"state_counter_\":1,\"transitions\": []}" > "$STATE_DB_PATH"
fi

SEEDS_PATH="${EXPERIMENTS_ROOT}/seeds"
mkdir -m 0777 -p "$SEEDS_PATH"
if [[ -n "$INIT_SEEDS_PATH" ]]; then
  echo "[*] Copying initial seeds from $INIT_SEEDS_PATH to $SEEDS_PATH"
  cp -p -r "$INIT_SEEDS_PATH"/* "$SEEDS_PATH/" || true
else
  echo "[*] No initial seeds path provided; creating a dummy seed."
  echo -ne "\0\0\0\0\0\0" > "${SEEDS_PATH}/seed_0"
fi

############################################
# Iterate
############################################
for ((i=1; i<=ITERATIONS; i++)); do
  ITER_TAG=$(printf "iter_%02d" "$i")
  ITER_ROOT="${EXPERIMENTS_ROOT}/${ITER_TAG}"
  ITER_ARTIFACT_ROOT="${ITER_ROOT}/artifacts"
  ITER_LOG_ROOT="${ITER_ROOT}/logs"
  # Seed dirs
  ITER_SEEDS_FOR_SAVE_SEEDS="${ITER_ARTIFACT_ROOT}/seeds_for_save_seeds"
  ITER_SEEDS_FOR_FUZZING="${ITER_ARTIFACT_ROOT}/seeds_for_fuzzing"
  ITER_SEEDS_AFTER_FUZZING="${ITER_ARTIFACT_ROOT}/seeds_after_fuzzing"
  ITER_MINIMIZED_SEEDS="${ITER_ARTIFACT_ROOT}/minimized_seeds"
  ITER_SEEDS_AFTER_DB_TRIMMING="${ITER_ARTIFACT_ROOT}/seeds_after_db_trimming"
  # State DB paths
  ITER_STATE_DB_BEFORE_SAVE_SEEDS_PATH="${ITER_ARTIFACT_ROOT}/state_db_before_save_seeds.json"
  ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH="${ITER_ARTIFACT_ROOT}/state_db_after_save_seeds.json"
  ITER_STATE_DB_AFTER_TRIMMING="${ITER_ARTIFACT_ROOT}/state_db_after_trimming.json"
  # Fuzz config paths
  ITER_FUZZ_CONFIG_PATH="${ITER_ARTIFACT_ROOT}/fuzz_config.json"
  ITER_SAVE_SEEDS_CONFIG_PATH="${ITER_ARTIFACT_ROOT}/save_seeds_config.json"
  # Fuzz output dir
  ITER_FUZZ_OUT="${ITER_ARTIFACT_ROOT}/fuzz_out"
  # Coverage logs
  ITER_COVERAGE_LOG_BEFORE_MINIMIZE="${ITER_LOG_ROOT}/coverage_before_minimize.log"
  ITER_COVERAGE_LOG_AFTER_MINIMIZE="${ITER_LOG_ROOT}/coverage_after_minimize.log"

  mkdir -m 0777 -p "$ITER_ARTIFACT_ROOT" "$ITER_LOG_ROOT" \
    "$ITER_SEEDS_FOR_SAVE_SEEDS" "$ITER_SEEDS_FOR_FUZZING" "$ITER_SEEDS_AFTER_FUZZING" "$ITER_MINIMIZED_SEEDS" "$ITER_FUZZ_OUT"

  ### Iteration setup
  # Copy the current state DB to iteration folder
  cp "$STATE_DB_PATH" "$ITER_STATE_DB_BEFORE_SAVE_SEEDS_PATH"
  # Copy the current seeds to iteration folder
  cp -p -r "$SEEDS_PATH"/* "$ITER_SEEDS_FOR_SAVE_SEEDS" || true

  ### Step 1: Run the fuzzer in SAVE_SEEDS mode to collect new seeds
  echo "[*] Iteration $i/$ITERATIONS: Running fuzzer in SAVE_SEEDS mode..."
  cp "$ITER_STATE_DB_BEFORE_SAVE_SEEDS_PATH" "$ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH"
  # Create fuzz config for SAVE_SEEDS
  echo "{\"fuzz_mode\":\"SAVE_SEEDS\",\"seeds_path\": \"${ITER_SEEDS_FOR_FUZZING}\",\"state_db_path\":\"${ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH}\"}" > "$ITER_SAVE_SEEDS_CONFIG_PATH"
  # Run the fuzzer in SAVE_SEEDS mode for each "promising" input from the previous fuzzing iteration.
  for f in "$ITER_SEEDS_FOR_SAVE_SEEDS"/*; do
    run_save_seeds "$f" "$ITER_SAVE_SEEDS_CONFIG_PATH" |& tee -a "${ITER_LOG_ROOT}/save_seeds.log"
  done

  ### Additional step! Copy the previous seeds also to the fuzzing input folder, so that we fuzz on both the old seeds and the new seeds obtained from SAVE_SEEDS.
  cp -p -r "$ITER_SEEDS_FOR_SAVE_SEEDS"/* "$ITER_SEEDS_FOR_FUZZING/" || true

  # NB! Remove the initial artificial 0-seed if it is there.
  INIT_SEED_NAME="seed_0"
  INIT_SEED_PATH="$ITER_SEEDS_FOR_FUZZING/$INIT_SEED_NAME"
  echo "Checking path $INIT_SEED_PATH for the init seed"
  if [[ -f "$INIT_SEED_PATH" ]]; then
      # 1. Get the total file size
      FILE_SIZE=$(wc -c < "$INIT_SEED_PATH" | tr -d ' ')
      
      # 2. Count how many bytes are left after deleting all null bytes (\0)
      NON_NULL_BYTES=$(tr -d '\0' < "$INIT_SEED_PATH" | wc -c | tr -d ' ')
      
      # If the file has data (size > 0) but 0 non-null bytes, it's an all-null file!
      if [[ "$FILE_SIZE" -gt 0 && "$NON_NULL_BYTES" -eq 0 ]]; then
          echo "[*] Deleting $INIT_SEED_NAME ($FILE_SIZE null bytes) from $INIT_SEED_PATH before fuzzing..."
          "${SUDO_CMD[@]}" rm -f "$INIT_SEED_PATH"
      fi
  fi

  ### Step 2: Run the fuzzer in FUZZ mode
  echo "[*] Iteration $i/$ITERATIONS: Running fuzzer in FUZZ mode for ${PER_ITER_TIMEOUTS[$((i-1))]}s..."
  echo "{\"fuzz_mode\":\"FUZZ\",\"state_db_path\":\"${ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH}\"}" > "$ITER_FUZZ_CONFIG_PATH"
  run_fuzz_engine "$ITER_SEEDS_FOR_FUZZING" "$ITER_FUZZ_OUT" "${PER_ITER_TIMEOUTS[$((i-1))]}" "$ITER_FUZZ_CONFIG_PATH"
  if [[ "$ENGINE" == "LIBFUZZER" ]]; then
    # Copy any fuzz-*.log files to ART_DIR
    mkdir -p "${ITER_ARTIFACT_ROOT}/libfuzzer_fuzz_log"
    mv -f fuzz-*.log "${ITER_ARTIFACT_ROOT}/libfuzzer_fuzz_log/" 2>/dev/null || true
  fi

  if [[ "$ENGINE" == "AFL" ]]; then
    cp -p -r "${ITER_FUZZ_OUT}/default/queue/id"* "$ITER_SEEDS_AFTER_FUZZING/" || true
  elif [[ "$ENGINE" == "LIBFUZZER" ]]; then
    cp -p -r "${ITER_SEEDS_FOR_FUZZING}"/* "$ITER_SEEDS_AFTER_FUZZING/"
  fi

  ### Save the replayable queue before minimize also.
  REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE="${ITER_ARTIFACT_ROOT}/replayable_queue_before_minimize"
  echo "[*] Iteration $i/$ITERATIONS: Converting all seeds from the queue to the replayable format for coverage collection..."
  python3 "$CREATE_REPLAYABLE_QUEUE" -i "$ITER_SEEDS_AFTER_FUZZING" -o "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" --fsm "$ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH"

  # Step 2.5: (Optional) Collect coverage information after the minimization.
  # if [[ -n "$COV_TARGET" ]]; then
  #   echo "[*] Collecting coverage (before minimize)..."
  #   "${SUDO_CMD[@]}" "$COVERAGE_SCRIPT_PATH" \
  #     -r "$COV_ROOT" \
  #     -t "$COV_TARGET" \
  #     -s "$REPLAYABLE_QUEUE_DIR_BEFORE_MINIMIZE" \
  #     -o "${ITER_LOG_ROOT}/coverage_before_minimize.txt" \
  #     -w "$GCOV_WRAPPER_SCRIPT" \
  #     "${COV_SCRIPT_EXTRA_ARGS[@]}"
  # fi

  ### Step 3: Minimize the seeds obtained from fuzzing
  echo "[*] Iteration $i/$ITERATIONS: Minimizing seeds obtained from fuzzing..."
  minimize_seeds "$ITER_SEEDS_AFTER_FUZZING" "$ITER_MINIMIZED_SEEDS" "$ITER_LOG_ROOT"

  # Step 3.3: Convert to the replayable format for coverage collection
  REPLAYABLE_QUEUE_DIR="${ITER_ARTIFACT_ROOT}/replayable_queue"
  echo "[*] Iteration $i/$ITERATIONS: Converting minimized seeds to replayable format for coverage collection..."
  python3 "$CREATE_REPLAYABLE_QUEUE" -i "$ITER_MINIMIZED_SEEDS" -o "$REPLAYABLE_QUEUE_DIR" --fsm "$ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH"

  # Step 3.4: Convert to the replayable format for coverage collection
  REPLAYABLE_CRASHES_DIR="${ITER_ARTIFACT_ROOT}/replayable_crashes"
  echo "[*] Iteration $i/$ITERATIONS: Converting crash seeds to replayable format..."
  python3 "$CREATE_REPLAYABLE_QUEUE" -i "${ITER_FUZZ_OUT}/default/crashes/" -o "$REPLAYABLE_CRASHES_DIR" --fsm "$ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH" || true

  # Step 3.5: (Optional) Collect coverage information after the minimization.
  # if [[ -n "$COV_TARGET" ]]; then
  #   echo "[*] Collecting coverage (after minimize)..."
  #   "${SUDO_CMD[@]}" "$COVERAGE_SCRIPT_PATH" \
  #     -r "$COV_ROOT" \
  #     -t "$COV_TARGET" \
  #     -s "$REPLAYABLE_QUEUE_DIR" \
  #     -o "${ITER_LOG_ROOT}/coverage_after_minimize.txt" \
  #     -c "${ITER_LOG_ROOT}/coverage_over_time.csv" \
  #     -w "$GCOV_WRAPPER_SCRIPT" \
  #     "${COV_SCRIPT_EXTRA_ARGS[@]}"
  # fi

  # ### Step 4: Trim state db
  echo "[*] Iteration $i/$ITERATIONS: Trimming state DB..."
  echo "CMD: python3 ${STATE_DB_TRIM_SCRIPT} $ITER_MINIMIZED_SEEDS $ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH --output-seeds $ITER_SEEDS_AFTER_DB_TRIMMING --output-fsm $ITER_STATE_DB_AFTER_TRIMMING"
  python3 ${STATE_DB_TRIM_SCRIPT} "$ITER_MINIMIZED_SEEDS" "$ITER_STATE_DB_AFTER_SAVE_SEEDS_PATH" \
    --output-seeds "${ITER_SEEDS_AFTER_DB_TRIMMING}" \
    --output-fsm "${ITER_STATE_DB_AFTER_TRIMMING}"
    # -p ${PRUNE_PERCENTAGE}

  ### Iteration wrap-up
  # Update state DB
  cp "$ITER_STATE_DB_AFTER_TRIMMING" "$STATE_DB_PATH"
  # Update the seeds for the next iteration
  rm -rf "$SEEDS_PATH"/*
  cp -p -r "$ITER_SEEDS_AFTER_DB_TRIMMING"/* "$SEEDS_PATH/"

done

# COPY all the replayable seed into one folder and run the coverage collection.
mkdir -p ${EXPERIMENTS_ROOT}/replayable_queue
for dir in "${EXPERIMENTS_ROOT}"/iter_*/artifacts/replayable_queue; do
  # Extract the iter_X part of the path
  iter_name=$(echo "$dir" | grep -o 'iter_[^/]*')
  
  # Loop through files and copy them with the iter_X prefix
  for file in "$dir"/*; do
    if [ -f "$file" ]; then
      filename=$(basename "$file")
      cp "$file" "${EXPERIMENTS_ROOT}/replayable_queue/${iter_name}_${filename}"
    fi
  done
done

mkdir -p ${EXPERIMENTS_ROOT}/replayable_queue_before_minimize
for dir in "${EXPERIMENTS_ROOT}"/iter_*/artifacts/replayable_queue_before_minimize; do
  # Extract the iter_X part of the path
  iter_name=$(echo "$dir" | grep -o 'iter_[^/]*')
  
  # Loop through files and copy them with the iter_X prefix
  for file in "$dir"/*; do
    if [ -f "$file" ]; then
      filename=$(basename "$file")
      cp "$file" "${EXPERIMENTS_ROOT}/replayable_queue_before_minimize/${iter_name}_${filename}"
    fi
  done
done

bash -c "${INTERCEPTFUZZ_DIR}/scripts/create_global_replayable_crashes.sh ${EXPERIMENTS_ROOT}"

# if [[ -n "$COV_TARGET" ]]; then
#   echo "[*] Collecting coverage (final)..."
#   "${SUDO_CMD[@]}" "$COVERAGE_SCRIPT_PATH" \
#     -r "$COV_ROOT" \
#     -t "$COV_TARGET" \
#     -s "${EXPERIMENTS_ROOT}/replayable_queue" \
#     -o "${EXPERIMENTS_ROOT}/coverage_final.txt" \
#     -c "${EXPERIMENTS_ROOT}/coverage_over_time.csv" \
#     -w "$GCOV_WRAPPER_SCRIPT" \
#     "${COV_SCRIPT_EXTRA_ARGS[@]}"
# fi

if [[ -n "$COV_TARGET" ]]; then
  echo "[*] Collecting coverage (final)..."
  "${SUDO_CMD[@]}" "$COVERAGE_SCRIPT_PATH" \
    -r "$COV_ROOT" \
    -t "$COV_TARGET" \
    -s "${EXPERIMENTS_ROOT}/replayable_queue_before_minimize" \
    -o "${EXPERIMENTS_ROOT}/coverage_final_wo_minimize.txt" \
    -c "${EXPERIMENTS_ROOT}/coverage_over_time.csv" \
    -w "$GCOV_WRAPPER_SCRIPT" \
    "${COV_SCRIPT_EXTRA_ARGS[@]}"
fi

# Record statistics
python3 /workspace/common/analyze_fuzz_iteration.py ${EXPERIMENTS_ROOT}