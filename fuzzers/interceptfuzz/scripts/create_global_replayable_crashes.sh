#!/bin/bash

# Check if a directory argument was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <run_directory>"
    exit 1
fi

RUN_DIR="${1%/}" # Remove trailing slash if present

if [ ! -d "$RUN_DIR" ]; then
    echo "Error: Directory '$RUN_DIR' does not exist."
    exit 1
fi

OUTPUT_DIR="$RUN_DIR/replayable_crashes"

# Create the output directory
mkdir -p "$OUTPUT_DIR"
echo "[*] Created output directory: $OUTPUT_DIR"

# Enable nullglob so empty directories don't cause literal '*'
shopt -s nullglob

total_copied=0

# Loop through all iter_* directories in the run folder
for iter_dir in "$RUN_DIR"/iter_*; do
    if [ -d "$iter_dir" ]; then
        iter_name="$(basename "$iter_dir")"
        src_dir="$iter_dir/artifacts/replayable_crashes"

        # Check if this iteration actually has a replayable_crashes directory
        if [ -d "$src_dir" ]; then
            iter_copied=0

            # Loop through all files in the source directory
            for crash_file in "$src_dir"/*; do
                if [ -f "$crash_file" ]; then
                    filename="$(basename "$crash_file")"

                    # Prepend iter_XX_ to the destination filename
                    cp -- "$crash_file" "$OUTPUT_DIR/${iter_name}_${filename}"

                    ((iter_copied++))
                    ((total_copied++))
                fi
            done

            if [ "$iter_copied" -gt 0 ]; then
                echo "  -> Copied $iter_copied crashes from $iter_name"
            fi
        fi
    fi
done

echo "[+] Done! Successfully collected $total_copied crashes into $OUTPUT_DIR."
