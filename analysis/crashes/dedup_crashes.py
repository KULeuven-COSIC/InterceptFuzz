#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

# Attempt to import tqdm for the progress bar, with a graceful fallback
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kwargs):
        return iterable

def setup_logging(verbose: bool) -> None:
    """Configures the logging level, forcing all log streams to stderr."""
    level = logging.DEBUG if verbose else logging.INFO
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr
    )

def load_rules(rules_path: Path) -> Dict[str, str]:
    """Loads crash rules from a JSON file."""
    try:
        with rules_path.open('r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load rules JSON from {rules_path}: {e}")
        sys.exit(1)

def get_crash_by_error(error: str, rules: Dict[str, str]) -> str:
    """Matches subprocess output against the loaded crash rules."""
    for crash_name, msg in rules.items():
        if msg in error:
            return crash_name
    return "UNKNOWN CRASH"

def get_output(binary_path: Path, seed_path: Path, timeout: int) -> str:
    """Executes the binary with the seed and returns the combined stdout/stderr."""
    try:
        result = subprocess.run(
            [str(binary_path), str(seed_path)],
            capture_output=True,
            timeout=timeout
        )
        out = result.stdout.decode(errors="replace")
        err = result.stderr.decode(errors="replace")
        return (out + err).strip()
    except subprocess.TimeoutExpired:
        logging.warning(f"Timeout expired for seed: {seed_path.resolve()}")
        return "ERROR: Timeout"
    except Exception as e:
        logging.error(f"Execution failed for {seed_path.resolve()}: {e}")
        return f"ERROR: {str(e)}"

def count_packets(seed_path: Path) -> int:
    """Parses binary LV structure and returns packet count:
    [4 bytes total length BE] [4 bytes packet 1 len BE] [packet 1 data] ...
    """
    try:
        data = seed_path.read_bytes()
        if len(data) < 4:
            return 0

        # Skip initial 4-byte total length (Big-Endian)
        offset = 4
        packets = 0
        file_len = len(data)

        while offset + 4 <= file_len:
            pkt_len = int.from_bytes(data[offset:offset + 4], byteorder="big")
            offset += 4 + pkt_len
            packets += 1
            if offset > file_len:
                break

        return packets
    except Exception as e:
        logging.warning(f"Failed to parse packet count for {seed_path.name}: {e}")
        return sys.maxsize

def main():
    example_usage = """
    Examples:
    Default run (appends to unknown_crashes.log if it exists):
        ./dedup_crashes.py -d ./crashes -b ./fuzz_target -r rules.json

    Specify custom output file and unknown crash log:
        ./dedup_crashes.py -d ./crashes -b ./fuzz_target -r rules.json -o summary.json -u unknown.log

    Explicitly overwrite the unknown crash log rather than appending:
        ./dedup_crashes.py -d ./crashes -b ./fuzz_target -r rules.json --overwrite-unknown

    Ignore unknown crashes completely:
        ./dedup_crashes.py -d ./crashes -b ./fuzz_target -r rules.json --ignore-unknown
    """

    parser = argparse.ArgumentParser(
        description="Crash Deduplicator (Pure JSON Edition)",
        epilog=example_usage,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--crashes-dir", type=Path, required=True, 
                        help="Path to the crash directory")
    parser.add_argument("-b", "--binary", type=Path, required=True, 
                        help="Path to the fuzz target binary")
    parser.add_argument("-r", "--rules", type=Path, required=True, 
                        help="Path to the JSON file containing crash matching rules")
    parser.add_argument("-f", "--file-regex", type=str, default="", 
                        help="Regex to match crash files (default: empty, matches all files)")
    parser.add_argument("-t", "--timeout", type=int, default=5, 
                        help="Timeout in seconds for each execution (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Enable verbose output logging")
    parser.add_argument("-o", "--output", type=Path, default=Path("crash_summary.json"),
                        help="Path to save the JSON results (default: crash_summary.json)")
    parser.add_argument("-u", "--unknown-output", type=Path, default=Path("unknown_crashes.log"),
                        help="File path to write full outputs of unknown crashes (default: unknown_crashes.log)")
    parser.add_argument("--overwrite-unknown", action="store_true",
                        help="Truncate/overwrite the unknown log file instead of appending (default: False)")
    parser.add_argument("--ignore-unknown", action="store_true",
                        help="Ignore unknown crashes completely (do not log or write to JSON) (default: False)")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.crashes_dir.is_dir():
        logging.error(f"Crashes directory not found: {args.crashes_dir}")
        sys.exit(1)
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        logging.error(f"Binary not found or is not executable: {args.binary}")
        sys.exit(1)

    rules = load_rules(args.rules)
    
    try:
        file_pattern = re.compile(args.file_regex)
    except re.error as e:
        logging.error(f"Invalid file regex '{args.file_regex}': {e}")
        sys.exit(1)

    valid_files = [p for p in args.crashes_dir.iterdir() if p.is_file() and file_pattern.search(p.name)]

    if not valid_files:
        logging.info("No crash files matched the given regex in the directory.")
        args.output.write_text("[]", encoding="utf-8")
        sys.exit(0)

    # Sort alphabetically by filename (maintains chronological/iteration order if prefixed)
    valid_files.sort(key=lambda p: p.name)

    # Prepare unknown crash log only if not ignoring unknown crashes
    if not args.ignore_unknown:
        try:
            if args.overwrite_unknown:
                args.unknown_output.write_text("", encoding="utf-8")
            else:
                args.unknown_output.touch(exist_ok=True)
        except Exception as e:
            logging.error(f"Failed to access unknown crash log file '{args.unknown_output}': {e}")
            sys.exit(1)

    structured_results: List[Dict] = []
    known_crashes: Dict[str, Dict] = {}

    logging.info(f"Found {len(valid_files)} matching crash files. Starting deduplication...")
    
    iterator = tqdm(valid_files, desc="Processing crashes", unit="file", 
                    disable=args.verbose or not HAS_TQDM, file=sys.stderr)

    for seed_path in iterator:
        full_seed_path = str(seed_path.resolve())
        if args.verbose:
            logging.debug(f"Processing: {full_seed_path}")
            
        output = get_output(args.binary, seed_path, args.timeout)
        crash_category = get_crash_by_error(output, rules)

        if crash_category == "UNKNOWN CRASH":
            if args.ignore_unknown:
                continue

            pkt_count = count_packets(seed_path)
            entry = {
                "index": len(structured_results) + 1,
                "category": "UNKNOWN CRASH",
                "first_file": full_seed_path,
                "first_packets": pkt_count,
                "shortest_file": full_seed_path,
                "shortest_packets": pkt_count,
                "file": full_seed_path,
            }
            structured_results.append(entry)
            
            # Append full trace to the user-specified unknown crashes log
            with args.unknown_output.open("a", encoding="utf-8") as uf:
                uf.write(f"=== UNKNOWN CRASH: {full_seed_path} ({pkt_count} packets) ===\n")
                uf.write(output + "\n")
                uf.write("=" * 60 + "\n\n")

            msg = f"Found UNKNOWN CRASH in file {full_seed_path} ({pkt_count} packets, appended to {args.unknown_output})"
            if HAS_TQDM and not args.verbose:
                tqdm.write(f"[*] {msg}", file=sys.stderr)
            else:
                logging.info(msg)

        else:
            pkt_count = count_packets(seed_path)

            if crash_category not in known_crashes:
                # First appearance of this crash category
                entry = {
                    "index": len(structured_results) + 1,
                    "category": crash_category,
                    "first_file": full_seed_path,
                    "first_packets": pkt_count,
                    "shortest_file": full_seed_path,
                    "shortest_packets": pkt_count,
                    "file": full_seed_path,
                }
                known_crashes[crash_category] = entry
                structured_results.append(entry)

                msg = f"Found new crash signature: '{crash_category}' in file {full_seed_path} ({pkt_count} packets)"
                if HAS_TQDM and not args.verbose:
                    tqdm.write(f"[*] {msg}", file=sys.stderr)
                else:
                    logging.info(msg)
            else:
                # Check if this crash recurrence has fewer packets
                current_best = known_crashes[crash_category]["shortest_packets"]
                if pkt_count < current_best:
                    known_crashes[crash_category]["shortest_file"] = full_seed_path
                    known_crashes[crash_category]["shortest_packets"] = pkt_count
                    if args.verbose:
                        logging.debug(f"Updated shortest seed for '{crash_category}': {full_seed_path} ({pkt_count} packets)")

    # Write output directly to the specified JSON file path
    try:
        args.output.write_text(json.dumps(structured_results, indent=2), encoding="utf-8")
        logging.info(f"Successfully generated structured log: {args.output}")
    except Exception as e:
        logging.error(f"Failed to write JSON summary to disk: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
