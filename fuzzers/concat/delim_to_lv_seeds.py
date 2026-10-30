#!/usr/bin/env python3
import argparse
import struct
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Convert delimiter-based seeds to Length-Value (LV) format with Big-Endian prefixes.")
    parser.add_argument("-i", "--input", type=Path, required=True, help="Input directory (or single file) with delimiter-based seeds")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output directory for the LV seeds")
    parser.add_argument("-d", "--delimiter", default="DEAD", help="Hex string for the delimiter (default: DEAD)")
    
    # We use ">I" (4-byte Big-Endian) based on your previous LV requirements
    parser.add_argument("--len-fmt", type=str, default=">I", help="Struct format for lengths (Default: '>I' for 4-byte BE)")
    args = parser.parse_args()

    try:
        delimiter = bytes.fromhex(args.delimiter)
    except ValueError:
        print("[-] Error: Delimiter must be a valid hex string (e.g., DEAD)")
        sys.exit(1)

    # Gather files (supports both a single file and a whole directory)
    if args.input.is_file():
        files_to_process = [args.input]
    elif args.input.is_dir():
        files_to_process = [f for f in args.input.iterdir() if f.is_file()]
    else:
        print(f"[-] Error: Input path '{args.input}' does not exist.")
        sys.exit(1)

    if not files_to_process:
        print("[-] No files found to process.")
        sys.exit(1)

    args.output.mkdir(parents=True, exist_ok=True)
    print(f"[*] Found {len(files_to_process)} file(s). Converting to LV format...")

    success_count = 0
    for filepath in files_to_process:
        raw_data = filepath.read_bytes()
        
        # 1. Split the data just like the C++ harness does
        chunks = raw_data.split(delimiter)
        
        inner_stream = bytearray()
        packet_count = 0
        
        # 2. Process each chunk
        for chunk in chunks:
            if len(chunk) > 0:  # Emulates your C++ 'if (i > start)' check
                # Pack the length prefix followed by the actual packet data
                inner_stream.extend(struct.pack(args.len_fmt, len(chunk)))
                inner_stream.extend(chunk)
                packet_count += 1
        
        if packet_count == 0:
            print(f"    [-] Skipping {filepath.name}: No valid payloads found.")
            continue

        # 3. Prepend the global Total Length prefix
        total_length = len(inner_stream)
        final_payload = struct.pack(args.len_fmt, total_length) + inner_stream
        
        # 4. Write to disk
        out_filepath = args.output / filepath.name
        out_filepath.write_bytes(final_payload)
        
        success_count += 1
        print(f"    [+] {filepath.name} -> {packet_count} pkts, {total_length} bytes total inner length")

    print(f"\n[+] Success! Converted {success_count}/{len(files_to_process)} seeds to '{args.output}/'")

if __name__ == "__main__":
    main()