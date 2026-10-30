#!/usr/bin/env python3
"""
Fuzzer Queue Converter

Converts an AFL-style fuzzer queue (StateID + Payload) into a standalone 
replayable queue using Length-Value (LV) encoded packets based on an FSM JSON.
Produces: [4 bytes total len BE][4 bytes pkt 1 len BE][pkt 1]...
"""

import argparse
import json
import logging
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Constants
ROOT_STATE_ID = 1


class QueueConverter:
    """Handles the parsing of FSM transitions and conversion of fuzzer seeds."""

    def __init__(self, fsm_path: Path, state_fmt: str = "<I", len_fmt: str = ">I", total_len_fmt: str = ">I"):
        self.fsm_path = fsm_path
        self.state_fmt = state_fmt
        self.len_fmt = len_fmt
        self.total_len_fmt = total_len_fmt
        
        # Calculate struct sizes dynamically
        self.state_id_size = struct.calcsize(self.state_fmt)
        self.len_prefix_size = struct.calcsize(self.len_fmt)
        self.total_len_size = struct.calcsize(self.total_len_fmt)
        
        # Mapping: { to_state: (from_state, packet_bytes) }
        self.transitions: Dict[int, Tuple[int, bytes]] = {}

    def load_fsm(self) -> None:
        """Parses the FSM JSON and builds the reverse-traversal dictionary."""
        if not self.fsm_path.exists():
            raise FileNotFoundError(f"FSM JSON file not found at {self.fsm_path}")

        try:
            with open(self.fsm_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in {self.fsm_path}: {e}")

        transitions_list = data.get("transitions", [])
        if not transitions_list:
            logger.warning("No transitions found in FSM JSON.")

        for t in transitions_list:
            to_state = t["to_state"]
            from_state = t["from_state"]
            packet_bytes = bytes(t["packet"])
            self.transitions[to_state] = (from_state, packet_bytes)

        logger.info("Successfully loaded %d FSM transitions.", len(self.transitions))

    def get_path_to_state(self, target_id: int) -> List[bytes]:
        """Reconstructs the chronological packet sequence to reach the target_id."""
        trace: List[bytes] = []
        search = target_id

        while search != ROOT_STATE_ID:
            if search not in self.transitions:
                raise ValueError(f"State ID {search} has no known parent in FSM.")
            
            from_state, packet = self.transitions[search]
            trace.append(packet)
            search = from_state

        trace.reverse()
        return trace

    def encode_lv(self, packet: bytes) -> bytes:
        """Encodes a single packet into the Length-Value format."""
        packet_len = len(packet)
        # Check against the maximum value that fits in the defined length format
        max_len = (1 << (self.len_prefix_size * 8)) - 1
        
        if packet_len > max_len:
            raise ValueError(f"Packet too large ({packet_len} bytes). Max size is {max_len}.")
        
        return struct.pack(self.len_fmt, packet_len) + packet

    def process_seed(self, input_path: Path, output_path: Path) -> None:
        """Parses a seed, prepends the FSM path, and writes the stream."""
        data = input_path.read_bytes()

        if len(data) < self.state_id_size:
            logger.debug("Skipping %s: File smaller than State ID size.", input_path.name)
            return

        # Extract State ID and Payload (Note: Input state ID is likely still little-endian from AFL)
        state_id = struct.unpack(self.state_fmt, data[:self.state_id_size])[0]
        payload = data[self.state_id_size:]

        # Fetch preamble
        preamble_packets = self.get_path_to_state(state_id)
        
        # Build full sequence
        full_sequence = preamble_packets + [payload]

        # 1. Encode inner stream of [4-byte packet len][packet] chunks
        inner_stream = bytearray()
        for pkt in full_sequence:
            inner_stream.extend(self.encode_lv(pkt))

        # 2. Prepend the 4-byte Big-Endian Total Length of the inner stream
        total_length = len(inner_stream)
        replay_stream = struct.pack(self.total_len_fmt, total_length) + inner_stream

        output_path.write_bytes(replay_stream)
        logger.debug("Converted %s -> State %d (%d packets, %d bytes total)", input_path.name, state_id, len(full_sequence), total_length)

    def convert_queue(self, input_dir: Path, output_dir: Path) -> None:
        """Iterates through the input directory and converts all valid seeds."""
        if not input_dir.exists() or not input_dir.is_dir():
            logger.error("Input directory does not exist: %s", input_dir)
            sys.exit(1)

        output_dir.mkdir(parents=True, exist_ok=True)

        seed_files = [f for f in input_dir.iterdir() if f.is_file()]
        if not seed_files:
            logger.info("No seeds found in %s", input_dir)
            return

        logger.info("Starting conversion of %d seeds...", len(seed_files))
        
        success_count = 0
        for seed_path in seed_files:
            out_path = output_dir / seed_path.name
            try:
                self.process_seed(seed_path, out_path)
                success_count += 1
            except Exception as e:
                logger.error("Failed on %s: %s", seed_path.name, e)

        logger.info("Conversion complete. Successfully processed %d/%d seeds.", success_count, len(seed_files))


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert fuzzer queue to a standalone replayable sequence.")
    parser.add_argument("-i", "--input", type=Path, required=True,
                        help="Path to the input fuzzer queue directory.")
    parser.add_argument("-o", "--output", type=Path, required=True,
                        help="Path to the output replayable directory.")
    parser.add_argument("-f", "--fsm", type=Path, required=True,
                        help="Path to the FSM JSON file.")
    parser.add_argument("--state-fmt", type=str, default="<I",
                        help="Struct format for input State ID (Default: '<I' for Little-Endian uint32).")
    parser.add_argument("--len-fmt", type=str, default=">I",
                        help="Struct format for packet length (Default: '>I' for 4-byte Big-Endian uint32).")
    parser.add_argument("--total-len-fmt", type=str, default=">I",
                        help="Struct format for total length prefix (Default: '>I' for 4-byte Big-Endian uint32).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose debug logging.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        converter = QueueConverter(
            fsm_path=args.fsm,
            state_fmt=args.state_fmt,
            len_fmt=args.len_fmt,
            total_len_fmt=args.total_len_fmt
        )
        converter.load_fsm()
        converter.convert_queue(args.input, args.output)
        
    except KeyboardInterrupt:
        logger.info("Process interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.critical("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()