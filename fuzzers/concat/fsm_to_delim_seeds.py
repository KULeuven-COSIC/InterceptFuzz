#!/usr/bin/env python3
import argparse
import json
import os
import sys
from typing import List, Tuple

def main():
    parser = argparse.ArgumentParser(description="Convert an FSM JSON into delimiter-separated binary seeds (Maximal paths only).")
    parser.add_argument("-i", "--input", required=True, help="Input FSM JSON file")
    parser.add_argument("-o", "--outdir", required=True, help="Output directory for the generated seeds")
    parser.add_argument("-d", "--delimiter", default="DEAD", help="Hex string for the delimiter (default: DEAD)")
    args = parser.parse_args()

    try:
        delimiter = bytes.fromhex(args.delimiter)
    except ValueError:
        print("[-] Error: Delimiter must be a valid hex string (e.g., DEAD or DEADBEEF)")
        sys.exit(1)

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            fsm = json.load(f)
    except Exception as e:
        print(f"[-] Failed to load JSON: {e}")
        sys.exit(1)

    # 1. Build the graph
    graph = {}
    for t in fsm.get("transitions", []):
        u = t["from_state"]
        v = t["to_state"]
        packet = bytes(t["packet"])
        
        if u not in graph:
            graph[u] = []
        graph[u].append((v, packet))

    if not graph:
        print("[-] No transitions found in the FSM.")
        sys.exit(1)

    all_paths: List[Tuple[List[int], List[bytes]]] = []

    # 2. Traverse the graph (Only save when we reach a leaf)
    def dfs(current_state: int, current_path_pkts: List[bytes], current_state_history: List[int]):
        is_leaf = True  # Assume we are at the end of a path

        for next_state, pkt in graph.get(current_state, []):
            if next_state not in current_state_history:
                is_leaf = False  # We found a valid child, so this is NOT a leaf
                
                current_state_history.append(next_state)
                current_path_pkts.append(pkt)
                
                dfs(next_state, current_path_pkts, current_state_history)
                
                # Backtrack
                current_path_pkts.pop()
                current_state_history.pop()

        # If we couldn't go any deeper, it's a maximal path! Save it.
        if is_leaf and current_path_pkts:
            all_paths.append((list(current_state_history), list(current_path_pkts)))

    ROOT_STATE = 1
    print(f"[*] Starting DFS traversal from Root State {ROOT_STATE}...")
    dfs(ROOT_STATE, [], [ROOT_STATE])

    if not all_paths:
        print("[-] No valid paths found.")
        sys.exit(1)

    # 3. Write to output
    os.makedirs(args.outdir, exist_ok=True)
    print(f"[*] Found {len(all_paths)} maximal paths. Generating seeds...")
    
    for i, (state_history, pkts) in enumerate(all_paths, start=1):
        final_state = state_history[-1]
        filename = f"seed_{i:04d}_to_state_{final_state}.bin"
        filepath = os.path.join(args.outdir, filename)

        final_payload = delimiter.join(pkts)
        with open(filepath, 'wb') as f:
            f.write(final_payload)
            
        path_str = " -> ".join(map(str, state_history))
        print(f"    [+] {filename} | Length: {len(pkts)} pkts | Path: {path_str}")

    print(f"\n[+] Success! {len(all_paths)} seeds written to '{args.outdir}/'")

if __name__ == "__main__":
    main()