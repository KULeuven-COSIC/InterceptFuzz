import json
import struct
import argparse
import shutil
import sys
from pathlib import Path
from collections import defaultdict, deque

# Global verbose flag
VERBOSE = False

def log(msg):
    if VERBOSE:
        print(f"[DEBUG] {msg}")

# -----------------------------------------------------------------------------
# 1. IO Helpers
# -----------------------------------------------------------------------------

def load_json(path: Path):
    try:
        log(f"Opening JSON file: {path}")
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"[!] Error loading JSON from {path}: {e}")

def save_json(data, path: Path):
    try:
        log(f"Writing JSON to {path}...")
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[*] Saved FSM to: {path}")
    except Exception as e:
        sys.exit(f"[!] Error saving JSON to {path}: {e}")

# -----------------------------------------------------------------------------
# 2. Logic: Identify Checkpoints & Prune
# -----------------------------------------------------------------------------

def scan_seeds(seed_dir: Path, endian: str):
    """
    Scans seeds to find 'Checkpoint' states.
    READ-ONLY: Does not delete invalid seeds, just ignores them.
    Returns: Set of state IDs found in valid seeds.
    """
    fmt = '<I' if endian == 'little' else '>I'
    checkpoints = set()
    seed_file_map = {} # filename -> old_id

    if not seed_dir.exists():
        sys.exit(f"[!] Seed directory '{seed_dir}' does not exist.")

    print(f"[*] Scanning seeds in '{seed_dir}'...")
    
    ignored_count = 0
    
    for fpath in seed_dir.iterdir():
        if fpath.name.startswith('.'): continue
        if not fpath.is_file(): continue

        try:
            with open(fpath, 'rb') as f:
                header = f.read(4)
                if len(header) != 4: continue
                
                state_id = struct.unpack(fmt, header)[0]
                
                # Ignore invalid State 0 seeds (DO NOT DELETE)
                if state_id == 0:
                    log(f"Ignoring invalid seed (State 0): {fpath.name}")
                    ignored_count += 1
                    continue
                
                checkpoints.add(state_id)
                seed_file_map[fpath.name] = state_id

        except Exception as e:
            print(f"    [!] Error reading {fpath.name}: {e}")

    if ignored_count > 0:
        print(f"[*] Ignored {ignored_count} invalid seeds (State 0).")
        
    return checkpoints, seed_file_map

def find_useful_states(checkpoints, transitions):
    """
    Backward Reachability Analysis.
    Finds all states that can reach any of the Checkpoints (or Root).
    """
    # 1. Build Reverse Graph (To -> From)
    rev_adj = defaultdict(list)
    for t in transitions:
        u, v = t["from_state"], t["to_state"]
        rev_adj[v].append(u)
        
    # 2. BFS from Checkpoints (going backwards)
    #    We start with checkpoints + Root (Root is always useful)
    start_nodes = checkpoints | {1}
    
    useful = set(start_nodes)
    queue = deque(start_nodes)
    
    log(f"Starting Backward BFS from {len(start_nodes)} checkpoints...")
    
    while queue:
        curr = queue.popleft()
        # Who points to 'curr'?
        for parent in rev_adj[curr]:
            if parent not in useful:
                useful.add(parent)
                queue.append(parent)
                
    log(f"Pruning complete. Kept {len(useful)} states.")
    return useful

def generate_state_map(useful_states):
    """
    Remaps IDs linearly.
    - Root (1) -> 1
    - Others -> 2, 3, 4... (Even leafs get a unique ID)
    """
    state_map = {}
    
    # 1. Map Root
    if 1 in useful_states:
        state_map[1] = 1
        
    # 2. Map Others (Sort for determinism)
    others = sorted([s for s in useful_states if s != 1])
    
    current_id = 2
    for s in others:
        state_map[s] = current_id
        current_id += 1
        
    return state_map

def clean_fsm_data(fsm_data, state_map):
    """ Rebuilds FSM with new IDs. """
    new_transitions = []
    
    for t in fsm_data.get("transitions", []):
        src, dst = t["from_state"], t["to_state"]
        
        if src in state_map and dst in state_map:
            new_t = t.copy()
            new_t["from_state"] = state_map[src]
            new_t["to_state"] = state_map[dst]
            new_transitions.append(new_t)
            
    # Count unique active states (All mapped states are > 0 now)
    unique_active = set(state_map.values())
    
    return {
        "state_counter_": len(unique_active),
        "transitions": new_transitions
    }

def update_seed_files(seed_file_map, state_map, src_dir, dst_dir, endian):
    """
    Copies VALID seeds to output directory with updated IDs.
    Does NOT touch src_dir.
    """
    fmt = '<I' if endian == 'little' else '>I'
    
    # Ensure output dir exists
    if not dst_dir.exists():
        dst_dir.mkdir(parents=True, exist_ok=True)
        
    count = 0
    
    for filename, old_id in seed_file_map.items():
        # Only process if the state is in our valid map
        if old_id in state_map:
            new_id = state_map[old_id]
            src_file = src_dir / filename
            dst_file = dst_dir / filename
            
            try:
                # Always copy first to avoid touching source
                shutil.copy2(src_file, dst_file)
                
                # Update ID in the DESTINATION file
                if new_id != old_id:
                    with open(dst_file, 'r+b') as f:
                        f.seek(0)
                        f.write(struct.pack(fmt, new_id))
                count += 1
            except Exception as e:
                print(f"    [!] Failed to process {filename}: {e}")
                
    print(f"[*] Wrote {count} cleaned seeds to '{dst_dir}'.")

# -----------------------------------------------------------------------------
# 4. Main
# -----------------------------------------------------------------------------

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("seeds_dir", type=Path, help="Input seeds directory (Read-Only).")
    parser.add_argument("fsm_path", type=Path, help="Input FSM JSON.")
    
    # Output arguments (Required if different, but we can default to overwriting if user insists)
    parser.add_argument("-s", "--output-seeds", type=Path, default=None, 
                        help="Output seeds directory. Defaults to 'seeds_cleaned' if not set.")
    parser.add_argument("-f", "--output-fsm", type=Path, default=None, 
                        help="Output FSM file. Defaults to overwriting input if not set.")
    
    parser.add_argument("--endian", choices=["little", "big"], default="little", help="Endianness.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose.")
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    # Handle Default Output Paths
    target_seeds_dir = args.output_seeds
    if target_seeds_dir is None:
        # Default to a new folder if not specified, to avoid accidental overwrite safety issues
        target_seeds_dir = args.seeds_dir.parent / (args.seeds_dir.name + "_cleaned")
        print(f"[*] No output seed dir specified. Using: {target_seeds_dir}")

    target_fsm_path = args.output_fsm if args.output_fsm else args.fsm_path

    # Safety Check
    if target_seeds_dir == args.seeds_dir:
        print("[!] Warning: Output seed dir is same as Input. This will modify files in-place.")
        # This is allowed if user explicitly requests it, but our logic handles it safely via copy+write.

    # 1. Load Data
    fsm_data = load_json(args.fsm_path)
    transitions = fsm_data.get("transitions", [])
    
    # 2. Get Checkpoints (Seeds) - READ ONLY
    checkpoints, seed_file_map = scan_seeds(args.seeds_dir, args.endian)
    print(f"    Found {len(checkpoints)} checkpoint states in valid seeds.")

    # 3. Determine Useful States
    useful_states = find_useful_states(checkpoints, transitions)
    
    # 4. Generate Map
    state_map = generate_state_map(useful_states)
    log(f"Mapping generated for {len(state_map)} states.")

    # 5. Save Results
    cleaned_fsm = clean_fsm_data(fsm_data, state_map)
    save_json(cleaned_fsm, target_fsm_path)
    
    # Write seeds to output directory
    update_seed_files(seed_file_map, state_map, args.seeds_dir, target_seeds_dir, args.endian)

if __name__ == "__main__":
    main()