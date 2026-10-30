#!/usr/bin/env python3
import os
import sys
import re
import json

def main():
    if len(sys.argv) < 2:
        script_name = os.path.basename(sys.argv[0])
        print("Error: Please provide the run directory path.", file=sys.stderr)
        print(f"Usage: python3 {script_name} /path/to/run_01", file=sys.stderr)
        sys.exit(1)

    run_dir = sys.argv[1]

    if not os.path.isdir(run_dir):
        print(f"Error: Directory '{run_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Automatically extract and uppercase the run directory name
    run_name = os.path.basename(os.path.normpath(run_dir)).upper()

    # 1. Discover Iteration Directories
    iters = []
    for name in os.listdir(run_dir):
        if name.startswith("iter_") and os.path.isdir(os.path.join(run_dir, name)):
            match = re.search(r"iter_(\d+)", name)
            if match:
                iters.append((int(match.group(1)), os.path.join(run_dir, name)))

    if not iters:
        # aflnet (Type 2) or concat (Type 3) - treat root as iter_01
        iters.append((1, run_dir))
    else:
        iters.sort()

    # 2. Locate Global Fuzzer Statistics and Calculate Execs/sec
    execs_done_total = 0
    total_time_seconds = 0
    execs_per_sec = None

    root_stats = os.path.join(run_dir, "fuzzer_stats")               
    default_stats = os.path.join(run_dir, "default", "fuzzer_stats") 

    if os.path.exists(root_stats) or os.path.exists(default_stats):
        stats_path = root_stats if os.path.exists(root_stats) else default_stats
        with open(stats_path, "r", encoding="utf-8", errors="ignore") as f:
            stats_content = f.read()
            m_done = re.search(r"execs_done\s*:\s*(\d+)", stats_content)
            m_sec = re.search(r"execs_per_sec\s*:\s*([\d.]+)", stats_content)
            
            if m_done:
                execs_done_total = int(m_done.group(1))
            if m_sec:
                try:
                    execs_per_sec = int(round(float(m_sec.group(1))))
                except ValueError:
                    pass

    elif iters:
        # Calculate cumulated stats for interceptfuzz across all iterations (Type 1)
        for iter_num, iter_dir in iters:
            cand = os.path.join(iter_dir, "artifacts", "fuzz_out", "default", "fuzzer_stats")
            if os.path.exists(cand):
                with open(cand, "r", encoding="utf-8", errors="ignore") as f:
                    stats_content = f.read()
                    
                    m_done = re.search(r"execs_done\s*:\s*(\d+)", stats_content)
                    if m_done:
                        execs_done_total += int(m_done.group(1))
                    
                    m_run_time = re.search(r"run_time\s*:\s*(\d+)", stats_content)
                    if m_run_time:
                        total_time_seconds += int(m_run_time.group(1))

        if total_time_seconds > 0:
            execs_per_sec = int(round(execs_done_total / total_time_seconds))
        elif execs_done_total > 0:
            execs_per_sec = 0

    # Helper function to extract coverage metrics
    def parse_metric(metric, text):
        m = re.search(fr"{metric}:\s*([\d.]+)%\s*\((\d+)\s*out of\s*(\d+)\)", text, re.IGNORECASE)
        if m:
            return float(m.group(1)), int(m.group(2)), int(m.group(3))
        
        m_fall = re.search(fr"{metric}:\s*([\d.]+)%", text, re.IGNORECASE)
        if m_fall:
            return float(m_fall.group(1)), None, None
        return None, None, None

    # Prepare root JSON structure
    output_data = {
        "run_name": run_name,
        "execs_total": execs_done_total if execs_done_total > 0 else None,
        "execs_per_sec": execs_per_sec,
        "iterations": []
    }

    # Identify the last iteration number
    last_iter_num = iters[-1][0] if iters else None

    # 3. Process each Iteration for States and Coverage
    for iter_num, iter_dir in iters:
        l_pct, l_cov, l_tot = None, None, None
        f_pct, f_cov, f_tot = None, None, None
        b_pct, b_cov, b_tot = None, None, None
        
        # Only look for coverage files strictly INSIDE the iter_X folder by default
        iter_cov_candidates = [
            os.path.join(iter_dir, "coverage_final_wo_minimize.txt"),
            os.path.join(iter_dir, "iterative_coverage_out.txt"),
            os.path.join(iter_dir, "coverage.txt"),
            os.path.join(iter_dir, "cov_summary.txt"),
            os.path.join(iter_dir, "logs", "coverage_after_fuzzing.txt"),
            os.path.join(iter_dir, "logs", "coverage_after_minimize.txt"),
            # written by fuzzers/interceptfuzz/scripts/collect_iteration_coverage.sh
            os.path.join(iter_dir, "artifacts", "coverage_before_minimize.txt")
        ]
        
        # If this is the LAST iteration, allow falling back to the root folder's coverage
        if iter_num == last_iter_num:
            iter_cov_candidates.extend([
                os.path.join(run_dir, "coverage_final_wo_minimize.txt"),
                os.path.join(run_dir, "coverage_final.txt"),
                os.path.join(run_dir, "iterative_coverage_out.txt")
            ])
        
        for cov_path in iter_cov_candidates:
            if os.path.exists(cov_path):
                with open(cov_path, "r", encoding="utf-8", errors="ignore") as f:
                    cov_content = f.read()
                    l_pct, l_cov, l_tot = parse_metric("lines", cov_content)
                    f_pct, f_cov, f_tot = parse_metric("functions", cov_content)
                    b_pct, b_cov, b_tot = parse_metric("branches", cov_content)
                break  
        
        total_states = None
        
        state_candidates = [
            os.path.join(iter_dir, "artifacts", "state_db_after_save_seeds.json"), 
            os.path.join(run_dir, "state_db.json")                                 
        ]
        
        for json_path in state_candidates:
            if os.path.exists(json_path):
                with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        m_state = re.search(r'"state_counter_":\s*(\d+)', line)
                        if m_state:
                            total_states = int(m_state.group(1))
                            break
                if total_states is not None:
                    break  
        
        # Build the iteration object
        iter_data = {
            "iteration": iter_num,
            "total_states": total_states,
            "coverage": {
                "lines": {"percent": l_pct, "covered": l_cov, "total": l_tot} if l_pct is not None else None,
                "functions": {"percent": f_pct, "covered": f_cov, "total": f_tot} if f_pct is not None else None,
                "branches": {"percent": b_pct, "covered": b_cov, "total": b_tot} if b_pct is not None else None
            }
        }
        
        output_data["iterations"].append(iter_data)

    # 4. Save the structured JSON
    out_file = os.path.join(run_dir, "statistics.json")
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4)
        print(f"[+] Successfully saved statistics to: {out_file}")
    except Exception as e:
        print(f"[-] Error saving to {out_file}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()