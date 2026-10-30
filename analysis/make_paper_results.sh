#!/bin/bash
# Regenerate every table and figure of the paper from a results folder.
#   ./analysis/make_paper_results.sh results [out_dir]
# Tables are printed to <out_dir>/*.txt, Fig. 3 is written to <out_dir>/fig3_*.pdf.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RES=$(cd -- "${1:?usage: $0 <results folder> [out_dir]}" && pwd)
OUT=$(mkdir -p "${2:-paper_results}" && cd -- "${2:-paper_results}" && pwd)
cd "$HERE"

run() { echo "[*] $1"; shift; "$@"; }
run "Consistency check"                    python3 data_check.py         "$RES" > "$OUT/data_check.txt"
run "Table II, Table VI (coverage)"        python3 coverage_table.py     "$RES" > "$OUT/table2_table6_coverage.txt"
run "Tables III, IV, VI (crashes)"         python3 crash_tables.py       "$RES" > "$OUT/table3_table4_table6_crashes.txt"
run "RQ1/RQ3 text (coverage over time)" python3 coverage_over_time_numbers.py "$RES" > "$OUT/text_coverage_over_time.txt"
run "Tables V, VII, VIII (Prefix Tree)"    python3 tree_tables.py        "$RES" > "$OUT/table5_table7_table8_tree.txt"
run "Table IX (coverage breakdown)"        python3 coverage_breakdown.py "$RES" > "$OUT/table9_coverage_breakdown.txt"
run "TMF numbers (Appendix B)"             python3 tmf_table.py          "$RES" > "$OUT/appendix_tmf.txt"
for t in ot wifi lte; do
    run "Fig. 3 ($t)"                      python3 plot_coverage_over_time.py "$RES" "$t" "$OUT/fig3_$t.pdf" > "$OUT/fig3_$t.txt"
done
echo "[+] Results in $OUT"
