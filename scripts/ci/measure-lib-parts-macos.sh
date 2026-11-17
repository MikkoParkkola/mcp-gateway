#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Throwaway measurement (the macOS gate for the lib test split): print the runner's hardware first, then build the lib
# test binary in sequence for the floor (part 0: the code every part shares; it also compiles the dependencies) and
# for parts 1..5, running nothing. Each build prints one MEASURE line: its step wall time, the mcp_gateway rustc's
# peak resident memory and wall time (the linker included), and the peak swap in use while it built.
set -uo pipefail
echo "runner: $(sysctl -n hw.ncpu) CPUs, $(( $(sysctl -n hw.memsize) / 1048576 )) MB RAM, $(sysctl -n machdep.cpu.brand_string), $(uname -m); swap at start: $(sysctl -n vm.swapusage)"
wrap="$RUNNER_TEMP/rss_wrap.py"
cat > "$wrap" <<'PY'
#!/usr/bin/env python3
import resource, subprocess, sys, time
start = time.monotonic()
rc = subprocess.call(sys.argv[1:])
if "mcp_gateway" in sys.argv and "--crate-name" in sys.argv:
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # bytes on macOS
    print(f"RSS-WRAP mcp_gateway peak {peak // 1048576} MB wall {time.monotonic() - start:.0f} s", file=sys.stderr)
sys.exit(rc)
PY
chmod +x "$wrap"
fail=0
for part in 0 1 2 3 4 5; do
    log="$RUNNER_TEMP/build-$part.log"
    swaps="$RUNNER_TEMP/swap-$part"
    : > "$swaps"
    # vm.swapusage reads "total = 2048.00M  used = 1024.50M  free = ...": the used figure, in MB.
    ( while :; do sysctl -n vm.swapusage | awk '{sub("M", "", $6); print $6}' >> "$swaps"; sleep 15; done ) &
    sampler=$!
    start=$(date +%s)
    MCP_GATEWAY_TEST_PART=$part cargo test --lib --all-features --no-run --config "build.rustc-wrapper=\"$wrap\"" > "$log" 2>&1
    rc=$?
    end=$(date +%s)
    kill "$sampler" 2> /dev/null
    peak=$(grep -o 'RSS-WRAP mcp_gateway peak [0-9]* MB wall [0-9]* s' "$log" | tail -1)
    swap=$(sort -n "$swaps" | tail -1)
    echo "MEASURE part=$part rc=$rc step=$((end - start)) s ${peak:-no RSS-WRAP line} swap_peak=${swap:-n/a} MB"
    if [ "$rc" -ne 0 ]; then
        tail -30 "$log"
        fail=1
    fi
done
exit "$fail"
