#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Throwaway measurement for the lib test split (stage A fail-fast): build the lib test binary for one part (1..5),
# or whole ("all": the part variable unset, today's build), and print the mcp_gateway rustc's peak resident memory
# (its waited-for children, the linker included) and wall time, the step's wall time and the runner's hardware.
# Usage: measure-lib-part.sh <1..5|all>
set -uo pipefail
part=$1
echo "runner: $(nproc) CPUs, $(free -m | awk '/^Mem:/{print $2}') MB RAM, $(free -m | awk '/^Swap:/{print $2}') MB swap, $(uname -m)"
wrap="$RUNNER_TEMP/rss_wrap.py"
cat > "$wrap" <<'PY'
#!/usr/bin/env python3
import resource, subprocess, sys, time
start = time.monotonic()
rc = subprocess.call(sys.argv[1:])
if "mcp_gateway" in sys.argv and "--crate-name" in sys.argv:
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    print(f"RSS-WRAP mcp_gateway peak {peak // 1024} MB wall {time.monotonic() - start:.0f} s", file=sys.stderr)
sys.exit(rc)
PY
chmod +x "$wrap"
if [ "$part" != all ]; then
    export MCP_GATEWAY_TEST_PART="$part"
fi
log="$RUNNER_TEMP/build.log"
start=$(date +%s)
scripts/ci/with-memory-log.sh cargo test --lib --all-features --no-run --config "build.rustc-wrapper=\"$wrap\"" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
end=$(date +%s)
peak=$(grep -o 'RSS-WRAP mcp_gateway peak [0-9]* MB wall [0-9]* s' "$log" | tail -1)
echo "MEASURE part=$part rc=$rc step=$((end - start)) s ${peak:-no RSS-WRAP line}"
exit "$rc"
