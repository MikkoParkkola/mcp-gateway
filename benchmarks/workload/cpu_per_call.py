#!/usr/bin/env python3
"""Throwaway measurement (never merged): gateway CPU per tools/call.

  cpu_per_call.py measure PORT PID WARMUP CALLS RATE OUT.json
  cpu_per_call.py summarize OUT_DIR

measure: paced legacy-era tools/call (gateway_invoke on the workload fixture,
the request k6_workload.js sends) at RATE/s over four keep-alive connections.
The gateway's utime+stime (/proc/PID/stat; its backend child is not counted)
is read after WARMUP calls and again after CALLS more. Every answer must be a
200 carrying the pinned text and no JSON-RPC error, else exit 3 (VOID).

summarize: files rep<N>-<ARM>.json for arms P, T0, T1. Per rep, the savings
P-T0 (all of B14 but item 1: item 2, plus 7916 and 7663, assumed off this
path), T0-T1 (item 1) and P-T1 (all of B14) in us/call; median and a
distribution-free 95% interval on the median from order statistics.
"""
import http.client
import json
import math
import os
import sys
import threading
import time
from pathlib import Path

EXPECT = "WORKLOAD_OK case=042 bundle=deterministic"
BODY = json.dumps({
    "jsonrpc": "2.0", "id": "1-tools/call", "method": "tools/call",
    "params": {"name": "gateway_invoke", "arguments": {
        "server": "workload", "tool": "workload_probe",
        "arguments": {"case_reference": "042"}}},
})
HEADERS = {"Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}
THREADS = 4
# CPC_MIX=workload: one call is one k6_workload.js iteration (health,
# initialize, tools/list, tools/call), each answer checked; CPU is per iteration.
MIX = os.environ.get("CPC_MIX") == "workload"
INIT = json.dumps({"jsonrpc": "2.0", "id": "1-initialize", "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "nfr-workload-1", "version": "1"}}})
LIST = json.dumps({"jsonrpc": "2.0", "id": "1-tools/list", "method": "tools/list", "params": {}})


def exchange(conn, method: str, body: str | None) -> tuple[bool, str]:
    """One request; ok when 200 and, for JSON-RPC, no error (tools/list must
    list tools, tools/call must carry the pinned text)."""
    if body is None:
        conn.request("GET", "/health")
    else:
        conn.request("POST", "/mcp", body, HEADERS)
    reply = conn.getresponse()
    raw = reply.read()
    if body is None:
        return reply.status == 200, f"{reply.status} {raw[:200]!r}"
    try:
        answer = json.loads(raw)
        ok = reply.status == 200 and "error" not in answer
        if ok and method == "tools/list":
            ok = bool(answer["result"]["tools"])
        if ok and method == "tools/call":
            ok = EXPECT in json.dumps(answer["result"])
    except (ValueError, KeyError, TypeError):
        ok = False
    return ok, f"{method} {reply.status} {raw[:200]!r}"


STEPS = ([("health", None), ("initialize", INIT), ("tools/list", LIST)] if MIX else []) + [("tools/call", BODY)]


def cpu_ticks(pid: int) -> int:
    stat = Path(f"/proc/{pid}/stat").read_text()
    fields = stat[stat.rindex(")") + 2:].split()
    return int(fields[11]) + int(fields[12])  # utime, stime: stat fields 14, 15


def drive(port: int, calls: int, rate: float) -> list[str]:
    """Send `calls` answered calls; any failure, raised or answered, is listed.
    A short count is a failure too: CPU is divided by `calls`, so a thread that
    died early would understate the cost per call."""
    errors: list[str] = []
    done = [0] * THREADS
    per, interval = calls // THREADS, THREADS / rate

    def worker(index: int) -> None:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            due = time.monotonic() + index * interval / THREADS
            for _ in range(per):
                pause = due - time.monotonic()
                if pause > 0:
                    time.sleep(pause)
                due += interval
                for method, body in STEPS:
                    ok, seen = exchange(conn, method, body)
                    if not ok:
                        errors.append(seen)
                        return
                done[index] += 1
            conn.close()
        except Exception as error:  # noqa: BLE001 -- any failure voids the arm
            errors.append(f"{type(error).__name__}: {error}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if not errors and sum(done) != per * THREADS:
        errors.append(f"answered {sum(done)} of {per * THREADS}")
    return errors


def measure(port: str, pid: str, warmup: str, calls: str, rate: str, out: str) -> int:
    port_n, pid_n, rate_f = int(port), int(pid), float(rate)
    calls_n = int(calls) // THREADS * THREADS
    if errors := drive(port_n, int(warmup), rate_f):
        print(f"VOID: warm-up answer rejected: {errors[0]}")
        return 3
    start, t0 = cpu_ticks(pid_n), time.monotonic()
    errors = drive(port_n, calls_n, rate_f)
    ticks, wall = cpu_ticks(pid_n) - start, time.monotonic() - t0
    if errors:
        print(f"VOID: answer rejected: {errors[0]}")
        return 3
    clk = os.sysconf("SC_CLK_TCK")
    row = {"calls": calls_n, "ticks": ticks, "clk_tck": clk, "wall_s": round(wall, 2),
           "achieved_rps": round(calls_n / wall, 1),
           "load1": float(Path("/proc/loadavg").read_text().split()[0]),
           "us_per_call": ticks / clk * 1e6 / calls_n}
    Path(out).write_text(json.dumps(row))
    print(json.dumps(row))
    return 0


def median_interval(values: list[float]) -> tuple[float, float, float, float]:
    """Median and the order-statistic interval with coverage >= 95%."""
    xs, n = sorted(values), len(values)
    k = 0  # largest k with P(Bin(n, 1/2) < k) <= 0.025
    while sum(math.comb(n, i) for i in range(k + 1)) / 2**n <= 0.025:
        k += 1
    if k == 0:
        raise SystemExit(f"{n} reps cannot support a 95% median interval")
    cover = 1 - 2 * sum(math.comb(n, i) for i in range(k)) / 2**n
    mid = (xs[(n - 1) // 2] + xs[n // 2]) / 2
    return mid, xs[k - 1], xs[n - k], cover


def summarize(out_dir: str) -> int:
    rows: dict[int, dict[str, float]] = {}
    for path in Path(out_dir).glob("rep*-*.json"):
        rep, arm = path.stem[3:].split("-", 1)
        rows.setdefault(int(rep), {})[arm] = json.loads(path.read_text())["us_per_call"]
    reps = sorted(r for r, arms in rows.items() if set(arms) == {"P", "T0", "T1"})
    if len(reps) != len(rows):
        print(f"VOID: incomplete reps {sorted(set(rows) - set(reps))}")
        return 3
    report = {"reps": len(reps), "per_rep": {r: rows[r] for r in reps}}
    for name, (a, b) in {"b14-minus-item1 P-T0": ("P", "T0"), "item1 T0-T1": ("T0", "T1"),
                         "b14 P-T1": ("P", "T1")}.items():
        mid, lo, hi, cover = median_interval([rows[r][a] - rows[r][b] for r in reps])
        report[name] = {"median_saving_us": round(mid, 3), "interval": [round(lo, 3), round(hi, 3)],
                        "coverage": round(cover, 4), "meets_bar": mid >= 1.0 and lo > 0}
    for arm in ("P", "T0", "T1"):
        report[f"{arm} median us/call"] = round(median_interval([rows[r][arm] for r in reps])[0], 2)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["measure"] and len(sys.argv) == 8:
        sys.exit(measure(*sys.argv[2:]))
    if sys.argv[1:2] == ["summarize"] and len(sys.argv) == 3:
        sys.exit(summarize(sys.argv[2]))
    sys.exit(__doc__)
