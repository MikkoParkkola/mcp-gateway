# NFR.WORKLOAD.1 VOID: root cause

`eval_workload.py` returned `VERDICT: VOID (exit 3)` on
`/home/<redacted>/perf-workload/run-20260918` with `C1: semantic assertion rate
below 100%`. The cause is a gateway behaviour change, not a harness defect and
not a configuration miss.

## What the cells measured

| cell | arm | semantic assertion rate | http_req_failed |
|---|---|---|---|
| A0-A3 | v3.5.0 (`32f135a6`) | 100.00% | 0.00% |
| B0-B3 | v3.5.1 | 100.00% | 0.00% |
| C0-C3 | v4 (`a2505be0`) | 48.65 / 48.66 / 48.74 / 48.71% | 0.00% |
| D1 | v4, modern era | n/a | 33.33% |

Every failure is an HTTP 200 carrying a JSON-RPC error. `initialize` and
`tools/list` pass 100%; only `tools/call` fails (C1: 4146 of 8155).

## Mechanism

The v4 backend health probe sends MCP `ping`. The workload fixture answers
`-32601 unsupported method` (`benchmarks/workload/mcp_backend.py:95-96`), which
is a complete answer proving the process is alive. `record_unserved_probe`
(`src/backend/lifecycle.rs:1181-1221`) counts that answer as unserved and
escalates on the third in a row (`UNSERVED_ESCALATION = 3`, `:33`). Escalation
trips the circuit breaker, which then rejects every subsequent `tools/call`.

Observed on an independently reproduced run (gateway log `/tmp/c12.log`, bench-host):

    11:45:20  Health probe was not served  method="ping" code=-32601 consecutive=1
    11:45:30  Health probe was not served  method="ping" code=-32601 consecutive=2
    11:45:40  record_failure{reason="health probe unserved"} failures=1..5 threshold=5
    11:45:40  Circuit breaker opened backend=workload reason=health probe unserved
    11:45:40  Circuit open, rejecting request  (every tools/call from here on)

The probe runs every 10s, so the breaker opens ~30s into a 60s cell. That is
the ~50% rate, and the variance between runs (48.66% in the artifact,
34.42% on re-run) is the probe phase relative to cell start. v3.5.0 and v3.5.1
have no such probe, which is why both score 100%.

## Reproduction and exclusions

- Reproduced on a fresh gateway from the same C-arm binary: 34.42%
  (`initialize` 100%, `tools/list` 100%, `tools/call` 34%).
- curl cannot reproduce: 500/500 correct at 50-way concurrency on fresh
  connections, 6/6 on one reused connection, 4/4 replaying the k6
  `initialize` -> `tools/call` sequence. None of those runs lasted 30s.
- Configuration is excluded. The Void-10 fix is present in the config the run
  used: `cache.enabled: false` and `failsafe.rate_limit` 500 rps / 500 burst
  (`config/gateway.workload.yaml:24-30`).
- An earlier probe of ours reported 81 of 200 concurrent calls missing the
  pinned payload. That was concurrent shell appends interleaving into one file:
  the 200 lines held 200 `WORKLOAD_OK` occurrences with 52 lines carrying two.
  The gateway returned 200 correct bodies.

## Two findings

1. **Product.** A backend that does not implement `ping` is auto-disabled ~30s
   after start and restart-looped. `ping` is optional for MCP servers, and
   `-32601` is evidence the peer is alive and speaking the protocol; the code
   comment at `:1169-1172` says as much before escalating anyway. Any real
   backend without `ping` regresses from working on v3.5 to shedding all
   traffic on v4.
2. **Harness.** `C*.gateway.stdout` and `C*.gateway.stderr` in the run
   directory are 0 bytes, so the run captured no server-side evidence. The
   cause was only visible after re-running the cell by hand.

## Consequence for the gate

NFR.WORKLOAD.1 cannot be graded MET. The v4 cells measured a tripped breaker,
not gateway throughput. The measurement is unrunnable until the escalation
decision is settled; patching the fixture to answer `ping` would make the cells
green while leaving the product finding in place, so the fixture must not be
changed before finding 1 has a ruling.

## Same mechanism elsewhere

**Retracted 2026-09-18.** `tests/mik_7212_mrtr7_stdio_acs.rs` rows 7a/7b were
attributed here to the same `ping` escalation, on the strength of the same
CI-only signature and a fixture that does not serve `ping`. The attribution is
wrong, and the shared signature is what made it look right: "fails only under
load" fits every bound measured in wall-clock time, so it identifies none of
them.

Row 7a stayed red on CI run 35353793208, whose commit already contains
`d11bf4a1` — the escalation exemption below. A cause that is already fixed on
the branch cannot be the cause. The child's own logs from that run name the
bound instead: 58 x `error=Delivery { key: "branch", error: TimedOut }`, the
30-second per-prompt bound in `src/gateway/input_bridge.rs:280`, reached because
the row answers one of its 64 outstanding questions and abandons the other 63.
Those 58 failures reach the client as 57 top-level `-32003` frames, and
`src/gateway/meta_mcp/invoke.rs:2336` collapses every `BridgeError` variant into
that one code and message, so the wire cannot say which bound was hit — only
the child's log can.

What remains under 7a after the retraction is a narrower and real defect: call
id 66, one past the admission cap, was accepted without a busy refusal, had a
free admission permit for roughly 35 seconds as the abandoned questions timed
out, and emitted no frame of any kind. See MIK-7387.

## 2026-09-18: finding 1 has a ruling, and the ruling is implemented

The escalation decision the section above was waiting on has been settled and
built, so the measurement is no longer unrunnable and the fixture is no longer
frozen.

- **Ruling.** `docs/requirements/RELEASE-4.0.0-requirements.md:93`
  (MIK-7217.OUTBOUND.2(d)) now exempts `-32601` explicitly: a well-formed,
  id-correlated `method not found` is evidence the peer is alive, not a fault.
- **Implementation.** `src/backend/lifecycle.rs:1215-1223` resets
  `unserved_consecutive` to zero on `METHOD_NOT_FOUND_CODE` and returns before
  the escalation check, so a backend that never serves `ping` can no longer be
  auto-disabled. It resets rather than skips, so a peer alternating `ping`
  refusals with genuine faults cannot accumulate faults across the answers that
  proved it alive. Commit `d11bf4a1`, which also closes GH #567.

Consequences for the two findings:

1. **Product finding — closed at head, not on the release line.** `d11bf4a1`
   is contained only by `origin/work/v4-audit-adjudication`; it is not an
   ancestor of `origin/main`. The fix reaches the release line when PR #561
   merges, and NFR.WORKLOAD.1 cannot be graded against main before then.
2. **Harness finding — still open.** `C*.gateway.stdout` / `C*.gateway.stderr`
   were captured as 0 bytes. A re-measurement that repeats that capture bug
   produces another number with no server-side evidence behind it, so the
   harness fix precedes the re-run.

The gate stays at `built`. Promoting it needs a re-measured throughput number
taken against a build that contains `d11bf4a1`, with non-empty server-side
capture. That run is a heavy workload benchmark and belongs on bench-host, not on
the Mac holding the shared build lock.
