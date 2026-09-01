# NFR.PERF.1 — benchmark contract

**Written before the run, on purpose.** A benchmark whose pass rule is chosen after the
numbers arrive is not a measurement, it is a defence. Nothing below may be edited once the
first measured rep starts; if something here turns out to be wrong, the run is void and a
new contract is written.

Status when written: **contract only, nothing measured yet.**

## What is being settled

`NFR.PERF.1` (`docs/requirements/RELEASE-4.0.0-requirements.md:230`) — verbatim:

> Tool-call latency through the gateway MUST NOT regress by more than 5% at P50 or 10% at
> P99 against 3.5.0 on the same workload.

This is an **end-to-end** requirement: "tool-call latency through the gateway", with P50 and
P99, which are properties of a distribution and cannot be produced by a microbenchmark. The
existing artifact `RELEASE-4.0.0-performance.md` measured the *added work* with criterion and
said so honestly in its own closing section. This contract replaces the argument with the
measurement it names.

## Arms

| arm | ref | commit |
|---|---|---|
| baseline | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` |
| candidate | `fix/mrtr2-continuation-handle` | `6218b8577e79b6cc07f34dd4c64326d1117558c6` |

Both built from source on the same machine, in the same session, with the same toolchain:

```
cargo build --release --locked --features a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics
```

The feature list is stated explicitly rather than left to `default` because a feature that is
absent in one arm compiles some benchmarked paths away entirely. Verified before writing this:
the `[features]` tables at the two refs are identical, so the same explicit list is achievable
at both (`git show v3.5.0:Cargo.toml` vs `Cargo.toml`). Each arm uses **its own** `Cargo.lock`
(`--locked`), because the dependency set is part of what the release is.

## Workload — the same one, and it is the repo's own

`tests/load/k6_gateway.js`, scenario `load` (50 VUs: 10 s ramp, 40 s hold, 10 s ramp down).

The script is present at **both** refs and is **byte-identical** between them:

| file | sha256 (first 16) at v3.5.0 | at HEAD |
|---|---|---|
| `tests/load/k6_gateway.js` | `6a8873a0a908566d` | `6a8873a0a908566d` |
| `tests/load/wrk_basic.lua` | `707fe47e32fb7d69` | `707fe47e32fb7d69` |
| `tests/load/README.md` | `4e5cd75900d45a5e` | `4e5cd75900d45a5e` |

That identity is what makes "the same workload" a fact rather than a claim. One copy of the
script is used to drive both arms.

Each VU iteration performs `initialize` -> `tools/list` -> `tools/call` against `POST /mcp`,
plus `/health`, `/dashboard`, `/ui/api/status`. The gateway is started with no backends
registered, so the surface under test is the Meta-MCP surface itself — which is the part of
the request path this release changed.

### The one workload hazard, named in advance

`k6_gateway.js:277-285` picks the tool to call as `listRes.result.tools[0].name`, falling back
to `gateway_status`. If the two arms order their tool list differently, the two arms call
**different tools**, and the comparison is between two workloads rather than two builds.

Pre-run check, mandatory: `tools/list` is issued once against each arm and `tools[0].name` is
recorded. If the names differ, this run is **void** and is repeated with the tool name pinned
identically for both arms.

## Primary metric and pass rule

Primary: **`mcp_tools_call_latency`**, the script's own Trend metric around the `tools/call`
request — the literal subject of the requirement.

```
PASS  iff  HEAD p50 <= 1.05 x v3.5.0 p50   AND   HEAD p99 <= 1.10 x v3.5.0 p99
```

Both computed on the **pooled** samples across that arm's measured reps, and additionally
reported **per rep**, so that variance is visible rather than hidden behind a median. A pass
whose per-rep spread is wider than the margin it passed by is reported as inconclusive, not
as a pass.

Secondary, reported but not the gate: `http_req_duration` p50/p95/p99,
`mcp_tools_list_latency`, `mcp_initialize_latency`, `health_latency`.

k6 runs with `--summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max"`, because p(99)
is not in k6's default summary for custom Trend metrics, and with `--summary-export`, so the
numbers come from JSON rather than from parsed console text.

## Rep schedule — interleaved, because the machine is shared

```
warm-up:  A0  B0        (discarded, never reported)
measured: A1  B1  A2  B2  A3  B3
```

A = v3.5.0, B = HEAD. **Interleaved, not blocked.** Spark is a shared machine with other
sessions' jobs landing on it; running all of one arm and then all of the other lets drift in
machine load masquerade as a difference between versions. Interleaving makes that drift appear
as within-arm variance, where it is visible.

Warm-up reps are discarded because a cold first arm is the standard way to manufacture a
regression that is not there.

Only one gateway process runs at a time. The arms bind **different ports** (v3.5.0 -> 39400,
HEAD -> 39401) so a stale listener from the previous rep cannot silently serve the next one.
Before every rep, `GET /health` is read and its reported version must match the arm being
measured — a positive identity check, not an assumption.

## Void conditions — declared now, so they cannot be negotiated later

The run is void, and is reported as void rather than quietly repaired, if any of:

1. `tools[0].name` differs between arms (see hazard above).
2. `http_error_rate` > 0 on any measured rep. Error responses have their own latency
   distribution; a fast 500 is not a fast tool call.
3. `checks` pass rate < 99% on any measured rep.
4. `/health` version does not match the arm under test at any rep.
5. Either build fails, or the two builds do not use the same feature list and toolchain.
6. Any measured rep runs while a second gateway process is listening.

Machine load is **recorded** (`uptime` before and after every rep) rather than used as a void
condition — interleaving is what handles load, and a load threshold chosen after seeing the
numbers would be exactly the kind of post-hoc rule this contract exists to prevent.

## Environment — pinned

| | |
|---|---|
| host | `spark` (all benchmarking; a Mac number would be rejected, correctly) |
| cores | 20 |
| rustc | `1.98.0 (88d9e12ae 2026-08-18)` — above the `rust-version = "1.95"` both arms require |
| k6 | `grafana/k6` container image, one image for both arms; exact digest recorded with results |
| shared? | yes — other sessions' jobs run concurrently. Load recorded per rep; arms interleaved. |
| transport | both arms delivered to Spark as one git bundle, built in an isolated directory, not in the shared checkout |

## What this measurement will not establish

Stated in advance, because a benchmark that oversells itself is worse than none:

- It measures a gateway with **no backends registered**. Real tool calls cross a second
  process boundary, which adds latency this run does not contain. That makes the test
  *harsher* than production — gateway overhead is a larger share of a smaller total — so it
  does not flatter the candidate.
- 50 VUs on a shared 20-core box is a load level, not *the* load level. Nothing here licenses
  a public throughput or latency claim.
- It settles `NFR.PERF.1` only. `NFR.PERF.2` is a separate question about header-first
  routing, answered separately.
