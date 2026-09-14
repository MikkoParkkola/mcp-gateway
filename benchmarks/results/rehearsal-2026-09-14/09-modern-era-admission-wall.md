# D/E reach `tools/call` and are refused there: modern-era admission

## What changed in the harness

`benchmarks/workload/k6_workload.js`, commit `03a21d63`. D and E declare the
modern era (`2026-07-28`), and `classify_request` (`src/protocol/meta.rs`)
reads that declaration as a promise about the whole request. The script now
keeps it, on the modern cells only:

- `params._meta["io.modelcontextprotocol/protocolVersion"]`
- `params._meta["io.modelcontextprotocol/clientCapabilities"]` (`{}`, the
  spec's own "no client options" form)
- `Mcp-Method` mirroring the JSON-RPC method
- `Mcp-Name` mirroring `params.name` on `tools/call` — `gateway_invoke`, the
  meta-surface tool actually executed, never the pinned backend tool nested
  inside `arguments` (`mcp_name_body_field`, `src/protocol/headers.rs:63-70`)

The legacy cells (A/B/C) are untouched by this commit: `IS_MODERN_ERA` is
false for `2025-06-18`, so their request bytes are identical to run
`2026-09-14-hdrfix-v2`.

## It works, up to the point where it does not

Previously D/E died at `initialize` with `missing required request metadata:
io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/
clientCapabilities`. They now pass `initialize` **and** `tools/list`, and
reach the pinned `tools/call`. Both cells then fail identically, at
`k6_workload.js:204` in `setup()`:

```
time="2026-09-14T16:26:33Z" level=error msg="Error: void: pinned tool
workload_probe did not return the pinned payload; got
{\"jsonrpc\":\"2.0\",\"id\":\"3-tools/call\",\"error\":{\"code\":-32602,
\"message\":\"JSON-RPC error -32602: An explicit idempotency key is
required\"}}\n\tat setup (file:///scripts/k6_workload.js:204:11(116))\"
hint="script exception"
```

(`smoke-D.k6.err` and `smoke-E.k6.err`, run dirs
`2026-09-14-modernfix-smoke` and `-smoke-e`. E uses the mixed config, D the
shared one; same error, same code.)

## The refusal is by design, and the enumeration is closed

`MetaMcp::admit_operation`, `src/gateway/meta_mcp/admission.rs:134-166`:

- no idempotency key → `Ok(SyncAdmission::Unprotected)` **iff** `!is_modern
  || read_only`; otherwise `-32602 "An explicit idempotency key is required"`
- key present → a verified principal is required, else `-32003 "A verified
  execution principal is required"`

`gateway.workload.yaml` configures no authentication, so `verified_identity`
and `credential_principal` are both `None`. That closes the enumeration: with
no auth, **no** backend tool call on the modern era can be admitted unless
the target is declared read-only. Supplying the key does not help — it moves
the refusal from `-32602` to `-32003`.

Two further facts the cell design has to reckon with:

1. The key is read from `params._meta["io.mcp-gateway/idempotency-key"]`
   (`IDEMPOTENCY_KEY_META`, `src/protocol/mrtr.rs:33`, parsed at `:117-128`).
   That is a **vendor-namespaced** field, not an MCP spec field. A
   spec-conformant modern client with no gateway-specific knowledge cannot
   produce it.
2. The only no-auth escape is `read_only_target(server, tool)`
   (`admission.rs:90-99`), backed by `idempotency.read_only_tools` in
   configuration — a top-level key that exists at 4.0.0 only. Checked at all
   three pins: `git grep -c read_only_tools -- src/` matches
   `src/config/features/idempotency.rs` at `69ba9e03` and returns nothing at
   `32f135a6` (3.5.0) or `e138680a` (3.5.1). Both legacy `Config` structs are
   `#[serde(default)]` with zero `deny_unknown_fields` anywhere under
   `src/config/`, so the key parses and is discarded without a warning.

## The exception is not mine to take

`idempotency.read_only_tools` would make D/E pass. It is not applied here.

- It is an **operator-owned exception to mandatory modern execution
  admission** — the module's own framing, not a harness knob. Writing it into
  a §0 artefact is a release-owner decision, the same class of call
  `06-finding-response-cache.md` routed upward rather than deciding in-harness.
- It would also invalidate what D/E measure. Declaring the probe read-only
  makes those calls cache-eligible, and §3 says the deterministic
  **real-backend** arm is the whole reason D/E exist. Caching them removes
  the real-backend property. That is the same argument `07` made against a
  smaller change, and it still holds.

This is a finding about the **harness's cell design**, not a gateway defect.
4.0.0 refusing unauthenticated modern-era backend execution is intended
behaviour. The mismatch is that the contract specified unauthenticated D/E
cells against a version that mandates admission for modern execution. Nobody
noticed when the cells were written.

## Measured run

### The run reached D1 and stopped there

`2026-09-14-modernfix-v1` produced ten `summary.json` files — `A1`-`A3`,
`B1`-`B3`, `C1`-`C3` and `D1` — and then stopped on `void: D1: k6 exited
non-zero` (`run_workload.sh` exit 3). `E1`-`E3` never ran.

One rep earlier, in the **B0 warm-up**, the gateway process aborted:

```
B0.gateway.stderr:
memory allocation of 172000 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

run_workload.sh: line 196: 3816382 Aborted (core dumped) HOME="$gwhome" ...
```

followed by 701 KB of `connection reset by peer` in `B0.k6.err` as k6 kept
posting to a dead listener. The harness carried on into `B1`-`B3`, each of
which starts its own gateway under its own `home-B*`, so those reps ran
against live listeners. A0 had completed cleanly minutes earlier, and B's
request bytes are unchanged by `03a21d63` (`IS_MODERN_ERA` is false for
`2025-06-18`, so neither `_meta` nor the mirrored headers are added on A/B/C)
— B ran clean four times in `2026-09-14-hdrfix-v2` with identical bytes.

This is consistent with co-residency, and not established as its cause: Spark
was running a peer agent's `cargo clippy --all-targets` at the time
(`stdiochk` sessions at 16:33:30Z and 16:37:24Z), and a 172 KB allocation
failing on a box reporting 78 GB available one minute later fits a transient
spike. It fits a per-process `RLIMIT_AS` or a cgroup limit on the runner slice
equally well, and neither has been checked. The falsifier is a rerun on a
compile-quiet box (`pgrep -c rustc` and `pgrep -c cargo` both 0, 1-minute load
below 8.00 — the box idles near 12 with 75 logged-in users, so the gate has to
key on the compile fleet, and 8.00 sits below every reading taken while the
peers were building: 11.21, 12.51, 12.97, 13.83). An identical abort there
would rule co-residency out. It has not been run, and nothing below depends on
it.

**No latency number from this run is reported.** The whole run sat next to a
Rust compile fleet and cell B lost its warm-up; the A/B/C figures for this
rehearsal stay the `2026-09-14-hdrfix-v2` ones in `07-header-fix-and-rerun.md`,
whose request bytes are identical to these.

### Verdict

`python3 eval_workload.py /home/mikko/perf-workload/runs/2026-09-14-modernfix-v1`,
complete output:

```
VERDICT: VOID  (exit 3)
  D1: http_error_rate above zero
```

The evaluator raises before it prints any per-rep line, so there is no table
to quote and no margin comparison to make. VOID is a status of its own, not a
failure of the gateway's latency.

The void fires on D1's error rate rather than on a missing artefact: k6 still
writes a summary when `setup()` throws, and `D1.summary.json` holds exactly
the three setup requests. `D1.k6.txt`:

```
http_req_failed................: 33.33% 1 out of 3
```

`http_error_rate` is `{"passes": 1, "fails": 2, "value": 0.3333333333333333}`
— `initialize` and `tools/list` returned 200, the pinned `tools/call` did not.
That single non-200 is the `-32602` quoted above. No measured iteration ever
ran, so D1 carries no `semantic_assertion_rate` at all: the cell's latency and
semantic properties are not weaker than A/B/C here, they are absent.

The run's version pins are copied verbatim to
`10-pins-modernfix-v1.json.txt`: A `32f135a6`/3.5.0, B `e138680a`/3.5.1,
C/D/E `69ba9e03`/4.0.0, k6 image
`sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755`.

## Consequence

1. The four-part modern request shape is implemented and verified working
   through `tools/list` on both modern cells. That part of the D/E blocker is
   closed.
2. D/E remain unmeasurable without a release-owner decision: either declare
   `workload_probe` read-only (cheap, but changes what D/E measure), or give
   the modern cells an authenticated principal plus a per-call
   `io.mcp-gateway/idempotency-key` (preserves the real-backend property,
   costs admission-store work on every rep and diverges D/E from A/B/C by
   more than protocol era).
3. The A/B/C spread finding from `07` stands independently and is unaffected
   by anything in this file.

No PASS was observed. None is claimed.
