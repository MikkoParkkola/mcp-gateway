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

### Attempt 1 aborted on the shared box, before any measured rep

`2026-09-14-modernfix-v1` died in the **B0 warm-up**. The gateway process
itself aborted:

```
B0.gateway.stderr:
memory allocation of 172000 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

run_workload.sh: line 196: 3816382 Aborted (core dumped) HOME="$gwhome" ...
```

followed by 701 KB of `connection reset by peer` in `B0.k6.err` as k6 kept
posting to a dead listener. A0 had completed cleanly minutes earlier, and B's
request bytes are unchanged by `03a21d63` (`IS_MODERN_ERA` is false for
`2025-06-18`, so neither `_meta` nor the mirrored headers are added on A/B/C)
— B ran clean four times in `2026-09-14-hdrfix-v2` with identical bytes.

This is consistent with co-residency, and not established as its cause: Spark
was running a peer agent's `cargo clippy --all-targets` at the time
(`stdiochk` sessions at 16:33:30Z and 16:37:24Z), and a 172 KB allocation
failing on a box reporting 78 GB available one minute later fits a transient
spike. It fits a per-process `RLIMIT_AS` or a cgroup limit on the runner slice
equally well, and neither has been checked. Attempt 2 is gated on a
resource-quiet box (`pgrep -c rustc` and `pgrep -c cargo` both 0, 1-minute
load below 4.00 on 20 cores) and snapshots contention before and after, which
decides it: an identical abort on a quiet box rules co-residency out.
Independently, a latency measurement taken next to a full Rust build would not
have been usable even if it had survived. **No measured rep exists from
attempt 1; no number from it is reported.**

### What a second measure pass can add, and what it cannot

`03a21d63` leaves the A/B/C request bytes untouched, so a fresh A/B/C sample
re-measures what `2026-09-14-hdrfix-v2` already measured and says nothing
about the change under test, while carrying the full contention risk of a
20-minute run on a shared box. The A/B/C numbers for this rehearsal therefore
stay the hdrfix-v2 ones (`07-finding-spread.md`); no second per-rep table is
built from attempt 2. What attempt 2 is for is the evaluator verdict on a run
directory containing the modern cells.

That verdict is already determined by the refusal above, and the exact string
is worth stating in advance so it is not mistaken for plumbing: with `setup()`
throwing, D1 writes no `summary.json`, `require_file` raises
`Void("missing required file: D1.summary.json")` (`eval_workload.py:42`), and
the run reports `VERDICT: VOID (exit 3)`. That is the admission wall, not a
missing artefact — the cell never got past the `-32602` quoted above.

### Attempt 2 status

Not yet launched. It is gated on a resource-quiet box and will be reported
verbatim, or reported as blocked, in the same terms. Nothing in this file's
conclusion depends on it: the substantive result is the two smokes, which
already carry the verbatim `-32602` on both modern cells.

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
