# NFR.WORKLOAD.1 — pre-registered workload contract

Status: **contract only, nothing measured yet.**

Criterion authority: `RELEASE-4.0.0-scope-update.md:55` and
`RELEASE-4.0.0-scope-tests.md:69`. Grading row lives in
`RELEASE-4.0.0-scope-status.json` (cited, never edited from here).

This contract is a sibling of `RELEASE-4.0.0-performance-contract.md`
(NFR.PERF.1), not an amendment to it. That contract is frozen and its scored
run is unfired; nothing here edits it.

Shared machinery is re-pinned below by sha measured when this document was
written, and **inherits no pin from NFR.PERF.1**. That is deliberate, not an
oversight: the runner sha in that contract is ambiguous — Amendment 3
declares `b65e2331...` superseding, while Amendment 5 and the copy on disk
carry `003571d7...`. Inheriting an unresolved pin would import another
effort's defect into this pre-registration, and inherited-pin ambiguity is
exactly what a reviewer is entitled to reject.

## 0. Harness components

| Component | Path |
|---|---|
| Backend fixture | `benchmarks/workload/mcp_backend.py` |
| Workload script | `benchmarks/workload/k6_workload.js` |
| Gateway config template (cells A-D) | `benchmarks/workload/gateway.workload.yaml` |
| Gateway config template (cell E) | `benchmarks/workload/gateway.workload.mixed.yaml` |
| Runner | `benchmarks/workload/run_workload.sh` |
| Evaluator | `benchmarks/workload/eval_workload.py` |
| Evaluator self-check | `benchmarks/workload/test_eval_workload.py` |

The fixture and the evaluator each carry a runnable self-check. The evaluator
check asserts that PASS, FAIL, INCONCLUSIVE and VOID are separately
reachable, including the specific voids for a patch-level health mismatch, a
missing checkout SHA, an unpinned load generator and an unparseable summary.

## 1. What is being settled

Whether a deterministic real-backend workload on 4.0.0 returns successful
semantic payloads and stays inside the regression budget against the legacy
gateway, on legacy, modern and mixed-era paths.

## 2. What is already settled elsewhere — do not rebuild

NFR.PERF.1 runs `tests/load/k6_gateway.js` against a gateway started with **no
backends registered**. That is exactly this row's "no-backend control,
separately labelled". It is reused as-is and reported under its own label; it
is not this row's real-backend arm and is never pooled with one.

The genuinely new component is the **deterministic real-backend arm**.

## 3. Arms and cells

Legacy real-backend cells, interleaved, the only comparison that gates:

| Cell | Ref | Port | Protocol path |
|---|---|---|---|
| A | `v3.5.0` | 39420 | legacy |
| B | `v3.5.1` | 39421 | legacy |
| C | `HEAD` (4.0.0) | 39422 | legacy |

4.0.0-only cells, measured and reported, never compared (no counterpart arm
exists):

| Cell | Ref | Port | Protocol path |
|---|---|---|---|
| D | `HEAD` | 39423 | modern |
| E | `HEAD` | 39424 | mixed-era |

Plus the separately labelled no-backend control from NFR.PERF.1.

Six cells total. The full 3x3 crossing is not run and is not required by the
row. A reviewer seeing six where a crossing gives eighteen should read 3.1
before reading it as sampling: the missing cells are not omitted, they cannot
exist.

### 3.1 Why 3.5.0 and 3.5.1 are legacy-only

Measured, not inferred:

```
git grep -c "2026-07-28" v3.5.0 -- src   # zero hits
git grep -c "2026-07-28" v3.5.1 -- src   # zero hits
git ls-tree -r --name-only v3.5.1 -- src/protocol/
#   messages.rs mod.rs negotiate.rs types.rs   (no era.rs)
```

`src/backend/era.rs` exists only at HEAD. Cells D and E therefore have no
legacy counterpart by construction, which is why they are measured and not
compared.

## 4. Freeze semantics — the decision this contract needs ruled

"Freeze the 3.5.0 baseline" and "same-host interleaved" cannot both mean
"measure 3.5.0 today, compare 4.0.0 to those numbers post-merge". A stored
number compared against a later separate run is precisely the non-interleaved
comparison the row forbids.

Recommended reading, **confirmed by the release owner** and the one this
contract is written to:

- **Frozen artefacts**: harness, this contract, per-arm checkout SHAs, build
  recipe, backend fixture, registration configs, pinned tool name, k6 image
  digest, evaluator. All sha-pinned here before the first measured rep.
- **Frozen reference figure**: a rehearsal-recorded 3.5.0 number, stored in
  `benchmarks/results/`, labelled `reference, not gating`.
- **Scored run**: re-measures A, B and C interleaved at post-merge time. The
  gate is decided only by that run.

The alternative reading (frozen numbers are the gating baseline) fails the
acceptance text and is not adopted here without an explicit ruling.

## 5. Workload

Backend: one process, `benchmarks/workload/mcp_backend.py`. One tool
(`workload_probe`), one fixed argument (`case_reference: "042"`), one fixed
payload (`WORKLOAD_OK case=042 bundle=deterministic`), and **no per-call I/O
of any kind** — nothing is logged, opened or flushed inside a `tools/call`, so
measured latency is gateway time and not fixture time.

`benchmarks/live_agent_mcp_server.py` was considered as the fixture and
rejected on evidence: it writes a JSONL log line inside every `tools/call`,
putting disk I/O in the measured path; its payload is keyed to `--trial-id`
and to tool-selection correctness rather than a fixed semantic result; and it
is owned by the MIK-6977 benchmark, so pinning it would couple this frozen
contract to a file another effort can legitimately change.

Invocation path: the backend tool is reached through the Meta-MCP surface via
`gateway_invoke` with `{server, tool, arguments}`. That schema is present and
identical at all three refs — `required: ["server", "tool"]` at `v3.5.0`,
`v3.5.1` and HEAD, with HEAD adding only an optional `nonce` that this
configuration never requires. One call shape is therefore valid for every
cell.

Semantic assertion: every measured `tools/call` must return the exact pinned
payload string. A response that is merely HTTP 200, or JSON-RPC well-formed,
or an error, fails the assertion. A cell whose semantic assertion rate is
below 100% voids.

### 5.1 Registration-config hazard — retired by measurement

NFR.PERF.1 could hold "same workload" as a fact because its k6 script was
byte-identical at both refs. A registered backend does not inherit that, so
the registration configs were compared directly:

```
git diff v3.5.0 HEAD -- examples/minimal.yaml examples/servers.yaml   # empty
```

The measured surface itself was compared, not assumed. The router's registered
route table is identical at `v3.5.0` and HEAD — `/.well-known/jwks.json`,
`/.well-known/oauth-protected-resource`, `/health`, `/api/costs`, `/mcp`,
`/mcp/{name}`, `/mcp/{name}/{*path}`, `/sse`, `/metrics`
(`src/gateway/router/mod.rs`). Both endpoints this row touches, `/mcp` and
`/health`, exist identically at both refs.

`/health` needs no credential: `auth.enabled` defaults to false and
`/health` is in `default_public_paths()` (`src/config/features/auth.rs`), so
the readiness probe is not measuring an auth path. Its `version` field is
`env!("CARGO_PKG_VERSION")` at both `v3.5.0` and HEAD
(`src/gateway/router/handlers.rs`), i.e. a bare `3.5.0`, which is the exact
form the evaluator compares and the form `pins.json` derives from
`Cargo.toml`. That was read from source rather than discovered in a rep.

The `backends.<name>.command` stdio registration shape is unchanged across
the range, and `--port` / `MCP_GATEWAY_PORT` is defined identically at
`v3.5.0` and HEAD (`src/cli/mod.rs`). Cells therefore share **one
byte-identical config**, rendered once per run from
`benchmarks/workload/gateway.workload.yaml`, with the port supplied per cell
on the command line. Byte-identity is a stronger guarantee than three configs
argued to be equivalent, and it is what the gating cells A, B and C run.

The committed file is a **template**, not the file the gateway loads. The
gateway expands `${VAR}` in a backend's `headers` and `env` and in
`capabilities.directories`, but **not** in `command`
(`src/config/mod.rs::expand_env_vars`, read at freeze). A
`${WORKLOAD_FIXTURE}` left in `command` would reach the shell verbatim and
every cell would void at backend start. The runner therefore substitutes the
fixture's absolute path once into `<run>/config/`, and all four gating cells
load that single rendered file — so byte-identity is preserved, not traded
away. `<run>/config.sha256` records the digest of both template and rendered
file, which is what §11 pins.

Cell E is the single exception: `gateway.workload.mixed.yaml` differs in
exactly one token, pinning the fixture to a legacy protocol version while the
client requests the modern one, which is what makes that cell mixed-era. Cell
E is report-only and never compared, so the gating cells keep byte-identity
between them.

### 5.2 Tool pinning — and why this row has its own k6 script

`tests/load/k6_gateway.js` is **not** used here, for three reasons: it is
byte-pinned by the NFR.PERF.1 contract whose scored run is unfired, so
editing it would disturb a frozen pre-registration; it has no way to pin a
tool name, selecting `listRes.result.tools[0].name` by list ordering; and its
`tools/call` check explicitly accepts an error response, which cannot express
this row's requirement for successful semantic payloads.

`benchmarks/workload/k6_workload.js` is used instead. The tool name, backend
name, expected payload and client protocol version all arrive by environment
variable, so the script is byte-identical across every cell by construction —
and because the runner supplies it rather than taking it from each checkout,
that identity needs no per-ref verification.

Before any measured request, the script's `setup()` asserts that
`gateway_invoke` is present on the meta surface and that the pinned tool
returns the pinned payload. Either failure aborts the run rather than
producing a cell that silently measured the wrong thing.

### 5.3 Load generator pinning

The k6 container is pinned **by digest**. The `:latest` fallback used in the
NFR.PERF.1 runner is removed: a mutable load generator between the reference
run and the scored run would silently invalidate the comparison and the
difference would be charged to the gateway. An unset or non-`sha256:` digest
is a hard void, exit 3, before any build starts — not a warning.


## 6. Primary metric and pass rule

Primary: `mcp_tools_call_latency` Trend around `tools/call`.

```
PASS iff  C.p50 <= 1.05 * min(A.p50, B.p50)
     and  C.p99 <= 1.10 * min(A.p99, B.p99)
```

3.5.1 is the current upgrade/comparison source; 3.5.0 remains the frozen
reference. Using `min` means the budget is held against whichever legacy arm
is faster, which is the conservative reading.

Pooled across measured reps, and reported per rep. Per-rep spread wider than
the margin it is being judged against yields **INCONCLUSIVE**, never PASS.

INCONCLUSIVE is a **distinct exit status of the evaluator**, not a string in a
report. `benchmarks/workload/eval_workload.py` exits:

| Exit | Verdict |
|---|---|
| 0 | PASS |
| 1 | FAIL |
| 2 | INCONCLUSIVE |
| 3 | VOID |

A criterion graded from a run that was actually inconclusive is the failure
mode that costs most, because in the ledger it looks exactly like a pass.
Nothing may grade this row from an exit status other than 0.

Cells D and E report p50/p90/p99 with no pass rule attached.

Secondary, non-gating: `http_req_duration` p50/p95/p99,
`mcp_tools_list_latency`, `mcp_initialize_latency`, `health_latency`.

k6 flags: `--summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max"`
plus `--summary-export`, each stream to its **own path** — the JSON-lines
stream, the text summary and the summary-export never share a file
descriptor, and none of them share stdout or stderr with the gateway. This is
defect D1 from the NFR.PERF.1 rehearsal record (A5), which voided that
rehearsal on plumbing rather than on any property of the gateway. The
evaluator treats an unparseable summary as VOID so the same defect can never
be mistaken for a measurement.

## 7. Rep schedule

```
warm-up  (discarded):  A0 B0 C0
measured:              A1 B1 C1  A2 B2 C2  A3 B3 C3
then:                  D1 E1  D2 E2  D3 E3
```

Interleaved because bench-host is shared and other sessions' jobs land on it. One
gateway listening at a time. Before each rep, `GET /health` version must match
that cell by **exact string** — 3.5.0 and 3.5.1 differ only by patch, so a
prefix match is not sufficient.

The runner writes the launch argv and the per-arm checkout SHA **before the
arm runs**, not into a summary afterwards, so a run that dies mid-arm still
leaves behind what it was running. This is defect D4 from A5. The evaluator
voids any rep whose `meta.argv` or `meta.checkout_sha` is missing, so the
guarantee is enforced rather than merely intended.

## 8. Void conditions

1. Pinned tool name absent from any cell's `tools/list`.
2. Semantic assertion rate below 100% in any measured rep.
3. `http_error_rate` above 0 in any measured rep.
4. k6 checks pass rate below 99%.
5. `/health` version exact-string mismatch for any cell.
6. Build failure, or differing feature set or toolchain across cells.
7. A second gateway listening during a rep.
8. Gating cells A, B and C not running a byte-identical gateway config.
9. k6 image unset, or resolved by tag rather than a `sha256:` digest.

Machine load (`uptime`) is recorded, not a void condition.

## 9. Build

Both legacy arms and HEAD:

```
cargo build --release --locked --features \
  a2a,webui,config-export,cost-governance,firewall,discovery,\
semantic-search,tool-profiles,metrics
```

Each arm keeps its own `Cargo.lock`. These builds run outside CI's
`RUSTFLAGS: -Dwarnings`, so the branch's known dead-code red does not block
measurement.

All builds and all reps run on bench-host via `bench-run --bg`. Nothing in this
contract runs on the Mac.

## 10. What this will not establish

Throughput, memory, cold-start, multi-backend fan-out, or any claim about
modern/mixed-era versus legacy performance. Cells D and E have no counterpart
arm; their numbers describe 4.0.0 only.

## 11. Pins

Filled before the first measured rep; empty pins void the run.

| Artefact | sha256 |
|---|---|
| this contract | (pinned at freeze) |
| `benchmarks/workload/run_workload.sh` | (pinned at freeze) |
| `benchmarks/workload/eval_workload.py` | (pinned at freeze) |
| `benchmarks/workload/mcp_backend.py` | (pinned at freeze) |
| `benchmarks/workload/k6_workload.js` | (pinned at freeze) |
| `benchmarks/workload/gateway.workload.yaml` (template) | (pinned at freeze) |
| `benchmarks/workload/gateway.workload.mixed.yaml` (template) | (pinned at freeze) |
| `<run>/config/gateway.workload.yaml` (rendered) | (pinned at first rep) |
| `<run>/config/gateway.workload.mixed.yaml` (rendered) | (pinned at first rep) |
| k6 image digest | (pinned at freeze) |
| cell A checkout SHA | (pinned at freeze) |
| cell B checkout SHA | (pinned at freeze) |
| cell C/D/E checkout SHA | (pinned at freeze) |

The runner writes the per-cell checkout SHAs, health versions and k6 digest
into `pins.json` in the run directory, and the evaluator voids the run if any
pin is empty or if any rep disagrees with it.

