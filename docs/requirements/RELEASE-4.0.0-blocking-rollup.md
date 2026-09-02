<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release readiness — what the blocking criteria actually are

The ledger (`RELEASE-4.0.0-criteria-status.md`) carries the counts; run
`scripts/release/count-release-criteria.py --check` for them rather than reading a figure here.
Whatever the blocking count is on the day, it is not that many decisions. The ledger's own
evidence cells say so — `NFR.SEC.2`, `.3`, `.4`, `NFR.OBS.4` and `NFR.PERF.3` all read
"same envelope", and `NFR.OBS.3` reads "verifies MIK-7217.DISCOVER.4-5". Grouping on those
clauses collapses them into **seven clusters and one residue**, of which five are unbuilt
mechanisms and two are measurements nobody has run.

This document exists so the shape of the remaining work survives outside one session's
context. It adds no verdicts: every row below is quoted from the ledger, and the ledger
stays the source of truth for status.

## The clusters

| # | cluster | rows | count | what is actually missing |
|---|---|---|---|---|
| A | MIK-7212 continuation envelope | `MRTR.1-8`, `MRTR.9`, `MRTR.10a`, `NFR.SEC.2`, `NFR.SEC.3`, `NFR.SEC.4`, `NFR.OBS.4`, `NFR.PERF.3` | 22 | nothing mints or opens a continuation on the live path. The type exists; no route reaches it |
| B | MIK-7217 era detection | `DISCOVER.4`, `DISCOVER.5`, `NFR.OBS.3` | 5 | `src/protocol/era.rs` is fully built and called from nothing. Design: `docs/design/2026-08-31-discover-outbound-era-probe.md` |
| C | MIK-7272 revision surface | `ORDER.2`, `SUB.2` (own-stream clause), `SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1` | 7 | five separate half-wirings: idempotency cache never enabled, extension set write-side absent, task methods advertised and not served, routing profile ignores modern mode |
| D | MIK-7213 response-cache keying | `CACHE.4` | 2 | the two clause rows `CACHE.4a` (key missing routing profile and protocol revision) and `CACHE.4b` (no policy epoch), designed in `docs/design/2026-08-31-cluster-f-response-cache-keying.md`. `CACHE.3` was in this cluster until both its clauses were met: the decision table is now read by the emitting code |
| E | performance measurements | `NFR.PERF.1`, `NFR.PERF.2` | 2 | no run against 3.5.0 exists. A code read cannot substitute. **Spark only** — a Mac number is worse than no number |
| F | compatibility and surface facts | `NFR.COMPAT.1`, `NFR.COMPAT.4` | 2 | each is a stated fact awaiting an operator decision, not code: the modern revision is not in `SUPPORTED_VERSIONS`, and the dual-role matrix has never been run. `NFR.COMPAT.3` was in this cluster until the operator waived it on the record on 2026-09-02, which is why the count is two rather than three. `NFR.PERF.4` left it earlier and is now residue: affirming the 14-16 ceiling settled the number, not the mechanism that holds it. `NFR.PERF.4` was in this cluster until the 14-16 ceiling was affirmed and the 17th tool identified as `gateway_webhook_status` (`src/gateway/meta_mcp_tool_defs.rs:565`), which only appears when webhooks are enabled |
| G | stdio dispatch path | `NFR.OBS.1`, `NFR.OBS.2`, `MIK-7246.CONFIRM.1a` | 3 | both records live in the HTTP router (`src/gateway/router/handlers.rs:720,994`) and both criteria say *per request* / *every* `tools/list`. The stdio dispatcher reaches neither, so one of the two transports the gateway serves MCP over is absent from the migration telemetry. `MIK-7246.CONFIRM.1a` is the same shape and not telemetry: the destructive-confirmation gate is imported and called once, in that same HTTP router (`src/gateway/router/handlers.rs:28,1196`), so a destructive meta-tool invoked over stdio executes with no confirmation sought. One wiring question — what the stdio dispatcher must do before it reaches `handle_tools_call` — answers all three |
| — | residue | `HEADER.9`, `CONTROL.4`, `CONFIRM.2`, `NFR.SEC.1`, `NFR.SEC.6`, `NFR.PERF.4`, `MIK-6704.IDENT.1a`, `MIK-6865.SCHEMA.1c`, `MIK-7215.CONTROL.3a` | 10 | genuinely independent; see below |

Cluster A is by far the largest of them. Wiring the continuation envelope removes twenty-two
blocking rows without a single new decision being made — though each of the twenty-two still
needs its own evidence afterwards, exactly as the ledger says. The total it leaves behind is
not quoted here: `scripts/release/count-release-criteria.py --check` derives it, and this
document has already carried two counts that went stale against the ledger they describe.

The `rows` column names PARENT criteria; the `count` counts LEDGER ROWS, and the two stopped
matching once compound criteria began to be split. `MRTR.1-8` is eight names and nineteen rows.
Read the names as a key to which cluster a row belongs to, never as its size. The counts here
are derived from the ledger by prefix, not transcribed from a previous revision of this file:
every blocking row lands in exactly one cluster and the seven totals sum to the ledger's, which
is the only reason this table can be trusted to be complete. The last revision covered 37 of
the blocking rows and read as though it covered all of them.

## The residue, one line each

- `MIK-7214.HEADER.9` — `build_mcp_headers` is the single outbound builder; the criterion's
  header is not among what it emits.
- `MIK-7215.CONTROL.4` — `SessionLifecycle` is sound and tested against the real type; no
  production caller registers with it.
- `MIK-7246.CONFIRM.2` — the confirmation path is `elicitation/create` over SSE, a different
  mechanism from the one the criterion names.
- `NFR.SEC.1` — 14 controls enumerated in `docs/requirements/nfr-sec1-control-inventory.md`;
  nine carry a refusal test, five are recorded gaps. `each` is unmet until those five do.
- `NFR.SEC.6` — the sweep exists; the row is a traceability question across MIK-7222/7246/7256.
- `MIK-6704.IDENT.1a` — deriving authorization from the authenticated credential is implemented
  and consumed (`principal_of`, `src/gateway/auth.rs:38-43`) and nothing asserts it. All three
  IDENT.1 tests prove the negative clause, now scored separately as `IDENT.1b`. A test, not a
  mechanism.
- `MIK-6865.SCHEMA.1c` — see the ledger row; scored when `SCHEMA.1` was split.
- `MIK-7215.CONTROL.3a` — scored blocking when `CONTROL.3` was split; the clause it carries is
  not held by the parent's evidence.

## The four decisions this reduces to

Everything above is engineering except these. They are operator calls, and no amount of
test-writing settles them.

1. **Does 4.0.0 ship the continuation envelope wired, or ship without it?** Fifteen criteria
   hang on the answer. `SUPPORTED_VERSIONS` does not name the 2026 revision, so an unwired
   envelope is consistent with the protocol the gateway actually serves.
2. **Does 4.0.0 ship era detection wired, or detect-only?** The design already resolved that
   the gateway detects and does not speak the modern revision outbound. Wiring the detector is
   still a separate yes.
3. **Is `exposed_meta_tools` enforcement acceptable as a breaking change?** Our own release
   notes call it breaking for operators who set the field. `NFR.COMPAT.3` forbids exactly that.
   Either the enforcement is reverted, or the criterion is amended with the operator's consent.
4. **Do the performance numbers gate the release?** `NFR.PERF.2` states its own consequence:
   without a number the change does not ship. That is a Spark job, not a decision — but
   whether it blocks is.

## The release blocker that is not a criterion

`mcp-2026-protocol` carries unpushed commits — `git rev-list --count HEAD --not --remotes`
is the count, and it is not written down here because it only ever grows and this document
said `Ten` until it had reached thirty-one. `hooks/PreToolUse/ratification-gate.py`
hard-blocks `git push` without a ratification stamp, and only a human running `ratify` in a
terminal mints one. Until then this branch is unbacked work on one disk: a disk failure loses
it, and nobody can review what they cannot fetch. Closing criteria does not move this.

The accumulated diff also carries new production emission code
(`src/gateway/router/handlers.rs`, commit `da18b0d3`) that has not been through the
dual-vendor gate. Commit is not merge, so nothing is violated yet — the review is due before
push, and its material is the diff, not the design documents.

## Who owns what, 2026-09-01

The clusters above describe the work. This section says who is doing it, because the gap that
kept reopening was not analysis — it was that twelve of the blocking rows had no
owner, and unowned work does not fail loudly. It simply never starts.

| cluster | rows | owner |
|---|---|---|
| A continuation envelope | 15 | `envelope-a`, design first. **Was assigned to a concurrent session on commit archaeology and that was wrong** — `src/protocol/continuation.rs` has not moved in 16 hours and the last substantive cluster-A commit is `149e553a`, 24 hours old. The largest cluster was unowned while this table said otherwise. |
| B era detection | 3 | `era-r4-repair` owns `src/protocol/era.rs`; `era-probe` owns `tests/mik_7217_era_probe_acs.rs`, held |
| C MIK-7272 revision surface | 6 | `surface-c`, design first |
| D response-cache keying | 2 | `cache-34` |
| E performance vs 3.5.0 | 2 | `perf-e`, Spark only |
| F compat and surface facts | 4 | the operator; three of the four are settled by "full scope", `NFR.COMPAT.3` is not |
| — residue | 5 | `residue-r` takes four; `HEADER.9` belongs to the header increment |

One ownership rule makes the rest work: **one owner per file**. `src/protocol/era.rs`,
`src/protocol/cacheable.rs` and `src/protocol/continuation.rs` each have exactly one, and a
design that needs something from another owner's file is routed rather than edited. This is not
politeness. A shared checkout with concurrent sessions has already produced one near-miss where
a full-file write would have replaced 583 lines of a live document with 209.

### What the operator still has to decide

Three of the four decisions this document listed are settled by the instruction to close the
full scope: wire the continuation envelope, wire era detection, run the performance numbers.
The fourth is not, because both of its answers are "fix the gap":

`NFR.COMPAT.3` forbids requiring an operator to edit configuration for existing behaviour to
continue. `meta_mcp.exposed_meta_tools` was documented as an allow-list and had no effect
outside tests; GH issue 449 made it real, and `gateway_search`/`gateway_execute` — previously
reaching every backend tool regardless of the list — are now restricted by it. Either the
enforcement ships and the criterion is amended in the open, or the enforcement is reverted and
the gateway keeps shipping a field that claims a restriction it does not apply. **Amending a
criterion needs the operator's recorded agreement and has not been given**, so the row stays
blocking and is not to be closed by reinterpretation.

### The count is checked, not asserted

`scripts/release/count-release-criteria.py --check` recounts the blocking column of every table
in `RELEASE-4.0.0-criteria-status.md` and exits non-zero on disagreement. Quote it from there or
run it; do not restate it. A hand-copied figure beside a machine-checked one has already drifted
four times, most recently as a `31 blocking` that was written against a 77-row ledger and was
still being read at 99 rows.

### Still true, and not moved by any of the above

The branch is unpushed, by the count above. Every criterion in the table could go green
without changing that, and the dual-vendor review still owes its pass on the accumulated
production diff before a push is attempted.

### The two gates that are not rows, and the file two owners share

The table above assigns an owner to every blocking row, which reads as full
coverage and is not. Two things gate the release and appear in no row, so nothing goes green
when they are skipped:

| gate | owner | why it is not a row |
|---|---|---|
| dual-vendor review of the accumulated production diff | this session, by default | its material is the diff, not any design document; every cluster could pass its own review and this would still be owed |
| `ratify`, then the push | **the operator, at a terminal** | a ratification stamp is minted by a human running `ratify`; no agent can produce one |

The second is the shortest item on the whole list and the only one nobody else can do. Thirty-one
commits are unbacked work until it happens: they exist on one disk, no reviewer can fetch them,
and a disk failure loses them without trace.

One file has two owners, and the ownership rule above did not catch it. The direct route
`POST /mcp/{name}` bypasses `invoke_tool_traced` (`src/gateway/backend_handlers.rs:724`) and
keeps no per-user cache (`:594`). `CACHE.4` binds "any shared cache the gateway keeps" and
`OTEL.1` binds tracing "across the gateway hop" — the same call site, split across cluster C and
cluster D. Both owners have been told. The seam goes to one of them and the other consumes it;
a call site owned half by tracing and half by caching is the coupling that produces the next
defect.

`NFR.COMPAT.1` is listed under cluster F as an operator fact, and it is also a dependency the
other two wirings run on. `SUPPORTED_VERSIONS` (`src/protocol/mod.rs:43`) does not name
`2026-07-28`; `MODERN_VERSIONS` (`src/protocol/meta.rs:219`) names it alone, and era-r4-repair's
frozen scope declares adding it explicitly out.

An earlier revision of this paragraph read that as a gap: wire both clusters, never negotiate
the revision, unwiredness moved one level up. That is wrong, and the correction matters more
than the claim did. The omission is deliberate and documented at the source
(`src/protocol/mod.rs:38-42`): listing `2026-07-28` in `SUPPORTED_VERSIONS` would make
`initialize` negotiate a revision the gateway cannot yet serve, so a client would be told yes
and then served 2025 semantics — silent, and worse than a refusal. `meta.rs:213-219` says the
same from the other side, and `discover_document` (`src/gateway/meta_mcp/mod.rs:1063-1082`)
already advertises `MODERN_VERSIONS` when the modern path is enabled, with a comment recording
that omitting it once made enabling it unreachable. era-r4-repair was right to scope the
addition out; the surface is not missing a version, it is gated.

The gate is `server.modern_protocol`, and it defaults to **false** (`src/config/mod.rs:1127`,
`:1174`, whose comment reads *"Off until the revision is served completely, not partly."*), read
at `src/gateway/router/handlers.rs:221`, `:755-760`, `:967`. So the real question is not who adds
a string to a list. It is whether 4.0.0 flips that default — see operator decision 5.

### One commit must not be handed to a reviewer whole

`ce72a5ba` contains 51 lines of this file that its author did not write: a `git add -A` on a
shared branch swept in another session's work while that session was mid-edit. The content is
intact and was superseded two commits later, so nothing was lost and the branch was correctly
not rewritten — rewriting shared history to repair an attribution line damages more than it
fixes. But the commit is now unsafe as review material: a reviewer handed `git show ce72a5ba`
spends findings on a document its author cannot defend, and that round does not come back.

When the cluster-D review is called, scope its material to `src/cache.rs`,
`src/gateway/meta_mcp/invoke.rs`, `tests/mik_7213_acs.rs` and the cluster's own doc sites.
The general rule this is an instance of: on a branch with concurrent sessions, stage explicit
paths. `git add -A` is a claim about the whole tree, and on a shared tree that claim is false.

### Two more operator decisions, surfaced from the residue

The four decisions above were derived from the clusters. The residue rows carry two
more, and neither is settled by "close the full scope" — both answers to each are a
defensible release.

`MIK-7215.CONTROL.4` is not blocked on ownership. `SessionLifecycle::register` takes a
closure, so registration lives at gateway startup and needs no edit to a firewall file.
It is blocked on a decision nobody has made: the module replaced the disconnect trigger
the modern revision deleted with a `track`/`reap` deadline, and nothing has chosen
**who calls the reaper** or **what the TTL is**. The TTL is an operator-visible retention
number, not an implementation detail. Wiring `register` alone would leave handlers that
are registered and never fire — indistinguishable from today except that the criterion
would read as met. That is the worst available outcome and it was correctly not built.

`MIK-7246.CONFIRM.2` names a confirmation mechanism; what exists is `elicitation/create`
over SSE, a different mechanism reaching the same outcome. Both readings are consistent
with everything in the tree, so no amount of reading code settles it. It is also
downstream of cluster A: even under the generous reading, reachability depends on the
continuation-envelope wiring, so it cannot close before A does and is not an independent
item on the critical path.

### A fifth decision, from correcting the fourth

The `NFR.COMPAT.1` paragraph above was published wrong and is now repaired. What the repair
exposes is a decision that no cluster surfaced, because no criterion is phrased to ask it:
**does 4.0.0 ship with `server.modern_protocol` defaulting to false?**

Both answers are defensible and neither is an analysis result.

| answer | what it costs |
|---|---|
| leave it false | 4.0.0 ships the modern revision behind an opt-in flag. Every cluster A and C row can be met and no default install exercises them. The release notes must say so plainly, or the version number overpromises. |
| flip it true | the default install negotiates `2026-07-28`. That is only honest once the modern path is served completely — which is exactly what clusters A and C are for, so the flip is a release-gating dependency on them, not an independent switch. |

The flag is not a gap and needs no ticket. It needs a sentence in the release notes under the
first answer, and a gating dependency under the second.

### One row that looked like a decision and is not

`NFR.SEC.1` row 5, the per-client circuit breaker, was flagged as arguably N/A on the
grounds that it refuses on a trip count rather than an absent input. The criterion asks
each control for a refusal test, and a circuit breaker has a perfectly ordinary one:
trip it, then be refused. `record_client_failure` (`src/gateway/auth.rs:292`) and
`check_client_circuit_breaker` (`:272`) are both public and `failure_threshold` is a
config field, so the test is short. Writing it closes the row without narrowing a
security criterion's population — which is the more expensive mistake of the two, and
the one that needs an operator's recorded agreement.
