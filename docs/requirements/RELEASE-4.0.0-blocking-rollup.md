<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release readiness — what the blocking criteria actually are

The ledger (`RELEASE-4.0.0-criteria-status.md`) reports 95 criteria, 99 rows, 62 met or
non-blocking, 37 blocking. That count is not that many decisions. The ledger's own
evidence cells say so — `NFR.SEC.2`, `.3`, `.4`, `NFR.OBS.4` and `NFR.PERF.3` all read
"same envelope", and `NFR.OBS.3` reads "verifies MIK-7217.DISCOVER.4-5". Grouping on those
clauses collapses them into **six clusters and one residue**, of which four are unbuilt
mechanisms and two are measurements nobody has run.

This document exists so the shape of the remaining work survives outside one session's
context. It adds no verdicts: every row below is quoted from the ledger, and the ledger
stays the source of truth for status.

## The clusters

| # | cluster | rows | count | what is actually missing |
|---|---|---|---|---|
| A | MIK-7212 continuation envelope | `MRTR.1-8`, `MRTR.9`, `MRTR.10a`, `NFR.SEC.2`, `NFR.SEC.3`, `NFR.SEC.4`, `NFR.OBS.4`, `NFR.PERF.3` | 15 | nothing mints or opens a continuation on the live path. The type exists; no route reaches it |
| B | MIK-7217 era detection | `DISCOVER.4`, `DISCOVER.5`, `NFR.OBS.3` | 3 | `src/protocol/era.rs` is fully built and called from nothing. Design: `docs/design/2026-08-31-discover-outbound-era-probe.md` |
| C | MIK-7272 revision surface | `ORDER.2`, `SUB.2` (own-stream clause), `SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1` | 6 | five separate half-wirings: idempotency cache never enabled, extension set write-side absent, task methods advertised and not served, routing profile ignores modern mode |
| D | MIK-7213 response-cache keying | `CACHE.3`, `CACHE.4` | 2 | designed in `docs/design/2026-08-31-cluster-f-response-cache-keying.md`, zero tests, decision table not referenced from `cacheable.rs` |
| E | performance measurements | `NFR.PERF.1`, `NFR.PERF.2` | 2 | no run against 3.5.0 exists. A code read cannot substitute. **Spark only** — a Mac number is worse than no number |
| F | compatibility and surface facts | `NFR.COMPAT.1`, `NFR.COMPAT.3`, `NFR.COMPAT.4`, `NFR.PERF.4` | 4 | each is a stated fact awaiting an operator decision, not code: the modern revision is not in `SUPPORTED_VERSIONS`; `exposed_meta_tools` enforcement is breaking; no dual-role matrix; the 17-tool scenario exceeds the documented 14-16 ceiling |
| — | residue | `HEADER.9`, `CONTROL.4`, `CONFIRM.2`, `NFR.SEC.1`, `NFR.SEC.6` | 5 | genuinely independent; see below |

Fifteen of the thirty-seven are cluster A. Wire the continuation envelope and the blocking
count drops to twenty-two without a single new decision being made — though each of the
fifteen still needs its own evidence afterwards, exactly as the ledger says.

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
kept reopening was not analysis — it was that twelve of the thirty-seven blocking rows had no
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

The table above assigns an owner to all thirty-seven blocking rows, which reads as full
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
frozen scope declares adding it explicitly out. So the gateway can wire the continuation
envelope and the revision surface in full and never negotiate the revision that reaches them —
unwiredness moved one level up, where no criterion in cluster A or C would report it. Whoever
adds the version is a decision, not an analysis; it is not currently anyone's.
