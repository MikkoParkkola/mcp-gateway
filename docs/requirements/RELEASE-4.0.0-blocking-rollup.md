<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release readiness — what the 38 blocking criteria actually are

The ledger (`RELEASE-4.0.0-criteria-status.md`) reports 95 criteria, 99 rows, 61 met or
non-blocking, 38 blocking. Thirty-eight is not thirty-eight decisions. The ledger's own
evidence cells say so — `NFR.SEC.2`, `.3`, `.4`, `NFR.OBS.4` and `NFR.PERF.3` all read
"same envelope", and `NFR.OBS.3` reads "verifies MIK-7217.DISCOVER.4-5". Grouping on those
clauses collapses the 38 into **six clusters and one residue**, of which four are unbuilt
mechanisms and two are measurements nobody has run.

This document exists so the shape of the remaining work survives outside one session's
context. It adds no verdicts: every row below is quoted from the ledger, and the ledger
stays the source of truth for status.

## The clusters

| # | cluster | rows | count | what is actually missing |
|---|---|---|---|---|
| A | MIK-7212 continuation envelope | `MRTR.1-8`, `MRTR.9`, `MRTR.10a`, `NFR.SEC.2`, `NFR.SEC.3`, `NFR.SEC.4`, `NFR.OBS.4`, `NFR.PERF.3` | 15 | nothing mints or opens a continuation on the live path. The type exists; no route reaches it |
| B | MIK-7217 era detection | `DISCOVER.4`, `DISCOVER.5`, `NFR.OBS.3` | 3 | `src/protocol/era.rs` is fully built and called from nothing. Design: `docs/design/2026-08-31-cluster-g-backend-era-detection.md` |
| C | MIK-7272 revision surface | `ORDER.2`, `SUB.2` (own-stream clause), `SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1` | 6 | five separate half-wirings: idempotency cache never enabled, extension set write-side absent, task methods advertised and not served, routing profile ignores modern mode |
| D | MIK-7213 response-cache keying | `CACHE.3`, `CACHE.4` | 2 | designed in `docs/design/2026-08-31-cluster-f-response-cache-keying.md`, zero tests, decision table not referenced from `cacheable.rs` |
| E | performance measurements | `NFR.PERF.1`, `NFR.PERF.2` | 2 | no run against 3.5.0 exists. A code read cannot substitute. **Spark only** — a Mac number is worse than no number |
| F | compatibility and surface facts | `NFR.COMPAT.1`, `NFR.COMPAT.3`, `NFR.COMPAT.4`, `NFR.PERF.4` | 4 | each is a stated fact awaiting an operator decision, not code: the modern revision is not in `SUPPORTED_VERSIONS`; `exposed_meta_tools` enforcement is breaking; no dual-role matrix; the 17-tool scenario exceeds the documented 14-16 ceiling |
| — | residue | `HEADER.9`, `CONTROL.4`, `CONFIRM.2`, `NFR.SEC.1`, `NFR.SEC.6`, `NFR.OBS.5` | 6 | genuinely independent; see below |

Fifteen of the thirty-eight are cluster A. Wire the continuation envelope and the blocking
count drops to twenty-three without a single new decision being made — though each of the
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
- `NFR.OBS.5` — the flag exists, defaults off and is read on the live path; the revertibility
  half is what is unproven.

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

Ten commits on `mcp-2026-protocol` are unpushed. `hooks/PreToolUse/ratification-gate.py`
hard-blocks `git push` without a ratification stamp, and only a human running `ratify` in a
terminal mints one. Until then this branch is unbacked work on one disk: a disk failure loses
it, and nobody can review what they cannot fetch. Closing criteria does not move this.

The accumulated diff also carries new production emission code
(`src/gateway/router/handlers.rs`, commit `da18b0d3`) that has not been through the
dual-vendor gate. Commit is not merge, so nothing is violated yet — the review is due before
push, and its material is the diff, not the design documents.
