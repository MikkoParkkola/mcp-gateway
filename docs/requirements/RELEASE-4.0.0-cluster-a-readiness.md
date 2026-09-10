<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Cluster A (MIK-7212 continuation envelope) — what is actually missing

Owner: `surface-a`. Written 2026-09-01, at `ce87436b`. Adds no verdicts: every status below is
quoted from `RELEASE-4.0.0-criteria-status.md`, which stays the source of truth. One correction to
that ledger is proposed at the end, with its evidence.

Fifteen rows: `MRTR.1`-`MRTR.8`, `MRTR.9`, `MRTR.10a`, `NFR.SEC.2`, `NFR.SEC.3`, `NFR.SEC.4`,
`NFR.OBS.4`, `NFR.PERF.3`.

## Design coverage: 12 of 15. Three rows have no design and cannot go green off what exists.

Two committed §P1 designs already cover most of the cluster, so no third was written for what they
already decide (H1/H2/H3 — SEARCH FIRST / UPDATE>CREATE / CONSOLIDATE).

| doc under `docs/design/` | rows it decides |
|---|---|
| `2026-08-30-mrtr-wiring.md` | `MRTR.1`, `MRTR.2`, `MRTR.3`, `MRTR.4`, `MRTR.8`, `MRTR.9` |
| `2026-08-30-shared-continuation-state.md` | `MRTR.5`, `MRTR.6` (fail-explicitly arm only) |
| `2026-08-31-sub-4-idempotency-wiring.md` | `MRTR.10a` — **cluster B's document, not mine** |
| — | `NFR.SEC.2`, `NFR.SEC.3`, `NFR.SEC.4` — decided by the two designs above, not separately named |
| **none** | **`MRTR.7`, `NFR.OBS.4`, `NFR.PERF.3`** |

The substantive parts of `mrtr-wiring` are the two `principal_fingerprint` definitions
(domain-separated, scheme-tagged; an anonymous caller gets no fingerprint, so an interim result is
refused rather than minted) and DE-2's per-request capability source. `shared-continuation-state`
carries `MRTR.6` only as far as the *fail-explicitly* arm; its forwarding half is a DEFERRED open
question with all four §P1 fields already present (owner = the MRTR.6 forwarding increment; resolved
by reading `src/idempotency.rs`; at the first line of the forwarder; if it resolves badly, forwarding
is dropped and `MRTR.6` is met by refusal alone). Cite it, do not re-derive it.

### The three uncovered rows

- **`MRTR.7`** (modern backend `InputRequiredResult` + legacy client → gateway issues an equivalent
  server-initiated request). No design exists: `rg -l 'to_legacy_client|Bridge::' docs/` returns
  nothing, `mrtr-wiring` says each bridge direction gets its own design, and
  `RELEASE-4.0.0-test-plan.md:352` says the same. Its hard constraint is already recorded as DE-4 in
  `mrtr-wiring`: **a stdio caller cannot be asked for more input**, which is precisely what an
  `MRTR.7` design has to resolve. A fourth document is the correct output here — the opposite of the
  cluster C situation, where a fifth would have been a duplicate. Scoped, not written: at the budget
  available this is a named next artifact.
- **`NFR.OBS.4`** (mint, redeem, expiry, rejection counted, with reason). No design, no counters. The
  surface to build on exists and needs no invention: `telemetry_metrics::counter!` behind the
  `metrics` Cargo feature, installed via `crate::metrics::install()` (see
  `src/gateway/meta_mcp/search.rs:753` for the in-tree idiom). What is missing is the name set and the
  reason cardinality — a paragraph, not a document.
- **`NFR.PERF.3`** (memory does not grow unboundedly with abandoned continuations; a soak with
  abandonment shows reclamation). No design, no soak. `InFlight::reap` and both capacity refusals
  exist in `src/protocol/continuation.rs` but nothing calls them on a live path, and no soak
  configuration observes them.
