<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# NFR.OBS.4 — continuation counters: the name set and the reason cardinality

`NFR.OBS.4` (`docs/requirements/RELEASE-4.0.0-requirements.md:242`), verbatim: *"Continuation
mint, redeem, expiry and rejection MUST be counted, with reason."*

Cluster A's readiness report calls this "a paragraph, not a document" — the emitting surface
needs no invention. `telemetry_metrics::counter!` is already the in-tree idiom
(`src/gateway/meta_mcp/search.rs:753`), installed by `crate::metrics::install()`
(`src/metrics.rs:23`), behind the `metrics` Cargo feature. What is genuinely undecided is the
name set and what may appear in a label, and one of those two has a security answer.

## Four counters, because the criterion names four events

| counter | incremented where | labels |
|---|---|---|
| `mcp_continuation_mint_total` | a successful mint returns an envelope | none |
| `mcp_continuation_redeem_total` | an envelope verifies and is accepted | none |
| `mcp_continuation_expired_total` | `InFlight::reap` drops an entry nobody returned for | none |
| `mcp_continuation_rejected_total` | any `Err(ContinuationError)` on the redeem path | `reason` |

`expired` and `rejected` both cover deadlines and are deliberately not merged. An envelope
presented after its deadline is a client that came back too late; an entry reaped without ever
being presented is a client that never came back at all. Those are different operational facts —
the first is a tuning signal for the lifetime, the second is the abandonment rate `NFR.PERF.3`
soaks for — and the criterion lists them separately for that reason. A redeem-time `Expired`
increments `rejected{reason="expired"}`; the reaper increments `expired_total`.

## The reason label is the variant name, and nothing else

Seven values, closed, from `ContinuationError` (`src/protocol/continuation.rs:193`):
`malformed`, `unknown_version`, `unknown_key`, `not_authentic`, `expired`,
`mint_budget_exhausted`, `too_large`.

**The `u8` payloads of `UnknownVersion` and `UnknownKey` must not reach the label.** They are
attacker-chosen: a caller who presents crafted envelopes mints up to 256 distinct label values
per counter, on demand, from unauthenticated input. That is an unbounded-cardinality write into
the metrics store from the network — a memory-growth path with no refusal in front of it, which
is the exact failure mode `NFR.PERF.3` exists to prevent one level down.

The type already draws this line for the client: `client_message` collapses all seven variants to
one sentence, on the reasoning that reporting *which* key id or wire version was refused lets a
caller map the live keyring one probe at a time (`:214-218`). A metrics label is a weaker
disclosure than a response body — it is operator-facing — but it is the same probe with the same
payload, and here it costs unbounded cardinality as well. The variant name carries everything an
operator can act on; the payload belongs in a log line at debug level, where retention is bounded
and access is not the metrics endpoint.

## What this does not decide

Whether the counters are also exported through the A2A adapter's metrics surface. Nothing in
`NFR.OBS.4` asks for it and no other counter in the tree does it, so the default is no; if that
turns out to be wrong it is an additive change to `install()`, not a rename.
