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
| `mcp_continuation_expired_total` | any deadline observed, from either side | `detected` |
| `mcp_continuation_rejected_total` | any refusal that is not a deadline | `reason` |

`expired` and `rejected` were nearly split the other way, with a redeem-time expiry counted as
`rejected{reason="expired"}` and only the reaper incrementing `expired_total`. That is wrong in a
way worth recording, because it reads as the careful choice: a *stateless* continuation — an
envelope the gateway holds nothing for — is never reaped, so its expiry would be invisible to the
expiry counter entirely, and the two populations would be split across two counters by an accident
of storage rather than by what happened.

So one counter owns deadlines, labelled `detected=reaped` (nobody came back) or
`detected=presented` (came back too late). Those remain the two operational facts they always
were — the first is the abandonment rate `NFR.PERF.3` soaks for, the second a tuning signal for
the lifetime — and `expired` is not a member of the `reason` set, so no event is counted twice.

## The reason set is the refusal set, not one type's variants

The obvious source is `ContinuationError` (`src/protocol/continuation.rs:193`), whose variants
give `malformed`, `unknown_version`, `unknown_key`, `not_authentic`, `mint_budget_exhausted`,
`too_large`. Taking that as the closed set is the error: it is the vocabulary of *one function on
one path*, and the criterion says continuations are counted, not that one type's failures are.
Refusals that happen elsewhere and would go uncounted include the bridge's round, prompt-count and
aggregate-deadline limits (`docs/design/2026-09-01-mrtr7-legacy-client-bridge.md` §5), a missing
or undeclared client capability (§6 there), a delivery failure to the client, and a mint refused
for want of a principal fingerprint.

The reason label is therefore an enum owned by the continuation orchestration, incremented at the
one boundary every refusal passes through, with `ContinuationError` mapping into it rather than
defining it. A refusal site that cannot name its reason in that enum is a site the enum is missing,
which is a compile error and not a silent `other`.

## The payload stays out of the label

**The `u8` payloads of `UnknownVersion` and `UnknownKey` must not reach the label.** They are
attacker-chosen: a caller presenting crafted envelopes mints up to 256 distinct label values per
payload, on demand, from unauthenticated input. That is bounded — 512 series across the two
variants, not unbounded — and it is still a write into the metrics store driven by the network, for
no operator benefit, on a counter that would otherwise have single-digit cardinality.

The type already draws this line for the client: `client_message` collapses all variants to one
sentence, on the reasoning that reporting *which* key id or wire version was refused lets a caller
map the live keyring one probe at a time (`:214-218`). A metrics label is a weaker disclosure than
a response body — it is operator-facing — but it is the same probe with the same payload, and here
it costs series as well. The variant name carries everything an operator can act on; the payload
belongs in a log line at debug level, where retention is bounded and access is not the metrics
endpoint.

## What this does not decide

Whether the counters are also exported through the A2A adapter's metrics surface. Nothing in
`NFR.OBS.4` asks for it and no other counter in the tree does it, so the default is no; if that
turns out to be wrong it is an additive change to `install()`, not a rename.
