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
| `mcp_continuation_redeem_total` | an envelope verifies **and** is accepted | none |
| `mcp_continuation_expired_total` | any deadline observed, from either side | `detected`, `phase` |
| `mcp_continuation_rejected_total` | any refusal that is not a deadline | `reason`, `phase` |

`redeem_total` counts **acceptances, not attempts**. A rejected redemption is already an
increment of `rejected_total`, so counting attempts here would double-count every refusal and
make `redeem_total` unusable as a success count. Attempts are recoverable as
`redeem_total + rejected_total{phase="redeem"}` — the sum is the derived quantity, not the
primitive, because the reverse decomposition is not available from an attempt counter alone.

`expired` and `rejected` were nearly split the other way, with a redeem-time expiry counted as
`rejected{reason="expired"}` and only the reaper incrementing `expired_total`. That is wrong in a
way worth recording, because it reads as the careful choice: a *stateless* continuation — an
envelope the gateway holds nothing for — is never reaped, so its expiry would be invisible to the
expiry counter entirely, and the two populations would be split across two counters by an accident
of storage rather than by what happened.

So one counter owns deadlines, and `detected` names **who noticed** — which is the only thing that
distinguishes one expiry from another once the deadline itself is the event.

| `detected` | who noticed | phase it arises in |
|---|---|---|
| `reaped` | a reclaimer, sweeping entries nobody came back for | `redeem` |
| `presented` | the envelope itself, arriving after its deadline | `redeem` |
| `awaited` | the gateway, waiting on a round it had already started | `bridge` |

`reaped` is the abandonment rate `NFR.PERF.3` soaks for; `presented` is a tuning signal for the
lifetime; `awaited` is a bridged prompt whose per-prompt or aggregate deadline (`MRTR.7` §5) passed
while the gateway held the round open. `expired` is not a member of the `reason` set, so no event
is counted twice.

The third value exists because `phase` and the stateful narrowing below would otherwise leave
`expired_total{phase="bridge"}` with no legal `detected`: a bridge deadline is not reaped (there is
no entry and no reaper) and not presented (nothing arrived at all), and an implementer forced to
pick one would make the deadline series incomparable across phases. Note the observer, not the
phase, is what `detected` reports — the two columns above agree today and are not required to.

**`detected=reaped` is defined only over stateful continuations, and that bound is structural.**
A reaper can only observe what something holds. A stateless continuation — an envelope the gateway
keeps no entry for — is abandoned by a caller simply never returning, and there is nothing in the
process that could notice: no timer, no entry, no event. This is not a gap to be closed later; it
is what stateless means. `detected=presented` has no such bound, because a late presentation
arrives on the wire either way.

Two consequences, stated so neither is read as a defect. First, `reaped` is an abandonment count
for the stateful population *only*, and the stateless abandonment rate is unobservable by
construction — an operator reading `reaped` as the total is reading a subset. Second,
`NFR.PERF.3`'s soak measures the stateful population only, which is the correct scope for it: the
criterion is about memory not growing with abandoned continuations, and a continuation the gateway
stores nothing for consumes no memory to reclaim. The unobservable population is exactly the
population that cannot leak.

## `phase` separates a forgery from a person saying no

`reason` alone is not enough to read a rejection graph, and the gap is a security one. The
`MRTR.7` bridge (`docs/design/2026-09-01-mrtr7-legacy-client-bridge.md` §5) refuses a round when a
client declines a prompt, exceeds a round budget, or lacks a capability. Those are **ordinary user
and policy outcomes**. `not_authentic` and `unknown_key` at redeem time are **attacker signal** — a
caller presenting an envelope this gateway did not mint. Sharing one counter puts both on the same
line, so an alert on a rejection spike fires when a group of users happens to decline prompts, and
the alert an operator would actually want — forged envelopes — is diluted by whatever the largest
benign population happens to be that day.

The `phase` label carries `mint`, `redeem` or `bridge`, and it is the axis a rejection alert is
written against, not `reason`. In the `MRTR.7` direction it also removes a category error:
**no continuation is ever minted to the legacy client**, because the client is the party being
asked. A bridge refusal is therefore not a refused continuation at all in the envelope sense; it
shares the counter because it is still a refusal in the continuation orchestration, and `phase` is
what keeps it from being read as one.

The same label is on `expired_total`, for the same reason and at no extra cost: a bridge round
timing out and a stored continuation aging out are different operational facts.

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

## Trust boundary and threats

Recorded because DoR `C15` and `C6` ask for it. The same note applies as in
`2026-09-01-mrtr7-legacy-client-bridge.md`: the accepted sibling designs in this family carry
neither section, so this is a family-wide gap being closed forward rather than one introduced here.

**C15.** The metrics surface is `auth-user` at best and frequently `unauth` on a private network —
a Prometheus scrape endpoint is not an authenticated API in most deployments, which is why the
payload rule above is a security rule and not a tidiness one. Data locality: `local`; counters live
in-process and are read by whoever scrapes. Partition behaviour: `AP` — telemetry is best-effort by
construction, and a counter that cannot be incremented never fails the operation it was counting.

**C6.** The surface is small: *unauthenticated input decides what gets written into a metrics store*.

| | threat here | mitigation |
|---|---|---|
| **S** | — | no identity is asserted on this path; counters name events, never principals |
| **T** | a caller steers label *values* to pollute a dashboard | the `reason` and `phase` sets are closed enums owned by the orchestration; attacker-chosen `u8` payloads never reach a label |
| **R** | — | counters are the repudiation control for other paths, not a target of one |
| **I** | label cardinality leaks which key ids or wire versions the keyring holds, one probe at a time | the same disclosure the type already refuses in `client_message` (`continuation.rs:214-218`); the variant name is exported, the payload is not |
| **D** | cardinality explosion as a memory-exhaustion vector | bounded by construction — the label sets are enums, so the series count is a compile-time product, not a function of traffic |
| **E** | — | no authorisation decision reads a counter |

## The label schema's stability expectation

**Counter names and label *keys* are a compatibility surface; label *values* are not.** A dashboard
or alert written against `mcp_continuation_rejected_total{phase="redeem"}` must keep working, so
renaming a counter or dropping a label key is a breaking change and goes through the ordinary
deprecation path. The `reason` set, by contrast, is expected to grow — §"the reason set is the
refusal set" makes a new refusal site a compile error precisely so that new values appear, and a
consumer that enumerates `reason` values exhaustively is relying on something this design says will
change. Aggregate over `reason`, alert on `phase`.
