<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release: gap assessment and plan to shippable

Assessed 2026-08-30 by four independent audits (requirements-vs-code, unwired production paths,
test-plan coverage, docs and release mechanics). Every gap below was verified by reading source,
never inferred from a document. The requirements sweep was still running when this was written;
its remaining batches amend section 1, they do not invalidate the sequence.

A second audit died on an output ceiling partway through emitting its rows. What
it had produced is recovered in `RELEASE-4.0.0-audit-partial.md` and is a floor
on the blocking count, not a total: at least eight of its findings sit outside
MRTR entirely, which is the first measured evidence of how far section 2 is
undersized.

## 1. Where the release actually stands

The 2026 protocol surface is **advertised but not reachable**. `discover_document` announces
`MODERN_VERSIONS` once `modern_protocol=true`, and the retry that the announcement invites is
refused at the door.

| gap | evidence | blocks |
|---|---|---|
| MRTR is unwired end to end | `handlers.rs:873-889` returns -32602 "retry forwarding is not available on this build" for every retry | MRTR.1-.10 |
| No production owner for continuation state | `Keyring`/`ConsumedLedger`/`InFlight` have zero non-test constructors; `AppState` holds no field for any of them | MRTR.5, MRTR.6 |
| Legacy-client bridge never called | `Bridge::to_legacy_client` has no caller | MRTR.7 |
| Outbound era probing unwired | `EraCache::resolve_with`/`classify` implemented and tested, zero callers in `src/backend` or `src/transport` | outbound modern/legacy negotiation |
| Tasks extension is dead code | `protocol::tasks::Task`/`TaskStatus` have no production call site; `tasks/get`/`tasks/update` fall through to method-not-found honestly | nothing — needs a keep/delete decision |
| Header/result/error/cache/order criteria | six gaps found, six criteria confirmed clean | see requirements sweep |
| Blocking criteria outside MRTR | at least eight, in tenancy, stateless confirmation, session expiry, log correlation, cache invalidation, error codes, tasks and extensions | see `RELEASE-4.0.0-audit-partial.md` |
| Diff coverage under floor | 61 branch-touched files average 77.40% lines against an 80% Standard floor; mutation coverage unmeasured | DoD §4 |

Test position, separately: six acceptance criteria have no case at any level, two cases cannot fail
against the defect they are attached to, and the existing `tests/mik_7212_acs.rs` exercises
primitives directly rather than the dispatcher — so it stays green whatever the wiring does. The
test plan says this itself at lines 327-330.

## 2. The sequence

Each increment is independently reviewable and mergeable. Delivery order within every increment is
the standing one: failing tests first, then implementation, then dual-vendor review.

**1 — Continuation state has one owner (S).** Closes MIK-7312, unblocks everything after it.
Add keyring, consumed-ledger and in-flight fields to `AppState` as a single owner with one
lifecycle; construct per process at startup; generate key material per process and never share it.
Tests: construction through the production path, and a second `AppState` refusing the first's token
(the current test builds two `Keyring`s by hand and proves only AES key separation).

**2a — The mint site can see who is calling (S).** No behaviour, so no new tests: the existing
suite is the safety net and a green run before and after is the evidence. `invoke_tool_traced`
takes `caller: &MetaMcpCallerContext<'_>` in place of its six flattened caller fields, and the
client's declared capabilities reach the scope where that context is built. Two source facts make
this mechanical rather than a design question: `invoke_tool` already takes the context whole, and
the comment at `invoke.rs:419-421` gives the reason in the codebase's own words — the authorizer
travels with the identity it authorizes. `invoke_tool_traced` is private with exactly one call
site. The alternative, two more loose parameters taking it from eleven to thirteen, is rejected by
that same comment.

**2b — Retry reaches the backend (M).** Closes MRTR.1, .2, .3, .9. Delete the `is_retry` arm at
`handlers.rs:872-889` and leave the malformed-envelope arm above it alone; open the envelope, forward
retry fields to the backend as siblings of `arguments` rather than merged into them, mint at the
call site after the result, pass `complete` and legacy results through unchanged. Inbound
`RetryFields` is attacker-controlled client shape and the outbound state is the backend's own
opaque value recovered from the token — conflating the two is the MRTR.2 defect, so they stay
separate types. One defect drives the increment: an `input_required` result is today neither a
success nor an error, so it falls through the `mark_completed` at `invoke.rs:1276` and is cached as
a final answer. Tests: the integration rows the plan already names, plus a pass-through row and a
fresh-JSON-RPC-id row that a fixture transport can fail. Pass-through asserts value equality and
that no `requestState` key was added, not byte identity — the crate does not preserve key order.

**3 — Single-use and expiry hold across replicas (S).** Closes MRTR.5. Origin refusal precedes any
key lookup; typed and distinct from expired and already-spent. Tests: expiry on redeem with an
injected clock, two `AppState`s racing one token, redeem after the minting process is replaced.

**4 — No second exchange with a legacy backend (M).** Closes MRTR.6. Pin the continuation to a live
`InFlight` hold where the mint recorded one; a missing hold is a refusal. Tests: minted against a
live hold, redeemed on the origin after the hold is gone.

**5 — Legacy-client bridge (M).** Closes MRTR.7 — currently `NOT YET` by design with no test row at
all. Wire `Bridge::to_legacy_client`; decide and record what a legacy client sees when a modern
backend asks. Tests: the whole row set, which does not exist yet.

**6 — Outbound era negotiation (M).** Wire `EraCache` into backend connection setup so outbound
calls probe rather than assuming legacy. Not previously tracked; found by the wiring audit.

**7 — Request binding and per-scheme fingerprint (S).** Closes MRTR.4 properly: same tool with
different arguments is refused, and the fingerprint distinguishes API key, agent JWT and mTLS
callers. The current binding test is generic and one row cannot fail against a short-circuiting
comparison, by its own comment.

**8 — Tasks extension decision (S).** Keep as a documented placeholder or delete. A design event,
not a wiring fix — it needs an owner's call, not an implementation.

**9 — Gate and release mechanics (S).** Raise diff coverage over the 80% floor on branch-touched
files, run mutation coverage and record it, reconcile the three disagreeing clippy invocations
across docs and CI, and add a local guard for the npm version rather than relying on the publish
step to overwrite it. Rewrite `docs/DEPLOYMENT.md:125-142`, and put the two operational
consequences in the release notes: a retry against a round-robin service is refused on every
replica but the minting one, and a rolling restart invalidates every outstanding continuation.

## 3. Not blocking the release

- Stale npm version in `npm/package.json:3` — CI syncs it at publish; the guard is hygiene.
- Homebrew formula staleness — `release.yml` regenerates it in the tap repo.
- Clippy invocation drift — cosmetic until a gate disagreement actually lets something through.
