<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# Design — wiring the outbound era probe (MIK-7217 DISCOVER.4, DISCOVER.5)

Status: proposed · Revision: 2 · Date: 2026-08-31
Tracking: MIK-7217 · Criteria: `docs/requirements/RELEASE-4.0.0-criteria-status.md:178-193`

## §P0 Scope

**FOR:** making the gateway learn a *backend's* protocol era by probing it, and caching that
answer per backend — so DISCOVER.4 and DISCOVER.5 stop being UNWIRED. Both transports.

**OUT:**

- the modern outbound request path (`_meta` envelopes, modern framing). That is
  MIK-7214.HEADER.9, currently ABSENT and blocking; this design builds nothing on it and,
  as of revision 2, reserves nothing for it either.
- adding `2026-07-28` to `SUPPORTED_VERSIONS`. `src/protocol/mod.rs:38-42` states plainly the
  revision is absent "until the modern request path exists… It is added in the increment that
  makes it true." This is not that increment.
- A2A backends — `src/backend/lifecycle.rs:372-383` refuses them on this path outright ("must be
  started via A2aProvider, not the legacy Backend::start() path").
- the `src/lib.rs:23` `2024-10-07` doc residual noted under DISCOVER.7. One-line doc fix,
  unrelated mechanism, does not travel with this change.

Revision 2 **narrowed nothing and widened one thing**: stdio moved from OUT to FOR. Recorded here
because §P0 freezes scope at first dual review and a move needs a stated reason — the reason is in
constraint 2, and it is a consequence of the revision-2 repair rather than a new appetite.

## Problem

Seven criteria carry the `MIK-7217.DISCOVER` prefix. Four are MET, one MET with a residual, and
two are UNWIRED — and the two UNWIRED ones are the entire outbound half:

| criterion | verdict | what it asks |
|---|---|---|
| DISCOVER.1 | MET (caveat) | server answers `server/discover` with a complete document |
| DISCOVER.2 | MET | answerable before `initialize`, without a session |
| DISCOVER.3 | MET | `initialize` result unchanged for a 2025 client |
| **DISCOVER.4** | **UNWIRED** | **gateway MUST detect a backend's era by probing, not by trusting a version string** |
| **DISCOVER.5** | **UNWIRED** | **detected era MUST be cached per backend and re-probed when a cached assumption fails** |
| DISCOVER.6 | MET | slow backend retried on a pinned schedule |
| DISCOVER.7 | MET (residual) | `2024-10-07` absent from advertised version lists |

The detector for DISCOVER.4 is complete, adversarially reviewed and heavily unit-tested at
`src/protocol/era.rs`. Nothing calls it. Stronger than uncalled: **no outbound `server/discover`
request is constructed anywhere in `src/`** — there is no sender to wire it to. The criteria file
files this under the shape already logged for EXT.1, OTEL.1 and TASK.1: built, tested, unreachable.

What the MET rows constrain, and this design must not break:

- **DISCOVER.1's caveat** — the *inbound* stdio arm passes `modern_enabled: false` unconditionally
  (`src/gateway/server/mod.rs:1687-1693`). This design does not touch the inbound document, and
  must not make that caveat harder to lift. It is not a precedent this design may cite for its own
  coverage: a limitation inside a shipped mechanism is not a licence to exclude a transport class.
- **DISCOVER.3's goldens** — `tests/mik_7217_acs.rs:213` compares the `initialize` result
  byte-for-byte against captured goldens. Nothing here changes the inbound result; if a golden
  moves, this design is wrong.
- **DISCOVER.6's pinned budgets** — `warmstart.rs:751-759` pins `attempt_timeout` 120s,
  `initial_gap` 2s, `max_gap` 30s. A probe inside the start path spends from that budget, so its
  timeout is chosen against those numbers, not freely.

## Measured constraints

### 1. A probe on a transport that has not connected does not reach the peer

This is the constraint revision 1 got wrong, and it decides the whole design.

Revision 1 placed the probe **between transport construction and `transport.initialize()`**, on the
reasoning that the era should be learned "without trusting the handshake". Read at source, that
placement cannot reach the peer's discover surface at all:

- **SSE backends — the configuration default.** `message_url` is `None` at construction
  (`src/transport/http/mod.rs:200,:327`) and is written only inside `initialize()`, from the
  endpoint the SSE handshake returns (`:434-435`). Before that, `get_message_url()` falls back to
  `self.base_url` (`:815-821`) — the SSE **GET** endpoint. A pre-handshake probe therefore POSTs a
  JSON-RPC request at a URL that does not accept one. `streamable_http` defaults to `false`
  (`src/config/mod.rs:1532,:1546`), so this is the ordinary case, not a corner.
- **OAuth backends.** The token is acquired *inside* `initialize()`: `oauth.initialize()` then
  `oauth.authorize()` if no valid token (`src/transport/http/mod.rs:378-421`). A probe issued
  earlier reaches `get_oauth_token()` (`src/transport/http/mod.rs:640-645`) on a client that has not
  initialized, so it goes out unauthenticated and is rejected.

Both failures land in the same place: transport error or non-2xx → `ProbeOutcome::NoAnswer` →
`classify` answers **Legacy** (`src/protocol/era.rs:60-100`). The gateway would record a confident
era for a peer it never asked. That is not a probe; it is a manufactured answer with a probe's
shape, and it is *systematically* wrong for the default transport mode rather than occasionally
wrong.

Switching the probe from `Transport::request` to `HttpTransport::send_request` — the improvement
both reviewers offered — fixes the real re-entry hazard at `src/transport/http/mod.rs:1019-1026` (a
session-expiry branch that calls `self.initialize()` and retries) and fixes **neither** of the two
failures above. The call surface was not the defect. The placement was.

**Elimination: the probe is issued immediately after the transport is connected**, still inside
`start_entry`, still directly on the transport. At that point the message endpoint is known, the
OAuth token exists, and the probe reaches the peer. The defect "the probe is specified on a
transport that has not connected" then cannot be stated, rather than being narrowed.

DISCOVER.4 is not weakened by this. It forbids trusting a **version string**; it says nothing about
ordering. The evidence is unchanged — the peer's own `server/discover` document, or one of the
reserved 2026 error codes — and the handshake's `protocolVersion` is never read for era, before or
after. Stated as an invariant the implementation must hold: **no code path derives `Era` from the
`initialize` result.**

Named consequence, so HEADER.9 inherits it rather than discovering it: today the legacy handshake
must run regardless, because `SUPPORTED_VERSIONS` has no modern revision to negotiate. When HEADER.9
adds one, the era may need to *select* the handshake, which puts the probe back before it — on a
connected transport, which is the part that has to be built either way. HEADER.9 re-opens this
ordering question; it is named here as one rather than left to be rediscovered.

### 2. With the probe after connection, both transports expose the same seam

Revision 1 excluded stdio because `stdio::start()` calls `initialize()` internally at
`src/transport/stdio.rs:256`, inside the spawn-then-teardown block at `src/transport/stdio.rs:246-261`
— there is no seam *before* the handshake without splitting that function and reworking its
teardown.

After the constraint-1 repair, no such seam is needed. `start_entry` reaches an identical state on
both arms: `transport.start().await?` for stdio (`src/backend/lifecycle.rs:344`) and
`transport.initialize().await?` for HTTP (`src/backend/lifecycle.rs:369`) each return a
**connected** transport, in the same match, before the transport is published to the pool entry. The
probe goes there, once, for both.

**Decision: this increment covers stdio and HTTP.** The open item revision 1 deferred is withdrawn —
not answered, *dissolved*: it asked whether to split `stdio::start()`, and the repair means nothing
needs splitting. `src/transport/stdio.rs:246-261` is not touched. This is the operator's FULL-SCOPE
directive met by construction rather than by appetite. No transport class is excluded, so
DISCOVER.4/.5 move off UNWIRED without a coverage caveat.

### 3. The probe must not re-enter the start path

The narrow true statement from revision 1, kept, with the false half removed.

Inside `start_entry`, the transport has not yet been published to the pool entry. A probe issued
through the ordinary `Backend::request*` surface would call `ensure_entry_started`
(`src/backend/lifecycle.rs:187`), find no connected transport at the early-out
(`src/backend/lifecycle.rs:202-207`), and block on the entry's `start_lock`
(`src/backend/lifecycle.rs:209`) — a non-reentrant `tokio::sync::Mutex` (`src/backend/pool.rs:12,:62`)
that the caller already holds. That self-deadlocks.

What revision 1 also claimed, and is **false**: that this makes lazy probing on the tool-call path
deadlock. It does not. `ensure_entry_started` returns at `src/backend/lifecycle.rs:202-207`
**without taking the lock** once the transport is connected, which is exactly the state a lazy probe
would run in. That rationale is withdrawn; the honest reasons to reject lazy probing are in the
options table, and they are about coverage and permits, not locks.

So: **the probe is issued directly against the connected transport, inside `start_entry`, never
through `Backend::request*`.** `src/backend/ops.rs:104` records the same shape being solved the same
way for the cold tool cache. Lock order is `start_lock` → era lock, never reversed, and the probe
closure touches nothing that re-acquires `start_lock` — load-bearing because `EraCache::resolve_with`
holds its own lock *across* the probe await by design (`src/protocol/era.rs:143-170`), so concurrent
resolution collapses onto one probe rather than stampeding a peer that is by hypothesis already
struggling (`src/protocol/era.rs:127-131`).

## The design

**Where the era lives.** On `Backend`, alongside the two caches already there
(`src/backend/mod.rs:200-207`). One `EraCache` per backend, constructed with the backend name so
its own log lines identify the peer.

**When it is learned.** Once, in `start_entry`, immediately after the transport is connected and
before it is published to the pool entry — the same point on both arms
(`src/backend/lifecycle.rs:344` stdio, `:369` HTTP). The probe is issued directly against that
transport, never through `Backend::request*` (constraint 3).

**What counts as evidence.** Only what `src/protocol/era.rs:60-100` already accepts: a
`server/discover` result, or one of the reserved 2026 error codes. Positive evidence only — a
transport error, a timeout or a non-2xx is `ProbeOutcome::NoAnswer`, and `NoAnswer` classifies
**Legacy**, which is the era the gateway already behaves as. A failed probe therefore costs nothing
but the probe. The `initialize` result's `protocolVersion` is never consulted, before or after
(DISCOVER.4's actual requirement).

**What it costs.** The probe runs inside the warm-start attempt, which DISCOVER.6 pins at
`attempt_timeout` 120s (`warmstart.rs:751-759`). The probe carries its own 10s timeout so a peer
that accepts a connection and then stalls cannot eat the attempt budget; on expiry it is `NoAnswer`
and start proceeds. 10s is chosen against the 120s attempt and the 2s/30s retry gaps, not freely: it
is under a tenth of the attempt, and above the `initial_gap`, so a probe that is merely slow does
not turn a healthy backend into a retry.

**Re-probing (DISCOVER.5's second half).** The cached era is invalidated when a request fails with
one of the reserved codes that contradict it — the same `-32022 / -32020 / -32021` set the classifier
already treats as era evidence. Nothing else invalidates: not a transport error, not a timeout, not
a restart of the process. This is the "re-probed when a cached assumption fails" clause read
literally — an assumption *fails* when the peer says the assumption is wrong, not when the network
does.

**No transport snapshot.** Revision 1 proposed recording the transport kind alongside the era so a
later reader could tell which arm produced it. It is removed, not narrowed: with both arms probing
at the same seam there is one production path, nothing reads the field, and a stored value nobody
reads is a second thing to keep true. If HEADER.9 needs it, HEADER.9 adds it with a reader.

**Interaction with the two existing caches.** The tool cache (`src/backend/cache.rs:223`) and the
metadata cache (`src/backend/cached_metadata.rs:96,:100,:245`) are unaffected: the era cache is
consulted by nothing they call, and it is populated before either is warmed. The era's own lock is
taken after `start_lock` and never before it (constraint 3).

## Options considered

| option | why not |
|---|---|
| probe before `initialize` (revision 1) | cannot reach the peer on SSE or OAuth backends; manufactures `Legacy` from a request that never arrived (constraint 1) |
| lazy — probe on first tool call | the honest objection is coverage, not deadlock: a backend that is started and never called never gets an era, and the probe would then spend a request permit on the latency path a caller is waiting on. Start is where the gateway already pays connection cost |
| trust `initialize`'s `protocolVersion` | DISCOVER.4 forbids exactly this |
| split `stdio::start()` to expose a pre-handshake seam | needed only under the revision-1 placement; the repair removes the need, and the teardown block at `src/transport/stdio.rs:246-261` stays untouched |
| HTTP-only this increment, stdio next | was revision 1's position; it survived only as a consequence of the wrong placement. Against the operator's FULL-SCOPE directive, and unnecessary once both arms share the seam |

## Open questions

Every question this design raised is answered here. **Nothing is deferred**; there is no four-field
deferral block because there is no deferred unknown.

- *Does a pre-`initialize` probe reach an SSE peer?* — read `src/transport/http/mod.rs:200,:327,:434-435,:815-821` and `src/config/mod.rs:1532,:1546` — no: `message_url` is unset until the handshake, and `streamable_http` defaults false — killed the revision-1 placement, which is the whole of revision 2.
- *Does it reach an OAuth peer?* — read `src/transport/http/mod.rs:378-421,:640-645` — no: the token is acquired inside `initialize()` — second, independent kill of the same placement.
- *Does a lazy probe on the tool-call path deadlock?* — read `src/backend/lifecycle.rs:187,:202-207,:209` — no: `ensure_entry_started` early-outs before taking `start_lock` when the transport is connected — withdrew a false rationale; lazy is still rejected, for coverage and permits instead.
- *Does the stdio arm expose the seam this design needs?* — read `src/backend/lifecycle.rs:344,:369` and `src/transport/stdio.rs:246-261` — yes, after connection both arms are in the same match — moved stdio from OUT to FOR, dissolving revision 1's only deferral.
- *Is `Transport::request` re-entrant on session expiry?* — read `src/transport/http/mod.rs:1019-1026` — yes, it can call `self.initialize()` and retry — the probe goes directly to the connected transport, so the branch is never entered from the start path.
- *What timeout can the probe afford?* — read `warmstart.rs:751-759` — 120s attempt, 2s/30s gaps — fixed the probe timeout at 10s, and stated the arithmetic instead of asserting the number.
- *Does anything read the transport-kind snapshot?* — searched `src/` — nothing — removed the field.

## Test plan delta

Component tests, driving `start_entry` against a fixture transport — not unit tests of
`src/protocol/era.rs`, which is already covered and is not what is broken.

| case | proves |
|---|---|
| fixture answers `server/discover` → backend's cached era is Modern | DISCOVER.4 on the positive path |
| fixture returns `-32022` → Modern | the error-code arm of the same classifier, reached through the real caller |
| fixture errors on the probe → Legacy, and `start_entry` still succeeds | a failed probe does not fail a start |
| fixture never answers → Legacy after the probe timeout, start succeeds | the 10s bound is real, not aspirational |
| stdio fixture and HTTP fixture, same assertions | both arms are covered — the claim that replaces revision 1's deferral |
| two backends, different eras, one probe each | DISCOVER.5's per-backend caching, and that the probe is not repeated per request |
| cached Modern, then a request returns `-32020` → era re-probed | DISCOVER.5's invalidation clause |
| a transport error after caching → era **not** invalidated | the negative half of the same clause; without it the previous row passes on a cache that invalidates on everything |

Each row can fail today: none of them has a production caller to exercise, which is the point —
they are written first and fail because the wiring does not exist.

## Revision 2 — findings and dispositions

| # | finding | disposition |
|---|---|---|
| F1 | probe placed before `initialize` cannot reach SSE or OAuth peers | **eliminated** — probe moved after connection. Killed at source: `src/transport/http/mod.rs:200,:327,:434-435,:815-821`; `src/config/mod.rs:1532,:1546`; `:378-421,:640-645`. The reviewers' own fix (use `send_request`) would have left both failures standing |
| F2 | stdio excluded, leaving DISCOVER.4/.5 partially wired | **eliminated** — the exclusion was an artefact of F1's placement. With the probe after connection, `src/backend/lifecycle.rs:344,:369` give both arms the same seam. Deferral dissolved, not answered |
| F3 | `Transport::request` can re-enter `initialize()` on session expiry | **repaired** — probe issued directly against the connected transport, so `src/transport/http/mod.rs:1019-1026` is unreachable from the start path. A patch is right here because the hazard is local to a sound mechanism and the placement repair already removes the caller |
| F4 | "lazy probing deadlocks" | **closed on inspection, and the rationale repaired** — `src/backend/lifecycle.rs:202-207` early-outs before `start_lock`, so the deadlock claim is false. The *narrow* claim (a probe from inside `start_entry` would deadlock) survives and is kept in constraint 3. Lazy stays rejected on coverage and permits |
| F5 | scope should be reduced to HTTP for this increment | **eliminated** — full scope, per the operator's directive, and now free: the repair makes stdio cost nothing extra |
| F6 | transport-kind snapshot has no reader | **eliminated** — field removed rather than documented |
| F7 | probe timeout asserted without arithmetic | **repaired** — 10s stated against `warmstart.rs:751-759`'s 120s attempt and 2s/30s gaps |

Two of the seven were patches; both say above why a patch is right. The other five removed the
thing the finding was about, so the finding can no longer be stated.
