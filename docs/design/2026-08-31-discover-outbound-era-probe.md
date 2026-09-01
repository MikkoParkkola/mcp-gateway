<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# Design — wiring the outbound era probe (MIK-7217 DISCOVER.4, DISCOVER.5)

Status: proposed · Revision: 5 · Date: 2026-09-01
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

Revision 4 moved neither FOR nor OUT, but it did move the **implementation surface**: the A3 repair
(shared in-flight resolution, revision-4 finding H7) meant this increment would modify the resolution
path in `src/protocol/era.rs`, which revision 3 said it would not touch. Revision 5 **withdraws that
move**: the shared in-flight resolution is deleted (F2 below), and the only remaining change to
`era.rs` is the effective-era accessor. Both moves are recorded rather than rounded away — a surface
move is visible or it is not a decision, and that holds in the direction that shrinks it too.

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
  `initial_gap` 2s, `max_gap` 30s. Those are the *configured* values; the attempt timeout actually
  applied is `configured.max(per-backend budget)` (`warmstart.rs:219-221`), so 120s is a floor. A
  probe inside the start path spends from that budget, so its timeout is chosen against those
  numbers, not freely.

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
ordering. The evidence is unchanged — the peer's own `server/discover` document, or one of the three
2026 error codes — and the handshake's `protocolVersion` is never read for era, before or
after. Stated as an invariant the implementation must hold: **no code path derives `Era` from the
`initialize` result.**

**A modern-only peer, named as a limit rather than left to be discovered.** Both reviewers raised
the same objection: probing after the handshake cannot discover a backend that refuses the
handshake. That is true, and it is not a defect this design introduces — it is the state of the tree.
The gateway's outbound `initialize` offers `PROTOCOL_VERSION` (`src/transport/http/mod.rs:440-452`,
`src/transport/stdio.rs:266-269`), which is `2025-11-25`
(`src/protocol/mod.rs:26`), and `SUPPORTED_VERSIONS` (`:43`) contains no 2026 revision. A peer that
speaks only `2026-07-28` is therefore unreachable *today*, before any era work, and probing before
the handshake would not have made it reachable either — constraint 1 showed a pre-handshake probe
does not arrive on SSE or OAuth backends at all. Reaching such a peer means offering a version it
accepts, which is HEADER.9's job, not this increment's. Recorded here as an accepted limit with its
owner, so that "the era probe handles modern-only peers" is never claimed on this design's behalf.
What this increment *does* owe, and pays in §3a below, is that the probe must not carry the
handshake's version and session headers — that half was in scope and is repaired.

One disambiguation, because a re-checker will hit it before the citation above. There *is* a 2026
constant in the tree: `protocol::meta::MODERN_VERSIONS` (`src/protocol/meta.rs:219`). It is
**inbound-only** — it is read by the router when a *client* connects to the gateway
(`src/gateway/router/handlers.rs:178,:222,:575,:702`) and by nothing on the outbound path. Finding
it and concluding the gateway can already negotiate 2026 with a backend inverts the direction of
the connection. The outbound offer is `PROTOCOL_VERSION`/`SUPPORTED_VERSIONS`, cited above, and it
has no 2026 revision. V.

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

### 3a. `Transport::request` is not a probe-safe call, and the safe one is already in the tree

Revision 2 said the probe goes "directly against the connected transport" and stopped there, as if
naming the object settled which *method*. It does not, and the two transports differ.

On HTTP, `Transport::request` re-enters `initialize()` when the peer's answer carries the
session-expiry signature (`src/transport/http/mod.rs:994-1026`, documented at `:343`), and every
request it sends carries the headers the handshake negotiated — `MCP-Protocol-Version` and
`MCP-Session-Id`, inserted unconditionally at `src/transport/http/mod.rs:570,:605`. A probe sent
that way would announce the very version string DISCOVER.4 forbids the era from depending on, and
could re-handshake mid-probe. On stdio there is no such path: `request`
(`src/transport/stdio.rs:473`) does not call `initialize()`, which is reached only from `start()`
(`:256`), and stdio carries no HTTP header channel at all
(`src/transport/mod.rs:66` — `carries_identity_headers` defaults false, and only HTTP overrides it).
So the seam is shared; the *call* cannot be, and revision 2's single sentence covered a real
asymmetry.

**Elimination, not a special case: the probe uses the same escape hatch `initialize()` itself uses.**
`HttpTransport::initialize()` avoids recursing into its own retry logic by calling `send_request`
directly (`src/transport/http/mod.rs:823`, and the reason is stated at `:1011`). That private method
*is* the probe-safe primitive; it is simply not reachable from outside the transport. The design
adds one trait method:

```
async fn probe(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;
```

with a default body of `self.request(method, params)`. stdio inherits that default, because for
stdio the default is already correct — shown above, not assumed. Websocket and any future transport
inherit it too and are no worse off than they are today.

**The 10s deadline sits in a wrapper the override cannot reach.** Putting it inside the default body
bounds only the transports that *inherit* — and HTTP is precisely the transport that overrides, to
reach `send_request` and skip the reserved headers, so it would have inherited nothing and waited out
the configured client timeout instead (30s by default, `src/config/mod.rs:1386`). The overridable
method is therefore the *unbounded* primitive, and the deadline is applied once around it, in the one
non-overridable place every probe passes through. An override that forgets the timeout is then not a
spelling an implementer can produce: there is no timeout in the overridden method to forget.

**HTTP cannot subtract headers, and revision 3 said it could.** Revision 3 had the HTTP override
call `send_request` "with the standard header set minus `MCP-Protocol-Version` and
`MCP-Session-Id`". That subtraction is not available: `build_headers` inserts both unconditionally
(`src/transport/http/mod.rs:570,:605`). Revision 3's own test row 6 cites those two lines and knew
it; §3a assumed otherwise, and the document contradicted itself. The decision, named here rather
than designed here: `build_headers` takes a mode, and the probe passes a probe mode that omits both
headers, with no session-expiry retry. Which spelling that takes — an enum, a second builder, two
call sites — is an implementation choice with no design content. What is settled is that the probe
must not reuse the request header set, and that the omission is a branch in the builder rather than
a subtraction at the call site.

**Omitting is not enough: the configured header map can put both back.** `build_headers` merges the
backend's own `headers` config last, over everything the builder generated
(`src/transport/http/mod.rs:607-615` — an unconditional `headers.insert(k, v)` per configured pair).
An operator who has pinned `MCP-Protocol-Version` or `MCP-Session-Id` in config therefore reinserts,
after the probe mode omitted them, exactly the two names the probe mode exists to remove. The rule is
stated as a post-condition rather than as a branch: **on the probe path both reserved names are absent
from the header map when it reaches the sender, whatever produced them.** The omission branch runs
first; a removal of both runs after the custom merge. Test row 6 asserts this against a backend
configured with both.

After this the finding cannot be restated: there is no "which method does the probe use" question
left to get wrong, because there is exactly one method whose contract is *this is the probe*.

**Adapter, stated rather than left to the implementer.** A JSON-RPC error is not a transport error:
it arrives as `Ok(JsonRpcResponse)` with `error: Some(..)` (`src/protocol/messages.rs:45-55`, and
the same fact is relied on at `src/transport/http/mod.rs:174-176`; `src/backend/metadata.rs:117-118`
is the existing caller that gets this right). So the mapping into `ProbeOutcome` is:
`Ok` with `result: Some(v)` → `Result(v)`; `Ok` with `error: Some(e)` → `Error(e.code)`. Written down because the obvious implementation — matching on the
`Result` — makes the `-32022` arm of `classify` unreachable and every 2026 peer read as `NoAnswer`,
which fails silently in the Legacy direction and would pass every test in the plan below that did
not name it.

**`Err(_)` splits, and collapsing it is how a corpse gets published as Legacy.** Revision 4 mapped
every transport error to `NoAnswer`, so a stdio child that died between `start()` and the probe
produced a *started* backend advertised as Legacy: the probe could not answer, and the design read
that silence as evidence about the peer's era when it was evidence about the peer's existence. The
two cases are separated by a question the transport can already answer — *would the next request on
this transport fail for the same reason?*

| probe result | meaning | outcome |
|---|---|---|
| the 10s deadline expires with no frame | the peer is connected and slow, or ignoring the method | `NoAnswer` → Legacy, start proceeds |
| an HTTP response the peer authored — any status, 4xx and 5xx included, or a body that is not a JSON-RPC frame | the peer is alive and does not serve the method | `NoAnswer` → Legacy, start proceeds |
| the stdio child's pipe is closed or the process has exited — `BrokenPipe`, `UnexpectedEof`, a closed reader channel, or the child no longer running | there is no peer | **fatal: `start_entry` returns `Err`, nothing is published** |
| the HTTP round trip did not complete — connect refused, TLS failure, or the connection dropped mid-response | the transport is no longer connected | **fatal: `start_entry` returns `Err`, nothing is published** |

The dividing line, so an implementer meeting a new error variant does not have to invent one: an
error the *peer* authored is never fatal, because the peer was there to author it, and silence is
never fatal, because a slow peer is a live peer. Everything else — the connection itself failing or
gone — is fatal. The probe therefore returns `Result<ProbeOutcome>` rather than `ProbeOutcome`:
`Err` carries exactly the fatal class and propagates out of `start_entry` with `?`, and `NoAnswer`
means *the peer is connected and told us nothing*. Test rows 4b and 4c are the two sides of this
line.

## The design

**Where the era lives.** On `Backend`, beside the `tools_cache` field it is modelled on
(`src/backend/mod.rs:34` for the struct, `:54` for that field), constructed where that field is
constructed (`src/backend/lifecycle.rs:134`). One `EraCache` per backend, built with the backend
name so its own log lines identify the peer.

**Per backend, and a pool slot is not a backend.** `PoolKey::PerUser` gives one backend several
slots, and a stdio slot is a separate child process that could in principle answer differently.
The era is keyed per backend anyway, because the alternative is worse: a per-slot era re-probes
every user's first start, and the era is a property of the *server implementation*, which a
per-user slot does not change. Two slots of one backend disagreeing means the operator pointed one
name at two implementations, which breaks more than era. Revision 3 recorded this as a ranked
assumption (A2) rather than hiding it in the word "backend"; revision 4 turned it into a question
for the requester, and the team-lead answered it — per backend *name*, provisionally. See Open
questions.

**When it is learned.** Once, in `start_entry`, immediately after the transport is connected and
before it is published to the pool entry — the same point on both arms
(`src/backend/lifecycle.rs:344` stdio, `:369` HTTP). The probe is issued directly against that
transport, never through `Backend::request*` (constraint 3).

**What counts as evidence.** Only what `src/protocol/era.rs:60-100` already accepts: a
`server/discover` result, or one of the three 2026 error codes. Positive evidence only — a
timeout or a non-2xx is `ProbeOutcome::NoAnswer`, and `NoAnswer` classifies
**Legacy**, which is the era the gateway already behaves as. A failed probe therefore costs nothing
but the probe. The `initialize` result's `protocolVersion` is never consulted, before or after
(DISCOVER.4's actual requirement). A transport that is no longer connected is not a failed probe but
a failed start (§3a): the gateway never publishes a backend it cannot reach.

**Reading the era back.** `EraCache::cached` returns `Option<Era>` (`src/protocol/era.rs:126`) and
`NoAnswer` stores nothing, so `None` is the ordinary state after an unanswered probe and every caller
would otherwise invent its own default. One accessor owns the mapping: **the effective era is the
cached era if one is stored, and `Legacy` otherwise.** `Option<Era>` stays available for the one
question that needs it — *has this backend ever resolved?* — which is what the re-probe trigger and
the telemetry counters read. A caller shaping a request reads the effective era and never sees
`None`.

**How strong the error-code evidence actually is.** `-32022`, `-32020` and `-32021`
(`src/protocol/era.rs:34,:37,:40`) sit inside JSON-RPC 2.0's `-32000..=-32099` band, which the
specification hands to *implementation-defined* server errors. They are therefore not reserved to
this revision, and `src/protocol/era.rs:77-79` overstates when it says "only a server that
implements this revision knows these codes". The bound that does hold is narrower and still
sufficient: JSON-RPC 2.0 *requires* `-32601` for a method the peer does not implement, and the
classifier already calls that "the honest legacy answer" (`src/protocol/era.rs:91-93`), so a false
Modern requires a peer that both lacks `server/discover` and answers it with one of exactly three
codes in the implementation-defined band. Revision 2 called such a peer "nonconforming"; both
reviewers pushed back, and they are right — a peer may legitimately own a same-named extension and
return an implementation-defined code for its own reasons without violating anything. The claim is
therefore narrowed to what the specification actually supports: such a peer is **unlikely, not
forbidden**. It is worth stating because false Modern is the expensive direction — the gateway would
frame modern requests at a peer that cannot read them, where false Legacy costs only the status quo.

**This bound depends on the correction path, and does not stand without it.** Revision 2 argued the
classifier could be repaired rather than eliminated because a false Modern is rare. Rare was never
the whole risk: revision 2 also had no way to heal one, so a false Modern was rare *and permanent*,
which is worse than that paragraph admitted, and the narrowing above makes "rare" weaker still. With
the re-probe rule below — where a cached Modern contradicted by `-32601` classifies Legacy and
re-resolves — a false Modern is rare *and self-correcting*, and repair-not-elimination is
defensible. A later reader must not lift this bound out on its own: without the correction path it
does not carry its conclusion. The overstated comment
at `src/protocol/era.rs:77-79` is production code, which this design-only increment may not touch;
it is disposed by riding the implementation increment that wires the probe, since that increment
edits this file anyway. No ticket: the correction is smaller than a ticket describing it.

**What it costs.** The probe runs inside the warm-start attempt. Revision 2 called 120s "the
attempt timeout" and computed against it; that number is a **floor**, not a ceiling —
`effective_attempt_timeout` returns `configured.max(per-backend budget)`
(`src/gateway/server/warmstart.rs:219-221`), so the real ceiling is at least 120s and is larger for
a backend with a bigger request budget. The arithmetic is restated in the direction that is
actually safe: the probe's own 10s timeout is bounded *above* by the smallest attempt ceiling the
system can produce (120s, the default floor, `warmstart.rs:46-49`), so it is at most a twelfth of
the shortest attempt and a smaller fraction of every longer one. A peer that accepts a connection
and then stalls cannot eat the attempt budget; on expiry the outcome is `NoAnswer`, and start
proceeds as Legacy. The retry-gap clause revision 2 attached to this is withdrawn: the gaps
(`warmstart.rs:46-49`) govern *whether a failed attempt is retried*, not whether a slow probe
becomes one, so "above the `initial_gap`" was a comparison between unrelated quantities.

**One probe per resolution, and on a stalled peer waiters are not free.** `EraCache::resolve_with`
holds its lock across the probe await (`src/protocol/era.rs:143-170`), so concurrent resolvers of the
same backend collapse onto one probe — as long as the probe produces a cacheable outcome. `NoAnswer`
is deliberately not cached (`src/protocol/era.rs:164-167`), so on a stalled peer each waiter takes
the lock in turn and pays its own 10s.

**Revision 4 tried to keep the collapse without the cache, and revision 5 deletes that repair rather
than specifying it.** Sharing an in-flight resolution while storing nothing is not expressible *in
the shape revision 4 wrote it*, holding the mutex across the await: a waiter can only look at the
cache after the leader unlocks, and by then the leader has stored nothing, so every waiter sees an
empty cache and probes. It is not impossible in general — `CachedMetadata` in this repo already drops
its lock and waits on a watch channel, and that spelling would work here too. Making it work means
replacing the mutex with an Empty/InFlight/Ready state machine that releases its state lock before
awaiting, registers waiters, broadcasts one outcome, clears it afterwards and wakes waiters on
cancellation, plus an ordering rule so a probe against a torn-down peer cannot commit after
`force_restart` invalidated it — a concurrency protocol invented in a review round, which is the move
this document has already refused once (H5). Buildable is not the bar. It is the second consecutive
round in which this mechanism has been found defective while the cost it removes is one idempotent
request per concurrent starter, and per repair-protocol step 0 the answer to that is to remove the
mechanism.

**Decision: there is no shared in-flight resolution. `resolve_with` is used exactly as it stands.**
Two properties survive unchanged, and they are the ones DISCOVER.5 asks for: a cacheable outcome
collapses the herd, and `NoAnswer` is never stored, so a peer that was briefly slow is never pinned
to Legacy. What is given up is the collapse on the *uncacheable* outcome, and its cost is bounded
and small. `warmstart` spawns one task per backend (`src/gateway/server/warmstart.rs`), so the
ordinary start path has one resolver per backend and nothing to collapse; contention needs several
`PoolKey::PerUser` slots of one backend starting inside the same 10s window, and it costs each of
them one idempotent `server/discover` against a peer that is answering none of them. If that cost
ever becomes real, per-slot keying removes it outright — and per-slot is the reading the requester
may still choose (Open questions). This increment therefore does **not** modify `src/protocol/era.rs`
beyond adding the effective-era accessor; revision 4's surface growth is withdrawn with the repair
that caused it.

**Re-probing (DISCOVER.5's second half).** Revision 2's rule was: invalidate when a request fails
with one of `-32022 / -32020 / -32021`. Two defects, one found here and one by both reviewers, and
they compose into a single repair.

The first: that set *is* the Modern signal. The only evidence that could correct a wrongly-cached
`Modern` was evidence that would have produced `Modern`. A legacy peer whose own extension happens
to answer `-32020` is cached Modern, then answers `-32601` to a request the gateway shaped
*because* it cached Modern — the code `classify` itself calls "the honest legacy answer"
(`src/protocol/era.rs:91-93`) — and that code is not in the invalidation set, so the entry never
heals. Rare *and permanent*.

The second: nothing would have re-probed anyway. `resolve_with` is called from exactly one place,
`start_entry`, which a connected backend's requests do not go through
(`src/backend/lifecycle.rs:202-207` early-outs before the lock). `invalidate` with no reachable
resolver is a cache eviction, not a re-probe, and DISCOVER.5 asks for a re-probe.

**The rule, in one owner — and the classifier never sees an ordinary answer.** Revision 3 fed
`classify` with "era-conditional" answers, and then had to define that term precisely enough for an
implementer to apply it. Both vendors said the definition could not be applied without guessing.
Revision 4 deletes the term instead of sharpening it. `classify` (`src/protocol/era.rs:60-100`) is
fed **only** `ProbeOutcome` values. An ordinary answer classifies nothing; it can only *trigger* a
fresh probe, and the probe's outcome is what decides.

That makes the trigger set a heuristic, and it is allowed to be one, because being wrong about it
is cheap: a wrong trigger costs at most one rate-limited probe and cannot change a cached era by
itself. Triggers, per backend: an answer carrying one of the three 2026 codes while the cached era
is Legacy, and a `-32601` to a request the gateway shaped because the cached era is Modern. The
probe then re-resolves through a path reachable from a connected backend, using the §3a primitive
against the transport already in the pool entry, and **the outcome goes to `classify()` unchanged** —
the same function, the same three 2026 codes, the same `-32601`. Only `NoAnswer` is special-cased, and
only by writing nothing: the entry stays exactly as it was. A restart is handled separately, below.

Revision 4 wrote a second mapping here — *`Result` Modern, `Error` of any code Legacy* — and it
contradicted `classify` in both directions. A dual-era peer that answers the re-probe with one of the
three 2026 codes (`src/protocol/era.rs:34,:37,:40`) is a **Modern** peer under `classify` and a Legacy
one under that shorthand, so a backend that had healed into Legacy for one bad request could never
heal back out; and a peer that returns a discover document while advertising only 2025 would be read
as Modern on the strength of the envelope rather than its content. Two classifiers is the finding
revision 4 believed it had closed; writing one out longhand in a second section is how it came back.
There is exactly one classifier, and the re-probe path does not get to paraphrase it.

**A re-probe is detached, and the triggering request does not wait for it.** The trigger arrives on a
response the caller is already holding, so the choice is: return that response now and correct the
cache behind it, or hold the caller for up to 10s to hand back a differently-shaped retry. This design
returns the response. The re-probe is spawned as a tracked task owning a clone of the transport
`Arc` it was issued against, it is cancelled at shutdown with the rest of the backend's tasks, and its
outcome is subject to the transport-identity rule below. The caller sees the original answer,
correct or not; the *next* request sees the corrected era. This is the cheap side of the trade — a
re-probe fires on a request that already went wrong, and making one more request go wrong is a
smaller cost than putting a 10s stall on a live request path. Left undecided, an implementer inherits
four questions the design never asked: caller latency, concurrency, cancellation, and shutdown.

After this the finding cannot be restated. There is no invalidation set to disagree with the
classifier, and no "era-conditional" definition to misapply, because a misjudged trigger can only
buy a redundant probe — never a misclassification.

**A restart is a new peer.** A `force_restart` on a shared slot tears down and re-creates the
transport (`src/backend/lifecycle.rs:821-885`), and for stdio that is a *different child process* —
possibly a different binary, after an upgrade. The era is invalidated there too. This is the one
place a non-answer from the peer invalidates, and it is not an exception to the rule above: nothing
contradicted the era, the thing the era described stopped existing.

**A probe in flight when the restart happens must not land on the new process.** A re-probe is issued
from the request path against the transport in the pool entry, and `force_restart` replaces that
transport underneath it, so a probe started against the old peer can complete after the new one is
published and write the dead process's era onto the live one. Invalidating *before* the new transport
is probed does not close this: the stale write happens after the invalidation. The rule is ownership,
not ordering, and it needs no new protocol because the entry already holds the discriminator: **a
probe result is written only if the transport it was issued against is still the transport in the pool
entry** — the same `Arc` the probe borrowed, compared by pointer identity. A probe against a replaced
transport discards its outcome and logs it as such; it never retries, because the new process will be
probed on its own start path. `force_restart` therefore does not wait for anything, and no
shared in-flight resolution has to be coordinated between callers. Test row 13 drives exactly
this interleaving.

**What re-probing costs, over time.** One limit, per backend: at most one re-probe per 30s, reusing
the ceiling the retry path already uses (`max_gap`, `src/gateway/server/warmstart.rs:46-49`) rather
than introducing a new number. Revision 3 carried a second limit — pin Legacy after a second
contradiction inside one window — and both vendors found it strands a genuinely modern peer that
triggers twice for an unrelated reason. It is deleted rather than narrowed, because with the
classifier fed only by probe outcomes the loop the pin was bounding cannot form: a peer that keeps
triggering costs one probe per 30s and nothing else. A one-way demotion that can be wrong is a
worse trade than a rate-limited probe that cannot be.

**What the probe emits.** The A3 cost accepted above, the rate limit, and the identity rule are all
claims about production behaviour that no test in this plan can observe, so the design says what
would show them. Four events, all on the existing tracing subscriber, all labelled by **backend name
only** — the same key the cache uses, so the label set is bounded by the configured backend count and
adds no new cardinality dimension. Nothing is labelled by user, slot, `PoolKey`, method or error
code; a per-user label would make the cardinality of a `PoolKey::PerUser` backend unbounded, which is
the one mistake this section exists to prevent.

| event | fields | answers |
|---|---|---|
| `era_probe` | `backend`, `outcome` ∈ {`modern`, `legacy`, `no_answer`}, `duration_ms`, `trigger` ∈ {`start`, `reprobe`} | how often peers stall, and whether the 10s bound is being reached in production |
| `era_cache` | `backend`, `hit` ∈ {`true`, `false`} | whether the cache is doing its job — the DISCOVER.5 claim, outside the test harness |
| `era_invalidated` | `backend`, `reason` ∈ {`restart`, `trigger`} | which of the two invalidation paths actually fires |
| `era_probe_discarded` | `backend` | the identity rule firing: a probe outcome dropped because its transport was replaced. Expected to be ~0; a non-zero rate means restarts and re-probes are racing more than the design assumes |

Two of these are also the falsifiers for claims made above and nowhere else checkable: `duration_ms`
on `trigger=start` is what would show A3's serialised waits actually happening (several `start`
probes for one backend, overlapping, each near 10s), and `era_probe_discarded` is what would show the
identity rule earning its place rather than guarding a race that never occurs.

**No transport snapshot.** Revision 1 proposed recording the transport kind alongside the era so a
later reader could tell which arm produced it. It is removed, not narrowed: with both arms probing
at the same seam there is one production path, nothing reads the field, and a stored value nobody
reads is a second thing to keep true. If HEADER.9 needs it, HEADER.9 adds it with a reader.

**Interaction with the two existing caches.** The tool cache (the `tools_cache` field on `Backend`,
`src/backend/mod.rs:54`, constructed at `src/backend/lifecycle.rs:134`) and the
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

Every question this design raised is answered here, and revision 3 stops claiming more than that.
**Nothing this design depends on is deferred** — narrower than revision 2's "nothing is deferred",
and the version that is true. Two things are *accepted*, and an accepted limit is not an open
question in disguise: a modern-only peer is unreachable until HEADER.9 offers a version it takes
(constraint 1 — owner named, nothing here depends on it), and N-waiter serialisation on a stalled
peer, which revision 4 tried to repair and revision 5 accepts with a bound after the repair was found
defective as written, twice (A3 below). Both have an owner and a trigger; neither blocks
anything in this increment.

Revision 4 opened one deferral and it was **closed the same day** by the team-lead. It is recorded
here in full, because the answer is provisional and a later reader must be able to see what it rests
on.

**Answered: "per backend" means per backend *name*.** DISCOVER.5's
text says the era "MUST be cached per backend"
(`docs/requirements/RELEASE-4.0.0-criteria-status.md:182`). GPT's review argues that under
`PoolKey::PerUser` one backend name can front two slots whose peers differ, so a per-backend key can
publish one slot's era to the other. That is a tension with the acceptance criterion as written, and
narrowing an acceptance criterion needs the requester's recorded agreement — it is not a repair this
design may make on its own. It was **not** resolved by inventing a generation-tagged cache with
compare-and-swap invalidation at revision 4; a concurrency protocol invented in a late review round
is exactly the shape that produced this round.

Recorded in the askable form the process requires:

> *Does DISCOVER.5's "per backend" mean per backend name, or per pool slot?* — asked of the
> team-lead, 2026-08-31 — **per backend name**, team-lead's call on the full-scope direction,
> **provisional and not operator-confirmed** — closed A2 and fixed the cache key. (The answer was
> given while revision 4 still carried the shared in-flight resolution; revision 5's deletion of that
> repair does not disturb it, as the note below records.)

The reason, stated so it does not have to be quoted from a message: era is a property of the peer
*process*, and every slot of one named backend is dialled from the same configured command or URL,
so a per-slot key would issue one probe per user slot against what is almost always the same remote
— a probe storm bounded only by user count, which is the opposite of what DISCOVER.5's caching
clause exists for. The residual is real and named: one slot's mis-detection is published to its
siblings. That is precisely what DISCOVER.5's re-probe half repairs, and per-slot has no comparable
self-correction to pay for its cost.

Two consequences travel with the answer. Per-backend keying is what *creates* the contention A3
describes — per-slot entries could not contend at all — so the accepted cost belongs to this reading
and would disappear under the other one. And if the operator later says per slot, the change is the
cache key alone: one field, one lookup, and A3 is deleted rather than repaired. Not a redesign.
The plan carries the same provisional status beside its other unconfirmed full-scope reading
(`docs/requirements/RELEASE-4.0.0-plan.md:115`, landed by the team-lead at `fb994c43`). That file is
team-lead-owned; this design does not edit it.

- *Does a pre-`initialize` probe reach an SSE peer?* — read `src/transport/http/mod.rs:200,:327,:434-435,:815-821` and `src/config/mod.rs:1532,:1546` — no: `message_url` is unset until the handshake, and `streamable_http` defaults false — killed the revision-1 placement, which is the whole of revision 2.
- *Does it reach an OAuth peer?* — read `src/transport/http/mod.rs:378-421,:640-645` — no: the token is acquired inside `initialize()` — second, independent kill of the same placement.
- *Does a lazy probe on the tool-call path deadlock?* — read `src/backend/lifecycle.rs:187,:202-207,:209` — no: `ensure_entry_started` early-outs before taking `start_lock` when the transport is connected — withdrew a false rationale; lazy is still rejected, for coverage and permits instead.
- *Does the stdio arm expose the seam this design needs?* — read `src/backend/lifecycle.rs:344,:369` and `src/transport/stdio.rs:246-261` — yes, after connection both arms are in the same match — moved stdio from OUT to FOR, dissolving revision 1's only deferral.
- *Is `Transport::request` re-entrant on session expiry?* — read `src/transport/http/mod.rs:1019-1026` — yes, it can call `self.initialize()` and retry — the probe goes directly to the connected transport, so the branch is never entered from the start path.
- *What timeout can the probe afford?* — read `warmstart.rs:751-759` — 120s attempt, 2s/30s gaps — fixed the probe timeout at 10s, and stated the arithmetic instead of asserting the number.
- *Does anything read the transport-kind snapshot?* — searched `src/` — nothing — removed the field.
- *Is `Transport::request` a safe call for the probe?* — read `src/transport/http/mod.rs:343,:994-1026,:570,:605` and `src/transport/stdio.rs:256,:473` — **no on HTTP** (re-enters `initialize()` on session expiry, and carries the handshake's version and session headers), **yes on stdio** (no re-entry, no header channel) — produced the `probe` primitive in §3a. V (two transports read independently).
- *Does a probe-safe send already exist?* — read `src/transport/http/mod.rs:823,:1011` — yes, `send_request`, which `initialize()` itself uses for exactly this reason; it is private — the primitive exposes what is already there rather than inventing one. V.
- *Is a modern-only peer reachable today?* — read `src/protocol/mod.rs:26,:43`, `src/transport/http/mod.rs:440-452`, `src/transport/stdio.rs:266-269` — no: the outbound handshake offers `2025-11-25` and no 2026 revision is in `SUPPORTED_VERSIONS` — turned both reviewers' first finding into a named accepted limit owned by HEADER.9, not a repair in this increment. V.
- *How does a JSON-RPC error reach the classifier?* — read `src/protocol/messages.rs:45-55`, `src/transport/http/mod.rs:174-176`, `src/backend/metadata.rs:117-118` — as `Ok(JsonRpcResponse)` with `error: Some(..)`, never as `Err` — specified the adapter in §3a, because the naive mapping silently disables the error-code arm. V.
- *Is the 120s attempt figure a ceiling?* — read `src/gateway/server/warmstart.rs:219-221,:46-49` — no, a floor; `effective_attempt_timeout` maxes it against the per-backend budget — corrected the timeout arithmetic. V.
- *Does holding the era lock collapse concurrent probes?* — read `src/protocol/era.rs:143-170,:164-167` — only for cacheable outcomes; `NoAnswer` is not cached, so waiters serialise — downgraded the claim and ranked the cost as A3; revision 5 re-read the same
lines to kill revision 4's repair, because a waiter can only observe the cache after the leader
unlocks, by which time the leader has stored nothing. V.
- *Can a fixture be injected into `start_entry`?* — read `src/backend/lifecycle.rs:302-370` and the existing fixtures at `src/backend/pool_tests.rs:1564`, `src/transport/stdio.rs:781,:849`, `src/transport/http/tests.rs:708` — not as a transport object, but yes through config, which is how the repo already tests start paths — the old test table was withdrawn and rebuilt on that seam. V.
- *Is a pool slot a backend?* — read `src/backend/pool.rs` `PoolKey::PerUser` and `src/backend/lifecycle.rs:821-885` — no; one backend can hold several slots, and a restart replaces the process — keyed the era per backend as a stated assumption (A2) and made `force_restart` invalidate. I (one reading; the trade-off is a judgement, not a measurement).

### Ranked assumptions (DoR G10-G12)

Ranked by impact × uncertainty. Each names the cheapest thing that would falsify it.

| # | assumption | if wrong | cheapest falsifier |
|---|---|---|---|
| A1 | A legacy peer answering `server/discover` with one of the three 2026 codes is unlikely enough to accept, given the correction path | a peer is framed modern for up to one contradiction window | test row 9 is exactly this scenario, run end-to-end; it also *is* the mitigation |
| A2 | ~~Era is a property of the backend, not of a per-user pool slot~~ | — | **promoted out of this table, then answered**: GPT's review made it a question about what DISCOVER.5 requires, which an assumption table cannot settle. The team-lead answered it — per backend *name*, provisional and not operator-confirmed — and the record is under Open questions, not here |
| A3 | Serialised 10s waits on a stalled peer are acceptable versus caching a non-answer or building a waiter registry | N `PoolKey::PerUser` slots of one backend, started inside one 10s window against a stalled peer, each pay 10s | **accepted with a bound, after revision 4's repair was withdrawn.** `warmstart` runs one task per backend, so the ordinary path has nothing to collapse; the cost needs concurrent per-user starts and buys each of them one idempotent request. The two repairs are worse: caching the non-answer pins a healthy peer to Legacy for being briefly slow, and a waiter registry is a concurrency protocol invented in a review round. Falsifier: the `era_probe` `duration_ms` field on `trigger=start` (telemetry above) showing per-user starts of one backend overlapping in production — until then this is a shape, not a measurement. No timing assertion is added: a latency test in CI is a flake with a ticket attached |

Evidence marking used throughout: **V** = two or more independent sources, **I** = one, **A** = none.
Every constraint and every answered question above carries a file:line reading; no claim in this
design is marked A. The one judgement that is not a reading — A2's trade-off — is marked I and
labelled as a judgement.

### Breaking change (DoR C5, DoD D2)

None. The era cache is a new field with a new consumer; no existing signature changes; the `probe`
trait method carries a default body, so every current `Transport` implementation compiles unchanged
and behaves exactly as today (§3a). No config key is added or renamed, no wire format moves, and no
golden in `tests/mik_7217_acs.rs:213` can shift, because the inbound `initialize` result is not
touched. Reversibility (G17): a two-way door — deleting the field and its call site returns the
gateway to Legacy-for-everything, which is what it does today.

## Test plan delta

Revision 2's table is **withdrawn, not amended.** Both reviewers found the same thing and it is
confirmed at source: it could not fail. `start_entry` constructs the transport from the backend's
config (`src/backend/lifecycle.rs:302-370`) and accepts no injected transport, so "drive
`start_entry` against a fixture transport" describes something the code cannot do; "the probe is not
repeated per request" is true trivially when `start_entry` is the only probe site; and the timeout
row asserted `Legacy` against a cache that deliberately never stores `NoAnswer`
(`src/protocol/era.rs:164-167`). A plan whose rows pass for reasons unrelated to the behaviour is
worse than no plan, because it retires the question.

**How a fixture is actually injected**, since that is what killed the old table: through *config*,
which is how this repo already tests start paths. A stdio backend whose command is a shell script
printing canned JSON-RPC frames — the existing pattern at `src/backend/pool_tests.rs:1564` and
`src/transport/stdio.rs:781,:849` — and, for HTTP, a mock server as at
`src/transport/http/tests.rs:708`. No new harness. The probe logic itself is additionally reachable
as a function over `&dyn Transport`, so the classification rows do not need a process at all; only
the wiring rows do.

One row per acceptance criterion, plus the negative rows each positive row needs to mean anything.
Every row names the assertion and why it fails on HEAD.

**Test-plan review verdict (§P2).** Q1 — every acceptance criterion has a covering case: DISCOVER.4
is covered by rows 1-6 (with 4b and 4c on the adapter split), DISCOVER.5 by rows 7-13, checked
against the criterion text at `docs/requirements/RELEASE-4.0.0-criteria-status.md:181-182`. No empty
cell. Q2 — can each named case actually fail: answered per row in the last column, re-attacked as
challenge #4 of the revision-4 dual review, which is where row 5's fixture defect was found, and
re-attacked again in revision 5, which found rows 4 and 5 asserting a `Legacy` that the effective-era
accessor returns for free — both now assert the probe frame, not only the verdict. Three rows (4b, 8,
10) are vacuous on HEAD and are labelled as regression rows in the table rather than counted as
evidence of this increment.

| # | case | asserts | why it fails today |
|---|---|---|---|
| 1 | stdio fixture answers `server/discover` → `Backend`'s era is `Modern` | DISCOVER.4 positive path, stdio | `Backend` has no era field; the read does not compile |
| 2 | HTTP mock answers `server/discover` → era is `Modern` | DISCOVER.4 positive path, HTTP — the arm with the header and re-entry hazards | same |
| 3 | fixture answers the probe `-32022` → era is `Modern` | the error-code arm, reached through the real caller, and the §3a adapter: a JSON-RPC error arrives as `Ok(_)` and must not be read as `NoAnswer` | no caller maps `JsonRpcResponse` to `ProbeOutcome`; with the naive mapping this row fails as `Legacy` |
| 4 | fixture answers `initialize`, then answers the probe `-32601` → **the fixture recorded exactly one `server/discover` frame**, era `Legacy`, `start_entry` returns Ok | a probe the peer *answers negatively* does not fail a start. The frame assertion is load-bearing: `Legacy` is also the effective-era default for a backend that was never probed, so an era assertion alone certifies the accessor rather than the probe | nothing probes, so the frame assertion fails on HEAD — which is the assertion that distinguishes this row from the default |
| 4b | fixture closes the pipe *before* answering the probe → `start_entry` **fails**, and no backend is published | a dead transport is a failed start, not a Legacy backend. Revision 3 collapsed this into row 4 and would have published a corpse as Legacy | HEAD fails the start for its own reasons, so this row cannot fail honestly on HEAD — a **regression row**, labelled like 8 and 10, not evidence of this increment |
| 4c | HTTP mock returns **404 with a peer-authored body** for `server/discover` → `start_entry` returns Ok and era reads `Legacy` | the other half of the adapter split (F1): a peer-authored HTTP error is an *answer*, and `send_request` flattens it to `Error::Transport("HTTP 404")` (`src/transport/http/mod.rs:910-913`), the same shape a dead socket produces. Without this row the natural override fails the start on the commonest legacy answer the default SSE transport gives | nothing probes; once a probe exists, the naive `?` on `probe()` fails the start, and this row catches it |
| 5 | fixture completes the `initialize` handshake, then hangs on `server/discover` → **the fixture recorded exactly one `server/discover` frame**, the probe returns `NoAnswer` at its deadline, `start_entry` returns Ok, era reads `Legacy` | the 10s bound terminates. Revision 3's fixture "accepts the connection and never answers" never reached the probe at all — it dies at `initialize`, so the row certified nothing. The assertion is **termination**, not latency: a broken bound fails by exhausting the harness timeout, deterministically. **Note the assertion is on `Era`, not on the cache**: `NoAnswer` is not stored, so asserting a cached value here is the trap revision 2 fell into, and `Legacy` alone is the un-probed default, which is why the frame count carries the row | no probe, no timeout, nothing to bound |
| 6 | HTTP probe frame captured at the mock → carries neither `MCP-Protocol-Version` nor `MCP-Session-Id`, asserted on **both** the start-path probe and a re-probe frame, **and again with a backend whose `headers` config pins both names in mixed case** | §3a: the probe must not carry the handshake's negotiated version | HEAD inserts both unconditionally (`src/transport/http/mod.rs:570,:605`), so this fails on HEAD *and* fails against a probe naively sent via `Transport::request`, *and* against a probe-mode branch that omits the two names before the configured map is merged over the top (`:607-615`) — the post-condition is on the map that reaches the sender, so the configured variant is the case that pins it |
| 7 | two backends, one Modern fixture and one Legacy fixture, started together → each reads its own era | DISCOVER.5's per-backend caching | no era to read |
| 8 | one backend, probe answered once, then N tool calls → the fixture records exactly one `server/discover` | the era is cached, not re-derived per request | vacuous on HEAD (zero probes); it becomes meaningful only once row 1 passes, and is listed as a *regression* row, not evidence of the increment |
| 9 | cached `Modern`, a request the gateway shaped for Modern returns `-32601` → a probe is issued and the era reads `Legacy` | DISCOVER.5's invalidation clause, in the direction that matters. Without this row a probe-time collision is permanent | neither the invalidation nor a resolver reachable from the request path exists |
| 10 | cached `Modern`, an ordinary tool call returns `-32602` → no probe is issued and the era is unchanged | the trigger set is real; without it row 9 passes on a cache that re-probes on everything | nothing probes, so this row passes vacuously on HEAD — recorded as a regression row, not hidden |
| 11 | a peer that triggers three times inside one 30s window → the fixture records exactly one extra `server/discover`; **then the clock advances past 30s and a fourth trigger produces exactly one more** | the rate limit in both directions. Revision 3 asserted a `Legacy` pin here; the pin is deleted, and the assertion is now on probe *count*, which is what the limit actually constrains. The second half is what stops a limit that suppresses correctly and never re-opens — one corrective probe disabling re-probing for the backend's lifetime passes the suppression half unaided | no bound exists |
| 12 | `force_restart` on a shared stdio slot → era invalidated before the new child is probed | a restart is a new process (`src/backend/lifecycle.rs:821-885`) | no era, no invalidation on restart |
| 13 | a probe against a transport that has since been replaced (`force_restart` completes while the old probe is still in flight) → the late outcome **is discarded**, and the era of the new child is whatever the new child's own probe returned | the transport-identity rule: a probe writes only if its `Arc<dyn Transport>` is still the entry's transport. This is the rule that makes a per-backend cache safe across a restart, and revision 4 cited a row 13 that did not exist | no era, no restart interaction, nothing to discard |

**Rows that cannot fail honestly, recorded rather than dropped.** Rows 4b, 8 and 10 are vacuous on
HEAD: each asserts the *absence* of a behaviour that is absent because nothing exists yet, or a
failure HEAD already produces for an unrelated reason. They are kept as
regression rows and marked as such, and neither is offered as evidence for DISCOVER.4 or
DISCOVER.5. Naming them is the point — an unmarked vacuous row is how a suite comes to certify
nothing.

**Empty cells, as findings.** DISCOVER.4 and DISCOVER.5 each have covering rows, so no criterion is
uncovered. Two behaviours in this design have **no row and no way to get one at this tier**, and
that is recorded here rather than left blank: a modern-only peer (unreachable today — see
constraint 1, owned by HEADER.9, so there is nothing to assert), and the N-waiter serialisation on a
stalled peer (a latency property of `PoolKey::PerUser`, observable only as a timing assertion, which
this plan refuses to add because a timing assertion in CI is a flake with a ticket attached — it is
accepted as A3, and the telemetry specified above is what would show it happening in production). Both are
ranked assumptions below, not silent gaps.

## What this increment does and does not claim

It claims DISCOVER.4 for **both** transports: an era learned by probing, from positive evidence
only, with no path deriving `Era` from the `initialize` result. It claims DISCOVER.5's caching half
outright — per backend, in the type, with the herd collapse the detector was written for. Revision 1
also claimed both only for HTTP; that restriction is gone, not weakened.

The re-probe half is **specified and tested here, and unexercised in production until a peer emits
one of the three 2026 codes**. The invalidation path and its negative case are in the test plan, so the
mechanism is proven by construction rather than by traffic. Revision 1 stated this as a dependency on
HEADER.9; the accurate statement is narrower — it depends on a peer, and HEADER.9 is merely when we
expect to meet one. The criteria file should record it that way.

**For a release reviewer, in one line: the modern-detection arm ships in 4.0.0 untestable against a
real peer.** No 2026 revision is offered by our outbound handshake (`src/protocol/mod.rs:26,:43`),
so no live backend can produce the Modern outcome until MIK-7214.HEADER.9 lands, and that criterion
is ABSENT (`docs/requirements/RELEASE-4.0.0-criteria-status.md:233`). "Accepted limit" reads smaller
than it is. This changes nothing in the design and it does constrain the closure comment: DISCOVER.4
and DISCOVER.5 may be claimed as *specified and proven by fixture*, never as exercised in
production.

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
| F8 | "only a 2026 implementer knows those numbers" overstates what JSON-RPC allows: `-32000..=-32099` is the *implementation-defined* server-error band, so the three codes are not reserved to this revision | **repaired** — "reserved" dropped at all four occurrences; the classifier's evidence is now argued from the narrower bound that does hold (a conforming peer answers an unknown method `-32601`, so a false Modern needs a nonconforming peer). A patch is right because the classifier itself is sound and unchanged — what was wrong was the strength of the claim about it, and false Modern stays the expensive direction. The overstated comment lives at `src/protocol/era.rs:77-79`; it is production code, disposed by riding the implementation increment that already edits that file |

Revision 2's tally: four eliminated, three repaired, one closed on inspection. The four eliminations removed the thing the
finding was about, so those findings can no longer be stated. The three repairs each say above why a
patch is right rather than an elimination. F4 removed nothing: half of it was false at source, and
what survived was kept with a corrected rationale.

## Revision 3 — findings and dispositions

Reviewed by GPT-5.x (`bin/gpt-review`) and by Grok (`bin/grok-review`), same material, revision 2 at
commit `5c7e64f4`. Both returned SHIP-WITH-FIXES. Both raised the probe-after-handshake objection
first, and they converged independently on four of the items below — recorded because agreement
between isolated reviewers is the strongest signal available here. Every claim was verified at
source before any repair; one died on inspection and cost no round.

| # | finding | raised by | disposition |
|---|---|---|---|
| G1 | probing after the handshake cannot discover a modern-only peer | both | **accepted, with the in-scope half repaired** — verified at `src/protocol/mod.rs:26,:43`: the outbound handshake offers `2025-11-25`, so such a peer is unreachable today and this design does not make it so. The half that *is* this design's — the probe carrying the handshake's version and session headers — is eliminated in §3a. Not a ticket: constraint 1 already names HEADER.9 as owner, and a ticket restating an owned limit costs a human's attention for nothing |
| G2 | no probe-safe transport primitive; `Transport::request` re-enters `initialize()` and carries handshake headers | both | **eliminated** — §3a adds one trait method whose contract *is* the probe, defaulting to `request` (correct for stdio, shown at `src/transport/stdio.rs:256,:473`) and overridden on HTTP to the same private `send_request` that `initialize()` uses to avoid its own recursion (`src/transport/http/mod.rs:823,:1011`). Afterwards there is no "which call does the probe use" question left to answer wrongly |
| G3 | invalidation cannot correct a false Modern, and nothing re-resolves from the request path | both, and found here as F9 | **eliminated** — one owner (`classify`) decides contradiction in both directions, fed only by era-conditional answers, with a resolver reachable from a connected backend. Found in this session at `src/protocol/era.rs:91-93`; the reviewers supplied the half this session had missed — that `resolve_with` has no caller outside `start_entry` (`src/backend/lifecycle.rs:202-207`). Bounded in time and pinned to Legacy after a second contradiction, so the fix cannot open a probe loop |
| G4 | the F8 bound is too strong: a legacy peer may own a same-named extension without violating JSON-RPC | both | **repaired** — "nonconforming" narrowed to "unlikely, not forbidden", and the bound now states its dependency on G3's correction path. A patch rather than an elimination because the classifier is sound; what was wrong was the strength of a claim about it |
| G5 | the test plan cannot fail: `start_entry` accepts no injected transport, one row is vacuous, one asserts a value the cache never stores | both | **eliminated** — the table is withdrawn, not amended, and rebuilt on the config-level fixture seam the repo already uses (`src/backend/pool_tests.rs:1564`, `src/transport/http/tests.rs:708`). Every row now names its assertion and why it fails on HEAD; the two rows vacuous on HEAD are marked as regression rows rather than counted as evidence |
| G6 | `NoAnswer` resolutions do not collapse; waiters serialise for 10s each | gpt | **accepted and ranked (A3)** — confirmed at `src/protocol/era.rs:143-170,:164-167`. Not repaired: the repairs are to cache a non-answer, which pins a healthy peer to Legacy for being briefly slow, or to split in-flight sharing from durable caching, which is a change to `era.rs` that this increment does not touch. **Superseded in revision 4 (H7)**, then **restored in revision 5 (F2)**: the in-flight sharing was not expressible in the shape revision 4 wrote it, and G6's original acceptance is what stands |
| G7 | the 120s attempt figure is a floor, not a ceiling, and the retry-gap clause is unrelated | gpt, and grok on the gap clause | **repaired** — confirmed at `src/gateway/server/warmstart.rs:219-221`. The arithmetic is restated against the smallest ceiling the system can produce, and the `initial_gap` comparison is withdrawn |
| G8 | two citations do not resolve: `src/backend/cache.rs`, and `src/backend/mod.rs:200-207` | grok | **repaired** — verified: that file does not exist and those lines are `CleanupState`. Replaced with `src/backend/mod.rs:34,:54` and `src/backend/lifecycle.rs:134` |
| G9 | the `JsonRpcResponse` → `ProbeOutcome` adapter is unspecified, and the obvious implementation disables the error-code arm | grok | **repaired** — specified in §3a, with test row 3 written to fail on exactly that mistake. Confirmed at `src/protocol/messages.rs:45-55` and `src/transport/http/mod.rs:174-176` |
| G10 | a restart replaces the peer, and a `PerUser` slot is not the backend | grok | **repaired** — `force_restart` invalidates (`src/backend/lifecycle.rs:821-885`), and per-backend keying is now a stated, ranked assumption (A2) instead of an unexamined use of the word "backend" |
| G11 | no V/I/A marks, no ranked assumptions, no breaking-change assessment | gpt | **repaired** — evidence marks on every answered question, three ranked assumptions with falsifiers, and a breaking-change plus reversibility statement |
| G12 | "exposes only `Transport::request`" | gpt, as G2's premise | **closed on inspection** — `src/transport/mod.rs:39` also exposes `request_with_headers` and `:66` `carries_identity_headers`. The premise is false; G2's conclusion is not, and is repaired on its own merits. No round spent |
| G13 | record probe outcome, duration, cache hit and invalidation reason as telemetry | gpt (improvement) | **accepted into scope** — the counters ride the implementation increment; A3 depends on the start-latency metric existing, so this is not decoration |

Revision 3: three eliminated, six repaired, three accepted with owners, one closed on inspection.
The eliminations are the ones that matter — after G2, G3 and G5 the findings they answer cannot be
restated, which is the test applied here rather than whether the objection was addressed.

## Revision 4 — findings and dispositions

Both revision-3 reviewers returned SHIP-WITH-FIXES. Seven findings and two improvements from GPT,
three findings and three improvements from Grok, plus four found in this session before the reviews
returned. Four of the ten reviewer findings are defects in revision 3's *own repairs* — that is the stuckness signal, and per
repair-protocol step 0 the answer taken here is elimination, not another patch: the classifier's
input rule and the Legacy pin are deleted, and the two facts revision 3 got wrong are corrected.

Counted honestly, because the target was the opposite: the design body grew from 479 lines to 538.
Two *rules* were deleted — the "era-conditional" input restriction and the Legacy pin — and the
mechanism they governed is simpler than it was. The added lines are record, not machinery: a
deferral and the decision that closed it, a disambiguation that stops a re-checker reaching the wrong constant, one test
row split into two, and this table. A design document that grows every round is a signal worth
watching even when each addition is defensible; it is recorded here rather than rounded away.

**Disclosure about the review brief (integrity).** Revision 3's brief told both vendors *not* to
re-raise "probing after the handshake cannot reach a modern-only peer", because it was closed at
source. A SHIP on a fenced item is silence I asked for, not confirmation, and must never be read as
agreement. GPT raised it anyway, as its first finding — so on this one item there is a real verdict,
recorded below. The revision-4 brief drops the fence.

**The process finding, stated so no one re-adds a fence.** A fence suppresses exactly the item most
worth hearing, and the evidence is in this round: the fenced item **died at source** the moment a
reviewer ignored the instruction — the requirement it quoted does not exist. Had both vendors
obeyed, that error would have survived the round wearing two SHIPs. A brief may hand a reviewer
evidence ("this was verified at `<file:line>`, here is what was found"); it may not tell a reviewer
what not to say. Evidence narrows a finding on its merits; a fence narrows the record.

| # | finding | vendor | disposition |
|---|---|---|---|
| H1 | probing after `initialize` violates DISCOVER.4, which "explicitly requires probing first" | gpt (fence breached) | **died at source** — DISCOVER.4's text (`docs/requirements/RELEASE-4.0.0-criteria-status.md:181`) requires the gateway to *detect* the era by attempting `server/discover`; it prescribes no ordering relative to `initialize`, and the quoted requirement does not exist. Worth more than a quiet SHIP: a reviewer told to leave the item alone reached for it regardless and got the criterion wrong, which is the strongest evidence available that the disposal holds. The reachability half stays an accepted limit owned by HEADER.9 |
| H2 | the HTTP probe still constructs both forbidden headers, because `send_request` builds them | gpt | **repaired, and it was self-contradiction** — `build_headers` inserts both unconditionally (`src/transport/http/mod.rs:570,:605`); revision 3's own test row 6 cited those lines while §3a claimed a subtraction. §3a now names the decision — the builder takes a mode, the probe passes the probe mode — without designing the spelling |
| H3 | "era-conditional" is not an operational definition; an ordinary answer can classify | gpt + grok, independently | **eliminated** — `classify` is fed only `ProbeOutcome`. An ordinary answer can *trigger* a probe and nothing else, so the term is deleted rather than sharpened. After this the finding cannot be restated: there is no definition left to misapply, and a wrong trigger costs one rate-limited probe, never a misclassification |
| H4 | the Legacy pin strands a peer that triggers twice for unrelated reasons | gpt + grok, independently | **eliminated** — the pin is deleted. With H3's cut the loop it was bounding cannot form; the ≤1 probe/30s rate limit is the whole bound |
| H5 | one backend-wide era spans per-user slots whose peers may differ | gpt | **raised as a requirements question, answered by the team-lead the same day: per backend name, provisional** — DISCOVER.5 says "cached per backend" and only the requester can say whether that means per name or per slot. Explicitly *not* resolved by adopting GPT's generation-tagged compare-and-swap cache: inventing a concurrency protocol in a late review round is the move that produced this round. The reasoning, the residual and the one-field reversal cost are recorded under Open questions. Revision 4 called A3's repair load-bearing under the answer given; revision 5 withdrew the repair (F2) and the answer stands unchanged — per-backend keying is what creates the contention, and the contention is accepted |
| H6 | treating a closed pipe as `NoAnswer` and still returning Ok publishes a dead transport | gpt | **repaired** — split into test rows 4 and 4b: an *answered* negative probe does not fail a start; a transport that died before answering fails the start on its own terms |
| H7 | uncached `NoAnswer` serialises N waiters at 10s each | gpt | **repaired in revision 4, and the repair is withdrawn in revision 5 (F2)** — sharing an in-flight future is not expressible while the mutex is held across the await, so the repair could not be built as written. A3 returns to an accepted, bounded cost |
| H8 | test row 5 cannot go green: the fixture dies at `initialize`, never reaching the probe | grok | **repaired** — the fixture now completes the handshake and hangs on `server/discover`. The assertion is termination plus `Legacy`, not latency; a broken bound fails by exhausting the harness timeout |
| H9 | `probe()` has no timeout in its contract | grok | **repaired in revision 4, and the repair moved in revision 5** — a deadline in the default body binds only the transports that inherit it, and HTTP is the one that overrides. The deadline now sits in a non-overridable wrapper around the overridable primitive |
| H10 | make `probe` mandatory rather than silently defaulting | gpt (improvement) | **rejected, with the reason** — a mandatory method breaks every current `Transport` implementation and turns a non-breaking change into a breaking one (C5/D2). The hazard it names is the unbounded wait, and H9 closes that directly. Websocket inheriting a correct default is the desired outcome, not a silent failure |
| H11 | add a DISCOVER.4 negative row | grok (improvement) | **already covered** — row 4 as rewritten *is* that case: the peer completes `initialize` and answers the probe `-32601`, and the era must read `Legacy`. No row added |
| H12 | apply row 6's header assertion to the re-probe frame, not only the start-path probe | grok (improvement) | **accepted** — one clause in row 6. The re-probe reuses the same primitive, and an assertion that only covers the start path would not notice if it stopped |
| H13 | record the `force_restart`/`PerUser` interaction | grok (improvement) | **folded into H5** — it is the same question about the cache key, and answering it twice in two places is how two answers drift apart |
| H14 | add deterministic generation-race and cooldown tests on a controllable clock | gpt (improvement) | **superseded by H3 and H4** — the generation race was GPT's own compare-and-swap cache, which is not adopted, and the cooldown it would exercise is the deleted pin. What survives is the ≤1 probe/30s rate limit, and test row 11 asserts it by probe count |
| S1 | a re-checker finds `MODERN_VERSIONS` and concludes the modern-only limit is wrong | self | **repaired** — the limit paragraph now names `src/protocol/meta.rs:219` as inbound-only, read by the router at `src/gateway/router/handlers.rs:178,:222,:575,:702` and by nothing outbound |
| S2 | a fenced item's SHIP read as reviewer confirmation | self | **disclosed above, and the fence is dropped for revision 4** |
| S3 | the §P2 test-plan review verdict was not recorded | self | **repaired** — Q1 and Q2 are answered in a note under the test table, with the criterion citation |
| S4 | row 5 asserted latency where A3 refuses latency assertions | self | **superseded by H8** — Grok found the deeper defect (the fixture never reaches the probe); row 5 is rewritten around termination, and the inconsistency goes with it |

Revision 4, counted from the table above: two eliminated, seven repaired, one died at source, one
answered by the lead, one rejected with its reason, one improvement accepted and applied, one
disclosed, four folded or superseded — eighteen rows. The eliminations are again the ones that
matter: after H3 and H4 the classifier has one input type and one bound, and neither finding can be
restated.

A revision-5 dual review was run after all. The paragraph that stood here said none would be, on the
argument that revision 3's repairs generated four of revision 4's findings and the exit from that
pattern is a receipt rather than another round. That argument was about *rounds*, and it was applied
to a round that had already been dispatched; the reviews came back, and a returned review is evidence
whatever the plan said. Its findings are below. The reasoning it replaced was not wrong about the
pattern — it was wrong that declining to read a review is a way out of it, and the round it produced
found two HIGH defects in revision 4's own repairs, which is the pattern, observed rather than
argued about.

## Revision 5 — findings and dispositions

Sources: `gpt-review` (six findings, three improvements) and `grok-review` (four findings, one
improvement), run on identical material. Both verdicts are `SHIP-WITH-FIXES`, read from the ledger
rows (`gpt-20260901T143023Z-25724.md`, `grok-20260901T143023Z-25722.md`) and both exit statuses,
not scraped from the transcripts. `gpt-review` read revision 4 as frozen; `grok-review`'s log records
that the file changed under it and that it re-read the then-current text in full, which is why F12
critiques a sentence revision 4 did not contain. Both name the adapter's treatment of a dead
transport.

| # | finding | from | disposition |
|---|---|---|---|
| F1 | the adapter maps a transport that died during the probe to `NoAnswer` and a successful Legacy start, and separately, mapping every `Err` to fatal would fail the start on a peer-authored HTTP 404 — the commonest legacy answer | both | **repaired, and the reason it is a patch: the mechanism is sound and the defect is one missing distinction.** `Err` splits by authorship — an error the peer wrote is an answer, silence is an answer, a connection that is gone is fatal. The table in §3a enumerates the four cases, and rows 4b and 4c are the two sides |
| F2 | shared in-flight resolution has no invalidation-versus-commit ordering, so a probe against the old peer can repopulate the cache after `force_restart` invalidated it | gpt | **eliminated.** Revision 4 added the sharing to repair A3; a waiter can only observe the cache after the leader releases the lock, and the leader stores nothing on `NoAnswer`, so the mechanism could not do its job under this lock discipline in the first place. Deleting it also deletes the ordering question, and A3 returns to an accepted cost with a stated bound and a falsifier. The generation-tagged state machine the finding proposed is a concurrency protocol invented in a review round, to protect a mechanism that should not exist |
| F3 | the transport-identity rule cites test row 13, which is not in the plan | grok | **repaired** — the row is added. A rule whose only proof is a citation to a row that does not exist is a rule nothing can fail |
| F4 | probe-mode omission of the two reserved headers can be undone by the configured header map, merged unconditionally afterwards | gpt | **repaired** — the rule was already stated as a post-condition on the map that reaches the sender (`src/transport/http/mod.rs:607-615`); what was missing was the case that pins it. Row 6 now runs again against a backend whose config sets both names in mixed case |
| F5 | rows 4 and 5 assert `start_entry` Ok plus era `Legacy`, which is the effective-era default this design adds, so both go green without a probe ever being issued | grok, gpt (improvement) | **repaired** — both rows assert the fixture recorded exactly one `server/discover` frame. This is the second time a row in this plan asserted a value the system produces for free; the general form is that an assertion equal to the default is not an assertion |
| F6 | the re-probe rule classifies outcomes with a second mapping that contradicts `classify()`: a 2026 error code reads Legacy, an envelope reads Modern | grok | **eliminated** — the paraphrase is deleted and the re-probe path calls `classify()` unchanged. Revision 4 believed it had closed "two classifiers" by feeding `classify` only `ProbeOutcome`; it then wrote a second classifier longhand in another section. A dual-era peer answering `-32022` would have been pinned Legacy with no way back |
| F7 | the design does not decide whether a request-triggered re-probe is awaited or detached | gpt | **repaired by deciding it** — detached, tracked, cancelled at shutdown, owning a clone of the transport `Arc`; the triggering caller gets its original response and the *next* request sees the corrected era. A decision the design did not make is one an implementer makes four times, differently |
| F8 | the rate-limit row checks suppression inside one window but never that probing becomes eligible again after it | gpt | **repaired** — row 11 gains a second half on a controllable clock. A limit that suppresses correctly and never re-opens passes the first half unaided |
| F9 | the H7 single-flight repair has no test | gpt | **died at source** — F2 removes the mechanism, so there is nothing to test. Recorded rather than dropped, because the finding was correct against the document it read |
| F10 | remove the stale statements that `NoAnswer` waiter serialisation is still an accepted assumption | gpt (improvement) | **inverted by F2, and applied in that direction** — with the repair withdrawn, serialisation *is* the accepted assumption again, so the statements are made consistent by restoring A3 rather than by deleting them. §P0, the open-questions paragraph, the lead's answer, the A3 row and the H7 row all now say the same thing |
| F11 | enforce the 10s deadline in a non-overridable wrapper rather than in the trait default | gpt (improvement) | **accepted** — the transport that overrides `probe` is exactly the one that needs the bound, and it was the one inheriting nothing. HTTP would have waited the configured client timeout instead (`src/config/mod.rs:1386`) |
| F12 | the revision-5 claim that shared in-flight resolution is unbuildable is too strong: `CachedMetadata` already drops the lock and waits on a watch channel | grok (improvement) | **accepted, and the claim is narrowed** — it is unbuildable *as revision 4 wrote it*, holding the mutex across the await. A watch-channel spelling exists in this repo. That does not restore the mechanism: F2's disposal rests on the cost being acceptable and bounded, not on the repair being impossible, and a buildable repair to an unnecessary mechanism is still unnecessary |

Revision 5, counted: two eliminated, six repaired, one died at source, three improvements accepted —
twelve rows. Both eliminations are in revision 4's own repairs, which is the argument for reading a
review you have decided not to need.

**One question this design cannot settle.** `docs/requirements/RELEASE-4.0.0-test-plan.md:60-68`
still describes the era probe as *built but not issued at backend startup* — true when it was
written, untrue as of this design, which issues the probe inside `start_entry`. The design has a
standing rule that `RELEASE-4.0.0-plan.md` is the team lead's and is not edited from here; whether
the sibling test-plan file falls under the same rule is not settled by anything read for this
increment, so the correction is **not** made here. It is named for the lead as an owned reconciliation
rather than filed as a ticket: it is one paragraph in a file whose owner is a person, not a decision
anyone needs to make twice.
