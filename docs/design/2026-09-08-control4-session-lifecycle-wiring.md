# CONTROL.4 — wiring `SessionLifecycle` on the 2026 path (design v2, §P1)

Rulings: `docs/release/2026-09-08-team-lead-rulings.md` §R3 (`8bbca3eb`, wire it, do not delete
it) and §R3a (`a445cf92`, which names the host, the key and the precondition). v1 of this
document predates R3a and is superseded in four places; the deltas are recorded inline, not
silently reinterpreted. NO CODE EXISTS YET.

## Problem

MCP 2026-07-28 removed protocol sessions. `SessionLifecycle::on_disconnect` fired on a transport
close the 2026 path no longer has (`src/gateway/session_lifecycle.rs:26-31`), so every registered
cleanup handler would never run and everything it reclaimed would leak, silently — nothing errors
when a callback is not called. The module already carries the replacement mechanism (`track`
:107-109, `untrack` :115-117, `reap(now)` :124-142) and it is reached from tests only (:80-81).

## Measured constraints

| fact | evidence |
|---|---|
| the state a reaper must reclaim is `last_tool`, keyed per identity | `last_tool: DashMap<String,String>` `src/security/firewall/anomaly.rs:50`, written at `:153` |
| the write happens inside `score_transition`, called one frame up by `observe` | `observe` `anomaly.rs:95`, `Observation::Scored(self.score_transition(...))` `:99` |
| an empty identity never reaches the write | `observe` returns `Observation::Unobservable` at `:97` before scoring |
| `observe` is called from the firewall's request check | `src/security/firewall/mod.rs:398`, inside `pub fn check_request(` `:352` |
| the key is `control_identity`, computed by the caller | `let anomaly_identity = (!control_identity.is_empty()).then_some(control_identity);` `mod.rs:395`, with a 15-line rationale `:380-394` |
| on the 2026 path that value IS the owner key | `handlers.rs:1298-1302`: `session_id` is empty there, so `control_identity = session_owner_key(client)` |
| the second caller passes a synthetic, bounded key | `backend_handlers.rs:97`: `format!("direct:{backend_name}")`, one per configured backend |
| a live TTL loop already exists and is the named host | `spawn_reaper_on` `src/gateway/streaming.rs:113-125`, tests `:647-737` |
| the firewall is already shared by `Arc` | `pub firewall: Option<Arc<Firewall>>` `src/gateway/router/mod.rs:112` |
| a comparable per-user TTL already ships | `PER_USER_IDLE_TTL = 300s`, `SWEEP_INTERVAL = 60s`, `src/gateway/server/mod.rs:2127-2128` |

**F1 — "the gateway's existing maintenance tick" has a referent after all.** §R3 and
`RELEASE-4.0.0-blocking-rollup.md:596` name a tick that `rg` finds nowhere; v1 concluded the
phrase had to be read as a shape. R3a resolves it by naming `streaming.rs:122`. F1 stands as a
correction to the rollup's wording, not as a design freedom.

**F2 — both write sites are gated twice, and R3a does not name this.** The `check_request` calls
sit under `#[cfg(feature = "firewall")]` (`handlers.rs:1284`, `backend_handlers.rs:95`) *and*
under `if let Some(ref fw) = state.firewall` (`:1285`, `:96`). `firewall` is in `default`
features, so a stock build populates the map. A `--no-default-features` build, or firewall
disabled by config, writes nothing to `last_tool` — and therefore nothing needs reaping. The map
being empty there is correct, not a leak; what it is not is evidence. §P2 must enable the feature
to observe anything, and no test may read an empty map as a pass.

## Decisions

**D1 — host: the existing streaming reaper loop. v1's `spawn_lifecycle_reaper` is DEAD.**
R3a forbids a second maintenance loop, so `spawn_reaper_on` (`streaming.rs:113`) gains one more
line inside its tick: `lifecycle.reap(now_unix())` beside `mux.reap_expired_sessions(ttl)`. The
loop already survives multiplexer death by `weak.upgrade()`, already skips missed ticks, and is
already tested at `:647-737`. Nothing new is spawned.

**D1a — how the loop reaches a `SessionLifecycle` (a decision R3a did not make; named per §P3).**
`spawn_reaper_on(self: &Arc<Self>)` takes no collaborators today and the multiplexer owns none.
Two shapes:
(a) a parameter — `spawn_reaper_on(&self, lifecycle: Arc<SessionLifecycle>)`, captured by the
spawned task. Every call site (`server.rs`, `webhooks.rs`, `proxy.rs`) must supply it, so the
compiler enforces that no caller silently gets a reaper-less loop.
(b) a field on the multiplexer, set at construction.
**Chosen: (a).** It adds no state to a type whose state is its session map, and the enforcement
is free. Not an `Option`: a `SessionLifecycle` with no tracked keys already reaps nothing, so the
null object costs one uncontended read per tick and removes a branch that could be wrong.
The single instance is created at gateway startup and stored beside `firewall` on the router
state, which is what lets the write site reach it (D4).

**D2 — clock: `u64` seconds since the Unix epoch, stated in the API doc, produced by one helper.**
`track(_, expires_at: u64)` / `reap(now: u64)` document no epoch or unit today, and three ACs pass
bare literals (1_000/5_000/2_000/6_000). Rejected: `Instant`/`Duration` — it changes a public
signature three ACs bind to, and cannot be logged, persisted or compared across a restart. The
unit seam against streaming's `Instant` is contained to one `SystemTime::now()` inside the tick.
Wall-clock jump is the accepted cost: backwards delays a reclaim, forwards reclaims early; both
touch derived state only (D5).

**D3 — key: `control_identity`, re-derived at the write site, NOT `session_owner_key` asserted
directly.** R3a's rule is "key on whatever `last_tool` is keyed by". That is the `session_id`
parameter of `score_transition`, which is `anomaly_identity`, which is `control_identity`
(`firewall/mod.rs:395`). On the 2026 path `session_id` is empty so `control_identity` resolves to
`session_owner_key(client)` — v1's conclusion, reached by the wrong route. Taking the value from
`control_identity` keeps the two keys equal by construction if that chain ever changes.

**D3a — DELETED. The empty-identity rule is already owned one layer down.**
v1 proposed reusing `unattributed` (`handlers.rs:1013`) to refuse tracking anonymous callers.
`observe` returns `Unobservable` for an empty identity and never writes (`anomaly.rs:95-99`), so
tracking exactly where the write happens inherits that rule. Reusing `unattributed` would create a
second rule about empty keys that can disagree with the first. Elimination, not a patch: after
this cut the finding "two components can disagree about which callers are trackable" cannot be
stated.

**D4 — write site: adjacent to `check_request` in `handlers.rs`, guarded on the same emptiness
test. v1's `handlers.rs:1013` is SUPERSEDED.** `control_identity` is computed at `:1298-1302`,
285 lines away from v1's site and inside the firewall gate; `:1013` is neither the same value nor
the same gate. One `track(control_identity, now + IDLE_TTL)` next to the `check_request` call
(`:1303`), under `!control_identity.is_empty()`, mirrors `observe`'s own guard.
Rejected: tracking inside `AnomalyDetector` at the literal `DashMap` insert. It covers both
callers by construction, but injects `SessionLifecycle` into an EE-licensed security module and
changes its constructor. R3a's contrast is *write site vs session open*, not *inside the insert*;
the handler site is the same request, the same key, adjacent to the write.
`backend_handlers.rs:102` is deliberately NOT a track site: its key is `direct:{backend_name}`,
one per configured backend, so the set is bounded and there is nothing to reclaim — and reaping it
would make the next direct call score as a first call, which is the signal the detector exists to
notice.

**D5 — reap is unconditional; the constraint moves onto what a handler may reclaim.** Streaming
guards with `receiver_count() == 0` (`:135`); an identity key has concurrent in-flight requests,
so no analogue exists. A handler registered here MUST be safe to fire while a request for the same
key is in flight — it reclaims derived, rebuildable state, never state a live request depends on.
`remove_session` (`anomaly.rs:189`) qualifies: it drops one `last_tool` entry, and the next call
for that identity scores as a first call, exactly as it does after the `MAX_TRACKED_IDENTITIES`
ceiling evicts it (`:138-149`). Rejected: a lock or an in-flight counter — new machinery to
protect a class of handler being declared out of bounds anyway.

**D6 — TTL: `IDLE_TTL` 300s, ONE module constant, carried as a STATED ASSUMPTION.** Matches the
shipped `PER_USER_IDLE_TTL` (`server/mod.rs:2127`). There is deliberately no lifecycle
`SWEEP_INTERVAL`: D1 rides the streaming reaper's existing loop, so the cadence is already owned by
streaming's `session_reaper_interval` config knob and a second constant beside it would have no
reader — a dead value that reads as a scheduling authority. (v2 GPT improvement, confirmed by
construction: with D1 as the host, nothing could ever read it.) Streaming's `session_ttl` is
likewise NOT collapsed in — `IDLE_TTL` governs only what `track` writes as a deadline.
**Nominal reclaim latency is therefore `IDLE_TTL + session_reaper_interval`, not 60 seconds.** Nominal,
not exact: `reap`'s strict `>` on whole seconds adds up to a second, a loaded runtime delays the tick by
an amount this design does not bound, and a wall-clock step moves the deadline after it is written. §P2
asserts against the INGREDIENTS of that figure — the write site's arithmetic and both constants — never
against a measured latency; see the composition table in the test plan. Writing 60s anywhere would promise a sweep cadence this
design does not own. (v2 kimi FINDING, MEDIUM/LIKELY/NOW — the same defect GPT raised independently.) Thirty seconds would hold less abandoned state under churn; an
hour would never lose a long human-in-the-loop elicitation. Nobody has ruled.

**D7 — observability: one `info!` per sweep that reclaimed anything, carrying the count — and
`reap` changes signature to `pub fn reap(&self, now: u64) -> usize` to supply it.** Matches streaming
(`:138`, `:145-149`). The signature change is not cosmetic: `reap` today returns `()`
(`session_lifecycle.rs:124`), so the only other way for the caller to log a count is to read
`tracked_count()` before and after, and that difference is wrong whenever a live request tracks a key
between the two reads. The count already exists inside `reap` as `expired.len()`; returning it is
strictly smaller than the racy alternative. (v2 GPT improvement, confirmed at source.) Per-key
`debug!` already exists (`session_lifecycle.rs:87-95`). No new metric until an operator asks a
question the log cannot answer.

### Findings carried in from the v2 review

**Reviewed baseline, disclosed.** Both v2 verdicts rendered on `55ee043d`. Everything folded in
below, and the D6 reclaim-latency correction at `a6616d5c`, landed AFTER that commit — so the
sentence "the design passed both legs" is true of `55ee043d` and overstates the tree by the repair
commits that followed. Per §R11 those repairs are the confirmation pass, not a new review: they
apply what both legs specified. The in-flight closure re-check goes back to kimi, the vendor that
raised the finding, which is the one place the author does not get to declare a finding closed.

**Observation on the review ledger, no action.** A `synthetic-review` row records no model. A kimi
leg and any other synthetic-model leg are indistinguishable in `~/.claude/data/reviews/runs/`, so
the row above cannot prove on its own that the second vendor was kimi — the provenance rests on
the wrapper (`bin/kimi-review` execs `synthetic-review --model kimi-k3`) plus the run timestamp.
Recorded, not filed: it is a defect in our tooling and nobody must act on it today.


GPT-5.x returned **SHIP** with zero FINDING blocks and four distinct improvements
(`~/.claude/data/reviews/runs/gpt-20260908T133849Z-53568.md`). Three are folded in above and here.
One is rejected, with its reason, because a finding is a lead until it survives its own citation.

**Delete the lifecycle `SWEEP_INTERVAL` (ACCEPTED).** Folded into D6 above.

**Return the expired-key count from `reap` (ACCEPTED).** Folded into D7 above.

**Name the integration test that proves real reclamation (ACCEPTED, and it is the §P2 entry F2 was
already demanding).** The plan must specify one case running with the `firewall` feature compiled in,
`security.firewall.enabled = true`, and `anomaly_detection = true`, against a key with a populated
predecessor entry — and it must assert the entry is GONE, not that `tracked_count` fell. F2 says why:
both write sites are gated twice, so a build with the feature off produces an empty map that is
correct and proves nothing. This is the §P2 row, recorded here so the plan cannot be written without
it.

**Track only when `verdict.anomaly_score` is `Some` (REJECTED — two reasons, both checked).** Its
cited site is wrong: `server/mod.rs:1210` is where the `Firewall` is *constructed*
(`Firewall::from_config`), not a `check_request` call. The only two production call sites are
`handlers.rs:1303` (D4's site) and `backend_handlers.rs:102` (ruled out under D4). More materially,
the predicate is too tight. `anomaly_score` is `None` in two different situations
(`firewall/mod.rs:398`, `and_then`): the detector is absent, and the detector is present but
`observe` returned `Unobservable`. `on_session_end` (`firewall/mod.rs:682`) is a no-op only in the
first. Gating on `anomaly_score.is_some()` would therefore skip the second and leak exactly the
entry the handler exists to remove. The guard stays `!control_identity.is_empty()`.

The residual GPT was reaching for is real and is already stated: when anomaly detection is off, the
map holds keys whose handler reclaims nothing. That is a no-op, not a leak, and the accepted
improvement above is what stops it being mistaken for a passing test.

**Kimi returned SHIP-WITH-FIXES** (`~/.claude/data/reviews/runs/synthetic-20260908T133850Z-53762.md`;
the `synthetic-` prefix is expected — `bin/kimi-review` is a shim that execs `synthetic-review
--model kimi-k3`). Its one gating finding is the SAME dead `SWEEP_INTERVAL` GPT raised, arrived at
independently. Both legs converging on one defect is why it is fixed above rather than argued with.

**No cardinality bound on the tracked set (kimi FINDING, LOW/POSSIBLE/BEFORE-PRODUCTION).
ACCEPTED AS A STATED BOUND, NOT A MECHANISM.** `SessionLifecycle`'s map is written at the same site,
from the same unbounded identity keyspace, that motivated `MAX_TRACKED_IDENTITIES` in the anomaly
detector (`anomaly.rs:138-149`) — but it is not the same map and does not get a second ceiling. A
ceiling here would be a second eviction rule that can disagree with the anomaly one, which is exactly
why D3a was deleted. The bound is TEMPORAL and is stated instead: **the map holds at most the
distinct control identities seen in one `IDLE_TTL + session_reaper_interval` window**, because every
key carries a deadline and `reap` removes it unconditionally (D5) — at the FIRST SWEEP AFTER the
deadline, never at the deadline itself. That is the same arithmetic as D6's reclaim latency, and it
is stated here rather than as `IDLE_TTL` alone because the correction applies at both sites: an
earlier draft of this paragraph said one `IDLE_TTL` window and was wrong by exactly one sweep.

The second term is NOT OURS, and that is the honest weakness of this bound. `session_reaper_interval`
is `StreamingConfig`'s field (`src/config/features/streaming.rs:37`), read by the host loop at
`src/gateway/streaming.rs:108`, defaulting to 60 s (`src/config/features/streaming.rs:14`) — with NO
validation and NO ceiling: `rg session_reaper src/config/` returns the declaration and the default
and nothing else. An operator who sets it to an hour widens this map's window to an hour, and no
code in this change can refuse that. So the claim is `IDLE_TTL + <an interval the gateway operator
owns>`, not a number. It is still refused a ceiling for the reason above — a second eviction rule
that can disagree with the anomaly one — and the residual is now stated at its true size rather than
understated by a sweep — and that stated bound is the whole resolution. An earlier draft closed this
paragraph by saying a ceiling "becomes a design event if the cardinality is ever measured to be the
problem"; the kimi closure pass killed it as the exact non-state §P1 forbids — a named risk with
nobody scheduled to take the measurement that would trigger it. Deleted rather than converted to a
deferral, because a deferral needs an owner, a trigger and a fallback and this had none of the
three: no one is watching this number, and implying someone was is what made the sentence a defect.

**Name the observable the §P2 test asserts on (kimi IMPROVEMENT, converging with GPT's).** The plan's
case asserts the reclaimed thing is GONE — the predecessor `last_tool` entry absent after the sweep —
never that `tracked_count` fell. `tracked_count` falls whether or not a handler ran, which is the
vacuous pass F2 warns about.

**Put D5's handler-safety rule at the API surface (kimi IMPROVEMENT, accepted).** One doc-comment
precondition on `SessionLifecycle::register`: a handler may only reclaim state whose loss is
indistinguishable from an eviction. U2 defers the rule's enforcement to the second registration; a
line on `register` is what the next handler's author will actually read.

**Pre-evaluate D1a shape (b) so U3 cannot force a third round (kimi IMPROVEMENT, accepted —
and SPENT UNUSED).** The fallback was shape (b), the `Arc<SessionLifecycle>` held as a multiplexer
field set at construction, needing no new call sites. U3 came back (a), so it is not taken. The
improvement still did its job: it made the answer resolve straight to code either way, which is
the only thing a pre-evaluation is for. Recorded, not deleted, so a later reader can see that (b)
was considered and why it lost rather than that it was never weighed.

### Findings carried in from the v1 review (both legs returned SHIP)

**Monotonic seconds, rejected (GPT, IMPROVEMENT).** "Monotonic seconds can retain the existing
`u64` signatures" and would remove the wall-clock hazard. It also needs a process-start `Instant`
reachable from both the write site and the tick — a new shared origin, i.e. a global — and it
makes the logged deadline meaningless to an operator comparing it against anything else. The
hazard it removes moves a reclaim by the size of the jump, and by D5 a reclaim touches only
rebuildable state. D2 stands; the trade is recorded rather than re-litigated.

**The re-track race is now REACHABLE, and it is closed by argument, not by machinery (Kimi,
MEDIUM).** `reap` collects expired keys under the write lock, removes them, then fires handlers
outside it (`session_lifecycle.rs:124-142`), so a live request can re-`track` a key between its
removal and its handler firing. Kimi's SHIP rested on "not reachable until a handler registers" —
U1 now registers one, so the premise is gone and the finding is live.
It is not a defect **for this handler class**. `Firewall::on_session_end` drops one `last_tool`
entry; the identity's next call then scores as a first call. That is bit-for-bit what already
happens whenever `MAX_TRACKED_IDENTITIES` evicts an identity (`anomaly.rs:138-149`) — a routine
production event the detector is built to absorb. D5's rule is exactly what makes the race
harmless: a handler may only reclaim state whose loss is indistinguishable from an eviction.
Rejected: a per-key generation counter re-checked before firing. It buys nothing for a handler
class that is already eviction-tolerant, and it would be the second mechanism claiming to decide
when a key is live. Recorded as a NAMED RESIDUAL: the first handler that is *not* eviction-tolerant
re-opens D5 (U2), and D5 is the gate that must refuse it.

## Scope (§P0)

FOR: the mechanism reaches production on the 2026 path — the existing streaming tick reaps,
one write site tracks, one real consumer is registered, the clock and TTL are documented.

**Receipt — the surface moved on 2026-09-08 (§P0 freeze).** v1 put "registering the four named
consumers' handlers" entirely OUT. R3a answered U1 with option (b): at least one real consumer
must be registered, and named it — `Firewall::on_session_end` (`src/security/firewall/mod.rs:682`,
whose only caller today is a test at `:1062`). That one consumer moves IN. The other three (cost
governance, tool profiles, semantic-search feedback) stay OUT. Reason: a reaper over a map no
production path reads is the fourth unreachable mechanism this plan exists to avoid, and R3a made
that a precondition on the design rather than a follow-up.

OUT: the other three named consumers; deleting `SessionStore`; `CostTracker::evict_old_records`
(`src/cost_accounting/mod.rs:572` — also dead, also unhosted, adjacent but not this change);
tracking at `backend_handlers.rs:102` (D4); and everything inside the keep-out fence
(`src/backend/lifecycle.rs` ~375-380, the HTTP startup and era-probe path, `src/backend/era.rs:99`).

**`on_disconnect` stays unreached, deliberately.** With this change `register`, `track` and `reap`
gain production callers; `on_disconnect` (`:62-67`) does not, because the 2026 path has no
disconnect to fire it — that is the whole premise of R3a. It remains a deletion candidate under
MIK-7291, named here so the WIRED trail does not quietly claim every symbol in the module.

**Loop lifetime, answered by the chosen host.** The reaper task ends when the multiplexer is
dropped — `weak.upgrade()` returns `None` and the loop breaks (`streaming.rs:118-124`). No
shutdown channel is added, and the lifecycle reap inherits that termination unchanged. (Raised
against v1's rejected host; it re-attaches to any host and is answered here.)

## Scheduled open questions (§P1)

**U1 — does CONTROL.4 close with zero handlers registered? — ASKABLE. RESOLVED.**
Asked of: the team lead. Answer (§R3a): no — at least one real consumer must be registered, and
the ruling names `Firewall::on_session_end`. What it changed: one consumer moved from OUT to FOR
(receipt above), D4 acquired a second obligation (the registered closure captures a
`Weak<Firewall>`; `firewall` is already `Option<Arc<Firewall>>` at `router/mod.rs:112`, so no
state restructuring is needed), and the §P2 plan must assert that the registered handler actually
fires — not merely that `tracked_count` fell.

**U2 — what a registered handler may safely reclaim — CHECKABLE, DEFERRED, and now load-bearing.**
Owner: whichever lane registers the SECOND handler (the first is `on_session_end`, checked against
D5 in this document — it is eviction-tolerant). What resolves it: reading that handler against D5
at its review, specifically against the re-track residual above. When: at that registration.
If it resolves badly: the handler needs an in-flight guard, D5 re-opens, and the generation
counter rejected above comes back into play. Blocks: any registration beyond `on_session_end`.

**U3 — may this change edit `src/gateway/streaming.rs`, and in which of D1a's two shapes? —
ASKABLE. RESOLVED.**
Asked of: the team lead. Answer (§R9): yes to shape (a), `spawn_reaper_on(&self, lifecycle:
Arc<SessionLifecycle>)`, on the reason D1a already gave — "a field lets a caller silently get a
reaper-less loop and the compiler says nothing, while a parameter makes every one of the three
call sites state what it is reaping". `Option` refused for the reason D1a gave: an empty lifecycle
already reaps nothing, so the `Option` buys a second way to spell the same emptiness.
What it changed: D1 has its host and D1a is settled as written — nothing in the design moved. The
answer UNBLOCKS rather than redirects, which is the cheapest kind and worth saying plainly: had it
come back "no edit", D1 would have had no host at all. Shape (b)'s pre-evaluation is spent unused.

Amended after §R11. R9 supplied the SHAPE half and this entry recorded it; the PERMISSION half —
R3a's "tell me before you edit it" — was still outstanding when the entry first read RESOLVED, and
saying so is the point of the four fields. R11 grants it in words: the keep-out on
`src/gateway/streaming.rs` is lifted for this change, for the reaper wiring only. Not the file in
general, and not for a second lane. Both halves are now on the record, so nothing about this
question is carried as implied.
