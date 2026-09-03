<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# What identifies a caller once sessions are gone

**FOR:** choosing the identity that replaces the protocol session in two places that
lost it — the transparency log's correlation key (`MIK-7215.CONTROL.3a`) and the
lifecycle reaper's tracking key and clock (`MIK-7215.CONTROL.4`), and re-keying the
cleanup handlers' own stores onto that identity so the reaper's calls reach something.

**OUT:**

- the continuation envelope and its wiring (cluster A). Both rows below hold whether or
  not a caller sends `_meta`; nothing here depends on A landing.
- `MIK-7215.CONTROL.5`, which governs whether a partially-correlated log may ship. This
  design removes the case that made 3a partial; it does not rule on 5.
- any change to `principal_of` or to how a credential is validated.
- the transparency log's format, retention or signing.

No code below.

## The problem

MCP 2026-07-28 removed protocol sessions. `src/gateway/session_lifecycle.rs:26` states
the consequence against itself: `on_disconnect` has nothing left to fire on, because
there is no session to DELETE and the stream whose close drove the other trigger is
replaced by `subscriptions/listen`. Two mechanisms were built on the session and now
rest on nothing:

1. The transparency log's correlation key. `src/gateway/meta_mcp/invoke.rs:1812-1816`
   reads a W3C trace id out of `_meta`, falls back to `session_id`, then to a literal
   placeholder string. After this release the middle rung is always absent, so any
   caller that does not send `_meta` is logged under the placeholder and correlates
   with nothing.
2. The lifecycle reaper. `SessionLifecycle::{register,track,reap}`
   (`src/gateway/session_lifecycle.rs:48`, `:107`, `:124`) replaced the disconnect
   trigger with a deadline. `rg SessionLifecycle` outside that module returns doc
   comments in `src/security/firewall/**` and nothing else: no construction, no holder,
   no caller of `track` or `reap` in production.

They are one design because they are blocked on the same unmade choice. The module's own
doc comment (`src/gateway/session_lifecycle.rs:100-102`) says the key is "whatever the
caller is identified by — a principal after the migration, a session before it" and
leaves the migration half unspecified. The log's fallback chain has the same hole.

## Measured constraints

| constraint | evidence |
|---|---|
| a per-invocation id already exists and the log ignores it | `trace::generate()` at `src/gateway/meta_mcp/invoke.rs:767`, threaded through the call as `trace_id` and recorded on the span at `:1012`; the correlation chain at `:1812-1816` does not consult it |
| a stable per-caller identity already exists | `principal_of` (`src/gateway/auth.rs:38-43`) is the first 12 hex of a SHA-256 over the validated secret, set from the bearer token at `:209`, the API key at `:224`, the OIDC client identity at `src/key_server/mod.rs:154` |
| a principal is not always present | the log's caller field already falls back for an unauthenticated call (`src/gateway/meta_mcp/invoke.rs:1806`) |
| ownership is not a blocker | `register` takes `impl Fn(&str) + Send + Sync + 'static`, so registration happens at startup and the firewall is only *called* from inside the closure — established at `docs/design/2026-09-01-residue-four-rows.md:82-85` |
| the repo has a settled shape for a periodic task | `tokio::spawn` + `tokio::time::interval` + `tokio::select!` on a shutdown receiver, twice: cost persistence at `src/gateway/server/mod.rs:1372-1382` (300s) and the health probe at `:1937-1942` (config-driven) |
| a per-caller reaper already exists, with a retention number | `spawn_idle_reaper` (`src/gateway/server/mod.rs:1980`) sweeps per-user backend slots on `PER_USER_IDLE_TTL = 300s` with `SWEEP_INTERVAL = 60s` (`:1988-1989`), and its own doc comment refuses to repurpose `stop_when_idle_for` into a per-user lifetime |
| both serve modes are an explicit requirement, not an assumption | that spawn is commented "Shared with `run_stdio`: a setting that works in one serve mode and silently does nothing in the other is the same class of defect this feature exists to correct" (`src/gateway/server/mod.rs:1360-1364`) |
| a dead retention setting is this repo's known failure | `idle_timeout` parsed for releases and did nothing; it is now in `retired_keys` (`src/config/mod.rs:540`) with tests pinning its rejection (`src/config/tests.rs:1016-1025`) |
| the module names its own residual | a key re-tracked between `reap`'s removal and `fire_cleanup` still has its handlers fired (`src/gateway/session_lifecycle.rs:76-77`) |
| the handlers' own stores are keyed by session id | the module's doc comment names them (`src/gateway/session_lifecycle.rs:4-8`): cost governance holds `per_session: DashMap<String, Arc<SessionCost>>` (`src/cost_accounting/mod.rs:434`), inserted at `:495` and removed at `:580`; the firewall's anomaly map has `remove_session`, meant to be registered here (`src/security/firewall/anomaly.rs:187`) |
| those stores gain no entry without an id | the cost record is guarded by `if let Some(sid) = session_id` (`src/gateway/meta_mcp/invoke.rs:1363-1364`), and `record` keys `per_session` on that string (`src/cost_accounting/mod.rs:495`) |
| the registry's locks are `parking_lot` and non-reentrant | `use parking_lot::RwLock` (`src/gateway/session_lifecycle.rs:12`); `fire_cleanup` already holds `callbacks.read()` across every handler call (`:83-95`) |
| the clock is the caller's | `track(key, expires_at: u64)` and `reap(now: u64)` take a bare `u64` (`src/gateway/session_lifecycle.rs:107`, `:124`); the module picks no time source |

## The decision

**The correlation key is per-invocation; the lifecycle key is per-principal. They are
different keys, and that is the point.**

`CONTROL.3a` asks that a correlation key survive. The chain keeps its order and gains a
rung: a caller-supplied W3C trace id first, then the minted `trace_id`, and the
placeholder becomes unreachable because the invoke path always mints one. The two rungs
are deliberately different scopes — a supplied trace id identifies a *call chain* and may
span several invocations, which is what a caller sends it for; the minted id identifies
*this* invocation. Correlation is only ever as narrow as the rung that supplied it, and
which rung fired is recorded, so a reader can tell a chain key from an invocation key
rather than inferring it. Without that marker the criterion is unauditable: a log full of
minted ids and a log full of placeholders look alike from outside.

`CONTROL.4` asks that cleanup happen without a disconnect. Cleanup is per *caller*, not
per request — the state being freed belongs to whoever authenticated — so the tracking
key is the principal, and the deadline is refreshed **at the start and again at the
completion** of each invocation by that caller. Refreshing only at the start would let an
invocation that runs longer than the TTL be reaped while it is still executing, which is
the reverse of the defect this row is about.

**The key must be the same string the handlers' stores are keyed by, so re-keying those
stores is part of this change, not a consequence of it.** The handlers do not receive a
key and look a caller up; they take a `&str` and delete the entry that string names
(`src/cost_accounting/mod.rs:580`, `src/security/firewall/anomaly.rs:187`). Firing them
with a principal while their maps hold session ids deletes nothing, and the leak survives
its own fix in silence — nothing errors when a removal matches no key. Both stores
already have no id to insert under once sessions are gone (`per_session` is written only
inside `if let Some(sid) = session_id`, `src/gateway/meta_mcp/invoke.rs:1363-1364`), so
they are not being re-keyed from a working state to a new one: they are being given the
identity they lost. This is a design event by the contract test — it changes what an
observable field means — and is named here rather than discovered during wiring.

That same guard settles what an anonymous caller holds: with no id, no `per_session`
entry is created, so a caller with no principal registers no deadline and has no
per-caller state to free. The claim is the guard's, not the design's.

The reaper runs as its own interval task spawned **beside `spawn_idle_reaper`
(`src/gateway/server/mod.rs:1364`), in both serve modes**, on that reaper's 60-second
sweep. Spawning it only where the HTTP server is built would give the gateway a retention
setting that works under one serve mode and silently does nothing under the other, which
is the defect that spawn's own comment exists to prevent. Its `u64` is monotonic seconds
since process start, not wall-clock: `track` and `reap` take a bare `u64` and the module
picks no source, and a wall-clock jump — NTP correction, a suspended laptop — would
otherwise reap every live caller at once or none ever.

### Options considered, and why the others were rejected

**For the correlation key:**

| option | rejected because |
|---|---|
| use the principal as the fallback | a principal is not per-request. Two concurrent calls from one caller collapse to one key, which is worse than a placeholder because the collision is invisible. An anonymous caller has none |
| refuse a request that carries no `_meta` trace id | turns a logging gap into an availability regression, and punishes every legacy client for a criterion about the log |
| leave the placeholder and widen `CONTROL.3a` | the criterion says the key must survive; widening it to match what shipped is the drift the ledger exists to catch |

**For the reaper's clock:**

| option | rejected because |
|---|---|
| reuse the cost-persistence timer (`src/gateway/server/mod.rs:1372`) | couples caller-state retention to a 300s cost-snapshot cadence that exists for another reason and may be retuned for that reason |
| reap lazily on the next invocation | a caller that never returns is exactly the caller whose state must be freed; the trigger is absent precisely when it is needed. This is the disconnect defect one indirection along |
| keep `on_disconnect` and fire it from stream close | `subscriptions/listen` replaced the stream whose close drove it (`src/gateway/session_lifecycle.rs:26`); a modern caller may never open one |

**For the module's named residual** (`:76-77`, a key re-tracked mid-reap has its handlers
fired): out of scope to *remove*, in scope to *not widen*. A per-principal key refreshed
on invocation makes the window reachable by an ordinary caller, where a per-session key
made it rare. Scheduled below rather than accepted silently.

## Unknowns

| question | how it was settled | what came back | what it changed |
|---|---|---|---|
| does a per-invocation id already exist on the invoke path, or must one be minted? | read `src/gateway/meta_mcp/invoke.rs:767`, `:1012`, `:1812-1816` | `trace::generate()` mints one per call and the correlation chain does not read it | removed the option of minting a second id, and made 3a a three-line rung rather than a mechanism |
| is the reaper blocked on another module's ownership? | `rg SessionLifecycle` across `src/`, plus `register`'s signature at `src/gateway/session_lifecycle.rs:48` | zero production references; `register` takes a closure, so the firewall is called, not edited | removed "who owns it" as a design question; the remaining question is the clock |
| does the repo have an established periodic-task shape, or is one being invented? | read `src/gateway/server/mod.rs:1372-1382` and `:1937-1942` | two live examples of spawn + interval + shutdown-select | chose a purpose-built task over reusing a timer, and fixed its shape |
| is a principal always available to key on? | read the log's own caller fallback at `src/gateway/meta_mcp/invoke.rs:1806` | no — an unauthenticated call already falls back there | made "no principal, no deadline" an explicit case rather than an assumed one |
| how long is a departed caller's per-principal state retained? | *askable, not checkable* — asked of the operator, relayed by the team lead on 2026-09-03; recommendation and reasoning below | **pending** | nothing yet. Nothing depending on the number is implemented: the reaper's TTL is a configured value, and the wiring increment reads it rather than embedding one |

### Deferred

| field | value |
|---|---|
| question | does the re-track window at `src/gateway/session_lifecycle.rs:76-77` need closing before this ships? |
| owner | `MIK-7215`, the increment that wires the reaper |
| what would resolve it | a test that re-tracks a key between `reap`'s removal and `fire_cleanup` and asserts the handlers do **not** run for it, driven through the production registration path. Any cleanup after a re-track is the defect, so a test asserting the handlers "ran once" would pass on the broken behaviour |
| when | with the wiring, not after it — a leak reintroduced by the fix for a leak is the shape this row is about |
| what if it resolves badly | the handler contract narrows to "must not re-enter the registry", and `reap` claims each key before firing rather than holding a lock across `fire_cleanup`. Holding it was the obvious fallback and is unavailable: the locks are `parking_lot` and non-reentrant (`src/gateway/session_lifecycle.rs:12`), so a handler that calls `track` or `untrack` would deadlock the reaper against itself — a hang is worse than the leak it was meant to close |

## Scope moved after the first review, and why

Re-keying the handlers' own stores was not in the original **FOR**; it is now. The review
showed the two are not separable: choosing the principal as the lifecycle key and leaving
the stores on session ids produces a reaper that fires handlers which delete nothing, and
a design that shipped that way would have met `CONTROL.4` on paper while the leak it
names survived. Splitting it into a follow-up would have put the half that makes the fix
work behind a second decision. Recorded here rather than absorbed silently, because a
**FOR** that grows without a paragraph is how a scope stops meaning anything.

## Stated residual

`principal_of` is the first 12 hex of a SHA-256 — 48 bits, chosen as a log fingerprint
(`src/gateway/auth.rs:38-43`). Using it to key state makes a collision a state-isolation
event rather than a cosmetic one: two callers would share a cleanup entry. Widening it is
out of scope by this design's own **OUT** list, and the collision probability at any
plausible number of concurrent principals is not what threatens this release. Named so
that a later change to `principal_of`'s width knows it now has a second consumer with a
stricter requirement than logging.

## Open for the operator — asked, awaiting an answer

**How long is a departed caller's per-principal state retained?**

The reaper needs a TTL, and a TTL is an operator-visible retention number, not an
implementation detail: it decides how long the gateway holds state belonging to a caller
that has stopped calling. Wiring a value chosen while typing would make the criterion
read as met while the number nobody agreed to is the one that ships.

Recommendation: **300 seconds, matching `PER_USER_IDLE_TTL`, and configurable with it.**
This gateway already answers "how long does a departed caller's state live" — 300 seconds
for per-user backend slots, swept every 60 (`src/gateway/server/mod.rs:1988-1989`). A
second, different number for the same question would mean a caller's backend slot and
that caller's cost and anomaly state expire at different times for no reason anyone could
state, and the two would drift the first time either was tuned. Reusing the number costs
nothing this design needs: 300 seconds already clears an idle interactive client's
think-time, since it was chosen for exactly that population of callers.

An earlier draft recommended 15 minutes and justified it by staying "far below" the 300s
cost-persistence cadence. That was arithmetically backwards — 15 minutes is 900 seconds,
three times that cadence — and both reviewers caught it. The cadence was never a bound on
this value; the real anchor was a reaper neither the draft nor its reviewers had found.

Two things the answer must not do, both of which this repo has already been bitten by.
It must not silently repurpose `stop_when_idle_for`, a backend-lifetime setting, into a
caller lifetime — `spawn_idle_reaper`'s own doc comment refuses that, and this reaper
inherits the refusal. And whatever knob is exposed must actually be read: `idle_timeout`
parsed for releases while doing nothing and now sits in `retired_keys`
(`src/config/mod.rs:540`). A TTL that configures nothing is worse than a constant,
because a constant does not lie to the operator setting it.
