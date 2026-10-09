# MIK-8202: a clock before 1970 must never make an expiry pass

Ticket: MIK-8202 (P2, Family: clock-before-epoch). Base: `docs/ranking-1-release-line`
at `6d924721f`.

## Problem

On a host whose clock reads earlier than 1970 (a dead RTC battery, an unsynced VM), the
gateway's wall-clock reads go wrong in one of two ways:

- `SystemTime::now().duration_since(UNIX_EPOCH)` returns `Err`, and the code falls back,
  usually to 0 (`unwrap_or(0)`, `map_or(0, ..)`, `unwrap_or_default()`).
- chrono `Utc::now()` returns a 1969 `DateTime` with no error, and `.timestamp()` is negative.

Either way "now" lands before every real deadline. Every comparison of the form
"now has passed the expiry" then answers no, and the expired thing is served. Examples:

- `key_server/store.rs:66-70`: `0 >= self.exp` is false, so an expired key-server bearer
  token validates.
- `config/features/api_key.rs:155-156`: `expires_at.is_some_and(|at| now >= at)` with a 1969
  `now`, called from `auth_resolved.rs:190` and `:235`, so an expired API key authenticates.
- `protocol/continuation/payload.rs:173-177` returns 0, and `keyring.rs:425` checks
  `now > payload.expires_at`, so every expired continuation and destructive-action
  confirmation opens. The comment at `payload.rs:171-172` claims the opposite.

A third failure: jsonwebtoken 11.1.0 reads the clock itself (`validation.rs:170-172`,
`.expect("Time went backwards")`), so every `decode` that validates `exp` panics instead of
refusing.

The gateway has 21 separate "now" helpers with different fallbacks (0, `u64::MAX`, `Err`, a
negative chrono value). The two that already fail closed (`personal_accounts/service.rs:228`,
`migration_entry.rs:130`) use `u64::MAX` at a check site. `u64::MAX` is only safe there: written
as a timestamp, it makes every later age check saturate to 0, so the record never expires.
That is the same bug in another form, so it is not the remedy.

## Census

Two read-only traces cover every non-test `SystemTime::now`, `UNIX_EPOCH`, `Utc::now`,
`Local::now` and `.timestamp()` site in `src` (198 sites, 58 of them test-only). Rows group
adjacent sites in one function, so the counts below are rows.

| role | fail open | panic | fail closed | harmless |
|---|---|---|---|---|
| EXPIRY: compares now to a deadline, ttl or age | 39 | 1 | 5 | 3 |
| FRESHNESS-RECORD: writes a time a later expiry check reads | 0 | 0 | 17 | 6 |
| RATE: a budget or rate window | 1 | 0 | 5 | 2 |
| RECORD: log, audit or metric only | 0 | 0 | 1 | 22 |
| ID / OTHER | 0 | 0 | 2 | 11 |

"Fail open" includes chrono sites that fail open only against a deadline set while the clock was
right (a row saved to disk, a credential's published expiry). That is the realistic case: the
clock goes wrong while the gateway holds state written before.

Appendix A lists every EXPIRY, FRESHNESS-RECORD, fail-open and panic row with file:line and the
PR that fixes it.

## Decision

### D1. One clock module, no fallback value

`src/clock.rs` (`crate::clock`) is the only code that reads the wall clock.

```rust
/// The host clock reads earlier than 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockBeforeEpoch;

pub(crate) fn unix_secs() -> Result<u64, ClockBeforeEpoch>;
pub(crate) fn unix_millis() -> Result<u64, ClockBeforeEpoch>;
/// A chrono now; `Err` when it would be before the epoch, never a 1969 date.
pub(crate) fn utc_now() -> Result<chrono::DateTime<chrono::Utc>, ClockBeforeEpoch>;
```

There is no fallback inside the module. A `Result` is `#[must_use]`, so a caller cannot read
the clock without deciding what a bad clock means for it. That decision is written at the call
site, where review sees it.

### D2. Expiry checks: `expired_by`, with the answer as an enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Validity { Live, Expired }

/// The site's own comparison against now; `Expired` when the clock cannot be read.
pub(crate) fn expired_by(check: impl FnOnce(u64) -> Validity) -> Validity;
pub(crate) fn expired_by_utc(check: impl FnOnce(DateTime<Utc>) -> Validity) -> Validity;
```

Each site keeps its own boundary (`now >= exp` at one, `now > expires_at` at another) inside
the closure, so nothing about its semantics moves. The closure returns `Validity`, not `bool`:
a closure answering "still valid?" would flip the meaning without a compile error, and the
project rule is enums, not booleans, for behaviour-selecting values. A bad clock answers
`Expired` at every check: the one direction that refuses rather than admits.

`expired_by` is for ACCESS decisions only: a credential, grant, session, lease, deadline or
continuation that admits something. A RETENTION site (a sweep that deletes or reclaims what has
aged out: idempotency entries, task rows, pooled connections, idle session state) reads
`clock::unix_secs()` and skips that sweep on `Err`. There "expired" is the dangerous answer:
deleting an idempotency key early readmits a retry that would run a side effect twice. Keeping it
until the clock is readable is the safe one. Appendix A marks each EXPIRY row ACCESS or
RETENTION.

What this does and does not guarantee: `expired_by` and the `Result` stop a site from failing
open by accident, and the lint (D6) stops a new raw read. Neither stops a site that matches on
the `Err` and answers `Live` on purpose; review catches that, and every ACCESS row gets a test
(see Tests).

Example, `key_server/store.rs`:

```rust
pub fn is_expired(&self) -> bool {
    clock::expired_by(|now| if now >= self.exp { Validity::Expired } else { Validity::Live })
        == Validity::Expired
}
```

### D3. Recorders refuse to write a time they cannot read

A FRESHNESS-RECORD site (minting a continuation, issuing a token, stamping `issued_at`)
propagates `ClockBeforeEpoch` as its module's refusal error: it mints nothing. It never writes 0
(the record reads as ancient, or never expires once an age check saturates) and never writes
`u64::MAX`. RECORD-only sites (logs, metrics) handle the `Err` explicitly at the call, for
example by omitting the field. That is visible and harmless.

Budget persistence is a recorder too. A save on a bad clock (`cost_accounting/enforcer.rs:709`
writes `saved_at`) is skipped, so the last valid snapshot survives; `restore` (`:656`) never sees
`saved_at = 0` and never discards a day's spend.

### D4. The existing `Clock` seam

`personal_accounts::provider::Clock::now_unix` becomes
`fn now_unix(&self) -> Result<u64, ClockBeforeEpoch>`. `SystemClock` delegates to
`clock::unix_secs`; `FixtureClock` returns `Ok`. A test can then pin a pre-epoch clock through
the seam it already uses, with a fixture that returns `Err`.

### D5. jsonwebtoken never reads the clock

jsonwebtoken 11.1.0 reads the clock only when `validate_exp || validate_nbf` is set
(`validation.rs:267-268`), and then panics on a pre-epoch clock (`:170-172`,
`.expect("Time went backwards")`). Release builds set `panic = "abort"` (`Cargo.toml:317`), so
one such decode takes down the whole gateway.

A check before `decode` is not enough, because the library samples the clock again inside it,
and a clock step between the two still panics. So every decode sets `validate_exp = false` and
`validate_nbf = false`, keeps `exp` in `required_spec_claims` (presence is still enforced), and
then judges the decoded `exp` and `nbf` once, against one `clock::unix_secs()` sample, with the
library's own rule: expired when `exp < now - leeway`, immature when `nbf > now + leeway`. This
lives in one helper, `clock::jwt_window(exp, nbf, leeway) -> Validity`, used by all three decode
sites (Appendix B). `AgentRegistry::now` (`gateway/oauth/agents.rs:107`) calls
`jsonwebtoken::get_current_timestamp` directly, so it moves to `clock::unix_secs` and refuses on
`Err`. `jsonwebtoken::get_current_timestamp` joins the D6 disallowed list.

### D6. The lint: clippy `disallowed-methods`

`clippy.toml` already routes home-directory lookups through `crate::home_dir` this way
(MIK-8001). Added: `std::time::SystemTime::now`, `std::time::SystemTime::elapsed`,
`chrono::Utc::now`, `chrono::Local::now` and `jsonwebtoken::get_current_timestamp`, each with
the reason "use crate::clock (MIK-8202)". `src/clock.rs` carries the permanent `#![allow]`, as
`src/home_dir.rs` does.

`Instant::now` stays allowed: it is monotonic, it cannot read before 1970, and it never
compares against a stored deadline.

### D7. The gateway refuses to start on a pre-epoch clock

Startup reads `clock::unix_secs()` before it binds or opens any store. On `Err` it exits
non-zero with "system clock reads before 1970; set the clock and restart (MIK-8202)". That
removes the common cause, a box that boots with a dead clock, in one place. D1-D6 still cover a
clock that steps back while the gateway runs.

### Known third-party behaviour

rustls-pki-types 1.15.1 `UnixTime::now()` calls `.unwrap()` on `duration_since(UNIX_EPOCH)`,
commented "Safe: this code did not exist before 1970". A certificate-validating TLS handshake on
a pre-epoch clock therefore panics, which under `panic = "abort"` stops the process. That fails
closed: nothing is admitted. D7 keeps a gateway from starting into it. It is not patched here.
## Delivery: one family, two PRs

**PR1 (Part of MIK-8202), the security half.**

- `crate::clock` (D1, D2), the `Clock` seam (D4), the jsonwebtoken change (D5) and the
  startup refusal (D7).
- Every fail-open or panic row on auth, credentials, budgets or event delivery: the rows marked
  PR1 in Appendix A. That covers API keys, bearer tokens, continuations and input-round
  deadlines, grants, attestation, sessions, journeys, the agent-token clock, the budget day and
  its `saved_at` writer, and every subscription-lease check. A lapsed lease that still delivers
  sends event data to a receiver whose subscription ended, which is an access decision.
- The D6 lint, with a transitional baseline. `docs/release/mik-8202-clock-baseline.tsv` lists
  `file<TAB>count`: the number of disallowed clock calls each not-yet-migrated file holds on the
  base. Each such file carries
  `#![allow(clippy::disallowed_methods, reason = "MIK-8202: clock reads not yet migrated")]`.
  `scripts/release/check_clock_baseline.py` checks the tree in three ways:
  1. It finds every `disallowed_methods` suppression, whatever its reason or form (inner,
     outer, `expect`, in a list). Each must be in the baseline or in the permanent set:
     `src/clock.rs`, `src/home_dir.rs`, and the existing home-directory test allows. Matching
     the reason text alone would let a differently worded allow through.
  2. Per baselined file, it counts the raw calls; the count may not exceed the baseline value.
  3. The baseline is a subset of the base's baseline: no new file, no raised count.
  So a grandfathered file cannot take on another raw read, and a swap of one file for another
  is refused.

**PR2 (Fixes MIK-8202), the mechanical half.** It migrates the remaining rows (RETENTION
sweeps, records, rate windows, outbound OAuth), deletes the duplicate helpers, and empties and
deletes the baseline and its script. Test code reads the clock through `crate::clock` too.
Integration tests under `tests/` cannot see `pub(crate)`, so they keep a per-file allow with the
reason "test clock; makes no expiry decision", in the permanent set.

## Tests (red first, on the current tree)

A test clock that returns `Err` is reachable through the seam each module already has: the
`Clock` trait (D4), or a `#[cfg(test)]` override in `crate::clock` (thread-local, as
`home_dir`'s `MCP_GATEWAY_TEST_HOME_DIR` does for directories). A thread-local does not follow a
spawned task. Rows that cross a `tokio::spawn` (the event worker, the budget saver) drive the
override inside the spawned task, or call the function under test directly. PR1's rows:

| row | input | red today because | green after |
|---|---|---|---|
| startup | gateway started with clock `Err` | starts and serves | exits non-zero, message names the clock |
| bearer exp | key-server token, exp in the past, clock `Err` | `0 >= exp` reads unexpired, token validates | refused as expired |
| continuation | sealed continuation past `expires_at`, clock `Err` | `0 > expires_at` false, opens | `Expired` |
| API key | key with `expires_at` in the past, chrono now 1969 | `api_key_expired` false, request authenticates | 401 expired |
| JWT decode | valid agent token, clock `Err` | jsonwebtoken panics | refused, no panic |
| bridge session | Open WebUI session past `expires_at`, clock `Err` | user id returned | `None` |
| subscription lease | subscription whose lease ended, clock `Err`, one event published | event delivered | not delivered |
| budget save | saved spend for today, clock `Err` at save, then clock restored and restart | `saved_at = 0` written, restore drops the day's spend | save skipped, restore keeps the spend |
| mint refusal | continuation mint with clock `Err` | mints with `issued_at = 0` | refused |
| retention | idempotency entry, clock `Err` during sweep | (today: kept) | kept, not deleted |

Each row has a positive control: the same input with a correct clock behaves as today. The
retention row is a guard against the D2 trap, so it is green both before and after. The existing
clippy step proves the lint: a planted `Utc::now()` outside `src/clock.rs` fails it, and so does a
planted allow with another reason.

## Alternatives considered

- **A sentinel inside the helper** (0 or `u64::MAX` by purpose). Rejected: it hides the error,
  and `u64::MAX` written as a record never expires (see Problem).
- **A purpose enum argument** (`now(Purpose::CheckDeadline)`). Rejected: the helper would
  still have to invent a value for the record purpose. A `Result` makes each site decide.
- **A clock check just before `decode`** (round 1 of this design). Rejected: the library reads
  the clock again inside `decode`, so a step between the two still aborts the process (D5).
- **A script lint instead of clippy.** Rejected: clippy is the existing mechanism (MIK-8001),
  and it is type-aware, so a re-export or `use` alias cannot slip past a text match.

## Risks

- PR1 is larger than "security half" suggests: 37 Appendix A rows plus D5 and D7. The
  per-module commits keep each reviewable on its own.
- The `Clock` seam signature change touches about 44 references in `personal_accounts`. They
  are all mechanical `?` or `match` changes, in PR1 because the consent-journey deadline is
  auth.
- chrono path names for clippy (`chrono::Utc::now` versus `chrono::offset::Utc::now`) must be
  confirmed against the compiler's def path. The planted-call test proves the entry fires.
- File ceiling: `src/clock.rs` is new and small. Touched files near 800 lines get no net growth.

## Appendix B: jsonwebtoken decode sites (D5)

| site | validates exp/nbf | today on a pre-epoch clock |
|---|---|---|
| src/gateway/oauth/jwt.rs:172 (`Validation::new` at :157) | yes, defaults | panic |
| src/key_server/oidc.rs:536 (`Validation::new` at :691) | yes, defaults | panic, masking the iat cap at :493 |
| src/gateway/openwebui_adapter.rs:370 (`validate_exp = true` at :364) | yes | panic |

`decode_header` (jwt.rs:135, oauth/mod.rs:136, oidc.rs:470) reads no clock. `keyring.rs:392`
is base64, not jsonwebtoken.

## Appendix A: every EXPIRY, FRESHNESS-RECORD, fail-open and panic row

Effect is today's behaviour before 1970. PR is the PR that changes the row.

| site | fn | role | pre-1970 effect today | PR |
|---|---|---|---|---|
| src/backend/pool.rs:25 | now_unix_secs (helper) | EXPIRY (idle eviction, non-auth) [RETENTION: skip sweep on Err] | FAIL-OPEN (non-auth): now-last_used saturates to 0, idle pooled transports never evicted | PR2 |
| src/cost_accounting/enforcer.rs:160 | current_day (helper) | RATE (daily budget) | FAIL-OPEN: restore() at :656 sees saved day != 0 and drops today's persisted spend, budgets restart at zero af | PR1 |
| src/cost_accounting/persistence.rs:153 | now_secs (helper) | FRESHNESS-RECORD (saved_at read by enforcer.rs:656) | HARMLESS: saved_at=0 matches current_day 0 while clock stays pre-1970; stale-row sweep throttle never fires ag | PR2 |
| src/events/client.rs:172 | post_tracked | FRESHNESS-RECORD (receiver checks it) | FAIL-CLOSED: receiver sees a 1969 timestamp and refuses the delivery | PR2 |
| src/events/services.rs:177 | (delegated bearer revalidation closure) | EXPIRY (OIDC bearer age) | FAIL-CLOSED: now=MAX, every bearer reads too old | PR2 |
| src/gateway/meta_mcp/chain_receipt.rs:151 | now (helper) | EXPIRY (chain link freshness) | FAIL-CLOSED: stale check passes but any real-clock link is refused as Future at :455 | PR2 |
| src/gateway/meta_mcp/response_security.rs:444 | (emit chain link) | FRESHNESS-RECORD (downstream verify_chain signature_chain.rs | FAIL-CLOSED: downstream sees ts=0 as stale | PR2 |
| src/gateway/meta_mcp/signing.rs:575 | (sign response closure) | FRESHNESS-RECORD | FAIL-CLOSED: response refused "Signing clock is invalid" | PR2 |
| src/gateway/openwebui_adapter.rs:447 | now_seconds (helper) | EXPIRY (iat skew) | PANIC: jsonwebtoken decode at :370 (validate_exp=true) panics first; if reached, :399 refuses every real iat ( | PR1 |
| src/gateway/router/accounts/bridge.rs:155 | unix_now (helper) | EXPIRY (Open WebUI session expiry) | FAIL-OPEN: an expired browser session reads unexpired, user id returned | PR1 |
| src/gateway/session_lifecycle.rs:125 | now_unix (helper, pub) | EXPIRY (idle/end-grace reclaim, non-auth) [RETENTION: skip sweep on Err] | FAIL-OPEN (non-auth): reap(0) never passes real deadlines, per-identity state never reclaimed | PR2 |
| src/gateway/task_service/mod.rs:87 | open_runtime (admission clock closure) | EXPIRY (24h idempotency retention, non-auth) [RETENTION: skip sweep on Err] | FAIL-OPEN (non-auth): completed entries never expire, cached results replayed past retention; slots fill to Ca | PR2 |
| src/identity_propagation/account_strategies.rs:510 | resolve | EXPIRY (external credential published expiry) | FAIL-OPEN: an expired external credential passes the initial-resolve check | PR1 |
| src/identity_propagation/account_strategies.rs:647 | revalidate | EXPIRY (external/managed lifetime) | FAIL-OPEN: `now < expires_at` true for any real expiry | PR1 |
| src/identity_propagation/mod.rs:420 | SignedAssertionStrategy::now_secs (helper) | EXPIRY (exchanged-token cache) + FRESHNESS-RECORD (minted as | FAIL-OPEN: token_exchange.rs:243 serves a cached exchanged token past expires_at; minted assertions are 1969-d | PR1 |
| src/key_server/handler.rs:258 | (token issue handler) | FRESHNESS-RECORD (store.rs:69) | HARMLESS: token valid only while clock stays pre-1970, expired once corrected | PR2 |
| src/key_server/oidc.rs:493 | (OIDC verify, MaxIat arm) | EXPIRY (OIDC replay/age cap) | FAIL-OPEN at site (age cap passes for any iat); in practice masked: the jsonwebtoken decode that follows panic | PR1 |
| src/key_server/store.rs:69 | TemporaryToken::is_expired | EXPIRY (key-server bearer exp) | FAIL-OPEN: `0 >= exp` false, expired key-server bearer tokens validate | PR1 |
| src/mtls/cert_manager.rs:413 | validity_to_date | FRESHNESS-RECORD (cert validity) | FAIL-CLOSED: cert generation refused | PR2 |
| src/oauth/client/mod.rs:535 | needs_proactive_refresh | EXPIRY (refresh scheduling) | FAIL-OPEN (outbound): remaining reads huge, proactive refresh skipped | PR2 |
| src/oauth/storage.rs:142 | TokenInfo::from_response | FRESHNESS-RECORD (storage.rs:165) | HARMLESS: token reads expired once clock is corrected, forcing refresh | PR2 |
| src/oauth/storage.rs:165 | TokenInfo::is_expired | EXPIRY (outbound OAuth access token) | FAIL-OPEN (outbound): expired backend tokens are presented instead of refreshed; upstream still refuses them | PR2 |
| src/personal_accounts/migration_entry.rs:130 | (migrate legacy grant) | EXPIRY | FAIL-CLOSED: everything reads expired | PR2 |
| src/personal_accounts/provider.rs:142 | SystemClock::now_unix | EXPIRY (consent-journey deadline) + FRESHNESS-RECORD (grant  | FAIL-OPEN: sweep `0 >= deadline` false, an expired OAuth consent journey's callback is admitted | PR1 |
| src/personal_accounts/service.rs:228 | expired | EXPIRY (grant) | FAIL-CLOSED: refresh, never serve | PR2 |
| src/personal_accounts/vault.rs:531 | now_secs (helper) | FRESHNESS-RECORD (managed marker) | HARMLESS: expires_at <= minted_at still holds, same clock | PR2 |
| src/personal_accounts/worker_journeys.rs:226 | now_seconds (helper) | EXPIRY (journey start window) | FAIL-OPEN: sweep never expires real-time journeys; :210 max_age = real deadline - 0 (~56 years) | PR1 |
| src/protocol/continuation/payload.rs:175 | now_unix_secs (helper) | EXPIRY (continuation / destructive-confirm grant) | FAIL-OPEN: `0 > expires_at` false, expired continuations and confirmation grants open; doc comment at payload. | PR1 |
| src/gateway/auth_resolved.rs:135 | is_expired_key | EXPIRY (API key) | HARMLESS on its own: only labels a rejection; the accept path is :190 | PR2 |
| src/gateway/auth_resolved.rs:190 | validate_token_with_origin | EXPIRY (API key) | FAIL-OPEN: 1969 `now` is before any real `expires_at`, so an expired API key authenticates | PR1 |
| src/gateway/auth_resolved.rs:235 | client_for_key | EXPIRY (API key, background) | FAIL-OPEN: an expired key's watches keep polling as that key | PR1 |
| src/gateway/auth_dashboard.rs:394 | Now::read | EXPIRY (dashboard session/handoff cap = minting API key `exp | FAIL-OPEN for the cap: session and handoff code outlive the minting key's expiry; idle/absolute limits HARMLES | PR1 |
| src/gateway/meta_mcp/visibility.rs:354 | grant_evaluation | EXPIRY (identity grant) | FAIL-OPEN: an expired identity grant still authorizes the tool call; lease `expires_at = now + lease` (store.r | PR1 |
| src/gateway/meta_mcp/invoke/policy.rs:173 | check_attestation_scoped | EXPIRY (attestation token, rotated-out token) | FAIL-OPEN: an expired or rotated-out attestation token validates | PR1 |
| src/commands/identity.rs:375 | parse_expiry | FRESHNESS-RECORD (grant expiry, checked at identity_grants.r | FAIL-CLOSED: a `--ttl-seconds` grant gets a 1969 expiry and is dead once the gateway clock is right (works whi | PR2 |
| src/gateway/router/handlers/events.rs:77 | EventsRequest::credential | FRESHNESS-RECORD (subscription lease, checked by Subscriptio | FAIL-CLOSED once the clock is right (1969 ceiling ends the subscription at once); consistent while it stays 19 | PR2 |
| src/events/services.rs:96 | Services::admits_grant | EXPIRY (API key bound to a subscription) | FAIL-OPEN: an expired API key's subscriptions keep receiving events | PR1 |
| src/events/operational_source.rs:45 | standing | EXPIRY (API key) | FAIL-OPEN: an expired key keeps its standing (admin or own-budget scope) for operational events | PR1 |
| src/events/admin.rs:123 | EventsAdmin::replay_dead | EXPIRY (subscription lease) | FAIL-OPEN for a lease stamped by a correct clock (persisted row, or capped at the credential's real expiry): r | PR1 |
| src/events/fanout.rs:89 | EventsHub::fan_out | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: expired subscriptions still match and get records | PR1 |
| src/events/fanout.rs:176 | EventsHub::offer | FRESHNESS-RECORD (outbox due time, dead-letter retention) | HARMLESS under one 1969 clock (relative); records persisted from a correct clock never come due (FAIL-CLOSED s | PR2 |
| src/events/fanout.rs:245 | EventsHub::withdraw | FRESHNESS-RECORD (callback opt-in tail, checked store.rs:209 | FAIL-CLOSED once the clock is right (1969 end stamp: tail already run out, callback re-challenged) | PR2 |
| src/events/fanout.rs:417 | hold_unserved | FRESHNESS-RECORD (hold bound) + EXPIRY filter | HARMLESS same-clock; FAIL-CLOSED once the clock is right (hold bound in 1969 ends the row) | PR2 |
| src/events/fanout.rs:441 | EventsHub::revoke | FRESHNESS-RECORD | FAIL-CLOSED (as :245) | PR2 |
| src/events/lifecycle.rs:105 | live_keys | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: an expired row keeps its upstream lifecycle key (source kept running) | PR1 |
| src/events/mod.rs:222 | EventsHub::open_with | EXPIRY (subscription lease, verification tail) | FAIL-OPEN, same qualifier: correct-clock rows and opt-in tails survive startup | PR1 |
| src/events/rpc.rs:467 | EventsHub::subscribe | EXPIRY (callback verification tail) + FRESHNESS-RECORD (leas | FAIL-OPEN for an opt-in whose tail end was stamped by a correct clock: `now - ended` is negative, so the callb | PR1 |
| src/events/rpc.rs:713 | EventsHub::unsubscribe | FRESHNESS-RECORD | FAIL-CLOSED (as fanout.rs:245) | PR2 |
| src/events/rpc_held.rs:52 | refresh_held | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: an expired held row is refreshed | PR1 |
| src/events/store.rs:409 | Store::admit_granted | EXPIRY (verification tail at commit) + FRESHNESS-RECORD (lea | FAIL-OPEN (as rpc.rs:467): commit re-check also accepts the correct-clock tail | PR1 |
| src/events/store_pending.rs:150 | enqueue_locked | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: records enqueued for an expired subscription | PR1 |
| src/events/watch_source.rs:291, :594 | rows, holders | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: an expired watch keeps polling the backend for its holder | PR1 |
| src/events/watch_source_hold.rs:83, :167 | judge_rows, hold_unclassed | FRESHNESS-RECORD (hold bound) | HARMLESS same-clock; FAIL-CLOSED once the clock is right | PR2 |
| src/events/schedule_source.rs:312, :328 | holders, held_by | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: expired rows keep timers held | PR1 |
| src/events/worker.rs:53 | EventsHub::sweep | EXPIRY (subscription lease) | HARMLESS: only keeps per-row rate state longer | PR2 |
| src/events/worker.rs:80, :109 | EventsHub::dispatch | EXPIRY (outbox expiry burial) + FRESHNESS | HARMLESS same-clock; correct-clock records never due (FAIL-CLOSED stall) | PR1 |
| src/events/worker.rs:152, :186, :213 | attempt_once | FRESHNESS-RECORD + RATE (retry window) | HARMLESS: same clock stamps and checks; `sends > max_attempts` still bounds retries | PR1 |
| src/events/worker.rs:363 | record_and_send | EXPIRY (subscription lease) | FAIL-OPEN, same qualifier: an event is POSTed to an expired subscription | PR1 |
| src/events/worker.rs:478 | send_event | EXPIRY (webhook secret rotation grace) | FAIL-OPEN for a grace stamped by a correct clock: the rotated-out secret keeps signing | PR1 |
| src/events/worker.rs:513 | sweep_dead_letters | EXPIRY (retention) [RETENTION: skip sweep on Err] | HARMLESS same-clock; correct-clock dead letters outlive retention (count/byte caps still apply) | PR2 |
| src/events/worker.rs:522 | retry_unsent | FRESHNESS-RECORD | HARMLESS (same clock) | PR2 |
| src/gateway/task_service/store_input.rs:111 | Shared::now (the task store clock; the cfg(test) override above it is test-only) | EXPIRY (input-round continuation deadline) | FAIL-OPEN: negative ts clamps to 0, `0 >= deadline` never holds, so a round past its continuation deadline sta | PR1 |
| src/gateway/task_service/execution/expiry.rs:141 | sweep | EXPIRY (task retention) [RETENTION: skip sweep on Err] | HARMLESS for 1969-created tasks; tasks persisted by a correct clock get a negative age and are never deleted ( | PR2 |
| src/gateway/meta_mcp/call_dispatch.rs:252 | begin_task | FRESHNESS-RECORD (task retention) | HARMLESS same-clock; FAIL-CLOSED once the clock is right (task deleted at the next sweep) | PR2 |
| src/commands/trust/lab.rs:218, :220; src/trust/lab.rs:71 | evaluate_lab_cards_with_mode, evaluate_card | FRESHNESS-RECORD (certification expiry, no in-crate check) | FAIL-CLOSED for an outside verifier: the certificate is issued already expired | PR2 |
| src/events/worker.rs:80 | EventsHub::dispatch | EXPIRY (subscription lease) | FAIL-OPEN (conditional, as worker.rs:363): records of an expired subscription stay ready instead of buried | PR1 |
| src/events/worker.rs:152 | attempt_once | EXPIRY (subscription lease) | FAIL-OPEN (conditional): an expired subscription's record is claimed | PR1 |
| src/events/worker.rs:513 | sweep_dead_letters | EXPIRY (retention) [RETENTION: skip sweep on Err] | FAIL-OPEN (conditional): correct-clock dead letters outlive retention (count/byte caps still evict) | PR2 |
| src/events/fanout.rs:176 | EventsHub::offer | FRESHNESS-RECORD | FAIL-CLOSED: correct-clock records never come due (delivery stalls) | PR2 |
| src/events/fanout.rs:417; watch_source_hold.rs:83, :167 | hold writers | FRESHNESS-RECORD | FAIL-CLOSED: the 1969 hold bound ends the row once the clock is right | PR2 |
| src/gateway/meta_mcp/call_dispatch.rs:252 | begin_task | FRESHNESS-RECORD | FAIL-CLOSED: task deleted at the next sweep once the clock is right | PR2 |
| src/gateway/task_service/execution/expiry.rs:141 | sweep | EXPIRY (retention) [RETENTION: skip sweep on Err] | FAIL-OPEN (conditional), unchanged count | PR2 |
| src/gateway/oauth/agents.rs:107 | AgentRegistry::now | EXPIRY (agent token, via jsonwebtoken::get_current_timestamp) | PANIC: the library expect aborts the release process | PR1 |
| src/cost_accounting/enforcer.rs:709 | snapshot saved_at | FRESHNESS-RECORD (read by restore at :656) | FAIL-OPEN after recovery: a bad-clock save writes saved_at=0 and restore drops the day's spend | PR1 |
| src/events/dedupe.rs:57 | Seen::first_sighting (consumer, no clock read of its own) | FRESHNESS-RECORD (24 h dedupe window) | a pre-epoch sighting leaves the window at once after recovery, so a duplicate is delivered | PR2 |
