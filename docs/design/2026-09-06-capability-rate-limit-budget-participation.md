# Design — capability execution and the rate-limit error budget (GH475.RL.10)

Status: proposed · 2026-09-06 · GH [#475](https://github.com/MikkoParkkola/mcp-gateway/issues/475), [#481](https://github.com/MikkoParkkola/mcp-gateway/issues/481)
No code in this document (§P1).

## §P0 Scope

FOR: deciding whether capability execution participates in the error-budget
system, and what GH475.RL.10 requires of it.

OUT: the MCP-backend recording path (`src/backend/ops.rs`, `src/failsafe/`) —
unchanged by anything here; RL.9 and RL.11 (separate rows, separate criteria);
retry policy for a `429`; any change to `is_rate_limited`'s predicate text.

## 1. The premise the brief carried is false

The criteria ledger (`docs/requirements/RELEASE-4.0.0-criteria-status.md:393`)
records RL.10 as ABSENT because "`src/capability/executor/` contains no call to
`is_rate_limited` and no rate-limit classification of any kind". That sentence
is true of the executor directory and false as a statement about capability
execution, which is the thing the criterion is about.

What the tree actually does, on the path by which a capability tool is
executed as agent traffic — the meta-MCP invoke path. (There is a second,
non-agent path, a CLI diagnostic; it is disclosed and dispositioned below,
not folded into this table.)

| step | site | what happens to a capability `429` |
|---|---|---|
| HTTP send | `src/capability/executor/mod.rs:124`, `:138` | transport health records **success** — any HTTP status is a live backend (`mod.rs:95`) |
| status check | `executor/jsonrpc.rs:204`, `params.rs:50`, `graphql.rs:260` | `Err(Error::Protocol("… returned {status}: {body[..500]}"))` |
| backend | `src/capability/backend.rs:441` | `?` — propagated unchanged |
| dispatch | `src/gateway/meta_mcp/invoke.rs:2447-2458` | `call_capability_tool_with_identity`, inside `dispatch_to_backend` |
| classify | `invoke.rs:1384` → `BudgetOutcome::of` `:3006` | `is_rate_limited(&error.to_string())` → `IgnoredRateLimit` |
| record | `invoke.rs:1896-1913` | returns before both budgets; emits `mcp_error_budget_suppressed_total{reason=rate_limited}` |

So a capability `429` is **already excluded** from the server error budget, from
the per-capability budget (`kill_switch.record_capability_failure`, `:1929`), and
from the kill switch. It is excluded because `reqwest::StatusCode`'s `Display` is
`429 Too Many Requests` and sits at the FRONT of the message, ahead of the
500-character body truncation, and `is_rate_limited` (`src/gateway/recovery.rs:286-307`)
matches both the `429` token and `too many requests`.

Two further facts that bound the problem:

- **There is no second *agent-facing* execution path.**
  `call_capability_tool_with_identity` has exactly one caller (`invoke.rs:2458`),
  and `src/gateway/router/backend_handlers.rs` contains no capability route
  (`rg capabilit` → no match). Every other `get_capabilities()` site is
  listing, search, policy or status. Nothing an agent can drive reaches a
  capability tool while bypassing `record_error_budget`.

  **One path does bypass it, and is excluded here on purpose, not missed.**
  `cap_test` (`src/commands/cap.rs:220-256`) constructs its own
  `CapabilityExecutor` (`:241`) and calls `.execute()` directly — an
  operator-invoked, one-shot CLI diagnostic (`mcp-gateway cap test`). It is
  never agent traffic and never reaches `MetaMcp::dispatch_to_backend`.
  Routing a CLI subcommand through the meta-MCP invoke path to buy it budget
  participation is a real architectural change for a manual diagnostic tool,
  for no agent-facing benefit — rejected on that basis, not overlooked.
  Residual, stated rather than silently absorbed: an operator running
  `cap test` against a throttled capability spends the same upstream provider
  quota a real invocation would, and the error budget never records it — no
  auto-disable, no counter, nothing. Acceptable for a tool an operator runs
  by hand; it would not be if `cap_test` were ever wired into unattended
  tooling. That premise is checked, not assumed: a whole-tree search
  (`rg --hidden --no-ignore 'cap_test|cap test'`, excluding `target/`) finds
  exactly two hits — the dispatch arm and the definition, both in
  `src/commands/cap.rs` — and no CI job, script, or workflow invokes it as of
  this revision.

  **A third bypass exists and was never in this design's scope to begin
  with — not implemented and skipped, simply outside §P0's FOR.** `CapabilityBackend`
  (`pub struct`, `capability/backend.rs:122`) and `CapabilityExecutor`
  (`pub struct`, `executor/mod.rs:51`) live in `pub mod capability`
  (`src/lib.rs:36`), and `CapabilityBackend::call_tool_with_context`
  (`capability/backend.rs:390`) is a `pub async fn`. mcp-gateway ships as a
  crate on crates.io; an external Rust program depending on it can construct
  either type and call it directly, never touching `MetaMcp::dispatch_to_backend`
  or `record_error_budget`. §P0 scopes this design to mcp-gateway's *own*
  execution paths — the meta-MCP invoke path and the `cap_test` CLI above —
  not to what a downstream library consumer does with an already-public API.
  Named so a reader does not read the invoke path as the only caller of
  `CapabilityExecutor::execute`; disposed as out-of-scope, not fixed.
- **There is no capability circuit breaker to protect.** `Failsafe` lives on
  `PooledEntry` (`src/backend/pool.rs:78`), the MCP-backend pool. `CapabilityExecutor`
  owns a bare `HealthTracker` (`executor/mod.rs:65`) and nothing else. "A 429 must
  not trip the capability breaker" is vacuous, and the health tracker cannot be
  fooled by a `429` because it never reads the status.

The correct statement of the gap is therefore not *capability execution records
nothing*. It is: **the exclusion is delivered, unpinned, and carried by a string.**

## 2. The two real gaps

**G1 — the classification is text-dependent.** Nothing in the executor knows it
observed a `429`. The status is destroyed into prose at `jsonrpc.rs:204` and
reconstructed by substring match 2,800 lines away. Three independent formatting
sites must all keep the status *in* the message for the exclusion to hold.
Order is not the hazard: `is_rate_limited` lowercases the whole string, matches
its phrases anywhere in it, and accepts `429` as a standalone token
(`recovery.rs:286`), so moving the status after the body survives, and so does
wrapping the error ("upstream request failed: …") or replacing `{status}` with
`{status.as_u16()}`, which keeps the bare token even when it drops "Too Many
Requests". What breaks it, and looks harmless in review: dropping the status
altogether, gluing the digits into a longer token (`HTTP429` lowercases to
`http429`, which is not the token `429`), or adding a fourth protocol executor
that formats its own message without a status. The predicate is also fooled in the other direction
by a body that merely contains the word "throttled".

**G2 — nothing pins it.** No test drives a capability `429` through
`dispatch_to_backend` into `BudgetOutcome`. The existing budget tests
(`invoke.rs:4412`, `:4433`, `:4451`, `:4465`) construct `BudgetOutcome` values or
synthetic strings directly; the capability executors' tests stop at the
`Error::Protocol` boundary. Delete the status from all three format strings and
the whole suite stays green while every throttled capability starts consuming its
own budget and auto-disabling itself under load — which is precisely the failure
GH #475 exists to prevent, arriving silently.

A third candidate gap does not exist and is recorded here so it is not
rediscovered: capability transport health is already status-blind by construction
(`executor/mod.rs:124`), not by text, so a `429` cannot mark a capability backend
unhealthy in `/health`.

## 3. What RL.10 actually demands — an ambiguity, resolved

The test-plan row (`docs/design/2026-09-05-error-budget-test-plan.md:36`) reads:

> `| GH475.RL.10 | a typed rate-limit outcome needs no text | a capability 429 observed at jsonrpc.rs is excluded with the error text scrubbed to an unrelated string | integration | behaviour | src/capability/executor/ tests |`

Two readings:

- **weak** — scrub the *body*, keep the status. Passes today, unmodified, because
  the status precedes the 500-char body truncation.
- **strict** — scrub the *whole message*, status included. Fails today, because
  with the status gone there is nothing left to classify from.

Strict is the face-value reading of both columns, and weak is the strained one.
"observed at `jsonrpc.rs`" places the observation at the status check, and "the
error text" means the text, not a half of it that the row never names. The weak
reading needs "the error text" silently narrowed to "the body portion", and it
makes the headline — *"a typed rate-limit outcome needs no text"* — false, since
under it the outcome needs exactly one piece of text and always has. A later
reader should not be able to take weak as the reasonable default: it is not the
plain reading, it is the reading that survives the tree as it stands.

Adopting it would also let the criterion be closed by a test whose subject is the
formatting of an error message — a test that passes for a reason unrelated to what
the row is named after. **Strict reading adopted.** Under it,
RL.10's behaviour is delivered and its property is genuinely absent, and those
have different fates (§5).

## 4. Options

### O0 — capability execution should not participate in the budget system at all

Argued, not assumed away, because it is the option that would delete the
criterion rather than satisfy it.

The case for it: error budgets and the kill switch exist to stop routing to a
backend that has stopped working. A capability backend is not a process the
gateway owns — it is somebody's REST API reached over HTTP, already covered by
transport health, and per-capability auto-disable is a blunt instrument to point
at a third party's endpoint. If capabilities did not participate, `is_rate_limited`
would have nothing to exclude them from, G1 and G2 would evaporate, and RL.10
would be deleted as a criterion about a system capability execution is not in.

Rejected, three reasons, any one sufficient:

1. **It is a removal, not an omission.** `record_capability_failure`
   (`invoke.rs:1929`) and the per-capability budget config exist and are wired;
   auto-disable of a single capability is a shipped 4.0.0 feature. Non-participation
   means deleting that, which is a scope change requiring the requester's recorded
   agreement, not an engineering simplification.
2. **The budget is measuring the right thing.** A capability that returns 500s
   for ten minutes should stop being routed to, for exactly the reason an MCP
   backend should. The `429` carve-out is the whole point of GH #475: distinguish
   *throttled* from *broken*. Dropping participation to avoid the distinction
   throws out the measurement to avoid one classification.
3. **It makes the failure mode worse, silently.** Without the budget the only
   remaining signal is transport health, which records a `429` and a `500`
   identically — as a success. A capability answering `500` to everything would
   read as perfectly healthy forever.

### O1 — typed rate-limit error from the executor, via existing `Error::Http` (RECOMMENDED)

Revised from an earlier draft of this option, which proposed a new
`crate::Error` variant (see the superseded cost discussion this replaced, now
folded into the DESIGN EVENTs below). Reuse beats addition here: at each of
the three format sites (`jsonrpc.rs:204`, `params.rs:50`, `graphql.rs:260`),
call `response.error_for_status_ref()` *before* the body is consumed. Verified
at source (reqwest 0.13.4, `src/async_impl/response.rs:409`): on `Err`, the
returned `reqwest::Error` is built from status, URL and the canonical reason
phrase only — it borrows nothing from the response body, so the borrow ends
immediately and `response.text().await` remains legal afterward on the same
`response` value. That ordering is what makes this option not a patch:
call `error_for_status_ref()` first, use its `Err` to log the body via
`tracing::warn!` for diagnostics (the disposition change named below), then
return `Err(Error::Http(err.without_url()))` through the
`#[from] reqwest::Error` conversion that already exists (`src/error.rs:168-170`).

**The gate is `status == 429`, NOT `error_for_status_ref()`'s `Err`.** Both
review legs caught the same defect independently and it is the one substantive
revision this review produced. `error_for_status_ref()` errors on *every*
non-success status, so gating on it would route all 4xx and 5xx through
`Error::Http` — whose classification arm keys on 429 and falls through to
`BackendError` for everything else. That is a real degradation, verified at
source: `classify_from_detail` (`meta_mcp/invoke.rs:3029-3060`) reads the
status out of today's `Error::Protocol` *text* and returns `Timeout` for
`408`/`504`/`"timeout"` and `BackendError` for `500`/`502`/`503`. A 504 that
tells an agent "timeout, retry after backoff" today would tell it
"backend error" tomorrow. DESIGN EVENT 3 refused exactly that trade for the
429 case; taking it for every other status would have been the same mistake
one status wider.

So each format site branches:

```
if status == 429  -> Error::Http(error_for_status_ref().unwrap_err().without_url())
otherwise         -> Error::Protocol(...)   // today's text, byte for byte
```

The non-429 path is **untouched** — same string, same classification, same
recovery hint. Only the 429 case changes carrier, which is the only case RL.10
is about. This is an elimination, not a patch: after it, "O1 degrades non-429
classification" cannot be stated, because O1 no longer touches non-429. Classification reuses
`reqwest::Error::status()`, verified to return `Some(code)` on a status error
(`reqwest src/error.rs:180`). `BudgetOutcome::of` matches on `Error::Http`'s
status; `is_rate_limited` stays where it is for the MCP-backend path, which has
no typed status to match on.

Eliminates rather than patches: after it, the finding "the exclusion depends on
message text" cannot be stated of the capability path.

It does **not** give `Retry-After` a place to live, and the superseded draft's
claim that it did was wrong. `reqwest::Error` carries three fields — `kind`,
`source`, `url` (`reqwest-0.13.4 src/error.rs:26-30`) — and the status
constructor fills `Kind::Status(status, reason)` and nothing else
(`:343-360`). The headers go with the response. Anything that later wants
`Retry-After` must capture it explicitly, at the format site, before the body
is consumed — a second value beside the error, not a field of it. Corrected
after the Kimi K3 leg of the §12 review flagged the sentence; verified at the
reqwest source above rather than accepted on the reviewer's word.

Cost, checked rather than assumed (section 6): reusing `Error::Http` adds no
public symbol (no D28) and breaks no exhaustive downstream `match` (no D2) —
`Http` already exists at the crate root (`src/lib.rs:94`, `src/error.rs`) and
downstream code that matches it today keeps matching it. That removes the
breaking-change cost the earlier draft carried. What it does **not** remove is
the obligation to name what changes, per §P3: three DESIGN EVENTs, the two
required by team-lead review plus one this document's own re-check surfaced,
are recorded here rather than left implicit.

**DESIGN EVENT 1 — diagnostic disposition changes.** Today the three format
sites embed the (truncated) response body directly in the formatted error's
`Display` string; under O1 the body moves to a `tracing::warn!` log line and
the returned `Error::Http`'s `Display` carries only status, URL and reason
phrase (reqwest's own formatting). An API consumer reading the error text sees
less; an operator reading logs sees the same information at a different level.
Named because it is a real observable-contract change even though it breaks no
type.

*The analysis above was half an analysis, and the missing half is a security
regression.* It asked only what the agent-facing text LOSES. What it GAINS is
the request URL: reqwest's `Display` appends `" for url ({url})"` unconditionally
whenever the error carries one (verified at source, reqwest 0.13.4
`src/error.rs:279-281`), and it redacts nothing from that URL — query string
included. REST capabilities put resolved secrets in query parameters:
`substitute_string` (`params.rs:164`) expands `{keychain.X}` and `{env.VAR}`,
and `substitute_params` (`:172`) turns the result into query pairs. So a naive
O1 would take an API key that today never leaves the process and hand it to the
calling agent inside an error string, at every non-success status, for every
REST capability that authenticates by query parameter.

RULING: **the URL never reaches the error.** `.without_url()` is called on the
status error before it is wrapped, so `Error::Http`'s `Display` carries the
status and reason phrase and nothing else. This is not a new mechanism — it is
the one this module already uses: `redact_url` (`executor/mod.rs:107-109`) is
`e.without_url()`, applied to every transport error `send_with_retry` returns
(`:129-133`, `:156`). The capability executor already treats a reqwest URL as
something an agent must not see; O1 was about to introduce the first path that
did not. The full `Display`, URL and all, stays in the `tracing::warn!` line
beside the body, where an operator reads it and an agent does not.

Both review legs raised this independently — Kimi K3 as its only HIGH,
Grok as CRITICAL/CERTAIN — and Grok named the in-tree helper. Two vendors on
one defect, confirmed at source before acceptance (V).

**DESIGN EVENT 2 — the JSON-RPC error code changes on the paths that emit one,
and this was disclosed, then ruled on — RESOLVED, not accepted-as-consequence.**

*Scope correction, from the Grok leg:* the heading of this event used to say
"what an MCP client sees", and on the meta-MCP invoke path that is wrong.
`invoke.rs:1452-1479` converts an `Err` into a tool-level result —
`isError: true`, `content: [e.to_string()]`, plus a `RecoveryHint` from
`classify_dispatch_error` — and deliberately never promotes it to a JSON-RPC
protocol error, so `to_rpc_code` is not called there at all. What an agent on
that path reads is the `Display` string and the recovery hint, which is why
DESIGN EVENT 1 and DESIGN EVENT 3 are the ones that bind the agent contract.
This event is still real and still worth ruling on — `to_rpc_code` is live for
the paths that do emit a protocol error — but it governs a narrower surface
than the original wording claimed. Verified at source before the correction.
`to_rpc_code` (`src/error.rs:193-209`) gives `Protocol(_)` its own arm,
`-32600`; `Error::Http` has no explicit arm and falls through the trailing
`_ => -32603`. Nothing in the capability path constructs `Error::Http` today —
this option is the first thing to route a capability-originated error through
it. The Kimi K3 review leg challenged that premise as overstated, on the theory
that `#[from] reqwest::Error` plus `?` already routes connect/DNS/timeout
failures into `Http`. **The challenge dies at source and the premise stands, on
stronger evidence than the original `rg`:** every reqwest error in the
capability path is mapped explicitly, never `?`'d. `send_with_retry` returns
`Error::Transport` on both its send arms (`executor/mod.rs:129-133`, `:156`),
and every body-consuming call maps to `Error::Protocol`
(`params.rs:48`, `:64`, `:78`, `:92`, `:99`; `jsonrpc.rs:201`, `:212`;
`graphql.rs:257`, `:268`). There is no bare `?` on a `reqwest::Error` anywhere
on the path. A `status() == None` `Error::Http` therefore cannot reach the
guarded arms from here — before O1 because the variant is never constructed,
after O1 because `error_for_status_ref()` only ever yields a status-bearing
error. Left unaddressed, a capability `429`
would surface as `-32603` (internal error) — wrong, and no more right than
today's `-32600` was, since a throttled upstream provider is neither an
invalid request nor a gateway fault.

Disclosing the consequence surfaced that `to_rpc_code` already reasons about
exactly this shape of case, four lines above the trailing arm:

```rust
Self::BackendUnavailable(_) | Self::CircuitOpen(_) | Self::BackendTimeout(_) | Self::Transport(_)
// Same class as `Transport` to a JSON-RPC caller: a backend-side
// failure, not a gateway fault. Omitting it reported a missing
// backend command as an internal error.
| Self::TransportPermanent(_) => -32000,
```

A capability `429` is that class: a backend-side failure, not a gateway
fault. **Ruling (operator, via team-lead): map it to `-32000`, not `-32603`.**
Moving `-32603` to a differently-wrong code was rejected as a trade not worth
taking while the correct arm already exists.

**Keyed on the discriminator, not the variant.** O1 adds a guarded arm ahead
of the trailing fallthrough — `Self::Http(e) if e.status() == Some(429) =>
-32000` — rather than moving the whole `Error::Http` arm to `-32000`.
`#[from]` populates `Error::Http` at every `?`'d reqwest call in the crate,
including outbound gateway calls that are not backend dispatch; moving the
arm wholesale would change their code too, and that blast radius has not been
checked call site by call site. A non-429 `Error::Http` (a transport error,
a 5xx, anything else) still falls through to `-32603`, unchanged from
before O1 — the semantic widening named below is scoped to the `429` case
only, not to `Error::Http` in general. `.status()` is the same predicate
`BudgetOutcome::of` and `is_rate_limited` already use, so this costs no new
mechanism and the three checks cannot disagree on what a `429` is.

This is still a genuine widening of what `Error::Http` carries — until now it
represented only transport failures (a request that never got a response);
O1 makes it also represent a capability backend's HTTP status, discriminated
by status code at the one site that needs to tell them apart. No new symbol,
no broken match, but a real semantic reuse, named rather than left to be
discovered by whoever next greps `Error::Http`'s call sites.

If mapping `.status()` at this site turns out to need more than the one
guarded match arm — a signature change, a new call path, anything touching
dispatch — that is a second hop and stops here for a report, not a silent
widening. Same if `.status()` is not reachable at the mapping site: report it
and pick, with the operator, between narrowing this document's claim and
accepting `-32603` explicitly, with the reason recorded.

Checked and closed, not left as risk: reusing `Error::Http` for capability
status errors introduces **no retry-storm risk**. `is_retryable`
(`src/chains/retry.rs:179`, `src/failsafe/retry.rs:96`) treats `Error::Http(_)`
as retryable, but it is consulted only by `failsafe::retry::with_retry` (sole
caller `src/backend/ops.rs:218`, the MCP-backend path) and
`chains::retry::retry_step` (sole caller `src/chains/executor.rs:175`).
Capability's own retry logic, `send_with_retry`
(`src/capability/executor/mod.rs:111-160`), is self-contained and never calls
`is_retryable` — so an `Error::Http` returned from the capability path cannot
trigger a retry it would not already have triggered under the current text-
matching behaviour. See the new Resolved rows in section 6.

**DESIGN EVENT 3 — the RecoveryHint category for a capability error can
degrade, and O1 must prevent it, not just name it.** `classify_dispatch_error`
(`src/gateway/meta_mcp/invoke.rs:2940-2958`) has an explicit arm,
`Error::Protocol(msg) => (classify_from_detail(Some(msg)), msg.clone())` —
the mechanism that turns a `429`-shaped message into
`ErrorCategory::RateLimited` and a retryable `RecoveryHint` (asserted by
`rate_limit_429_classified_as_rate_limited`, `invoke.rs:3078`). `Error::Http`
has no arm there either, and falls through the same trailing
`_ => (ErrorCategory::BackendError, error.to_string())` that DESIGN EVENT 2
found in `to_rpc_code` — the identical gap, in a second match. Confirmed
wired, not theoretical: `classify_dispatch_error` is called from the `Err(e)`
branch of the same `dispatch_result` O1 feeds to `BudgetOutcome::of`
(`invoke.rs:1384` records the budget, `invoke.rs:1461` classifies the error,
both off one match on one result). Unfixed, a throttled capability call that
O1 correctly keeps out of the failure budget would still tell the calling
agent `BackendError` with no retry guidance instead of `RateLimited,
retry: true` — losing the exact recovery signal RL.* exists to get right.
Unlike DESIGN EVENT 2's JSON-RPC integer, a rarely-inspected protocol detail,
this is agent-facing behaviour on the path this design is about, so naming it
as accepted degradation is the wrong disposition. O1's implementation adds an
`Error::Http` arm to `classify_dispatch_error` alongside the existing
`Protocol` one — matching on `reqwest::Error::status()` directly (already
used by `BudgetOutcome::of`, so the two cannot disagree on what a `429` is,
same rationale as `is_rate_limited`'s single-predicate design) rather than
round-tripping through `classify_from_detail`'s text scan — so that "a
capability 429's recovery hint degrades under O1" cannot be stated of the
landed code. This is one match arm, mechanically identical in shape to the
one already present, folded into O1's implementation steps (section 7, item
3) rather than a separate option.

4.0.0 is a major release in preparation, but that is no longer the load-bearing
fact here — O1 as revised needs no breaking-change window, because it adds no
public symbol and breaks no match. What still needs the requester's sign-off is
narrower: the three DESIGN EVENTs above, not an enum-widening ask. See the revised
section 6.

### O1b — the same classification, carried crate-internally (rejected)

Revised alongside O1: the question this section answers is no longer "can we
avoid O1's public-enum cost", because reusing `Error::Http` means O1 no longer
has one. What remains is narrower and still worth asking — could the
classification avoid `crate::Error` entirely and stay on a purely
crate-internal carrier, so that none of the DESIGN EVENTs named in O1 need apply?
Both ends of *this* wire — the meta-MCP invoke path's classification hookup,
the only wire O1 touches — are in-crate: the status is known at
`executor/jsonrpc.rs:204` and consumed at `invoke.rs:1384`. That is narrower
than "nothing here is externally reachable": §1 discloses a separate,
out-of-scope path where a library consumer calls
`CapabilityBackend`/`CapabilityExecutor`'s public API directly, and this
section's in-crate claim is not about that path — it is unaffected by O1b
either way, since O1b never proposes changing those signatures.

Rejected for a signature reason, not a language one this time: the carrier
between the two ends is the return type of
`CapabilityBackend::call_tool_with_context` (`src/capability/backend.rs:390`) —
`pub`, on a `pub` type, in a `pub` module (`src/lib.rs:36`). A bespoke
crate-internal carrier would still have to cross that `pub` boundary somehow —
either as a new field/variant on an already-`pub` type (D28 again, the exact
cost O1 now avoids by reusing `Error::Http`), or by converting to
`crate::Error` at the boundary, which is what O1 already does and does not
need a second carrier type to do. O1b buys nothing O1 does not already have,
and adds a second representation of the same status alongside `Error::Http` —
the two-representations-can-disagree defect O3 is rejected for below.

This is not O3. O3's defect is two representations that can disagree; O1b is one
representation in the wrong place.

### O2 — one shared error constructor plus a format-contract test

Keep the string, but funnel all three executors through a single constructor that
guarantees the status token leads, and test that constructor.

Rejected as the primary: the defect stays describable. A fourth executor that does
not use the constructor, or a caller that wraps the error, re-arms it, and the
contract test cannot see either. This is the patch the repair protocol says to
take only when the root cause is out of scope — it is not.

### O3 — classify at `dispatch_to_backend` from a side channel

Have the dispatch site ask the capability layer "was that a rate limit?" via
per-call state set during execution.

Rejected: two representations of one outcome that can disagree — the caller sees
one error, the budget sees another — and the side channel has to be per-call state
threaded through an `async` boundary that currently threads none.

### O4 — do nothing; record RL.10 as ABSENT

Rejected. The behaviour is present and correct; recording it as absent is a false
negative in the ledger, and leaving it unpinned (G2) is the actual risk.

## 5. Verdict

**Capability execution participates in the budget system, and already does.**
O1 is the change; O0 is rejected on the record above.

### What records what, and where

| recorder | owner | point | a `429` counts as |
|---|---|---|---|
| transport health | `HealthTracker` on `CapabilityExecutor` (`executor/mod.rs:65`) | inside `send_with_retry`, at the HTTP send (`:124`, `:138`) — before any status is read | **success** (unchanged; status-blind by construction) |
| server error budget + kill switch | `MetaMcp` (`invoke.rs:1896`) | after `dispatch_to_backend` returns (`:1384`) | **excluded** — no sample recorded either way |
| per-capability budget / auto-disable | same (`:1929`) | same call | **excluded** |
| circuit breaker | none exists for capabilities | — | n/a |

`execute_with_context` itself records nothing new. That is deliberate and is the
answer to "at which point in `execute_with_context`": the classification is
produced there (the executor is the only place holding a `StatusCode`) and
*consumed* at `invoke.rs:1384`, where the recording already happens for every
backend kind. Adding a recorder inside the executor would build a second
accounting surface beside a working one and give a capability `429` two chances
to be counted.

### How it composes with the MCP-backend path

It does not compose — it runs *beside* it, and that is correct. The MCP-backend
path records at `src/backend/ops.rs:254` via `Failsafe::record_dispatch_failure`
(`src/failsafe/mod.rs:88`), which owns a circuit breaker and a per-slot health
tracker. The capability path records at `invoke.rs:1384` via `BudgetOutcome`,
which owns budgets and the kill switch. They share exactly one thing: the
predicate `is_rate_limited` (`recovery.rs:286`) — the single signal table RL.11
is about. O1 does not change that predicate, does not add a second one, and does
not move either recorder; it changes only what the capability path *feeds* into
the decision, from a formatted string to a type. An MCP backend keeps using the
text predicate because a transport error there genuinely has no typed status.

### Fate of the criterion

- **RL.10 — behaviour:** MET, one leg pinned. The exclusion works today. The
  test this section originally named — drive a capability `429` through invoke,
  assert `IgnoredRateLimit` and no budget sample — is **not** the test that
  landed: `BudgetOutcome::of`'s recorder is private to `invoke.rs`, so the pin
  enters at the shared predicate instead (§7, item 1). What is asserted is therefore
  the predicate leg; the `BudgetOutcome` leg of the trace stays read off the
  source. This is the part that must land regardless of O1.
- **RL.10 — property ("needs no text"):** MET once O1 lands. Revised from an
  earlier draft that recorded this as ABSENT pending a breaking-API ask: O1 as
  reused (via `error_for_status_ref()` into the existing `Error::Http`, not a
  new variant) adds no public symbol and breaks no exhaustive match, so there
  is no D2/D28 gate to clear and O1b's "no crate-internal route around the
  gate" finding no longer has a gate to be about — recorded below as CLOSED,
  not silently dropped. What O1 still owes, per §P3, is naming its two DESIGN
  EVENTs (section 4): the diagnostic-disposition change and the JSON-RPC-code
  change. Both are named there and in the Resolved table below; neither
  blocks implementation, because neither is a public-surface change.
- The "if the ask is refused" branch this section previously carried is now
  moot for the same reason and is closed explicitly rather than left to lapse:
  there is no enum-widening ask left to refuse. See the Deferred table's
  closure note in section 6.

## 6. Open questions — scheduled, per §P1

### Resolved (checked)

| question | check run | result | what it changed |
|---|---|---|---|
| Does any *agent-facing* path reach a capability tool without `record_error_budget`? | `rg call_capability_tool`, `rg capabilit src/gateway/router/backend_handlers.rs`, read of every `get_capabilities()` site — scoped to the meta-MCP invoke surface, the only surface an agent drives | one execution caller, `invoke.rs:2458`, inside the recorded window; no route in `backend_handlers.rs` | killed a suspected third gap **on the invoke surface**; the design does not add a recorder for an agent-facing path that does not exist. This search was scoped to that surface and could not see, and does not claim to see, the CLI (`src/commands/cap.rs`), which never routes through `invoke.rs` — see §1's disposition of `cap_test` for that separate, non-agent path |
| Does the 500-char body truncation break the exclusion? | read `jsonrpc.rs:204-207`, `params.rs:50-54`, `graphql.rs:260-263` | status precedes the truncated body in all three | RL.10 under the *weak* reading passes today — which is why section 3 had to settle the reading rather than assume it |
| Is there a capability circuit breaker a `429` could trip? | `rg failsafe\|Failsafe src/capability/`, read `executor/mod.rs:65` | none; bare `HealthTracker` only | removed "must not trip the breaker" from the design as vacuous, in one line rather than a section |
| Does capability transport health mis-count a `429`? | read `send_with_retry` `executor/mod.rs:112-158` | any HTTP status records success | no change needed at the transport layer |
| Is `crate::Error` `#[non_exhaustive]`? If it were, O1 would add no breaking change and need no ask. | read `src/error.rs:14-15`, `rg non_exhaustive src/error.rs src/lib.rs` | no attribute; the enum is plain `pub enum Error` | **superseded, closed not dropped:** this check was scoped to the earlier new-variant draft of O1. The revised O1 reuses `Error::Http` and never adds a variant, so `#[non_exhaustive]` is no longer load-bearing for this option — recorded so the question does not silently reappear as if never asked |
| Does a rate-limit-shaped variant already exist, so that O1 would only construct an existing symbol differently? | read all 22 variants of `src/error.rs:15-179` | none; the nearest precedent is `Forbidden`, which does carry a typed HTTP `status` | **superseded, closed not dropped:** answered a question the revised O1 no longer asks — it reuses `Error::Http`, an existing transport-error variant, rather than adding a new one |
| Can the classification avoid the public enum entirely by staying crate-internal? | read `CapabilityBackend::call_tool_with_context` `src/capability/backend.rs:390`, `pub mod capability` `src/lib.rs:36`, plus the Rust rule that variants inherit enum visibility | no: no `pub(crate)` variant exists as a language feature, and the alternative carrier is an equally public signature | O1b's conclusion (no gate-free crate-internal route) is retained as the answer to a narrower, still-live question: O1b now compares against O1's *actual* mechanism (reusing `Error::Http`) rather than a hypothetical new variant, and still finds no cheaper carrier — see O1b as revised |
| Does `error_for_status_ref()` lose the response body needed for diagnostics? | read reqwest 0.13.4 source `src/async_impl/response.rs:409`, `src/error.rs:180` | the returned error is built from status/URL/reason only, borrowing nothing from the body; the borrow ends immediately so `response.text().await` remains legal after | confirms O1's mechanism is sound: call `error_for_status_ref()` first, log the body via `tracing::warn!`, then convert — no diagnostic information is silently lost, it moves to a log line (DESIGN EVENT 1, section 4) |
| Does the borrow-then-consume ordering actually compile at the **REST** site, where `handle_response` moves `response` into `.text().await` in the same block? | inserted `let http_err = response.error_for_status_ref().err();` immediately before the `.text()` call at `params.rs:46` and ran `cargo check --lib` (2026-09-06), then put the original content back | `Finished dev profile ... in 23.49s` — compiles clean; the `Err` arm yields an owned `reqwest::Error`, so the `&Response` borrow ends before `.text()` moves the value | closes the one site where O1's ordering was not obviously free. The reqwest source read above establishes the mechanism; this establishes it **at the site the DETECTION test pins**, so no reviewer round is spent on it |
| What JSON-RPC code does a capability `429` surface as, once it is carried as `Error::Http`? | read `to_rpc_code` `src/error.rs:193-209`; `rg` confirms nothing in the capability path constructs `Error::Http` today | `Protocol(_)` has its own arm (`-32600`); `Http` has none and falls through `_ => -32603` — named as DESIGN EVENT 2, then **ruled on**: a guarded `Self::Http(e) if e.status() == Some(429) => -32000` arm, same class as the existing `BackendUnavailable\|CircuitOpen\|BackendTimeout\|Transport\|TransportPermanent => -32000` arm four lines above it; non-429 `Http` still falls through to `-32603`, unchanged | DESIGN EVENT 2 (section 4): resolved to `-32000`, not left as `-32603` — moving the whole `Http` arm was rejected (blast radius across every `?`'d reqwest call in the crate, not checked call-by-call); the guarded arm costs no new mechanism since it reuses the `.status()` discriminator `BudgetOutcome::of` already keys on |
| Does reusing `Error::Http` on the capability path create a retry-storm risk? | read `is_retryable` `src/chains/retry.rs:179` and `src/failsafe/retry.rs:96`; traced their sole callers `src/backend/ops.rs:218` (MCP-backend) and `src/chains/executor.rs:175`; read `send_with_retry` `src/capability/executor/mod.rs:111-160` | `is_retryable` treats `Error::Http` as retryable, but capability's own retry logic never calls `is_retryable` — it is self-contained | no risk: an `Error::Http` returned from the capability path cannot trigger a retry it would not already trigger under today's behaviour; closed rather than left as an unstated risk |
| Does any other match on `crate::Error` discriminate `Protocol` from `Http` on the dispatch path O1 touches? | `rg 'Error::Protocol\|Error::Http' src/`, read `classify_dispatch_error` `invoke.rs:2940-2958` and its call site `invoke.rs:1461`, traced back to the shared `dispatch_result` also read at `invoke.rs:1384` | yes: `classify_dispatch_error` gives `Protocol` a `classify_from_detail` arm and lets `Http` fall through `_ => BackendError` — the same shape of gap `to_rpc_code` has | DESIGN EVENT 3 (section 4): unlike the JSON-RPC code, this one is not accepted as-is — O1's implementation must add the missing `Http` arm so the RecoveryHint category does not degrade |

### Deferred

None. The earlier deferred question — "may `crate::Error` gain a typed
rate-limit variant, given D2/D28" — is **closed, not dropped, because it is
moot**: the revised O1 (section 4) reuses the existing `Error::Http` variant
via `error_for_status_ref()` instead of adding one, so there is no enum
widening left to ask the operator to approve. This closes what was tracked as
finding #4 (moot given finding #2's O1 revision) explicitly, rather than
letting it lapse silently when O1 changed underneath it. What O1 still owes —
naming its three DESIGN EVENTs — is not a deferred question; all three are named in
section 4 and recorded as Resolved above, and none blocks implementation
(DESIGN EVENT 3 is a required implementation step, not an open question).

## 7. What lands next, in order

1. **(item 1)** The RL.10 behavioural pin (G2) — **LANDED 2026-09-06, at a different seam
   than this section named, and the difference matters.**

   The seam named above — a capability `429` driven through the invoke path from
   a mock upstream, asserting `mcp_error_budget_suppressed_total` and two
   untouched budgets — **is not reachable, by design of the security layer, not
   by any shortcoming of the fixture.** `CapabilityExecutor::execute_jsonrpc`
   calls `validate_url_not_ssrf` (`capability/executor/jsonrpc.rs:153`), which
   rejects an IP literal in a private or reserved range before the HTTP call; a
   domain-named loopback host passes that sync check and is then stopped by
   `PinningResolver` (`capability/executor/mod.rs:176-184`) at DNS. There is no
   env or test escape hatch and none should be added: a fixture that opens an
   SSRF hole to prove a rate-limit property is a bad trade. The named counter is
   also not observable in-process — no metrics recorder is installed in the test
   harness — so the two-budget effect was the only half of that observable that
   could have been asserted anyway. Nor is there an alternative route around the
   probe: `CapabilityBackend` (`capability/backend.rs:122`) and
   `CapabilityExecutor` carry no trait or DI seam a test could substitute
   instead — the only trait in the chain, `ProtocolExecutor` (`executor/rest.rs:48`),
   abstracts response *formatting* (REST/JSON-RPC/GraphQL), not transport
   substitution, and has no injection point today: `dispatch_protocol`
   (`executor/mod.rs:361`) is private and selects concretely, and the
   `HashMap<&'static str, Arc<dyn ProtocolExecutor>>` that would make it
   injectable is documented at `mod.rs:356-360` as future work, not present
   code. So the only way to drive a real `429` through the full invoke path
   today is the SSRF-blocked loopback probe; a mockable substitute is not a
   route nobody tried, it is a route that does not exist yet to try.

   What landed instead: `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`
   (`src/capability/executor_tests.rs:993`). It drives a real loopback `429` and
   a real `500` whose bodies are **identical** — the status line is the only
   difference — through the production formatter `handle_response`
   (`capability/executor/params.rs:38`, format site `:51`) and hands each
   resulting `Error::Protocol` message to `Failsafe::record_dispatch_failure`
   (`failsafe/mod.rs:88`), which runs the same `is_rate_limited` predicate
   (`gateway/recovery.rs:286`) that `BudgetOutcome::of` runs. `Failsafe` is
   **not on the capability path** — only `backend/ops.rs:271` and `:409` reach
   it, and capability errors go to `BudgetOutcome::of` instead — it is the only
   *public* consumer of that predicate, which is why the pin enters there. What
   the pin therefore establishes is the classification of a real capability
   error string, not the capability path's own budget bookkeeping. The observable is
   the **effect** — the throttled response leaves the circuit breaker closed,
   the control opens it — never `BudgetOutcome`'s return value. The control is
   what proves the path ran and discriminated.

   What that pin does and does not close, stated plainly so no reader has to
   infer it:
   - it closes G2 **for the predicate leg of all three capability format
     sites** — that a real error string built at `params.rs:51`,
     `jsonrpc.rs:205` or `graphql.rs:261` is classified as rate-limited. It
     does not assert the `BudgetOutcome` leg, which stays read off the source.
     CORRECTION, 2026-09-06: this document as first written claimed the pin
     covered the REST leg only and that `jsonrpc.rs:205` and `graphql.rs:261`
     were "driven by no test". That was true when written and is no longer:
     the DETECTION half landed
     `a_real_jsonrpc_429_is_excluded_by_the_shared_rate_limit_predicate`
     (`executor_tests.rs:1194`) and
     `a_real_graphql_429_is_excluded_by_the_shared_rate_limit_predicate`
     (`:1239`) alongside the REST case (`:1002`), each mutation-probed by
     dropping the status from its own format literal. All three legs are now
     pinned; none of them is pinned for G1, which is what this design is for.
   - it closes nothing of G1 at any of the three sites. Detection is not
     prevention; only O1 is.
   - it does not pin that `execute()` calls `handle_response` — the test enters
     at `handle_response`, as the executor's existing response tests do
     (`executor_tests.rs:695`, `:738`, `:787`). The production call site is
     `executor/mod.rs:494`.
   - the meta-MCP recorder half was already pinned, and is not re-pinned here:
     `error_budget_tests` (`gateway/meta_mcp/invoke.rs:4396`) asserts the
     two-budget effect for `IgnoredRateLimit`, `Failure` and `Success`. Those
     tests construct the outcome directly — the shape objection above stands
     against them — but with this pin the two halves meet at the shared
     predicate rather than at a string a test wrote for itself.

   Falsifier: a **mutation** probe, per §P2's retrofitting note — no pre-fix ref
   exists, because the behaviour was never broken. Run 2026-09-06 against
   `params.rs:51` with the status dropped from the `"API returned {}: {}"`
   literal: the throttled case tripped the breaker and the test failed on its
   first assertion (`a real 429 must not trip the breaker`), not on a compile
   error. Restore verified by re-running the test to PASS, not by `git status`.
2. The ledger correction at `RELEASE-4.0.0-criteria-status.md:393` — the ABSENT
   line's stated reason is false and the row splits into behaviour and property.
3. O1 — no longer gated on section 6 (that gate is closed, moot; see the
   Deferred-table closure note). Implementation proceeds directly; its three
   named DESIGN EVENTs (section 4) travel with it into §P4 review. DESIGN
   EVENT 2's ruling (`-32000` via a guarded `Self::Http(e) if e.status() ==
   Some(429)` arm, not a moved `Http` arm) and DESIGN EVENT 3's
   `classify_dispatch_error` `Error::Http` arm land in the same commit as the
   three format-site rewrites, not as a follow-up — a capability `429`
   reaching `to_rpc_code`'s new code path without both also reaching
   `classify_dispatch_error`'s and mapping to `-32000` rather than `-32603`
   is a state the design never intends to exist even transiently.

## 8. Reviews

§12 dual-vendor review of this document: NOT YET RUN.
