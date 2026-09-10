# Design: per-request resend permission through the transport seam

Criterion: `MIK-7272.SUB.4` — "a side-effecting call, re-issued after a broken
stream with a new request id, MUST be protected by an idempotency key or the
tasks extension". Authority: ADR-012 amendment A3 (two resend sites), A1 (only
an explicit annotation grants permission).

## Problem

ADR-012 A3 names two places the gateway can re-issue a call it already sent.

Site 1 — the backend retry layer — is built. `Backend::resend_policy_for`
(`src/backend/ops.rs:150-168`) disables retries for a `tools/call` whose tool is
absent from `self.resend_permitted`, the set of tools whose backend-declared
annotations carry an explicit `readOnlyHint: true` or `idempotentHint: true`.

Site 2 — HTTP session-expiry recovery — is not.
`HttpTransport::request_with_headers` (`src/transport/http/mod.rs:1472-1507`)
detects an expired upstream session, drops the caller's session bucket,
re-runs `initialize()`, and resends the original request verbatim:

```rust
self.sessions.write().remove(bucket);
self.initialize().await?;
return self
    .send_request_with_headers(&request, extra_headers, identity_key, era)
    .await;
```

That recovery is unconditional. If the first attempt reached the backend and
executed a side effect before the session died, the resend executes it a second
time. A transport failure after the backend acted is indistinguishable from one
before it, so the transport cannot decide this on its own — and today it is not
even told.

The recovery is deliberately sited inside the transport (comment at
`src/transport/http/mod.rs:1476`): it must also rescue circuit-breaker
half-open probes, so it cannot be lifted up to the Backend layer where the
permission set lives. The permission must therefore travel *down*.

## Constraint the existing code already fixes

The doc comment on `Transport::request_with_headers`
(`src/transport/mod.rs:26-32`) states the rule for per-request state:

> The headers are passed by value down the call stack — never stashed on the
> shared transport — so concurrent requests from different users cannot
> cross-contaminate (tenant isolation, IDP.3).

A transport instance is shared across concurrent callers. Any resend permission
stored on `self`, in a task-local, or in an ambient context is the same defect
in a new field: caller A's read-only call would license a resend of caller B's
side-effecting one. The permission MUST be a parameter on the call.

## Options

**A — fifth parameter.** Add a resend-permission argument to
`Transport::request_with_headers`. Smallest textual diff. Costs: a fifth
positional parameter on a signature that already reads poorly, and every future
per-request attribute repeats the same signature break.

**B — options struct.** Introduce `RequestOptions<'a> { extra_headers,
identity_key, resend }`, add `request_with_options`, and keep
`request_with_headers` as a defaulted wrapper that denies resend. Costs more
lines now; every later per-request attribute becomes a field rather than a
signature break across three implementors.

**C — ambient context** (task-local, or a field on the transport). Rejected on
the constraint above: it reintroduces exactly the cross-contamination the
by-value header parameter exists to prevent.

**Recommendation: A.** There are three implementors
(`src/transport/mod.rs:41` default, `src/transport/http/mod.rs:1443`, the test
double at `src/gateway/meta_mcp/invoke.rs:4340`) and one production caller
chain (`Backend::request_with_headers`, `src/backend/ops.rs:184`). B pays a
refactor's cost for a second attribute that is not on the roadmap. The
repo rule that a behaviour-selecting parameter is an enum rather than a `bool`
is satisfied by naming the type:

```rust
pub enum ResendPermission { Denied, Permitted }
```

`Denied` is what the defaulted trait method passes, so a transport or a caller
that has not been taught about this refuses to resend rather than silently
resending — the fail-safe direction, matching `carries_identity_headers`
defaulting to `false`.

## Behaviour

1. `Backend::request_with_headers` derives the permission from the same source
   site 1 uses — membership of `resend_permitted` for a `tools/call` — via a
   shared predicate, so the two sites cannot drift apart.
   A non-`tools/call` method is `Permitted`: `initialize`, `tools/list` and
   friends carry no side effect, and refusing to recover them would regress
   MIK-5982/MIK-6040.
2. `HttpTransport` recovery: on `Denied`, drop the session bucket and
   re-initialize as it does today (the session IS dead; leaving it poisons
   every later call), but return the original error instead of resending. On
   `Permitted`, behave exactly as today.
3. The refusal is observable: a `warn!` naming the method and the reason, so an
   operator reads "not resent, no explicit annotation" rather than a bare
   error.

## Fail-safe direction

Refusing a resend that would have been safe costs the caller one error and a
retry they can make themselves. Permitting one that was not safe executes a
side effect twice, silently. Every default therefore denies: the trait default,
a tool absent from the permitted set, and a `tools/call` whose annotations were
never read.

## Acceptance

`tests/mik_7272_sub4_adr012_acs.rs`:
- `session_expiry_does_not_resend_an_unannotated_call` — running, must stay
  green.
- `session_expiry_still_recovers_an_explicitly_read_only_call` — currently
  `#[ignore]`d on this seam; un-ignored and green when this lands.
- No existing `src/transport/http` test regresses; MIK-5982/MIK-6040 recovery
  for non-`tools/call` methods is unchanged.

## Out of scope

The tasks-extension alternative to an idempotency key (already built, TASK.1),
consolidating the duplicated direct-route forwarding branches
(`src/gateway/router/backend_handlers.rs:842` and `:899`), and any change to
site 1.

## Resend-site audit

Added after review: the claim that ADR-012 A3 names every resend site was
asserted, not checked. Audited, with results recorded here so the next reader
does not have to repeat it.

**A third resend path exists** — protocol-version renegotiation.
`HttpTransport::send_request` resends the same request after the backend
rejects the protocol version, by HTTP status (`src/transport/http/mod.rs:750-757`)
and by JSON-RPC error (`:795-809`). It needs no permission and is left alone: a
version rejection is the backend refusing to process the message at all, so the
first attempt provably executed nothing — the same reasoning that puts
`CircuitOpen` on the pre-dispatch allowlist in `Error::is_pre_dispatch`.

**Redirects do not re-execute.** The client installs a custom redirect policy
(`src/transport/http/mod.rs:541`, `evaluate_redirect` at `:127`) that refuses a
cross-origin target and counts hops. A 307/308 re-submits the body, but the
redirecting response is not an execution, so the side effect still happens once.

**No retry middleware.** There is no retry layer on the `reqwest` client
builder; every repeat in this transport is one of the paths named above.

## Callers the new parameter forces to choose

Enumerated so no caller silently inherits `Denied` and loses MIK-5982/MIK-6040
recovery:

- `Backend::request_with_headers` (`src/backend/ops.rs:260`) — the only
  production caller at the `Transport` level. Derives the permission.
- `Backend::request` (`src/backend/ops.rs:47`) and
  `HttpTransport::request` (`src/transport/http/mod.rs:1440`) — thin delegating
  wrappers. They carry no tool context, so they pass `Denied`; the methods that
  reach them in production are not `tools/call`.
- Circuit-breaker half-open probes: these run *through* `Backend`, not around
  it, so they inherit rule 1 and stay recoverable for non-`tools/call` methods.
- Test callers: `src/transport/http/tests.rs:1166,1466-1486`,
  `src/backend/pool_tests.rs:148`, and the test double at
  `src/gateway/meta_mcp/invoke.rs:4340`.

Note that `src/gateway/router/backend_handlers.rs:833,891` and
`src/gateway/meta_mcp/invoke.rs:3036` call `Backend::request_with_headers`, not
the transport method — they are unaffected by the signature change.

## Recovery is bounded to one attempt

Already true, now stated and tested rather than assumed: the resend calls
`send_request_with_headers` directly (`src/transport/http/mod.rs:1505`), which
is the raw send path with no recovery wrapper, so a resent request cannot
re-enter recovery and re-initialize again. A backend that keeps rejecting a
fresh session yields one error per request, not a loop. The same shape protects
`initialize()`, which also calls the raw path (comment at `:1490`).

## Acceptance, amended

- `session_expiry_denies_resend_but_still_heals_the_session` — on `Denied`, the
  dead session bucket is still dropped and `initialize()` still runs; only the
  resend is refused. This is the fail-safe's harder half and was covered by
  prose alone.
- A refused resend increments a counter alongside the `warn!`, and both name
  the tool, not just the method — so refusals are trendable and attributable
  instead of anecdotal.

## Amendment 2 — deny-by-default applies to methods too

Two CRITICAL findings from the second review, both accepted. They share a
single fix.

**Behaviour rule 1 above was wrong.** "A non-`tools/call` method is
`Permitted`" grants resend to every method the gateway does not recognise,
which is the opposite of the fail-safe direction this design argues for two
sections earlier, and contradicts ADR-012 A3. A future side-effecting method
would inherit permission by default.

**The caller inventory was also wrong** about the consequence: `Backend::request`
(`src/backend/ops.rs:47`) is the path metadata discovery takes, so a blanket
`Denied` there would have silently regressed session recovery for `tools/list`
— the MIK-5982/MIK-6040 behaviour this change promises to preserve. Rated
MEDIUM/CERTAIN, and correct.

**One predicate, computed once, used by both sites.** Replace rule 1 with

```rust
fn resend_permission(method: &str, params: Option<&Value>, permitted: &HashSet<String>)
    -> ResendPermission
```

- `tools/call` → `Permitted` only when the named tool is in `permitted`.
- an explicit allowlist of methods that cannot carry a side effect —
  `initialize`, `ping`, `tools/list`, `resources/list`, `resources/read`,
  `prompts/list`, `prompts/get` — → `Permitted`.
- everything else, including any method added later → `Denied`.

`Backend::request` and `Backend::request_with_headers` both call it, and
`resend_policy_for` (site 1) is rewritten on top of it, so the two sites cannot
drift — this is the second reviewer's improvement, adopted.

## Residual risk: same-origin redirect

One reviewer rates the automatic redirect path CRITICAL. Verified at source
(`src/transport/http/mod.rs:127-144`): the custom policy stops after 5 hops,
rejects an SSRF target, and refuses any cross-origin target, so a redirect can
only bounce within the origin the operator configured. Re-execution therefore
requires a same-origin backend that performs the side effect AND answers
307/308 — non-conforming, but not impossible.

The redirect policy is built per client and cannot see a per-request
permission, so this design does not claim to close it. It is recorded as a
bounded residual risk with an acceptance test asserting the hop cap and the
cross-origin refusal, and is the reason the counter in behaviour rule 3 exists.

## Acceptance, amended again

Added on review: concurrent permitted and denied calls on one shared transport
must not license each other; BOTH expiry shapes (transport `Err`, and `Ok` with
an expiry `error` member) must honour the permission; and a failed
re-initialization must surface the original error rather than the
re-initialization's.
