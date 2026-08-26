# Authorize at the dispatch chokepoint (MIK-7252)

## §P0 SCOPE

**FOR**: closing the path by which an internal orchestration caller reaches a
backend tool without the invoking caller's authorization checks running.

**OUT** (labelled, filed separately if raised):
- the router's own pre-check, its error envelopes, and the firewall hook
- admin gating of meta-tools (`is_admin_meta_tool`), already correct
- SSRF policy semantics, `trust_configured_backends` (MIK-3529 settled)
- rate limiting, cost budgets, identity grants — orthogonal controls
- the origin/Host gate and anonymous-admin work on this branch

## The defect

`authorize_tool_target` (`src/gateway/router/authorization.rs:105`) is the only
place the caller's backend scope, per-client tool scope, global tool policy,
mTLS policy and agent scope are checked. It is called from exactly two sites,
both in the router: `handlers.rs:547` and `backend_handlers.rs:82`.

The router decides WHICH targets to check with
`backend_tool_targets_for_call` (`authorization.rs:57`), which returns targets
for three shapes only — a surfaced tool, `gateway_invoke`, and
`gateway_execute`. Every other tool name returns an empty vector, and an empty
vector authorizes nothing.

`gateway_run_playbook` (`meta_mcp/mod.rs:1188`) is not one of the three. Its
steps reach `MetaMcp::invoke_tool` through `MetaMcpInvoker::invoke`
(`meta_mcp/support.rs:175`), and `invoke_tool_traced` performs only one
authorization check of its own — an admin gate on capabilities that register a
caller-addressed external destination (`invoke.rs:560`). Backend scope, tool
scope, tool policy, mTLS and agent scope are never consulted on that path.

`api_key_name` IS threaded down and is used for budget enforcement
(`invoke.rs:861`), provenance subject (`:1440`) and identity grants (`:1782`).
None of those is the client's backend/tool scope. **Carrying an identity that
the authorization checks never read is not a fix** — an earlier commit on this
branch claimed to close this ticket by threading that identity and was wrong.

## Unknowns, resolved before freezing this design

| question | what was run | answer | what it changed |
|---|---|---|---|
| Can the meta layer rebuild an `AuthenticatedClient` from `api_key_name`? | `rg` for a by-name lookup over `src/` | No such lookup exists; the value is produced by validating a presented credential (`auth.rs:333`) | Killed the "look it up at dispatch" option. The identity must be threaded, not recovered. |
| Are playbook step targets knowable before execution? | read `PlaybookStep` (`playbook.rs:86-104`) | `server` and `tool` are static strings; only `arguments` interpolate | A router-side pre-check IS possible — so the choice between patch and elimination is a real choice, not forced. |
| Does the code-mode chain have the same hole? | read `targets_from_code_mode_arguments` (`authorization.rs:209`) | No — it walks every `chain` step | Narrows the defect to the playbook path today, and shows the shape of the recurrence. |
| Would the check break working setups? | read `can_access_backend` (`auth.rs:366`), `check_tool_scope` (`auth.rs:378`) | Both default-permissive: empty backend list means all, absent allow/deny lists pass | UX risk is contained to clients that carry an explicit restriction, which is the population the check is for. |
| Does the playbook engine spawn steps onto a `'static` task? | read `src/playbook/engine/mod.rs` for `spawn`/`JoinHandle`/`'static` | No matches; steps are awaited inline against a borrowed invoker (`:177`) | Confirms a borrowed authorizer compiles. Raised as a review finding and refuted here rather than left as an assumption. |
| What does a failed step do today? | read `engine/mod.rs:163-211` and `ErrorStrategy` (`playbook.rs:136`) | `Retry` re-runs it `max_retries` times; `Continue` records `Value::Null` and proceeds; `Abort` returns the error | Forced an explicit decision on refusal semantics — see below. A refusal handled as an ordinary step failure would be retried, or null-filled into a partial result. |
| Does the stdio path have `AppState`? | read `src/gateway/server/mod.rs:1620-1670` | No. `dispatch_single` receives `tool_policy` AND `mtls_policy` (`:1542`), but checks only tool policy, only for `gateway_invoke` (`:1645`) | Killed the single-adapter design. Two authorizers are required, and stdio gains a check it does not have today. |
| Should the stdio authorizer evaluate mTLS, since it holds the handle? | read `MtlsPolicy::evaluate` (`src/mtls/access_control/mod.rs:89-111`) | With the policy enabled, a `None` identity returns `Deny`, and a non-matching identity also returns `Deny` (fail-closed) | No. stdio presents no certificate, so an operator who configures any mTLS rule would find every stdio call refused. mTLS is a property of the network transport stdio does not use. Recorded because the handle being in scope makes this a live trap. |

## Options

**A — add `gateway_run_playbook` to `backend_tool_targets_for_call`.**
Smallest diff. Rejected: it is the patch, and the finding stays statable
afterwards. The defect is not "playbooks were forgotten", it is "authorization
lives at the router while dispatch lives in the meta layer, so every internal
caller must remember to register itself". Code mode was the third such caller
and was remembered; the playbook was the fourth and was not. Rejected also
because a step's `condition` can skip it, so the router would authorize targets
that never run — refusing a playbook for a step that would not have executed is
a UX regression invented by the fix.

**B — authorize inside `MetaMcpInvoker::invoke`.** Fixes the playbook only.
Same recurrence one layer down. Rejected.

**C — authorize at the dispatch chokepoint (CHOSEN).** `invoke_tool_traced` is
the point every backend invocation passes through. Authorizing there makes the
finding unstatable: no path reaches a backend without it, so no future caller
can forget.

**D — a proof token mintable only by the authorizer.** Compile-time rather than
runtime. Deferred, not rejected: C closes the hole, and D can be layered later.

### The claim C rests on, made checkable

Every call site that reaches `invoke_tool`, enumerated so a future reader can
re-run the search rather than trust this list
(`rg -n "invoke_tool\(" --type rust`, non-test):

| site | shape | authorized today? |
|---|---|---|
| `meta_mcp/mod.rs:1140` | surfaced tool | yes — router computes the target |
| `meta_mcp/mod.rs:1174` | `gateway_invoke` | yes — router computes the target |
| `meta_mcp/search.rs:478` | code-mode single call | yes — `targets_from_code_mode_arguments` |
| `meta_mcp/search.rs:531` | code-mode chain step | yes — same, walks every step |
| `meta_mcp/support.rs:175` | **playbook step** | **no — this is the defect** |

The value of the chokepoint is that this table stops needing to be correct.

## The design (C)

### What the chokepoint does and does not cover

`invoke_tool_traced` is the single point every **meta-layer** dispatch passes
through — surfaced tool, `gateway_invoke`, code-mode single, code-mode chain
step, playbook step. It is not the only way a backend is reached: the direct
`/mcp/{name}` passthrough (`router/backend_handlers.rs:403`) dispatches without
entering the meta layer at all, which is why it carries its own
`authorize_tool_target` call at `backend_handlers.rs:82`.

So this change produces **two** authorization points, each adjacent to the
dispatch it guards, and neither claims to cover the other. Stating it the
narrow way is the point: a maintainer who believes the inner authorizer covers
the direct route will one day delete the outer one.

### Structure

The meta layer cannot reach `AppState` and must not hold it: `AppState` owns
`meta_mcp`, so an `Arc<AppState>` stored inside `MetaMcp` is a reference cycle
that never frees. The authorization context is **borrowed per request, never
stored** — compilable because no step execution is spawned onto a `'static`
task (verified above).

1. **A neutral home for the port.** `ToolTarget`, `OwnedToolTarget` and
   `AuthorizationError` are `pub(super)` to `gateway::router`
   (`router/authorization.rs:18,25,41`), so `meta_mcp` cannot name them and the
   trait does not compile where they live. A new `src/gateway/authz.rs` owns
   the trait, the target type and the error at `pub(crate)`;
   `router::authorization` uses them rather than defining its own. A move, not
   a second copy — two definitions of a target type is how two layers drift.
2. `MetaMcpCallerContext<'a>` gains `authorizer: &'a (dyn ToolAuthorizer + Sync)`
   and **loses its `Default` impl**, so no site can acquire an authorizer by
   omission. Cost, counted: 19 construction sites — 17 in `meta_mcp/tests.rs`,
   one in `invoke.rs`, one in `server/mod.rs`.
3. `ToolAuthorizer` takes the **whole `ToolTarget`**, matching
   `authorize_tool_target`'s signature so the two cannot drift as policy grows
   to read arguments.
4. **Two production implementations, because the transports carry different
   identity:**
   - `RouterAuthorizer` (HTTP) captures `&AppState` plus the resolved `client`,
     `oauth_agent_identity` and `cert_identity`, and calls the existing
     `authorize_tool_target` unchanged. No policy logic is rewritten.
   - `ToolPolicyAuthorizer` (stdio) checks the global tool policy only. It
     **replaces** the inline block at `server/mod.rs:1631-1649`, which runs for
     `gateway_invoke` alone — so stdio gains tool-policy enforcement on
     playbook and code-mode steps that have none today. Deleting that block is
     part of this change, not an addition beside it. It deliberately does not
     evaluate mTLS: see the unknowns table.
   - `AllowAll` exists only under `#[cfg(test)]`, so it cannot be reached from
     a release build.
   - The HTTP site constructs `RouterAuthorizer` **concretely**, not through a
     `dyn` parameter it could be handed, so the weaker stdio authorizer cannot
     be installed on the network path by a miswire. This is weaker than a
     closed enum over the two transports, which was considered and deferred:
     the enum's HTTP variant needs router types, reintroducing the layering
     problem the neutral module exists to solve.
5. `invoke_tool` takes `&MetaMcpCallerContext<'_>` instead of five loose
   parameters. The comment declining that refactor cites "no behavioural gain";
   there is one now, and the parameter count drops.
6. `run_playbook` passes the caller context into `MetaMcpInvoker`, so each step
   is authorized at the moment it runs — after its `condition` is evaluated.

### Authorization precedes every pre-dispatch side effect

Not only the cache read. A refused call must burn nothing, so the check runs
before: the response-cache lookup, the idempotency lookup **and its in-flight
registration**, any nonce registration, any per-user credential mint for an
identity-propagating backend, the budget spend, and the "tool invoked" info
log. A denied call that has already minted a token or pinned an idempotency key
has had an effect it was not entitled to.

### A denial is not retried, is never silent, and respects `on_error`

An earlier revision of this design made an authorization refusal terminal
regardless of `on_error`. Both reviewers rejected it and both were right, for
two different reasons that compose:

- It **overrides a documented contract**. `on_error: continue` is a deliberate
  choice by the playbook author, and `playbooks/research.yaml` in this
  repository uses it. Making a denial terminal takes the cleanup and fallback
  steps after an optional step away from exactly the restricted callers this
  change is for. That is the user experience getting worse, not better.
- It was **a semantic with no mechanism and no test that could catch its
  absence**. The engine's `on_error` match (`playbook/engine/mod.rs:196-210`)
  would have gone on null-filling, and every acceptance fixture defaults to
  `Abort`, so the design would have shipped stating a rule the code did not
  implement and no criterion would have failed.

The replacement keeps what was actually right about the concern and drops the
override:

1. **A denial is a distinct error, not a backend failure.** Authorization
   refusal gets its own variant so it is classifiable, rather than arriving as
   an opaque `Err` indistinguishable from a timeout.
2. **A denial is never retried.** The attempt loop
   (`playbook/engine/mod.rs:172-192`) breaks immediately on that variant, so
   `max_retries` cannot turn one refusal into `n` identical denials — waste
   that reads like a brute-force loop in the audit log.
3. **`on_error` is then honoured unchanged.** `Abort` aborts, `Continue`
   records the step in `steps_failed` and proceeds to the next step. No new
   control flow, no new strategy.
4. **A denial is never silent.** Under `Continue` the step is recorded as
   failed with its refusal reason, so a partial run is visibly partial. The
   null-filled apparent success that motivated the original decision is closed
   by making the denial visible, not by aborting the run.

### Refusals are observable, and one layer owns saying so

A chokepoint refusal is the first signal of an attempted scope bypass through
an orchestration path. **The chokepoint emits the audit line, not the
authorizer**, so a silent or third-party `ToolAuthorizer` implementation cannot
omit it: caller, server, tool and transport are recorded at the point the
refusal is observed, from data the chokepoint already holds.

### What the authorizer is NOT asked

The authorizer is invoked only where a dispatch resolves to a real backend
`(server, tool)`. Meta-tool names are never passed to it: a playbook step names
a backend and a tool, and a nested meta call recurses to this same point. A
restricted client's tool allow-list is never matched against `gateway_invoke`
itself.

### The router keeps its pre-check

Retained deliberately: it produces the JSON-RPC error envelope clients already
receive, and it is where the firewall request scan hangs. Two consequences,
recorded rather than discovered later:

- Across a config reload between the two checks the chokepoint is
  authoritative, because it is the one adjacent to the dispatch it guards.
- On the paths the router already covers — `gateway_invoke`, code mode,
  surfaced tools — `authorize_tool_target` now runs **twice**, so an
  agent-scope ALLOW audit fires twice for one invocation. Audit consumers must
  not read doubled allows as doubled invocations. The playbook path, which the
  router never covered, audits once.

## Residual risk, stated

`AllowAll` being test-only closes the "satisfy the type permissively" route in
release builds, and constructing `RouterAuthorizer` concretely closes the
miswire. Neither stops a future author writing a second permissive
implementation. Only option D prevents that, and D is deferred.

## Acceptance criteria

Refusal cases — each names the check that must fire, so a fix wiring one of
them fails the others:

- MIK.AUTHZ.1 A playbook step targeting a backend outside the caller's
  `backends` list is refused, and the refusal names the backend.
- MIK.AUTHZ.2 A playbook step targeting a tool outside the caller's
  `allowed_tools` is refused.
- MIK.AUTHZ.3 A playbook step hitting a tool denied by global tool policy is
  refused. (Policy lives on `AppState`, not the client, so this proves the
  authorizer carries state and not merely an identity.)
- MIK.AUTHZ.10 A playbook step denied by mTLS certificate policy is refused.
- MIK.AUTHZ.11 A playbook step outside the caller's agent scope is refused when
  agent authentication is enabled.

Denial semantics — the fixtures must set `on_error` explicitly, because the
default is `Abort` and an `Abort` fixture passes whether or not the rule holds:

- MIK.AUTHZ.17 `on_error: retry`, `max_retries: 3`, a denied step: the
  authorizer is consulted **once** and the backend zero times. A retried denial
  fails this.
- MIK.AUTHZ.18 `on_error: continue`, a denied step followed by an allowed step:
  the run completes, the allowed step executes, and the denied step appears in
  `steps_failed` carrying its refusal reason. A terminal-refusal implementation
  fails this; so does one that records the step as a silent null.
- MIK.AUTHZ.19 `on_error: abort`, a denied step: the run returns the refusal,
  and no later step executes.

Behaviour that must not change:

- MIK.AUTHZ.4 An admin, unrestricted caller runs the same playbook unchanged.
- MIK.AUTHZ.5 A client with no explicit restrictions runs it unchanged — the
  default-permissive path is not narrowed.
- MIK.AUTHZ.6 A step skipped by its `condition` is never authorized. Asserted
  with a **counting** authorizer showing zero consultations for that step, not
  by the absence of an error.
- MIK.AUTHZ.8 Direct `gateway_invoke` and code-mode chains keep their current
  behaviour and refusal messages.

Ordering and coverage:

- MIK.AUTHZ.7 A refused step performs no backend call, writes no cache entry
  and spends no budget.
- MIK.AUTHZ.12 A refused target already present in the response or idempotency
  cache is still refused — authorization precedes the cache read.
- MIK.AUTHZ.20 A refused call registers no idempotency in-flight entry and
  mints no per-user credential.
- MIK.AUTHZ.13 Every meta-layer dispatch shape — surfaced tool,
  `gateway_invoke`, code-mode single, code-mode chain step, playbook step — is
  refused when the authorizer denies, driven at the meta layer with a denying
  authorizer built through the same caller context production builds.
- MIK.AUTHZ.14 A refusal emits an audit line carrying caller, server, tool and
  transport, emitted by the chokepoint rather than the authorizer. Asserted on
  the presence of the four fields, not on a sentence.
- MIK.AUTHZ.21 The direct `/mcp/{name}` route keeps its existing refusal
  behaviour, proving the outer check was not removed as redundant.

Transport:

- MIK.AUTHZ.15 A stdio playbook step hitting a policy-denied tool is refused.
  (No coverage today; the inline check runs for `gateway_invoke` only.)
- MIK.AUTHZ.16 A stdio caller keeps its admin standing and its existing
  `gateway_invoke` behaviour after the inline block is deleted.
- MIK.AUTHZ.22 With mTLS rules configured, stdio calls are **not** refused —
  the stdio authorizer does not evaluate a policy stdio cannot satisfy.

MIK.AUTHZ.9 is withdrawn: removing `Default` and gating `AllowAll` behind
`#[cfg(test)]` makes it a property of the types, and a test that greps for a
symbol is a lint wearing a test's clothes.
