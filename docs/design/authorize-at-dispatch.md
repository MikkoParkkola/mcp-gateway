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
| Does the stdio path have `AppState`? | read `src/gateway/server/mod.rs:1620-1670` | No. It holds a `tool_policy` handle only, and checks it for `gateway_invoke` alone (`:1645`) | Killed the single-adapter design. Two authorizers are required, and stdio gains a check it does not have today. |

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

The meta layer cannot reach `AppState` and must not hold it: `AppState` owns
`meta_mcp`, so an `Arc<AppState>` stored inside `MetaMcp` is a reference cycle
that never frees. The authorization context is therefore **borrowed per
request, never stored** — verified compilable by the absence of any spawned,
`'static`-bound step execution in the playbook engine.

1. `MetaMcpCallerContext<'a>` gains `authorizer: &'a (dyn ToolAuthorizer + Sync)`.
   `MetaMcpCallerContext` **loses its `Default` impl**, so no construction site
   can acquire an authorizer by omission. Every site names one.
2. `ToolAuthorizer` has one method, taking the **whole `ToolTarget`** rather
   than a `(server, tool)` pair, matching `authorize_tool_target`'s existing
   signature so the two cannot drift as policy grows to read arguments.
3. **Two production implementations, because the two transports have different
   identity to check against:**
   - `RouterAuthorizer` (HTTP) captures `&AppState` plus the resolved `client`,
     `oauth_agent_identity` and `cert_identity`, and calls the existing
     `authorize_tool_target` unchanged. No authorization logic is rewritten.
   - `ToolPolicyAuthorizer` (stdio) checks the global tool policy and nothing
     else, because stdio has no client, no certificate and no agent identity to
     scope against. It **replaces** the inline check at `server/mod.rs:1631-1649`,
     which today runs for `gateway_invoke` only — so stdio gains tool-policy
     enforcement on playbook and code-mode steps that currently have none.
     Deleting that block is part of this change, not an addition beside it.
   - `AllowAll` exists only under `#[cfg(test)]`. It cannot be reached from a
     release build, so the guard cannot be defeated by satisfying the type.
4. `invoke_tool` takes `&MetaMcpCallerContext<'_>` instead of five loose
   parameters. The existing comment declining that refactor cites "no
   behavioural gain"; there is one now, and the parameter count drops.
5. `invoke_tool_traced` authorizes after `server` and `tool` are extracted and
   **before any dispatch, cache read, idempotency lookup or budget spend**. A
   cached result for an out-of-scope target is never served.
6. `run_playbook` passes the caller context into `MetaMcpInvoker`, so each step
   is authorized at the moment it runs — after its `condition` is evaluated.

### A refusal is terminal, and is not a step failure

`ErrorStrategy` describes how to handle a **backend** failure: `Retry` re-runs
the step, `Continue` records `Value::Null` and proceeds. An authorization
refusal is neither transient nor recoverable, and routing it through that
machinery produces two bad outcomes: a permission denial retried `max_retries`
times, which is waste that reads like a brute-force loop in the log; and a
half-executed playbook whose output mapping silently interpolates nulls from
the step the caller was not allowed to run.

So an authorization refusal **aborts the run regardless of `on_error`**, and
the caller receives one error naming the backend and tool that was refused. A
clear refusal is better UX than a partial result that looks like a success.

### What the authorizer is NOT asked

The authorizer is invoked only where a dispatch resolves to a real backend
`(server, tool)`. Meta-tool names are never passed to it: a playbook step
names a backend and a tool, and a nested meta call recurses to this same point
unchanged. A restricted client's tool allow-list is therefore never matched
against `gateway_invoke` itself.

### Refusals are observable

A chokepoint refusal is the first signal of an attempted scope bypass through
an orchestration path. Each one emits a warning-level audit line carrying
caller, server, tool and transport, so these are distinguishable from ordinary
backend errors rather than buried among them.

### The router keeps its pre-check

It is now redundant for backend targets and is retained deliberately: it
produces the JSON-RPC error envelope clients already receive, and it is where
the firewall request scan hangs. The two layers call the same function against
the same policy snapshot in the common case; across a config reload between
them the chokepoint is authoritative, because it is the one adjacent to the
dispatch it guards.

## Residual risk, stated

`AllowAll` being test-only closes the "satisfy the type permissively" route in
release builds. It does not stop a future author writing a second permissive
implementation. Nothing short of option D prevents that, and D is deferred.

## Acceptance criteria

Refusal cases — each names the check that must fire, so a fix wiring only one
of them fails the others:

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

Behaviour that must not change:

- MIK.AUTHZ.4 An admin, unrestricted caller runs the same playbook unchanged.
- MIK.AUTHZ.5 A client with no explicit restrictions runs it unchanged — the
  default-permissive path is not narrowed.
- MIK.AUTHZ.6 A step skipped by its `condition` is never authorized, so an
  unreachable step cannot refuse the playbook. The assertion is on the
  step-skipped record, not on the absence of an error.
- MIK.AUTHZ.8 Direct `gateway_invoke` and code-mode chains keep their current
  behaviour and refusal messages.

Ordering and coverage:

- MIK.AUTHZ.7 A refused step performs no backend call, writes no cache entry
  and spends no budget.
- MIK.AUTHZ.12 A refused target whose result is already in the response or
  idempotency cache is still refused — authorization precedes the cache read.
- MIK.AUTHZ.13 Every dispatch shape below the router — surfaced tool,
  `gateway_invoke`, code-mode single, code-mode chain step, playbook step — is
  refused when the authorizer denies. This is the test of the chokepoint claim
  itself, driven directly at the meta layer with a denying authorizer.
- MIK.AUTHZ.14 A refusal emits an audit line naming caller, server, tool and
  transport.

Transport:

- MIK.AUTHZ.15 A stdio playbook step hitting a policy-denied tool is refused.
  (No coverage today; the inline check runs for `gateway_invoke` only.)
- MIK.AUTHZ.16 A stdio caller keeps its admin standing and its existing
  `gateway_invoke` behaviour after the inline check is replaced.

MIK.AUTHZ.9 is withdrawn. It asserted that a served `MetaMcp` always carries a
real authorizer; removing `Default` and gating `AllowAll` behind `#[cfg(test)]`
makes that a property of the types, and a test that greps for a symbol is a
lint wearing a test's clothes.
