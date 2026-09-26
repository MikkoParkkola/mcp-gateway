# Direct route runs the controls meta dispatch runs (#1452, MIK-7597)

Status: DRAFT for review. Base: `docs/ranking-1-release-line` at 46161901e.
Coordinated with LIFECYCLE.1 (design `docs/design/2026-09-26-lifecycle-1-direct-route-tasks-and-input.md`
§3 A.2, branch `docs/lifecycle-1-design`): one pre-dispatch chain `DirectRouteGuards::run` and one
post-dispatch step `DirectRouteGuards::after_dispatch`, in `src/gateway/router/direct_guards.rs`,
`pub(crate)` by maintainer decision 2026-09-26. Whichever change merges first creates the module.

## 1. Problem (source at 46161901e)

`POST /mcp/{name}` `tools/call` (`src/gateway/router/backend_handlers.rs:515` `backend_handler_inner`,
dispatch through `dispatch_in_scope` :428) skips controls that meta dispatch
(`src/gateway/meta_mcp/invoke.rs:1570` `invoke_tool_traced`) applies:

| # | Control | Meta site | Direct route |
|---|---|---|---|
| G1 | Operator / error-budget kill switch | `invoke.rs:1637` | never consulted |
| G2 | Per-capability disable after high error rate | `invoke.rs:1644-1659` | never consulted |
| G3 | Cost budget | `invoke.rs:1999` (`admit_spend` :3162) | never consulted |
| G4 | Active session profile | `invoke.rs:1089` (`check_invocation_policy`) | only the global tool policy |
| G5 | Error-budget recording and auto-kill | `invoke.rs:3296` (`record_error_budget` :2566) | failures feed only the client breaker (`backend_handlers.rs:1231`) |
| G6 | Response contract gate, response inspection, context integrity | `invoke.rs:1383` `apply_response_gates` | only the response firewall |
| G7 | Message signing and replay nonce | `signing.rs:185-214`, `finalize_gateway_invoke_response` :219 | no signing envelope exists on this route |

Already shared or equivalent on both routes (no change): auth middleware rate limit and client
breaker, request firewall and memory scanner, authorizer and tool policy, tool-name validation,
attestation, idempotency, undeclared-key refusal, invocation audit, response firewall.
Not applicable: `admin_capability_rule` and identity grants apply to the capability provider, which
`/mcp/{name}` cannot address (`state.backends` holds configured backends only, `server/mod.rs:625`;
capabilities attach to meta alone, `:1355`). The response cache is a performance feature.

Impact: an operator's kill switch, a disabled capability, a spend limit and a session profile do not
hold for a caller that names the backend in the URL; failures there never trip the error budget.

## 2. Design

### 2.1 One implementation per control, in `MetaMcp`

Each control keeps its single implementation where its state lives (`MetaMcp`). Two façade methods,
in a new child module `src/gateway/meta_mcp/invoke/dispatch_guards.rs` (a child of `invoke`, so it
reaches the private items it wraps without widening them; `invoke.rs` is on the size ratchet):

```rust
/// Pre-dispatch admission for one backend call. The ONE place G1-G4 are decided.
pub(crate) fn admit_backend_call(&self, call: BackendCall<'_>) -> Result<Admission>;
/// Post-dispatch accounting and payload gates. The ONE place G5-G6 run.
pub(crate) fn settle_backend_call(&self, call: BackendCall<'_>, result: Result<Value>) -> Result<Value>;
```

`BackendCall { server, tool, session_id, api_key_name, trace_id, route: Route }`, `Route` an enum
(`Meta`, `Direct`). `Admission` carries the budget warnings meta already appends to results.

- `admit_backend_call`, in order: kill switch (G1), capability disable (G2), active profile (G4),
  cost budget (G3). Each refusal keeps today's meta error: `-32000` for G1/G2, the profile's
  `Protocol` refusal for G4, `-32003` for G3.
- `settle_backend_call`: `record_error_budget(BudgetOutcome::of(&result))` (G5), then on success
  `apply_response_gates` (G6).

Meta calls these in place of its inline code: `invoke.rs:1637-1659` becomes one call, the
`admit_spend` call at :1999 stays where it is (after the cache lookup, so a cache hit spends nothing)
but goes through the same function with a `budget_only` step, and `:3296` becomes
`settle_backend_call`. Net lines in `invoke.rs` go down.

### 2.2 Router chain (one chain, reconciled with LIFECYCLE.1)

There is one chain per route boundary and one implementation per control:

- `MetaMcp::admit_backend_call` / `settle_backend_call` own G1-G6. Meta dispatch calls them
  directly; nothing else implements those controls.
- `DirectRouteGuards::run` and `DirectRouteGuards::after_dispatch` (router, agreed with LIFECYCLE.1)
  are the direct route's single pre- and post-dispatch chain. They are thin compositions:
  `run`'s FIRST step is `state.meta_mcp.admit_backend_call(..)`, followed by LIFECYCLE.1's
  router-only checks (isolation, tool policy and sanitisation, propagation) that produce
  `GuardedCall`. `after_dispatch`'s first step is `settle_backend_call`, then the response scan.
  Neither re-implements a G1-G6 control.
- The request thread and the LIFECYCLE.1 task worker both call `run` / `after_dispatch`; no
  direct-route code path calls `admit_backend_call` except through `run`.

`DirectRouteGuards::run(&self, ctx: &DirectCall<'_>) -> Result<GuardedCall, Refusal>` calls
`state.meta_mcp.admit_backend_call(..)` FIRST, before the idempotency reservation
(`backend_handlers.rs:~955`) and before any LIFECYCLE.1 check, so a refused call reserves nothing and
reaches no backend. `DirectRouteGuards::after_dispatch` calls `settle_backend_call` on the backend
result before the response scan. A refusal maps to HTTP 200 with the JSON-RPC error meta returns
(the caller sees one classification whichever route it used).

Direct session id: the `mcp-session-id` header when present (`backend_handlers.rs:647`), else none
(no session profile, same as a sessionless meta call).

### 2.3 G7 signing and nonce

ADR-001 defines message signing for the `gateway_invoke` envelope only; the direct route has no
signed envelope to carry a nonce or return a MAC. Proposal: when `message_signing.enabled` and
`require_nonce` are both on, the direct route refuses `tools/call` with `-32001`
("message signing is enforced; use gateway_invoke"), so an operator who mandates signed exchanges
has no unsigned side door. With signing off or nonce optional, behaviour is unchanged. Extending
ADR-001 to the direct route is out of scope. Reviewers: challenge this.

## 3. Visibility (maintainer decision 2026-09-27)

New `pub(crate)`: `MetaMcp::admit_backend_call`, `MetaMcp::settle_backend_call`, and the
`BackendCall`, `Route`, `Admission` types, approved as a maintainer decision following the
`pub(crate)` precedent for `DirectRouteGuards`. Nothing existing is widened.

## 4. Behaviour change (UPGRADING item 69)

A direct `/mcp/{name}` call to a killed backend or disabled capability, over a key's cost budget, or
outside the session's active profile is now refused with the error meta dispatch returns. Direct-route
failures count toward the error budget and can auto-kill a backend. Response contract, inspection and
context-integrity settings now apply to direct-route results. With message signing and
`require_nonce` both on, the direct route refuses `tools/call` with -32001 and names
`gateway_invoke` (maintainer decision 2026-09-27: fail closed).

## 5. Tests (red first)

| id | AC | Level | Cell | Red today |
|---|---|---|---|---|
| T1 | DIRECT.1 | router | backend killed via `KillSwitch::kill`; POST `/mcp/{name}` `tools/call`; JSON-RPC -32000; backend call counter == 0 | backend called, result returned |
| T2 | DIRECT.1 | router | capability disabled by error budget; same shape | backend called |
| T3 | DIRECT.2 | router | budget enforcer with a key already over its daily limit; -32003; counter == 0 | backend called |
| T4 | DIRECT.3 | router | session profile excluding the tool, `mcp-session-id` set; refused; counter == 0 | backend called |
| T5 | DIRECT.4 | router | `require_nonce` on; direct `tools/call` refused -32001; counter == 0 | backend called |
| T6 | DIRECT.5 | router | backend answering errors; N direct failures reach the auto-kill threshold; `is_killed` true | never killed |
| T7 | DIRECT.6 | router | response contract `fail_closed` with no contract for the tool; direct result refused | result delivered |
| T8 | DIRECT.8 | unit | both-routes parity table (§6) | table rows red for G1-G6 on Direct |

Mutants (throwaway CI): M1 drop the kill-switch step (T1, T8 red); M2 drop the budget step (T3, T8);
M3 drop the profile step (T4); M4 drop `settle_backend_call` from `after_dispatch` (T6, T7, T8);
M5 run `admit_backend_call` after the idempotency reservation (T9 below red); M6 drop the nonce
refusal (T5).
T9: a refused direct call leaves no idempotency entry (a retry with the same key after un-killing
succeeds).

## 6. Both-routes parity test (DIRECT.8)

One table in `src/gateway/router/dispatch_parity_tests.rs`: a row per control in §1 plus the
already-shared ones (rate limit, request firewall, authorizer, tool name, attestation, undeclared
keys, audit, response firewall). Each row arms its control with a fixture function and states the
expected outcome. The test runs every row through both routes (`gateway_invoke` and
`/mcp/{name}`) against one counting backend and asserts the same refusal code and the same backend
call count. Completeness: the row names must equal `DISPATCH_CONTROLS`, a `const &[&str]` in
`dispatch_guards.rs` that `admit_backend_call` and `settle_backend_call` iterate in order; adding a
step there without a row, or a row without a step, fails the test.

## 7. Out of scope

Response cache on the direct route; ADR-001 signing envelope on the direct route; LIFECYCLE.1's own
checks (isolation, policy, sanitisation, propagation), which it moves into `run` itself.
