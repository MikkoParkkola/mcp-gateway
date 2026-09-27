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

### 2.1 One implementation per control, in `MetaMcp`, at the stage each already runs

Each control keeps its single implementation where its state lives (`MetaMcp`), and runs at the same
lifecycle stage on both routes as it does on meta today (review finding: moving response gates into
dispatch accounting would change their stage and route their refusals through backend-error recovery).
Four `pub(crate)` stage methods, in a new child module `src/gateway/meta_mcp/invoke/dispatch_guards.rs`
(a child of `invoke`, so it reaches the private items it wraps without widening them; `invoke.rs` is on
the size ratchet):

| Stage | Method | Runs | Controls |
|---|---|---|---|
| S1 policy | `admit_target(&BackendCall) -> Result<()>` | before idempotency, cache and nonce | G1 kill switch, G2 capability disable, G4 session profile |
| S2 spend | `admit_spend_for(&BackendCall) -> Result<Vec<String>>` | once, immediately before an actual backend dispatch (after cache/idempotency short-circuits, which spend nothing) | G3 budget check |
| S3 accounting | `account_dispatch(&BackendCall, Outcome)` | at dispatch completion, before idempotency settlement | G5 error budget, and the existing spend recording (`invoke.rs:3298-3322`: `cost_tracker.record` and `enforcer.record_spend`) |
| S4 payload | `gate_payload(&BackendCall, Value) -> Result<Value>` | on the successful result payload, where meta runs it today (`invoke.rs:2441`) | G6 = the existing `apply_response_gates` (contract, inspection, context integrity) |

`BackendCall { server, tool, session_id, api_key_name, trace_id }`. On the direct route: `server` is the
path `{name}`, `tool` is `params.name`, `api_key_name` is the authenticated client's key name,
`session_id` the `mcp-session-id` header. `Outcome` is the existing
`BudgetOutcome` classification plus success/failure for spend recording, built from the dispatch
result by the one classifier `BudgetOutcome::of`.

Meta keeps its order and replaces inline code with calls: `check_invocation_policy`'s profile check
(`invoke.rs:1089`) and the kill-switch/capability block (`:1637-1659`) are one `admit_target` call
(single profile implementation, policy before nonce as today); `admit_spend` (:1999) and the bridged-round admission (:937, input bridge) both become
`admit_spend_for`; `:3296-3322` becomes `account_dispatch`; `:2441` becomes `gate_payload`. Net lines
in `invoke.rs` go down.

**Spend recording (review finding, critical):** admission alone is not a budget. S3 moves the existing
spend recording into the shared accounting step, so a direct call records spend exactly as a meta call
does and successive direct calls cross the limit.

### 2.1a Direct-route adapter

`dispatch_in_scope` returns `Result<JsonRpcResponse>`. One adapter, `DirectOutcome::from_response`,
maps it for S3/S4: a transport error or JSON-RPC `error` is a failure (classified by `BudgetOutcome::of`
semantics, so a backend rate-limit refusal is `IgnoredRateLimit`); a `result` is success, and its value
is what S4 gates. A tool-level `isError: true` result is success for accounting, as on meta. Spend eligibility and
error-budget class are separate outputs of the adapter, each unit-tested for: ordinary success,
`isError: true`, JSON-RPC error, transport error, backend rate-limit refusal.

### 2.2 Router chain (one chain, reconciled with LIFECYCLE.1)

There is one chain per route boundary and one implementation per control:

- The four `MetaMcp` stage methods (S1-S4, §2.1) own G1-G6. Meta dispatch calls them directly;
  nothing else implements those controls.
- `DirectRouteGuards::run` and `DirectRouteGuards::after_dispatch` (router, agreed with LIFECYCLE.1)
  are the direct route's single pre- and post-dispatch chain. They are thin compositions: `run`'s
  FIRST step is `state.meta_mcp.admit_target(..)` (S1), followed by LIFECYCLE.1's router-only checks
  (isolation, tool policy and sanitisation, propagation) that produce `GuardedCall`.
  `after_dispatch` calls `account_dispatch` (S3) then `gate_payload` (S4), then the response scan.
  S2 `admit_spend_for` is the one stage outside `run`, because it must follow the idempotency
  short-circuit (a cached result spends nothing); the request thread and the worker both call it
  through `DirectRouteGuards::before_dispatch`, a one-line wrapper in the same module.
  None of these re-implements a G1-G6 control.
- The request thread and the LIFECYCLE.1 task worker both call `run` / `before_dispatch` /
  `after_dispatch`; no direct-route code path calls a stage method except through them.

Direct-route order (request thread and LIFECYCLE.1 worker alike):
1. `DirectRouteGuards::run`: S1 `admit_target`, then the G7 signing refusal (§2.3), then LIFECYCLE.1's
   router-only checks. All of `run` executes before the idempotency reservation, so a refused call
   attempts no reservation and a cached result is never returned past a refusal.
2. Idempotency reservation / cached-result short-circuit (unchanged, `backend_handlers.rs:~955`).
3. `DirectRouteGuards::before_dispatch`: S2 `admit_spend_for`, immediately before `dispatch_in_scope`;
   its warnings are attached to a successful result as `_cost_warnings`, as meta does (`invoke.rs:2446-2455`).
4. Dispatch.
5. `DirectRouteGuards::after_dispatch`: S3 `account_dispatch` (before idempotency settlement), then
   S4 `gate_payload` on a successful result, then the response scan.

A refusal from S1/S2/G7 maps to HTTP 200 with the JSON-RPC error meta returns. An S4 refusal is a
post-dispatch refusal, as on meta: the backend ran, accounting recorded it, and the caller gets
HTTP 200 with the gate's JSON-RPC error; the idempotency entry settles with that error. It never
takes the dispatch-`Err` arm (`backend_handlers.rs:1041-1053`, HTTP 500), which stays for transport
failures. Every `tools/call` dispatch site on the route goes through these steps: the request
thread's and the LIFECYCLE.1 worker's, passthrough backends included (S4 then gates the unsanitised
result; the response scan already runs there).

Direct session id: the `mcp-session-id` header when present (`backend_handlers.rs:647`), else none;
with none (or an empty header) `active_profile` returns the default routing profile, as for a
sessionless meta call (`meta_mcp/mod.rs:1550`).

### 2.3 G7 signing and nonce

ADR-001 defines message signing for the `gateway_invoke` envelope only; the direct route has no
signed envelope to carry a nonce or return a MAC. Proposal: when `message_signing.enabled` and
`require_nonce` are both on, the direct route refuses `tools/call` with `-32001`
("message signing is enforced; use gateway_invoke"), so an operator who mandates signed exchanges
has no unsigned side door. The refusal is a step of `DirectRouteGuards::run` (before the idempotency
reservation). This is a direct-route restriction, not a claim that signing is
gateway-wide. With signing off or nonce optional, behaviour is unchanged. Extending
ADR-001 to the direct route is out of scope. Reviewers: challenge this.

## 3. Visibility (maintainer decision 2026-09-27)

New `pub(crate)`: `MetaMcp::admit_target`, `admit_spend_for`, `account_dispatch`, `gate_payload`, and the
`BackendCall` and `DirectOutcome` types, approved as a maintainer decision following the `pub(crate)`
precedent for `DirectRouteGuards`. Nothing existing is widened.

## 4. Behaviour change (UPGRADING item 69)

A direct `/mcp/{name}` call to a killed backend or disabled capability, over a key's cost budget, or
outside the session's active profile is now refused with the error meta dispatch returns. Direct-route
failures count toward the error budget and can auto-kill a backend. Response contract, inspection and
context-integrity settings now apply to direct-route results. With message signing and
`require_nonce` both on, the direct route refuses `tools/call` with -32001 and names
`gateway_invoke` (maintainer decision 2026-09-27: fail closed).

## 5. Tests (red first)

All router cells use one counting backend and assert its call count. An allowed-call baseline row
(no control armed) must dispatch exactly once, so a harness that never reaches the backend cannot pass.

| id | AC | Cell | Red today |
|---|---|---|---|
| T1 | DIRECT.1 | backend killed via `KillSwitch::kill`; POST `/mcp/{name}` `tools/call`; -32000; count 0 | backend called |
| T1b | DIRECT.1 | as T1 but the idempotency key already holds a cached result; still -32000 (kill precedes the cache) | cached result returned |
| T2 | DIRECT.1 | capability disabled by error budget; -32000; count 0 | backend called |
| T3 | DIRECT.2 | limit of N calls, empty accumulator: N direct calls succeed, call N+1 -32003; count N; successful results carry `_cost_warnings` near the limit | all N+1 dispatched |
| T3b | DIRECT.2 | direct JSON-RPC and transport failures do not increment the spend accumulator | n/a (guard) |
| T3c | DIRECT.2 | a bridged multi-round exchange and a direct call draw on one budget | n/a (guard of the :937 extraction) |
| T4 | DIRECT.3 | session profile excluding the tool, `mcp-session-id` set: refused, count 0; absent and empty header: default profile, dispatched | backend called |
| T5 | DIRECT.4 | matrix: signing off (dispatched); signing on, nonce optional (dispatched); signing on + `require_nonce` (-32001, count 0); signed `gateway_invoke` with nonce under the same config succeeds; with an idempotency key already holding a cached result, still -32001 | third row dispatched |
| T6 | DIRECT.5 | backend returning JSON-RPC errors (not rate-limit); server threshold reached before any per-capability limit (capability budget disabled in the fixture); after N failures `is_killed` is true and the next call is refused | never killed |
| T6b | DIRECT.5 | backend rate-limit refusals do not count toward the budget | n/a (guard) |
| T7 | DIRECT.6 | response contract `fail_closed` + `action_mode`, no contract for the tool: refused post-dispatch, count 1; observe mode (`action_mode` off): delivered, warning logged | delivered in both |
| T7b | DIRECT.6 | response inspection `action_mode` with a HIGH finding: refused; context integrity `team_shared` withholding: withheld | delivered |
| T8 | DIRECT.8 | both-routes parity table (§6) | G1-G6 rows red on Direct |
| T9 | ordering | with the T1 kill fixture, the idempotency reservation is never called (counter via a test hook on `direct_route_idempotency`) | counter is 1 today |
| T10 | worker | T1, T3 and T7 run through the LIFECYCLE.1 task worker's dispatch as well as the request thread (lands with or after LIFECYCLE.1; added to whichever lands second) | backend called |
| T11 | replay | a payload-gate refusal settles the idempotency entry; a retry with the same key replays the refusal without dispatching | n/a (guard) |

Mutants (throwaway CI): M1 drop kill switch from `admit_target` (T1, T1b, T8); M2 drop `admit_spend_for`
on direct (T3, T8); M3 drop spend recording from `account_dispatch` (T3); M4 drop the profile step (T4);
M5 call `admit_target` after the reservation (T9, T1b); M6 drop the nonce refusal (T5); M7 skip
`account_dispatch` on direct (T6, T3); M8 skip `gate_payload` on direct (T7, T7b, T8); M9 add a control
inline in `invoke_tool_traced` only (T8 structural check, §6); M10 map an S4 refusal to the
dispatch-`Err` arm (T7 status 500 instead of 200).

## 6. Both-routes parity test (DIRECT.8)

`src/gateway/router/dispatch_parity_tests.rs`, three parts:

- Shared controls (G1-G6): a row per entry of `DISPATCH_CONTROLS` (a `const` list in
  `dispatch_guards.rs` the stage methods iterate; row names must equal it). Each row arms its control
  and states the refusal code or payload effect, backend call count and state assertion (spend,
  error-budget sample, `_security_findings`). Every row runs through both routes and must give the
  same result, plus the allowed baseline row.
- Already-shared controls (rate limit, request firewall, authorizer, tool name, attestation,
  undeclared keys, audit, response firewall): a second table, both routes, same assertion shape.
  Not in `DISPATCH_CONTROLS`, which lists only what this change moves.
- G7 is route-specific by design and is covered by T5 alone, with its own per-route expectations.

Structure: a source check reads `invoke_tool_traced`, `backend_handler_inner` and
`src/gateway/router/direct_guards.rs` and fails if an inner primitive appears there:
`kill_switch.is_killed`, `is_capability_disabled`, `record_error_budget`, `enforcer.record_spend`,
`apply_response_gates`, or `active_profile(..).check`. Calls to the stage methods, and the plain
`active_profile(session_id)` lookup meta uses for routing and cache keys (`invoke.rs:1661`), are
allowed. A control added inline on one route therefore fails (M9); correct wiring passes.

## 7. Out of scope

Response cache on the direct route; ADR-001 signing envelope on the direct route; LIFECYCLE.1's own
checks (isolation, policy, sanitisation, propagation), which it moves into `run` itself.
