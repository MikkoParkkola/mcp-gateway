# Test plan — authorize at dispatch (MIK-7252)

Companion to `authorize-at-dispatch.md`, frozen after six rounds with a
unanimous SHIP.

The right-hand column is the plan. A test that runs, asserts, and could not have
failed is worse than no test: it reports coverage it does not have. Two failure
modes are called out by name throughout, because both were found in the first
draft of this plan:

- **passes for the wrong reason** — a fail-closed policy refuses whether or not
  the identity reached it, so the refusal proves nothing about propagation;
- **cannot observe what it names** — the code path the criterion describes is
  not reachable from the shape the case uses.

L: U=unit, I=integration (router→meta→backend), E=engine, S=stdio.

## Where the denying authorizer may be injected

`DenyAll`, `AllowAll` and the counting wrapper are the only legitimate doubles,
and none contains policy logic. They are injected **only** through the
production caller-context constructor — the one `router/handlers.rs` and
`server/mod.rs` use. A test-only seam that builds a context some other way
proves the double works, not that the chokepoint is reached.

## Refusal cases, each paired with an allow case

A fail-closed policy denies a missing identity exactly as it denies a
disallowed one. So every refusal row below carries an allow row: without it, a
fix that never propagates the identity passes the refusal and fails nothing.

| AC | case | L | why it can fail |
|---|---|---|---|
| 1 | client `backends:["alpha"]`, step targets `beta` → refused, message names `beta` | I | succeeds today |
| 1a | same client, step targets `alpha` → succeeds | I | fails a fix that refuses everything |
| 2 | client `allowed_tools:["safe_*"]`, step calls `danger_tool` on an allowed backend | I | backend scope passes, so a .1-only fix fails here |
| 2a | same client, step calls `safe_read` → succeeds | I | fails a deny-all fix |
| 3 | global tool policy denies `alpha:blocked` | I | policy is on AppState, so an identity-only fix fails |
| 3a | same policy, step calls a permitted tool → succeeds | I | fails a fix that refuses on any policy presence |
| 10 | mTLS policy denies this certificate for `alpha:tool` | I | distinct policy object |
| 10a | **a certificate the policy ALLOWS → succeeds** | I | `evaluate(None)` is `Deny` when enabled, so 10 alone stays green with the identity dropped entirely. This row is what proves propagation |
| 11 | agent auth on, step outside the agent's scope | I | distinct check |
| 11a | **an in-scope agent identity → succeeds** | I | same fail-closed trap as 10a; without this, dropping `oauth_agent_identity` passes 11 |

## Denial semantics — fixtures must set `on_error` explicitly

The default is `Abort`, and an `Abort` fixture passes whether or not the rule holds.

| AC | case | L | why it can fail |
|---|---|---|---|
| 17 | `on_error: retry`, `max_retries: 3`, denied step → authorizer consulted **once**, backend zero times, name in `steps_failed`, reason in `step_errors`, later steps still run | E | a denial routed as an ordinary `Err` is retried three times |
| 17a | **a real chokepoint denial, not a synthetic one, produces the engine's non-retry variant** | I | 17-19 run at engine level with an injected error; without this row nothing proves a production authorizer refusal is converted to that variant, and the branches are covered while the conversion is untested |
| 18 | `on_error: continue`, denied step then an allowed step → run completes, allowed step ran, name in `steps_failed`, reason in `step_errors` | E | fails terminal-refusal and fails silent-null; the two fields separate them |
| 18a | `on_error: continue`, an ordinary **backend** failure → its message also lands in `step_errors` | E | fails a fix recording refusals only, leaving ordinary failures unexplained |
| 19 | `on_error: abort`, denied step → the run returns **the denial's own code and message**, and no later step runs | E | asserting only "aborted" passes for any error; the code is what pins it to a denial |

## Behaviour that must not change

| AC | case | L | why it can fail |
|---|---|---|---|
| 4 | admin, unrestricted, same playbook as 1 → succeeds | I | fails a hard-coded non-admin or a deny default. Passes against unfixed code — see the honesty list |
| 5 | client with empty `backends`, no allow/deny lists → succeeds | I | fails a deny-by-default fix. Passes against unfixed code |
| 6 | a run with two steps: one `condition: false` targeting an unauthorized backend, one executed. Counting authorizer shows **0 consultations for the skipped step and exactly 1 for the executed one** | E | a zero-count alone is satisfied by an authorizer that is never called at all; the paired count=1 is what makes zero meaningful |
| 8 | direct `gateway_invoke` refused → **the literal message in use today**, pinned as a string constant in the test | I | fails a reroute through a new message path |
| 8a | code-mode chain step refused → its literal message today | I | split from 8 deliberately: one row covering two shapes hides a regression in either |
| 24 | a playbook that denies nothing serialises **without** a `step_errors` key | E | pins the wire identity of a successful run; fails a naive `BTreeMap` field that always emits `{}` |

## Coverage of the chokepoint claim

| AC | case | L | why it can fail |
|---|---|---|---|
| 13 | `DenyAll` through the production caller-context constructor, against all five meta shapes — surfaced tool, `gateway_invoke`, code-mode single, code-mode chain step, playbook step | U | a playbook-only fix fails four rows. The highest-value row in this plan |
| 21 | the direct `/mcp/{name}` route keeps its existing refusal behaviour | I | fails if the outer check is deleted as redundant. Passes against unfixed code |
| 7 | a refused step performs **no backend call and spends no budget** — counting mock backend at zero | I | a post-dispatch check passes 1 and fails this |
| 23 | denied `gateway_invoke` over the **full router path** → exactly one refusal line | I | the router returns before the chokepoint, so a meta-level fixture proves nothing here |
| 14a | **Http half, on a router-uncovered shape (a playbook step)**: refusal line carries caller, server, tool, and `transport = Http`; the authorizer emits nothing | I | on a router-covered shape the router emits and the chokepoint is never reached, so the ownership claim would be proven against the wrong gate |
| 14b | **Stdio half**, same assertion with `transport = Stdio` | S | cannot run at integration level; a fix hard-coding one transport fails one of the two halves |

## Transport

| AC | case | L | why it can fail |
|---|---|---|---|
| 15 | stdio playbook step hits a policy-denied tool → refused | S | no coverage today; fails against pre-fix source |
| 16 | stdio keeps admin standing and its `gateway_invoke` refusal after the inline block is deleted | S | guards the deletion. Passes against unfixed code |
| 22 | with mTLS rules configured, stdio calls are **not** refused | S | fails an implementation that hands stdio the mTLS policy, which would deny everything. Passes against unfixed code |

## Criteria that cannot be observed today, and why

Withdrawn rather than written as cases that would run green and prove nothing.
Each names the condition that would make it live again.

- **MIK.AUTHZ.12 (a cached result is not served to a refused caller)** and the
  cache clause of **MIK.AUTHZ.7**. No shape both reaches the chokepoint and uses
  the cache. Every internal call injects `_full` via `internal_invoke_args`, and
  `_full` skips the response cache (`invoke.rs:799`, `:1231`) and idempotency
  (`:750`) outright — "a `_full` request is always a fresh, uncached dispatch",
  in the code's own words. Router-covered shapes do use the cache, but the
  router refuses them before the chokepoint runs. The property still holds — it
  is enforced by the router gate for cached shapes — but it is not observable at
  the chokepoint. **Live again if** internal calls stop injecting `_full`.
- **The nonce and idempotency clauses of MIK.AUTHZ.20.** `internal_invoke_args`
  puts no `nonce` on the envelope, and `_full` skips idempotency, so a playbook
  step cannot exercise either; a direct `gateway_invoke` is refused at the
  router first. The credential-mint clause survives and stays in 20.
- **MIK.AUTHZ.9** was withdrawn at design time: the types prove it, and a test
  that greps for a symbol is a lint wearing a test's clothes.

The placement of the check above the cache read and the nonce block is still
required by the design. It is currently justified by reading, not by a test,
and that is stated here rather than hidden behind a green row.

## Honesty list — rows that pass against unfixed code by design

4, 5, 8, 8a, 16, 21, 22, and weakly 19. They are regression guards: their job
is to fail if this change breaks something, not to demonstrate it works. A
coverage tool scores them as covering the new mechanism; they do not. The rows
that actually demonstrate the mechanism are 1, 2, 3, 10, 11, 13, 15, 17, 17a,
18, 23 and 14a/14b.

## Falsifier probes

Every row in the demonstrating set gets a probe against pre-fix content, per
development-process.md §P2: copy the file, restore under a trap, confirm the
failure is the intended assertion and not a compile error, then confirm the
test goes green again after restoring. The restore is verified by re-running the
test, never by `git status`.
