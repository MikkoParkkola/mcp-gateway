# Test plan — authorize at dispatch (MIK-7252)

Companion to `authorize-at-dispatch.md`, frozen after six rounds with a
unanimous SHIP.

The right-hand column is the plan. A test that runs, asserts, and could not have
failed is worse than no test: it reports coverage it does not have. Three
failure modes are named throughout, because all three were found in earlier
drafts of this plan:

- **passes for the wrong reason** — a fail-closed policy refuses whether or not
  the identity reached it, so the refusal proves nothing about propagation;
- **cannot observe what it names** — the code path the criterion describes is
  not reachable from the shape the case uses;
- **asserts at the wrong level** — the engine only ever sees a `ToolInvoker`, so
  no engine-level row can count authorizer consultations.

## Levels, and what is visible at each

| L | boundary | what a row may assert |
|---|---|---|
| **E** engine | `PlaybookEngine::execute(_, _, &dyn ToolInvoker)` | `ToolInvoker::invoke` call counts, `steps_failed`, `steps_skipped`, `step_errors`, the returned error. **Never** authorizer consultations — the engine has no authorizer |
| **U** meta | `invoke_tool` through the production caller-context constructor | authorizer consultations, cache and idempotency state, nonce store, budget enforcer, backend counters |
| **I** router | a request through `handlers.rs` | client-visible envelopes, refusal messages, audit lines, which gate refused |
| **S** stdio | `dispatch_single` | the same, on the stdio transport |

## Where a double may be injected

`DenyAll`, `AllowAll` and the counting wrapper are the only legitimate doubles,
and none contains policy logic. They are injected **only** through the
production caller-context constructor — the one `router/handlers.rs` and
`server/mod.rs` use. A test-only seam that builds a context another way proves
the double works, not that the chokepoint is reached.

## Refusal cases, each paired with an allow case

A fail-closed policy denies a missing identity exactly as it denies a
disallowed one. Every refusal row therefore carries an allow row: without it, a
fix that never propagates the identity passes the refusal and fails nothing.

| AC | case | L | why it can fail |
|---|---|---|---|
| 1 | client `backends:["alpha"]`, playbook step targets `beta` → refused, message names `beta` | I | succeeds today |
| 1a | same client, step targets `alpha` → succeeds | I | fails a fix that refuses everything |
| 2 | client `allowed_tools:["safe_*"]`, step calls `danger_tool` on an allowed backend | I | backend scope passes, so a 1-only fix fails here |
| 2a | same client, step calls `safe_read` → succeeds | I | fails a deny-all fix |
| 3 | global tool policy denies `alpha:blocked` | I | policy is on `AppState`, so an identity-only fix fails |
| 3a | same policy, step calls a permitted tool → succeeds | I | fails a fix that refuses on any policy presence |
| 10 | mTLS policy denies this certificate for `alpha:tool` | I | distinct policy object |
| 10a | a certificate the policy **allows** → succeeds | I | `evaluate(None)` is `Deny` when enabled, so 10 alone stays green with the identity dropped entirely. This row is what proves propagation |
| 11 | agent auth on, step outside the agent's scope | I | distinct check |
| 11a | an **in-scope** agent identity → succeeds | I | same fail-closed trap as 10a |

## Denial semantics — fixtures must set `on_error` explicitly

The default is `Abort`, and an `Abort` fixture passes whether or not the rule
holds. These rows are engine-level, so they assert `ToolInvoker` call counts and
result fields, never authorizer consultations.

| AC | case | L | why it can fail |
|---|---|---|---|
| 17 | `on_error: retry`, `max_retries: 3`, an invoker returning the denial error → **`ToolInvoker::invoke` called once**, name in `steps_failed`, reason in `step_errors`, later steps still run | E | an ordinary `Err` is retried three times, so the count fails. Stated as invoker calls because the engine cannot see an authorizer |
| 17a | the same playbook driven at meta level with a **real** `DenyAll` → the authorizer is consulted once and the backend zero times | U | 17 uses a synthetic error; only this row proves a production refusal is converted to the non-retry variant. It is at U because that is where an authorizer exists to count |
| 18 | `on_error: continue`, a denied step then an allowed step → run completes, allowed step ran, name in `steps_failed`, reason in `step_errors` | E | fails terminal-refusal and fails silent-null; the two fields separate them |
| 18a | `on_error: continue`, an ordinary **backend** failure → its message also lands in `step_errors` | E | fails a fix recording refusals only, leaving ordinary failures unexplained |
| 19 | `on_error: abort`, a denied step → the run returns **the denial's own code and message**, and no later step runs | E | asserting only "aborted" passes for any error; the code pins it to a denial |

## No side effect before the check

One row per criterion, each naming every oracle it needs. AUTHZ.7 has three
clauses and therefore three oracles; a backend counter alone cannot see a cache
write or a budget spend.

| AC | case | L | why it can fail |
|---|---|---|---|
| 7 | a refused meta-level `gateway_invoke` → **backend counter 0**, **no new response-cache entry for that key**, **no recorded budget spend** | U | a check after the spend at `invoke.rs:861` passes a backend-only assertion; a check after the cache write at `:1231` passes both. Each clause needs its own oracle or the clause is untested |
| 7a | the same call allowed → backend counter 1, a cache entry present, a spend recorded | U | makes 7's three zeros meaningful; without it an unreachable code path scores three passes |
| 12 | prime the response cache for `alpha:tool` as an allowed caller, then drive the same target with `DenyAll` → refused, and the cached value is **not** returned | U | a check after the cache read returns the cached payload. The cache must be genuinely primed |
| 12a | the same primed target with `AllowAll` → the cached value **is** returned | U | proves the fixture's cache is real, so 12's refusal is not just an empty cache |
| 20 | a refused call carrying a fresh top-level `nonce` against a live `NonceStore` → refused, and the same nonce is **still registrable** afterwards | U | a check below `:634` consumes the nonce |
| 20a | a refused call against a live idempotency cache and an identity-propagating backend → **no in-flight entry for that key**, **no minted credential** | U | both need live subsystems on the path; with neither configured the row passes vacuously, which is why 20b exists |
| 20b | the same call allowed → an in-flight entry appears and a credential is minted | U | proves both subsystems were reachable, so 20a's zeros mean something |

Why a client `gateway_invoke` is the shape for all of these: `_full` skips the
cache (`invoke.rs:799`, `:1231`) and idempotency (`:750`), and it is injected
**only** by `internal_invoke_args` (`support.rs:204`). A client's invoke carries
none, so it reaches the chokepoint through the live paths. That is also the case
the design calls authoritative — the router allowed the call, policy changed
between the gates, and the chokepoint must refuse before the cache is read.

## Coverage of the chokepoint claim

| AC | case | L | why it can fail |
|---|---|---|---|
| 13 | `DenyAll` through the production caller-context constructor, against all five meta shapes — surfaced tool, `gateway_invoke`, code-mode single, code-mode chain step, playbook step | U | a playbook-only fix fails four rows. The highest-value row in this plan |
| 6 | a run with two steps, one `condition: false` targeting an unauthorized backend and one executed → **`ToolInvoker::invoke` called exactly once, for the executed step** | E | a zero-count alone is satisfied by an invoker never called at all; the paired count of one makes zero meaningful. Stated as invoker calls because the engine sees no authorizer |
| 6a | the same playbook at meta level with a counting authorizer → **consulted once**, for the executed step only | U | this is where "never authorized" is actually observable |
| 14 | satisfied by 14a and 14b together; it has no separate case, because the criterion is one assertion made on two transports | — | — |
| 14a | **Http**, on a router-uncovered shape (a playbook step): the refusal line carries caller, server, tool and `transport = Http`, and the authorizer emits nothing | I | on a router-covered shape the router emits and the chokepoint is never reached, so ownership would be proven against the wrong gate |
| 14b | **Stdio**, same assertion with `transport = Stdio` | S | cannot run at I; a fix hard-coding one transport fails one half |
| 23 | a denied `gateway_invoke` over the **full router path** → exactly one refusal line | I | the router returns before the chokepoint, so a meta-level fixture proves nothing here |
| 21 | the direct `/mcp/{name}` route keeps its existing refusal behaviour | I | fails if the outer check is deleted as redundant |

## Behaviour that must not change

| AC | case | L | why it can fail |
|---|---|---|---|
| 4 | admin, unrestricted, the same playbook as 1 → succeeds | I | fails a hard-coded non-admin or a deny default |
| 5 | client with empty `backends` and no allow/deny lists → succeeds | I | fails a deny-by-default fix |
| 8 | a direct `gateway_invoke` refused → **the literal message in use today**, pinned as a constant in the test | I | fails a reroute through a new message path |
| 8a | a code-mode chain step refused → its literal message today | I | split from 8 deliberately: one row covering two shapes hides a regression in either |
| 24 | a playbook that denies nothing serialises **without** a `step_errors` key | E | pins the successful-run wire; fails a field that always emits `{}` |

## Transport

| AC | case | L | why it can fail |
|---|---|---|---|
| 15 | a stdio playbook step hits a policy-denied tool → refused | S | no coverage today; fails against pre-fix source |
| 16 | stdio keeps admin standing and its `gateway_invoke` refusal after the inline block is deleted | S | guards the deletion |
| 22 | with mTLS rules configured, stdio calls are **not** refused | S | fails an implementation that hands stdio the mTLS policy, which would deny everything |

`MIK.AUTHZ.9` remains withdrawn from design time: the types prove it, and a test
that greps for a symbol is a lint wearing a test's clothes.

## Honesty list — rows that pass against unfixed code by design

4, 5, 8, 8a, 16, 21, 22, 23, 24, and weakly 19. They are regression guards:
their job is to fail if this change breaks something, not to demonstrate that it
works. A coverage tool scores them as covering the new mechanism; they do not.
23 and 24 are here because one refusal line and an absent `step_errors` key are
both true of the code before this change.

Rows that demonstrate the mechanism, and therefore earn a probe: 1, 1a, 2, 2a,
3, 3a, 6, 6a, 7, 7a, 10, 10a, 11, 11a, 12, 12a, 13, 14a, 14b, 15, 17, 17a, 18,
18a, 20, 20a, 20b.

## Falsifier probes — three kinds, because one does not fit all

Per development-process.md §P2: copy the file, restore under a trap, confirm the
failure is the intended assertion and not a compile error, then confirm the test
goes green again. The restore is verified by re-running the test, never by
`git status`.

| rows | probe | why this one |
|---|---|---|
| refusal rows touching no new API — 1, 2, 3, 10, 11, 15 | restore pre-fix production source | the strongest probe: the mechanism is genuinely absent |
| refusal rows naming change-introduced APIs — 12, 13, 17a, 20, 20a, and 17/18/18a via `step_errors` | make the chokepoint's authorization call a **no-op**, one line, leaving every type in place | restoring the source leaves the test file uncompilable, and a compile error is not a falsification |
| **allow** rows — 1a, 2a, 3a, 6a, 7a, 10a, 11a, 12a, 20b | invert the authorizer to **deny everything** | a no-op probe makes an allow row pass, so it cannot falsify one. Only forcing a denial proves the row is watching the allow path |

A row whose probe does not produce the expected failure is not evidence of a
correct implementation. It is evidence the row is not testing what it claims.
