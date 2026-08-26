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
| 17a | a **single-step** playbook, `on_error: retry`, `max_retries: 3`, driven at meta level with a counting wrapper over `DenyAll` → the authorizer is consulted exactly once **for that step** | U | 17 uses a synthetic error; only this row proves a production refusal is converted to the non-retry variant. It is at U because that is where an authorizer exists to count |
| 18 | `on_error: continue`, a denied step then an allowed step → run completes, allowed step ran, name in `steps_failed`, reason in `step_errors` | E | fails terminal-refusal and fails silent-null; the two fields separate them |
| 18a | `on_error: continue`, an ordinary **backend** failure → its message also lands in `step_errors` | E | fails a fix recording refusals only, leaving ordinary failures unexplained |
| 18b | `on_error: retry` with attempts exhausted by an ordinary failure → its message also lands in `step_errors` | E | the `!succeeded` arm null-fills for `Continue` **and** `Retry` (`engine/mod.rs:206`); 18a covers only the first, so a fix populating one arm passes it and leaves retry callers unexplained |
| 19 | `on_error: abort`, a denied step → the run returns **the denial's own code and message**, and no later step runs | E | asserting only "aborted" passes for any error; the code pins it to a denial |
| 17b | `on_error: retry`, `max_retries: 3`, an invoker returning an **ordinary** error → `ToolInvoker::invoke` called **three** times | E | without this control, an implementation that disables retrying altogether satisfies 17 and 17a. This is the row that says only *denials* stop retrying |

## No side effect before the check

One row per criterion, each naming every oracle it needs. AUTHZ.7 has three
clauses and therefore three oracles; a backend counter alone cannot see a cache
write or a budget spend.

| AC | case | L | why it can fail |
|---|---|---|---|
| 7 | a refused meta-level `gateway_invoke`, cache starting **empty** → **backend counter 0** and **no cache entry written** for that key | U | a check placed after the cache write at `:1231` passes a backend-only assertion. The empty start matters: with a primed cache a hit at `:799` returns early and produces the same two zeros without proving anything |
| 7b | an **exhausted** budget AND an unauthorized target → the error returned is the **authorization refusal**, not the budget error | U | this is how budget ordering is observable at all. `BudgetEnforcer` is a concrete `Arc<BudgetEnforcer>` (`meta_mcp/mod.rs:182`), not a trait, so no counting wrapper can be injected; and a spend assertion is vacuous because `record_spend` (`:960`) is post-invoke and success-only. Two competing gates and one returned error is the discriminator: authorization below `check` at `:861` yields the budget message |
| 7a | the same call allowed → backend counter 1 and a cache entry present | U | makes 7's zeros meaningful; without it an unreachable code path scores two passes |
| 12 | prime the response cache for `alpha:tool` as an allowed caller, then drive the same target with `DenyAll` → refused, and the cached value is **not** returned | U | a check after the cache read returns the cached payload. The cache must be genuinely primed |
| 12a | the same primed target with `AllowAll` → the cached value **is** returned | U | proves the fixture's cache is real, so 12's refusal is not just an empty cache |
| 20 | a refused call carrying a fresh top-level `nonce` against a live `NonceStore` → refused, and the same nonce is **still registrable** afterwards | U | a check below `:634` consumes the nonce |
| 20c | the same call **allowed** → the nonce is consumed, and replaying it is rejected | U | proves the nonce was on the path at all. Without it, a nonce in the wrong place — or never read — leaves 20 green for the wrong reason |
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
| 13a-13e | `DenyAll` through the production caller-context constructor, as **five independent cases** — 13a surfaced tool, 13b `gateway_invoke`, 13c code-mode single, 13d code-mode chain step, 13e playbook step | U | the highest-value rows in this plan, and independent on purpose: one case asserting five shapes stops at the first failure and hides the other four, reporting one defect where there may be four |
| 6 | a run with two steps, one `condition: false` targeting an unauthorized backend and one executed → **`ToolInvoker::invoke` called exactly once, for the executed step** | E | a zero-count alone is satisfied by an invoker never called at all; the paired count of one makes zero meaningful. Stated as invoker calls because the engine sees no authorizer |
| 6a | the same playbook at meta level with a counting authorizer → **consulted once**, for the executed step only | U | this is where "never authorized" is actually observable |
| 14 | satisfied by 14a and 14b together; it has no separate case, because the criterion is one assertion made on two transports | — | — |
| 14a | **Http**, on a router-uncovered shape (a playbook step): the refusal line carries caller, server, tool and `transport = Http`, and the authorizer emits nothing | I | on a router-covered shape the router emits and the chokepoint is never reached, so ownership would be proven against the wrong gate |
| 14b | **Stdio**, same assertion with `transport = Stdio` | S | cannot run at I; a fix hard-coding one transport fails one half |
| 23 | a denied `gateway_invoke` over the **full router path** → exactly one refusal line **of the shared `audit_refusal` helper** | I | the router returns before the chokepoint, so a meta-level fixture proves nothing here |
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
| 15a | a stdio playbook step hitting a **permitted** tool → succeeds | S | a stdio authorizer that denies every backend target passes 15 and 16 on its own; this row is what refuses that |
| 16 | stdio keeps admin standing and its `gateway_invoke` refusal after the inline block is deleted | S | guards the deletion |
| 22 | with mTLS rules configured, a stdio call to **an actual backend tool** is not refused | S | fails an implementation that hands stdio the mTLS policy, which would deny everything |

`MIK.AUTHZ.9` remains withdrawn from design time: the types prove it, and a test
that greps for a symbol is a lint wearing a test's clothes.

## Honesty list — rows that pass against unfixed code by design

4, 5, 6, 8, 8a, 16, 21, 22, 24, and weakly 19. They are regression guards: their
job is to fail if this change breaks something, not to demonstrate that it
works. A coverage tool scores them as covering the new mechanism; they do not.
6 is here because engine-level condition-skip behaviour predates this change;
its meta-level pair 6a is what demonstrates anything.

**Row 23 is NOT on this list**, and an earlier draft put it there wrongly. On
unfixed code the router emits **zero** lines of the new refusal helper, so
"exactly one" is false, not true. Reading it as a regression guard invites
`count <= 1`, which a helper omitted from the router path would satisfy — on the
one path that actually runs for HTTP callers. It asserts exactly one line **of
the shared helper**, and it fails today.

## Falsifier probes

Per development-process.md §P2: copy the file, restore under a trap, confirm the
failure is the intended assertion and not a compile error, then confirm the test
goes green again. The restore is verified by re-running the test, never by
`git status`.

This table is the only list of which rows earn a probe. An earlier draft kept a
separate prose list, and the two disagreed — four rows were named there and
appeared in no probe row.

**A probe is chosen per row by one question: what sabotage turns THIS row red?**
Not which section the row lives in. An earlier draft assigned by section and got
three rows wrong in the same way — a probe that leaves the assertion green is
not a weak probe, it is no probe, and it certifies nothing. Each class below
therefore says what it makes fail.

**No row restores the pre-fix source.** Every demonstrating test names
something this change introduced — the authorizer, `step_errors`, the status
mapping — so a source restore breaks compilation. Behaviour is reverted
instead: a weaker probe honestly labelled, rather than a stronger one falsely
claimed.

| rows | probe | why this one, and not another |
|---|---|---|
| 1, 2, 3, 10, 11 | disable the chokepoint's authorization call, one line, every type left in place | an earlier version of this row said "restore pre-fix production source, because these assertions name no new API". That was wrong, and was never what ran: these tests construct `RouterAuthorizer`, set the `authorizer` field and call `refusal_status`, all introduced by this change, so restoring the source breaks the build — and this plan's own rule is that a build error falsifies nothing |
| 15 | make the real stdio authorizer permit everything | substituting `AllowAll` does not compile: it is `#[cfg(test)]`, which is the guarantee working rather than a probe |
| 7, 7b, 12, 13a-13e, 20, 20a | make the chokepoint's authorization call a **no-op**, one line, every type left in place | the refusal disappears and each row's assertion goes red. Restoring the source instead leaves these test files uncompilable, and a compile error is not a falsification |
| 23 | remove the `audit_refusal` call from the **router** gate | 23 runs the full router path, which refuses and returns *before* the chokepoint — the chokepoint no-op leaves its line intact and the row green. Sabotaging the gate that actually emits it takes the count from one to zero |
| 6a, 17a | the same no-op | consultation counts drop to zero, so the row fails. A deny-all probe cannot falsify them: the authorizer is consulted once whatever verdict it returns |
| 17, 18, 18a, 18b | revert the **engine** change — restore the retry loop without the denial break, and stop populating `step_errors` | 17's single invoker call becomes three, and `step_errors` disappears. These run at engine level against a synthetic invoker, so a chokepoint no-op would leave every assertion untouched |
| 17b | widen the denial break to match **every** error, not only a denial | 17b asserts pre-existing behaviour — ordinary errors retried three times — so the engine revert restores exactly what it expects and cannot fail it. The risk 17b guards is an over-broad non-retry, so that is the sabotage: ordinary errors then stop after one call and the row goes red |
| 14a, 14b | remove the `audit_refusal` call from the **chokepoint**, leaving the refusal itself intact | these rows assert that the *chokepoint* owns the emission, so the probe must remove the emitter and nothing else. A probe that removes the refusal takes the line with it and would pass equally against an implementation where some other layer emits — proving the refusal fired, which is not the claim |
| 1a, 2a, 3a, 7a, 10a, 11a, 12a, 15a, 20b, 20c | invert the relevant authorizer to **deny everything** — the stdio one for 15a | the permitted call is refused and the row goes red. A no-op probe makes an allow row pass and cannot falsify one; nor can removing an authorizer, since a permitted call succeeds either way |

Rows on the honesty list get no probe: they are expected to pass before and
after, and a probe that "fails" one would be reporting the guard working, not
the mechanism.

A row whose probe does not produce the expected failure is not evidence of a
correct implementation. It is evidence the row is not testing what it claims.

## Test names

`authz_<row>_<slug>`, where `<row>` is the row label in lower case — so
`authz_13e_playbook_step_denied`. The intent was that a grep for a row label
finds its test, or finds a gap.

That holds for most rows and NOT for four of them: an allow row shares a fixture
with the refusal it pairs with, so `10a`, `11a`, `12a` and `20c` live inside
`authz_10`, `authz_11`, `authz_12` and `authz_20` rather than in functions of
their own. Splitting them would duplicate the setup and let the pair drift. The
index in "Coverage, stated exactly" is what covers those four; the grep does
not.

## Fixture notes that are easy to get wrong

- **20b** needs the backend gated — paused mid-call — so the idempotency
  in-flight entry can be observed while it exists. Inspecting after completion
  sees an entry that has already been cleared, and reads as absent.
- **7b** needs the enforcer *enabled* and a tool whose `cost_for` is non-zero.
  A disabled enforcer or a free tool never produces the budget error, so the
  discriminator has only one arm and the row passes whatever the ordering. (This
  note previously sat on 7/7a, whose spend oracle no longer exists.)
- **20a** cannot use the no-op probe for its in-flight half: with authorization
  removed the call dispatches successfully, and the in-flight entry becomes a
  completed one rather than staying absent. Only the credential half fails under
  that probe, so **the in-flight assertion is carried by 20b**, whose gated
  backend can observe the entry while it exists.
- **12** needs a genuinely primed cache, not a mock returning a hit. **7** needs
  the opposite — an empty one — so a cache hit cannot manufacture its zeros.
- **20a** reads its two oracles *after* the refusal returns. It does not pause
  the backend the way 20b must: there is no in-flight window to inspect on a
  call that never dispatches, and waiting for one would hang.
- **8 and 8a** pin literal message strings as constants in the test, so a
  reworded refusal fails loudly rather than silently passing a `contains` check.

## Coverage, stated exactly

Rewritten from the test list rather than patched. Two review rounds found this
section contradicting itself — claiming a count its own table disproved, and
listing rows as untested two sections after recording their probe results. That
is what incremental edits to an inventory produce, so this is generated from
`rg "fn authz_"` and kept that way.

**33 tests exist.** By area:

| area | tests |
|---|---|
| client scope, real policy (`router::tests`) | `authz_1`, `authz_1a`, `authz_2`, `authz_2a` |
| global tool policy (`router::tests`) | `authz_3`, `authz_3a` |
| certificate policy (`router::tests`) | `authz_10` — refuse and permit in one case |
| agent scope (`router::tests`) | `authz_11` — refuse, permit, and no-identity |
| dispatch shapes (`meta_mcp::authz_tests`) | `authz_13a` ×2, `authz_13b` ×2, `authz_13c`, `authz_13d`, `authz_13cd`, `authz_13e` ×2 |
| denial semantics (`meta_mcp::authz_tests`) | `authz_17`, `authz_17b`, `authz_18`, `authz_18a`, `authz_19`, `authz_24` |
| condition skip (`meta_mcp::authz_tests`) | `authz_6a` |
| pre-dispatch ordering (`meta_mcp::authz_tests`) | `authz_12` (cache), `authz_20` (nonce) |
| HTTP status and attribution (`router::tests`) | `authz_playbook_denial_answers_forbidden_over_http`, `authz_every_refusal_branch_carries_the_status`, `authz_ordinary_error_is_not_reclassified_as_forbidden`, `authz_refusal_principal_names_the_authenticated_identity` |
| stdio (`server::tests`) | `authz_15`, `authz_15a`, `authz_22` |

**On the naming convention.** The plan proposed `authz_<row>_<slug>`, one test
per row, so a grep for `authz_10a` would find a gap. Several rows are paired
inside one function instead — `10a` lives in `authz_10`, `11a` in `authz_11`,
`12a` in `authz_12`, `20c` in `authz_20`. That is deliberate: an allow row and
its refusal row share a fixture, and splitting them duplicates the setup while
letting the pair drift. The cost is real and is stated here rather than hidden:
**a grep no longer finds those four rows**, so this table is the index instead.

**Still not implemented:**

| rows | why not, and what it would take |
|---|---|
| 14a, 14b, 23 — the audit line | no log-capture harness exists; see below |
| 7, 7a, 7b — budget ordering | needs a live budget enforcer with a priced tool. Placement is read, not tested: the check sits at `invoke.rs:551`, above `:861` |
| 20a, 20b — idempotency and credential minting | needs a live idempotency store and an identity-propagating backend, with the backend gated so the in-flight entry can be observed while it exists |
| 8, 8a, 16, 21 — message and route regressions | pin literal strings and the direct route; guard a future refactor rather than demonstrate this change |

**A limitation of the identity tests, stated.** `authz_10` and `authz_11` build
`RouterAuthorizer` and the caller context themselves rather than driving
`handlers.rs`. They prove the authorizer consults the identity it is given; they
do NOT prove the production handler hands it over. That wiring is one
construction site (`handlers.rs`, the `RouterAuthorizer { .. }` literal) and its
completeness is enforced by the type — the struct has no `Default`, so every
field must be named — but a site that named `None` explicitly would compile and
these tests would stay green. Control: code review over one literal.

**What that leaves unproven, precisely**: that the audit lines fire; that
idempotency, credential minting and budget consultation do not precede the
check; and that the HTTP handler passes the certificate and agent identities it
holds.

**What IS proven, by probe rather than assertion**: a playbook step outside the
caller's backend scope, tool allow-list, global policy, certificate policy or
agent scope is refused under the real production policy, and is NOT refused when
the chokepoint is disabled; a refused caller is served no cached result and
burns no nonce; and a denial is neither retried nor silently null-filled.

## What the probes actually found

Run against the implemented change. Recorded because a probe that behaves
unexpectedly is evidence about the plan, not just about the code.

| probe | result |
|---|---|
| chokepoint disabled, meta rows | every denial row → **red**; every allow row stayed green. The three-way probe split is confirmed empirically: disabling a check cannot falsify an allow row |
| chokepoint disabled, router rows | `authz_1` and `authz_2` → **red**, their allow halves green. These use the real `RouterAuthorizer` over a real `AuthenticatedClient`, so this is what demonstrates the defect is closed under production policy rather than under a double |
| engine reverted | `authz_17` and `authz_18` → **red**, `authz_24` green |
| authorizer inverted to deny everything | every allow row → **red** |
| stdio authorizer permits everything | `authz_15` → **red**, `authz_15a` and `authz_22` green |
| check moved below the nonce registration | `authz_20` → **red** — a refused call burned the nonce, so the honest retry was rejected as a replay. `authz_12` stayed green, correctly: the cache read is further down still. `authz_17b` also went red, because the check then sits below tool-name validation and is never consulted |
| check moved below the cache read | `authz_12` → **red**: the refused caller was served the cached payload |
| certificate and agent identities dropped at the authorizer | the ALLOW halves of `authz_10` and `authz_11` → **red**; both denial halves stayed green |

Four results corrected the plan rather than the code:

- **One probe is not enough for ordering.** Moving the check below the nonce
  store left `authz_12` green, and only moving it below the cache read turned it
  red. A single generic "wrong order" probe would have certified one of the two
  falsely.
- **The fail-closed trap is real, and was demonstrated.** Dropping both
  identities turned only the ALLOW halves red — `evaluate(None)` denies, and
  agent auth with no identity denies, so each refusal row alone would have
  passed with the identity never arriving. The allow half is the entire proof.
- **`authz_17b` is not a pure control.** The plan filed it as passing against
  unfixed code. It asserts both a retry count (pre-existing) and that an
  ordinary failure lands in `step_errors` (not), so it is falsifiable two ways.
- **A permissive double cannot compile into a release build.** Substituting
  `AllowAll` into the stdio construction site failed to build, because it is
  `#[cfg(test)]`. That is the withdrawn AUTHZ.9 proven by the type system.

One finding about the system, not about this change: **a missing backend does
not produce an error.** It returns a success envelope carrying `isError: true`,
so the engine records the step as COMPLETED and the retry path never engages.
Two draft tests were built on the opposite assumption and could not have failed.
A related one: an invalid tool name IS a refusal here — `authorize_tool_target`
validates the name first — so it answers 403, which looks like a mapping bug and
is not.

## Criteria verified by reading, not by test

Stated rather than hidden behind a green row.

**AUTHZ.14a, 14b and 23 — the refusal audit line.** Both gates call the shared
`audit_refusal` helper: the router pre-check at `handlers.rs` before it returns
its error response, and the chokepoint at `invoke.rs` before it returns
`Error::Forbidden`. Neither is covered by a test.

The reason is the cost of the instrument, not the value of the rows. This
repository has no log-capture harness — no `MakeWriter` into a shared buffer, no
scoped subscriber helper, nothing under `src/` that asserts on emitted spans.
Building one means installing a subscriber that the test process shares across
parallel tests, which is a well-known source of flakes, and a flaky test that
guards observability is a worse trade than a stated gap: it costs every future
run and it teaches people to re-run until green.

What that leaves unproven, precisely: that the lines fire, that they carry the
right transport, and that a router-covered refusal emits exactly one. The
control is code review over two call sites of a single helper, which is a
smaller surface than the harness would be.

**Revisit when** a log-capture helper exists for any other reason. At that point
these three rows are cheap and should be written.
