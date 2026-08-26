# Test plan — authorize at dispatch (MIK-7252)

Companion to `authorize-at-dispatch.md`, which froze after six rounds with a
unanimous SHIP. Every acceptance criterion in that design has a row here; a
criterion without one is the finding, and `MIK.AUTHZ.9` is absent because it was
withdrawn rather than skipped.

The right-hand column is the one that matters. A test that runs, asserts, and
could not have failed is worse than no test: it reports coverage it does not
have. Each row therefore states what makes it capable of failing, and the
weaknesses section names the rows where that claim is thinnest.

One row per acceptance criterion; an empty evidence cell is the finding.
L: U=unit, I=integration (router->meta->backend), S=stdio, E=engine.
Every negative row needs a falsifier probe against pre-fix content per
development-process.md §P2: save the file, restore under a trap, and confirm
the failure is the intended assertion rather than a compile error.

## Refusal cases — each must fail a fix that wires only one check

| AC | case | L | can it fail for the right reason? |
|---|---|---|---|
| 1 | client `backends:["alpha"]`, step targets `beta` -> refused, message names `beta` | I | yes — succeeds today |
| 2 | client `allowed_tools:["safe_*"]`, step calls `danger_tool` on an ALLOWED backend | I | yes — backend scope passes, so a .1-only fix fails here |
| 3 | global tool policy denies `alpha:blocked` | I | yes — policy is on AppState, fails an identity-only fix |
| 10 | mTLS policy denies the cert for `alpha:tool` | I | yes — distinct policy object |
| 11 | agent auth on, step outside agent scope | I | yes — fails a fix that drops `oauth_agent_identity` |

## Denial semantics — fixtures MUST set on_error, or an Abort default passes by luck

| AC | case | L | can it fail for the right reason? |
|---|---|---|---|
| 17 | `on_error: retry`, `max_retries: 3`, denied step -> authorizer consulted ONCE, backend zero times, `step_errors` has the reason, later steps still run | E | yes — a denial routed as an ordinary Err is retried 3x; a reasonless partial fails the third assertion |
| 18 | `on_error: continue`, denied step then an ALLOWED step -> run completes, allowed step ran, name in `steps_failed`, reason in `step_errors` | E | yes — fails terminal-refusal AND silent-null; the two fields separate them |
| 18b | `on_error: continue`, an ordinary BACKEND failure -> its message also lands in `step_errors` | E | yes — fails a fix that records refusals only, leaving ordinary failures unexplained |
| 19 | `on_error: abort`, denied step -> run returns the refusal, no later step runs | E | yes — weakest of the three, but it pins the unchanged path |

## Behaviour that must not change (the UX guard)

| AC | case | L | can it fail for the right reason? |
|---|---|---|---|
| 4 | admin, unrestricted, same playbook as .1 -> succeeds | I | yes — fails a hard-coded non-admin or deny-default |
| 5 | client with empty `backends`, no allow/deny lists -> succeeds | I | yes — fails a deny-by-default fix |
| 6 | step `condition` false AND unauthorized target -> COUNTING authorizer shows zero consultations for that step | E | yes — a counting assertion cannot be satisfied by "no error" |
| 8 | direct `gateway_invoke` + code-mode chain keep exact refusal messages | I | yes — message equality fails a reroute |

## Ordering and coverage

| AC | case | L | can it fail for the right reason? |
|---|---|---|---|
| 7 | refused step -> counting mock backend saw 0 calls, no cache entry, no budget spend | I | yes — a post-dispatch check passes .1 and fails this |
| 12 | prime the response cache as an allowed client, then a restricted client's step targets it -> refused, cached value NOT served | I | yes — the leak a post-cache check ships. Cache must be genuinely primed, not mocked |
| 20 | refused call registers no idempotency in-flight, mints no per-user credential, and consumes no nonce — live NonceStore, top-level `nonce` on the envelope, same nonce still registrable after | I | yes — a nonce in a step's arguments is never read there and would pass vacuously |
| 13 | DENYING authorizer against all five meta shapes: surfaced, `gateway_invoke`, code-mode single, code-mode chain step, playbook step | U | yes — a playbook-only fix fails four rows. Highest-value row |
| 14 | refusal emits an audit line; assert the VALUES — transport is Http via the router constructor, Stdio via the stdio one | I | yes — a fix that hard-codes one transport fails half the row. Ownership proved with an authorizer that logs nothing |
| 23 | denied `gateway_invoke` over the FULL router path -> exactly ONE refusal line | I | yes — the router returns before the chokepoint, so a meta-level fixture proves nothing here; two lines fails it |
| 21 | direct `/mcp/{name}` route keeps its existing refusal behaviour | I | yes — fails if the outer check is deleted as redundant |

## Transport

| AC | case | L | can it fail for the right reason? |
|---|---|---|---|
| 15 | stdio playbook step hits a policy-denied tool -> refused | S | yes — no coverage today, fails against pre-fix source |
| 16 | stdio keeps admin standing; its `gateway_invoke` refusal unchanged after the inline block is deleted | S | yes — guards the deletion |
| 22 | mTLS rules configured -> stdio calls NOT refused | S | yes — fails an implementation that hands stdio the mTLS policy, which would deny everything |

## Weaknesses stated up front

- **AC 13 is the highest-value row and the easiest to fake.** If the denying
  authorizer is injected anywhere other than the production caller-context
  path, it proves the mock works, not that the chokepoint is reached.
- **AC 18 carries the whole denial-semantics repair.** Its assertion must be on
  the recorded reason, not on `steps_failed` membership alone — a silent null
  also lands in `steps_failed`.
- **AC 14 must prove ownership, not presence.** Use an authorizer that emits
  nothing; if the line still appears, the chokepoint owns it.
- **AC 12 needs a genuinely primed cache.** A fixture faking a hit proves
  nothing about ordering.
- **No fixture may reimplement a production authorizer.** Only `AllowAll`,
  `DenyAll` and a counting wrapper are legitimate doubles, and none of them
  contains policy logic.
