# §P4 COMBINED VERDICT — MIK-7272 TASK.1 (all three legs returned)

## Verdicts — authority stated, not scraped

| leg | vendor | verdict | authority |
|---|---|---|---|
| 1 | grok-review | **SHIP** | rc=0 + wrapper trailer `grok-review: verdict SHIP` + run file `~/.claude/data/reviews/runs/grok-20260907T040205Z-5615.md` |
| 2 | synthetic-review | **SHIP-WITH-FIXES** | rc=0 + wrapper trailer `synthetic-review: verdict SHIP-WITH-FIXES` + run file `~/.claude/data/reviews/runs/synthetic-20260907T040210Z-6148.md` |

NOT a ledger row. `~/.claude/data/reviews/paired-ledger.jsonl` (600 B) holds only
`airlok-mac` rows and has nothing for either run. §PA authority here = process exit
status + the wrapper's own emitted trailer + the run file. Process-emitted, not body-scraped.

Barred / excluded:
- `claude-review` (1802 B) — Claude reviewing Claude. Barred leg, unread, does not count.
- `gpt-review` (41,605 B) — body with no valid verdict. `MISSING` under §PA. 41K of prose is
  not a third leg.

Third leg (FUNCTIONAL, per DoD FUNCTIONAL PASS) HAS run — four of four criteria PASS,
recorded in full below. All three legs have returned.

## THE BLOCKER

**F1 (synthetic) blocks ratification.** The `.10` initialize narrowing — the gateway
deliberately does NOT advertise the tasks extension from `initialize`, only from
`server/discover` — is a NARROWING OF AN ACCEPTANCE CRITERION. The repair protocol is
explicit: dropping or narrowing an AC needs the **requester's recorded agreement, before it
happens**. The code itself says "provisional pending the operator". The team lead is not
the operator.

State: this change cannot be ratified until either the operator ratifies the `.10`
narrowing, or the initialize half gets built. Everything below is secondary.

**Grok's LOW finding is the same decision seen from the other side.** Its finding —
`docs/design/2026-09-06-task-1-tasks-extension-test-plan.md:127` still records `.10b` as
"served `initialize` **and** `server/discover`... **Yes — red today**", and line 143 still
counts it in the red tally — is VERIFIED AT SOURCE and contradicts the tests as they now
stand (`ac_task_1_10_initialize_does_not_advertise_the_tasks_extension`,
`tests/mik_7272_task_1_acs.rs:244`). Two independent legs converged on the `.10` story.
The doc repair is DOWNSTREAM of the operator's ratification: ratify → rewrite `.10b` as
discovery-only; refuse → `.10b` stands and the initialize half must be built. One operator
line settles both findings.

## F2 (synthetic) — dies as a live defect, survives as drift risk

Claim: a `tasks/*` method could reach the task store without passing the unattributed-caller
guard.

What I checked: `rg -on '"tasks/[a-zA-Z]+"'` across `src` returns only `tasks/get`,
`tasks/update`, `tasks/cancel` — a 3-way match between the guard predicate, the dispatcher
(`src/gateway/router/handlers.rs:1505,1514`) and the protocol list.

What that proves: **no missing `tasks/*` method**. What it does NOT prove: that no other
path reaches the task store. The guard's other arm is `tools/call` carrying a `task`
parameter, and a literal search for `"tasks/…"` cannot see a sibling path shaped like that.

Disposition: no repair, no round spent. Residual = there is no MECHANICAL tie between the
guard predicate and the dispatcher; the next added method is a silent bypass. Recorded as
an observation (§P0 disposal 3), not a ticket.

## F3 (synthetic) — the advertise-ahead ruling

Already the lead's recorded ruling; MIK-7311 mitigates. No repair.

## FIVE OF SEVEN — the payload gap, named exactly

The payload froze at 07:01 and carried **five** commits: `52e6c756`, `2c522f53`,
`6d21869c`, `d5861bf2`, `dd29a63d`. The change now has **seven**. Neither leg saw:

| commit | time | bears on a finding? |
|---|---|---|
| `496661fb` docs: what the guard does NOT close in `.11`/`.12` | 07:02 | **No.** Annotates `.11`/`.12`, not `.10`. Adjacent to F2's territory, changes none of its premises. |
| `67ebc57a` test: show the `.20` row can fail | 07:05 | **No.** Records the falsifier probe; a doc annotation on a test grok DID see (`dd29a63d`). |

Both are records, not behaviour. No finding was judged against a moved story. The
confirmation pass still goes back to each finding's own vendor.

Also not in the payload's AC list: `.20` itself (six ACs transmitted: `.10a`, `.10b`,
`.11a`, `.12`, `.18`, `.19`). Grok reviewed the `.20` test from the diff without its
criterion text — which is why its three improvements land on `.20`'s assertion strength.

## Improvements — disposition, one line each

Grok (all SMALL, all real):

| # | what | disposition |
|---|---|---|
| 1 | `.20` asserted only that the message is not "no such task" — a §P2 Q2 defect, a case that passes while broken | **APPLIED** `98c0a975`. Asserts positively now (no `error`, a `result`). It still cannot assert a task HANDLE: `tools/call` writes no `result/taskId` until the store lands (`.8a`), and a case pinned to a field nothing writes can never go green — recorded in the test's own comment. |
| 2 | `.20` varied more than `auth.enabled` — the disabled arm came from `AuthConfig::default()`, which also drops both API keys and the public `/mcp` listing | **APPLIED** `98c0a975`. Both arms come from `public_mcp_auth()` and differ in `enabled` alone. |
| 3 | rename `implemented_extensions()` — it returns empty while the gateway does implement tasks | **HELD** on the operator's `.10` ruling. Ratify the narrowing and the rename is right; refuse it and the function gets a body instead of a name. |

Synthetic:

| # | what | disposition |
|---|---|---|
| 1 | round-trip test: `to_extensions()` fed back through `from_capabilities()` | **APPLIED** `2bdba41e`. The doc comment's round-trip claim is an assertion now, with a non-empty guard so it cannot pass vacuously. |
| 2 | pin the guard's live-ness premise against "the shipped local/compose/published-probe presets" | **DIED AT SOURCE.** No such presets exist: those are three cases inside one `support.rs` test function, the published-probe case lists `/health` only, and the compose case is the configuration `network_bind_refusal` REFUSES to start. No shipped configuration lists `/mcp` public anywhere (`gateway.example.yaml`, the helm configmap, the k8s configmap — `/health` only), and `support.rs` has no preset builder. The premise came from a FALSE COMMENT in the fixture, which claimed `support.rs` "writes exactly this" for those presets. Value discharged by repairing the citation (`53dea5fa`): the fixture now cites what actually admits it — the loopback-with-no-`public_url` early return at `support.rs:554`, and the local-install assertion at `support.rs:979-986`. No new test was added: `support.rs:982` already asserts exactly that, and a second copy in the ACs file is the duplication §P3a exists to catch. A claim that dies at source closes the finding; no round spent. |
| 3 | align `implemented_extensions()` once the operator disposes of `.10a` | **HELD** — same operator line as grok 3, and the improvement says so itself. |

Confirmation passes go back to each finding's own vendor: grok for 1-2, synthetic for 1
and the 2 disposal.

## Third leg — FUNCTIONAL, driven, four of four PASS

Driver: an isolated agent, handed the criteria and how to launch, nothing else (no diff,
no design). Not the author. One round, per the DoD functional-pass rule.

Revision driven: binary built 07:35:35 from a tree carrying `2c522f53` (the guard) and
`d5861bf2` (the counter). Worktree HEAD moved `58313791` → `d6a2d88e` under the driver
while it worked — this is a SHARED checkout and another session was committing. The
driver checked what moved: docs, `meta_mcp/invoke.rs`, `prompt_cache.rs`,
`transport/http/mod.rs`, `protocol/trace.rs` — none of the three files these criteria
depend on (`gateway/router/handlers.rs`, `protocol/task_store.rs`,
`protocol/subscriptions.rs`). Valid basis; recorded because it is not a clean checkout.

Mechanism: two live `target/debug/mcp-gateway serve` instances driven over HTTP as a
client drives them — auth on, two API-key principals, port 39777; auth off, port 39779.
Both killed and their configs and logs removed afterwards.

| criterion | verdict | what was driven, and what came back |
|---|---|---|
| `.11a` | **PASS** | principal-b asks for a task owned by principal-a, and for an id that never existed. Both: `{"error":{"code":-32602,"message":"no such task"}}`, byte-identical under `cmp`. No "not yours" leak. |
| `.18` | **PASS** | no credential at all: dispatch (`tools/call` with `task:{}`), `tasks/get` on someone else's real id, `tasks/get` on a never-existed id — same id-free refusal for all three. Dispatch is refused before a record is created (`handlers.rs:994-1010`), so "invisible to the next unattributed caller" holds because there is nothing to be visible. |
| `.19` | **PASS** | unattributed `subscriptions/listen` naming a real-but-not-mine id, a never-existed id, and no id at all: one identical ack in every case, and the ack never echoes `taskIds`. Narrowed in silence, not refused — the `.18` contrast. |
| `.20` | **PASS** | auth off: the credential-less caller is admitted with a REAL handle (`taskId: task-73bf958c-…`), and that id then answers `tasks/get` with the full view while a never-existed id on the same server returns `no such task`. This is the assertion the unit test cannot yet make — `.8a` has not landed — made against the running gateway instead. |

Two observations from the driver, neither a defect:

- `.11a` and `.18` share one refusal path (`missing_task_error`, `handlers.rs:243`). One
  fix covers both criteria; they are not independent surfaces.
- `.19` is structural, not a special case: the ack schema has no `taskIds` field, so there
  is nothing to withhold.

Named as not drivable: notification DELIVERY over a `.19` stream once a subscribed task
changes state — it needs a slow task and a long-lived reader. The ack layer was driven;
the delivery layer was not, and this line is the record of that rather than a silent gap.

## Test state

`cargo test --quiet --test mik_7272_task_1_acs` → **19 passed; 0 failed**.
Falsifier probe (trap-protected, §P2): removing `&& state.auth_config.enabled` turns
`.20` red on its admission assertion and nothing else (18/1); restored → 19/0, verified by
re-running, not by `git status`.
Repo-wide clippy reds are PEER-uncommitted (`build_outbound_meta` never used; executor_tests
arity) — not this change's, reported not chased, per RED-SIGNAL TRIAGE.

## What each leg could actually READ — verified at source

`~/.claude/bin/synthetic-review` posts the prompt to a bare
`chat/completions` endpoint (`BASE=https://api.synthetic.new/openai/v1`, line 106;
`urllib.request.urlopen` at line 214). No tool loop, no filesystem. Its own preamble
tells the reviewer "you may still read it read-only by absolute path" — for THIS
transport that sentence is false. Synthetic saw the payload and nothing else.

Grok cited `file:line` for all four of its findings, so that leg did read the tree.

Consequence for `.20`, stated precisely: the payload transmitted six criteria
(`.10a`, `.10b`, `.11a`, `.12`, `.18`, `.19`) and `.20` was not among them. The leg that
could have looked `.20` up anyway is the one that raised all three `.20` improvements.
The other leg could not have looked it up at all. So `.20` received **no canonical
criterion check from either leg** — grok read the test as code, synthetic could not read
anything. That is stronger than "six ACs were transmitted", and it is why the `.20`
improvements are being applied rather than deferred with the rest of the batch.
