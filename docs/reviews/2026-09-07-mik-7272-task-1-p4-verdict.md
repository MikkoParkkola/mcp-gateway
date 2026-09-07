# §P4 COMBINED VERDICT — MIK-7272 TASK.1 (both code legs returned)

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

Third leg (FUNCTIONAL, per DoD FUNCTIONAL PASS) has NOT run. Change is not done.

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

## Improvements — batched, not yet applied

Grok (all SMALL, all real):
1. `.20` asserts only that the message is not "no such task" — a different refusal
   (method-not-found, capability miss, tool error) satisfies the admission half.
   `tests/mik_7272_task_1_acs.rs:1072`. This is a §P2 Q2 defect: a case that passes while
   broken.
2. `.20` varies more than `auth.enabled` — `state_public_mcp()` also changes `public_paths`
   and `api_keys`. A guard keyed on key-count would keep passing the pair. `:1061`.
3. `implemented_extensions()` now returns empty while the gateway DOES implement tasks —
   rename to a handshake-specific name so the next editor does not "complete" it.
   `src/gateway/meta_mcp_helpers.rs:145`.

Synthetic: three SMALL (round-trip test, preset pinning) — same batch.

None applied. One repair round after the operator's line, one commit per finding,
confirmation pass back to the finding's own vendor.

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
