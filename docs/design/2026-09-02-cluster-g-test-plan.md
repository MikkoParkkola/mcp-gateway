# Cluster G — test plan (§P2)

Written before any test code and before any implementation. Reviewed as a plan, then the
tests get their own review as tests.

## Scope

Covers `NFR.OBS.1` and `NFR.OBS.2` only. `MIK-7246.CONFIRM.1a` is **not** planned here: its
behaviour on stdio is deferred to the operator (see the design note), and a test plan for a
branch whose required behaviour is undecided would be a plan for whichever behaviour I
happened to assume. It is added when the question is answered, not before.

## One row per criterion

| # | criterion | case | level | type | falsifiable how |
|---|---|---|---|---|---|
| 1 | `OBS.1` | a `tools/call` over stdio emits exactly one observed record carrying `method`, `protocol_revision`, `revision_source` | integration | positive | free — stdio emits nothing today |
| 2 | `OBS.1` | a **non-`tools/call`** method over stdio (`initialize`, then `ping`) emits a record each | integration | positive | free — and this is the case that would have caught the round-1 design error |
| 3 | `OBS.1` | a request declaring itself modern while omitting a required field emits a record **and then** returns `-32602` | integration | negative-path | free — and it pins the ordering, not just the presence |
| 4 | `OBS.1` | the same three shapes over HTTP still emit exactly one record each | integration | regression | **not free** — see the honesty section |
| 5 | `OBS.1` | an internal caller reaching the meta-MCP layer inside one inbound message (playbook step, code-mode step) does not add a second record for that message | unit | exactly-once | free — depends on a boundary that does not exist yet |
| 6 | `OBS.2` | a `tools/list` over stdio emits the `tools/list` record | integration | positive | free — stdio emits nothing today |
| 7 | `OBS.2` | a `tools/list` over HTTP still emits exactly one, not two, after the change | integration | regression | **not free** — see the honesty section |

Row 5 exists because both reviewers raised it independently in round 1: the design's "both
callers" tables enumerate the *transports*, and the tool-policy precedent the design leans
on records playbook and code-mode steps reaching this same layer. Those are callers too.
Whether they should produce a record is a real question — they are not inbound requests —
and the plan answers it as *no*, one record per inbound message, which is the only reading
under which "per request" counts the same thing on both transports.

## Can each case actually fail? (§P2 question 2)

Rows 1, 2, 3, 5 and 6 fail for free: they assert a record that no code emits today, so
writing them first produces a real red.

**Rows 4 and 7 are the honest problem.** They pass today, and they will still pass if the
change is written correctly — but they would also pass if the extraction were never done at
all. A test that cannot distinguish those two states is not a regression guard, it is
decoration. They need the falsifier probe from the process, run once when the tests are
written, against a deliberately wrong implementation:

- place the record inside `MetaMcp::handle_tools_call` instead of the transport entry — the
  exact error round 1 caught. Rows 2, 3 and 4 must go red. If row 4 stays green, it is not
  measuring what it claims and is rewritten before it is trusted.
- emit the record in both the extracted function and the old HTTP site — rows 4 and 7 must
  go red on the count. If they only assert "at least one record", they will not, and
  "exactly one" is the whole content of those two rows.

Both probes restore the correct implementation and re-run, so the restore is verified by a
green run rather than by `git status`.

## Fixtures — the trap this plan is trying to avoid

The tests drive the **real** stdio loop and the **real** HTTP handler. A fixture that stands
in for either one would be asserting against a reimplementation of the code under test, and
the record's whole value is that it fires on the path a user's request actually takes. In
particular the malformed case (row 3) must be a genuine malformed request through the real
shape classifier, not a hand-constructed `RequestShape::Malformed` — the ordering being
pinned is *classifier, then record, then return*, and a hand-built shape skips the first two.

## What this plan does not cover, stated

- The stdio confirmation branch (`CONFIRM.1a`) — deferred, above.
- Whether `protocol_revision` is *available* to report on stdio. That is the design's open
  question 1, still scheduled: the stdio path is documented as having no access to the
  running config. If the field turns out to be unavailable there, rows 1–3 assert its
  absence rather than a fabricated value, and the plan is amended to say so before the tests
  are written, not after they are seen to fail.
