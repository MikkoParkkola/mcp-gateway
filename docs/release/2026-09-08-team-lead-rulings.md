# Team-lead rulings — 2026-09-08

Six lanes asked for rulings on the same day. Each is recorded here because a ruling
delivered only to a mailbox reaches one agent; the lanes that inherit the consequence
read the repository. Each ruling names what was verified, at source, before it was made.

## R1 — `bridge-mrtr7`: the sampling-guard objection falls; `WIRE.5` stands

The lane proposed dropping `WIRE.5`'s second fixture on the grounds that a mid-exchange
refusal could strand a pending sample. Verified at source and it cannot: `PendingSampleGuard`
is an RAII guard bound to `send_request`'s own scope (`src/gateway/proxy.rs:98-103,532-533`),
held across the await and dropped when the call unwinds, however the caller then behaves. A
refusal arriving after `send_request` returns has nothing left to strand. The same construction
appears at `:219`, `:286` and `:417`, so the property is the module's, not one call site's.

The fixture stays. **Add the clause** the lane asked about: the `WIRE.13` row carries a
dispatch ceiling of four where the budget names three prompts, because `run` is entered with
one dispatch already made (`first: &InputRequired`). One sentence on the row, so the next
reader does not re-derive it as an off-by-one.

## R2 — `sub4-idempotency`: the config gate goes; enabled unconditionally

Overruled in the lane's favour, which is where the earlier ruling was already heading.
A guarantee holding only while nobody opts out has the same defect as one holding only
when someone opts in. This is already recorded on the `SUB.4` row
(`docs/requirements/RELEASE-4.0.0-criteria-status.md:227`) and supersedes the config-gate
half of 2026-09-07. The TTL survives as a module constant carried as a stated assumption.

Which design governs: the reviewed **2026-08-31** wiring design. The unreviewed 430-line
revision says on its own face that it rides the next design review "before SUB.4 writes
code" — code is written, so it is not the document that gated it. Mark it superseded rather
than leaving two documents disagreeing (H3): an agent that loads the wrong one follows it.

## R3 — `control4-lifecycle`: wire it, do not delete it

Two decisions appeared to collide. The 2026-08-29 backlog triage narrowed **MIK-7291** to
"rides along as a deletion only", calling `SessionLifecycle` dead code on the 2026 path. The
`CONTROL.4` row is blocking and asks that TTL-reaping own the cleanup disconnect used to do.

They do not actually collide. "Dead code" describes the code's state today — nothing calls
`register`/`track`/`reap` — and says nothing about whether the requirement is dead. The
requirement is live precisely because the 2026 transport removed the disconnect event that
used to trigger the cleanup; state that was reclaimed on disconnect is now reclaimed by
nothing. Deleting the mechanism leaves a blocking criterion unmet and removes the evidence
that anyone noticed.

MIK-7291's narrowing binds the *ticket*, not the *criterion*. The deletion clause is
withdrawn; MIK-7291 closes when `CONTROL.4` wires it. The 2026-09-07 ruling stands: proceed
under the stated assumption — maintenance-tick reaper, TTL as a defensible default recorded
as an assumption, not as an operator decision. Update the triage document to say so, or the
next reader finds the same contradiction and rules on it again.

## R4 — `confirm-gate`: `CONFIRM.2` stays with the bridge lane, and the seam note is written anyway

The row is reachable-through-the-MRTR-path, and that path is the bridge lane's file. Moving
it would split one wiring change across two owners. The gate-side seam note the lane offered
costs no code and lands where the bridge lane will need it — write it, hand it over, do not
implement against it. The revised `CONFIRM.1a` close is approved. The citation drift found in
`1b`, `2` and `3` is repaired by the lane that found it: same file, docs-only, cheaper than a
handoff.

## R5 — `envelope-meta`: phase 2 go; work around the dirty files, do not adopt them

Phase 2 is row rewrites recording what `044896aa` and `44b978ea` closed, plus the residual
that stays unpinned. The uncommitted files in the tree are this side's own work from earlier
in the week — Codex's coordination note disclaims the production surface and attributes the
schema diff here. That does not make them this lane's to land. **Commit only your own paths**
(`git commit -o <paths>`), revert nothing, and leave the `HEADER.4a` case where it sits: a
shared index commits what you did not stage.

## R6 — `ext1-otel1`: close `SCHEMA.1c` without a new runtime dependency

Do not promote `jsonschema` from dev-dependency to runtime to obtain meta-validity checking.
The row's value is the `$ref`/composition bound, which the walk delivers; meta-validity is a
different property being bought at the price of a runtime dependency on the trust path
(D30). Close it with the walk and state the limit in the row. The red tests are this lane's
own, on its own row. Record the `U9` observation in the same commit.

## What these six have in common

Four of the six were answerable from source in under ten minutes and had been waiting on a
person. Two — `R3` and `R2` — were genuine collisions between two documents that each read as
authoritative, and both existed because a decision was recorded in one place and its
consequence in another. That is the recurring cost here, and it is why each ruling above says
which document to amend, not only what the answer is.
