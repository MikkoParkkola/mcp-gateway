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

### R3a — amendment, same day: wire it to the identity, not to the session

R3 said wire it and named the mechanism as a maintenance-tick reaper fired off session
lifecycle. The second half is wrong on the 2026 path, and the lane must not build it as
written. Read at source before designing:

- `src/security/firewall/anomaly.rs:187` `remove_session` and
  `src/security/firewall/mod.rs:682` `on_session_end` have exactly one caller between them,
  a test at `mod.rs:1062`. Nothing in production reclaims `last_tool`. The subject of
  `CONTROL.4` is real, so the row is not `N/A` — that disposition was considered and fails.
- The only bound today is `MAX_TRACKED_IDENTITIES` with arbitrary eviction
  (`anomaly.rs:129`). A ceiling reached by evicting a stranger's predecessor is not
  reclamation: the evicted caller's next call scores as a first call, which is the sequence
  the detector exists to notice.
- The 2026 path mints no session. `router/handlers.rs:1633`: "the connection carries no
  state. There is no `Mcp-Session-Id`, because the revision deleted protocol sessions." The
  comment at `anomaly.rs:129` says the same from the other end — "a stateless caller never
  disconnects because it never connected."

So a reaper hung off session disconnect reclaims nothing for exactly the traffic 4.0 is
about, and `CONTROL.4` would read MET over an empty map. The key must be whatever
`last_tool` is keyed by — the caller identity — tracked where that entry is written, not
where a session is opened.

`src/gateway/streaming.rs:122` already runs a TTL reaper on a live maintenance loop, with
tests at `:647`-`:737`. Hang the identity reap on that loop; do not build a second one.

Precondition on the design, before any code: name the write site that will call `track`,
and show the registered callback reaching `Firewall::on_session_end`. A reaper whose
`tracked` map no production path populates passes its own tests and closes a blocking row
falsely, which is the fourth unreachable mechanism this plan exists to avoid.

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

## R7 — `sub4-idempotency`: the replay is live; the lane that activated it repairs it

`SUB.4`'s route-1 wiring made a dormant defect reachable, and the design went on calling
it dormant. Verified at source rather than taken on report: `identity_suffix` is
`|idp:{binding}` **or the empty string** (`src/gateway/meta_mcp/invoke.rs:1198-1202`),
`idempotency_key_for` concatenates it verbatim (`src/gateway/meta_mcp/support.rs:43`), and
the comment at `:1203-1209` fixes exactly this bug class for `caller_principal` while
leaving the retry key on the old derivation. Two callers under the same client-chosen key,
same tool, same arguments, share one entry on the shipped default.

0BUG stop-the-line. The repair stays in the lane that performed the activation: it is one
derivation inside the funnel that lane already occupies. Fall back to the verified subject;
keep `identity_suffix` and `caller_principal` separate values, because the comment is right
that they are different contracts with different lifetimes. Auth off with no verified
identity still pools — that is the operator's own decision, already computed as
`unattributed` at `src/gateway/router/handlers.rs:1013`, and `control4-lifecycle` reached
the same conclusion independently the same morning. Do not mint a third rule about empty
keys. The two-caller test goes red first (repair protocol step 4).

**MIK-7408 is re-scoped to this repair.** Its question — whether P8 blocks on the suffix fix
or lands with it tracked behind — assumed the repair could be ordered against a future
activation. The activation already happened, so the question is void, not answered.

### R7a — the R2 supersession clause is withdrawn

R2 told the lane to mark the unreviewed revision superseded. The lane checked and the two
documents R2 names are one file — reviewed at revision 2, unreviewed at revision 5. The
instruction would have put a supersession header on the document R2 had just made
governing, naming itself. Withdrawn. The fold the lane was already running is the stronger
fix and is what R2 should have said: one document survives and the other is deleted, rather
than two surviving with a pointer between them.

## R8 — `bridge-mrtr7`: `WIRE.5` takes per-round gating; the criterion is not narrowed

Two exits: (A) move the design to gate inside the retry loop, or (B) narrow `WIRE.5` to
accounting alone. (A). The elimination test decides it — after (B) the finding is still
statable, because an exchange that overspends an operator's limit stays describable and
merely untested; after (A) it cannot be stated at all. Eliminating a mechanism is the lane's
to do. Eliminating a criterion needs recorded agreement, and it is refused.

Accepted costs, recorded so they are not later read as drift: this is a §P3 design event
moving what a criterion asserts, so §P0 and §P2 reopen on their own terms before §P4
resumes, and the round count does not reset — the spec moves, the history does not. **The
four-dispatch ceiling clause R1 asked for on `WIRE.13` is withdrawn by its author**; it was
derived from the fixture (A) deletes.

### R8a — `BRIDGE.4`: the lane's error shape beats the one this document specified

An earlier ruling named `BridgeError::Unanswered`. The lane read the site and found the
outer `Delivery` variant already covers a timeout by its own doc text, so the missing thing
is the inner reason: `DeliveryError::Unanswered { key }`, returned where the bare `continue`
sits at `src/gateway/input_bridge.rs:484-486`. Take the lane's. What survives from the
ruling is the cancellation-safe hold on the pending entry — the `PendingSampleGuard`
construction at `src/gateway/proxy.rs:98-103` — and that
`tests/mik_7212_mrtr7_bridge_acs.rs:1117` inverts rather than gets annotated.

## R9 — `control4-lifecycle`: the reaper takes its collaborator as a parameter

`spawn_reaper_on(&self, lifecycle: Arc<SessionLifecycle>)`, not a field. A field lets a
caller silently get a reaper-less loop with no compiler complaint; a parameter forces all
three call sites to state what they reap. Not an `Option` — an empty lifecycle already reaps
nothing, so the `Option` would only add a second spelling of the same emptiness.

The lane's open question — does `CONTROL.4` close with zero handlers registered — was
answered by its own v2 before it reached this document: R3a option (b) moved
`Firewall::on_session_end` from OUT to FOR, so one real consumer is registered and the
criterion no longer closes over an empty map. Recorded rather than ruled, because ruling on
a superseded question is how a stale answer gets authority.

Endorsed without change: D5's bar that a handler may only reclaim state whose loss is
indistinguishable from an eviction, and its rejection of a per-key generation counter as a
second mechanism deciding when a key is live.

## R10 — `confirm-gate`: leave the contaminated commit; `CONFIRM.1a` says which PARTIAL it is

`868a940d` swept a sibling lane's uncommitted `SCHEMA.1c` regrade in under this lane's
message. Leave it. Every lane is committing against that base, and rewriting a shared base
to repair an attribution line trades a cosmetic wrong for a real one. The owning lane posts
its own evidence comment citing that SHA.

**Branch rule, all lanes**: `git commit -o <path>` commits the path's whole working-tree
content, so on a shared tree it will commit a peer's uncommitted edits to the same file.
Stage the hunk, verify with `git diff --cached --stat`, then commit.

`CONFIRM.1a` stays PARTIAL and the cell must state which kind. The requirement is met by
construction — all three producers return one variant and reach one arm at
`src/gateway/meta_mcp/mod.rs:1964-1967`. What is open is coverage: two tests nobody has
written, each costing 120 seconds against a module-private `ELICITATION_TIMEOUT`
(`src/gateway/destructive_confirmation.rs:53`). Name the constant as the obstacle. A release
owner reading "coverage residual, closing action is two slow tests" decides differently from
one reading a bare PARTIAL, and the difference is a shipped release. Not MET: a refusal path
never executed against the timeout arm carries no evidence of its own, and this release has
already produced rows reading MET over machinery nothing reached.

## R11 — `envelope-meta`: no third review round

The two repair commits apply findings both legs raised and the lane accepted at source. That
is §12's confirmation pass, not a new review. Re-reading repairs the reviewers themselves
specified spends a round without converging. Record the disclosure on the rows — both
verdicts are against `d1dd5056`, the repairs are unreviewed — because a stated limit a
reader can check beats a round nobody learns from. The three rows stay PARTIAL: the SSE GET
stream is a real remaining gap, verified at source this turn.

## A wrapper name is not a vendor

`kimi-review` is a one-line wrapper that execs `synthetic-review --model kimi-k3`, so a
valid kimi leg logs and records its verdict under a `synthetic-review:` prefix. Two lanes
have now read that prefix as a foreign or disqualified vendor, and one was about to discard
a passing dual-vendor review over it. It is the wrapper's own name.

## R12 — `control4`: reaper wiring may edit `src/gateway/streaming.rs` (U3 granted)

`control4-lifecycle` asked whether wiring the session reaper could touch
`src/gateway/streaming.rs`, a file outside the lane's declared surface. Granted, bounded three
ways: shape (a) from its own design, reaper wiring only, and nothing else in that file. The
grant is recorded here rather than left in the lane's mailbox because the next lane to touch
streaming needs to know a peer holds an authorised edit there, and a mailbox reaches one agent.

Bound is the surface, not the lane: an edit to `streaming.rs` for any other purpose is a §P0
scope move and needs its own ruling.

## R13 — MIK-7414's `$ref` criteria were mis-stated by the team lead, and are amended

`ext1-otel1` pushed back that two acceptance criteria I wrote onto MIK-7414 described a
mechanism its design does not build: they said the walk *rejects* what exceeds the bound, and
that composition (`allOf`/`anyOf`/`oneOf`/`not`/`if`) is bounded alongside `$ref`. Verified at
source against R6 and the lane's design: the mechanism stamps an advisory verdict on the trust
card and refuses nothing, and composition is legal 2020-12 that is deliberately observed, never
constrained. Both were transcription errors in the ticket, not gaps in the work.

Amended in Linear this turn, with the reason recorded on the issue. Correcting a criterion that
mis-states the design it describes is not a scope cut and needs no separate agreement — the
repair protocol's bar (a requirement may not be dropped without the requester's recorded
agreement) guards against silently removing work, and this removes none. Ordering rejection, or
bounding composition, would be new design stacked on R6 and is explicitly not ordered.

The general form, for every lane: a criterion is a claim about the design, and a lane that
reads one as wrong should say so rather than build to it. This one was caught because the lane
argued back.
