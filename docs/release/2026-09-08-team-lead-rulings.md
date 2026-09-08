# Team-lead rulings — 2026-09-08

Six lanes asked for rulings on the same day. Each is recorded here because a ruling
delivered only to a mailbox reaches one agent; the lanes that inherit the consequence
read the repository. Each ruling names what was verified, at source, before it was made.

Three lanes in one day asked for a ruling on a section that was already ruled. That is a
defect in this file, not in those lanes: a document nobody can search is a document nobody
reads twice. Find the question below before asking it.

| # | lane | the question it answers |
|---|---|---|
| R1 | `bridge-mrtr7` | can a mid-exchange refusal strand a pending sample? (no — `WIRE.5` stands) |
| R2 | `sub4-idempotency` | does the replay cache keep a config gate? (no — enabled unconditionally) |
| R3 | `control4-lifecycle` | wire the lifecycle reaper or delete it? |
| R4 | `confirm-gate` | which lane owns `CONFIRM.2`, and is the seam note still written? |
| R5 | `envelope-meta` | may phase 2 start on a tree holding another lane's dirty files? |
| R6 | `ext1-otel1` | can `SCHEMA.1c` close without adding a runtime dependency? |
| R7 | `sub4-idempotency` | who repairs a replay path that is already live? |
| R8 | `bridge-mrtr7` | is `WIRE.5` narrowed by per-round gating? (no) |
| R8a | `bridge-mrtr7` | which `DeliveryError` variant a silent client produces — `TimedOut`, not `Deadline` |
| R9 | `control4-lifecycle` | how does the reaper reach its collaborator? (parameter, not global) |
| R10 | `confirm-gate` | rewrite a commit contaminated by a peer's file? (no — `CONFIRM.1a` says which PARTIAL) |
| R11 | `envelope-meta` | is a third review round owed? (no) |
| R12 | `control4-lifecycle` | may reaper wiring edit `src/gateway/streaming.rs`? (U3 granted) |
| R13 | team lead | the `$ref` criteria for MIK-7414 were mis-stated, and are amended here |
| R14 | release | when does the DoD functional pass run, and who owns it? |
| R15 | any | a stale comment a ticket *cites* has a consumer, and gets fixed |
| R16 | `envelope-meta` | which package owns an uncommitted criteria row? (E) |
| R17 | any | who owns a `cargo fmt` failure? (the commit that introduced it) |
| R18 | package F | is the soak on the release critical path? (no — but a FAILING run is §11) |
| R19 | package F | when is the benchmark candidate pinned, and is a rehearsal discarded? |
| R20 | package F | is rustc 1.98.1 against a 1.98.0 pin a void run? (no) |
| R21 | `bridge-mrtr7` | `BRIDGE.4` aggregate expiry is `Deadline`; the reason is attribution |
| R22 | `bridge-mrtr7` | `WIRE.5` is ruled twice; a residual is stated as one sentence |
| R23 | `ext1-otel1` | package E's `$anchor` work: one ticket, one observation, neither built for 4.0.0 |

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
is the inner reason, returned where the bare `continue` sits at
`src/gateway/input_bridge.rs:484-486`. Take the lane's.

**Amended 2026-09-08, on the lane's correction.** This ruling first spelled that inner reason
`DeliveryError::Unanswered { key }`. No such variant exists: `enum DeliveryError`
(`src/gateway/input_bridge.rs:158-186`) carries `Declined`, `UnknownAction`, `ClientRefused`,
`Malformed`, `NoReplyMember`, `NoSession`, `TimedOut` and nothing else, and `rg -n 'Unanswered'
src/ tests/` returns zero hits in the whole tree. It was doubly unconstructible: an absent
variant, and a `key` field that lives one level up on `BridgeError::Delivery`. The constructible
form, and the one R21 assumes, is
`Err(BridgeError::Delivery { key: prompt.key, error: DeliveryError::TimedOut })` — whose own doc
line already reads "Nothing came back inside the per-prompt wait", which is exactly the condition
that `continue` sits on. Read with R21: the aggregate arm stays `BridgeError::Deadline`, the
silent-client arm inside a live budget takes the `TimedOut` shape above, discriminator
`left <= per_prompt` → `Deadline`. R21's "no new variant" is now spelled for both arms rather
than for only one, so a reader of R8a alone cannot implement the collapse. What survives from the
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

## R14 — the DoD functional pass is scheduled, with an owner and a trigger

The plan records "live acceptance: NOT RUN" as a gap and leaves it there. A gap with no owner
is rediscovered rather than closed, and this one blocks DONE however many criteria rows go MET,
so leaving it as prose would let a row count report a release that cannot ship.

It is not startable today and that is not an excuse: the pass drives the running thing **built
from the revision under review**, and the revision under review does not exist yet — four lanes
hold unlanded wiring and strict CI is red on a compilation failure another session owns.
Driving a half-wired tree would produce evidence about a revision nobody ships.

Deferral fields, since a deferral without them is an open question with better manners:

- **owner** — team lead, this session. Not a lane: the driver may not be the author, and every
  lane is an author of the thing it would drive.
- **what resolves it** — one isolated driver, handed the acceptance criteria and how to launch
  and nothing else, exercising the gateway the way its users do. Command-line surfaces are
  driven by running the command; the HTTP path by firing the request. Same model family is
  permitted, one round.
- **when** — the trigger is package G's `MRTR.7a`/`MRTR.7b` reaching MET with strict CI green,
  not a date. That is the first moment a revision exists that is worth driving.
- **if it resolves badly** — a FAIL or an unresolved INVESTIGATE is a §11 stop-the-line, not a
  row annotation. The release does not ship over it, and the finding enters the repair protocol
  and the round budget like any other review finding.

Until the trigger fires, nothing may be closed whose evidence depends on it. Note what that
rules out: any row claiming a user-visible behaviour holds. Rows pinned by a test and a source
anchor are unaffected, which is why the lanes proceed.

## R15 — a stale comment a ticket *cites* has a consumer, and gets fixed

`confirm-gate` had disposed a contradiction as an observation: `src/gateway/destructive_confirmation.rs:28` and `:38` still describe the pre-fix behaviour ("the action proceeds after a `WARN` log entry"), which is now false for the modern path that refuses at `src/gateway/meta_mcp/mod.rs:1964-1967`. It re-priced the disposal on discovering that MIK-7246 quotes that exact line in its Evidence section as the statement of the bug, and asked rather than took the edit.

Ruled: **fix it in this change** — §P0's disposal table takes the first option that holds, and two doc-comment lines in the file the row is already about is smaller than the ticket describing it would be. Timing condition: the commit lands *after* the in-flight review leg returns, so that verdict stays attributable to the material the reviewer actually read.

The generalisable half, which is why this is a ruling and not a mailbox reply: **a contradiction nobody references is an observation; one a ticket quotes has a consumer.** A stale line cited as evidence outlives the fix and reads to the next auditor as proof the bug is still there. Before settling on "observation", check whether anything cites the thing you are declining to fix.

## R16 — the uncommitted criteria row belongs to package E

Verified rather than assumed: `git diff -U0` on `docs/requirements/RELEASE-4.0.0-criteria-status.md` shows exactly one changed row, `MIK-6865.SCHEMA.1c`. That is package E's own criterion, so `ext1-otel1` carries it. Two lanes have been hunk-staging around it for an afternoon, which is the cost of an unowned dirty file in a shared tree.

Caution attached to the grant: the row reads MET, and R13 amended what MET has to mean for `SCHEMA.1c`. A row that predates its own criterion's amendment may claim a mechanism the amendment reworded.

## R17 — `cargo fmt` failures belong to the commit that introduced them

`src/idempotency.rs:881` fails `cargo fmt --check` and reproduces with no working-tree change, tracing to `04daba2d` on the SUB.4 lane. Two other lanes correctly reported it instead of fixing it. That is the right instinct and it is now the rule: in this shared tree, a repo-wide `cargo fmt` sweeps a peer's file into your commit. Format the file you broke; report the one you did not.

Same for the ten `cargo clippy --all-targets` warnings, which sit in `src/capability/executor/executor_tests.rs`, `src/gateway/meta_mcp/tests.rs` and `tests/common/mod.rs` — none in the reporting lane's files. Red signals you did not cause are a report, not a project.

## R18 — package F is off the release critical path, and knowing that changes what a bad run means

`perf-baseline` reported Package F as the work that closes `NFR.PERF.1`. It is not, and the row itself says so. `NFR.PERF.1` in `docs/requirements/RELEASE-4.0.0-criteria-status.md:364` carries a **release owner's ruling dated 2026-09-05: 4.0.0 ships on the headroom argument** — worst shared case +6.07% against a 10% P99 bound — with the blocking flag lifted the same day and the grade deliberately left at PARTIAL, because "rewriting a criterion to match the evidence you happen to have is what makes the rest of a ledger worth less".

So the end-to-end run is not what unblocks the release. Two things it can still win, both real:

- the row closes **at its own wording** instead of by exception, which is strictly better than a headroom argument even when the headroom argument is sound;
- the residual attached to that ruling — *no P50 or P99 for this release may be quoted publicly until an end-to-end run produces one* — is lifted. That residual otherwise binds every release note and every public claim indefinitely.

And one thing it can lose, declared **before any number is seen**, because that is the whole discipline of the contract this package is executing: a run showing a P99 regression past the bound is evidence against a decision already made on headroom. It gets reported as that, not buried and not re-framed. A **void** run is neutral and costs a re-run; a **failing** run is §11 stop-the-line and reopens a closed ruling. Those are different outcomes and the lane may not collapse them.

Consequence for scheduling: Package F does not gate the release, and the release does not wait on it.

## R19 — pin the candidate at execution, and rehearse before the scored run

The contract (`docs/requirements/RELEASE-4.0.0-performance-contract.md:28`) pins the candidate at `6218b857`. HEAD is now `79352d15` and six lanes are committing to this branch every few minutes; any commit named in advance is stale before the build starts.

Ruled: **the candidate is the HEAD of `fix/mrtr2-continuation-handle` at the moment the first scored rep starts, recorded then, not chosen in advance.** A pin whose only property is that someone typed it earlier buys nothing; a pin recorded at execution is what makes the number attributable.

Ruled with it: **one rehearsal now on current HEAD, explicitly non-evidence, then one scored run at the R14 trigger.** The rehearsal exists to trip the six declared void conditions — above all the `tools[0].name` hazard the contract names in advance — while tripping them is free. The failure this avoids is specific: a single scored shot that discovers a void condition at the moment the release is trying to go out. The rehearsal's numbers are discarded and may not be cited, including if they look good.

## R20 — a toolchain newer than the pinned one is not a void

Spark has rustc 1.98.1; the contract's environment table pins 1.98.0. `perf-baseline` flagged it as drift it would record rather than paper over — right instinct, wrong severity.

Void condition 5 is **arm-to-arm**: "the two builds do not use the same feature list and toolchain". It says nothing about matching the environment table. The table's own gloss states why 1.98.0 is written there — "above the `rust-version = "1.95"` both arms require" — and 1.98.1 is also above it. Both arms building on 1.98.1 satisfies the condition exactly.

Ruled: **not a void.** Record the actual `rustc -vV` string with the results and correct the environment row in the same commit as the re-pin. Do not stall the run on it.

The general form, since this will recur: a pinned environment value serves a stated purpose, and drift is judged against that purpose, not against the string. Read what the pin is *for* before declaring a mismatch fatal — and read the void conditions, which are the only things entitled to void a run.

## R21 — `BRIDGE.4`: aggregate expiry is `Deadline`, and the reason is attribution

`bridge-mrtr7` routed the question rather than answering it in its own design doc, having noticed that R8a put error shape on `ask()`'s failure path with the release owner. Correct instinct, and the escalation is granted on its merits.

Ruled: **the aggregate budget expiring inside a prompt's wait fails with `BridgeError::Deadline`.** The clamp at `input_bridge.rs:481-484` keeps both causes and the tie-break the lane stated stands — `left <= per_prompt` resolves to `Deadline`, aggregate wins the tie.

The primary reason is not reachability. It is that **`Delivery { key, error }` names a key, and naming a key attributes the failure to that key's owner.** A client that answered every prompt inside its own budget did not time out; the call did. Reporting that as a delivery timeout against the client's entry is a false statement about which party failed, and it is the kind of false statement that gets read later by someone deciding whether a backend is flaky.

Two consequences, both confirmatory rather than load-bearing: `BridgeError::Deadline` stays reachable from `ask()` instead of being swallowed by the variant R8a did touch, and test-plan row 321 keeps its assertion **unchanged** and becomes the row that pins the distinction. A ruling that also avoids churn is a pleasant accident, not an argument — if attribution had pointed the other way, row 321 would have moved.

Riders. `proxy.rs:557-558` builds `TimedOut` from a dropped channel under a comment claiming to mean what the bridge's timeout arm means by it — an arm that has never constructed one. That comment becomes true for the first time under this ruling; it rides with the repair per §P4a, as the lane already proposed. No new variant, no wire change, docs and one branch.

## R22 — `WIRE.5` is ruled, twice; a residual must be stated as one sentence

`bridge-mrtr7` reports `WIRE.5` as a still-unruled escalation. It is ruled at **R1** (the sampling-guard objection falls, the second fixture stands) and again at **R8** (per-round gating, exit A; the criterion is not narrowed). Both predate the escalation.

If something in the lane's escalation survives R1 and R8, the lane states **that residual in one sentence** and it gets ruled. What cannot happen is a lane blocking on "unruled" against a section that answers it — the rulings file is the SSOT precisely so a second delivery is not required. This is the second time a lane has reported blocked on a question already answered in this file, which is a signal about how the file is being read, not about the lane.

## R23 — package E's two non-gating improvements: one ticket, one observation, neither built for 4.0.0

`ext1-otel1` closed `SCHEMA.1c` and asked what to do with kimi's two non-gating suggestions. Disposed per §P0, taking the first option that holds:

- **`$anchor` plain-name fragments and `$id`-relative bases (MEDIUM) — file a ticket.** A human decides whether 4.1 closes it, which is what makes a ticket the right disposal rather than the default one. It is explicitly **not built for 4.0.0**: the limitation is disclosed in the row, it over-reports and never silently passes, and its direction is the safe one. New code on the trust path, late, to close a documented false-alarm class is a worse trade than shipping the disclosure.
- **Hoisting `SchemaBounds::inspect` out of `from_tool` to the backend cache insert (SMALL) — record as an observation on that same ticket.** Not its own ticket: anyone working the anchor code is already inside this function and can hoist while there. Two tickets for two edits in one function is the expensive default the §P0 table exists to stop.

The row stays closed. Neither of these reopens a reviewed row.

### R24 — `NFR.SEC.3`: `rotatable` is per-replica. Branch (c). `test-plan.md:301` stands

Asked by lane `ext1-otel1`, deferred to the team lead by
`docs/design/2026-09-06-nfr-sec3-key-rotation.md` with the trigger *before any
implementation begins*. No prior ruling covered it.

**(c) — per-replica lazy rotation inside `mint`.** The criterion reads
"continuation envelope versioned, key rotatable, verification keys retained for
the max lifetime" (`RELEASE-4.0.0-criteria-status.md:366`). It says nothing about
where the key material comes from, and per-replica rotation meets it as written:
an age check off the `now` already injected, retire and mint a fresh kid, drop
retained keys older than `CONTINUATION_LIFETIME_SECS` in the same pass.

**(b) is refused, and not on preference.** Operator-supplied shared key material
would make the `MRTR.5` row at `RELEASE-4.0.0-test-plan.md:301` *unsatisfiable* --
that row asserts a token minted by one `AppState` is `NotAuthentic` on a second
built through the production constructor **from the same configuration**, decided
before any ledger lookup. Shared configured keys make that refusal impossible. The
row is the one the cross-replica claim rests on, so (b) does not add a feature; it
withdraws an accepted criterion and re-opens `MRTR.5` mid-release. Branch (b)'s
substance -- durable ledger, reload-driven rotation, in-flight continuity -- is
already MIK-7312, sequenced after this release.

`test-plan.md:301` stands as written. `MRTR.5` is untouched. The design's decision
to decline three of the four pieces of branch (b) is ruled correct by the same
answer, so it needs no separate §P3 event.

The design's §P4a citation of a criteria cell reading "Branch (b) is the one taken"
is **stale** -- that string does not exist in the ledger, and the live row frames the
gap as (c) does. Correcting another lane's artefact is not `ext1-otel1`'s work;
recording it here is enough.

Acceptance-criterion identifiers for this criterion are the lane's to author with
the §P2 test plan (`MIK-7417.SEC3.<n>`), reviewed with the plan. Not a question.

### R25 — `CONTROL.4` T6: the negative half stays, and it may not generate another round

`control4-lifecycle` is right that T6's no-idle-log half is D7's design preference
rather than a `CONTROL.4` acceptance criterion, and right that three rounds each
finding a defect in the previous round's repair is the shape the repair protocol
answers with DELETE.

It is now green and correct. Deleting a correct mechanism costs a change and a
review round to remove work already paid for, so it stays -- but the signal is not
discarded: **one more finding against T6's negative half, its marker, or the
marker-ordering constraint, and the response is deletion, not repair.** No fourth
patch round on that mechanism. The positive count assertion was never in dispute
and survives either way.

### R26 — nobody pushes; the diverged branch is reconciled once, by the team lead

`fix/mrtr2-continuation-handle` is DIVERGED, not behind: 19 remote commits no
session here holds, 166 local. Reported by `sub4-idempotency`, whose refusal to
rebase unilaterally is correct -- a rebase rewrites six sessions' commits.

No lane pushes. Reconciliation is one team-lead **merge**, never a rebase, at
release-candidate time, and the ratification gate requires an operator-minted stamp
in a terminal regardless. Lanes keep committing locally with `git commit -o <paths>`.

Clippy on `tests/common/mod.rs` (three errors at `:13`, `:23`, `:38`, from
`fe06e167` and `46adb8cd`) belongs to `ext1-otel1` -- they are its own COMPAT.1
commits. It may not commit that file yet: the envelope-meta lane holds an
uncommitted `SPEC_ENCODING_TABLE` hunk there, and `commit -o` on the path would
publish another lane's unreviewed work. Sequence: envelope-meta lands its hunk
first, then `ext1-otel1` fixes its own three lints.

## R27 — the release has 19 open blocking criteria, not 20, and `blocking` is a property

Recount of `docs/requirements/RELEASE-4.0.0-criteria-status.md` by column, not by
memory: 21 rows carry `blocking = yes`. Two of them are already `MET` --
`MIK-6865.SCHEMA.1c` and `NFR.SEC.1`. Nineteen are open.

That column marks a criterion as release-gating **by nature**. It is not a gap
flag, and a row does not lose its `yes` when it reaches `MET`; the header count
of 21 counts the property, and 183 minus 21 gives the 162 "met or non-blocking"
on the same line. A `MET` row carrying `yes` is therefore correct and needs no
repair -- the reading that finds a contradiction there has read the column as a
gap flag.

`NFR.PERF.1` is `no`, and has been through every revision of the file that git
records; `c4f13034` recorded that ruling deliberately. It is a real gap and it
stays in the full-scope plan, but it is **not on the release critical path**.
Package F may not be escalated as gating work, and no other package waits on it.

Four rows had evidence prose whose piped `rg` alternations split their own table
cells, one of them swallowing a status field. Rewritten as `-e` arguments in
`91b2b07b`; every row now holds seven fields (main table) or eight (NFR table,
which carries the extra `T` column, so its status is field five and the main
table's is field four).

## R28 — the hunk was not envelope-meta's, and `commit -o` was the wrong tool

I told `envelope-meta` to land the uncommitted `SPEC_ENCODING_TABLE` addition in
`tests/common/mod.rs` so `ext1-otel1` could commit three clippy fixes in the same
file. That instruction was wrong twice over, and the lane refused it with evidence
rather than following it. The refusal was correct and the instruction is retracted.

**Wrong owner.** The uncommitted work is one coherent three-file change, not a
stray hunk: `tests/common/mod.rs` gains the `pub const`, `tests/mik_7214_acs.rs`
deletes its private copy for a `use common::SPEC_ENCODING_TABLE`, and
`tests/mik_7214_header_9_acs.rs` gains
`a_modern_named_call_encodes_a_name_a_header_cannot_carry_raw`. That is a fixture
being promoted to shared so a HEADER.4a encoding case can consume it — the case
row 113 of the criteria ledger already names as a sibling session's then-uncommitted
work. `envelope-meta`'s five commits this cycle are all one docs file and it has run
no cargo command. Committing it would have put one lane's signature on another's
unreviewed work: precisely the harm R26 exists to prevent, with the names swapped.

**Wrong tool, so the sequencing was never needed.** `git commit -o <path>` commits
the whole working-tree content of that path, foreign hunks included, which is why
the instruction reached for an ordering between lanes. Hunks are separable. The
addition sits at `+210`; the three clippy errors are at `:13`, `:23` and `:38`, so
under `git diff -U0` they are disjoint and each lane can stage its own.

**Standing mechanism for this shared worktree.** Six sessions share one index, so
staging into it and committing has a race whose failure mode is publishing a peer's
work. Use a private index instead, and refuse the commit if the branch moved:

```sh
idx=$(mktemp -u); export GIT_INDEX_FILE=$idx
git read-tree HEAD
git diff -U0 -- <your paths> > /tmp/mine.patch   # edit down to YOUR hunks
git apply --cached --unidiff-zero /tmp/mine.patch
git diff --cached --stat                          # must match your edited-line count
tree=$(git write-tree); unset GIT_INDEX_FILE; rm -f "$idx"
c=$(git commit-tree "$tree" -p HEAD -m "type(scope): summary")
git update-ref refs/heads/$(git branch --show-current) "$c" HEAD
```

`update-ref` with an expected old value refuses rather than clobbering if a peer
committed in the interval. `commit -o` stays correct for a file a lane owns whole,
which is every docs commit this release has made; this is for a file two lanes are
inside at once.

**The hunk itself.** It stays uncommitted until its author claims it. Nobody's
lints wait on it. If no lane claims it within the hour, `envelope-meta` may adopt
it as material for HEADER.4a — reading it as a test before trusting it, per §P2 —
and the commit body must say it was adopted from the working tree with the author
unidentified, so the record does not imply authorship it cannot support.

## R29 — package B's remaining slices belong to envelope-meta

`envelope-meta` asked whether the SSE GET era re-assert and the HEADER.4a outbound
encoding are its work at all, having opened no design or test plan for either: its
§P0 scope this cycle was the docs catch-up.

They are its work. A cycle's §P0 scope bounds one change; it does not reassign a
package. Package B is `HEADER.9a`, `HEADER.9b` and `CONTROL.3b`, and it has been
`envelope-meta`'s since the gap plan was written. Start at the design step, as
asked — the two gaps sit at *design done, no failing test*, which is where §P2
begins, not where it ends.

Three things the lane established that the board should carry:

- The SSE GET gap is verified at source: `establish_sse_connection`
  (`src/transport/http/mod.rs:924`) calls `build_mcp_headers(HeaderMode::Sse, None)`
  at `:927` and never reaches `finalise_modern_headers`, so a modern peer
  reconnecting the stream is handed the handshake version. `HeaderMode::Close` is
  not a third gap — the design decided it legacy.
- `CONTROL.3b` is *past* implementation (`044896aa` wires `merge_client_meta`) with
  one test missing: no case drives a real client `params._meta` through
  `handle_request` to `invoke.rs:1865`. That is a retrofit, so it owes the §P2
  falsifier probe rather than a free failure. Nobody should estimate it as a
  ten-minute test.
- All three rows stay PARTIAL and blocking. The count in R27 does not move.

## R30 — 525 evidence anchors, none of which names when it was read

`confirm-gate` found eight anchors in the `CONFIRM.1a` cell sitting twelve lines
low. The cell had been rewritten fifteen minutes after `5182b3fc` added seventeen
lines of doc comment to the file it cites, and its headline said its citations had
been re-verified at source. They had been read — just not after the commit that
moved them. The lane found five more of the same in its own seam note. Both are
fixed (`56ca3fd1`, `33efb4aa`).

The lane's generalisation is right and it is not confined to that lane: on a branch
where six sessions commit within the hour, **"re-verified today" is not a freshness
claim.** Measured across the whole ledger: 525 `path:line` anchors, 129 distinct
files, 161 rows. Zero of them name a commit.

That is the release gate's own evidence. An anchor that has silently drifted does
not read as wrong — it reads as a citation, and a reviewer who spot-checks one that
happens to be stale learns nothing about the other 524.

**Two rules, from now.**

1. A cell citing `path:line` names the symbol it expects to find there, and the
   commit it was read at: `` `src/gateway/x.rs:99 for_modern` @ 9ceaeb54 ``. The
   symbol is what makes the anchor checkable by something other than a person; the
   sha is what makes staleness detectable without re-reading.
2. No row is quoted as release evidence until its anchors have been re-read against
   the revision being released, or verified mechanically under rule 1.

**Rule 1 is worth nothing without the checker, so the checker is the deliverable.**
`perf-baseline` owns it: extract every `path:line` plus its named symbol from the
ledger, assert the file has that line and that the line's neighbourhood contains
the symbol, report every anchor that fails. That lane spent this cycle building an
evidence apparatus designed to be ungameable and is parked until R14 fires; this is
the same problem one level up, and it is the difference between a ledger a reader
can trust and one a reader can only sample.

Backfilling 525 anchors by hand is not ordered and would not be done. The checker
reports which are stale; only those get re-read. Anchors written from now carry
their sha, so the backlog is bounded and shrinking rather than growing.

## R31 — "strict CI green" cannot mean what R14 said while §P2 is in force

`control4-lifecycle` disclosed that `cargo test` on this branch no longer builds
`mik_7215_control4_reap_count_acs`: T3 asserts on a count `reap` does not return
yet. That red is correct. §P2 requires the failing test first, and a test that
fails because the surface is absent is the free, real failure the rule exists to
buy.

It also makes R14's trigger unsatisfiable. R14 releases the scored NFR.PERF.1 run
on `MRTR.7a/7b MET plus strict CI green`, and strict CI cannot go green while any
lane is correctly mid-TDD. Six lanes writing tests first means a permanent red, so
the trigger as written would hold the scored run until the last implementation on
the branch landed — which is after the moment the measurement is useful.

Two rules cannot both be obeyed, so one of them was wrong. It was mine.

**R14's trigger now reads: no UNREGISTERED red.** A lane landing a deliberately
red target registers it, in the same commit, in `docs/release/expected-red.md`:
the target name, the criterion it belongs to, whether it is compile-red or
assert-red, and the commit that introduced it. The trigger is satisfied when every
red in strict CI appears in that register and `MRTR.7a/7b` are MET.

The register is what stops "intended red" being a claim anyone can make about any
failure after seeing it. A red that is genuinely expected can be declared before it
is observed; one declared afterwards is a story about a failure. Same asymmetry as
§P2's own: order is what carries the proof, not effort.

Registration is not a licence to leave it red. Every entry owes a green, and an
entry whose criterion reaches MET while the entry still stands is a contradiction
the RC check must catch — the register is a debt list, and it must be empty at RC.

`control4-lifecycle`'s second disclosure stands as its own small rule: **a compile
error is one error for the whole file, so a compile-red row proves the surface is
absent and says nothing about whether its assertion can discriminate.** Every
compile-red row owes one falsifier probe at green time — break the single operand
it exists to pin, watch that row go red on its own assertion. The lane found this
in its own test plan and relabelled every row by kind rather than being told. T3 is
the one row where compile-red is the whole evidence, because there the signature
*is* the criterion.

The `gpt-20260908T144154Z` SHIP does not cover the corrected plan, and relaunching
both legs rather than carrying the verdict forward was right: a self-found
correction committed after a verdict is a new delta, not a confirmation pass.
