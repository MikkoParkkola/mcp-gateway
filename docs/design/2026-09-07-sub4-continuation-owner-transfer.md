<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# SUB4: keep one owner across continuation phases

Status: r3 Grok SHIP retained; focused GPT r4 documentation finder pending. This revision
repairs the findings without implementing the changed behavior.
FOR: finish approved synchronous admission across HTTP meta/direct routes and
preserve one owner through authenticated continuation phases. OUT: durable Task
dispatch, new protocol features/activation switches, crypto changes, and the
coordinator-owned production finalizer. Those remain separate release work.
A real held-RPC adapter remains a **4.0 dependency**, not an exclusion from 4.0.

## Authority, evidence and readiness

Authority: [current SUB4 contract](2026-08-31-sub-4-idempotency-wiring.md), its
MRTR.10b row, and the coordinator's 2026-09-07 engineering ruling: retryability
applies when a valid authenticated continuation is delivered. A dispatched
operation with malformed/capability-refused interim and no usable continuation
retains unavailable ownership; no automatic redispatch or no-effects claim. A
new deliberate key is a new operation, without a promise that the prior call
had no effects. The canonical MRTR.10b row now states this distinction.

Source facts already checked for r1: `invoke.rs::mint_continuation` holds a
record before sealing; `redeem_retry` authenticates envelope, caller, original
operation, live hold and JTI. `continuation.rs::InFlight` currently stores only
replica/deadline, while `dispatch_to_backend` awaits the local request future.
Returned JSON proves neither absence of effects nor ownership of a live RPC.
Direct HTTP currently lacks sealed mint/redeem and must reuse this shared seam.
No payload `input_required` predicate grants transfer or release authority.

Existing tests stay frozen: 54/54 CLI cases passed, actual exit 0, in
`sub4-admission-green-r1` and `-r2`. Their separate tests receipt is
`sub4-admission-tests-review-r3.verified.json`, material SHA
`2b126699137234dcce636d9f4b08d69b6aaf821b1c2eb5f0f2936a8617da35a6`.
It covers the first HTTP leg, not the phase/lifetime tests below. Core reviewed
atomic ownership, strict count/byte bounds and no active expiry remain unchanged.

Compact DoR applicability (canonical quality-gates-dor.md; evidence grades:
V=source/runtime verified, A=bounded planning assumption):

| Gates | Applicability and evidence |
|---|---|
| G0-G5, B1-B5 | Security/reliability mandate and user-authorized SUB4 release outcome, no NPV claim. Existing MIK-7272.SUB.4/W02 ownership; coordinator maintains live tracker fields/dependencies. Stable AC mapping below. G2 estimate A: 3-6 focused hours including tests, review, validation; 100K input +20K output planning allowance = $3 at policy $15/$75 per million, not actual billing or a budget authorization. Earlier r1 review cost is sunk and preserved in receipts. |
| T0-T6, G6-G9 | Reuse existing Rust/core/continuation interfaces; alternative release-on-payload rejected below. No dependency, language or crypto replacement; SHA/HMAC remain unchanged (T1c). Existing implementation searched, no new framework or numerical algorithm. Beyond-SOTA/novel optimization N/A; stronger owner generation checks fit current authority. |
| G10-G12 | Ranked unknowns: held RPC ownership (release dependency below); atomic claim/transfer race (PHASE.2/.5); cache masking dispatch (CACHE.1). Cheapest checks are current call graph/source and bounded counted-backend tests, before broad suites. No unknown silently assumed resolved. |
| G13-G21 | Adoption/security increment: moat/novelty/perf-first N/A. Premortem: replay a side effect after disconnect/claim theft; owner retention and negative-plus-positive tests target it. Existing core and sealed claims are prior art; no new technology claim. Additive in-process seam, reversible pre-release; no one-way data migration. |
| C1-C5, C7-C14 | Shared service, no second admission authority; interface/behavior seams and V-model matrix below. No public carrier change; legacy unkeyed compatibility retained. Existing dependencies/license. Scoped impact required before symbols; unit/integration/CLI tests, race/failure tests, then critical coverage >=95% and viable mutation >=85%. Keep new files <=800 lines through focused modules. No asymptotic scan or unbounded bytes added. |
| C6, C15-C17 | Threats: spoofed payload target/claim, stolen claim, changed key/args/representation, reuse, cancellation, expiry and cache aliasing. Verified principal, authenticated single-use consume, same generation and strict result/metadata bounds; never infer effects from JSON. No new unauthenticated authority. |
| P1-P8 | Existing CLI/build lane, observability and final delivery logger; no new service/SLO or deployment topology. No retained raw secrets in token/new admission metadata, fixed capacity; expiry cleanup and cancellation documented. Full release regression/CI and independent wired acceptance remain mandatory. No production rollback claimed from an uncommitted patch. |
| L1-L7, O1-O4 | Existing repo/licensing and symmetric crypto retained; no new dependency/data export/AI/device regulation surface or persistent schema in this event. Existing retention limits apply. Repository naming and ADR authority reused; no new irreversible architecture decision. |

## Transition and transport contract

Keep the same non-cloneable Sync lease. Transfer only through server control
flow after the awaited local backend request returned a usable interim, current
capability checks permit delivery, and the existing authenticated continuation
can be minted. The record accepts the lease before its handle can be published.
The request wrapper becomes empty only after acceptance; a cancellation cannot
strand an owner between the two. Mint/transfer failure publishes no handle and
retains post-dispatch unavailable ownership. No raw principal/key/arguments or
lease state is added to the outward sealed envelope.

Both HTTP routes use the same claim-before-default-admission seam. The direct
route gains existing sealed continuation mint/redemption, with its own bound
representation. Authenticate principal, original target/arguments, explicit key,
representation, live hold and single-use JTI before taking the lease. A failed
claim never falls through to a new admission. Return the existing lease, outbound
backend retry state/answers and original backend/tool as one server-owned claimed
result. The lease exposes that authenticated response target to the finalizer;
**never parse the token twice or derive the target from backend response text**.
Fresh requests use ordinary authorized targets. Root finalization runs after
wrapping/shaping and before result retention or serialization, including replay.

The internal idempotency operation identity is the composition of the stable
owner identity and the semantic phase fingerprint. MRTR.10a's inclusion of
`inputResponses`/`requestState` applies to that complete identity; it does not
require a second reservation map or a different owner per phase. The immutable
original operation binding remains intact. A live validated claim
allows this phase's new answers. Advance the entry's canonical phase fingerprint
under its existing generation check, including forwarded arguments and semantic
state/answers; never change owner/key or representation. Changing answers alone
cannot advance. Completed-phase replay uses a separate existing-operation-key lookup, not the
continuation dispatch-redemption API. Its implementation cannot call the JTI
consumer, claim-take or owner-insertion operations. The dispatch-redemption API
still refuses a second redemption, including when a matching final result exists.
On the separate result-lookup path, authenticate
and validate the presented envelope (including its expiry), caller, original
operation, key and representation, then use an **existing-only** admission lookup
for the exact phase fingerprint. A matching secured Completed entry may be read
without redeeming or re-consuming its already-spent JTI and without requiring the removed live
hold. The lookup never inserts an owner. A missing/mismatching/unavailable entry
refuses; an active entry requires the live single-use claim transition. Thus a
spent claim cannot dispatch, while an identical final phase can replay while its
envelope remains valid. Changed answers after settlement, stale phases, or a
no-claim changed-phase attempt conflict; expired envelopes refuse even when a
secured result remains retained. This path never repairs a bad claim by admitting
new work.

| State/event | Owner/claim transition | Observable guarantee |
|---|---|---|
| New admissible operation | one active Sync lease | at most one backend start for a phase |
| Usable authenticated question | same lease moved into live record before publication | same-key fresh request cannot become another owner |
| Valid answer on live claim | one atomic take; same owner advances phase | exactly one concurrent claimant dispatches |
| Invalid key/caller/body/representation/token | no consume/take or new admit | rightful live claim remains usable |
| Spent claim for exact secured final phase | authenticated existing-only lookup, no consume or insert | replay only, never dispatch |
| Expired/missing claim or spent claim without exact final match | refusal, no fresh admission | no second execution |
| Another usable question | transfer same owner with fresh claim | phase chain retains one operation |
| Final response | secured final artifact retained by same owner | same-phase replay has no backend effect |
| Refused/malformed interim, mint failure, post-dispatch failure | unavailable retention, no usable claim delivered | no restart under same key; no no-effects claim |
| Expiry/drop after local request completed | drop dispatched lease to unavailable | claim capacity reclaimed; no fresh operation |

Protected keyed backend calls bypass ordinary response-cache **reads**; same-key
replay comes only from admission. Legacy unkeyed caching is unchanged. Distinct
explicit keys therefore execute independent operations even with response cache
ON. This replaces r1's incorrect key-B cache-hit retention proposal; it does not
change key carrier, required-key exceptions or identity authority.

A local RPC still running must keep its lease until cancellation has been joined
or its future completes. Current awaited dispatch supplies completed-future
provenance, not proof of no effect. **4.0 dependency:** owner=root/bridge delivery
coordinator; trigger=adapter introduces a held legacy RPC (Task `INPUT-06` adapter); mandatory AC `SUB4.BRIDGE.LIFE.1`
in the canonical release test plan; integration check=actual pending future survives client drop,
then cancel/expiry joins it before ownership settlement, with a counted effect
and retry falsifier; failure action=block that adapter's activation and 4.0
acceptance until its owned cancel/join path passes. Metadata deletion is never
the fallback. This amendment adds no fake held task solely to satisfy a test.

Options rejected: release on payload (duplicate window); fresh-admit a changed
phase (two owners); store interim as final (breaks continuation); extend then
evict active TTL (time does not establish completion); retain an ordinary cache
hit for another key (aliases deliberately distinct operations).

## Test delta and gate order

Tests first, compiled reds, separate paired tests review, then the narrow fix.
Use actual service/claim symbols and production builder on transport tests;
verified credentials, counted effects and bounded barriers/events. Each invalid
attempt uses its own fresh fixture, then the **same rightful claim** succeeds
exactly once, proving the invalid attempt did not consume its JTI. Missing or
expired records cannot have that positive; a separate still-live record is the
control, plus zero new starts for the invalid claim. Cache OFF except CACHE.1.

| ID / authoritative AC | V-model level; type | Discriminating assertion |
|---|---|---|
| SUB4.PHASE.1 / SUB.4 + MRTR.10b | CLI acceptance + component; happy-path/regression | Both HTTP routes: initial keyed call delivers authenticated question; valid same-key answer advances to a second usable question, its fresh claim advances to final secured result. Identical final-phase retry with still-valid envelope reads that result through the separate existing-operation-key lookup despite spent JTI, adding no start. Directly calling dispatch-redemption again still refuses. |
| SUB4.PHASE.2 / SUB.4 P1/P5, NFR.SEC principal binding | component + HTTP integration; real race/security | Both HTTP routes: barrier race same claim: one takes/advances, loser never dispatches. Wrong key/owner/original args/representation refuse without consuming; after each, rightful same claim succeeds with its fresh answers. Changed answers without claim or after settlement refuse. |
| SUB4.PHASE.3 / MRTR.8b + SUB.4 no duplicate | component + both HTTP routes; boundary/failure | Both HTTP routes: missing, expired, already-taken-without-final-match, malformed/unauthentic token never fresh-admit. Already-consumed exact final phase follows PHASE.1 read-only replay; altered phase does not. Live invalid attempts preserve same JTI for valid retry; absent/expired cases preserve a separate live record. Expiry reclaims claim count while key remains unavailable. |
| SUB4.PHASE.4 / MRTR.10b external refusal + SUB.4 P6 | component + HTTP integration; failure injection | Both HTTP routes: undeclared capability, malformed interim, mint/record-capacity failure: no usable claim, repeated same key adds no backend effect. Response makes no no-effects claim. New deliberate key is a distinct operation and adds exactly one counted dispatch, not an automatic retry. |
| SUB4.PHASE.5 / SUB.4 P1/P6/P7 | component + HTTP integration; cancellation/race | Both HTTP routes: cancellation at record transfer leaves exactly one owner. Current awaited-future path is provenance control; spoofed input_required cannot transfer/release. Actual held-RPC cancel/join belongs to the explicit 4.0 dependency above, not a fabricated test here. |
| SUB4.SYNC.CACHE.1 / SUB.4 P2 independent operations | production CLI acceptance; regression/negative control | Same verified principal, route, target, arguments, representation and cache state throughout; only explicit key changes between protected A and B. Cache ON: legacy unkeyed warm + repeat keeps backend count 1, proving hit. Protected A then B execute, counts 2 then 3. Same A returns its original count-2 artifact while ordinary cache holds count-3 artifact from B, proving admission-sourced replay; backend stays 3. No sleep/TTL assumption. |
| SUB4.SYNC.LIFE.1 / SUB.4 P1/P6/P7 | both HTTP routes; real concurrency/failure | Backend commits counted effect then waits on a gate; concurrent same-key refuses promptly. Disconnect client; settle/join local request future as applicable, then retries never repeat effect. Fresh-key control adds one. Gate release is not described as proof of backend cancellation. |

Then focused existing MRTR/continuation/idempotency regressions, self-QA, paired
code review, quantitative critical gates, and independent wired acceptance after
finalizer integration. Preserve actual commands, exits, source hashes and failed
runs externally. No issue closure or complete-release claim from this component.

### Local stdio operator identity (coordinator ruling, 2026-09-07)

Modern stdio writes use a typed `StdioLocalOperator` principal under the existing
local-spawning-operator trust boundary. It is a distinct structured identity tag
from **all** HTTP credential and OIDC strings; HTTP construction and caller metadata
cannot select it. No path spelling, OS/env string or new persisted UUID supplies
identity. The private admission service / protected task store is the lookup
realm: there is no cross-store task retrieval. Within that realm the logical local
operator binding is stable on reopen/relocation; different stores remain isolated
by their independent record lookup and lifetime directory leases. Sync still has
only process-lifetime deduplication, with no cross-restart effect promise. This
principal grants no OIDC, personal-account or delegated identity. The actual stdio
transport alone creates the typed context; request metadata cannot create trusted
context. Existing admin and per-step ToolPolicy checks continue to apply.

`MIK-7272.SUB4.STDIO.OWNER.1` (SUB4.COMPAT.1/MANAGEMENT.1; component + real stdio acceptance,
security/compatibility): modern keyed mutation works and same-key replay adds no
effect; modern missing-key refuses; legacy unkeyed repeats execute twice. Existing six management cases remain mandatory. Independent security cases:
`MIK-7272.SUB4.STDIO.OWNER.3` rejects aliasing from an injected principal tag or an
HTTP credential whose raw text equals the stdio spelling; `.4` requires current
ToolPolicy denial; `.5` proves the created context has no OIDC/account identity.
All are independently recorded assertions, not inferred from compatibility.

`MIK-7272.SUB4.STDIO.OWNER.2` (TASK ownership/recovery; component + store integration,
persistence/isolation): same protected store reopens/relocates and its local
operator can retrieve the retained task. A different store cannot retrieve it;
an HTTP owner in the same store cannot alias the typed stdio owner. This case
blocks durable-Task activation/acceptance until the store is integrated; a fresh
Sync service is allowed to have no retained Sync outcome. No storage-instance
UUID is added solely for global uniqueness when lookup has no cross-realm path.

C6 STRIDE for this existing-trust-boundary binding (no new privilege):

| Threat | Mitigation | Falsifier / residual |
|---|---|---|
| Spoofing | Transport alone constructs typed stdio tag; structured HTTP namespace differs for every raw string. | OWNER.3 hostile metadata and matching HTTP spelling. Local spawning operator is intentionally trusted. |
| Tampering | Protected store custody and lifetime lease; no caller-chosen identity file/path input. | OWNER.2 independent-store lookup refuses; Task STORE-06 retains permissions/symlink controls. |
| Repudiation | Existing delivery-attempt logging and server-owned target/phase observations; no client-receipt claim. | OWNER.4 + captured phase records, no caller-supplied authority labels. |
| Information disclosure | Principal- and store-scoped lookup; current authorization before retained delivery. | OWNER.2/.3 and policy-revocation cases; no answer/key/token/raw-principal data in observation records. |
| Denial of service | Existing strict admission/Task counts and bytes; live owner retained until true settlement, bounded claim expiry. | Existing SLOTS/BYTES plus BRIDGE.LIFE.1; no unbounded identity registry. |
| Elevation of privilege | Local tag never creates OIDC/account/delegation identity; ToolPolicy and existing admin rules remain. | OWNER.4/.5; private-directory operator custody is a stated assumption, not protection from its owner. |

The historical MRTR.10b/CACHE.4 identical-follow-up cache falsifier applies to
**unkeyed cache-only calls**. It cannot require discarding a keyed live owner.
Phase transfer/refusal observations may expose phase/reason labels and counts,
never answers, tokens, keys or raw principal data. Test their absence in captured
records while using existing counters/loggers, without a new telemetry subsystem.

## Finder disposition

R1 actual process 0/process-ok for both; same material SHA
`5671b76e64a77f1a459f73ee85c8af533d76a110ab931c8dc5e0c777fb1324b9`,
94,831 bytes. Receipts: `sub4-owner-transfer-plan-review-r1.verified.json`; runs
`gpt-20260907T003848Z-72207.md`, `grok-20260907T003848Z-72202.md`.
GPT: canonical retryability ruling/row repaired; direct route uses shared sealed
claim; fake held-RPC test removed with explicit full-release dependency; each
live invalid claim has rightful same-claim control; DoR and V-model mapping added.
Grok: cache aliasing replaced by approved keyed cache-read bypass; fresh claimed
answers distinguished from changed no-claim/stale/settled attempts. Improvements:
transition table, response-target handoff, deterministic cache control, accurate
local lifetime wording. Finder must confirm these repairs; r1 is not approval.

R2 actual 0/process-ok pair, material SHA
`ec324918c697e0f033e22c40649767e2334cebb041106bdfe3f73efa4831da8d`,
15,634 bytes; `sub4-owner-transfer-plan-review-r2.verified.json`.
GPT `gpt-20260907T005903Z-98353.md`: repaired canonical MRTR.10 rows,
existing-only final replay, identical-input cache control and stable bridge AC.
Grok `grok-20260907T005903Z-98354.md`: PHASE.2/.4 explicitly both routes;
correct `INPUT-06` reference and named full-release AC; new-key counted positive
and unkeyed historical-cache clarification added. Parent SUB4 design links here
as the controlling invariant amendment; canonical test rows are aligned, not a
second conflicting owner specification. R3 also reviews the coordinator's narrow
stdio authority ruling above; no behavior for that new binding precedes approval.

R3 same material SHA `59aa516d7631d7d995a00f10aa15e3ecae0e5c84222c51d73402986f4024850d`,
14,318 bytes, actual0/process-ok pair. Grok SHIP retained from
`grok-20260907T011620Z-19930.md` under repair item6. GPT
`gpt-20260907T011620Z-19929.md` requests documentation/traceability repair:
separate result lookup vs dispatch redemption; composite operation identity;
ticket-qualified canonical stdio cases; STRIDE mapping. These clarify the same
r3 behavior and add no state, authority, cache policy or execution exception.
R4 finder sees those exact repairs. Cache-write bypass suggestion is not adopted:
the approved read-bypass contract and independent-key cache discriminator stay
unchanged. Grok improvements fold cache exception and stdio cases into parent
plans, order the multi-question positive before final settlement, and keep the
typed principal at the transport rather than in a reusable authorizer.

R4 GPT finder `gpt-20260907T015001Z-61283.md` returned SHIP with actual exit 0
and process-ok, material SHA `98b630ff58634a1f6de6606b3afa954f26251e867481302ffbc11e6bf54055eb`,
15,933 bytes. `sub4-owner-transfer-plan-review-r4.verified.json` verifies this
repair closure plus the retained r3 Grok SHIP; it does not claim a new same-byte
pair. The parent SUB4 and Task-plan excerpts also match the exact files recorded
in `sub4-owner-transfer-plan-review-r4-context-binding.json` after review; those
whole files were not retransmitted. The design/test-plan gate is closed. Failing
tests, their separate review, implementation and delivery gates remain pending.
