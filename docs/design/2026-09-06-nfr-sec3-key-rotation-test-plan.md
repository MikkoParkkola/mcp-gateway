# NFR.SEC.3 — continuation key rotation test plan

Status: design/test-plan, assertion-first tests and final code gates approved by
both vendors. Eighteen rotation tests, four actual-builder cases and134 existing
continuation/MRTR regressions pass. Coverage, mutation and component measurements
are complete. Independent acceptance-only drive and the parent-owned release
chain remain pending; this is not a release-completion claim.
FOR: prove mint-side age rotation and verification retention without losing live
continuations or weakening single-use protection. Owner: release lead.
OUT: shared keys, distributed ledgers, manual rotation API, task persistence and
message-signing keys. This is the existing continuation AES-GCM mechanism only.

Design: `2026-09-06-nfr-sec3-key-rotation.md`, including the takeover clarification.
Acceptance: NFR.SEC.3 versioned envelope, rotatable keys, verification material
retained for maximum lifetime; regress MRTR.5a/.5b and existing mint budget.
Value: removes a restart-only key lifecycle and keeps already-issued work usable.
Targets: `src/protocol/continuation/keyring.rs` and focused tests; actual-builder
fixture `src/gateway/meta_mcp/continuation_rotation_tests.rs`. Coordinate
with root's InFlight changes; do not rewrite consumed-ledger behavior.

Use synthetic trusted epoch T=1000, the actual constants (rotation 60s, maximum
lifetime 300s), and `Payload::issued_at` as the sole time input to mint. Inspect
the decoded envelope's existing public kid byte; a test-only non-mutating ring
snapshot may expose kid, creation/retirement times and remaining quota, never
key bytes. Successful opening must compare the complete payload to its original.
No sleeps, reduced production constants, fabricated readiness, or compile-red.
Assert `(256 - 1) * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS`:
the returning kid's reuse distance from its previous retirement is 255 intervals,
not 256. This adopts r2 GPT's arithmetic correction without changing 60/300.

| Case | Criterion / assertion | Level / type | Decisive falsifier |
|---|---|---|---|
| ROTATE.1 | First mint at T uses initial kid; at T+59 it still uses that kid; mint at T+60 uses successor kid and both live envelopes open. | unit / boundary | Missing age trigger or premature rotation. |
| ROTATE.2 | Last old-key mint at retirement instant (before triggering rotation) remains verifiable through its actual expiry; retain key through retirement+300 equality and remove only after it when a mint prunes. Observe ring directly as well as valid/expired payload outcomes. | unit / retention | Premature deletion or `>=` pruning; live control prevents refusal-only success. |
| ROTATE.3 | Advance open-only calls beyond age threshold; kid/ring unchanged. A payload beyond its expiry refuses as `Expired` while its key is retained. Next mint performs age rotation. | unit / trigger regression | Rotation/pruning on verification changes the refusal reason or key state. |
| ROTATE.4 | Drive at least 257 rotations using increasing epochs; all current/live-retained kids unique, successor wraps from255 to0, production ring at most7. Check oldest valid payloads each step and a prunable cohort disappears. | unit / wrap + bounded state | Lowest-free reuse, overwriting a live kid, no pruning, or wrong equality count. |
| ROTATE.5 | With small legal mint budget, exhaust current key; additional mints refuse and do not change kid. At age threshold mint succeeds with new-key remaining quota=budget-1. | unit / quota | Budget-triggered rotation, no quota reset, or never rotating an exhausted key. |
| ROTATE.6 | Rendezvous N minters after each observes age-due state and before acquiring the write guard with new-key budget >= N. Exactly N successes and zero errors; one successor installed; all N envelopes open; remaining quota is budget-N and the next mint refuses. | unit / concurrency | Missing write-lock recheck or non-atomic key/kid publication. |
| ROTATE.7 | Rendezvous more minters than the remaining quota after observing the same counter and before reservation, without advancing time. Exactly quota mints succeed, others get MintBudgetExhausted; repeated refusals never restore capacity. Test saturation via internal counter fixture at u64::MAX as an additional guard. | unit / concurrency + arithmetic | Load/check/add race or wrapping counter. |
| ROTATE.8 | First mint at nonzero T stamps once; backward time does not rotate/prune; returning to threshold rotates once. Near-u64::MAX inputs do not wrap retirement/age arithmetic. | unit / clock | Constructor wall clock, zero-origin immediate rotation, or unchecked arithmetic. |
| ROTATE.9 | Real ContinuationState retains its replica identity, consumed ledger and held exchanges across mint-triggered rotation. A previously consumed handle stays consumed; an unspent live handle opens and routes. A second production AppState from same config refuses the first state's envelope before spending. | component / preservation + isolation | Replacing the whole ContinuationState or sharing keys. |
| ROTATE.10 | Preloaded raw-key constructor preserves verification before first mint, assigns retirement on first mint, retains old material for its full window, and never replaces a retained successor. Pair with normal successor rotation. | unit / library compatibility | Dropping imported verification keys immediately or overwriting a live successor. |
| ROTATE.11 | Normal round trip keeps current envelope version and existing binding/AAD tamper refusals. A known injected successor verifier proves its material was used. Exactly one structured rotation event has only message, old_kid, new_kid and retained_keys; Debug/logs omit old/new material and payload data. Collision event fields are similarly exact and bounded. | unit / compatibility + disclosure | Version/AAD drift or key-material formatting. |
| ROTATE.12 | Using the design's real builder + ContinuationState clock and pending InputRequired fixture, actual meta-MCP handle_tools_call flow crosses rotation with its pending exchange intact; completion runs backend once; a duplicate redemption with a fresh idempotency key cannot run it again. | integration / production wiring | Helper-only rotation or replacement of the spending/held state. |
| ROTATE.13 | Separate component mint/open/rotation contention measurements at one/7-key rings from the release-wide actual HTTP NFR.PERF.1 comparison; archive source/build identities and unchanged workload before measurement. Component measurements report latency/throughput; only the actual release workload is graded against NFR.PERF.1 budgets. | performance / release measurement | Lock contention or unbounded retention. Not an assertion-red unit gate. |
| ROTATE.14 | Inject successor RNG error and pre-publication panic; old ring snapshot/quota unchanged, old envelope opens, next normal mint rotates successfully. New state cannot be partly published. | unit / fault atomicity | Mutating retirement/kid before successor preparation. |
| ROTATE.15 | Continuous reader threads repeatedly open valid envelopes while an age-due writer mints; all readers complete an additional open after the due writer signals its write request and rendezvous before write acquisition. Readers keep running until bounded writer completion; joins occur only after bounded completion signals. | concurrency / writer progress | Recursive guard acquisition/deadlock; source lock-fairness contract supplements the observed progress schedule. |

ROTATE.2 stages the old-key envelope at the exact impending retirement instant
using the same internal fixture that tests rotation, without teaching production
mint to bypass its age check. It separately checks ordinary public mint behavior
from ROTATE.1. The wire contract alone cannot observe retained-but-expired material,
so both state snapshot and cryptographic positive control are required.

Fail-fast: verify current key/kid/counter callers with GitNexus and scoped source
reads; review design and matrix; author every non-deferred correctness case with
behavior-preserving scaffolding only; run compiled tests and record genuine
assertion failures plus existing controls. Review those tests separately before
rotation implementation. A helper-only test cannot close ROTATE.9/.12.

The RNG/failure seam is a private successor-key factory; production passes the
existing SystemRandom-backed key construction, tests supply the typed failure
and a pre-publication failpoint. ROTATE.14 uses the real rotation transaction,
not a parallel test algorithm. The controlled clock and exact pending exchange
for ROTATE.12 are fixed in the design's Production clock and integration seam;
root owns the shared builder/invoke hunks coordinated with BRIDGE. No unresolved
clock or RNG design choice is deferred to test authors.

After green: focused caller regressions, fmt/Clippy, critical-path coverage >=95%
and mutation >=85%, self-QA, canonical two code-review legs and isolated functional
driver. Run performance before claiming release readiness; update the source's
stale process-budget/multi-replica comments and the release evidence at the tested
revision. No source commit or release gate is approved by this document alone.

## Takeover implementation checkpoint — tests only

Root verified r2 design/test-plan GPT and Grok SHIP, both actual exits 0:
`gpt-20260906T150407Z-93123` and `grok-20260906T150407Z-93118`.
Actual scope-bound material SHA-256
`9ec00ee2f4de3880c93aae4e4af52e702c5912448aee78ba67a01097c2dbab77`,
45,581 bytes; external `rotation-design-review-r2.*` receipts. The subsequent
255-interval arithmetic correction is exactly the r2 GPT requested LATER repair;
the production 60/300 constants and accepted scope did not change.

The new `src/protocol/continuation_rotation_tests.rs` module currently contains
18 named `rotate_*` cases for ROTATE.1–11, .14 and .15. It observes actual current
key/kid/quota fields without exposing key bytes. Epoch snapshots report None
because the pre-rotation representation has no epoch fields. The raw old-key
sealer is confined to the retirement-equality fixture; all normal cases call
real mint/open. The fault-hook adapter is explicitly pre-implementation compile
scaffolding that delegates to current mint; it must be connected to the real
private successor transaction before those assertions can pass. No age trigger,
RingState publication, pruning or new quota behavior is implemented at this stage.

The focused command awaiting root's serialized Spark slot is:

```sh
cargo test --all-features --lib protocol::continuation::key_rotation:: \
  --jobs 4 -- --nocapture
```

Rustfmt/parser checks pass after correcting a draft Rust pattern annotation;
that parser failure is not assertion-red evidence. Compilation and runtime
results are not yet known. The filter deliberately excludes root's independent
scheduled-cleanup tests, whose no-op/RED state does not establish rotation RED.
ROTATE.12's actual handle_tools_call test is reserved in a separate meta-MCP
module, awaiting root's shared trusted-clock/builder seam. ROTATE.13 performance,
post-implementation concurrency sabotage, coverage/mutation and final DoD remain
unrun. Barrier launches alone are not claimed as deterministic proof that a
missing lock/recheck is caught; the named race falsifiers must be run after green.

Pre-edit GitNexus disambiguated Keyring struct and Keyring::mint LOW with zero
graph callers (Rust method graph omission, not no consumers); Keyring::open
MEDIUM with seven direct callers. The direct open consumers include
retry_origin_backend, redeem_retry, the continuation benchmark and existing
MRTR tests. Static source confirms real mint at invoke.rs:397 and trusted
clock reads at 390/502/546, plus ContinuationState construction and extensive
MRTR/mint-budget tests. Parent owns only the shared ContinuationState clock,
builder/invoke seams and InFlight cleanup hunks; the rotation agent owns Keyring
and the two new rotation test modules. No edits to cleanup semantics or other
agents' source are authorized by this checkpoint.

## Tests review r1 findings and r2 closure preparation

The first Keyring run compiled: 18 selected, 16 assertion failures and two
controls passed, actual exit 101 (`mcp-gateway-v4-rotation-red-r1.log`).
The first actual-builder run compiled: one clock assertion failure and one
immediate-completion control passed, actual exit 101
(`mcp-gateway-v4-rotation-wiring-red-r1.log`). Its failure is actual minted
issued_at=1788711171 versus trusted T=1000. Compiler warnings remain in raw logs;
none is being counted as behavioral RED. These supersede the earlier unknown
checkpoint above; revised r2 runtime results are still pending.

Tests review r1: GPT `gpt-20260906T155515Z-27693` and Grok
`grok-20260906T155516Z-27846`, both SHIP-WITH-FIXES, wrapper exits0,
authoritative process_status=ok, same scope/head and actual material SHA256
`9e0203ecc267f3808df3ae7a7ca70d26d1beb3d4877e4b83f8e99c10b06221dc`,
222847 bytes. Exact receipts and verified bindings are archived as
`rotation-tests-review-r1.{gpt,grok}.{ledger,process}.json` and `.validation.json`
in the external scope-review evidence directory. No NOW finding is waived.

R2 repairs awaiting review closure:

- ROTATE.14 installs cfg(test) successor/prepublication hooks on the real
  Keyring, then calls public mint. The discarded free mint wrapper was deleted.
  Its failpoints remain unused in the baseline, so they still fail assertions.
- ROTATE.6/.7 rendezvous inside the due transition/quota decision and clear
  hooks before controls. During implementation the same observed quota feeds
  bounded CAS; the due barrier is after dropping read and before write. The
  required missing-recheck and non-atomic reservation sabotages remain unrun.
- ROTATE.11 verifies known successor material cryptographically and captures
  exact structured event fields, rejecting disclosure even under unanticipated
  encodings/field names. Collision diagnostic has its own exact event oracle.
  Reused kid2 must authenticate newly generated material and reject the old
  imported token as NotAuthentic. UnknownKey would be incorrect after id reuse;
  generic is_err could pass merely on Expired and has been removed.
- ROTATE.15 observes six real opens after write-request signaling and then
  continuous readers until writer completion. This signal is deliberately
  called write-request, not proof of parking_lot's private queued state. A
  watchdog assertion precedes joins, so an injected deadlock cannot hang the
  runner indefinitely. No statistical starvation guarantee is claimed.
- ROTATE.9/.12 now drive two actual builder-owned MetaMcp instances through
  handle_tools_call. A handle spent before rotation stays spent afterward; a
  pending exchange keeps its state/hold and completes once. Foreign redemption
  actually refuses before its ledger consume probe and never reaches backend.
  Both production owners remain alive throughout. The old direct-ledger unit
  check is only a component control, not evidence of caller ordering.

The combined builder flow expects five backend calls, effects [0,1], authentic
opaque handles, unchanged replica/state identity, preserved pending hold, and
no extra effect from fresh-idempotency duplicate or foreign redemption. Its
companion positive control proves the real backend/builder/child-process fixture
can complete a normal exchange even before clock/rotation behavior exists.

R2 actual compiled RED repeats 18 Keyring cases: 2 controls pass and 16
assertion failures, exit101; builder2: 1 control pass and 1 issued_at assertion
failure (1788711822 versus T=1000), exit101. Logs are
`mcp-gateway-v4-rotation-red-r2.log` and
`mcp-gateway-v4-rotation-wiring-red-r2.log`; eight current lib-test warnings are
retained, no compiler errors. Keyring failure attribution: absent epoch stamp
(8first/10preload), missing age rotation (1–6/8max/9/15), counter rewrite on
saturation (7max), absent collision diagnostic (10collision), unused successor
material/failpoints (11log/14error/14panic). Existing AAD and concurrent
remaining-budget controls pass. The writer/request cohort and due/quota
rendezvous all complete before their downstream baseline assertions fail.

After that run, only helper definitions were moved unchanged to
`src/protocol/continuation_rotation_tests/support.rs` (visibility adjusted to
parent module), keeping the assertions/hooks identical. This avoids adding an
800+ line test file: assertions715/support162, builder module438. Rustfmt parsed
the split; root accepted the existing RED lineage without a redundant behavioral
rerun. The next compile must confirm this module extraction. This structural
change and all moved bytes are included in the r2 tests review material.

## Tests review r2 and exact r3 compile closure

Both r2 vendors returned SHIP-WITH-FIXES, process_status=ok and actual wrapper
exits0: GPT `gpt-20260906T162647Z-29722`, Grok
`grok-20260906T162647Z-29715`. Their actual bound SHA256 is
`bc14ae50aaa9dfd50fd73d57d2d6979b9c4ab64e2c16b1418593ef8cc2dbf880`,
149590 bytes; `.validation.json` verifies scope/head/hash/bytes/process equality.

GPT's sole NOW required compiling the extracted module. That check found real
E0583 plus155 cascading helper-resolution errors: outer `#[path]` changes where
a bare `mod support` resolves. Fixed with explicit
`#[path = "continuation_rotation_tests/support.rs"]`. This was an extraction
compile regression, not behavior RED. The exact fixed tree then compiled on
Spark (root r8 source pins in `focused-delivery-r8-source-manifest.json`):
unit18 =2controls PASS/16assertion RED; gateway2 =1control PASS/1assertion RED,
actual exits101. Raw r3 logs are `mcp-gateway-v4-rotation-red-r3.log` and
`mcp-gateway-v4-rotation-wiring-red-r3.log`. Both trusted clock assertions now
pass under root's separately reviewed wiring; the gateway case reaches the
intended missing-rotation assertion (kid1 == kid1).

Grok's sole NOW correctly distinguished foreign retry refusal from inability to
decrypt: a shared key plus a separate held table could refuse as Gone. The real
foreign path now also requires keyring.open to return NotAuthentic and observes
the complete empty ledger's length before/after, without a consume mutation.

R2 optional improvements adopted: both fault tests also include a successful
rotation and retained key eligible for pruning before the injected failure;
second actual mint directly asserts issued_at=T+60; tracing Visit captures str
and i64 as their types. Successor wire/AAD coverage already exists in the known
successor test: complete opening under its known key, VERSION check, changed kid
authentication refusal. Tuple snapshot entries remain a small documented
observation adapter with exact expected metadata; the named-field suggestion is
nonblocking readability work, with no additional behavior or untested promise.

The reviewed tests gate still awaits paired narrow r3 closure. Keyring runtime
rotation is not implemented. Post-green recheck/CAS/recursive-lock/fault
publication and shared-initial-key sabotages, coverage/mutation, performance and
independent functional drive remain mandatory and unrun.

Tests r3 receipts: GPT `gpt-20260906T173007Z-5655` SHIP-WITH-FIXES;
Grok `grok-20260906T173007Z-5649` SHIP; both actual0/process ok, verified
actual bound SHA256 `2a924de671e08c9d8feeba894927628857b2f04fbb02ecffcd0e8ca63b1e8342`,
101758 bytes. Both previous NOW findings close. GPT added one concrete NOW on
the retained-key variant: it did not retain/open the current key's envelope
after failure. Both fault cases now preserve active_payload/active_token from
the actual successful rotation and assert complete opening at issued_at after
the injected fault, alongside the retired-token and metadata/quota checks.
Grok independently suggested the same repair as an improvement.

Exact r4 runs in isolated source-work/target-work/tmp-work (main and immutable
pre-rotation benchmark source untouched) compile with no compiler errors:
unit18=2controls PASS/16assertion RED and wiring2=1control PASS/1missing-kid RED,
both actual101. Evidence `rotation-{unit,wiring}-red-r4.log`,
`rotation-red-r4.{process,source}.json`. Current local test hashes match the
actual tested files. This is the only new test repair for narrow r4 closure;
no runtime Keyring behavior has changed.

Tests gate CLOSED: r4 GPT `gpt-20260906T174235Z-46672` and Grok
`grok-20260906T174235Z-46677` both SHIP, authoritative process_status=ok,
actual wrapper exits0, exact scope/head/hash/bytes verified. Bound SHA256
`332e88b09cd3a604b3c7f4fe5c51aeda3f788b8a079485157095b8888ab87728`,
60042 bytes. All NOW findings close; implementation may begin. Raw receipts
`rotation-tests-review-r4.*` remain external. Optional named snapshot fields and
duplicated fault-setup extraction are readability suggestions, not missing
acceptance behavior; current explicit independent oracles remain intact.

Fresh pre-implementation impacts: Keyring.open/private key HIGH at depth3, with
7 direct open callers and retry/direct-backend flows; warning reported. Some
same-name Rust methods are misattributed by the index, so static callers augment
the raw rotation-impact-*.json evidence (real mint invoke.rs:397, open routing
and redemption, ContinuationState construction, existing MRTR tests/benchmark).

### First implementation validation and fixture correction

The isolated first implementation passes all 18 unit cases. Its actual-builder
flow exposed a fixture error: a fresh explicit idempotency key did not bypass
response caching, so an already-spent retry returned its previous completion
before the continuation guard. The diagnostic retained calls=4 and effects=[0];
it did not replay a backend effect. The full guard-driving fixture now disables
only response caching for both actual builders, retaining every error, effect,
key, ledger and held-state assertion. The separate no-rotation positive control
keeps the default cache config; it does not close CACHE4/MRTR cache semantics.
Both real-builder cases now pass, actual exit 0. No runtime cache code changed.
Evidence: `rotation-wiring-cache-diagnosis.*`, `rotation-wiring-green-r2.*` and
`rotation-cache-ordering.md` in the external scope-review evidence directory.

Regression runs compile and pass: 41 continuation library cases (18 rotation +
23 lifetime), and all 92 existing `mik_7212_acs` integration cases, actual exits0.
The isolated pre-existing scaffold warnings (3 lib-test/47 library warnings)
remain visible in `rotation-regression-*.log`; they are not a clean Clippy claim.

Six post-green deliberate sabotage runs each compile and exit101 on the intended
behavioral oracle: remove write recheck (ROTATE.6, unequal key IDs); replace CAS
with load/store (ROTATE.7, 24 successes instead of3); retain read lock through
write acquisition (ROTATE.15, five-second completion watchdog); publish before
the failure hook (ROTATE.14, snapshot mismatch); prune live state before RNG
failure (ROTATE.14, retained-key snapshot mismatch); reuse the same initial key
in independently built gateways (ROTATE.9/12, direct foreign open unexpectedly
succeeds while held-state refusal still works). The last mutation changed only
the isolated snapshot's constructor; root's release implementation was untouched.
Every mutant was removed and the exact baseline file restored; receipt
`rotation-falsifiers-restored.json` SHA256
`60a044fd4f266907bd1c1026a77768902c4810f44c19444fad712fa04f1e1497`.
Full command/exit/mutant hashes and logs are `rotation-falsifiers.process.json`
and `rotation-falsifier-*.log`. These six falsifiers supplement, rather than
replace, the pending cargo-mutants score.

Narrow fixture gate CLOSED: GPT `gpt-20260906T181333Z-17786` and Grok
`grok-20260906T181442Z-20658` both SHIP, process_status=ok and actual exits0.
Correct checkout/head, identical scope and authoritative material binding were
verified: SHA256 `21698848979767db8f71be467fff3b5f9e16f5e83b788b49569d1c50906bc2f0`,
55832 bytes, run `mcp-v4-rotation-tests-20260906-r5b`. Earlier r5 both-SHIP
outputs had blank checkout/head fields because the launcher cwd was wrong;
those receipts remain history and do not satisfy this gate. No ledger was edited.
The optional default-cache observation/error-message refinements are not NOW
findings; cache integration remains explicitly parent-owned and unresolved here.

### Self-QA and improvement before code review

The exercise pass ran the implementation and actual caller, found the response
cache masking the guard, repaired the fixture through its own paired test gate,
and then ran all six planned falsifiers. The improvement pass removed the
oversized module through the peer-approved mechanical split and repaired all
nine owned Clippy warnings: checked fixture conversions, compile-time constant
invariant, reused hex encoding, moved a constant, and named the test-only
successor factory type. The long actual-builder test keeps one ordered temporal
flow with a narrow explained Clippy expectation; splitting it would hide the
same-state before/after observations. No production behavior or acceptance
condition changed during hygiene. The extraction body was byte-identical before
the test-only type alias; public `continuation::Keyring` is preserved and every
other new key-ring type remains private.

Exact hygiene tree: Clippy exits0, zero warnings in owned files; 18 rotation and
two actual-builder cases pass. Full historical snapshot Clippy has98 unrelated
warnings, preserved for the release lead's combined clean-build gate. Evidence:
`rotation-final-hygiene-*`, `rotation-clippy-owned-final.json`. Initial combined
coverage passes the critical line threshold:238/250 executable lines (95.2%),
22/22 functions; raw LLVM region result378/408 (92.65%) is reported separately,
not represented as 95% region coverage. Coverage combines41 continuation lib,
two instrumented child-owned actual-builder cases (profiles observed),92 prior
acceptance cases and19 MRTR component cases. All pass. Final hygiene only moves
lines/types and checked fixture expressions; final-source profile mapping and
uncovered defensive-path classification are still to be archived. Parser errors
from the coverage CLI setup are retained and are neither behavior RED nor a
coverage pass. Full55-mutant evaluation is running; no mutation score yet.

ROTATE.16 caller rollback extension is specified in the design's Code finder
repair section. Both actual-builder cases (successor RNG error and TooLarge)
retain a known live old exchange, compare the complete held table and ledger
before/after failed mint, then prove normal later mint and old-handle redemption.
Expected RED is one extra held entry, not a compiler error or generic refusal
alone. The private cfg(test) hook and backend oversized-state switch are compile
scaffolding; the production error arm is unchanged until reviewed RED closes.


ROTATE.16 separate tests gate CLOSED: GPT `gpt-20260906T185217Z-26436`
and Grok `grok-20260906T185217Z-26441` both SHIP, actual exits0,
process_status=ok, correct checkout/head and identical authoritative material
SHA256 `752cab279cc2591761ca41e440832195ce17597aa4cc7ffd5e538f8810379fa0`,
77035 bytes (scope + NUL + frozen stdin). Both actual-builder cases compiled and
failed exactly at whole-held-map equality: the original expiry1300 hold remained,
but the failed mint leaked a second expiry1360 hold. The generic -32003 refusal,
backend call/effect counts, unchanged ledger and counted RNG hook all passed
before that assertion. Evidence: `rotation16-red-r1.*` and
`rotation16-tests-review-r1.*` in the external evidence directory.

Optional test-review improvements are recorded observations, not NOW findings:
the existing child completion marker prefix is inherited from ROTATE12 but its
label identifies each ROTATE16 case; the 9000-byte state deliberately exceeds
the fixed 8192-byte envelope bound and an unexpected successful mint already
fails the refusal oracle; a dedicated oversized-state non-disclosure assertion
can strengthen a later error-response increment. The approved tests and their
RED lineage remain unchanged. The narrow production error-arm rollback is now
implemented; GREEN, sabotage restoration and final finder closure remain pending.


ROTATE.16 runtime repair verified: both new cases pass; the complete focused
library suite passes45 cases (18 Keyring rotation,23 lifetime,4 actual-builder),
and the two existing MRTR integration targets pass92+19. All command exits0.
Clippy exits0 with zero warnings in owned Keyring/test files;98 unrelated
historical-snapshot warnings remain preserved for root's combined release gate.
The rollback-removal sabotage compiles and fails both exact whole-map assertions,
then restores the original source SHA256
`7cb8d843be828c6ae3f9ba7d3d219b0e67b7121a0c85da75f48e7b75054f1bc8`.
A post-run parser initially expected a paraphrased assertion string; it failed
after source restoration. Correcting the parser verified the original red log
without changing tests or repeating the mutation. This parser failure is not a
runtime failure or an extra test result.

Final-source LLVM coverage is253/264 executable lines (95.83%),25/25 functions,
and393/422 regions (93.13%) in Keyring; the caller rollback lines400–403 execute
twice in the instrumented actual-builder child processes. Raw line coverage
includes the compiled cfg(test) hooks. Seven profiles are observed after45+111
passing cases, with four real-builder child profiles; profiles were cleared first.
Every coverage source hash matches the current owned files and shared continuation
and invoke files. Full raw metrics, unforced defensive branches, the untested empty
constructor input and macro instantiations are retained in
`rotation16-coverage-report.json`; no uncovered region is excluded or mislabeled.

The completed Keyring cargo-mutants run reports44 caught,5 missed,6 compile
unviable,0 timeouts among55 generated mutants, actual exit2. The critical score is
44/49=89.80%, retaining all five viable survivors. The survivors include exact
maximum-envelope equality and invalid short-wire error classification gaps;
they are not blanket-classified equivalent. Full outcomes and compiler logs are
archived under `rotation-mutation-r1-full/`. The caller rollback has an additional
manual removal falsifier above; a focused generated-mutant caller run is pending.

ROTATE.13 component measurement is complete: three alternating pre/post pairs,
all actual0, no concurrent build/mutation process at each recorded snapshot,
user services untouched. Single-thread32-byte mint/open p50 moves608→624ns and
512→528ns. Eight-contender same-key p99 moves3.760→7.712µs; barrier-inclusive
throughput moves213509→144089 calls/s. This contention cost is retained, not
presented as an improvement. Due-rotation p99 is1.248µs single-thread and7.184µs
with eight contenders. Per-run ranges, payload sizes, warmup/sample counts,
source/binary identities and background load are in
`rotation-component-measurement-report.md` and its raw receipts. These component
numbers do not grade the parent-owned actual HTTP NFR.PERF1 release budgets.
Final code finder closure, independent acceptance-only drive, and owned build
artifact housekeeping remain open at this record.


The focused caller cargo-mutants run now passes:3/3 caught,0 missed/unviable/
timeouts, actual0; baseline4 actual-builder tests pass. The installed tool's
regex selection unexpectedly retained six unrelated RecoveryContext field
mutations. The preflight rejected that scope before any mutant execution;
`--in-diff` with the exact reviewed four-line rollback correctly selected only
three mint_continuation function mutants. The generated3 supplement the manual
rollback-deletion falsifier; neither is represented as covering the other.
Evidence: `rotation16-mutation-r2-full/`, `rotation16-mutation-r2.process.json`,
and `rotation16-owned-rollback.patch`. No source change was needed for this tool
selection correction. Combined raw score across the two owned runs is47/52
viable mutants (90.38%); per-run89.80% and100% remain visible.


### Final code gate and finding dispositions

GPT `gpt-20260906T191729Z-5197` and Grok `grok-20260906T191729Z-5192`
both SHIP, actual exits0 and process_status=ok. Identical authoritative material:
SHA256 `0d9db8ccd38f049a413e41100a21e9e19fa4acb22aa73361e5bf1d636955929f`,
184082 bytes; correct checkout/head and scope verified in
`rotation-code-review-r2.binding-check.json`. The confirmed unpublished-hold NOW
finding is closed. These receipts approve the code leg; they do not replace the
fresh acceptance-only driver, H8 evidence or parent-owned release-chain checks.

All remaining reviewer suggestions are disposed as recorded observations:

- A truncated authenticated body shorter than a GCM tag currently answers
  NotAuthentic rather than Malformed. This is the unchanged legacy diagnostic
  classification, with no accepted token or repeated effect; it remains a LOW
  LATER observation, also visible in the viable short-wire mutation survivor.
- Preflighting encoded size could save quota/AEAD work for oversized backend
  state, but failed sealing remains safely bounded and now returns held capacity.
  This optimization was explicitly outside the reviewed rollback repair.
- Exact maximum-length inclusivity has a surviving mutation and remains a
  reported test boundary gap inside the passing raw score, not an excluded mutant.
- Additional metric counters could supplement the tested structured rotation
  logs; the existing observability contract requires those bounded events.
- Dropping the ring guard before AEAD, or replacing the CAS reservation with
  fetch_update, would change the reviewed synchronization/fault-observation
  boundary. The measured contention cost is recorded; these alternatives are
  not introduced without their own design and concurrency falsifiers.

No suggestion is silently dropped, no new ticket is needed for a human decision,
and no acceptance condition or assertion was weakened. Final documentation
status/receipt updates occur after the frozen review and change no source.


Owned H8 cleanup is complete: the5.9GB normal debug target and4.1GB instrumented
debug target are removed, and all three owned temporary directories are empty.
Cargo initially refused the copied target because CACHEDIR.TAG was absent; it
removed nothing. After exact task-path/no-symlink/build-directory checks, only
the two owned debug directories were removed directly. Release artifacts needed
for a later independent public-library drive and all required evidence remain.
Receipt: `rotation-housekeeping-complete.json`. Final scoped rustfmt and
`git diff --check` both pass. No source changed after the final code review.
