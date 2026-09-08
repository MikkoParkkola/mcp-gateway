# Approved scope delivery plan

Read [requirements](RELEASE-4.0.0-scope-update.md),
[decisions](RELEASE-4.0.0-scope-decisions-2026-09-06.md) and
[tests](RELEASE-4.0.0-scope-tests.md) together. Verdicts belong only in
`RELEASE-4.0.0-scope-status.json`; do not copy a changing total into this plan.

[Local validation evidence](../release/v4.0.0-scope-contract-validation.md)
distinguishes the implemented release gate from the still-pending product work.

## Ownership and integration

On 2026-09-06 the user transferred full release delivery to Codex:

> now you are taking over the mcp-gateway 4.0 release delivery. I want you to close all the gaps, implement everything needed for that release, do it according to the development-process and dod criteria.

Delivery owner: Codex, checkout `mcp-v4-delivery`, branch
`codex/v4-release-delivery`. The takeover base is
`0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf`. Claude's six uncommitted paths
were captured as a binary patch, checked for stability, and copied into this
isolated checkout; its original `mcp-2026-protocol` checkout remains untouched.
Snapshot SHA-256:
`0e93222f4ac8d8812b94b1241ef7cabb7ac844b3dbc3afba03af0d412332aff4`.
The approved scope contract was then applied together with its checker and
publishing workflow changes. Importing these files is not feature acceptance.

At takeover, the canonical baseline parser reports 28 blocking rows and the
supplemental ledger has 31 pending criteria. The old readiness board and DoD
report are historical evidence, not current completion verdicts. Preserve the
older branches and their uncommitted work until delivery and ownership are
verified; do not reset, stash, or merge into another session's checkout.

## Delivery readiness and checkpoint

FOR: deliver all baseline and approved supplemental 4.0 requirements through
implementation, independent review, real-client acceptance, release gating and
the complete publishing/deployment chain. OUT: the deferred features listed in
the scope update and unrelated portfolio work. No requirement is waived here.

Acceptance is every applicable baseline/supplemental criterion backed by current
evidence, the canonical development process and DoD satisfied, CI green on the
reviewed revision, and published artifacts and deployed behavior verified.
Value is the approved capability expansion and removal of known data-loss and
cross-caller authorization defects; no speculative monetary ROI is claimed.

Duplicate/in-flight audit: reuse the latest bridge, continuation, identity,
authorization and subscription primitives. Six inherited dirty paths have explicit
snapshot provenance. Design/test/source ownership is assigned per increment;
shared dispatch, config and credential integration are sequenced by the owner.

Risks: stale design dispositions can silently narrow approved scope; helper-only
tests can miss production wiring; copied in-flight tests may not compile; shared
credential/cache keys can defeat account isolation. Validate designs against the
approved contract, require real entry-point regressions and an independent
functional driver, and never grade an unavailable or failed gate as passed.

The active DoR/DoD skill points to `~/.claude/rules-source/workflows/` for
`development-process.md`, `quality-gates-dor.md`, and `quality-gates-dod.md`.
These files were read at takeover; older repository copies differ. Each increment
follows reviewed design → reviewed test plan → reviewed failing tests →
implementation → self-QA/improvement → independent code/functional review →
documentation and delivery. Gate applicability and evidence are recorded with the
increment; historical review availability is refreshed, never assumed.

- [x] Snapshot current branch and dirty work; reconcile GitHub/Linear state.
- [x] Import the approved scope contract into the isolated delivery checkout.
- [x] Back up inherited committed head `0d4df3c0` to `origin/codex/v4-release-delivery`;
      local uncommitted edits are not represented by that backup.
- [x] Approve GH462/GH452 design/test plans with both current vendor reviews
      (same material SHA `5de39d7d1ceab1bf1749971626438c2f351ce0660a158233a14cb965c765d1fa`).
- [x] Close the inherited lifetime API compile prerequisite and record assertion-level reds
      (23 observer cases: 16 assertion failures, 7 controls; 111 existing callers green).
- [ ] Complete safety increments (config preservation, session deletion, signing).
- [ ] Complete bridge/confirmation, identity/cache/accounts, tasks/idempotency,
      continuation lifecycle, discovery/transport and operational work packages.
- [ ] Grade conformance, workload, upgrade/rollback, critical coverage/mutation,
      supported client/build matrix and the Spark Open WebUI account journey.
- [ ] Complete independent reviews, tracker evidence, CI, merge, publication,
      deployment verification and cleanup of this delivery's own temporary work.

Validation starts with contract/parser checks and focused failing acceptance
tests, then broadens to Rust suites, fmt/clippy, security audit, coverage/mutation,
real protocol/CLI/browser journeys and final artifact checks. Mac free space was
16 GiB at takeover; Spark has 416 GiB free and Rust 1.98 available, so heavy builds
use a dedicated Spark workspace without changing its running services.

Before each implementation package: refresh its ticket and current source,
claim the target paths with the active implementer through the established
coordination mechanism, review the design and cost, write the discriminating
acceptance tests, then implement. A listed package is a responsibility, not a
claim that a particular agent has accepted it. Takeover assignments are explicit:
root owns lifetime/idempotency integration and delivery; config, session ownership,
signing, bridge and account workers own their named increments. Workers share
this delivery checkout, preserve other edits and wait for reviewed tests before
behavior implementation. The original Claude checkout remains untouched.

## Work packages and dependency order

| Package | Responsibility / target areas | Depends on | Required exit evidence |
|---|---|---|---|
| SAFETY | #462 config read-modify-write; #452 legacy session handler; gateway signing startup/config | Current implementation inventory | Invalid-config byte preservation, owner/nonowner behavior, enabled-signing startup behavior through production entry points |
| BRIDGE | MIK-7387 stdio loop/writer; MIK-7388 production pending ownership | MIK-7212 HTTP/MRTR contract; stdio design and estimate | Existing stdio ACs enabled and passing; live peer cancellation and both applicable bridge directions |
| TASKS | Tasks executor/store, routes, notification integration and lifecycle | Stable public dispatch and identity context; reviewed persistence/recovery design | Full task lifecycle, reconnect/restart fault tests and no silent side-effect replay |
| ACCOUNTS | B/C storage/consent fallback, credential resolution, MIK-7334 cache isolation | Selected Open WebUI on Spark → gateway → Google Workspace journey; revised ADR-008/6746 boundary; reusable identity/connection implementations | Two-account journey, refresh/revoke/restart, public route parity and no shared fallback |
| DISCOVERY | MIK-3274 ranker; existing tiered disclosure, derived exposure, schemas and surfaced tools | Frozen held-out baseline; current authorization/cache context | Outcome improvement plus exact/glob/authorization regression controls |
| OPERATIONS | MIK-7235 catalogue policy; MIK-6710 audit read implementation | Pin selection criteria; audit filtering/work-bound design | Valid pins/exclusions and bounded audit work with equivalent results |
| VALIDATION | Conformance, workloads, upgrade, current critical-path quality, demos and all publishing gates | Integrated packages | Recorded evidence applicable to the final release candidate |

SAFETY and baseline characterization can proceed independently. The reference
journey is selected. TASKS and ACCOUNTS require separate reviewed designs; token custody,
crash recovery and cancellation must not be designed as helper-only patches.
BRIDGE and ACCOUNTS both touch dispatch; sequence their integration with the
current owner. No calendar estimate is inferred from ticket ROI or test count.

## Required design amendments

- MRTR increment: legacy stdio remains out of the HTTP-only increment, but is
  now explicitly in the release. Preserve the existing initialize barrier and
  frame serialization tests. Retain the established refusal when a capability
  is unavailable; do not turn absent client capabilities into fabricated input.
- Tasks increment: add a companion executor/store/routing design to the
  existing schema design. Specify atomic create-before-ack, principal binding,
  cancellation/settlement races, TTL/results limits, interrupted operations and
  upstream recovery. Choose numeric limits from workload/resource measurements
  before implementation; that engineering choice does not reopen inclusion.
- Auth: revise the superseded count-based multi-user formula and A+B+C+D gate
  in old ticket bodies. Reuse ADR-008's preferred external authorization and
  fallback-only custody. Specify consent state binding, expiry/replay defense,
  key custody, encrypted storage, token audience and provider revocation. The
  old custom passthrough header does not prove a standard client auth flow.
- Account adapter: for the selected Open WebUI journey, reconcile MIK-6207/6209 against
  current verified identity plumbing and remove wrong-repository administrative
  ACs. Reuse the existing Spark deployment after recording its configuration and
  versions. Validate an actual distinct identity per request through any mcpo
  hop; running bridge containers alone do not prove the acceptance route.
- Ranking: measure before changing the algorithm; freeze thresholds and corpus
  then integrate. Preserve Code Mode glob bypass. Do not promise general typo
  correction from a sequential-character scorer alone.
- Audit: a result limit is not a work limit with arbitrary filters. Choose an
  indexed query or a documented bounded scan with continuation; preserve API
  semantics or explicitly version the behavior. Verify rare-match cases.

## Existing work to reuse and tracker reconciliation

| Record | Action at integration |
|---|---|
| MIK-7387, MIK-7311 | Mark release inclusion settled; keep implementation/design evidence open. |
| MIK-6744/6745, MIK-3274, MIK-7235, MIK-6710 | Associate with 4.0 and the supplemental acceptance IDs. |
| MIK-7334 | Supported personal catalogues require isolation; the invariant-catalogue-only shortcut no longer covers that supported mode. |
| MIK-6746 | Derive remaining standard/route interoperability from current code and older implementation comments. |
| MIK-6735, MIK-6750, MIK-6905/6906/6908 | Already delivered mechanisms: verify and reuse; do not recreate based on an open parent. |
| GitHub #449 / MIK-7332 | Correct stale 4.1 association; already approved for 4.0. |
| GitHub #451, #440 | Check current served behavior and delivery before closing; component implementations exist. |
| GitHub #475/#481/#482 | Keep active error-budget work and typed/observable real-path tests with its current owner. |
| MIK-7116, MIK-7217, MIK-7377 | Close only gateway release ACs; split broader model/portfolio obligations explicitly. |

This package does not post comments, mutate remote milestones or instruct the
active agent. Those integrations remain visible handoff work, not assumed done.

## Release check semantics

`python3 scripts/release/check_scope_acceptance.py --check` verifies plan and
ledger consistency, including the existing counter, and reports pending work.
`--release` also requires no baseline blocking row, no pending supplemental
criterion and no unanswered required decision. Both use the same data.

The gate is added to the existing publishing dependency chain in `release.yml`,
`ci.yml` and `docker.yml` for `v4.0.0` tags (including prerelease suffixes) and
the release workflow's manual `tag` input. Other versions retain their existing
gate behavior. This is a local workflow change until integrated and run in CI.

Before recording MET: review actual acceptance evidence, place its repository
path in the JSON row, and explain its scope in `note`. A script's existence is
not evidence that a product feature passed. The verifier intentionally does
not replace the deferred execution-to-evidence attestation project.

## Delivery lead engineering rulings

On 2026-09-06, the release lead resolved NFR.SEC.3 design Q1 in favor of
per-process live key rotation (option C). The unchanged criterion requires
versioning, rotation and retained verification for the continuation lifetime;
it does not prescribe shared/operator-supplied key material. Preserve the MRTR.5
production-constructor key-separation case and the approved topology boundary.
The prior status-row assumption of configured shared keys and a shared ledger
is superseded, not treated as an additional operator requirement. This is a lead
implementation ruling under the takeover instruction, not a fabricated user
selection. The criterion remains ABSENT/blocking until implementation and evidence.

## Verified checkpoint — 2026-09-06 14:20 UTC

Local work remains uncommitted; the remote branch still contains only the inherited
0d4df3c0 base. No PR merge, service deployment, restart or release tag is claimed.

- GH452 owner-aware DELETE is implemented. Spark all-feature integration suite:
  11 passed; existing streaming library regressions: 14 passed. Paired final code
  reviews and copied-tree mutation work are running; isolated functional drive and
  critical coverage remain required. Stable sources match the tested Spark copy.
- GH462 repaired tests compile and expose 29 intended integration assertion failures
  with 12 controls, plus 1 binary assertion failure with 2 controls. Separate tests
  closure review is running; production preservation changes are still pending.
- MRTR8b observer adapter compiles and all 111 existing caller regressions pass.
  Strengthened tests use two expired keys and unrelated route/complete targets;
  16 assertion failures/7 controls. Test closure review precedes behavior changes.
  Mandatory scheduled expiry has a separate reviewed-design pipeline and cannot
  be credited from observer correctness.
- Signing MIK7406 and response firewall MIK7407 are In Progress in v4.0.0, assigned
  to Mikko. Signing has live blocked-by relations to MIK7407 and MIK7272 SUB4;
  its original stable MIK7377.SIGNING1–6 identifiers are retained. Firewall's
  final delivery-attempt event records a hash after filtering/signing, before
  write, and never claims client receipt. Design/test closure remains in progress.
- Full accounts, bridge, tasks/SUB4 and key rotation designs are being reconciled
  with test plans and canonical review receipts; none is runtime acceptance.
- Parser checks pass: 146 baseline criteria/182 rows/28 blocking; supplemental
  contract 31 criteria still pending. These are validation snapshots, not manually
  maintained release verdicts. Release publishing remains blocked.

External evidence directory: the operator's Codex scope-review folder for this
date. Spark logs are retained there with test command names. cargo-llvm-cov0.9.0
was installed and version-checked on Spark for critical-path validation.


## Verified checkpoint — 2026-09-06 15:10 UTC

- Local changes remain uncommitted and unpushed; remote delivery branch remains
  inherited 0d4df3c0. Original Claude worktree remains preserved. No release tag,
  PR merge or service deployment is claimed.
- MRTR8b Change A: 23/23 focused tests and 111/111 caller regressions pass.
  Both final-code reviewers SHIP, bound SHA256
  541396df9fe501cd6ea9895559ce56625b4f04b53b15eea14367358716d872e7,
  119391 bytes, actual exits 0. Local source regions 78/78 covered across InFlight
  and reclaim_abandoned; no branch-coverage claim. Copied-tree mutation run has
  green unmutated baseline and 47 candidates; score pending. Mandatory Change C
  remains unimplemented pending focused performance-contract repair closure.
- GH452: both final-code reviews SHIP; 56/56 changed-function source regions
  covered. Mutation baseline green, 10/11 caught = 90.9%, one production-unreachable
  inner-auth mutant retained in denominator. Independent drive r1 stopped before
  launch due subprocess network restriction; no AC exercised. Coordinator SSH
  worked. R2 uses authorized fullaccess and has verified pinned binary hash;
  functional outcomes remain pending.
- GH462: 44 integration, 4 binary, 13 persistence, 78 reload, 8 setup, 13 add/remove
  and 2 discovery-writer tests pass. Reduced-feature E0609 exposed an unconditional
  cost_governance field reference. Small cfg-propagation repair compiles and all
  36 reduced-feature cases pass; all-feature confirmation and final DoD continue.
- All-feature library characterization remains 4077 passed / 1 failed / 4 ignored.
  Sole failure is typed capability 429 (RL10); no all-library green claim. #481 now
  has assigned owner, bug/high priority labels, 4.0.0 milestone and explicit RL10
  unchecked AC. Original intake remains historical, other rows remain separate.
- Account design/test plan increments1–3 have paired review plus finder closure;
  source/red-test work starts next. Signing, bridge, response firewall, key rotation,
  and Tasks/SUB4 are in focused repair closure. Their docs are not runtime evidence.
  Shared response finalization is protocol shaping → firewall → signing → immutable
  delivery-attempt hash → serialization. Finalization refusals must not charge or
  reset the caller failure circuit.
- SUB4 lead engineering ruling: no automatic body-derived key; read-only keyless
  repeats stay independent, external writes/unknown mutability require explicit key
  and stable verified identity. Same principal/key has one atomic Sync/Task owner;
  mode or representation changes cannot repeat an effect. This implements the
  existing MUST, with compatibility notes required; it is not an invented user vote.


## Verified checkpoint — 2026-09-06 15:40 UTC

- GH452 independent HTTP drive completed: seven ACs PASS, no skipped cases;
  pinned binary6d128266e994. Original streams, cross-owner isolation, anonymous
  and public-path refusal, and one concurrent scheduling case observed. Driver
  processes/ports cleaned; raw inconclusive first requests retained with corrected
  repeats. Local only, not committed/merged/released.
- GH462 completed its increment evidence: both code SHIP, 44 all-feature +36
  reduced-feature cases, 92 independent public checks. Fixed critical windows
  29/29 executable lines and55/55 source regions covered; raw generic/async
  instantiations85/208 retained separately, no whole-file/branch claim. Mutation
  8/9 viable caught (one informational-message survivor),2 compiler-unviable
  excluded rather than counted as kills. Independent evidence audit found no
  calculation defect. Internal nonpublic clauses use reviewed component evidence,
  marked N/A-to-public-drive rather than invented driver passes.
- A-only mutation run: 47 generated,17 caught,30 compiler-unviable,0 missed or
  timeouts; actualexit0. 28 unviable proposals manufacture an unsupported
  MutexGuard constructor; two require absent Default implementations. Full logs
  retained. No compiler failure counts as caught. Explicit guard-call/retention
  boundary probes remain to complement this generator limitation before combined
  A+C closure.
- Cleanup worker scaffold compiled with8 assertion failures; tests review GPT
  requested stronger exact-time/barrier/termination oracles, Grok SHIP. Repairs
  staged, worker still no-op; new private serving owner/context types are scaffold,
  builder/transport cleanup still unwired. Scope remains full A+C expiry.
- RL10 compiled tests20:13 controls pass/7 assertion failures. Latest WARN-only
  capture preserves approved diagnostic scope; paired test review running.
- Bridge initial9 conformance tests all assertion-red; amended16-case matrix is
  being re-driven and finder-reviewed. Existing23 cases remain separately required.
- Account foundation9 tests plus2 lock tests ready for first compiled red. Key
  rotation r2 design/plan bothSHIP; config-preservation worker now owns Keyring
  tests/implementation while root retains InFlight and shared trusted-clock seams.
- All source still uncommitted. Release parser checks remain146 criteria/182rows/
  28blocking and31supplemental pending; no acceptance grade raised from these
  checkpoints alone. Final integrated fmt/Clippy/CI/release gates remain open.


## Verified checkpoint — 2026-09-06 16:25 UTC

Work remains local/uncommitted on the delivery branch; its remote backup still
contains only the takeover base. No PR merge, release, deployment or service restart
has occurred. Claude's original checkout independently advanced six documentation
commits to `7f87851c`; those four changed documents were reconciled here with the
exact Q4 authorization preserved. The original checkout was not edited. Its newly
uncommitted spec-preview test patch is preserved externally, not yet imported.
The first merge script mishandled conflict-marker delimiters; the partial result
was repaired against preserved three-way snapshots and all four files validated.

- GH462 config preservation and GH452 session DELETE retain their previously
  recorded independent-drive, code-review and quantitative evidence.
- Bridge mode/schema/ElicitResult component: all43cases, all10metadata tests and
  all19MRTR regressions pass. Independent coverage reports new elicitation module
  171/171lines and295/296regions; a duplicate-required-name review finding is now
  receiving a test-first repair. Full transport bridge/stdio/capability wiring
  remains mandatory and in progress.
- RL10 typed429 implementation: focused30/30pass; isolated regressions101executor,
  13recovery,9errorbudget,1RPCpass. First integration attempt did not execute tests
  because root builder test adapters lacked a CleanupRuntime import; fixed and
  rerun green. Manual typed-status probes and final review/driver are pending.
- Scheduled cleanup worker:9focused tests and23observer lifetime regressions pass.
  Isolated clean-profile coverage covers every worker and table-reclaim region;
  whole cleanup module coverage is only39/46regions because default/clock builder
  scaffolds are not yet exercised. Do not claim95%wholemodule or production
  lifecycle closure. Three separately reviewed real-builder tests currently fail
  at the expected missing clock/worker wiring. HTTP/stdio I/O lifecycle and
  performance remain required.
- Rotation tests:18compiled,16expected assertion failures and2controls pass;
  actual builder flow1controlpass/1clock-wiring failure. Test-hook sensitivity
  repairs and helper extraction are being closed before rotation implementation.
- Personal-account foundation:15compiled tests,14expected assertion failures and
  1Debugcontrolpass. Both test finder closures are SHIP and implementation began.
- Signing initial5tests:4expected assertion failures, disabled compatibility
  controlpass. Repaired false-green oracles are in finder closure; the full
  cryptographic/nonce/config/delivery matrix remains required. Spark Node22.23.2
  actually preserves the2^63token in JSON.parse reviver context.source.
- Response firewall:18componenttests8pass/10expected failures; corrected modern
  HTTP, legacy HTTP, both direct route modes and2stdio probes expose actual leaked
  results after successful benign/backend-count controls. The first modern probe
  was a missing-metadata fixture error and is superseded by its verified rerun.
  Six discovery probes have compiled and their failure attribution is under review.
- TASKS/SUB4 design finder closure is SHIP. Mandatory keys apply to modern calls;
  existing3.5unkeyed behavior stays compatible. One shared execution admission
  owner, durable task recovery, byte/count limits and the same-audience verified
  identity collision fixture remain implementation obligations.

Release parsers still report146criteria/182rows with28baseline blockers and all31
supplemental scope criteria pending. No acceptance grade was raised from planning,
scaffolding, review verdicts or isolated component tests.


## Verified checkpoint — 2026-09-06 17:20 UTC

Delivery is incomplete. All six parallel agents stopped when the Codex account
hit its usage limit. The required GPT finder reviews for the repaired bridge
component and response-firewall tests also exited with a usage-limit error;
there is no verdict for those runs. The user was asked whether to restore credits
or wait for the reset. This is an external review blocker, not permission to waive
the development process. No release, merge, deployment or restart has occurred.

The release lead continued the already reviewed builder implementation and
validation:

- The real builder creates continuation state with the shared trusted clock and
  starts cleanup with a serving owner that aborts the worker on drop. Three
  builder lifecycle tests, three existing builder callers, constructor parity,
  nine worker cases, 23 observer cases and 19 MRTR caller regressions pass.
  These are 58 focused/regression cases; real HTTP/stdio I/O lifecycle and
  performance are still required. The strengthened shutdown test observes two
  scans, retains a MetaMcp clone, and proves an expired record remains untouched
  after owner drop. The child harness has a 45-second watchdog.
- Current-source LLVM coverage is 46/46 regions and 40/40 lines for the cleanup
  module, and 6/6 regions for serving-owner methods. No branch-coverage claim.
  Both explicit expiry faults (remove reclamation; expire equality) are caught
  by compiled assertions; exact source restoration returns 23+9+3 tests to green.
  Evidence: external `root-expiry-quant-r1`.
- Account foundation: 15/15 tests pass in both main and isolated builds. All eight
  explicit storage faults are caught by their intended compiled assertions;
  exact source restoration returns 15/15 to green. FIFO/file-type hardening,
  service operations, OAuth and the Open WebUI reference journey remain open.
  Evidence: external `accounts-foundation-quant-r1`.
- Rotation's repaired 18 unit tests compile: two controls pass and 16 expected
  behavior assertions fail. The real-builder pair now reaches missing rotation
  rather than missing clock wiring: one control passes, one expected failure.
  The isolated pre-rotation benchmark binary builds; no measurement was run.
  Keyring rotation implementation awaits its test finder closure.
- Signing config has two passing controls and 11 expected failures. The 10 v2
  Rust-vector tests compile with one unsigned-error control passing and nine
  expected missing-v2 failures; some deeper tampering assertions remain behind
  their failing valid-signature controls. The independent Node verifier passes
  all 11 tests on Spark. No signing runtime acceptance is claimed.
- Response firewall: repaired component tests are 14 engine cases (six pass,
  eight expected failures) plus five marker cases (two pass, three expected
  failures). Four challenge cases compile with one control pass and three
  expected failures. The component Grok finder leg is SHIP; GPT is unavailable.
  Both public-route test ledger rows are SHIP, but the interrupted Grok tool
  session's direct exit receipt has not been recovered, so final verification
  remains pending. Runtime enforcement is still scaffolded.
- Bridge component: 46+10+19 tests pass on the isolated repaired source; six
  explicit faults are caught with restored controls green. GPT code-finder
  closure failed at the account limit. Full transport wiring remains open.
- RL10: the original implementation retains 30 focused greens, the original
  paired code review, and 16/18 viable generated faults caught (four compiler-
  unviable candidates excluded, two survivors retained). A confirmed reqwest
  reason-phrase leak prevents closure. Its repaired plan now requires a canary
  after `without_url()` with `url()` absent, on the same raw fixture used by all
  three executors. GPT original plan SHIP plus Grok finder SHIP are verified;
  the new gateway regression tests and source repair remain to be implemented.
- Claude's original checkout advanced to `0527aacc` with one additive ORDER.2
  sessionless-promotion test. It was imported after confirming this file had no
  delivery edits; its first actual compile/run passes. The original checkout and
  its six dirty files remain untouched. Full ORDER.2 stdio work remains open.

Validation failures were preserved and diagnosed: the extracted rotation helper
needed an explicit module path; the first new signing-seam sync omitted its vector
fixture file. Neither compiler failure counted as a behavior red. Both were
repaired before the recorded tests ran. The test driver now also halts on Cargo's
plain `could not compile` diagnostic. A review-receipt check initially assumed a
newline delimiter; the actual wrapper uses `scope + NUL + material`, which was
verified against the ledger before recording the Grok plan closure.

All source changes remain uncommitted on `codex/v4-release-delivery`. The remote
Git branch still contains only the takeover base; a separate source checkpoint
archive preserves unfinished work. The release parsers still report 28 baseline
blockers and all 31 supplemental criteria pending. No acceptance grade was raised
from component tests, coverage, plans or incomplete reviews.

## Verified checkpoint — 2026-09-06 17:58 UTC

The account-limit interruption recorded above is resolved. Required GPT reviews
now complete successfully, and all six delivery agents have resumed. This does
not waive or complete any release gate.

- Response enforcement now passes 14 engine tests, five native error-projection
  tests and the broader 135-test firewall suite. The 135 include the 14 engine
  cases. Production transport/finalizer wiring is still incomplete. The corrected
  challenge suite compiles with one disabled control passing and four intended
  assertion failures; the ten finalizer cases have one control passing and nine
  intended assertion failures. Neither red suite is accepted as implemented.
- RL10's custom reason-phrase repair passes all 34 focused tests in its isolated
  source lane. Both test-review legs are closed. Final code review and refreshed
  quantitative evidence remain pending; the previous original-code review does
  not cover this new repair.
- Key rotation's corrected unit/builder tests cleared both finder reviews.
  Implementation is underway in the isolated rotation lane. No runtime rotation
  or benchmark result is claimed yet.
- The repaired signing configuration tests compile with two controls passing
  and 12 expected failures. Earlier supposed short-key falsifiers accidentally
  used 33-byte strings and are withdrawn; the rerun pins actual byte lengths.
  Vector test review, implementation and production response delivery remain open.
- The bridge component's final finder closure is verified. The next transport
  channel tests are in review; full HTTP/stdio exchange remains unwired.
- Account FIFO hardening has cleared its test gate. Its repaired case passes,
  but the full account run exposed a concurrent initialization/reopen failure
  that is under investigation. Full store/service and OAuth remain incomplete.
- The HTTP/TLS cleanup design review found missing precision in the runtime seam
  and a missing TLS-specific startup-error case. The design is being corrected
  before scaffolding. Existing builder/worker evidence remains component-only.
- Original-checkout commits through `5d359559` contributed committed ORDER.2
  evidence and a corrected PERF.4 diagnosis via a clean three-way document merge.
  The surface can reach 13 as well as 17 tools; the 14–16 contract needs both
  bounds enforced. The original checkout's dirty work remains untouched.

Current main-lane test logs and source pins are preserved externally under
`mcp-gateway-v4-scope-review`, including `firewall-engine-green-r1-source-manifest.json`
and the `mcp-gateway-v4-*-r1/r2.log` files. Source changes remain local and
uncommitted; the remote Git backup still contains only the takeover base. Full
conformance, performance, client journeys, upgrade/rollback, integrated CI,
publication and deployment verification remain mandatory.

## Verified checkpoint — 2026-09-06 18:59 UTC

Release grades remain unchanged: component evidence does not complete integrated
acceptance. The current source remains uncommitted in the delivery worktree.

- Root snapshot r14 passes signing v2 vectors10, response-challenge enforcement5,
  firewall engine14, rotation units18 and actual builder rotation2. Finalizer15
  compiles with one control pass/14 intended failures; signing delivery13 compiles
  with two controls passing/11 intended failures. The first engine rerun used an
  incorrect filter and ran zero tests; its result is excluded. Corrected r14b ran
  all14 and passed. Logs and per-file hashes are in the external review directory.
- RL10's reason-phrase repair cleared both final code reviews and caught16/18
  viable generated mutations. Independent functional r2 failed: HTTPBingo returned
  402 to gateway requests, and the supplied GraphQL fixture did not dispatch.
  Four controlled direct curls isolated HTTPBingo's User-Agent prerequisite:
  default-header requests returned429; no-User-Agent requests returned402, with
  or without the canary query. The coordinator's GraphQL YAML instructions also
  used an unsupported top-level query field. Corrected independent r3 uses the
  supported body.query and explicit synthetic User-Agent on the same pinned
  binary; its result is pending. No functional acceptance is inferred from r2.
- Rotation generated mutation evidence is44/49 viable caught (89.80%), with five
  survivors retained and six compiler-unviable candidates separately recorded.
  Final code review identified an unpublished hold stranded after failed mint;
  two actual-caller regression tests now expose that gap. Repair is in progress.
- Account primitive reopening exposed inherited file-lock lifetime on concurrent
  child creation. The minimal explicit-unlock repair passes its two focused tests
  plus shared-lock caller regressions and40 four-thread primitive soaks. Final
  code/quantitative gates and the account store/service/OAuth journey remain open.
- Raw bridge channel tests and component regressions pass. SSE test review has
  produced stronger no-frame and body-drop oracles; full HTTP/stdio wiring and
  authenticated client exchanges are still pending.
- A real partial-write probe reproduced audit-log corruption after write failure
  and restart. This is a release blocker under CONTROL.3/MIK-7407. Its repair must
  preserve the existing4MiB startup-scan bound and coordinate concurrent writers
  before repairing only an incomplete suffix; no logger repair is claimed yet.
- The targeted chacha20 lockfile update to0.10.2 removes the yanked dependency
  warning. Cargo audit reports no vulnerabilities or warnings on that snapshot;
  new/updated crate checksums and license declarations were verified. The x86
  runtime/CI gate remains necessary. CI and release-test jobs now explicitly pin
  Node22.23.2 for the independent signing verifier; actionlint passes locally.
- MIK-7212 now retains its original criteria and also records unchecked stable
  criterion MIK-7212.MRTR.8b with the eight-case HTTP/TLS lifecycle mapping. Live
  readback was verified after accounting for Linear's standard issue mention and
  trailing-newline normalization. The HTTP P1 finder closure remains pending.

Full tasks/idempotency, personal OAuth, transport bridge, response/signing
delivery, catalog/pins/ranking, conformance, performance, Open WebUI on Spark,
upgrade/rollback, integrated CI and release publication remain required. This
checkpoint neither waives them nor converts plans or expected failures to passes.
