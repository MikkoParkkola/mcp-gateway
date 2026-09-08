# Approved scope delivery plan

Read [requirements](RELEASE-4.0.0-scope-update.md),
[decisions](RELEASE-4.0.0-scope-decisions-2026-09-06.md) and
[tests](RELEASE-4.0.0-scope-tests.md) together. Verdicts belong only in
`RELEASE-4.0.0-scope-status.json`; do not copy a changing total into this plan.

[Local validation evidence](../release/v4.0.0-scope-contract-validation.md)
distinguishes the implemented release gate from the still-pending product work.

## Ownership and integration

The active implementation checkout is `mcp-2026-protocol`, branch
`fix/mrtr2-continuation-handle`. This contract is prepared independently on
`codex/v4-scope-contract`, initially based on `ec9c0d9ad8c5b3f3c171eb019a1a141fd06cbf76`
and fast-forwarded independently to `487d761dc58ebf47830f31e01c8488d39ae39e28`
before final validation. The active checkout was not changed by that refresh.
At the boundary check Claude was editing transport/TLS documents and drafting
CACHE.4 policy-epoch work. No runtime source or existing Rust tests are edited
by this package. Do not reset, stash or merge into that active checkout.

Integration owner: the release integrator. Import this contract as a small
reviewed change when the active branch is ready; reconcile the short links in
existing plans if their surrounding text moves. Preserve concurrent runtime
work and its new evidence. The workflow and checker additions must travel
together. No feature is completed by importing this documentation.

Before each implementation package: refresh its ticket and current source,
claim the target paths with the active implementer through the established
coordination mechanism, review the design and cost, write the discriminating
acceptance tests, then implement. A listed package is a responsibility, not a
claim that a particular agent has accepted it. No extra agents are assigned here.

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
