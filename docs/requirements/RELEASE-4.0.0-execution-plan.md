# 4.0.0 — execution plan to a passing DoD check

**Superseded historical record. It is not the authority for anything.** It was written as a
durable checkpoint of what remained, and the work it lists has since been done or re-owned. Read
it for why decisions were made. For scope, read `RFC-0061-protocol-2026-07-28-release-scope.md`
and `RELEASE-4.0.0-requirements.md`; for current status and what is still open, read
`RELEASE-4.0.0-dod-check.md`, which is the only current account. Every "remaining", "blocking"
and "next" below describes the state at the time of writing, not the state now.

## State at the time of writing

Superseded checkpoint, kept for its rationale rather than its status. It was written when the
branch stood 175 commits ahead of `main` with no open PR and the DoD check recorded §3, §4,
§5 and §8 as passing. The current status lives in `RELEASE-4.0.0-dod-check.md` and nowhere
else: §4 is now BLOCKED on unmeasured coverage and mutation (MIK-7324), and retry forwarding
is refused rather than implemented (MIK-7325). Read the sections below for why each decision
was made, not for what remains.

## Blocking gaps to a passing DoD check

| # | Gap | Gate | Disposal |
|---|---|---|---|
| 1 | Consumed-continuation ledger is process-local; a second replica spends one continuation twice | §11 stop-the-line, gated BEFORE-PRODUCTION | DEFERRED to 4.1.0 under the single-replica constraint below |
| 2 | Mint counter is process-local, so a restart resets the NIST envelope bound | same | same shape as #1 |
| 3 | Task model unverified — the specification page 404s at the indexed path | §12 finding, unverified | re-fetch from another path; if still 404, record as residual with an owner |
| 4 | Failed-task payload shape unverified, same cause | same | same |
| 5 | §12 ran ONE vendor over eight rounds; the gate requires two | §12 BLOCKING | second vendor pass when quota returns (grok and kimi are both rate-limited as of 2026-08-29) |
| 6 | MIK-7256 has a reviewed design and test plan, no tests and no implementation | §P2 onward | next in the pipeline |

### Gaps 1 and 2 — deferred, and on whose assumption

The DoD check hands the operator two options: ship 4.0.0 as legacy-safe groundwork with the
modern path documented as preview, or hold the tag until these close. This plan proceeds on
the first. **That assumption has not been put to the operator**, and one line overturns it.

It is the cheaper branch and it is reversible: both gaps bind only on multi-replica
deployment, `server.modern_protocol` defaults off, and no client can reach either. Holding
the tag buys nothing that a default-off switch and a written constraint do not already buy.

Deferred, carrying the four fields §P1 requires:

| field | value |
|---|---|
| owner | **MIK-7312**, filed before the tag, not "we" |
| what would resolve it | a shared atomic insert-if-absent store behind both the ledger and the mint counter |
| when | before the first multi-replica deployment of the modern path, whichever release that lands in |
| what if it resolves badly | the modern path stays single-replica; the release notes carry the constraint, and the deployment documentation refuses multi-replica while `modern_protocol` is on |

Nothing in 4.0.0 may depend on either gap being closed. The release notes and the
deployment documentation carry the constraint as shipped text, not as a plan to write it.

## Gates must be re-run at the head that is tagged

The §3, §4 and §5 verdicts in the DoD check are recorded at head `c4f4781a`. Every commit
since then, and MIK-7256's implementation, invalidates them. Clippy, fmt, the secret scan
and the full test suite are re-run at the final head before any of those gates is claimed.
Local `cargo` is halted by the disk guard, so that run goes to Spark via `spark-run`.

## §12 cannot pass today, and the clock is running

The dual-vendor bar is unmet: grok is at its Copilot free-tier limit and kimi returns 429.
The finder-unavailable clock under the repair protocol started at the round-18 launch,
**2026-08-29 19:15 UTC**. Everything except §12 can reach green without them.

## Ticket hygiene the goal requires

- Six tickets are recorded in RFC-0061 as shipped in 3.5.0 and closable without work:
  MIK-7258, MIK-7257, MIK-7243, MIK-7245, MIK-7244, MIK-7265. Each needs the claim
  VERIFIED against 3.5.0 code before it is closed, then closed with the evidence comment.
- Three are re-scoped and must not be implemented: MIK-7251, MIK-7250, MIK-7042.
- In Review in Linear: MIK-7217, MIK-7214, MIK-7213, MIK-7215, MIK-7212, MIK-7116.
  Their Linear state must match the branch: implemented but unmerged, no PR.
- Backlog: MIK-7218, MIK-7219, MIK-7216.
- MIK-6729 is no longer Blocked. Its blocker was recorded all along, in the description
  rather than as a Linear relation: the identity-propagation trait. That trait exists on
  this branch (`src/identity_propagation/mod.rs:160`) and the ticket's own strategy is
  implemented against it, so the block was satisfied and stale. Now In Review.
- No GitHub milestone or open PR exists for 4.0.0.

## Order

1. Verify and close the six no-work tickets; fix the three known-wrong Linear states.
2. MIK-7256 through the process: failing tests, implementation, self-QA, review, docs.
3. Gaps 3 and 4 are resolved as checks and turned into defects: the tasks specification
   was found at `/extensions/tasks/overview`, and the branch is short of it by two
   statuses, two required fields, an error payload shape and a capability check. The
   extension ships not implemented — the capability key is not advertised, so no client
   negotiates it (DoD check, disposition of 3 and 4). Verify in code that nothing offers
   the key, and say so in the release notes. Tasks conformance is owned by MIK-7311 and the
   two multi-replica gaps by MIK-7312, both filed. Put the single-replica constraint into
   shipped text.
4. Bump the version to 4.0.0 everywhere it is written down. `Cargo.toml` still reads
   `3.5.0`, as do `deploy/helm/mcp-gateway/Chart.yaml` `appVersion`,
   `deploy/helm/mcp-gateway-crds/Chart.yaml` `appVersion` and the image tag in
   `deploy/helm/mcp-gateway/values.yaml`. The chart's own `version` tracks packaging and
   moves on its own. Nothing in this plan bumped them, and a 4.0.0 tag built from a tree
   that calls itself 3.5.0 ships a lie in the binary's `--version`.
5. Re-run §3, §4 and §5 on Spark at the final head.
6. Second-vendor review pass **against the final head's full diff**, not resumed from the
   round 18 material: that verdict was given before the tasks disposition, the
   single-replica text and MIK-7256 existed. A ratification stamp is bound to a diff hash,
   so a stamp minted against the older diff does not cover what is being pushed. Then the
   DoD comment on each ticket.
7. Open the PR, land it, then §P5 housekeeping.

## Design events during implementation (§P3)

Decisions taken while implementing MIK-7256 that the design did not make, named here at
the moment they were made rather than discovered in review.

**The overlay reaches every lazily-resolved reader, not only the ones a test reaches.**
`fetch_credential`, `auth.bearer_token`, `api_keys[].key`, `agent_auth.hs256_secret`,
`key_server.admin_token`, `SecretResolver::resolve`'s `{env.NAME}` and
`validate_env_reference` all take the overlay. The eight test rows exercise a subset. A
reader still calling `std::env::var` directly reintroduces this defect in a different
spelling, so shipping only the tested subset would deliver the failed-reload guarantee on
some paths and not others. This widens the diff on a branch already at final review, and
that cost is accepted deliberately.

**Startup resolves configuration through `Config::load_evaluated`, which is fallible, and
a malformed env file terminates startup.** `Config::load` and `load_config_or_default`
are untouched, so the design's objection — that a fallible startup routes a typo into
`load_config_or_default`'s swallow at `src/config_persistence.rs:14-23` and yields
`Config::default()` — does not apply: the swallow is on a path this change does not use.
The production entry point moves onto `load_evaluated`; a `load_evaluated` nothing calls
would leave the defect in place while the tests passed.

**The malformed-line diagnostic is rebuilt, not forwarded.** `dotenvy::Error::LineParse`
echoes the offending line in its `Display`. The diagnostic carries file, line number and
category only, because the offending line is the secret.

**Attestation keys are read through the overlay, so an env file can supply them.**
`GATEWAY_ATTESTATION_SIGNING_KEY` and `GATEWAY_ATTESTATION_KEY_ID` are read by
`attestation/wiring.rs:124-125` through `env.resolve`, which is the overlay-aware reader
rather than `std::env::var`. An earlier draft of this plan recorded the opposite, on a
reading of line numbers that had moved; the current source is the authority. What remains
true is that they are fixed variable names rather than `{env.NAME}` references in
configuration, so they are supplied as environment values and not as config-file
references.

A sweep of every credential-shaped `std::env::var` in the tree returned 20 call sites, of
which three are in scope: `SecretResolver::resolve` (`src/secrets.rs:51`),
`fetch_credential` (`src/capability/executor/credentials.rs:22`) and
`resolve_admin_token` (`src/config/features/key_server.rs:136`). The reader list in the
design event above names `auth.bearer_token`, `api_keys[].key` and `hs256_secret`
separately, but all three resolve through `SecretResolver::resolve`; threading that one
function covers them. The remaining survivors are justified: the overlay's own baseline
read, a separate binary outside the gateway startup path, two sites building a *child*
process environment, two is-it-set diagnostics that never resolve a value, one enumerator
and one feature flag.
