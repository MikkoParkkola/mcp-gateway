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
| 3 | Task model unverified — the specification page 404s at the indexed path | §12 finding, unverified | **RESOLVED.** Found at `/extensions/tasks/overview`; the branch is short of it and the extension ships not advertised. Conformance owned by MIK-7311 |
| 4 | Failed-task payload shape unverified, same cause | same | **RESOLVED**, same source |
| 5 | §12 ran ONE vendor over eight rounds; the gate requires two | §12 BLOCKING | **RESOLVED.** The second vendor is back, routed through a shim that presents native grok behind the Copilot argv (`~/.claude/bin/copilot-as-grok`); Copilot's own monthly quota is spent. Two vendors have since reviewed the MRTR design and test plan |
| 6 | MIK-7256 has a reviewed design and test plan, no tests and no implementation | §P2 onward | in the pipeline |
| 7 | §4 coverage is measured and **below** the Standard floor by 2.6 points | §4 BLOCKING | MIK-7324. Mutation, the other half of §4, is now measured and passing on `src/protocol` (28 caught / 2 missed, both survivors closed) |
| 8 | Multi-round-trip tool calls are built and unreachable — a 2026 backend that asks a question cannot complete a call | §2 WIRED, on the branch's headline feature | MIK-7325. Design reviewed, six findings, all six verified at source and repaired; confirmation pass in flight |

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

Steps 1 and 3 are done and step 5 is half done; what follows them is now the queue below.

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

## The queue as it now stands

Ordered by what blocks what, not by size. Each item is finished before the next starts, because
each later item's review has to see the earlier one's code.

| # | work | why it is here | gate it closes |
|---|---|---|---|
| 1 | MRTR wiring (MIK-7325) — test plan reviewed **as a plan** over two rounds and a confirmation pass, then failing tests, response side, retry side | the headline feature is currently declined at the door; a fixture backend emitting `input_required` does not exist yet and must be written first | §2 WIRED |
| 1a | Continuation state (MIK-7312) — design, review, test plan, then per-process key material plus a process-local consumed ledger. **Not** a shared storage backend: the design rejects one, because per-process keys are what make a continuation single-use across replicas | MRTR.5 says MUST and the operator held the release for it on 2026-08-30. MRTR.6 is *not* closed here: no table of held legacy exchanges exists to correlate a retry against, so the origin path refuses rather than resumes | MRTR.5 |
| 1a' | MRTR.6 closure — either build the retry-to-exchange mapping, or make the explicit refusal permanent and document it as the answer | MRTR.6 says MUST and 1a leaves it on the refusal arm. Deciding which arm ships is a design event, not an implementation detail | MRTR.6 |
| 1b | Legacy-client bridge — design, review, test plan, then wiring `Bridge::to_legacy_client` (mrtr.rs:186), which has no caller | MRTR.7 says MUST, same decision. The translation exists; issuing the requests over the client's transport mid-call is the missing half | MRTR.7 |
| 2 | Tasks-extension conformance (MIK-7311) — two statuses, two required fields, an error payload shape, a capability check | the extension is unadvertised, so this is conformance rather than a live defect; fetch the specification page again before writing anything | §12 finding |
| 3 | Coverage on the five named modules (MIK-7324) | §4's failing half; `src/main.rs` is the sharpest, 22 added lines and none executed | §4 |
| 4 | Mutation over the rest of the branch diff, on Spark, module by module | the measured 93.3% covers `src/protocol` only, and a subset is a lower bound | §4 |
| 5 | Version bump to 4.0.0 everywhere (step 4 above), then re-run §3, §4, §5 at the final head | a tag built from a tree calling itself 3.5.0 ships a lie in `--version` | §3, §4, §5 |
| 6 | Second-vendor review against the final head's full diff, then the DoD evidence comment on each ticket | a ratification stamp binds to a diff hash, so an older stamp covers nothing being pushed | §12, §1 |
| 7 | Deploy — MIK-7265 closes on deploy, not on merge. Production is 3.4.0 and answers a foreign `Origin` with HTTP 200 | a merge is not a deployment | §11 |

### The §12 blocker resolved, and not by waiting

Both of the second vendor's routes were exhausted at once, which is what made it look permanent: the
xAI quota was spent and the GitHub Copilot fallback answered `monthly quota exceeded` on a fresh
session. The two were not the same outage. xAI came back; Copilot did not. The review wrapper only
knew how to speak Copilot's command line, so a small shim now presents the native tool behind that
same argument shape, and the wrapper cannot tell the difference. Two vendors have reviewed the MRTR
design (three rounds), its test plan (two rounds), and the repairs (a confirmation pass each).

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

## The queue does not cover the release, and the sweep says by how much

`RELEASE-4.0.0-criteria-status.md` verified acceptance criteria against `src/` and `tests/`
directly, never against another document's claim. Result: 33 MET, 14 ABSENT, 12 UNWIRED, 4 MET
with a caveat, 1 UNTESTED. Thirty-one criteria are blocking, and the queue above owns fourteen of
them. The other seventeen have no owner anywhere.

Read as a plan the queue is not wrong, it is short. That is the finding.

### The seventeen collapse into five causes, not seventeen tasks

| # | increment | criteria closed | why these belong together |
|---|---|---|---|
| 5 | Shared-cache key correctness | CACHE.3, CACHE.4 | The key covers 2 of 8 response-varying dimensions (`invoke.rs:639-640,780`), both conditional, with zero tests. A cache keyed on less than what varies the response serves one caller's result to another. This is a data-disclosure defect wearing a performance feature's clothes, and it outranks everything else in this table. CACHE.3's missing decision table is the same gap stated as documentation |
| 6 | Outbound request envelope | HEADER.5, HEADER.9 | Both are the outbound half of the request builder: mirroring an argument onto `Mcp-Param-{name}`, and carrying the modern `_meta` envelope. One mechanism, one design, one review. HEADER.5's validation half already exists (`param_headers.rs::mirrored_params`) and is waiting for a sender |
| 7 | Principal-keyed control plane | TENANT.1, CONTROL.2, CONTROL.3, CONTROL.4 | Every one says the same thing: key on the authenticated principal or the trace id, never on the session. Splitting them means designing that substitution four times. Work on the first two is already in flight in another session (`src/security/firewall/tenant_guard.rs`, `principal_window.rs`, both untracked) — this increment must start by reconciling with it, not by rebuilding it |
| 8 | Modern-path conformance | RESULT.2, ERROR.2, ORDER.2, SUB.3, SUB.4 | Five corrections to what the 2026 path returns and advertises: a default when a backend reply omits a field, `-32602` for resource-not-found, a tool set that cannot vary per connection, removal of SSE resumability, and the retry-after-broken-stream case that has code but no test |
| 9 | Declare-or-delete the unwired surface | EXT.1, OTEL.1 | `ExtensionSet::gateway_declares` and `TraceContext` are built, unit-tested, and have zero production call sites — each carries a doc comment admitting it. Full scope means wiring them, not deleting them; the deletion arm is recorded here only because HEADER.5 took it three days ago and the precedent should be visible when this is decided |

CONFIRM.2 is not in the table: the destructive-confirmation gate must be reachable through the MRTR
path, so it closes when item 1 wires that path or it does not close at all. It rides on item 1 as an
acceptance criterion, not as an increment.

### The largest single lever is already queued

Twelve of the thirty-one blocking criteria are UNWIRED, and eight of those twelve are MRTR
(MRTR.1-.8). That is one subsystem, fully built, fully unit-tested, with no production caller —
`§2 WIRED` and `D7` in the DoD, and `§11` stop-the-line. Item 1 closes eight criteria in one
increment. Nothing else in this plan has that ratio, which is why it stays first.

### Two things this plan still does not know

- **MIK-7217.DISCOVER, 7 criteria, unswept.** The blocking count of 31 is a floor. Sweeping
  DISCOVER can only raise it, and it should happen before anyone commits to a release date rather
  than after.
- **Four criteria are MET with a caveat and two are MET on inference** (SCHEMA.1, SURFACE.1,
  SUB.1, SUB.2; ORDER.3, CONTROL.5). Each is either a criterion that passes or evidence that has
  not been produced yet, and today nobody can tell which from the record. Resolving six caveats is
  cheap; discovering at tag time that one of them was a seventh gap is not.

### Order, and the one thing that reorders it

Items 1, 1a, 1a', 1b, 2 stand as written. The five new increments then run 5, 7, 6, 8, 9 —
cache-key disclosure first because it is the only orphan that is a live security defect, the
principal-keyed plane second because another session is already inside those files and the cost of
colliding grows daily.

The reordering trigger: if the DISCOVER sweep returns a blocking criterion in a module any of these
increments touches, that increment absorbs it rather than queueing behind it. Discovering a
neighbour's gap while already holding the file is the cheapest moment there will ever be to fix it.
