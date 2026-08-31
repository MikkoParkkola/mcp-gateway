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
| 2 | Tasks-extension conformance (MIK-7311, and TASK.1) — two statuses, two required fields, an error payload shape, a capability check | the extension is unadvertised, so this is conformance rather than a live defect; fetch the specification page again before writing anything | §12 finding |
| 3 | Coverage on the five named modules (MIK-7324) — **runs after the wiring increments**, see Order | §4's failing half; `src/main.rs` is the sharpest, 22 added lines and none executed | §4 |
| 4 | Mutation over the rest of the branch diff, on Spark, module by module — **runs after the wiring increments**, see Order | the measured 93.3% covers `src/protocol` only, and a subset is a lower bound | §4 |
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
directly, never against another document's claim. Coverage is complete: **73 criteria, 32 blocking**, counted from
the table rows rather than from any summary line above them — this document twice carried a total
its own source contradicted. The queue above owns fourteen. The other eighteen had no owner
anywhere, which is what the increments below exist to fix.

Read as a plan the queue is not wrong, it is short. That is the finding.

### The eighteen collapse into five causes, not eighteen tasks

| # | increment | criteria closed | why these belong together |
|---|---|---|---|
| 5 | Shared-cache key correctness | CACHE.3, CACHE.4 | The key covers 2 of 8 response-varying dimensions (`invoke.rs:639-640,780`), both conditional, with zero tests. A cache keyed on less than what varies the response serves one caller's result to another. This is a data-disclosure defect wearing a performance feature's clothes, and it outranks everything else in this table. CACHE.3's missing decision table is the same gap stated as documentation |
| 6 | Outbound request envelope | HEADER.5, HEADER.9 | Both are the outbound half of the request builder: mirroring an argument onto `Mcp-Param-{name}`, and carrying the modern `_meta` envelope. One mechanism, one design, one review. HEADER.5's validation half already exists (`param_headers.rs::mirrored_params`) and is waiting for a sender |
| 7 | Principal-keyed control plane | TENANT.1, CONTROL.2, CONTROL.3, CONTROL.4 | Every one says the same thing: key on the authenticated principal or the trace id, never on the session. Splitting them means designing that substitution four times. **First task, before any design: reconcile with the in-flight work in another session** (`src/security/firewall/tenant_guard.rs`, `principal_window.rs`, both untracked). That is a task with an output, not a caution — starting anywhere else rebuilds what already exists, and the cost of colliding grows daily |
| 8 | Modern-path conformance | RESULT.2, ERROR.2, ORDER.2, SUB.1, SUB.2, SUB.3, SUB.4 | Seven corrections to what the 2026 path returns and advertises: a default when a backend reply omits a field, `-32602` for resource-not-found, a tool set that cannot vary per connection, removal of SSE resumability, and the retry-after-broken-stream case that has code but no test. SUB.1, SUB.2 and SUB.3 join it because the sweep showed all three are **one defect**: `mcp_sse_handler` (`handlers.rs:167-260`) carries no era or `MCP-Protocol-Version` gate anywhere in the function, so the GET endpoint was supplemented rather than replaced and `Last-Event-ID` is read unconditionally at `:206`. SUB.1 and SUB.2 were filed under evidence quality on the strength of a `MET*` that is not in the status file's own vocabulary — a partial-credit status invented mid-document, and this is what it concealed |
| 9 | Build the outbound side of the protocol surface | EXT.1, OTEL.1, DISCOVER.4, DISCOVER.5 | Not a tidy-up and not four wirings. `ExtensionSet::gateway_declares` and `TraceContext` are built, unit-tested and have zero production call sites; the era detector has nothing that sends a probe, and `EraCache` (`era.rs:111`) holds one `Option<Era>` under one mutex where DISCOVER.5 requires per-backend keying, so the cache is redesigned rather than wired. The title said declare-or-delete while the body described construction — sizing this as a tidy-up is how it stayed last in the queue. The deletion arm survives only because HEADER.5 took it three days ago and that precedent should be visible when this is decided |
| 10 | Close the four evidence-quality criteria | SCHEMA.1, SURFACE.1, ORDER.3, CONTROL.5 | Two are MET with a caveat and two on inference. Each is either a criterion that passes or evidence nobody has produced, and today the record cannot tell which. Cheap here, expensive as a seventh gap discovered at tag time. Given an increment because a bullet in a prose section has no owner and no gate |

CONFIRM.2 is not in the table: the destructive-confirmation gate must be reachable through the MRTR
path, so it closes when item 1 wires that path or it does not close at all. It rides on item 1 as an
acceptance criterion, not as an increment.

### The largest single lever is already queued

Fourteen of the thirty-two blocking criteria are UNWIRED, and eight of those fourteen are MRTR
(MRTR.1-.8). That is one subsystem, fully built, fully unit-tested, with no production caller —
`§2 WIRED` and `D7` in the DoD, and `§11` stop-the-line. Item 1 closes eight criteria in one
increment. Nothing else in this plan has that ratio, which is why it stays first.

### Three things this plan still does not know

- ~~MIK-7217.DISCOVER, unswept~~ — **swept 2026-08-31, 5 MET and 2 blocking**, raising the count
  from 31 to 33 as predicted — since revised to 31 by the full sweep, because HEADER.7 and .8
  cleared in the same window, and then to 32 when the blocking rule was applied to the SCHEMA.1
  clause row (see the correction note below). Both blockers (DISCOVER.4, DISCOVER.5) are the era detector, and they
  join increment 9.
- ~~Ten of the seventy-three criteria have never been read against source~~ — **false when written,
  and the way it was false is the finding.** The rows existed. They landed in `3b0ced13`, a commit
  whose message never mentions them, and that sweeper left the header reading `63 of 73` and the
  prose still saying those groups were unswept — both falsified by their own commit. Every reader
  after it, this plan included, inherited a gap that had already been closed. A sweep that updates
  rows without updating the counter is indistinguishable from no sweep at all.
  The dispatched sweep re-verified all ten against source rather than trusting the rows, which is
  the only reason this is a paragraph and not a wasted increment: **7 of the 10 are blocking**, and
  the three OAUTH criteria are genuinely MET on production paths (`oauth/client/mod.rs:87` called at
  `:840`, `:58` at `:1100`, `:381-386` reaching disk through `storage.rs:178`). Coverage is 73 of 73.
- **Two criteria are MET with a caveat and two are MET on inference** (SCHEMA.1, SURFACE.1;
  ORDER.3, CONTROL.5). Each is either a criterion that passes or evidence that has not been
  produced yet, and today nobody can tell which from the record. Resolving four caveats is cheap;
  discovering at tag time that one of them was a fifth gap is not. The bucket started at six and
  lost two the moment they were re-read, which is the argument for reading the rest: SUB.1 and
  SUB.2 sat here on the strength of a `MET*` that the status file's own vocabulary does not define,
  and both turned out to be ABSENT and blocking.

**Correction, 2026-08-31 — the blocking total is 32, not 31.** The operator was told 31 twice
before this was caught. `MIK-6865.SCHEMA.1 (clause: valid under JSON Schema 2020-12)` was recorded
UNTESTED with `blocking = no`, the sole row in the file violating its own stated rule ("A criterion
is BLOCKING unless it is MET or N/A"). The row is new — it was created by splitting SCHEMA.1 when
the caveat turned out to hide an unimplemented clause — and a split can create a non-MET row where
the criterion previously had none, so a split can move the blocking total even though editing a
status on an existing row cannot. Corrected in place; the totals above are derived from the table
rows, not carried forward.

### Order, and the one thing that reorders it

Items 1, 1a, 1a', 1b, 2 stand as written. **Items 3 and 4 move to after the wiring increments**,
and that is this plan's own finding turned on itself: coverage and mutation cannot see the unwired
class, because those lines *do* execute — under tests. Raising coverage on a module nothing imports
buys a green number over dead code, and `src/main.rs` with 22 added lines and none executed is
exactly that shape. Measure the tree that ships, not the tree that compiles.

The six new increments then run 5, 7, 6, 8, 9, 10 —
cache-key disclosure first because it is the only orphan that is a live security defect, the
principal-keyed plane second because another session is already inside those files and the cost of
colliding grows daily.

The reordering trigger: if the DISCOVER sweep returns a blocking criterion in a module any of these
increments touches, that increment absorbs it rather than queueing behind it. Discovering a
neighbour's gap while already holding the file is the cheapest moment there will ever be to fix it.

### The fourteen unwired criteria are one defect, not fourteen

Increment 9 was written as a tidy-up. The DISCOVER sweep showed it is the release's actual shape.

`src/protocol/era.rs` is complete, adversarially reviewed — its own comments cite "Found by
adversarial review, 2026-08-29" — and heavily unit-tested. Nothing in `src/` imports it. A search
for an outbound `server/discover` request finds only the *inbound* dispatcher arms
(`server/mod.rs:1686`, `handlers.rs:826`), doc comments, and tests. The gateway can answer a
discovery probe and cannot issue one.

That is the same shape as every other unwired criterion, and once seen it does not unsee:

| criterion | half that exists | half that does not |
|---|---|---|
| HEADER.5 | `mirrored_params` validates a mirrored header | nothing mirrors an argument onto one |
| DISCOVER.4, .5 | the era detector reads a probe result | nothing sends a probe |
| EXT.1 | `ExtensionSet::gateway_declares` builds a declaration | nothing declares it |
| OTEL.1 | `TraceContext` parses and carries trace headers | nothing propagates them outbound |
| MRTR.1-.8 | the continuation is minted, sealed and verified | no production path mints one |

The receiving half is always the one that exists. It is also always the half that is easy to
unit-test in isolation, which is why all of it is green and none of it runs. A test that constructs
an `Era` and asserts the detector classifies it correctly passes whether or not a probe is ever
sent — the fixture supplies what production never produces.

Two consequences for this plan, both concrete:

- Increment 9 is not five wirings, it is **one question asked five times**: which component owns the
  outbound side of a protocol feature. Answering it once and applying it beats five designs, and
  splitting it across five increments guarantees five different answers.
- `EraCache` (`era.rs:111`) holds a single `Option<Era>` under one mutex, with no backend keying at
  all. DISCOVER.5 says *per backend*. The type cannot represent the requirement, so this is not a
  wiring job with a caching detail attached — the cache is redesigned or the criterion is not met.
  `invalidate()` likewise has no production trigger.

The test-plan rule that would have caught this class is already written down (`§P2`: can this case
actually fail?). It was applied to test *assertions* and not to the question of whether the
production path under test is ever entered. A unit test over an unimported module is a case that
cannot fail, for the most complete reason available.
