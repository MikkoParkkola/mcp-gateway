<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# v4.0.0 scope contract: the eleven rows that are not MET, and what each needs

`scripts/release/check_scope_acceptance.py --check` reports 31 criteria with
11 pending. Those eleven were re-derived against source on 2026-09-17, each
one twice and independently. This is the consolidated result: what every row
actually needs, who can supply it, and a recommendation where the answer is a
judgement call rather than an engineering task.

Three facts frame the whole set.

**None of the eleven has a row in the criteria ledger.**
`docs/requirements/RELEASE-4.0.0-criteria-status.md` carries no entry for any
of them, and neither does `RELEASE-4.0.0-requirements.md`. They are
supplemental-scope criteria that exist only in the scope contract
(`RELEASE-4.0.0-scope-update.md`, obligations in
`RELEASE-4.0.0-scope-tests.md`). The ledger's completeness claim is not
violated — these are not requirement IDs — but grading them against the ledger
returns nothing, which has already misled at least one pass. Grade them
against `RELEASE-4.0.0-scope-status.json`.

**Eight of the eleven terminate on a ruling, not on work.** Three are
engineering tasks, and two of those are order-blocked behind a ruling or a
merge. So the release does not advance by writing more code against this set;
it advances by settling eight questions.

**Several of the recorded notes are stale, and two were stale in the
flattering direction** — they described a gap that source shows is already
closed. Section 4 lists every correction.

## 1. The eight rows that need a ruling

Each is stated as a question with two answers. The recommendation is the
cheaper answer wherever the expensive one buys no behaviour.

### 1.1 MIK-7334.CATALOGUE.1 — does withholding count as isolating?

The criterion asks that one backend return different tool names and schemas to
two identities (`RELEASE-4.0.0-scope-tests.md:40`). The shipped behaviour does
not serve a per-identity catalogue at all: it withholds one
(`src/backend/metadata.rs:110-112`). Isolation therefore holds, but by absence.

The premise is unproducible as written, and the reason is structural, not a
missing test. Metadata never routes through the per-identity pool —
`request_internal` takes `shared_transport()`, which is a hardcoded shared key
(`src/backend/pool.rs:275-281`), and the fetch passes no identity
(`src/backend/metadata.rs:142`). No caller identity reaches a metadata fetch in
either session mode.

The cost of the shipped fix is worth stating plainly, because it is larger than
"a catalogue is withheld": the withhold empties the cache that discovery and
routing read, so a `per_user` backend surfaces **zero** tools
(`src/gateway/meta_mcp/search.rs:155`, `spec_preview.rs:1039`). A mode declared
supported (`RELEASE-4.0.0-scope-delivery.md:86`) that yields no tools reads as
absent rather than isolated. A side effect falls out of the same gate:
`search.rs:155` spawns `refresh_stale_backend_tools` whenever the cache is
empty, and the withhold guarantees it never populates, so every discovery pass
respawns it.

- **(a) Rewrite the criterion** to "per-identity catalogues are withheld, not
  served." Closes today on `src/backend/tests.rs:1805` and `:1843` as they
  stand — both plain tests, no ignore attribute, no feature gate.
- **(b) Fund a per-identity catalogue fetch.** Real work in the metadata path,
  and it is the only answer that makes the supported mode return tools.

**Recommendation: (a), with (b) filed as post-4.0.0.** Shipping the mode as
"withheld" is honest; shipping it as "supported" while it returns zero tools is
not. This row also gates NFR.DEMO.1 scenario 3 (§1.7).

### 1.2 MIK-6744.STORE.1 — migrate 3.x tokens, or keep the published promise?

The criterion requires migrating existing local data
(`RELEASE-4.0.0-scope-tests.md:41`). The release ships the opposite, as a
published and test-pinned commitment: item 1 of five in `NOTICE_4_0_0_ITEMS`,
"Stored tokens from 3.x are not migrated: each OAuth backend re-authenticates
once" (`src/commands/upgrade.rs:242`, count asserted at `:1158`).

No migration path exists, and the barrier is the key rather than decryption:
`storage_key` is `backend_name + NUL + issuer` (`src/oauth/client/mod.rs:114`),
so a 3.x backend-name-only filename is never opened. The store is explicit that
it creates nothing: "Existing state is never replaced, and nothing is migrated
into a store this command creates" (`src/personal_accounts/mod.rs:778-779`).

This row cannot be closed by adding a test in either direction — a test pinning
shipped behaviour asserts the opposite of the criterion, and one pinning
migration is red by construction.

- **(a) Rewrite the conjunct** to the shipped re-authenticate-once behaviour.
  One requirement edit; every other conjunct stays as graded.
- **(b) Build migration** and withdraw notice item 1 — which falsifies a
  published release note.

**Recommendation: (a).**

### 1.3 MIK-6744.STORE.2 — may a surface deferred past 4.0.0 be graded MET?

The row's own blocking note is stale on its headline: it says the covering test
does not exist, and it does — `a_reconnected_grant_refuses_the_credential_prepared_under_the_old_one`
(`src/gateway/meta_mcp/account_rest_tests.rs:1295`), which warms the cache,
commits a reconnected grant through live custody, then asserts a refusal with
no new wire request and no token in the error. Its commit `c14b977b` is an
ancestor of `origin/main`, contrary to the note. Conjunct C4 is closed.

What remains — revocation, and the refresh-job half of C3 — has no production
path. `invalidate` and `commit_grant_if` both carry an attribute deferring them
by name to the post-4.0.0 backlog
(`src/personal_accounts/service.rs:319-326`, `worker.rs:235-241`, `:254`), and
every caller outside the module is a test.

- **(a) Accept the declared deferral** and rewrite the row to what 4.0.0 ships.
- **(b) Fund the production revoke path.**

**Recommendation: (a).** The deferral is already declared in source and named
in the code; the row should say the same thing.

### 1.4 NFR.WORKLOAD.1 — authorise the corrected re-run, or hold the row?

The harness is built and has been executed, but it is off the release line:
`790898c6` is not an ancestor of `origin/main`, and `origin/main` carries no
`benchmarks/workload/` directory at all. Every number produced so far grades a
tree the release does not ship.

The substance is also short of the bar. Cells A/B/C came back inconclusive
(spreads of 0.070/1.677 and 0.109/0.734 against margins of 0.05/0.10), and D/E
landed at 0.663 because the shipped default rate limit of 100 requests per
second (`src/config/features/failsafe.rs:20-21`) sheds load against an offered
rate of roughly 137 per second.

The docket fork at `docs/release/v4.0.0-decision-docket.md:17` is unsigned, and
it is worth knowing before signing that the diagnosis recommends **neither
docketed option as worded**
(`docs/release/2026-09-16-nfr-workload-1-diagnosis.md:266-305`): keep the 100%
threshold, disable the response cache for every cell, raise
`requests_per_second` above the offered rate in the one shared template, re-pin
and re-run. It also shows the docketed cost of raising the limit is overstated
— section 8 condition 8 requires A/B/C to be byte-identical to each other, not
to a frozen template. And it flags the second docketed option as a trap:
scoping the void condition lets the grader pass while the cells answer from
cache, so the result would rest on cache latency rather than gateway latency.

- **(a) Authorise the corrected re-run.** Harness-only work: two keys in
  `benchmarks/workload/gateway.workload.yaml`, merge the branch, one run on
  dedicated compute. No production change.
- **(b) Hold the row** and ship 4.0.0 without a workload number.

**Recommendation: (a).** The correction is two configuration keys, and the
alternative is shipping with the row open.

### 1.5 NFR.BUILD.1 — accept the declined client-version pin?

Conjunct C1 asks for pinned client versions. The supported matrix declines it
deliberately: "No client version is pinned, and that is a claim in itself"
(`docs/release/v4.0.0-supported-matrix.md:58-62`), pinning config contracts at
`:65-73` instead. No engineering closes a declined pin; it needs a ruling
either way, which the docket already recommends accepting
(`v4.0.0-decision-docket.md:18`).

**One correction to that docket line, and it matters: its claim that "nothing
else in the row is open" is false.** Two conjuncts are absent:

- **C5, current critical-path coverage.** The only artifact is
  `docs/design/2026-09-03-cluster-a-coverage-audit.md`, which scopes itself out
  at `:3` ("Audit only. It writes no test, decides no gap") and pins its
  observation to `9b0643d4` at `:7`. No coverage or mutation job exists in CI.
- **C6, mutation evidence grading the final integration revision.** Absent, and
  that revision has not been cut.

So the C1 ruling closes C1 only. The row stays open on C5 and C6 regardless of
how C1 is answered.

**Recommendation: accept the C1 decline and record the reason in the row, and
in the same edit reopen the row against C5/C6** so the docket stops implying
the row closes on one signature.

### 1.6 MIK-6745.JOURNEY.1 — a live recorded route, and a missing code path

The contract asks for a pinned route from client through gateway to a Google
Workspace backend with recorded config versions, and says in as many words that
the existing install "is a starting environment, not acceptance evidence"
(`RELEASE-4.0.0-scope-tests.md:43`). No recording directory exists.

Two conjuncts are additionally unbuilt in code. `ConnectOffer` appears only in
`src/personal_accounts/service.rs:151` and `:366` and nowhere in the gateway,
so C1's gateway-brokered consent offer is Slice C of ADR-008 and not yet
written (`ADR-008:138`). C2 asks for a cancelled browser consent;
`tests/oauth_cancellation.rs` holds two tests, both about runtime future
cancellation rather than a user declining at the consent screen.

This row needs a deployment either way — landing C1 does not produce a recorded
live route. **No recommendation: it is a scheduling question, not a fork.**

### 1.7 NFR.DEMO.1 — five recordings, none of which exist

All five recording conjuncts are uncovered (`scope-update.md:58`, obligations
at `scope-tests.md:72`), and the versions/expected/actual conjunct is moot with
no recording to carry it. A sweep for any recording format returns exactly
three files — `demo.gif` and two copies under `docs/` — and `demo.tape` records
the context-token pitch, not a scenario. No CI job records anything.

**One recorded blocker on this row is stale.** The mixed-era scenario was held
behind the legacy stdio bridge; that cluster closed (`f93a805b` and `756bd6cd`
are both ancestors of HEAD, and no ignore attribute remains in
`tests/mik_7212_mrtr7_stdio_acs.rs`). Mixed-era is recordable now.

**A harder blocker is not recorded anywhere.** Scenario 3, isolated personal
accounts, has no shipped mechanism to record — it maps to the mode
MIK-7334.CATALOGUE.1 owns (§1.1), which currently returns zero tools. Whether
scenario 3 exists at all is decided by that ruling.

**Recommendation: rule §1.1 first, then author the four unblocked scenarios.**
Four of the five are authoring work available today; scenario 3 is either
recordable or dropped from the five depending on §1.1.

### 1.8 MIK-3274.RANKING.3 — the three unmeasured metric families

One of four required metric families is frozen. Discovery turns, invalid
invocations and total completed-task tokens carry no baseline and no threshold
— `FREEZE.md:161-171` floors selection quality only, and the other three rows
read "not set -- baseline not measured". Measuring them needs the live-agent
trial harness `FREEZE.md:123-145` specifies: the 114-query corpus driven
through the real 119-tool set with repeats, at live API cost.

**A defect worth separating from the row:** the cited regression harness does
not regress anything. `tests/mik_3274_ranking_3_baseline.rs` says so itself at
`:209-210` — "this test measures, it does not grade" — and its strongest
assertion is `overall_top1_hit_rate >= 0.0 && <= 1.0` at `:212`. The floors
live only in a markdown table; nothing goes red on a selection-quality
regression today. That is a small, separately closable fix (§3.3) and it does
not close this row.

**Recommendation: authorise the live-agent run, or descope the three families
to post-4.0.0 explicitly.** This row order-blocks MIK-3274.RANKING.1
(`scope-update.md:50` requires the freeze to precede ranking implementation),
so leaving it unruled leaves two rows open rather than one.

## 2. The three rows that are engineering work

### 2.1 MIK-6746.CONTRACT.1 — a token audience that is optional is not enforced

The one row in this set that is closable today, start to finish, with no
ruling and no deployment.

`audience` on an agent config is `Option<String>`
(`src/gateway/oauth/agents.rs:45`), and the check runs only inside
`if let Some(ref expected_aud)` (`src/gateway/oauth/jwt.rs:166-168`). A backend
configured with no audience therefore skips `check_audience_claim` entirely
(`jwt.rs:249`), and no startup check rejects the absent value. A correctly
signed token minted for a different service is accepted.

The in-tree precedent is `src/key_server/oidc.rs:429-435`, where
`KeyServerConfig::validate` guarantees a non-empty audience list. Mirroring it
on the agent config is the smallest fix: a `validate()` that rejects an absent
audience, plus a row asserting that `verify_agent_token` **rejects** a
correctly signed token whose agent has no configured audience — red before,
green after.

Two further conjuncts on the row: C5 route parity for the client-supplied
passthrough header is a second and cheaper test row in
`src/gateway/router/backend_handlers/tests.rs`; C3 asks that the custom header
be reconciled rather than copied into new work
(`scope-update.md:65`), and `ADR-008:123-124` promotes it to primary with no
reconciliation recorded.

One conjunct is **not buildable as a test** and should be said out loud rather
than left to fail quietly: the standard-interoperability cell of
`scope-tests.md:46` — "a custom header alone cannot pass" — needs a
standards-based ingress that does not exist in this tree. That is a scope call,
not a missing test.

### 2.2 NFR.CONFORMANCE.1 — closable by code, but the grade is branch-local

Both the scope contract and the tracked-gap entry at
`tests/mik_7272_conformance.rs:356-364` assert that
`ExtensionSet::from_capabilities` has no production caller. **That premise is
true on `origin/main` and false on `work/v4-audit-adjudication`.** Verified at
source: `src/gateway/router/handlers.rs:199` calls it inside
`declares_tasks_extension`, gated at `:1041`; `origin/main`'s copy of
`handlers.rs` contains no such call; the commit that added it, `d191cc68`, is
not an ancestor of `origin/main`.

The consequence is a scheduling one. The row is closable by code, but the grade
does not reach the release line until PR #561 merges — and the tracked-gap
string becomes false on the same merge, which is a CI-enforced string carrying
a premise the merge falsifies.

The residual gap is narrower than "recovery is unimplemented": the invoke
funnel keeps only a boolean, so conjunct E4 has no recovered set to assert
against (`src/gateway/router/tests/task_execution_adapter/refusals.rs:377-383`,
which states the fork itself — "until the funnel holds the set or the row is
amended").

There is a cheap fork here worth putting on the record. `Extension::from_id`
exact-matches a single identifier (`src/protocol/extensions.rs:36-41`), so at
one recognised extension the set and the boolean are isomorphic: carrying the
set through the funnel buys a test-observable value, not a behaviour change.
Amending E4 to the boolean is defensible and costs a sentence; carrying the set
costs a change to the funnel signature.

### 2.3 MIK-3274.RANKING.1 — real code, order-blocked

Neither conjunct is covered: no abbreviation matching and no word-boundary
discovery exist. Discovery matching is substring plus synonym only —
`tool_matches_query` to `word_matches_text` to a plain `contains`
(`src/gateway/meta_mcp_helpers.rs:449-466`) — and the scoring module has no
boundary or distance function.

A Levenshtein edit-distance implementation **does** already exist at
`src/gateway/meta_mcp_helpers.rs:47`, consumed by `did_you_mean` at `:75` for
post-failure error suggestions. It is not on the ranking path, but it means the
fix reuses an in-tree helper rather than adding a dependency.

The row that can fail: an abbreviation query whose gold tool is currently
outranked must return top-1, with control rows asserting that an exact
identifier and a Code Mode glob keep their present rank —
`scope-tests.md:57` names both controls.

**Order-blocked behind §1.8.** `scope-update.md:50` requires the freeze to
precede ranking implementation, so landing fuzzy matching first makes
MIK-3274.RANKING.3 permanently unsatisfiable as written.

## 3. Corrections to the record

Every item below was checked against source on 2026-09-17. Two of them
described a gap that is already closed, which is the direction that costs most
— a recorded gap nobody re-checks funds work against nothing.

### 3.1 Claims that overstate the gap

| Where | Says | Source says |
| --- | --- | --- |
| `RELEASE-4.0.0-conformance-matrix.md:101` | E1-E3 server-side `extensions` serialisation "are still unwritten" | Three tests exist at `src/gateway/meta_mcp_helpers_tests.rs:866`, `:889`, `:908` |
| MIK-6744.STORE.2 note | `c14b977b` "is NOT on the release line" | It is an ancestor of `origin/main`; conjunct C4 is closed |
| MIK-7334.CATALOGUE.1 note | a Stateless-mode identity leak | Refuted by its own cited source: `pool_key_for` collapses every non-per-user case to the shared key (`src/backend/pool.rs:173-181`) and the metadata fetch passes no identity |
| MIK-7334.CATALOGUE.1 note, conjunct 3 | call results are not identity-keyed | Capability results are: `build_cache_key` prefixes authority and subject (`src/capability/executor/params.rs:283`), asserted at `src/capability/executor_tests.rs:1559`. The MCP side has no result cache to key |
| NFR.DEMO.1 note | mixed-era "depends on the legacy stdio bridge, mid-flight" | That cluster closed; `f93a805b` and `756bd6cd` are ancestors of HEAD |

### 3.2 Claims that understate it, or are simply wrong on a number

| Where | Says | Source says |
| --- | --- | --- |
| `RELEASE-4.0.0-conformance-matrix.md:103-104` | 6 of the 125 files under `capabilities/` carry a top-level `sha256` | **93 of 125**, pinned by `df7162a7` on 2026-09-14, after the grading. Does not move C2's grade — those hashes cover definition files, not backend builds — but the number belongs corrected |
| `v4.0.0-decision-docket.md:18` | of NFR.BUILD.1, "nothing else in the row is open" | False against C5 and C6 (§1.5) |
| MIK-6744.STORE.1 note | notice item 1 "of four" | Five; asserted at `src/commands/upgrade.rs:1158` |
| MIK-3274.RANKING.3 note | `tests/mik_3274_ranking_3_baseline.rs` is the regression harness | It grades nothing (§3.3) |
| MIK-3274.RANKING.1 note | no edit-distance implementation | The grep was scoped to `src/ranking/`. One exists at `src/gateway/meta_mcp_helpers.rs:47` |
| `FREEZE.md:7`, `:181` | measurement pinned to `b121451e` | Not an ancestor of HEAD; it lives only on `origin/docs/mik-3274-ranking-3-baseline`. The artifacts themselves are on-line via `f241b464`, so this is a citation defect, not missing evidence |
| `v4.0.0-supported-matrix.md:111-138` | 18 feature combinations | The `feature-combos` job runs 17; the 18th is covered by the `check` job |

Line-number drift in the scope-contract notes, none of which changes a grade:
`metadata.rs:96` is now `:110`, `tests.rs:1783` is now `:1805`, `:1826` is now
`:1843`.

### 3.3 One separately closable defect

`tests/mik_3274_ranking_3_baseline.rs` is cited as the selection-quality
regression harness and does not grade a single floor. Adding a second test that
asserts each of the five `FREEZE.md:161-165` floors against the computed report
— comparing the exact fractions 84/114, 98/114, 4/12 and 12/20 as section 4 of
that document instructs, not the truncated display values — makes a
selection-quality regression visible. The existing test is a plain async test
at `:137`, neither ignored nor feature-gated, so such a row runs and can fail.

This does not close MIK-3274.RANKING.3. It closes the gap between what that row
claims to be protected by and what is actually protected.

## 4. What to do, and in what order

The dependency chain matters more than the list. Four of the eleven rows are
waiting on another row rather than on work.

1. **Rule §1.1 (CATALOGUE.1).** It unblocks NFR.DEMO.1 scenario 3, and until it
   is answered four of the five demo recordings are worth authoring but the
   fifth cannot be planned.
2. **Rule §1.8 (RANKING.3).** It unblocks MIK-3274.RANKING.1, which is
   otherwise real work that must not be started first.
3. **Merge PR #561.** It is the only thing standing between
   NFR.CONFORMANCE.1's grade and the release line, and it also decides when the
   tracked-gap string in `tests/mik_7272_conformance.rs` has to be corrected —
   the merge is what falsifies it.
4. **Sign the three remaining forks** — §1.2, §1.3, §1.4 — all of which have a
   cheap recommended answer and no dependency on the others.
5. **Correct the record (§3) regardless of any ruling.** None of it needs a
   decision; all of it is currently misleading a reader of the ledger.
6. **Land MIK-6746.CONTRACT.1 (§2.1) and the floor assertions (§3.3).** The
   only two pieces of engineering in this set that are neither order-blocked
   nor waiting on a signature.

Two rows resist all of the above by nature: MIK-6745.JOURNEY.1 needs a live
recorded route and NFR.DEMO.1 needs recordings. Neither is a test, and no
command produces either.

### The honest summary

Eight of eleven rows need a signature, not a commit. Two of the three that are
engineering work are order-blocked behind a signature. The one row that is
neither — an optional token audience that is never enforced when absent
(§2.1) — is also the only one of the eleven with a security consequence.
