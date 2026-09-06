<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release readiness — what the blocking criteria actually are

The ledger (`RELEASE-4.0.0-criteria-status.md`) carries the counts; run
`scripts/release/count-release-criteria.py --check` for them rather than reading a figure here.
Whatever the blocking count is on the day, it is not that many decisions. The ledger's own
evidence cells say so — `NFR.SEC.2`, `.3`, `.4`, `NFR.OBS.4` and `NFR.PERF.3` all read
"same envelope", and `NFR.OBS.3` observes the era detection MIK-7217.DISCOVER.4-5 built. Grouping on those
clauses collapses them into **the clusters tabled below and one residue**, of which five are unbuilt
mechanisms and two are measurements nobody has run.

This document exists so the shape of the remaining work survives outside one session's
context. It adds no verdicts: every row below is quoted from the ledger, and the ledger
stays the source of truth for status.

## Standing ruling — narrowing a criterion is not available on this release

Several rows below present the same shape of choice: build the mechanism the criterion names, or
rewrite the criterion so that what exists already satisfies it. `MIK-7246.CONFIRM.2` and
`NFR.SEC.3` both reach it, and more will.

The repair protocol reserves narrowing a requirement to the requester's **recorded agreement**,
and that agreement exists, in the affirmative, for the whole release. The instruction this work
runs under is to *implement the full 4.0.0 scope, with all gaps fixed with the full scope* — the
phrase appears twice in one sentence, which is not how someone writes who wants the scope
trimmed. So the default is settled and does not need asking again per row: **build the mechanism.**

Two consequences worth stating plainly, because they are the cost of the ruling rather than
arguments against it. Rewriting a criterion stops being a disposal available to a slice owner, so
a row that could have closed by an edit now closes by a change with a design, tests and two review
legs. And a question already put to the operator and unanswered — `CONFIRM.2` was put twice — is
answered by this ruling rather than by a third attempt, because a third attempt asks the same
person the same thing while the answer sits in what they already said.

What this does **not** license: dropping an acceptance criterion, deferring a row, or deciding a
row is not worth building. Those are still scope changes and still need the operator, and the
ruling makes them rarer rather than easier. It settles which way the *build-or-rewrite* fork goes,
nothing wider. A row whose build branch turns out to be genuinely infeasible is a finding to
report, not a licence to take the other branch.

This section landed inside `e5f76c2c`, a commit whose message is about a cache test-plan control and
whose author trailer is not the author of these paragraphs. A concurrently running session staged
the whole worktree rather than its own paths, and this file was open. Recorded rather than rewritten:
history is shared with several live sessions, so a rebase costs far more than a wrong subject line.
The commit to search for is this one, not that one.

## Standing ruling — stage paths, never the worktree

Two slice owners escalated the same thing rather than repairing it, correctly: it is a ruling,
not a repair. Seven commits across four sessions have swept other sessions' uncommitted edits
into an unrelated commit — `e5f76c2c`, `1967d93e`, `13975971`, `ed94ef45`, `c08c055a`,
`5f714c7e`, `32f051e3` (89 of its 96 lines belonged to someone else). Every one of them used
`git commit -a` or `git add -A` on a branch that eleven sessions share.

**The rule: `git commit -o <path> [<path>...]`, always. Never `git commit -a`, never
`git add -A`, never `git add .`.** A shared worktree has no such thing as "my changes" that git
can infer; the only session that knows which paths are yours is you, and the only way to say so
is to name them.

Two states where `-o` alone will not do the job, named so that nobody improvises a fallback to
`-a`. A path git has never seen is not in the index and `-o` refuses it: `git add <that path>`
first, naming it, then `git commit -o <that path>`. And a commit mid-merge cannot be partial at
all — git refuses every path-limited commit until the merge concludes, so finish or abort the
merge rather than reaching for a flag that stages everything.

No content has been lost to this — the sweeps commit real work, and it stays reachable. What is
lost is *provenance*: the message describes one slice's finding while the diff carries four, so
the repair protocol's commit-per-finding is unavailable to every session on this branch, and a
later reader looking for when a change landed searches the wrong subject line. That is the whole
cost, and it is enough.

Not repaired by rewriting history. A rebase on a branch with eleven live worktrees costs more
than the wrong subject lines it fixes.

**When you discover you swept**: leave the commit alone and record the provenance — an empty
commit naming the real authors and what each contributed (`85fd8985` is the precedent), or a
line in the affected design doc. A correction that is findable beats a history that is tidy.

**Not enforced mechanically, deliberately.** The obvious guard is a `pre-commit` hook, and this
repository's hooks live in a `.git` directory shared by every worktree *including the operator's
own checkout* — a guard that misfires there blocks their commits, not just ours. Installing one
is the operator's call and has been put to them. The predicate is checked rather than assumed:
`git rev-parse --git-common-dir` from this worktree returns `/Users/mikko/github/mcp-gateway/.git`
(V, 2026-09-06), which is the same directory the operator's own checkout uses, hooks included.

Put on 2026-09-06 in the operator's own session, as a direct question with three branches — block
above a staged-file threshold with an override, warn only, or leave the rule in prose — and no
answer came back inside the window the asking tool waits. Recorded rather than assumed,
for the reason `CONFIRM.2` is recorded: a week later an unanswered question and an unasked one look
identical. The default while it is open is the prose rule above, which is the reversible branch —
installing a guard in hooks the operator's own checkout reads is not a thing to do on silence.

Two review legs, both SHIP: Grok on the ruling as first written (`829089d2`), and Kimi on the
repair that closed its four findings (`66fa059f`) — the closure re-check returned to the vendor that
raised them, judged all four closed, and raised nothing new.

## The clusters

How far each cluster has actually got — design, test plan, review, code, owner —
is tracked in `RELEASE-4.0.0-readiness-board.md`. This section defines them.

| # | cluster | rows | count | what is actually missing |
|---|---|---|---|---|
| A | MIK-7212 continuation envelope | `MRTR.7`, `MRTR.8b`, `NFR.SEC.3`, `NFR.OBS.4`, `NFR.PERF.3` | 6 | the envelope is minted, opened, bound and consumed on the tool-invoke path (`redeem_retry`, `src/gateway/meta_mcp/invoke.rs:529`, called at `:1301`), and the in-flight table reclaims abandoned exchanges at the bound (`src/protocol/continuation.rs:659`). `MRTR.1`, `MRTR.3`, `MRTR.4-5`, `MRTR.8a`, `MRTR.9` and `MRTR.10a` left this cluster as that wiring landed. `NFR.SEC.2` and `NFR.SEC.4` left it on 2026-09-04: the eight named fixtures already existed in `tests/mik_7212_acs.rs` and now assert the reason each refusal gives, and the confidentiality test reads the decoded envelope rather than the base64 text it used to search. What remains is the legacy-client bridge (`MRTR.7a/7b`) and the observability and performance evidence over the envelope |
| C | MIK-7272 revision surface | `ORDER.2`, `SUB.2` (own-stream clause), `SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1`, `MRTR.10` | 8 | five separate half-wirings: idempotency cache never enabled, extension set write-side absent, task methods advertised and not served, routing profile ignores modern mode |
| D | MIK-7213 response-cache keying | `CACHE.4` | 2 | the two clause rows `CACHE.4a` (key missing routing profile and protocol revision) and `CACHE.4b` (no policy epoch), designed in `docs/design/2026-08-31-cluster-f-response-cache-keying.md`. `CACHE.3` was in this cluster until both its clauses were met: the decision table is now read by the emitting code |
| F | compatibility and surface facts | `NFR.COMPAT.1` | 1 | `NFR.COMPAT.1` is now a code change, not a decision: the operator ruled on 2026-09-02 that 4.0.0 serves 2026-07-28 out of the box, so `server.modern_protocol` must default to true — a one-line flip (`src/config/mod.rs:1229`, and re-derive it rather than trusting that number — the guard commits of 2026-09-04 moved it from 1174) not yet made, and one that cannot land before cluster A wires the continuation path, since default-on turns every gap there into a first-run defect. `MRTR.7a/7b` are the specific reason: the legacy-client elicitation bridge (`Bridge::to_legacy_client`, `retry_params`, `InputRequired::from_result`, `src/protocol/mrtr.rs:128-223`) has zero production call sites, and default-off is the only thing making that unreachable. `NFR.OBS.5` joined this cluster on 2026-09-04 because it is the SAME one-line change: the operator's 2026-09-03 ruling retired its `default off` clause, so the row cannot close until the flip lands, and the flip cannot land until cluster A wires the bridge. Its test file is rewritten and red ahead of that, which is the intended state, not a regression. `NFR.COMPAT.4` left this cluster on 2026-09-06. The dual-role matrix does exist (`tests/mik_7272_conformance.rs`), its two axes are role and transport, and the refusal is mechanised rather than asserted: `matrix_has_no_empty_cells` (`:316`) fails the build on any statement no test names, and `the_client_role_is_covered_and_not_only_the_server_one` (`:382`) stops the client axis from being satisfied by an empty one. The 2026-09-02 operator ruling on the role clause stands unchanged. `NFR.COMPAT.3` was in this cluster until the operator waived it on the record on 2026-09-02, which is why the count is two rather than three. `NFR.PERF.4` left it earlier and is now residue: the ceiling was affirmed and the 17th tool identified as `gateway_webhook_status` (`src/gateway/meta_mcp_tool_defs.rs:565`), which only appears when webhooks are enabled — that settled the number, not the mechanism that holds it **Updated 2026-09-06**: the flip LANDED early (`83c98902`, 2026-09-04) ahead of cluster A, and the operator ruled it stands. `NFR.OBS.5` is now MET (`cargo test --test nfr_obs5_flag` = 6 passed; the three by-design reds are green). The cluster dropped to 2 open, and to **one** on 2026-09-06 when `NFR.COMPAT.4` closed. `NFR.COMPAT.1` remains open, and the CONDITION the flip was supposed to wait for became a hard RELEASE gate on `MIK-7212.MRTR.7a`/`7b`: 4.0.0 must not ship serving the modern revision by default while the legacy-client bridge is unreachable from production. `NFR.COMPAT.1` is open on ONE of its two halves, not both: the criterion needs the default true **on a wired path**, the default is now true, and only the wired path is missing — so `MRTR.7a`/`7b` is the whole of what is left of it. |
| G | stdio dispatch path | `MIK-7246.CONFIRM.1a` | 1 | `NFR.OBS.1` left this cluster on 2026-09-06. It was recorded met on 2026-09-05 and reopened the same day, because `d306c7e8` had put the record SITE on the stdio dispatch path without the record's CONTENT following it: stdio has no header, nothing on that transport remembered the revision settled at `initialize`, and `classify_and_observe` fell to `("absent", "none")` on every legacy request after the handshake. The close is the mechanism the reopen named and nothing wider -- the session stores the negotiated revision (`bind_session_revision`, `src/protocol_revision_telemetry.rs:558`, called from the handshake at `src/gateway/meta_mcp/mod.rs:1174`), the dispatcher reads it back and passes it where the HTTP router passes its header (`src/gateway/server/mod.rs:1768`), and the legacy arm of the classifier consults it (`src/protocol/meta.rs:519`). Three tests drive `dispatch_single` and assert the revision AND its source, and a 2026-09-06 falsifier probe deleting `.or(session_revision)` failed the handshake test on its own equality assertion. `NFR.OBS.2` is the sibling row and **stays in this cluster**, for a different reason than it entered with. `81c0a8ad` put the `tools/list` surface record on the stdio dispatch path (`src/gateway/server/mod.rs:1727-1735`) with two tests beside the dispatcher, which closed the missing-site half; the row was recorded met on 2026-09-05 and reopened the same day on review, because the record's *content* is not the surface. It writes `profile = "none"` as a stdio invariant on the reasoning that no header can name a profile, but a profile is not only header-named: `active_profile` (`src/gateway/meta_mcp/mod.rs:1053-1063`) resolves it from `session_profiles` keyed by session id and falls back to the registry default, and `handle_tools_list_for_session` reads it. A stdio session with a bound profile, or any deployment with a non-trivial default, is filtered by a profile the record calls `none`. `code_mode` and `query_present` have the same shape — the declared input, not the filter that ran. Closing it means recording the profile actually resolved and the filters actually applied at the site that builds the list, which also removes the duplication between the two record sites. `MIK-7246.CONFIRM.1a` was the same shape and is not telemetry, and it is the one row of the three **already answered in the tree**: the gate moved out of the HTTP router into `dispatch_single` (`src/gateway/server/mod.rs:1656`), which `run_stdio` (`:1495`) routes every request through, so a destructive meta-tool invoked over stdio is now refused with `-32001` instead of executing unconfirmed. It stays listed here until the suite, the lints and the dual-vendor review are green on that change. One wiring question — what the stdio dispatcher must do before it reaches `handle_tools_call` — answered all three; the revision record still needs it done. The confirmation half is **specified, not open**: the criterion says the gate MUST refuse when it cannot obtain confirmation, so stdio fails closed. Design and test plan: `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md`. A third gap of the same shape sits in this cluster's design rather than in a fourth row: `src/gateway/server/mod.rs:1748` hardcodes `retry: &NO_RETRY`, so a stdio client can never present a continuation at all. It has no criterion of its own — no requirement names it — so it is a design input here, not a blocking row, and it is not counted |
| H | GH #475 error budgets and the upgrade path | `GH475.RL.10` | 1 | promoted into the ledger on 2026-09-05 under the readiness board's ruling; the cluster's own first piece of work was the promotion itself, and the `rows` cell read 5 rather than 0 for the first time. Four rows landed 2026-09-06 and left the cluster: `GH475.RL.9` (`tests/gh475_rl9_429_only_neither_opens_circuit_nor_exhausts_budget.rs`, GH #481), `GH475.OBS.2` (`a8b1158f`), `GH475.MIG.3` (`82d8490b`) and `GH475.OBS.1` (`5e0a8da2`) — all four GH #481. `GH475.MIG.2` was never a member of this cluster — it was already MET (`version-coupled`), blocking `no`, before this cluster was promoted into the ledger; `98bef5d1` the same day only tightened its assertion and did not touch its blocking status (see `RELEASE-4.0.0-criteria-status.md`'s `GH475.MIG.2` row). What is left is one row: `GH475.RL.10` — the capability executor classifies rate limits nowhere, so that criterion presupposes an exclusion that was never built. `GH475.OBS.1`'s three cases (`ignored_rate_limit_increments_the_suppressed_counter_exactly_once`, `success_outcome_does_not_increment_the_suppressed_counter`, `ordinary_failure_does_not_increment_the_suppressed_counter`, `src/gateway/meta_mcp/invoke.rs:4650-4688`) scrape `mcp_error_budget_suppressed_total` and pin all three `BudgetOutcome` arms, scoped by the `0961b990` ruling to exclude `src/backend/ops.rs:258` (the Failsafe path, already observable under `mcp_backend_requests_total`) from the criterion's population. `GH475.RL.10` carries [#481](https://github.com/MikkoParkkola/mcp-gateway/issues/481). The sixth row #481 lists, `GH475.RL.11`, is not here: reading the call graph settles it as stated, so the ledger records it MET (`structural`) and #481 stays open for the case rather than the property |
| — | residue | `HEADER.9a`, `HEADER.9b`, `CONTROL.4`, `CONFIRM.2`, `NFR.SEC.1`, `NFR.PERF.4`, `MIK-6865.SCHEMA.1c`, `MIK-7215.CONTROL.3a` | 8 | eight rows, but at most **seven workstreams**, and two of those share one: `HEADER.9a`/`9b` are answered by the same absent era branch in `build_mcp_headers` (`src/transport/http/mod.rs:534-627`), and `CONTROL.3a`/`CONTROL.4` are both covered by `docs/design/2026-09-03-post-session-caller-identity.md`. The earlier "no shared mechanism" reading was wrong and is what made the residue look larger than it is — it also listed nine names against a count of ten, because `HEADER.9` was never resplit here. Not all free: `HEADER.9a`/`9b` wait on B's per-backend era and `CONFIRM.2` on A's continuation path. See below |

Cluster C carries one prerequisite that is not visible in its row. `SUB.4`'s activation is
blocked on the idempotency key binding the calling principal: `identity_suffix`
(`src/gateway/meta_mcp/invoke.rs:1128-1132`) is empty whenever identity propagation is off, which
is the shipped default, so two authenticated callers derive one KEY — not one fingerprint, which
is the same for both because the calls genuinely are the same `(server, tool, arguments)` — and the
second is served the first's stored response. Three moves are needed, not one: the fallback chain
`caller_principal` already uses (`:1140-1142`); the relocation into `derive_key` that SUB.4's own
"Constraints, measured" already decided; and a suffix that is hashed or length-prefixed rather than
concatenated raw after a client-supplied key, since without that third move the second one hands a
forgeable binding to the population it just started binding. Provenance and the full derivation:
`docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md`, which found it while
withdrawing its own duplicate of this wiring on 2026-09-06.

Cluster B is not in the table because it has nothing left to block on. `DISCOVER.5b` closed on
2026-09-05 and era detection carries no blocking row; a cluster with a count of zero is a
finished cluster, and listing it here would put a row in a rollup of what is missing that
names nothing missing.

Cluster E is gone from the table for the same reason, as of 2026-09-06, though by a different
route: `NFR.PERF.1` did not get met, it got ruled non-blocking. The operator's 2026-09-05 ruling
(quoted in full on the `NFR.PERF.1` row of `RELEASE-4.0.0-criteria-status.md`) ships 4.0.0 on the
headroom argument — worst shared case +6.07% against a 10% P99 bound, nothing near either
budget — and lifts the blocking flag on the record. The grade does not move: the row is still
PARTIAL, because the criterion's own wording still asks for a P50 and a P99 no harness in this
repository can produce, and rewording the row to fit the evidence available was explicitly
rejected. What changed is only whether that gap gates the release, which is this rollup's whole
subject — so a cluster of one PARTIAL, non-blocking row names nothing this document is for.

Cluster A is still the largest of them; its own row above carries the count. It began at
twenty-two: the wiring
landed and `MRTR.4`, `MRTR.5` and `MRTR.9` left the cluster with their evidence recorded, which
is what the shrinkage means. What is left needs no new decision either — each row needs its own
evidence over a path that already exists. The total it leaves behind is
not quoted here: `scripts/release/count-release-criteria.py --check` derives it, and this
document has already carried two counts that went stale against the ledger they describe.

The `rows` column names PARENT criteria; the `count` counts LEDGER ROWS, and the two stopped
matching once compound criteria began to be split. `MRTR.3` is one name and two rows, `MRTR.7-8`
two names and four. `MRTR.4`, `MRTR.5`, `MRTR.6` and `MRTR.9` have all left the cluster
as they were met, which is why what was once one span is now two single names and a pair.
Read the names as a key to which cluster a row belongs to, never as its size. The counts here
are derived from the ledger by prefix, not transcribed from a previous revision of this file:
every blocking row lands in exactly one cluster and the eight totals — the seven letters plus residue — sum to the ledger's, which
is the only reason this table can be trusted to be complete. The last revision covered 37 of
the blocking rows and read as though it covered all of them.

## The residue, one line each

- `MIK-7214.HEADER.9a` — `build_mcp_headers` (`src/transport/http/mod.rs:534-627`) is the
  single outbound builder and carries no era branch at all, so emission is not gated on what
  the peer negotiated. Every `negotiat*` hit in that file (`:457-501`, `:642-644`) is the
  INBOUND initialize-retry path.
- `MIK-7214.HEADER.9b` — the same absent branch: header values are not derived from the
  negotiated envelope either. Two ledger rows, one workstream — the evidence for 9a and 9b is
  byte-identical, which is why the residue above counts them once.
- `MIK-7215.CONTROL.4` — `SessionLifecycle` is sound and tested against the real type; no
  production caller registers with it.
- `MIK-7246.CONFIRM.2` — the confirmation path is `elicitation/create` over SSE, a different
  mechanism from the one the criterion names.
- `NFR.SEC.1` — 14 controls enumerated in `docs/requirements/nfr-sec1-control-inventory.md`;
  thirteen carry a refusal test, one is a recorded gap (row 5, the client circuit breaker,
  whose reclassification is the operator's call). A 15th control, the firewall, is blocked on
  files another session owns. `each` is unmet until row 5 and the firewall are settled.
  Counts as of 2026-09-06: `cargo test --test nfr_sec1_controls` = 10 passed, 0 failed. The
  "nine / five" this line carried was a transcript of an earlier draft of the inventory and
  had drifted from both the inventory and the criteria ledger.
- `NFR.PERF.4` — the ceiling and the seventeenth tool are both settled (see cluster F above);
  what is absent is the mechanism that holds the surface at the ceiling, which is a surface
  decision rather than a measurement.
- `MIK-6865.SCHEMA.1c` — see the ledger row; scored when `SCHEMA.1` was split.
- `MIK-7215.CONTROL.3a` — scored blocking when `CONTROL.3` was split; the clause it carries is
  not held by the parent's evidence.

`MIK-6704.IDENT.1a` left this residue on 2026-09-06. It was a test, not a mechanism, and the
test now exists: `tests/mik_6704_acs.rs` `mod principal_derives_from_the_credential` asserts the
positive clause at the two arms a test binary can reach, and a source guard reads every
`AuthenticatedClient` literal in `src/` for the two it cannot. Both rows were probed by
reintroducing the defect, so neither passes vacuously.

`NFR.SEC.6` left the residue on the same day. It was a traceability question across four tickets,
and all four are closed AND asserted: MIK-7222 by `tests/mik_7222_acs.rs`, MIK-7256 by mechanism
rather than by a label (a refused config candidate no longer mutates the process refusing it — its
env files build an `EnvOverlay` published only on success), and MIK-7249/7262 alongside them. The
2026-09-04 reading of this row was wrong on both of its load-bearing claims.

## The four decisions this reduced to — all four are now answered

Everything above is engineering except these. They were operator calls, and no amount of
test-writing would have settled them. Three fell to the instruction to close the full scope;
the fourth was ruled on directly. They are kept here because the answers are what the rest of
this document is now written against, and because a question that disappears once answered
reads later as a question nobody asked.

1. **Does 4.0.0 ship the continuation envelope wired, or ship without it?** **Wired.** Fifteen
   criteria hung on this. The operator ruled that 4.0.0 serves `2026-07-28` out of the box, so
   `server.modern_protocol` defaults to true and every default install reaches the modern path.
   That removes the *ship-without-it* answer outright: an unwired envelope behind a default-on
   flag is a first-run defect, not an opt-in gap. The flip cannot land before the wiring.
2. **Does 4.0.0 ship era detection wired, or detect-only?** **Wired**, by the same full-scope
   instruction. The design's own resolution is unchanged — the gateway detects and does not
   speak the modern revision outbound — so wiring the detector is the whole of the work.
3. **Is `exposed_meta_tools` enforcement acceptable as a breaking change?** **Yes** — the
   operator waived `NFR.COMPAT.3` on the record on 2026-09-02. The enforcement ships and the
   criterion no longer blocks. What that waiver bought and cost is set out below.
4. **Do the performance numbers gate the release?** **They were run** on 2026-09-03, which
   answers the question the useful way: `NFR.PERF.2` states its own consequence — without a
   number the change does not ship — and the full-scope instruction scheduled the Spark job
   rather than arguing about whether its absence blocks. The job closed `NFR.PERF.2` and left
   `NFR.PERF.1` PARTIAL for want of a P50 and a P99 the harness cannot produce. **Ruled on
   2026-09-05**: that gap does not gate either. 4.0.0 ships on the headroom argument instead —
   worst shared case +6.07% against a 10% P99 bound — and the blocking flag on `NFR.PERF.1` is
   lifted. The grade stays PARTIAL; only the release-gating question moved. See cluster E's
   removal note above and the `NFR.PERF.1` row itself for the ruling in full.

Two decisions surfaced from the residue rows remain genuinely open, and they are set out under
*Two more operator decisions* below.

## The release blocker that is not a criterion

`mcp-2026-protocol` carries unpushed commits — `git rev-list --count HEAD --not --remotes`
is the count, and it is not written down here because it only ever grows and this document
said `Ten` until it had reached thirty-one. `hooks/PreToolUse/ratification-gate.py`
hard-blocks `git push` without a ratification stamp, and only a human running `ratify` in a
terminal mints one. Until then this branch is unbacked work on one disk: a disk failure loses
it, and nobody can review what they cannot fetch. Closing criteria does not move this.

The accumulated diff also carries new production emission code
(`src/gateway/router/handlers.rs`, commit `da18b0d3`) that has not been through the
dual-vendor gate. Commit is not merge, so nothing is violated yet — the review is due before
push, and its material is the diff, not the design documents.

## Who owns what, 2026-09-01

The clusters above describe the work. This section says who is doing it, because the gap that
kept reopening was not analysis — it was that twelve of the blocking rows had no
owner, and unowned work does not fail loudly. It simply never starts.

The row counts are deliberately **not** repeated here — the cluster table above
carries them and this snapshot drifted from it within a day. One column, one job:
who owns the work.

| cluster | owner |
|---|---|
| A continuation envelope | `envelope-a`, design first. **Was assigned to a concurrent session on commit archaeology and that was wrong** — `src/protocol/continuation.rs` has not moved in 16 hours and the last substantive cluster-A commit is `149e553a`, 24 hours old. The largest cluster was unowned while this table said otherwise. |
| B era detection | `era-r4-repair` owns `src/protocol/era.rs`; `era-probe` owns `tests/mik_7217_era_probe_acs.rs`, held |
| C MIK-7272 revision surface | `surface-c`, design first |
| D response-cache keying | `cache-34` |
| E performance vs 3.5.0 | run on `spark` 2026-09-03; `NFR.PERF.2` closed, `NFR.PERF.1` needs an end-to-end harness that does not exist. **2026-09-06**: the operator's 2026-09-05 ruling lifted `NFR.PERF.1`'s blocking flag on the headroom argument (worst shared case +6.07% against a 10% P99 bound); the row stays PARTIAL but no longer gates the release, and the cluster is closed — see its removal note above |
| F compat and surface facts | the operator settled the surface questions on 2026-09-02: `NFR.COMPAT.1` became a code change and `NFR.COMPAT.3` was waived on the record. What is left is work, not a decision — the default flip and the dual-role matrix. **2026-09-06**: the default flip is done and `NFR.OBS.5` is met; the dual-role matrix and `NFR.COMPAT.1` are what remain, plus a new hard release gate on the `MIK-7212.MRTR.7a`/`7b` bridge, which the flip landed ahead of |
| G stdio dispatch path | unowned. `NFR.OBS.1` and `NFR.OBS.2` have both closed and left the cluster; what remains is `MIK-7246.CONFIRM.1a`, whose code is in the tree and which waits on the dual-vendor review verdict, not on an agent |
| — residue | `residue-r` takes the decision rows; `HEADER.9a`/`9b` belong to the header increment and wait on B |

### Ownership status, 2026-09-02: named everywhere, in flight nowhere

The table above is a list of assignments. It is not evidence that anyone is working, and today
it is not describing work that is happening.

| check | result |
|---|---|
| branches advanced in the last 24h | one — `fix/mrtr2-continuation-handle`, this note's own branch |
| last commit on `main` | 2 days ago |
| worktrees belonging to a named owner above | none |
| remote-tracking branches for a named owner | none — every `origin/*` ref but this note's own is 2 days old |
| uncommitted work in the main checkout | one file, `CLAUDE.md`, unrelated to any cluster |
| rollup rows marked met since the table was written | zero — `count-release-criteria.py --check` reported 53 blocking when this table was written; it reports 44 since the Spark run closed `NFR.PERF.2` on 2026-09-03 and the ledger splits landed |

No local branch, no remote branch, no worktree and no commit exists for `envelope-a`,
`era-r4-repair`, `era-probe`, `surface-c`, `cache-34` or `perf-e`. Two agent worktrees do exist —
`gap/meta-tool-exposure` (locked) and `gap/discover-schema` — and both belong to other work and
last moved two days ago.

**What was checked, and what was not — and the gap turned out to be the whole story.** Checked:
local branches, remote-tracking refs, worktrees in both trees, and the main checkout's working
tree. *Not* checked, at first: whether the agent processes themselves are still alive.

**They are.** Three teammate agents are running against this repository right now, one of them
writing cluster A's failing tests. So the git evidence above was accurate and its headline
reading was wrong: this is not a plan with no work happening. It is a plan whose work is
happening entirely in agent context and touching no disk. That is the more dangerous of the two,
because it looks like progress from inside and like nothing at all from outside, and a context
limit converts one into the other with no warning.

Worse, from this session those agents are not addressable: `SendMessage` resolves neither their
task identifiers nor the owner names this table assigns, and the spawn prompts are not
recoverable from the compacted transcript. Work that cannot be reached cannot be asked to
persist itself.

**The rule this earns.** An owner is a branch with commits on it *and* a live process that can be
reached. A dispatch that records only the name gives up both halves the moment the session that
made it loses its context. Future dispatches record the agent identifier next to the owner name
in this table, and every owner commits a WIP branch before doing anything else.

The last row is a weaker check than it looks and is listed as what it is. A rollup row is marked
met by a documentation act, so an owner could have landed working code and never touched this
file. It is offered as corroboration, not as an activity measure.

**What this does and does not prove.** It does not prove nothing was done: an agent can do real
work and hold all of it in its own context. It proves something worse is possible, which is that
if such work exists it is *unpersisted*, and unpersisted work is indistinguishable from no work
the moment the agent stops. The rollup's own diagnosis applies to itself: unowned work does not
fail loudly, and neither does owned work whose owner has gone quiet. The failure looks identical
from here — a table full of names and a criteria count that has not moved.

**The correction is the same shape as the one this section already made for cluster A.** An
owner is not a name in a table; it is a branch with commits on it. Until each cluster has one,
treat the assignments above as *proposed* rather than *in progress*, and read the 44 as the
number that will still be there tomorrow. The only cluster with anything landed is G, and what
landed is a design note and a test plan — deliberately no code.

**A review is only a review of the revision it ran against.** Cluster G's round-3 review
raised four findings; three of them were already closed by a commit that landed 23 minutes
*after* the reviewer started, and the fourth had been closed too. Reading the verdict without
checking its run timestamp against `git log -1 --format=%cI` on the reviewed file would have
spent a round re-closing closed findings, and — worse — would have counted a stale verdict as
the revision's review. Only one clause survived the check: the stdio `tools/list` case stated
no cardinality where its HTTP twin said *exactly one, not two*. The current revision is
therefore at round 4, unreviewed until that round returns, and the plan is not a plan of
record until it is.

One ownership rule makes the rest work: **one owner per file**. `src/protocol/era.rs`,
`src/protocol/cacheable.rs` and `src/protocol/continuation.rs` each have exactly one, and a
design that needs something from another owner's file is routed rather than edited. This is not
politeness. A shared checkout with concurrent sessions has already produced one near-miss where
a full-file write would have replaced 583 lines of a live document with 209.

### What the operator still has to decide

Three of the four decisions this document listed were settled by the instruction to close the
full scope: wire the continuation envelope, wire era detection, run the performance numbers.
The fourth was not, because both of its answers were "fix the gap" — and it has since been
answered directly:

`NFR.COMPAT.3` forbids requiring an operator to edit configuration for existing behaviour to
continue. `meta_mcp.exposed_meta_tools` was documented as an allow-list and had no effect
outside tests; GH issue 449 made it real, and `gateway_search`/`gateway_execute` — previously
reaching every backend tool regardless of the list — are now restricted by it. Either the
enforcement ships and the criterion is amended in the open, or the enforcement is reverted and
the gateway keeps shipping a field that claims a restriction it does not apply. Amending a
criterion needs the operator's recorded agreement, and on 2026-09-02 **it was given: the
criterion is waived for this field**. The enforcement ships, the row leaves cluster F, and the
release notes carry the break rather than the criterion swallowing it. The waiver is recorded
for this field only — `NFR.COMPAT.3` still binds every other configuration surface.

### The count is checked, not asserted

`scripts/release/count-release-criteria.py --check` recounts the blocking column of every table
in `RELEASE-4.0.0-criteria-status.md` and exits non-zero on disagreement. Quote it from there or
run it; do not restate it. A hand-copied figure beside a machine-checked one has already drifted
four times, most recently as a `31 blocking` that was written against a 77-row ledger and was
still being read at 99 rows.

### Still true, and not moved by any of the above

The branch is unpushed, by the count above. Every criterion in the table could go green
without changing that, and the dual-vendor review still owes its pass on the accumulated
production diff before a push is attempted.

### The two gates that are not rows, and the file two owners share

The table above names an owner where one exists, which is not the same as covering the
release. Cluster G has no owner and no branch; the remaining F and residue items are named work
rather than assigned work. On top of that, two things gate the release and appear in no row, so
nothing goes green when they are skipped:

| gate | owner | why it is not a row |
|---|---|---|
| dual-vendor review of the accumulated production diff | this session, by default | its material is the diff, not any design document; every cluster could pass its own review and this would still be owed |
| `ratify`, then the push | **the operator, at a terminal** | a ratification stamp is minted by a human running `ratify`; no agent can produce one |

The second is the shortest item on the whole list and the only one nobody else can do. Every
commit `git rev-list --count HEAD --not --remotes` reports is unbacked work until it happens: it
exists on one disk, no reviewer can fetch it, and a disk failure loses it without trace. The number
is not copied here for the same reason the plan does not copy it — it moves with every commit.

One file has two owners, and the ownership rule above did not catch it. The direct route
`POST /mcp/{name}` bypasses `invoke_tool_traced` (`src/gateway/backend_handlers.rs:724`) and
keeps no per-user cache (`:594`). `CACHE.4` binds "any shared cache the gateway keeps" and
`OTEL.1` binds tracing "across the gateway hop" — the same call site, split across cluster C and
cluster D. Both owners have been told. The seam goes to one of them and the other consumes it;
a call site owned half by tracing and half by caching is the coupling that produces the next
defect.

`NFR.COMPAT.1` is listed under cluster F as an operator fact, and it is also a dependency the
other two wirings run on. `SUPPORTED_VERSIONS` (`src/protocol/mod.rs`) does not name
`2026-07-28`; `MODERN_VERSIONS` (`src/protocol/meta.rs:219`) names it alone, and era-r4-repair's
frozen scope declares adding it explicitly out.

An earlier revision of this paragraph read that as a gap: wire both clusters, never negotiate
the revision, unwiredness moved one level up. That is wrong, and the correction matters more
than the claim did. The omission is deliberate and documented at the source
(the `SUPPORTED_VERSIONS` doc comment, `src/protocol/mod.rs`): the 2026-07-28 lifecycle scopes `initialize` to revisions
`2025-11-25` and earlier, so listing the modern revision in `SUPPORTED_VERSIONS` would have a
retired handshake negotiate a revision that has none, and a client would be told yes and then
served 2025 semantics — silent, and worse than a refusal. The omission is permanent, not an
increment waiting to land. `meta.rs:213-219` says the
same from the other side, and `discover_document` (`src/gateway/meta_mcp/mod.rs:1063-1082`)
already advertises `MODERN_VERSIONS` when the modern path is enabled, with a comment recording
that omitting it once made enabling it unreachable. era-r4-repair was right to scope the
addition out; the surface is not missing a version, it is gated.

The gate is `server.modern_protocol`, and it defaults to **false** (`src/config/mod.rs:1127`,
`:1174`, whose comment reads *"Off until the revision is served completely, not partly."*), read
at `src/gateway/router/handlers.rs:221`, `:755-760`, `:967`.

**The gate is that default, and this paragraph is where it is defined.** `SUPPORTED_VERSIONS`
(`src/protocol/mod.rs`) is not a second half of it and must stay legacy-only. Checked against the
specification rather than reasoned from the constant's name: `initialize` belongs to "`2025-11-25`
and earlier"
([lifecycle](https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle)), and a
modern client states its revision in per-request `_meta` rather than negotiating one. The same
page records that a dual-era server answers `initialize` for legacy clients and serves them the
negotiated legacy revision. Listing `2026-07-28` there would have a retired handshake negotiate a
revision that has no handshake.

This has been concluded the wrong way twice — once in the release plan, once by a reviewer — so the
reasoning is recorded here, not the conclusion alone. The two constants are separate on purpose:
`MODERN_VERSIONS` (`src/protocol/meta.rs:219`) carries the string and drives method availability on
`POST /mcp`, which is the surface the revision is actually served on. Whether 4.0.0 flips the
default at all is operator decision 5.

### One commit must not be handed to a reviewer whole

`ce72a5ba` contains 51 lines of this file that its author did not write: a `git add -A` on a
shared branch swept in another session's work while that session was mid-edit. The content is
intact and was superseded two commits later, so nothing was lost and the branch was correctly
not rewritten — rewriting shared history to repair an attribution line damages more than it
fixes. But the commit is now unsafe as review material: a reviewer handed `git show ce72a5ba`
spends findings on a document its author cannot defend, and that round does not come back.

When the cluster-D review is called, scope its material to `src/cache.rs`,
`src/gateway/meta_mcp/invoke.rs`, `tests/mik_7213_acs.rs` and the cluster's own doc sites.
The general rule this is an instance of: on a branch with concurrent sessions, stage explicit
paths. `git add -A` is a claim about the whole tree, and on a shared tree that claim is false.

### Three more operator decisions, surfaced from the residue

The four decisions above were derived from the clusters and are answered. The residue rows
carry three more, and none is settled by "close the full scope" — every answer to each is a
defensible release. These three are the open ones.

`MIK-6865.SCHEMA.1c` asks what "the revision's `$ref` and composition bounds" names, and the
answer decides whether the row is already at its boundary or has a defect behind it. The
first-party surface is measured and clean: all 19 `gateway_*` schemas and all 110+ capability
schemas are valid under 2020-12, every published `$ref` resolves in its own document, and none
of them composes at all — no `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`, at any depth
(`tests/schema_2020_12_validity.rs`, walking the emitted surface rather than the source tree,
each row probed by hand-editing a violation in). So the question is not a measurement. It is
what the sentence asks for: **(a)** a numeric limit the 2026-11-25 revision states, which needs
the clause pointed to or the row asserts an invented number; **(b)** the gateway's own
publishing policy, which makes today's zero a commitment and would refuse a legitimate `oneOf`
in a future capability; or **(c)** nothing beyond 2020-12 validity plus `$ref` resolution, which
is what the evidence already supports and leaves the words "and composition" doing no work.
The scope half changes the answer under all three: `tools/list` also forwards a connected
server's own tool descriptors verbatim — `get_cached_tool` through
`project_tool_descriptor_trust_card`, with no resolution, no meta-validation and no composition
check anywhere on that path, demonstrated by putting an `allOf` and a dangling `$ref` through it
and watching them arrive untouched. Reading it as everything the gateway *publishes* means the
gateway must start inspecting and refusing a third party's schema, which stops a backend being
routable — a product decision about what we refuse to carry. Reading it as what the gateway
*authors* leaves the forwarding gap as its own row. Recommendation, from the agent that
measured it and not an answer: **(c) plus authored-only**, with the forwarding gap filed
separately. Under (c) the row goes MET; under (a) or (b) it stays PARTIAL and the bound gets
written as a real assertion. Asked 2026-09-06, unanswered; recorded as U9 in
`docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity-test-plan.md`. The row stays
blocking either way while it is open, because an unanswered bound gives the test nothing to
assert against.

`MIK-7215.CONTROL.4` is not blocked on ownership. `SessionLifecycle::register` takes a
closure, so registration lives at gateway startup and needs no edit to a firewall file.
It is blocked on a decision nobody has made: the module replaced the disconnect trigger
the modern revision deleted with a `track`/`reap` deadline, and nothing has chosen
**who calls the reaper** or **what the TTL is**. The TTL is an operator-visible retention
number, not an implementation detail. Wiring `register` alone would leave handlers that
are registered and never fire — indistinguishable from today except that the criterion
would read as met. That is the worst available outcome and it was correctly not built.

Put to the operator 2026-09-06 with four candidate defaults and their costs; no answer has come
back. Recorded because an unanswered question and an unasked one look identical in a document a
week later, and only one of them is a process failure. Until they rule, the row proceeds under a
stated assumption rather than staying ownerless: **the reaper runs on the gateway's existing
maintenance tick and the TTL is a config field defaulting to five minutes**, chosen to match the
SSE reconnect window a client or proxy will attempt, so an ordinary network stall recovers
instead of losing the call. The assumption is cheap to reverse — it is one default value and one
call site — and it is named here so that reversing it is an edit rather than a rediscovery. What
the assumption gives up is recorded with it: thirty seconds would hold less abandoned state under
churn, and an hour would never lose a long human-in-the-loop elicitation. Neither is wrong; both
were the operator's to pick.

`MIK-7246.CONFIRM.2` requires that the destructive-confirmation gate "be reachable through the
MRTR path, so a modern client can confirm". Designed 2026-09-06
(`docs/design/2026-09-06-confirm-2-destructive-confirmation.md`); the design settles the
mechanism question that stood here before, and replaces it with a narrower one only the operator
can answer. The gate knows exactly one channel, elicitation, which needs a session, and the
modern path deliberately mints none (`router/handlers.rs:583-587`, a recorded decision:
per-request minting "grew a table of sessions nothing could reach, and handed the
sequence-anomaly detector a fresh identity every call"). There is no request-scoped channel back;
only `send_to_session` exists. So: **does a refusal count as the modern-path answer for 4.0.0?**
Yes closes the row with documentation, one test and a requirement-row edit, and does not move the
security posture, because the admin gate runs first and every governed tool is already admin-only
(`meta_mcp/mod.rs:1578-1584`), so the credential is the real control and the confirmation is the
courtesy an honest client extends to its user. No means building a gateway-originated in-band
`InputRequired` with a continuation redeem on retry: seven measured needs, all costed in the
design, reusing the continuation primitives (`Keyring`, `InFlight`, `Payload`) and none of its
call sites, because the live `redeem_retry`/`mint_continuation` pair serves *backend*-originated
exchanges on the invoke path while the confirmation case is gateway-originated at a meta-tool
gate. The honest counterweight, recorded rather than buried: the row's own words are "so a modern
client **can confirm**", and refusing is not confirming. CONFIRM.1a already mandates refusal when
confirmation cannot be obtained and 1b already forbids proceeding on a warning, so a CONFIRM.2
that also meant "refuse" would restate its two neighbours. That adjacency argues for the
affirmative reading, which is why yes is a **requirement change needing recorded agreement**, not
an interpretation the team may adopt on its own. Two questions fall out only if the answer is no:
whether a gateway-originated `InputRequired` is an acceptable 4.0.0 surface addition given
MIK-7212 is blocked by MIK-7388, or whether CONFIRM.2 is deferred with a recorded deferral, which
the row's own Source column would support; and whether requiring a *legacy* protocol
declaration to reach destructive confirmation is acceptable product behaviour. That question was
first put to the operator on a false premise -- "a modern client cannot kill a server at all" --
which `router/handlers.rs:568-597` refutes: `declares_modern_by_header` is computed per request
from the `mcp-protocol-version` header, the modern arm returns `(String::new(), None)` while the
legacy arm calls `get_or_create_session_for`, and nothing persists an era between requests. The
same client therefore reaches elicitation on any request where it declares legacy. The capability
is not absent; it is conditioned on a header the client itself controls, one request at a time.
That lowers the cost of the refusal branch materially -- yes to Q1 gives up a header-conditioned
convenience, not a capability -- and it is recorded here rather than silently repriced, because
the operator was asked to weigh a loss larger than the one that exists. The counterweight stands:
asking a modern client to downgrade a header to obtain a confirmation is a workaround, not a
design. One unknown is deferred and
belongs to the operator or the MIK-7212 owner because it is a client-ecosystem fact and not a repo
fact: does a modern client that declares in-band `elicitation` exist, and would it retry? It
blocks the build-it branch and not the refusal branch.

Put to the operator 2026-09-06 with the three branches and their costs, twice, and no direct
answer came back either time. **It did not need a third asking: the standing ruling at the top of
this same file (lines 18-47) already answers it.** Everything above this paragraph is the record
of the question as it was asked, kept because the reasoning is what makes the answer auditable —
it is not a live question, and a reader who stops before this paragraph would think it is.

**Fork closed 2026-09-06 — the answer is no, and the branch is the build.** Where a row offers
*build the mechanism* or *rewrite the criterion so what exists already satisfies it*, the recorded
operator agreement is to build; that is exactly the shape of this question, and it is exactly the
recorded agreement the repair protocol requires before a requirement may be narrowed. So
CONFIRM.2 takes the gateway-originated in-band `InputRequired` with a continuation redeem on
retry. The affirmative reading of "can confirm" stands, the refusal branch is not taken, and the
two fall-out questions resolve with it: the surface addition is settled as build, and the product
question about a legacy declaration is moot, because it only arises on the branch not taken.

What the ruling does **not** license, and what therefore stays exactly where it was: deferring
this row out of 4.0.0, or dropping one of its acceptance criteria. Those remain the operator's,
and the deferred client-ecosystem unknown above is not a licence to take either — if no modern
client that declares in-band `elicitation` turns out to retry, that is a finding carried back to
the operator with the measurement attached, not a fallback the implementer elects. The row stays
blocking until the mechanism exists, which is a different sentence from the one it replaced: it
was blocking on an answer, and it is now blocking on a build.

### A fifth decision, from correcting the `NFR.COMPAT.1` paragraph

That paragraph was published wrong and is now repaired. What the repair exposes is a decision
that no cluster surfaced, because no criterion is phrased to ask it:
**does 4.0.0 ship with `server.modern_protocol` defaulting to false?**

Both answers were defensible and neither was an analysis result. The operator took the
second; the first is recorded because it is what the second gave up.

| answer | what it costs |
|---|---|
| ~~leave it false~~ | 4.0.0 ships the modern revision behind an opt-in flag. Every cluster A and C row can be met and no default install exercises them. The release notes must say so plainly, or the version number overpromises. |
| **flip it true — taken** | the default install serves `2026-07-28`. That is only honest once the modern path is served completely — which is exactly what clusters A and C are for, so the flip is a release-gating dependency on them, not an independent switch. |

The flag is not a gap and needs no ticket. It needs a gating dependency on clusters A and C,
which is what the taken answer buys.

**Answered by the operator 2026-09-02: flip it true.** 4.0.0 serves `2026-07-28` out of the box.
The second column is therefore the one that binds: the flip is a release-gating dependency on
clusters A and C, not an independent switch, and it lands last — after the continuation path is
wired, because a default-on stateless path turns every remaining gap in it into a first-run
defect rather than an opt-in one. Until the flip lands, `README.md:355` and the PR body stating
`off by default` remain true and are not to be updated ahead of it.

### One row that looked like a decision and is not

`NFR.SEC.1` row 5, the per-client circuit breaker, was flagged as arguably N/A on the
grounds that it refuses on a trip count rather than an absent input. The criterion asks
each control for a refusal test, and a circuit breaker has a perfectly ordinary one:
trip it, then be refused. `record_client_failure` (`src/gateway/auth.rs:292`) and
`check_client_circuit_breaker` (`:272`) are both public and `failure_threshold` is a
config field, so the test is short. Writing it closes the row without narrowing a
security criterion's population — which is the more expensive mistake of the two, and
the one that needs an operator's recorded agreement.
