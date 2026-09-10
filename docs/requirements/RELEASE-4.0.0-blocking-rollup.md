<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# 4.0.0 release readiness — what the blocking criteria actually are

The ledger (`RELEASE-4.0.0-criteria-status.md`) carries the counts; run
`scripts/release/count-release-criteria.py --check` for them rather than reading a figure here,
and `--blocking` for the list of ids behind that count rather than hand-writing a regex over the
ledger — one such regex found 10 of the 28.
Whatever the blocking count is on the day, it is not that many decisions. The ledger's own
evidence cells say so — `NFR.SEC.2`, `.3`, `.4`, `NFR.OBS.4` and `NFR.PERF.3` all read
"same envelope", and `NFR.OBS.3` observes the era detection MIK-7217.DISCOVER.4-5 built. Grouping on those
clauses collapses them into **the clusters tabled below**. The residue that once sat outside them
is empty: every id still blocking belongs to a cluster, and the clusters that emptied out were
struck rather than left as rows of zeroes.

This document exists so the shape of the remaining work survives outside one session's
context. It adds no verdicts: every row below is quoted from the ledger, and the ledger
stays the source of truth for status.

A flat count is not evidence of a stall. The tally held at 28 across eighteen commits in under two
hours, and the reason is that the work is uncommitted rather than absent: `git status --porcelain`
showed live edits for `MIK-7214.HEADER.9`, `MIK-7212.MRTR.7` and `MIK-6865.SCHEMA.1c` while none of
the three had moved a ledger row. Reading the tally cold therefore under-reports progress on
roughly the rows that are being worked hardest. Before treating an unmoved count as stuckness,
check the dirty set and the last commit touching each blocking id — a stuckness call made on the
count alone would fire on exactly the wrong rows.

That check has now been run, and the answer is the uncomfortable one. Every file in the dirty set
has an mtime at least four and a half hours old, and two are from the previous day; the set itself
has not changed membership across that window. So the uncommitted work covering
`MIK-7214.HEADER.9`, `MIK-7212.MRTR.7`, `MIK-6865.SCHEMA.1c` and the cluster B trace-metadata plan
is **parked, not in flight**, and the flat count is reporting the situation correctly after all.
Marked `I`: file mtimes say nothing moved, they do not say why, and a session can be alive and
blocked as easily as gone. What would settle it is the owner answering, or a commit appearing on
any of those paths. What must not happen either way is another session adopting those files — they
are peer-held, and the standing rule on that is unchanged.

## `MIK-7214.HEADER.9`'s SSE GET path has lost its stated blocker

The ledger's `HEADER.9a` row defers the SSE GET header site with a reason: "Close is deliberately
unshaped — `MIK-7215.STATELESS.3a` requires the minted session there"
(`RELEASE-4.0.0-criteria-status.md:113`). That row is now **MET**: "no `Mcp-Session-Id` on the
modern path … test asserts `Mcp-Session-Id` **absent** on a modern response, via the real router"
(`:181`). So whoever picks `HEADER.9` up should not inherit the deferral — the thing it waited on
has landed.

Worth reading the two sentences side by side before building, because they do not obviously agree.
`STATELESS.3a` asserts a session id is **absent** on the modern path; the `HEADER.9a` note says
that row "requires the minted session there". One of the two is describing something the other is
not, and the note is the likelier suspect, being a parenthetical about a site nobody has shaped.
Either reading discharges the deferral — a met blocker blocks nothing — but the SSE GET work should
start by settling which session, if any, that site is supposed to carry.

Marked `I`. This is read from two ledger cells; the SSE GET site itself
(`src/transport/http/mod.rs`, GET header path) has not been opened here, and it is peer-held.

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

## Standing ruling applied — `MIK-7272.TASK.1.10b` is a build, not a narrowing

The first row to reach the fork after the ruling above. The criterion reads "the **served**
`initialize` **and** `server/discover` capabilities carry the identifier"
(`docs/design/2026-09-06-task-1-tasks-extension-test-plan.md:127`); the implementation narrowed it
to discovery-only and pinned the other half shut, asserting `initialize` stays silent
(`tests/mik_7272_task_1_acs.rs:244`). That is build-or-rewrite, and the ruling settles it: **build.**
It was put to the operator once and went unanswered, which the ruling answers rather than a second
attempt.

The narrowing's premise does not survive this document. It rested on `implemented_extensions()`
returning an empty map, so that no extension had ever appeared in a handshake and discovery-only
matched the architecture. Cluster C (line 109) already names "extension set write-side absent" as
one of its five half-wirings — that emptiness is the gap the cluster exists to close, not a design
to preserve.

What the build is, read at source rather than from the design document. The two surfaces are no
longer one seam: `server/discover` builds its own capabilities from
`discovery_extensions()`, which reads `ExtensionSet::gateway_declares()`
(`src/gateway/meta_mcp/mod.rs:1172`, `src/gateway/meta_mcp_helpers.rs:156`), and a comment at the
call site records why it diverged. So **the discovery half of `.10` is already served**; the
remaining gap is `initialize` alone, where `build_server_capabilities(implemented_extensions())`
still takes the empty map (`src/gateway/meta_mcp_helpers.rs:145`, `:190`). Anyone reading
`docs/design/2026-08-31-task-1-tasks-extension.md:236-243` gets the superseded one-seam picture;
that split was a §P3 design event recorded in a code comment and never in the design.

The conditional is one line and needs no version threading: `build_initialize_result` already takes
`negotiated_version` as its first parameter, two lines above the call
(`src/gateway/meta_mcp_helpers.rs:188-192`). A 2026 client gets the identifier; a 2025 client keeps
the empty map and a byte-identical result, which is what `DISCOVER.3` pins. The objection recorded
beside the initialize-silent test — that completing `.10` breaks byte-identity for every 2025
client — holds for an unconditional insert and not for a conditional one. Cost, named rather than
discovered later: `DISCOVER.3` gains a 2026 golden case, and the initialize-silent test becomes
era-scoped rather than deleted, because for a 2025 client it is still the correct assertion.

The infeasibility clause of the ruling above applies to whatever the build turns up next. It does
not apply to the seam itself: that was read at source and is reachable, so a hard edge found later
is a finding to report, never a route back to the narrowing.

Basis is `I`: this applies the standing ruling and the twice-stated full-scope instruction to one
row. No fresh operator answer exists, and none is recorded here.

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

Clusters A, D, F, G, H and I have cleared, and the residue emptied on 2026-09-10: every row they named is met or non-blocking in the ledger, so they no longer appear here. What each of them was, and how it closed, is kept in the ownership table and the notes below. This table names only what still blocks.

| # | cluster | rows | count | what is actually missing |
|---|---|---|---|---|
| C | MIK-7272 revision surface | `SUB.2` (own-stream clause), `SUB.4` | 2 | two half-wirings. `SUB.2b` is absent on the outbound leg only: the inbound legs now capture rather than discard (`parse_sse_response` returns `Result<SseExchange>`, `src/transport/http/mod.rs:312`; progress-token match, `src/transport/stdio.rs:416-431`). It stays blocking because the captured notifications have no production consumer, and the inbound scaffold does not merge alone. `SUB.4` is no longer unwired — all three routes reach a guard as of `5dd2b48c` — but it is PARTIAL rather than MET: the direct `POST /mcp/{name}` route RELEASES the client's key when the backend call fails (`backend_handlers.rs:862-867`, `idempotency.rs:562-571`), which is the broken-stream case the criterion is written about. What it now waits on is a decision about uncertain execution, not more wiring. `EXT.1`, `OTEL.1`, `TASK.1` and `MRTR.10` left this cluster as their wiring landed, and `ORDER.2` left it on 2026-09-08 |

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
every blocking row lands in exactly one cluster and the cluster totals sum to the ledger's, which
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
- `MIK-7246.CONFIRM.2` — closed on 2026-09-10 and the last row to leave the residue, which is
  now empty. The finding above stands as history: the confirmation path is `elicitation/create`
  over SSE, a different mechanism from the one the criterion names. It closed measured rather
  than argued — both halves of the continuation path were already committed, and the tests that
  read them are green at HEAD `482746c1`. `HEADER.9a`/`9b`, `CONTROL.4`, `NFR.SEC.1`,
  `NFR.PERF.4`, `MIK-6865.SCHEMA.1c` and `MIK-7215.CONTROL.3b` all left the residue the same
  way, as their evidence landed.
- `NFR.SEC.1` — closed on 2026-09-09 and no longer residue. All 15 controls enumerated in
  `docs/requirements/nfr-sec1-control-inventory.md` now carry a refusal test, which is what
  `each` asks for: row 5's is `control_5_a_modern_caller_whose_circuit_is_open_is_refused`
  (`tests/nfr_sec1_controls.rs:311`) over `client_preflight` (`src/gateway/auth.rs:951`), and
  the firewall control's is `control_15_a_modern_tools_call_the_firewall_blocks_is_refused`
  (`:393`). The team lead refused the row-5 N/A on 2026-09-07 and the inventory withdraws its
  own contrary argument at `nfr-sec1-control-inventory.md:110`. Counts as of 2026-09-08:
  `cargo test --test nfr_sec1_controls --features firewall` = 12 passed, 0 failed. What
  remains is test STRENGTH at row 5 — the case never trips the breaker through repeated
  erroring `POST /mcp` calls — which is a strengthening task, not a coverage gap.
- `NFR.PERF.4` — settled on 2026-09-08 and no longer residue. The surface decision was taken: `gateway_webhook_status` is enumerated where its registry is attached, the band is
  14-17, and `tests/nfr_perf_4_meta_tool_band.rs` holds the served surface inside it (`docs/design/2026-09-08-perf4-webhook-status-restoration.md`).
- `MIK-6865.SCHEMA.1c` — closed on 2026-09-09 and no longer residue. MET against the criteria
  as `R13` amended them; the verdict is stamped on the trust card from the production path
  (`SchemaBounds::inspect_descriptor`, `src/trust/descriptor.rs:58`, reached from
  `src/gateway/ui/control_plane.rs:583`). The residual `$anchor` limit is `MIK-7415`, not 4.0.0.
- `MIK-7215.CONTROL.3b` — regraded MET->PARTIAL on 2026-09-06, so it entered the residue rather
  than being scored into it at the split. Its test builds `_meta` one level below where a
  conforming client puts it, reproducing the code's own shape instead of a caller's, so it passes
  without establishing the clause. `CONTROL.3a` left this residue on 2026-09-07: its clause is about RETAINING a key, and the
  key is now minted by the gateway rather than supplied by the caller, so it no longer waits
  on the `_meta` seam at all. That seam is `CONTROL.3b`'s alone.

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

### Three blocking rows have no owning ticket, 2026-09-06

A ticket-state sweep on 2026-09-06 reconciled the 28 blocking rows against every `MIK-####`
reference in the ledger: 21 are owned by six In-Progress tickets, 3 are evidentially tied to
`MIK-7212`'s bridge work, 1 is `GH475.RL.10`, and **`NFR.SEC.1`, `NFR.SEC.3` and `NFR.PERF.4`
have no owning Linear ticket at all**.

They are recorded here rather than filed. The criteria ledger already tracks them with more
detail than a ticket would carry, and a Linear row would be a second copy that drifts — the
same failure this document was written to stop. What the gap costs is visibility outside this
file, which is exactly what this paragraph buys back.

The same sweep corrected `MIK-7262` from Backlog to Done — its five acceptance criteria are
met by a source-verified, mutation-probed fix that `NFR.SEC.6` already documents — and left
`MIK-7256` alone: `NFR.SEC.6` asserts it is closed by mechanism while its own prose still
hedges that "a restart-only edit published by an earlier reload is still outstanding". That
hedge is a human read, not a state correction.

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
*authors* leaves the forwarding gap as its own row. **Answered 2026-09-08, ruling `R6`**
(`docs/release/2026-09-08-team-lead-rulings.md:103`): **(c)**, and the meta-validity half is
refused on purpose — a validator on the trust path of every emitted descriptor means promoting
`jsonschema` from dev-dependency to runtime, declined under `D30`. The forwarding gap is closed
without the product decision this paragraph feared: the gateway INSPECTS what it forwards and
publishes the verdict beside it (`trustCard.schemaBounds`), and refuses nothing, so no backend
stops being routable. `src/trust/schema_bounds.rs` holds the one walker both the emit path and
`tests/schema_2020_12_validity.rs` use. The row is MET with the bound stated in it: `$ref`
resolution, not meta-validity, and composition stays an observation rather than a bound.

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

### Which of the blocking rows an operator ruling actually gates

The sections above record the decisions one at a time, as each was surfaced. What none of
them answers is the question an operator arriving cold asks first: *of the rows still
blocking, how many are waiting on me?* This table is only that. It adds no new decision
and no new criterion — the open decisions are stated in `RELEASE-4.0.0-plan.md` under
"Open for the operator" and are not restated here, only cited by their number there.

| blocking row | verdict | gated by | what an answer unblocks |
|---|---|---|---|
| `MIK-7213.CACHE.4a` | PARTIAL | plan decision 4 | whether `CACHE.1-4` are HTTP-only fixes the keying surface the design must cover |
| `MIK-7213.CACHE.4b` | ABSENT | plan decision 4 | same surface question; the policy-epoch design cannot freeze scope without it |
| `MIK-6865.SCHEMA.1c` | MET | plan decision 2 | **Settled 2026-09-08** by ruling `R6`: publish-and-flag. Nothing is refused or degraded; the descriptor carries `trustCard.schemaBounds` and composition is not a bound (`src/trust/schema_bounds.rs`) |
| `GH475.RL.10` | MET | closed, not decided | the property leg needed no operator ruling: the design's revised §4 reuses `Error::Http` instead of widening the enum, so there was no breaking change to approve. Shipped 2026-09-07 |
| `NFR.PERF.4` | ABSENT | plan decisions 7 **and** 8 | both, not either: 7 sets which served surfaces the band governs, 8 says where webhook status goes. **Settled 2026-09-08**: it stays enumerated, gated on registry attachment, and the band is `14..=17` (`docs/design/2026-09-08-perf4-webhook-status-restoration.md`) |

**Five rows, four decisions, twenty-three rows waiting on nobody.** The remaining
twenty-three are engineering the team can start today: they need a design, a reviewed test
plan and code, in that order, and no ruling stands between them and a first commit.

The one design already carrying a stop verdict is `NFR.PERF.4`'s
(`docs/design/2026-09-06-nfr-perf-4-meta-tool-surface-band.md`, revision 3, DO-NOT-SHIP),
and it stops on exactly decisions 7 and 8 — which is why that row appears here rather than
among the twenty-three. Every other design under `docs/design/` for a blocking row reads
`proposed`, `draft` or `reviewed, not implemented`: pre-implementation states, not blocks.
The single `superseded` document (`2026-09-06-gh475-rl10-capability-rate-limit-classification.md`)
names its own replacement.

Checked by reading the `Status:` line of every design document, not by recalling which
were open. That check exists because `NFR.PERF.4` was listed as the one unblocked
implementation item in an earlier draft of the plan while its own design had been
DO-NOT-SHIP on two rulings for a day.

### A sixth decision, surfaced by the MRTR.7a/7b bridge wiring

The elicitation bridge cannot land until this is settled, because landing it makes the
behaviour reachable on the first call that times out:
**when an elicitation prompt no human answers times out, does the abandonment end the round
or end the call?**

The design defers it as an ASK and `MIK-7388` carries it as `BRIDGE.4`. It is not an analysis
result: both answers are implementable and the requirement file already asserts one of them.

| answer | what it costs |
|---|---|
| **ends the round** — what row 320 says today | the backend is retried without that answer and the remaining rounds continue. Already specified, pinned by a frozen acceptance row, encoded in 23 passing tests. Cost: a backend proceeds without input a person was required to supply — the exact shape GPT-5 filed as a HIGH defect. |
| ends the call | no answer, no retry. A required human input cannot be silently skipped. Cost: row 320 and its acceptance test change before the wiring does, and one unanswered prompt ends a call that had rounds left. |

Recommendation on the record: **ends the round**, because the abandonment is already
observable — the backend receives a MISSING key, never a filed empty answer, so a caller can
distinguish *nobody answered* from *answered with nothing*. That distinction is what makes the
reviewer's objection survivable rather than merely disputed.

Unanswered as of 2026-09-06. `MIK-7212.MRTR.7a` and `7b` stay UNWIRED until it is ruled on;
the wiring itself is unaffected either way, so the ruling gates the ship gate, not the code.

## What is actually reachable right now (2026-09-06)

Two separate obstacles were being conflated, and only one of them is real.

**Not the obstacle: file collisions.** Five source files carry another session's
uncommitted edits. Classifying every blocking row by the source files its evidence
cites (`scripts/`-free, done by hand against this ledger) puts only six of the
twenty-eight behind one of them:

| blocking row | held file |
|---|---|
| `MIK-7212.MRTR.8b` | `src/protocol/continuation.rs` |
| `MIK-7212.MRTR.10a` | `src/gateway/meta_mcp/mod.rs` |
| `MIK-7246.CONFIRM.1a` | `src/gateway/meta_mcp/mod.rs`, `tests.rs` |
| `NFR.COMPAT.1` | `src/gateway/meta_mcp/mod.rs` |
| `NFR.SEC.3` | `src/gateway/meta_mcp/mod.rs`, `continuation.rs` |
| `GH475.RL.10` | `src/capability/executor_tests.rs` |

Fifteen rows cite only files nobody holds. Seven cite no source file at all and need
their evidence read before they can be scheduled.

**The actual obstacle: the working tree does not compile.** An edit to
`src/protocol/continuation.rs` calls `len()` with an argument the method does not
take (`:1023`, against the definition at `:756`). The file has not been touched since
14:20. Until it is finished or reverted, `cargo test --lib` fails for every session in
that worktree, so no criterion can produce test evidence there — which is why the
collision looked like the blocker. It was the compile.

**Workaround that touches nothing shared.** Build a committed revision in a detached
worktree, where the parked file is its clean committed version:

```
git worktree add --detach <path> <sha>
cd <path> && cargo test --lib -- <filters>
```

Used to verify `a694dce5` (48 passed, 0 failed) after the same command failed to
compile in the shared tree. This is a way to obtain evidence, not a licence to edit a
held file from a second checkout — that is working around the collision, not
respecting it.

### What that classification does not tell you

It sorts rows by the files their **evidence** cites. That is not the same as the files
a **fix** must touch, and the gap is not academic: `MIK-7272.OTEL.1` classifies as clear
— its evidence names `invoke.rs`, `trace.rs`, `mcp_provider.rs`, none of them held — yet
wiring it looked as though it required carrying the inbound `_meta` down to
`dispatch_to_backend` on `MetaMcpCallerContext` (`src/gateway/meta_mcp/mod.rs:113`, held).
FALSIFIED 2026-09-07 (`b130960b`): the value went down as an explicit parameter on the two
functions already on that path, touching no held file. The example still stands as a warning
that evidence files are not fix files — it no longer stands as an example of a blocked row.

Read the classification as a **first pass that narrows twenty-eight to fifteen**, then
confirm the fix's own file set before scheduling one. The six rows it marks held are
reliable — a cited held file is a real block. The fifteen it marks clear are candidates,
not clearances.

## Base-tree CI gap — not owned by any criterion (recorded 2026-09-07)

`cargo clippy` reports 5 errors on the base tree, reproducing unchanged without
any release change applied. Per RED-SIGNAL TRIAGE these belong to no builder on
this board: 0BUG stop-the-line covers what a change broke, never what it stood
next to. They are recorded here rather than filed as a ticket (§P0: filing is the
most expensive disposal) because they are not a decision anybody needs to make —
they are work with an obvious shape.

They still block the release. `--deny warnings` is on the CI job, so the release
cannot go green while they stand, and no criterion row will ever catch that: every
row asserts a behaviour of the gateway, and none asserts that the tree compiles
clean. A gate nobody owns is a gate nobody runs.

Evidence: reported by a builder against the base tree (I, one source — not
re-measured by the coordinator). Whoever picks this up re-measures first; a
clippy count quoted from a report is not a clippy count.

## Standing rulings issued 2026-09-07, after the fleet stopped

Every builder session hit the weekly limit within four minutes of each other.
Four rulings were outstanding in mailboxes at that moment. A mailbox reaches one
agent and dies with the session, and those sessions are dead, so the rulings are
recorded here instead. Whoever resumes a row below acts on this text without
asking again.

### MIK-7272.TASK.1.10b — the shape as built is APPROVED

The builder diverged from the instruction and flagged it rather than swapping it
silently. The divergence is upheld on both halves:

- The era is **threaded** from the dispatcher's single `classify_and_observe`
  (`router/handlers.rs:785`) rather than re-derived inside `handle_initialize`.
  The instruction asked for a second classification, and a second classification
  is two predicates answering one question, free to drift — the defect already
  sitting at `src/protocol/meta.rs:110-117`. The builder was right and the
  instruction was wrong.
- `implemented_extensions()` is **deleted**, not populated. Populating it would
  have closed the held rename finding by renaming; deleting it closes it by
  construction, leaving the finding with nothing to restate.

The review launches on this shape, unmodified. No rebuild.

### MIK-7215.CONTROL.3a — the minted correlation id as the LAST rung is APPROVED

Ordering is otel-traceparent, then session id, then the minted id — not the
literal minted-first the instruction implied. Putting the minted id first fails
two already-pinned tests that no one authorised changing, and the criterion's
clause is about the case the old placeholder string used to cover, which is the
last rung rather than the first. Row is MET.

### MIK-7215.CONTROL.3b — merge the metadata field on the meta-tool path ONLY

`extract_tools_call_params` drops the client metadata field, and the fix must
not be an unconditional merge: `route_direct_backend_call` runs before the
meta-tool match, so an unconditional merge synthesises that field into every
direct-route backend payload, inventing it for backends that never asked. Five
tests pin the current return shape; that they exist is evidence the shape is
relied upon. Merge conditionally, on the meta-tool path, and leave the direct
route byte-identical. The peer-owned call site is NOT authorised — if the
conditional merge cannot be built without it, report rather than reach in.

### MIK-7215.CONTROL.4 — YES, start-only refresh satisfies it. Land Design A.

The objection was that refreshing only at invocation start could reap an
invocation still executing past the deadline. Against the state actually
reclaimed, that cost is one identity's previous-tool entry, and the anomaly
detector already accepts exactly that loss for its own eviction, in its own
words: the caller's next call scores as a first call. Early reaping costs one
neutral-scored call. That is scoring fidelity, not a leak and not a correctness
break, so it does not justify a response-side signature change reaching through
three peer-owned files.

Land Design A as specified: 300s via the existing per-user idle constant at
`server/mod.rs:2136` — the board's `:1988` citation is stale — no new config
field, and both firewall construction sites wired. Wiring one serve path would
leave half the surface leaking, which is the whole reason the criterion exists.

### GH475.RL.10 — shipped 2026-09-07, by elimination

> **Closed.** The section below describes the state before the fix and is
> kept as the record of why the shape was chosen. What shipped: the three
> formatters became one helper, `status_error`
> (`src/capability/executor/params.rs:45`), and a `429` returns
> `Error::Http` (`8f8a478a`). The residual this section is about -- an edit
> to a format literal silently un-classifying a throttle -- is gone rather
> than detected: there is no text to edit. Two downstream arms carry the
> type where the prose used to go (`to_rpc_code`, `classify_dispatch_error`),
> each pinned by a test that fails when its arm alone is removed. The
> throttle log carries a body length, never the body (`83b75675`).


Rate-limit detection matches the text of an error message; three sites build
that message and one has a test pinning the wording, so an edit at either of the
other two silently stops a 429 being recognised and the caller reads throttled as
absent. The escalation asked whether to replace the string contract with a typed
value, which would break any consumer matching the text.

Asked of the operator 2026-09-07, no answer inside the window. Proceeding on the
one option that needs no ruling: add a typed discriminant that code checks, and
emit the byte-identical message on the wire. Nothing external breaks, so the
question the escalation raised does not arise; the frozen message needs a comment
saying why it is frozen, or someone tidies it away and reopens the defect. If the
operator later prefers the clean break, that is a further change, not a rework.
