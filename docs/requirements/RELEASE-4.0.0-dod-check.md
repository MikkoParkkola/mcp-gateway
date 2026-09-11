# DoD check — MCP 2026-07-28 support (branch `feat/mcp-2026-protocol`)

**Date**: 2026-08-30 · **Base**: `main` at 3.5.0 (`cdd52622`) · **Head**: `edfd020a`, at which §3 and §4 were re-run after that commit changed production code; every commit above it changes documentation only
**Requirements**: `RELEASE-4.0.0-requirements.md` · **Plan**: `RELEASE-4.0.0-test-plan.md`

Gates were **run**, not asserted. Where a verdict is N/A it carries its reason, because an N/A
without one is a skipped gate wearing a label. Where a gate was run against an *earlier* commit than
the head, that is said in the same line rather than rounded up.


---

# DoD re-check at `a148c94e` — 2026-09-11

**Assessment revision**: `8dd68269` — the commit at which this section's verdicts were last
re-derived. Each measurement names the commit it ran at, which is not always this one; where a gate
was run earlier, the row says so. **Head when the code-facing gates were run**: `a148c94e`
(`fix(release): record scope evidence as repository paths`); every commit since changes documentation
only ·
**Merge-base with `main`**: `origin/main` at `738c7cee`, 0 behind / 209 ahead ·
**Branch**: `feat/sub2b-outbound-mint` · **PR**: [#528](https://github.com/mikkoparkkola/mcp-gateway/pull/528) (draft) ·
**SSOT**: `~/.claude/rules-source/workflows/quality-gates-dod.md` (cited by full path deliberately —
two copies of that file exist on disk and have drifted; the bare filename resolves to the stale one)

This is the release-readiness re-check for 4.0.0. It supersedes nothing: the 2026-09-03 re-check
below is the record at `c3083368`, and the 2026-08-30 assessment under it is the record at
`edfd020a`. Verdict words carry the same meanings as in the section below — **PASS** / **FAIL**
mean the gate was run, **N/A** carries its reason, **NOT EVALUATED** means the gate applies and was
not run, and **OUTSTANDING** means only an operator act can satisfy it.

## How this was measured

The cargo gates were run on Spark in a detached worktree at `5e42f9b3`
(`/home/mikko/github/.worktrees/dod-4.0.0`), under the compute-routing rule that keeps heavy builds
off the Mac. `a148c94e` is one commit above that tree and changes a single JSON document
(`docs/requirements/RELEASE-4.0.0-scope-status.json`), so no cargo verdict below is affected by the
difference. The Python release gates and the secret scan were run on the Mac at `a148c94e` itself.
The working tree was clean at measurement time (`git status --porcelain` empty), so every verdict
belongs to the commit rather than to an in-flight edit.

One difference from the 2026-09-03 run is worth naming rather than rounding up: clippy was run as
`--all-targets -- -D warnings`, **not** `--all-targets --all-features`. Code behind the non-default
`spec-preview` and `runtime-substrate` features was therefore not linted in this pass.

**Change under check**: **82 files, +15,522 / −660** against the merge-base `738c7cee`, measured at
`5d3047bd` — 39 under `src/`, the rest documentation and tests. Three figures for this change appear
in this document and they are not in conflict: this one is the working-tree diff at the head named
here, D13b quotes PR #528's own metadata (82 files, +15,492/−660) as the forge reported it at audit
time, and both move as documentation commits land. Where a row reuses a figure taken at an earlier
commit it names that commit.

## H1–H11 — file hygiene

| gate | verdict | evidence |
|---|---|---|
| H1 SEARCH FIRST | PASS, documentation only | `ls docs/requirements/` located this file; the section was appended rather than filed separately. Scored against this document's own placement, not against the 80-file change |
| H2 UPDATE > CREATE | PASS, documentation only | third section of `RELEASE-4.0.0-dod-check.md`; no new file. Whether the 39 changed `src/` files preferred extension over creation is NOT EVALUATED |
| H3 CONSOLIDATE | PASS, documentation only | gate definitions cited by path, never restated. Consolidation across the changed source is NOT EVALUATED; see H9 |
| H4 RIGHT LOCATION | PASS, documentation only | `docs/requirements/`, beside the criteria ledger it reports on. Says nothing about where the change's new source files landed |
| H5 NAMING | PASS, documentation only | existing filename unchanged. Naming across the change's new modules is NOT EVALUATED |
| H6 no orphans | PARTIAL | `clippy --all-targets -- -D warnings` promotes rustc's `dead_code`, so a clean run rules out crate-internal orphans **except where a marker suppresses the check** — and this change adds two, at `src/backend/metadata.rs:160` and `:182` (see D10), which are exactly two crate-internal items the clean run cannot speak for. `dead_code` does not fire on `pub` items reachable from the library surface, so each of the 11 new public items was swept by hand for consumers. Ten have production call sites outside their defining file. **One does not: `IdempotencyCache::age_in_flight` at `src/idempotency.rs:554` is called only from that file's own `#[cfg(test)]` block** (the module boundary is at `:897`; every call site is at `:1037` or later). It is not dead code — `idempotency` is `pub mod` at `src/lib.rs:53`, so it is externally reachable and rustc will never flag it — which is precisely the blind spot this row warns about. Either a test-only helper is being exported, or a production caller is missing |
| H7 no redundant docs | PASS | `jscpd -f markdown` over the 29 changed Markdown files (6,534 lines) finds **0 clones at 12 lines / 70 tokens** and, loosened to 5 lines / 30 tokens, exactly **one — 10 lines, 0.14%**: the release-criteria cluster table repeated at `docs/release/v4.0.0-release-notes-DRAFT.md:172` and `docs/requirements/RELEASE-4.0.0-gap-assessment-2026-09-11.md:46`. Read at source, it is a data table each document legitimately needs to stand alone. That is the detector's result at those thresholds over the changed Markdown only; restatement below the threshold, or in documentation this change did not touch, is not ruled out and was not assessed |
| H8 no temp files | PARTIAL | `git status --porcelain` is empty in the working tree and in the Spark measurement worktree, which establishes repository state and nothing else. No on-disk housekeeping sweep was run over build artefacts or scratch directories, so that half is NOT EVALUATED |
| H9 no duplicate functions | PARTIAL | `jscpd -f rust -l 15 -k 60` over the 39 changed `src/` files at `252da51a`: **3 clones, 60 duplicated lines of 10,223 (0.59%)**. One is genuine — `src/backend/ops.rs:318` and `:456` repeat a 17-line error/metrics tail between the request path and the notification path, and it is extractable. The other two are boilerplate: a `BackendConfig` test fixture (`src/gateway/meta_mcp/protocol.rs:487` / `:535`) and the parallel subscribe/unsubscribe parameter extraction (`src/gateway/meta_mcp/resources.rs:370` / `:416`). PARTIAL because the `ops.rs` duplication is real and unfixed, not because the measurement is missing |
| H10 dir conventions | PASS, documentation only | evidence document under `docs/requirements/` with its siblings. Directory conventions across the 39 changed `src/` files are NOT EVALUATED |
| H11 untracked tracked-or-ignored | PASS | `git status --porcelain` empty |

## §3 / §4 / D9 — static gates and the suite

Every row below was run; none is asserted.

| gate | command | verdict | evidence |
|---|---|---|---|
| formatter | `cargo fmt --check` | PASS | exit 0, no diff |
| linter / SAST | `cargo clippy --all-targets -- -D warnings` | PASS | exit 0, zero warnings. `--all-features` not run — see above |
| suite | `cargo test --quiet` | PASS | exit 0 · **5,470 passing, 0 failing, 30 ignored** across 96 test targets including doctests |
| SCA | `cargo audit` | PASS with one allowed warning | exit 0. `chacha20 0.10.0` is **yanked**, reached through `rand 0.10.2` from `uuid`, `tungstenite` and the crate directly. A yank is not an advisory; no HIGH finding |
| secret scan | `trufflehog --results=verified` | PASS | 0 verified findings |
| log-leak lint | `scripts/dev/cwe532-leak-lint.py src crates` | PASS | 418 files scanned, 0 findings |
| release ledger | `scripts/release/count-release-criteria.py --check` | PASS | 149 criteria, 189 rows, 188 met or non-blocking, **1 blocking** |
| scope contract | `scripts/release/check_scope_acceptance.py --publish-check` | PASS | 31 criteria rows, 30 `pending`, 1 `met`. The one blocking criterion is NFR.SEC.7 in the *baseline* ledger, which is a different file and is not counted here |
| release gate self-tests | `test_scope_acceptance.py`, `test_scope_contract_interface.py` | PASS | 44 + 12 tests, both OK |

CI agrees with the local runs: at `a148c94e` the PR's checks report 20 SUCCESS and no FAILURE, and
the two jobs that were red — *Release criteria ledger (report-only off a tag, blocking on one)* and
*Release criteria ledger (header matches rows)* — are both SUCCESS. Their single shared cause was
the evidence format, and one data fix cleared both.

The first three rows on Spark were captured through `tail -60`, which truncated the suite output to
its last twelve targets. The gate verdict was never in doubt — the runner records `PIPESTATUS[0]`,
not the tail's status — but the *counts* above come from a second, untruncated run at the same
commit rather than from the truncated log, because a truncated log is not evidence of a total.

## D1–D30 + T1c

| gate | verdict | evidence |
|---|---|---|
| D1 TESTED | PARTIAL | 5,470 passing, 0 failing — the pass-rate half is PASS. The adaptive-coverage half is now measured, and clears on every scope except one: **85.69% of lines** workspace-wide at `f903b854`, code-identical to this head, clearing the Standard ≥80% floor (see §4 for the run, the touched-file scope and the one Critical-tier row that does not clear). It cannot be graded higher until that tier is settled: `src/idempotency.rs` is either Standard, in which case 91.84% clears, or Critical, in which case it does not, and this document does not get to pick the reading that passes. The coverage run also used default features while the suite figure is the wider set, so the two halves are not from one build |
| D2 COMPATIBLE | PASS | four behavioral changes are breaking and each carries a migration note in `docs/UPGRADING-4.0.md`, plus a one-time startup notice |
| D3 MEASURED | PARTIAL | `RELEASE-4.0.0-performance.md` carries the before/after for the workload rows: 47 shared cases, none dropped. The two estimators name different worst cases and both are under the 10% bound — by criterion's own comparison the largest regression is `semantic_search/query_top10/200` at **+7.76%** `[+7.43%, +8.09%]`; by point estimate it is `session_sandbox/check_tool_denied` at **+9.16%** (86.27ns → 94.18ns, a 7.9ns delta, +6.07% `[+5.05%, +7.11%]` by comparison). Best gain 67% on `input_scanner/scan_clean_args_5_fields`. These are microbenchmarks, not an end-to-end latency measurement. Ranking has no frozen baseline — criterion `MIK-3274.RANKING.3`, NEEDS-MEASUREMENT |
| D4 DRY | PARTIAL | scored for the evidence fix only, which edited one document and left the checker and its 44 tests alone deliberately. No SSOT-duplication sweep was run over the other 79 changed files |
| D5 CONTRACTS | PARTIAL | the evidence fix changes no public API. The branch's own API changes are graded in the criteria ledger rather than re-verified here; no interface-stability diff was run against the merge-base |
| D6 E2E | PASS | driven 2026-09-12 against the binary built from `9c1ab3d7`, the revision under review. The earlier "needs a deployed build" reading of this row was wrong: §1 FUNCTIONAL PASS says an endpoint "is driven the way its user drives it — fire the request — and that is a full pass, not a lesser one", against the revision under review rather than an already-running instance. Six behaviours driven over `POST /mcp` and `GET /mcp` by an independent driver given the wire surface and no requirements document: `MIK-7272.SUB.2b` (request-scoped progress **and** message on the originating request's own response stream, client's own `progressToken`), `MIK-7272.SUB.2a` (both excluded from the subscription stream), `MIK-7272.SUB.3` (no standalone stream, no event ids, no `Last-Event-ID` redelivery), `MIK-7272.ERROR.1` (`-32020`/`-32021`/`-32022`, none of the retired codes), `MIK-7272.ERROR.2` (`-32602` for an unknown resource URI) — six PASS, no unresolved INVESTIGATE. The sixth behaviour, foreign `Origin`/`Host` refusal with a positive control, has **no criterion row** (`rg -n rebinding` over the criteria ledger is empty) and was driven because the security rows assert it. Evidence posted per §1 step 3: PR #528 `issuecomment-5641378641`. SUB.2b's message clause is conditional on the request declaring `io.modelcontextprotocol/logLevel` — the first drive's FAIL was a brief that omitted that key, eliminated against capability gating and against the legacy path before re-driving. Two limits, unresolved rather than rounded: token mint-and-translate is indistinguishable from pass-through from the client side, and this is a debug binary on loopback, so the rows that ask for a deployed build (AC9, NFR.SEC.7) are untouched by it |
| D7 WIRED | PARTIAL | the CI wiring cited elsewhere is D24, not D7. Sweeping the 39 changed `src/` files: **7 are test files and all 7 are correctly `#[cfg(test)]`-gated** at their `mod` declaration (`src/backend/tests.rs`, `src/gateway/meta_mcp/authz_tests.rs`, `era_gate_tests.rs`, `outbound_log_tests.rs`, `src/gateway/router/backend_handlers/tests.rs`, `src/transport/http/sse_decoder_tests.rs`, `tests.rs`); the remaining **32 are ungated production modules** reachable from the crate root. At symbol level the H6 sweep found 10 of the 11 new public items called from production and one — `IdempotencyCache::age_in_flight` — called only from its own test block. PARTIAL for that one symbol; the file-level wiring is clean |
| D8 OBSERVABLE | PARTIAL | the gate is "metrics/logs/traces **+ correlation ID propagated**" and the two halves split. Emission is met: the change adds 11 `tracing::*!` / `telemetry_metrics::*!` call sites, and both backend entry points carry `#[tracing::instrument]` spans. **Propagation is not.** The crate has no correlation-ID concept — `rg -w correlation_id src` is empty — and the field that stands in for one is minted, not carried: `src/backend/ops.rs:44` and `:384` set `request_id = %uuid::Uuid::new_v4()` inside the span attribute, so every backend call invents a fresh UUID. The only other `request_id` in the change is the JSON-RPC sequence counter at `src/transport/http/mod.rs:326` and `src/transport/stdio.rs:86`, which is a protocol id, not a trace id. Nor is there an enclosing span to inherit from: `rg -n 'instrument|span!'` over `src/transport/http/mod.rs`, `src/gateway/router/backend_handlers.rs` and `src/gateway/meta_mcp/invoke.rs` returns nothing, so the two spans have no parent carrying an inbound id. Two backend calls serving one inbound request therefore carry two unrelated ids, and neither is tied to the client's request |
| D9 STATIC | PASS | see the matrix above |
| D10 0-BUG | PARTIAL | 0 debt markers in `src/`. "0 known defects" is withdrawn as well: the supplemental contract's 30 `pending` rows include unresolved assessments — identity-dependent tool catalogues crossing callers among them — and pending work is not the same as defect-free. The **no new suppression** claim was wrong and is withdrawn. Against the merge-base `738c7cee`, `src/backend/metadata.rs` gains two `#[expect(dead_code, ...)]` markers, at `:160` on `set_resend_permitted` and `:182` on `resend_permitted_snapshot`; both are deliberate (`expect` rather than `allow`, so the gate errors when the direct-route caller lands) but both are new. The third added `#[allow]` line is a move rather than an addition: `#[allow(clippy::too_many_lines)]` sits at `src/gateway/router/handlers.rs:580` on `main` and at `:620` here |
| D11 OPTIMIZED | PARTIAL | criterion benchmarks ran on Spark 2026-09-03; no profiling pass at this head |
| D12 REVIEWED | PARTIAL | three rounds (four launches) ran and **none reached the gate**, which requires `MIN_DISTINCT_APPROVALS` = 2. Round 1 on `7d6040e2` against `5e42f9b3`: kimi SHIP, gpt SHIP-WITH-FIXES, grok SHIP-WITH-FIXES — recorded as `1 of 2 required distinct vendors approved`. Round 2 on `f903b854` was launched twice: the first launch returned gpt SHIP-WITH-FIXES with grok and kimi silent; the second returned gpt SHIP-WITH-FIXES and grok SHIP-WITH-FIXES, the latter carrying the `#[expect(dead_code)]` finding that corrected D10. Round 3 on `252da51a`: gpt SHIP-WITH-FIXES, grok emitted a preamble with no `VERDICT` line, kimi wrote a 0-byte run file. **The gate is unmet because no round produced two approvals, not because the vendors went unheard** — across every round exactly one verdict was a bare SHIP (kimi, round 1) and all others were SHIP-WITH-FIXES, which the gate does not count as approval. Re-running cannot close it while findings keep landing; closing it needs either a round in which two vendors have nothing left to fix, or an operator decision to accept this section on one vendor. All rounds' findings are applied; see *What the review changed* below. What is PARTIAL is the approval count, not the review effort |
| D13 TRACKED | PASS | committed, pushed, and carried by PR #528 |
| D13a ISSUE-CLOSED | N/A | nothing may close before D18, and D18 is outstanding |
| D13b EFFORT-LOGGED | N/A | the gate is conditional — "actual effort recorded (**if tracker supports**)". The tracker does not support it. Linear's own documentation describes an estimate as "how much effort each issue **will** take" — a forward-looking complexity or size value — and the `MIK-7272` issue payload returned by the Linear API carries `estimate` (**8 Points**), `priority`, SLA timestamps and a state history, with no actual-effort or time-spent field. An estimate is not actual effort, so the conditional does not fire and the gate does not apply. A previous revision recorded this as NOT MET on the reasoning that no effort figure exists; that reasoning was right about the absence and wrong about its consequence, since the gate exempts trackers that cannot record one. What the forge can state is size, not effort: PR #528 carries **82 files, +15,492/−660** against the base. The forge's **100 commits** is a page size rather than a total — `git rev-list --count 738c7cee..HEAD` returns **234** at assessment revision `f2fb4a85`, and `gh pr view --json commits` returns only the oldest 100 |
| D13c DEPS-UNBLOCKED | PASS | the 13 held `codex/v4-*` drafts each carry an explicit held-disposition comment naming the condition for revisiting |
| D13d LABELED | PASS | `gh pr view 528` returned **zero labels** when audited, so the gate was failing rather than unevaluated. Three were applied from the repository's own set and verified back: `enhancement` (the PR is a `feat`), `security` (it changes `src/security/firewall/mod.rs` and `src/security/http_diagnostics.rs`) and `rust`. Priority is deliberately left unset — that is the operator's call, not an auditable property of the diff |
| D14 DOCUMENTED | PASS | `docs/UPGRADING-4.0.md`, `CHANGELOG.md` 4.0.0 section, release-notes draft, criteria ledger |
| D15 CLEAN | PARTIAL | the tree is clean and the evidence fix removes a CI failure while adding no file. D15 is defined as H6–H11, and three of those — H6, H8 and H9 — are PARTIAL above, each holding an unevaluated half. It cannot be scored higher than its weakest prerequisite |
| D16 TELEMETRY | N/A | no savings-emitting change on this branch |
| D17 LEARNINGS | PASS | one lesson recorded — that writing `path:line` citations into a field whose contract is a bare path breaks the gate validating it, and the fix is the data rather than the checker. The store is operator-local, so this row is an assertion about an artifact outside the repository |
| D18 MERGED | OUTSTANDING | PR #528 is a draft, `mergeable: MERGEABLE`, state `BLOCKED`, review empty. Merge is the operator's act |
| D19 BACKUP | N/A | no production state to snapshot at this stage |
| D20 ROLLBACK | PARTIAL | `docs/UPGRADING-4.0.md` §Rolling back documents the 3.x downgrade path and why it does not re-prompt. The gate asks for a *tested* procedure and nothing was exercised, so execution is NOT EVALUATED |
| D21 CANARY | OUTSTANDING | the gate is "feature flag/gradual for high-risk" and this release changes the shared transport, routing and idempotency paths, which is high-risk by that standard. The mechanism was **absent** at the previous revision and now **exists**: `514aff5d feat(release): publish a prerelease tag to opt-in channels only` adds `scripts/release/check_tag_manifest.py` (19 unit cases, run by all three tag-triggered workflows) and makes a `v4.0.0-rc.1` tag reach only channels a user opts into — the GitHub release is marked prerelease, npm publishes under `next`, crates.io receives a prerelease Cargo will not resolve for `^4`, `ghcr:latest` is withheld while the version tag is still signed and SBOM-attested, and the Homebrew formula bump and MCP Registry listing are skipped. Staging procedure and the five stable pointers to observe unmoved: `docs/release/v4.0.0-prerelease-channel.md`. Not a feature flag — feature-gating the transport rewrite would double the code paths in the highest-risk area of the release — but the gradual-rollout half of the gate, which is the half a client-installed binary can satisfy. **OUTSTANDING, not MET**: no rc has been published, so no exposure has been staged and nothing has been observed. That publish is an operator act. Claiming MET off a workflow edit is the fabrication this gate exists to catch |
| D22 TELEMETRY (structured) | PASS | the gate asks for structured, queryable telemetry and the binary emits it on two channels. `setup_tracing` at `src/lib.rs:113` takes a format argument and installs `fmt::layer().json()` when it is `"json"` (`src/lib.rs:118-122`), driven by `--log-format` / `MCP_GATEWAY_LOG_FORMAT` (`src/cli/mod.rs:143-146`); events carry named fields rather than interpolated prose — `audit_refusal` at `src/gateway/authz.rs:139` emits `transport`, `caller`, `server`, `tool`, `reason` as fields, and dedicated targets exist for machine consumers (`mcp_gateway::observed`, `projection_ab` at `src/gateway/meta_mcp/invoke.rs:358`). Independently, the firewall writes one NDJSON line per invocation (`src/security/firewall/audit.rs`). Bounded statement: JSON is opt-in, the default remains human-readable text, and logs go to stderr by design — stdout carries JSON-RPC frames (`src/lib.rs:105-107`) |
| D23 ALERTING | PARTIAL | thresholds exist and are configurable on both paths: cost governance ships three tiers — 50% `Log`, 80% `Notify`, 100% `Block` (`src/cost_accounting/config.rs:48`, asserted at `:121-129`), and the firewall carries `anomaly_threshold` defaulting to 0.7 with an opt-in `anomaly_block_threshold` (`src/security/firewall/mod.rs:84-103`). The routing half is what falls short. `AlertAction::Notify` appends a string to the response's `warnings` vector (`src/cost_accounting/enforcer.rs:229-233`) and `Log` emits a `tracing` warning; both terminate in-process. A search for an outbound alert destination — webhook, pager, mail — found none: `src/gateway/webhooks/` is an *inbound* receiver (`src/gateway/webhooks/mod.rs:101`), not a notifier. So failures do raise alerts, and an operator supervising stderr or reading the response sees them, but there is no configurable route to an operations channel |
| D24 ENFORCEMENT | PASS | the scope check is enforced in three workflows, not documented only |
| D25 SESSION | N/A | no agent-session persistence change |
| D26 SEC-MONITOR | PARTIAL | three of the gate's four requirements are met in code. **Distinct channel**: the firewall's `AuditLogger` opens an append-only NDJSON file (`src/security/firewall/audit.rs:62-70`), a sink separate from the stderr tracing stream that carries ops logs, and `firewall` is a *default* feature (`Cargo.toml:178`). **Sanitized input logging — partially, and the module's own claim overstates it**: `AuditEntry` records `args_hash`, a SHA-256 of the arguments, and the module comment says raw argument values are never logged (`src/security/firewall/audit.rs:11-13, 44-45`). That holds for the argument payload and not for the entry as a whole: the same entry serializes `findings`, and `Finding.matched` is documented as "the matched pattern or fragment (truncated for logging)" (`src/security/firewall/mod.rs:262-263`). A scanner hit therefore writes a truncated fragment of the input into the audit log. Truncated is not the same as hashed, and the module comment should not be read as covering it. **Anomaly thresholds**: `anomaly_score` is carried on every entry and compared against the configured threshold (`src/security/firewall/mod.rs:84-103`). Auth and permission refusals are recorded by a helper an authorizer cannot suppress (`src/gateway/authz.rs:128-147`) — but that helper emits a `tracing` warning, which lands on the **ops** stream, not in the NDJSON security channel. So the gate's own pairing, auth and permission events reaching a channel distinct from ops, is **not** met by the refusal path: the distinct channel exists and carries firewall verdicts, while authorization refusals go to the stream everything else goes to. Two gaps: the channel is **opt-in** — `audit_log` defaults to `None` (`src/security/firewall/mod.rs:62, 133`), so an operator who sets no path gets no separate security log, and the `stderr()` fallback (`:326`) applies only when an explicitly configured path fails to open. And **immutable** is met only as append-only file mode; a search for hash chaining, signing or tamper-evidence in the audit modules returned nothing, so a writer with file access can still rewrite history |
| D27 COUPLING | PASS | the dependency count is unchanged — no crate added, lockfile untouched. A top-level module graph built from every `crate::` reference in `src/` at `738c7cee` and at this head is **identical in shape**: 55 modules both sides, one strongly-connected component of 30 modules both sides, and **no module newly inside it**. The cycle is pre-existing and this change neither widens nor enters it. Five module-level edges are added and none removed (`backend`→`error`, `error`→`security`, `transport`→`backend`, `transport`→`error`, `transport`→`failsafe`); read at source, three are doc-comment links (`src/error.rs:140` and `:142`, `src/transport/stdio.rs:441`), one is confined to a test module (`src/transport/http/tests.rs:2215`), and the only compile-time addition is `use crate::error::{Error, Result}` at `src/transport/http/sse_decoder.rs:40` — transport depending on error, the conventional direction. No inversion. Limitation: the graph is built from textual `crate::` references, so it over-counts doc links and test code, which is why each new edge was read individually |
| D28 API-SURFACE | PASS | `git diff 738c7cee..HEAD -- src` adds **11 bare-`pub` items and removes 0**, plus 28 `pub(crate)`. The additions sit in `src/error.rs` (1), `src/idempotency.rs` (3), `src/protocol/meta.rs` (1), `src/security/firewall/mod.rs` (2), `src/security/http_diagnostics.rs` (2) and `src/transport/mod.rs` (2); **all five modules are exported from `src/lib.rs`** — `error:47`, `idempotency:53`, `protocol:65`, `security:76`, `transport:89` — so all 11 additions are externally reachable, not a crate-internal subset. The additions are additive, but **the release does carry one breaking public-API change, and the earlier "no signature change" reading of this row was wrong**: `pub trait Transport`'s `request_with_headers` gains a required parameter, `_resend: ResendPermission` (`src/transport/mod.rs:112-120`, added by this diff along with the `ResendPermission` enum itself). The method carries a default body, so an implementor that never overrode it is unaffected — but any external implementor that *did* override it, and any external caller of the five-argument form, fails to compile. That is a breaking change on a `pub` trait and belongs in the breaking-change list D2 keeps, not in an additive-only verdict. Found by review, verified at source |
| D29 DEBT-TRAJ | PARTIAL | clippy is clean at `-D warnings`, which bounds but does not measure the trajectory. The dependency-graph comparison D27 records *was* run — 55 modules and one 30-module cycle on both sides of `738c7cee`, identical in shape — so the coupling half is not the gap. What is unmeasured is trajectory over time: this branch has no debt figure from a prior release to move away from |
| D30 SUPPLY-CHAIN | PASS | `cargo audit` clean of advisories; no new dependency; lockfile unchanged by this commit |
| T1c MOAT-MEASURED | N/A | the gate fires on emerging tech whose advantage is *asserted without numbers*. This release asserts none: the 82 changed files include no benchmark artefact, `benchmarks/public_claims.json` is unchanged, and the `README.md` diff adds no numeric or comparative claim (`git diff ... -- README.md | rg '^\+' | rg -i '%|x |faster|token|benchmark'` returns nothing). The repository's standing moat claim — the schema-only context reduction — already carries measured numbers in `benchmarks/public_claims.json` behind a CI drift check, and this branch neither alters nor relies on it |

## §1–§13 and B1–B4 — the SSOT rows this table would otherwise omit

The D-gates above are not the whole SSOT. These rows are named so that an unevaluated gate is
visible rather than absent.

| gate | verdict | evidence |
|---|---|---|
| §1 requirements traced | PASS | 149 criteria, 189 rows, each graded in `RELEASE-4.0.0-criteria-status.md` |
| §2 WIRED (reasoned) | PARTIAL | D7's sweep of the 39 changed `src/` files ran and is recorded above: 7 test files correctly `#[cfg(test)]`-gated, 32 ungated production files. What is still absent is the *reasoned* half this gate asks for beyond D7's mechanical sweep — per-symbol reachability argument for the newly public surface |
| §3 static matrix | PASS | the matrix above, run not asserted |
| §4 test matrix | PARTIAL | suite PASS. The SSOT gives this gate three measurable legs — coverage thresholds, coverage no-drop (§5) and **mutation ≥75% on new code, ≥85% on a Critical path**. **The threshold leg is measured and clears everywhere but one file; the no-drop leg is measured and passes; the mutation leg is NOT EVALUATED at this head.** No `cargo-mutants` run covers this branch's diff: the preserved 2026-08-30 section records mutation as incomplete on a different branch, and nothing since supersedes it. `cargo llvm-cov --workspace --summary-only --no-fail-fast` ran on Spark against `f903b854`, which is code-identical to this head (`git diff --name-only f903b854..HEAD -- src tests Cargo.toml Cargo.lock` is empty, every commit since being documentation). Exit status 0; **85.69% of lines** (75,305 / 87,880), 85.88% of regions, 86.68% of functions across the workspace. Against the canonical thresholds: **Standard ≥80% passes on both candidate scopes, and Critical ≥95% passes on every touched file whose tier is settled.** The whole workspace is 85.69%, and the stricter scope this document's own §P3 choice mandates — the files this change touched, taken together — is **85.79%** (14,858 / 17,319), over the 31 of 39 changed source files llvm-cov instruments; the eight absent are seven `*_tests.rs` / `tests.rs` modules and `src/security/mod.rs`, which carries no instrumented regions. **Critical ≥95% passes on the security and protocol files this change touched** — `src/security/firewall/mod.rs` 97.33%, `src/security/http_diagnostics.rs` 98.21%, `src/protocol/meta.rs` 96.43%, `src/backend/era.rs` 100%, `src/transport/notification_sink.rs` 99.74%. One row is named rather than buried: `src/idempotency.rs` at **91.84%** does not clear Critical, and replay protection is arguably a Critical rather than a Standard path; this document records it as a reading a reviewer may disagree with, not as a settled tier. **The no-drop leg is now measured and passes, after two earlier readings of why it could not be that were both wrong.** It was first called structural — no baseline anywhere — which the 2026-08-30 section below refutes: that records **83.16%** whole-crate at `4c599c89`. It was then called not agent-runnable, which was also false; it was simply unrun. The 83.16% figure is not *comparable* — different branch, different head, `--all-features` rather than default, crate rather than workspace scope — so a matched pair was measured instead: the identical command on the merge-base `738c7cee` and on `f903b854`. **Base 85.12% of lines (73,324 / 86,140); head 85.40% (75,050 / 87,880); regions 85.35% against 85.61%. Coverage rises by 0.28 points of lines and 0.26 of regions, so there is no drop.** Both sides exited 0. Both runs carry `-- --skip cli::gh462`, and the reason is recorded rather than buried: 18 `cli::gh462_*` rows in `tests/gh462_config_preservation.rs` are instrumentation-hostile — they snapshot a directory into which the instrumented child writes `.profraw` files — and they fail at the merge-base under coverage while passing at the head. Skipping them on **both** sides is what makes the two halves comparable; measuring only the side where they pass would have compared two different suites. Default features only, so `spec-preview` and `runtime-substrate` stay unmeasured for the same reason they stay unlinted |
| §5–§7 | PARTIAL | §7 Documentation is PASS — upgrade guide, changelog, release-notes draft and this record, all updated for the user-facing changes. §5 Change Safety is itself split: **coverage no-drop PASSES** on the matched pair §4 records (85.12% base, 85.40% head), and nothing destructive ran without approval, but §5's third leg — new and changed code at 100% — is NOT EVALUATED, and the preserved 2026-08-30 section explains why a changed-line figure is not trustworthy here: llvm-cov's LCOV exporter and its own JSON summary disagreed by up to 9.9 points on the same file. §6 Regression is NOT EVALUATED: no bug-to-failing-test trace was run on this branch |
| §8 STRIDE / DAST | PARTIAL | **STRIDE run at this head over the changed surface; DAST still NOT EVALUATED.** The release adds one genuinely new caller-visible channel — the gateway's own `notifications/message` on the requesting stream — and that is where the pass concentrated. **S**: no new authentication surface; `agent_id` is a label read from the caller's own context and defaults to `"anonymous"` (`src/gateway/meta_mcp/invoke.rs:1531`), so it identifies without authenticating, as before. **T**: the new per-request state is `tokio::task_local!` — `SINK`, `TRANSLATIONS`, `LEVEL` at `src/transport/notification_sink.rs:36-51` — which no other task can reach, so the channel adds no cross-request mutable state. **R**: the repudiation gap is the one D8 records and this change does not close it; the new `trace_id` is caller-visible but the backend spans still mint fresh UUIDs. **I**: the emitted payloads carry `agent_id`, `server`, `tool`, `trace_id` (`:1543-1553`) and a refusal naming ADR-008 INV-2 (`:1344-1353`) — every field is either supplied by the caller in the same request or is the caller's own label, so nothing crosses a tenant boundary, and delivery is per-request by construction. The process-wide `DROPPED` counter is operator-facing and logged, never returned to a caller (`:120`). **D**: the sink is a per-request bounded channel, `mpsc::channel(REQUEST_NOTIFICATION_DEPTH)` with depth 64 (`:34`, `:70`), and sheds via `try_send` rather than stalling the call (ADR-014 §5), so a chatty backend cannot stall its own caller or reach another's queue. **E**: the release *reduces* privilege surface — `25d00554` refuses era-removed methods on the direct backend route, which previously served them. **Not covered**: runtime DAST, which needs the same deployed build NFR.SEC.7 waits on |
| §9–§10 | PARTIAL | **§9 Ops**, three legs: *alerts/metrics updated* is met for what this branch adds — the diff against `738c7cee` introduces three labelled counters on the new refusal paths (`mcp_health_probe_unserved_total`, `mcp_gateway_removed_method_refused_total`, `mcp_resend_denied_total`), which is the error-rate signal the gate names; *rollback documented* is met (see D20); *feature flags* is outstanding rather than absent (see D21: a prerelease channel now exists, no rc has been staged through it). The gate also asks new components to emit **latency, token and memory** alongside error rate, and this branch adds counters only — no histogram, no timing — so three of the four required signal families are absent for the new paths. **§10 Perf**: the gate's budget is stated as P50 +5% / P99 +10%, and **no end-to-end P50/P99 measurement exists** — D3 and AC6 both say so. What was measured is a Criterion microbenchmark set, whose worst criterion `semantic_search/query_top10/200` moved **+7.76%** [+7.43%, +8.09%]. A microbenchmark estimate is not a percentile of served requests, so it can neither clear the budget nor breach it; it is a signal that the slowest measured path moved by more than the P50 allowance, recorded under NFR.PERF.1 and standing under the operator's non-blocking ruling. Token, memory and bandwidth budgets were not measured, and the percentile budget is **NOT EVALUATED** rather than exceeded. **Soak: FLAGGED as the gate instructs** — a case-insensitive search of every `.yml`/`.yaml` in the repository, hidden files included, finds no soak configuration, and this is a large change by the gate's own standard |
| §11 | **BLOCKS — determinate, not unassessed** | §11 is a list of conditions that stop the line, and at this head **two** of them hold. **Not integrated**: the D18 delivery chain is incomplete — PR #528 is a draft with zero reviews, so it is unreviewed and unmerged. **Not deployed**: the listening process is `3.4.0-f30539af`, which predates `5d25f104`; this is the same fact that holds NFR.SEC.7. **UAT: this condition is now closed.** A UAT was run 2026-09-12 against the binary built from `9c1ab3d7` — six behaviours driven by an independent driver over `POST`/`GET /mcp`, six PASS, no unresolved INVESTIGATE, evidence at PR #528 `issuecomment-5641378641` (see D6). The gate blocks on a UAT that never ran exactly as it blocks on a failing one; neither now applies. Of the remaining conditions, three do *not* fire: CI is green, no security regression is recorded, and the change is wired to a production consumer (§2/D7). The coverage condition is **not** cleanly clear, and reading it as clear was an error: the gate blocks on coverage *below the fail-under floor*, which is a different question from the no-drop leg §4 measures. Coverage rises (85.12% → 85.40%), but D1 leaves the applicable floor for idempotency unresolved, so whether this head sits above its own floor is unresolved with it. So §11 now blocks on delivery and deployment — both operator acts — and on that one unresolved floor |
| §12 peer review | PARTIAL | §12 is Peer Review, not documentation; the documentation evidence that stood here has moved to §5–§7 where it belongs. The verdict is D12's: three rounds, four launches, never two distinct vendor approvals in one round |
| §13 | MET | three legs, three met. **Follow-ups → backlog**: `docs/requirements/RELEASE-4.0.0-backlog-triage.md` carries the triage. **Retro comment on the PR**: posted at <https://github.com/MikkoParkkola/mcp-gateway/pull/528#issuecomment-5641100336> (comment id `5641100336`, verified through `gh api`), covering what worked, what did not, and what changes next. **Done Log**: `docs/DONE-LOG.md` exists and links the PR and the retro |
| B1 IDENT | N/A | the attribution surface is untouched: the 82-file diff contains no `src/attestation/`, `src/identity_grants.rs`, `src/identity_propagation/`, `src/mtls/` or `src/key_server/` path. The one attribution-adjacent gap this release does carry — backend spans minting a fresh UUID instead of propagating a correlation ID — is graded under D8 rather than double-counted here |
| B2 MEM | N/A | a protocol and router change with no agent-memory surface; hebb owns memory and is not in the diff |
| B3 DURABLE | PARTIAL | in scope and partly evidenced. `src/idempotency.rs` changes substantially (+399/-71), and the suite carries checkpoint and restart rows that run green in the D1 pass — `tests/mik_5223_acs.rs:350` `ac_9_b3_durable_rotation_state_persists_across_checkpoint`, `tests/mik_7218_acs.rs:282` `mcp728_u1_2_stdio_window_survives_process_restart`, `tests/mik_7217_era_probe_acs.rs:373` `discover_5_a_restart_discards_the_cached_era` (the era mechanism this branch adds), and `tests/mik_7272_sub4_three_routes.rs:295` `direct_route_does_not_replay_across_callers`. What is *not* covered is a mission-length disconnect-and-resume against a live peer; the green rows are unit-scoped |
| B4 PLATFORM | PASS | the change routes through the gateway's own primitives — capability system, meta-MCP surface, transport layer — rather than adding parallel plumbing. `mcp-gateway` **is** the Bet-4 platform, and this release extends it in place |

## Acceptance criteria for 4.0.0

The criteria ledger (`RELEASE-4.0.0-criteria-status.md`) is the authority; this table is its
one-line summary plus the supplemental scope contract.

| # | Acceptance criterion | Status | Evidence |
|---|---|---|---|
| AC1 | Every release criterion is graded, none silently absent | PARTIAL | `count-release-criteria.py --check` passes over 149 criteria and 189 rows, which establishes that none is *absent*. It does not establish that each is *graded*: `RELEASE-4.0.0-scope-status.json` holds 30 `pending` rows, 25 of which carry the note "Not yet graded against the approved scope update." Baseline coverage is complete; grading is not |
| AC2 | At most one blocking criterion remains, and it is named | MET for the baseline ledger only | the baseline criteria ledger has exactly one: NFR.SEC.7, `RELEASE-4.0.0-criteria-status.md:411`, "blocking until the live endpoint passes". This does **not** clear the release. The supplemental contract `RELEASE-4.0.0-scope-status.json` carries **31 criteria rows: 30 at `pending` and 1 at `met`** — no third status exists in the file — and those 30 are obligations this row's count never covered |
| AC3 | Static gates green at head | MET | fmt, clippy, audit, secret scan, log-leak lint — all exit 0 |
| AC4 | Suite green at head | MET | 5,470 passing, 0 failing, 30 ignored |
| AC5 | Breaking changes carry a migration path | MET | `docs/UPGRADING-4.0.md`, five items, each with the action needed — D2's four breaking behavioral changes plus the one-time startup notice, which is why the two counts differ |
| AC6 | Performance contract measured, no regression past the freeze | PARTIAL, non-blocking by operator ruling | NFR.PERF.1 is recorded PARTIAL and non-blocking. Largest regression +7.76% by criterion comparison, +9.16% by point estimate, both inside the <10% band. These are microbenchmarks; no end-to-end tool-call latency measurement exists, and ranking has no frozen baseline |
| AC7 | Supplemental scope contract validates in CI | MET | `check_scope_acceptance.py --publish-check` green; both previously-red jobs read this step |
| AC8 | Out-of-scope work is held with a stated condition, not abandoned | MET | 13 `codex/v4-*` drafts, each commented with its held disposition |
| AC9 | Origin/Host enforcement proven against a deployed build | **NOT MET — blocking** | needs an operator deploy of a build carrying `5d25f104`; the listening process is `3.4.0-f30539af`, which predates it. The enforcement itself is now proven against **this revision's** binary (`9c1ab3d7`): foreign `Origin` and foreign `Host` both refused, correct ones accepted, positive control included — PR #528 `issuecomment-5641378641`. That closes the behavioural question and leaves only the deploy, which is this row's literal wording and an operator act |
| AC10 | A driven end-to-end journey passes against that build | **NOT MET — blocked by AC9** | the journey half is done: six behaviours driven over `POST`/`GET /mcp` against `9c1ab3d7`, six PASS, recorded in D6 and in PR #528 `issuecomment-5641378641`. "That build" is AC9's deployed build, so this row cannot close on a locally-driven binary however fully it passes; what remains is the deploy alone, not the driving |
| AC11 | Dual-vendor review of the release head | NOT MET | five rounds ran on **this section** and none recorded the two distinct vendor approvals the gate requires (see D12): every round but the first returned SHIP-WITH-FIXES from every vendor that answered. The claim that stood here — that 233 of the 234 commits between `738c7cee` and `f2fb4a85` "were excluded from every round" — was **false as written**, and true only of the five document rounds. The branch's Rust has been reviewed repeatedly: twelve recorded runs cite its files (`src/gateway/meta_mcp/invoke.rs`, `src/transport/http/sse_decoder.rs`, `src/transport/notification_sink.rs`, `tests/mik_7272_sub2b_acs.rs`), and one of those rounds **did** pair two distinct vendors on the same material — `kimi-review` SHIP (`synthetic-20260911T150153Z-15208.md`) and `grok-review` SHIP (`grok-20260911T150156Z-15632.md`), three seconds apart on revision `0a477a4b`, both already cited in `RELEASE-4.0.0-blocking-rollup.md:1276,1344`. What the gate asks for is nonetheless still absent: every one of those rounds took a narrow sub-scope as its material — that pair reviewed a stdio notification-drain change — and **no round has taken the release head as its payload**. NOT MET for that reason, not for an absence of review. Grading this from per-file citation counts would repeat the same error in a new form: a reviewed file with no findings is cited nowhere, so citations bound review from below and never from above |
| AC12 | Merged to `main` | **NOT MET — operator act** | PR #528 draft, state `BLOCKED` |

## Verdict

**Not every gate that was run is green, and the count of what remains is larger than one blocker.**
Two operator acts hold the release — the NFR.SEC.7 deploy and the #528 merge — and **§11 stops the
line on three of its own conditions**: unreviewed and unmerged, not deployed, and a UAT that has
never been run. The first two are the operator acts restated in the gate's own language; the third
is not, and nothing in this record closes it. Behind them sits no wholly unevaluated row and a large
set of unevaluated halves inside PARTIAL rows, inventoried below — thirty `pending` rows in the
supplemental contract (`RELEASE-4.0.0-scope-status.json`), and one gate that ran three rounds across
four launches without reaching its own threshold: the dual-vendor review never recorded the two
distinct approvals D12 requires. The baseline ledger's "one blocking criterion" is true and is not
the whole number.

The code-facing picture is clean and was run rather than asserted. Formatter, linter-as-SAST, the
full 5,470-test suite, dependency audit, secret scan and the log-leak lint all pass at this head.
The release ledger validates, the scope contract validates, and the two CI jobs that were red are
red no longer — their single cause was this branch writing `path:line` citations into a JSON field
whose contract is a repository path, which the acceptance checker resolves with `is_file()`. The
fix put the data back into the format the contract and its 44 tests specify and moved the line
numbers into each row's `note`, where they are still readable and nothing validates them. Widening
the checker was the alternative and was rejected: a gate that resolves `scoring.rs:190` by
discarding `:190` also accepts `scoring.rs:99999`, and this is the gate whose output says the
release is shippable.

**Two holds need the operator.** **NFR.SEC.7** is the single blocking criterion and is terminal for
an agent: a listening process answers a foreign `Origin`/`Host` with the full tool list, and proving
the fix requires a deploy of a build carrying `5d25f104` — the running process is `3.4.0-f30539af`,
which predates it. Its second half, drift between merged and listening controls, was met on
2026-09-11 by `scripts/dev/check-control-drift.py` against `security-controls.toml`. **D6** cannot be
driven until that deploy exists, and **D18** is the merge itself.

**The larger hold is not an operator act, and it is larger than one count.** Reading the tables
above rather than a remembered number, two different things are outstanding and should not be added
together.

**No row now carries "no evaluation at all."** The last three — §9–§10, §11 and §13 — were assessed
at this head and resolved into determinate verdicts rather than being reclassified: §9–§10 is
PARTIAL (three new error-rate counters, no latency/token/memory signal for the new paths, the
NFR.PERF.1 microbenchmark regression, and a soak configuration the gate asks to be flagged when
missing — it is missing), §11 **BLOCKS** on three of its own conditions (unreviewed and unmerged,
not deployed, UAT never run), and §13 is now MET: the two gaps it recorded were closed at this
revision — the retro is comment `5641100336` on PR #528 and the Done Log is `docs/DONE-LOG.md`.

**Twenty-four rows are PARTIAL**, and they are not one kind of thing. Most hold an unevaluated half that no count above reaches — H6, H8
and H9 in file hygiene; D1, D3, D4, D5, D7, D8, D10, D11, D12, D15, D20, D23, D26 and D29 among the
D-gates; §2, §4 (mutation), §5–§7 (§5's changed-line leg, and §6), §8 (DAST) and §12 among the SSOT
rows, to which §9–§10 is now added; and B3. **Four of the twenty-four hold a measured deficiency
rather than an unrun assessment**, and lumping them with the rest understates them: H9 (duplicate
logic found, not merely unlooked-for), D8 (the observability half that was scored and fell short),
D12 (five rounds run, the threshold not reached) and D23 (thresholds present, no alert route
exists). Those four need a decision or a change, not a measurement. §11 **BLOCKS**, and three are
**OUTSTANDING** on an operator act: D6, D18 and D21 — the last of these was NOT MET at
the previous revision and moved once the prerelease channel landed. Every number in this paragraph is counted off the
tables above; the previous revision said "fourteen" while listing nineteen.

**Most of what is outstanding is agent-runnable, and calling it deploy-blocked was wrong.** A
previous revision of this section filed D22, D23, D26 and DAST behind the NFR.SEC.7 deploy. Three of
those four never needed it, and all three have now been run at this head rather than merely
reclassified: D22 is **PASS** (JSON tracing layer plus the firewall's NDJSON stream), D23 is
**PARTIAL** (thresholds configurable on both paths, but no outbound alert route exists) and D26 is
**PARTIAL** (a distinct, sanitized, threshold-carrying security channel that is opt-in and only
append-only rather than tamper-evident). Each verdict cites source, and each is a read of the code
in this working tree — no deployed process was involved.

**What genuinely needs the deployed build** is narrower: D6's end-to-end pass, the *live* half of
§8's DAST — its configuration half is as readable as the other three — and D20's rollback
*execution* as opposed to its documentation.

**What has been closed since the previous revision**: D21 NOT MET, T1c N/A, B1–B4 as N/A, N/A,
PARTIAL and PASS, §8's STRIDE pass over the changed surface, and §4's coverage threshold leg measured
on Spark at 85.69%.

Naming which is which is the point. A gate folded into N/A stops being work and starts being an
unexamined assumption, and a gate filed under "needs the operator" when an agent could run it today
is the same mistake wearing a better excuse.

None of the unevaluated gates is a discovered defect. The distinction this record insists on is
between *green* and *unexamined*, and at this head there is considerably more of the second than the
first table suggested before review.

## What the review changed

Three vendors reviewed `7d6040e2` against `5e42f9b3` on 2026-09-11 — gpt and grok returned
SHIP-WITH-FIXES, kimi SHIP. Their findings are applied above, and they were right about a class of
error worth naming: **eleven rows had been scored against the smallest commit in the range while the
section's header claimed a re-check of all eighty files.** D4, D5 and D21 are the clearest cases — a
one-document fix genuinely adds no dependency and needs no canary, but that says nothing about a
release touching transport, routing and idempotency.

Two findings corrected facts rather than verdicts, and both were verified at source before being
accepted. The `#[allow(clippy::too_many_lines)]` reported as a new suppression is a **move**: it
sits at `handlers.rs:580` on `main` and at `:620` here, so that particular claim does not stand against
D10 — which remains PARTIAL for the reasons its own row gives. And the
largest regression depends on which estimator is read — `semantic_search/query_top10/200` at +7.76%
by criterion's own comparison, `session_sandbox/check_tool_denied` at +9.16% by point estimate. The
earlier row quoted the second case's *comparison* figure and called it the worst, which understated
the first.

One reviewer suggestion was not taken. grok proposed dropping the benchmark file from
`MIK-3274.RANKING.3`'s evidence, since a pending row needs none and the note already calls the file
unrelated. It stays, labelled as inventory evidence: the claim being made is that the directory
holds nothing usable as a ranking baseline, and the file that is there is what supports it.

---

# DoD re-check at `c3083368` — 2026-09-03

**Head**: `c3083368` (`docs(criteria): record the row-6 elimination and the row-9a red test`) ·
**Merge-base with `main`**: `2ff8fedc` · **Branch**: `fix/mrtr2-continuation-handle` ·
**SSOT**: `rules-source/workflows/quality-gates-dod.md` (cited by full path deliberately — two
copies of that file exist on disk and have drifted; the bare filename resolves to the stale one)

The 2026-08-30 assessment below this section stands as the record **at `edfd020a`**, and covers
§3, §4, §5, §8 and §12 only. This section is the full-gate re-check: every gate in the SSOT gets a
row, because a gate absent from the table is the failure this table exists to prevent.

## How this was measured, and what that costs

The shared worktree was **not clean** at measurement time: `tests/mik_7212_mrtr_component_acs.rs`
carried 159 uncommitted insertions belonging to a concurrent session, and those insertions do not
compile (`E0061` at `:1010`, one argument supplied to a two-argument `open`). A gate run there
measures that session's in-flight edit, not `c3083368`. Every cargo gate below was therefore run in
a **detached worktree checked out at `c3083368`** (`/Users/mikko/github/.worktrees/dod-c3083368`,
`git status --porcelain` empty), so the verdicts belong to the commit and not to whatever the shared
tree happened to hold. The uncommitted file is reported, not touched.

Verdicts use four words, and the distinction between the last two is the point:

| verdict | means |
|---|---|
| **PASS** / **FAIL** | the gate was run and this is what came back |
| **N/A** | the gate does not apply, with the reason stated |
| **NOT EVALUATED** | the gate applies and was not run, with the reason stated |
| **OUTSTANDING** | satisfiable only by an act the operator has withheld (push, PR, merge) |

An N/A without a reason is a skipped gate wearing a label; a NOT EVALUATED folded into N/A is the
same lie one column to the left.

## H1–H11 — file hygiene

| gate | verdict | evidence |
|---|---|---|
| H1 SEARCH FIRST | PASS | `ls docs/requirements/` before writing; found this file and extended it |
| H2 UPDATE > CREATE | PASS | this section appended to `RELEASE-4.0.0-dod-check.md`; no new file |
| H3 CONSOLIDATE | PASS | gate definitions cited by path, never restated here |
| H4 RIGHT LOCATION | PASS | `docs/requirements/`, beside the requirements and test plan it checks |
| H5 NAMING | PASS | existing filename unchanged |
| H6 no orphans | PARTIAL | `clippy --all-targets --all-features -- -D warnings` promotes rustc's `dead_code`, so a clean run is evidence of no crate-internal orphan. `dead_code` does **not** fire on `pub` items reachable from the library surface, so orphans there are NOT EVALUATED — no per-symbol reachability sweep was run over 85 changed `src/` files |
| H7 no redundant docs | NOT EVALUATED | 65 documentation files changed against the merge-base; no de-duplication sweep was run, and reading them for overlap is outside this task's FOR |
| H8 no temp files | PASS, with a reported exception | measurement worktree `git status --porcelain` empty. `target/` in the shared worktree is dirty and is **not mine to clean** — a concurrent session is mid-build in it (LOOP-CLEAN) |
| H9 no duplicate functions | NOT EVALUATED | no duplication detector was run; `clippy` does not answer this |
| H10 dir conventions | PASS | evidence document under `docs/requirements/` with its siblings |
| H11 untracked tracked-or-ignored | PASS at the commit | `git status --porcelain` empty in the worktree at `c3083368`. In the shared tree one **tracked** file is modified and belongs to another session — reported, not cleaned |

## Verdict of this re-check

**Nothing here changes the 2026-08-30 conclusion; it puts a number on the rest of the gate set.**
The static gates are genuinely clean at `c3083368` — formatter, clippy-as-SAST with
`--all-targets --all-features -- -D warnings`, secret scan, and `cargo audit` all pass, the last
with one yanked-crate warning that is not an advisory. The suite is **4,859 passing, 14 failing**,
and thirteen of the fourteen are acceptance tests deliberately written ahead of unfinished
multi-round-trip work. The fourteenth is a genuine loose end: a conformance check that cites a test
deleted at `6e744936`.

The larger finding is not any single red cell. It is that **21 applicable gates were never run**,
and until this table existed they were invisible rather than open. Coverage and mutation carry
figures from `edfd020a` and were not re-measured. Nine gates need a deployed system. Six need an
analysis pass nobody has done on this branch. One — **T1c**, post-quantum readiness — is flagged
unanswered rather than guessed, because a wrong N/A there is the exact hole the gate exists to
close. And the dual-vendor review gate is unmet for a reason outside the code: the second vendor
returns `402 Payment Required`.

Four more are outstanding because the operator has withheld the acts that would satisfy them. Those
are recorded as outstanding, not scored as failures.

## §1–§13

| gate | verdict | evidence |
|---|---|---|
| §1 Intent & Impact | PARTIAL | acceptance criteria are tracked per row in `docs/requirements/RELEASE-4.0.0-criteria-status.md`: **114 MET, 1 NOT MET, 9 N/A**. The one NOT MET is `NFR.OBS.5`, revised by operator ruling on 2026-09-03 and recorded in `RELEASE-4.0.0-gap-plan.md`. The consolidated DoD comment §1 requires on the tracking issue has **not** been posted — see OUTSTANDING below |
| §2 Code Quality | MIXED, each part measured separately | **markers**: 0 occurrences of the two forbidden markers across `src/**/*.rs` (`rg -c`). **unsafe**: `#![deny(unsafe_code)]` at `src/lib.rs:24`. **LOC ceiling**: N/A at branch scope — the ≤800-line gate governs a *change*, and this is a release branch of **751 commits** carrying +25,977/−708 lines under `src` and `tests`; per-commit compliance was not measured, and saying the branch fails an 800-line gate would be scoring the wrong unit. **WIRED**: see H6 |
| §3 Static Checks | PASS | `cargo fmt --check` → exit 0, zero bytes of output. `cargo clippy --all-targets --all-features -- -D warnings` → exit 0, **zero** lines beginning `warning`/`error`. Secret scan over the full 204-file diff `2ff8fedc..c3083368` for PEM blocks, `sk-ant-`, `AKIA…`, `ghp_…`, `xox[baprs]-` → **0 matches** |
| §4 Testing | see the dedicated block below | |
| §5 Change Safety | NOT EVALUATED | the no-drop check needs a coverage run on both sides of the merge-base; coverage was not re-measured at this head (see §4) |
| §6 Regression | OBSERVED, not gate-measured | the branch's practice is visible — criteria rows carry falsifier probes, and this session's own row 9a landed as a **red** test at `tests/mik_7212_acs.rs:1770` with a green control before any fix. That is evidence of the practice on the rows inspected, not a sweep proving every fix on 751 commits arrived test-first |
| §7 Documentation | PASS | 65 documentation files changed against the merge-base (+23,549 lines), including `README.md`, `CHANGELOG.md`, `ARCHITECTURE.md` and `docs/spec-divergences.md` |
| §8 Security & Compliance | PARTIAL | **SCA**: `cargo audit` — result recorded below. **SAST**: `cargo clippy … -D warnings` clean (the SSOT's §3 matrix names clippy as the Rust SAST leg). **Control inventory**: `docs/requirements/nfr-sec1-control-inventory.md` exists on this branch. **STRIDE / DAST / privacy / licensing** NOT EVALUATED — none was run in this task, and asserting them from the presence of a document is the failure mode this table is built against |
| §9 Ops | NOT EVALUATED | feature-flag, alert and rollback verification needs the deployment surface; nothing was exercised |
| §10 Performance | MEASURED EARLIER, not re-run | `docs/requirements/RELEASE-4.0.0-performance.md` records NFR.PERF.1/2 measured 2026-08-29 via `benches/gateway_benchmarks.rs` (criterion, 100 samples, `modern_request_path`) against 3.5.0. Not re-run at `c3083368`; cited as of that date, not as fresh |
| §11 Stop-the-Line | OUTSTANDING BY INSTRUCTION | the "not integrated" trigger fires — unpushed, no PR, unmerged. The operator has instructed that nothing be pushed and no PR opened, so this is a deliberate outstanding state, not a gate failure. No other §11 trigger fires from what was measured: CI not consulted (no PR), no security regression found, no data regression observed |
| §12 Peer Review | PARTIAL — one vendor only | the dual gate needs two independent frontier models. The second leg is **dead**: `API error (status 402 Payment Required): Grok Build usage balance exhausted`. One leg cannot ratify, and `~/.claude/bin/ratify` refuses without both, so this gate is honestly unmet at this head rather than half-credited |
| §13 Retro & Backlog | OUTSTANDING | the retro comment attaches to a PR, and no PR exists |

## §4 / D1 — the test suite, measured

`cargo test --all-features --no-fail-fast` at `c3083368` in the clean worktree — **exit 101**:

```
63 test-result lines · 4,859 passed · 14 failed · 23 ignored
```

**The 14 failures are not a green table rounded up, and they are also not regressions.** They fall
in three binaries, and **all three files are branch-new** — `git cat-file -e 2ff8fedc:<path>` fails
for each of `tests/mik_7212_acs.rs`, `tests/mik_7212_mrtr_component_acs.rs` and
`tests/mik_7272_conformance.rs`. A test that does not exist on the merge-base cannot be a
regression from it, so the base-reproduction question is answered by construction rather than by a
second full build:

| binary | failing | what it is |
|---|---|---|
| `mik_7212_mrtr_component_acs` | 12 | the multi-round-trip acceptance criteria, written first against work that is not implemented — `ac_mrtr_1`, `_2`, `_3` ×2, `_4` ×3, `_5a`–`_5d`, `_8`. This is the RED half of red-green, and the 2026-08-30 verdict below already names retry forwarding as the unfinished core path (MIK-7325) |
| `mik_7212_acs` | 1 | `ac_mrtr_9a_a_url_mode_request_to_a_form_only_client_is_refused`, red at `:1770` with a green control — written this session, deliberately red, independently re-run and confirmed by the team lead |
| `mik_7272_conformance` | 1 | `every_cited_test_exists` — **a real finding, not a deliberate red.** The conformance evidence for "Multi Round-Trip Requests replace server-initiated requests" cites `mik_7212_acs::inflight::ac_mrtr_6_a_retry_landing_elsewhere_is_sent_to_the_holder`, and that test no longer exists: row 6's routing variant was deleted at `6e744936`. The elimination did not carry its citation with it. Reported, not repaired — repair is outside this task's FOR |

So §4's "100% pass" is **FAIL at this head**, and the honest reading is that 13 of the 14 are the
suite doing its job and the fourteenth is a dangling reference left by a deletion.

**Coverage**: NOT RE-RUN. The 2026-08-30 assessment below measured it **at `edfd020a`** and found it
**below the floor**. That number is cited as of that commit, not carried forward as fresh.
**Mutation ≥75% on new code**: NOT RE-RUN. Measured at `edfd020a` on `src/protocol`, where it
passed; no figure exists for the rest of the changed surface.
**23 ignored** tests were counted, not classified, at this head.

## §8 / D30 — dependency audit, measured

`cargo audit` at `c3083368` — **exit 0**, 1,239 advisories loaded, 453 crate dependencies scanned:

```
0 vulnerabilities
1 warning: chacha20 0.10.0 — yanked
    chacha20 0.10.0 <- rand 0.10.2 <- {uuid 1.26.0, tungstenite 0.30.0, mcp-gateway 4.0.0}
```

A **yanked** crate is not an advisory: nothing says this version is vulnerable, only that its
publisher withdrew it from the registry. It reaches the tree transitively through `rand 0.10.2`,
which `mcp-gateway` depends on directly and which `uuid` and `tungstenite` also pull. The SSOT's
blocking condition is `HIGH SCA = BLOCK`; there is no HIGH here and no advisory at all, so this is
recorded as a **warning to clear on the next `rand` bump**, not as a gate failure.

## D1–D30, D13a–d, T1c

| gate | verdict | evidence |
|---|---|---|
| D1 TESTED | see §4 block | |
| D2 COMPATIBLE | PASS by version contract | `Cargo.toml` moves `3.5.0` → `4.0.0`; a major bump is where breaking change is permitted, and `commands/upgrade/` carries the post-upgrade migration framework. The migrations themselves were not executed here |
| D3 MEASURED | PARTIAL | performance measured 2026-08-29 (§10). No before/after ROI figure for the branch as a whole; marked **I**, one source |
| D4 DRY | NOT EVALUATED | no duplication sweep run — same reason as H9 |
| D5 CONTRACTS | NOT EVALUATED | interface stability across 85 changed `src/` files was not diffed symbol-by-symbol |
| D6 E2E | PARTIAL | the suite includes HTTP and stdio integration binaries exercised in the run below; no separate user-journey E2E pass was staged |
| D7 WIRED | PARTIAL | as H6: `-D warnings` clean covers crate-internal reachability; `pub` surface NOT EVALUATED |
| D8 OBSERVABLE | NOT EVALUATED | `src/metrics.rs`, `src/tracing_context/` and `src/stats.rs` exist, but presence is not emission — no metric or trace was observed being produced |
| D9 STATIC | PASS | §3: linter 0, formatter clean, clippy-as-SAST 0. Type checking is the Rust compiler and it succeeded |
| D10 0-BUG | PARTIAL | 0 forbidden markers in `src/`. Known-open items are recorded in `RELEASE-4.0.0-blocking-rollup.md` and the 2026-08-30 section below, which lists six open findings — so "0 known" is **not** true at this head and the table says so |
| D11 OPTIMIZED | PARTIAL | criterion benchmark harness exists and was run 2026-08-29; not profiled or re-tuned at this head |
| D12 REVIEWED | PARTIAL | as §12 — one vendor reachable, one dead |
| D13 TRACKED | PASS | all work committed; branch commits reference `MIK-6729`, `MIK-7246`, `MIK-7256`, and the criteria doc keys every row to a `MIK-…` acceptance-criterion ID |
| D13a ISSUE-CLOSED | CORRECTLY NOT DONE | the gate forbids closing before D18 merge, and nothing is merged. Compliance here *is* the open state |
| D13b EFFORT-LOGGED | NOT EVALUATED | not checked in Linear during this task |
| D13c DEPS-UNBLOCKED | NOT EVALUATED | dependent-issue state not checked |
| D13d LABELED | NOT EVALUATED | issue labels not checked |
| D14 DOCUMENTED | PASS | §7 |
| D15 CLEAN | PASS, with the reported exception | H6–H11; the one dirty file belongs to another session |
| D16 TELEMETRY (savings) | N/A | `emit_elite_savings()` is a claude-elite performance-telemetry hook, not a surface this Rust gateway has; no performance claim in this release is routed through it |
| D17 LEARNINGS | NOT EVALUATED | hebb is offline this session (`mcp_timeout`), so no durable learning could be written; recorded rather than silently skipped |
| D18 MERGED | OUTSTANDING BY INSTRUCTION | delivery chain step 1 (pushed) onward are all unsatisfied by operator instruction. Recorded as deliberately outstanding, not as failure |
| D19 BACKUP | N/A | nothing is being deployed to production in this task |
| D20 ROLLBACK | NOT EVALUATED | the release carries a revision-downgrade path (`NFR.OBS.5`, revised 2026-09-03), but no rollback procedure was exercised |
| D21 CANARY | NOT EVALUATED | no gradual-rollout mechanism exercised |
| D22 TELEMETRY (structured) | NOT EVALUATED | as D8 |
| D23 ALERTING | NOT EVALUATED | as D9/ops; no alert routing inspected |
| D24 ENFORCEMENT | PASS in part | the numerical claims gate is real: `benchmarks/public_claims.json` with a CI drift check, per the repository's own `CLAUDE.md`. Whether every gate in this table is CI-enforced was not audited — most are not |
| D25 SESSION | N/A | no agent session-persistence surface is changed by this branch |
| D26 SEC-MONITOR | NOT EVALUATED | security-channel separation and immutable logging not inspected |
| D27 COUPLING | PASS | direct dependencies in `Cargo.toml` go **109 → 110**; the single addition is `jsonschema 0.52.1` with `default-features = false`. The ceiling is +2. No cycle check was run |
| D28 API-SURFACE | NOT EVALUATED | public symbol counts per module were not taken |
| D29 DEBT-TRAJ | NOT EVALUATED | no complexity measurement before/after; the SSOT names `cargo clippy` + a dependency graph for Rust, and only the first half was run |
| D30 SUPPLY-CHAIN | PARTIAL | `Cargo.lock` pins **451** checksums, so lock hashes are pinned. `cargo audit` result recorded below. One new dependency added (D27) and it was **not** separately audited beyond what `cargo audit` covers |
| T1c PQC-READINESS | NOT EVALUATED | the branch touches `src/mtls/`, `src/key_server/` and `src/attestation/`; whether this release introduces a *new* key agreement or signature primitive — which is what triggers the gate — was not determined. Flagged rather than guessed, because a wrong N/A here is exactly the harvest-now-decrypt-later hole the gate exists for |

## B1–B4 — Agent Stack Bets

| bet | verdict | evidence |
|---|---|---|
| B1 IDENT | PARTIAL | `src/attestation/`, `src/identity_grants.rs` and `src/identity_propagation/` are the platform-owned attribution surface and this branch changes them; no per-action attribution audit was run |
| B2 MEM | N/A | this release is a protocol/router change with no agent-memory surface; hebb is the owner and is untouched |
| B3 DURABLE | NOT EVALUATED | `src/scheduler/`, `src/idempotency.rs` and the continuation/resume machinery exist and are the durable surface, but no simulated disconnect-and-resume check was run at this head |
| B4 PLATFORM | PASS | the change reuses the gateway's own primitives — capability system, meta-MCP surface, transport layer — rather than adding parallel plumbing; `mcp-gateway` **is** the Bet-4 platform |

## The gates that were not evaluated, gathered in one place

Scattered through a table, an un-run gate reads as a footnote. Gathered, it is the shape of the
gap. **Twenty-one** applicable gates were not run, in four groups:

- **Needs a coverage or mutation run** (long, and the shared tree was busy): §4 coverage, §4
  mutation, §5, D1's coverage half.
- **Needs a deployed or running system**: §9, D8, D19, D20, D21, D22, D23, D26, B3.
- **Needs an analysis pass nobody has run on this branch**: H7, H9, D4, D5, D28, D29, and the
  `pub`-surface half of H6/D7.
- **Needs a Linear query**: D13b, D13c, D13d.

One gate is flagged rather than answered: **T1c**. Deciding it needs a determination of whether the
branch introduces a new key-agreement or signature primitive, and a guessed N/A there is precisely
the failure the gate is written to catch.

Two gates are unmet for a reason outside this branch: **§12/D12**, because the second review vendor
returns `402 Payment Required` and one leg cannot ratify; **D17**, because hebb is offline.

## What is outstanding by instruction, not by failure

The operator has instructed that nothing be pushed and no pull request be opened. That makes the
following unsatisfiable *by design* at this head, and they are recorded as outstanding rather than
scored as failures: **D18** (the whole five-step delivery chain), **§11**'s "not integrated"
trigger, **§13** (a retro attaches to a PR), and the §1 requirement that the DoD verdict be posted
as an issue comment. **D13a** is the inverse — the gate forbids closing the issue before merge, so
the open state *is* compliance.

## Every command that produced a verdict above

Run in `/Users/mikko/github/.worktrees/dod-c3083368`, a detached worktree at `c3083368` with an
empty `git status --porcelain`, for the reason given at the top of this section:

```
cargo fmt --check                                         # exit 0, no output
cargo clippy --all-targets --all-features -- -D warnings  # exit 0, zero warning/error lines
cargo test --all-features --no-fail-fast                  # see the §4 block
cargo audit                                               # see the §4 block
```

Run in the branch worktree, read-only:

```
git status --porcelain
git diff --stat  2ff8fedc..c3083368
git diff --numstat 2ff8fedc..c3083368 -- src tests
git rev-list --count 2ff8fedc..c3083368
git diff 2ff8fedc..c3083368 | rg -c '<secret patterns>'   # 0 matches
rg -c '<forbidden markers>' --glob 'src/**/*.rs'          # 0 files
rg -n 'deny\(unsafe_code\)' src/lib.rs                    # src/lib.rs:24
rg -c '^checksum = ' Cargo.lock                           # 451
rg -o '<verdict words>' docs/requirements/RELEASE-4.0.0-criteria-status.md | sort | uniq -c
```

## Reported, not repaired

Three things were found and deliberately left alone, because this task measures and does not fix:

1. `tests/mik_7212_mrtr_component_acs.rs` in the shared worktree carries **159 uncommitted
   insertions that do not compile** — `E0061` at `:1010`, one argument passed to the two-argument
   `ContinuationKeyring::open` defined at `src/protocol/continuation.rs:423`. This is a concurrent
   session's in-flight work. It is why every gate above was run elsewhere, and under LOOP-CLEAN it
   is reported rather than touched.
2. `target/` in the shared worktree is dirty. H8 assigns build-artifact cleanup to the change that
   made them; these are not mine and a concurrent build is using them.
3. Commit `aecced48` may not compile in isolation. That costs bisectability, not the correctness of
   `c3083368`, and it is noted here rather than chased.
### What changed between measurement and this commit

The measurement above is fixed at `c3083368`. While it was running, the concurrent session
committed twice on top of it, and two of the three items just reported were resolved by those
commits rather than by me:

- `4cdf6958` — `test(cluster-a): the retry that must not open a second exchange` lands the 159
  uncommitted insertions that would not compile. Item 1 above is therefore **closed**, and the
  reason the gates were run in a separate worktree stands as the record of why it mattered.
- `983ed081` — `test(conformance): repoint MRTR.6 evidence at the surviving test` closes the
  `every_cited_test_exists` failure found in §4 above: the citation now names a test that exists.

Neither commit was re-measured. Saying "13 of 14 failures remain" at `983ed081` would be an
inference, and the point of this table is that inferences do not get cells. The two gates whose
verdicts those commits would move — §4 and §3's clippy leg — are **stale by two commits** as of this
writing, and the next re-check should start there.


---

# The 2026-08-30 assessment, at `edfd020a` — unchanged below this line
## Verdict, first

**The 2025 path is done and shippable. The 2026 core path is not finished: retry forwarding is
accepted and then refused (MIK-7325), so a well-formed multi-round-trip tool request cannot
complete. What else remains is gated on production topology, a tasks extension this release
deliberately does not advertise, and one parsed protocol field with no consumer.**

Eight independent review rounds produced **42 findings, a later scope audit added a forty-third, and
the confirmation pass on this document found two more that had never been written down. Thirty-nine
are closed**, each with a probe that makes its own fix fail and only its own fix. Of the six recorded
open, two are gated on multi-replica production, two are conformance gaps in a tasks extension this
release does not advertise, one is a parsed protocol field with no consumer, and one is test hygiene.
Six is what is currently recorded open, which is not the same claim as six being all there are. The
first five are unreachable by a client while the switch defaults off; the last exists only in a test.

An earlier revision of this paragraph said two of them could not be verified against a specification
page returning 404. That was a wrong path rather than a missing document: the page was found and
fetched, and both findings are now stated against it. The claim is corrected here rather than left
standing beside the body that contradicts it.

Two findings were closed by **removing** a mechanism rather than repairing it, because in both cases
what existed was worse than nothing: retry fields merged into tool arguments while forwarding the
client's own sealed envelope, and a `tasks/get` that answered every handle with a fabricated
success. Both are recorded below as decisions.

The single most valuable result of these rounds was not a defect but a **process finding**: the
conformance matrix compared the code against a requirements document written from the same
incomplete reading of the specification, so both agreed and it went green over four wire-format
errors. Three protocol areas had been implemented without ever fetching their own specification
pages.

## §3 Static checks — PASS at head

| Gate | Command | Result |
|---|---|---|
| Linter | `cargo clippy --all-targets --all-features -- -D warnings` | 0 warnings |
| Formatter | `cargo fmt --check` | clean |
| Secret scan | private-key / API-key patterns over the branch diff | 0 |

Both the linter and the suite were re-run at the release head on this laptop, under a load limiter
and with the build directory outside the repository. An earlier round ran them on the Linux build
host instead, because a local guard halted every `cargo` command at 4.6 GB free disk; clearing
another session's build cache was not this session's to decide. Only this branch's own debug
artifacts were removed locally, which is housekeeping the rules already assign to the change that
created them.

## §4 Testing — BLOCKED: execution passes, coverage is measured and short of the floor

- **4,611 tests passing across 46 binaries, 0 failing** — measured at the head commit under `--all-features` with `--no-fail-fast`, so neither a disabled feature nor an earlier failing binary can hide a row. The figure recorded in the previous revision, 4,463 across 45 binaries, was the default feature set.
- **41 doc-tests pass.**
- **23 tests are `#[ignore]`d.** Twelve are doc-test examples and ten are pre-existing integration tests needing Docker or a live API. **One is this branch's**: `ac_discover_1_advertises_the_target_revision`, which asserts the gateway advertises 2026-07-28 — deliberately false while the switch is off. The previous revision of this document said "one test is ignored" and meant one of *mine*; as written it was a false claim about the suite, and this corrects it.

**The suite had only ever been run under default features, and `--all-features` was red.**
The handshake golden is keyed by feature set on purpose — under `spec-preview` the `initialize`
result advertises two extra tool capabilities, so one golden is one feature set — but only the
`default` goldens had been captured. Under `--all-features` the row failed on a missing fixture,
which is the row working: a golden that silently stopped comparing would have been the failure worth
having. The two `spec_preview` goldens are now captured. Capturing them from this tree rather than
from the 3.5.0 tag is legitimate here and was verified rather than assumed: `meta_mcp_helpers.rs`,
`meta_mcp/spec_preview.rs` and `handle_initialize` are byte-identical to `cdd52622`, so this tree
*is* 3.5.0 for the handshake. The only handshake-adjacent change on the branch is `SUPPORTED_VERSIONS`
dropping the never-specified `2024-10-07`, and the result does not carry that list. The new files
record `"version": "4.0.0"` where their siblings record `"3.5.0"`; the row nulls that field and
asserts it separately against the crate version, and hand-editing a captured golden is the one thing
the capture rule forbids.

### Coverage — measured, and below the floor

Coverage was the first of the two missing §4 numbers and it is now measured. Mutation is not, and
the section below says so in its own words rather than borrowing this one's authority.

Run at head `4c599c89` from the branch worktree:
`cargo llvm-cov --all-features --no-fail-fast --summary-only --json`. `--all-features` matches the
feature set every other §4 figure was taken under, so the numbers are comparable to the suite result
above rather than to a different build.

| scope | lines | regions |
|---|---|---|
| whole crate, 318 instrumented files | **83.16%** (65,302 / 78,529) | 83.39% |
| `src/protocol/`, the revision's new module, 14 files | **94.60%** (1,332 / 1,408) | 94.59% |
| the 61 files this branch touched, aggregated | **77.40%** (13,402 / 17,315) | 75.87% |

Against the canonical thresholds — Critical ≥95%, Standard ≥80% — this does not clear:

- the crate as a whole clears the Standard floor;
- `src/protocol/` misses the Critical threshold by 0.4 points, and protocol parsing on a security
  path is Critical rather than Standard;
- the files this branch touched, taken together, sit **2.6 points under the Standard floor**.

The third row decides the gate, and it is also the one most easily misread, so what it is:
file-level coverage of every file the branch edited, including lines the branch never touched. It
attributes a legacy file's untested remainder to this change. A changed-line figure was derived as a
cross-check and comes out near 90%, but it is **not** recorded as the measurement, because the
control for it failed: llvm-cov's LCOV exporter and its own JSON summary disagree on 28 of the 51
changed files present in both, by up to 9.9 points on `src/gateway/router/handlers.rs`. An
instrument that disagrees with itself by ten points does not get to carry a gate verdict. The
file-level rows above are llvm-cov's own per-file counts summed, with no derivation in between, and
that is why they are the ones quoted.

Under either reading the answer is the same and the gate does not turn on the ambiguity: 77.40% is
below the floor, and 90% is below the 100% §5 asks of new and changed code.

**A choice this document made, named rather than assumed (§P3).** The canonical §4 states the
thresholds without saying what they range over, and the two candidate scopes give opposite verdicts:
the crate as a whole is 83.16% and clears the Standard floor, while the files this branch touched are
77.40% and do not. This document applies the threshold to the change rather than to the codebase,
which is the stricter of the two and the one consistent with §5 asking 100% of new and changed code —
a release gate that a large well-covered codebase can satisfy while the change under review is
untested would not be measuring the change. Recording it because it is a judgment, not a reading:
a reviewer may take the other one. **It is not load-bearing on the verdict today.** Mutation is
unmeasured either way, so §4 stands BLOCKED under both scopes, and the choice only starts deciding
anything once MIK-7324 closes the mutation half.

**Where the untested code sits.** The "what if it resolves badly" row below undertook to name
specific modules rather than a percentage, and this is that list — added lines reached by no test,
worst first:

| file | added lines covered |
|---|---|
| `src/main.rs` | 0 / 22 |
| `src/transport/http/mod.rs` | 30 / 57 |
| `src/gateway/server/mod.rs` | 65 / 89 |
| `src/oauth/client/mod.rs` | 54 / 73 |
| `src/gateway/router/handlers.rs` | 189 / 223 |

`src/main.rs` is the sharpest of these: 22 added lines, none executed by any test. These counts come
from the cross-check whose control failed, so they rank the modules rather than grade them — which
is what the row promised and all it needs to do.

### Mutation — measured on `src/protocol`, and it passes there

The canonical DoD §4 asks for a mutation score ≥75% on new code. `cargo-mutants` now has a number,
scoped to `src/protocol/*.rs`: **28 caught, 2 missed, 0 timeouts — 93.3%**, run on Spark with
`--all-features -j 8 --timeout 300`. 132 mutants were unviable (they do not compile) and are not
scored, which is the tool's own convention.

Both survivors were in the continuation envelope, and both are now closed:

| survivor | what it proved absent | closed by |
|---|---|---|
| `continuation.rs:368` — `>` becomes `>=` in `Keyring::open` | nothing pinned the 8 KiB envelope bound at its exact boundary | `envelope_size::a_token_of_exactly_the_permitted_size_is_judged_on_its_contents` |
| `continuation.rs:178` — `client_message` returns `""` | nothing required a refusal to say anything at all | `envelope_size::a_client_facing_refusal_still_tells_the_caller_something` |

Both tests were proven by falsifier probe before being committed: baseline green, each mutant
reintroduced by hand and each test red **on its own assertion** rather than on a compile error,
then the source restored and both green again. With them the scoped score is 30/30.

**This is a subset, and a subset score is a LOWER BOUND on the branch, not a grade for it.** The
full branch diff is several times the `src/protocol` surface; the modules coverage named as weakest
(`src/main.rs`, `src/transport/http/mod.rs`, `src/gateway/server/mod.rs`, `src/oauth/client/mod.rs`,
`src/gateway/router/handlers.rs`) are not in this run. What the run does establish is that the
security-critical new module — envelope mint, open, caller binding, single-use ledger — has no
surviving mutants.

Getting here cost two blocked baselines, which is worth recording because the failure was invisible
where a human runs the tests: `cargo-mutants` sets a **relative** `TMPDIR`, `tempfile::tempdir()`
then returns a relative path, and the `config` crate drops the leading `./` when it names the file
in a parse error. One test compared the rendered path verbatim, so it passed in the repo, passed in
isolation, and failed the mutation baseline on two machines. A baseline failure stops the tool
before it tests a single mutant, so the whole gate was blocked by a test that looked green
everywhere else. Reproduced in one command (`TMPDIR=./reltmp cargo test --lib <name>`) and fixed by
matching the last two path components instead.

| field | value |
|---|---|
| owner | **MIK-7324** |
| what would resolve it | mutation over the **rest** of the branch diff, on Spark, module by module, starting with the five coverage named |
| when | before the 4.1.0 tag, or immediately if the operator holds 4.0.0 for it |
| what if it resolves badly | survivors outside `src/protocol` become tests under MIK-7324; the modern path stays default-off until they close |

§4 stands BLOCKED regardless: mutation is now measured and passing on the scope that was run, and
**coverage is measured and failing** — the touched-file aggregate is 2.6 points under the Standard
floor. One of the two criteria passing does not unblock a gate that needs both.
Holding the tag is a live option and one line from the operator takes it.

### Falsification — every control was made to fail, and two could not be

The rule this release ran on: a control you cannot make fail is not a control. Thirty-one probes
across the branch. The fourteen from earlier increments are unchanged; the thirteen run against this
round's security repairs are below, each failing **only** the rows that observe it.

| Control | Probe | Rows that failed |
|---|---|---|
| `Payload` redaction | `Debug` derived again | 1 |
| Routing under contention | `route` back to `try_lock` → `Gone` | 1 |
| Explicit completion | `complete` releases nothing | 2 |
| Ledger capacity policy | evict the soonest live entry again | 1 |
| Keyring construction | duplicate key ids allowed | 1 |
| Client-facing error | internal cause leaked into the message | 1 |
| Mint budget | budget never exhausts | 2 |
| Mint budget | ceiling clamp removed | 1 |
| Mint budget | counter never advances | 3 |
| Envelope bound, opening | size check removed | 1 |
| Envelope bound, minting | size check removed | 1 |
| Envelope bound, value | bound lowered below real backend state | 13 — it is load-bearing on the ordinary path |
| Mirrored field selection | `resources/read` reads `name` again | 2 — the helper row and the router row |
| Decoy-name bypass, end to end | name-then-`uri` fallback restored in the handler | 1 |
| Repeated header line | first occurrence taken, as before | 1 |

**A probe that reported less than it found**, worth recording because it nearly passed for a
methodology reason rather than a code one: running two test binaries in one `cargo test` invocation
stops after the first one fails, so the second never runs and its rows are silently absent from the
result. One probe appeared to leave the router row untouched. Re-run against that binary alone, it
failed it — 19 passed, 1 failed. **A falsifier must name one binary, or pass `--no-fail-fast`**;
otherwise an unrun test reads exactly like an insensitive one.

**Two probes exposed holes in the controls rather than in the code**, which is the point of running
them:

- The **mint budget shipped with no control at all**. The first probe disabled it and nothing failed. The bound was 2^32 envelopes, which no test can reach, so it was untestable by construction. It now has a clamped builder and a remaining-budget reader, and three probes that fail.
- The **constant-time comparison has no honest failing row, and this is recorded rather than papered over**. Reverting `redeemable_by` to the short-circuiting slice comparison passes all rows — verified by running it, not assumed. A unit test cannot observe timing. The behavioural row beside it was renamed to `a_wrong_binding_of_any_length_is_refused_identically`, which is what it actually proves; the timing property itself is assured by reading the code, and that is a weaker assurance, stated as one.

## §5 Change safety — PASS

Every modern behaviour has a **legacy regression row** beside it: session header still sent, `ping`
still served, `initialize` byte-identical against a captured golden per revision, no `resultType` or
`_meta` added to a 2025 result, headers not required of a client that never sent one. The legacy
path is the thing most likely to break, so it is the thing most tested.

## §8 Security — PASS on tooling, with open findings below

- `cargo audit`: **0 vulnerabilities**, 425 dependencies. One `yanked` warning, identical on `main`.
- `#![deny(unsafe_code)]` holds; no dependency added.
- Nine security findings from review were closed in this round; two remain open and are listed below.

## §12 Review — the whole record, in one place

This section is the single account of who reviewed what, at which head, and what came back.
Every other document points here rather than restating it.

| rounds | head | vendors | outcome |
|---|---|---|---|
| 1-8 | per-module chunks | codex/GPT only | authorised single-vendor deviation, findings below |
| 9-17 | per-module chunks | GPT + Grok | findings below |
| release material | `e6e2ddd9` | GPT + Kimi | both SHIP-WITH-FIXES; Grok errored, no verdict |
| repair commit | `edfd020a` | GPT + Kimi | both SHIP-WITH-FIXES; Grok unavailable, monthly quota |
| confirmation | `fae481ef` | GPT + Kimi | both SHIP, no findings; Grok unavailable, monthly quota |

The three 2026-08-30 rounds reviewed the release *material* — the PR body, this document and the
repair diff — not the feature work, which rounds 1-17 covered per module. Grok is recorded as
unavailable in all three, which is not agreement. The confirmation round returned SHIP from both
vendors with no findings; the one improvement they both raised — a closed item still sitting inside
the numbered open list — is applied in the commit that carries this paragraph. So the head being
merged is one commit past the last reviewed head, and that is stated rather than rounded up.

The operator set single-vendor review (codex/gpt) for rounds 1 to 8, so the dual-vendor gate was
**deliberately not met** there and it is a known, authorised deviation rather than a passed gate.

Reviews are chunked per module. An earlier attempt sent the whole 2,893-line diff and died at zero
bytes five times; the cause was payload size, diagnosed by a minimal smoke test returning in seconds.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 1 | `src/protocol/continuation.rs` | 7 — 3 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 2 | repairs to round 1 | 1 CRITICAL (BEFORE-PRODUCTION) | **SHIP** |
| 3 | `src/gateway/router/handlers.rs` | 10 — 1 CRITICAL, 7 HIGH, 2 MEDIUM, all CERTAIN | SHIP (none gated NOW) |

**A process failure worth recording**: round 1's findings were first read from a truncated tool
output showing only the last three. Work proceeded on three findings while four — including two
CRITICAL — sat unread in the authoritative run file. They were found only when that file was opened
directly. The lesson is the one already written down: read the source, not a rendering of it.

### Round 1 and 2 — disposition of all eight

Nine repairs, each with a probe above, re-checked by the vendor that raised them (**SHIP**):

| Finding | Repair |
|---|---|
| CRITICAL — ledger evicts a live entry at capacity | refuses instead, reclaiming only entries past a deadline |
| CRITICAL — `for_test()` ships a publicly known key in production builds | constructor deleted; tests build their own keyring |
| CRITICAL — process-local ledger across replicas | **open**, gated BEFORE-PRODUCTION, documented in the module |
| HIGH — `open` decodes an unbounded client token | 8 KiB bound checked before decoding, enforced at both ends |
| HIGH — `Payload` derives `Debug` over sealed state | hand-written redacting `Debug` |
| MEDIUM — `route` maps lock contention to `Gone` | awaits the lock; the old code contradicted its own comment |
| LOW — binding comparison short-circuits on length | compares SHA-256 digests of both sides |
| (round 2) CRITICAL — mint budget resets on restart | **open**, gated BEFORE-PRODUCTION; the doc comment that overclaimed a per-key guarantee was corrected to say it bounds one process |

Four improvements were also taken: per-key mint budget, explicit completion release, duplicate-key-id
rejection, and one generic client-facing refusal message.

## Findings by area

The totals are stated once, at the top of this document; this section only says where the closed
findings fell and what each area got wrong. The ones still open are named under "What is honestly
NOT finished".

| Area | Closed | What was wrong |
|---|---|---|
| Continuation envelope | 6 | live replay window at capacity; a public constructor shipping a known key; an unbounded client token; sealed state in `Debug`; lock contention answered as a lost exchange; a length-leaking comparison |
| Request path | 9 | a header-declared modern request classified legacy; retry fields merged into tool arguments; `resultType` overwritten; a destructive call running unconfirmable; a session minted per stateless request; the modern revision missing from discovery; notifications answered before validation; a session header on modern refusals; a fabricated `tasks/get` success |
| Mirrored headers | 3 | a decoy `name` validated while `uri` executed; a repeated header line reduced to its first value; malformed retry fields accepted inconsistently |
| Era classifier | 5 | capabilities present but unusable; modern-only keys read as legacy; a partial document read as a discovery document; a failed probe cached as legacy; an attacker-sized subtree copied per request |
| Subscriptions | 5 | filter read at the wrong level; `resourceSubscriptions` read as a boolean; a minted id instead of the request's own; the tag written where no client looks; a valid empty filter refused |
| Security controls | 3 | an anomaly check that could not observe and allowed anyway; lifecycle deadlines that accumulated and reclaimed live callers; a non-atomic score-and-update |

### Two were closed by removing the mechanism, not repairing it

Both are recorded as decisions rather than omissions, because in both cases the thing that existed
was worse than nothing:

- **Multi-round-trip retry forwarding.** The fields were merged into the tool `arguments` object. The specification makes them siblings of `arguments`, so a backend read them nowhere — and a tool with an argument of either name had it silently overwritten. Worse, the `requestState` forwarded was the **client's own envelope**, which `continuation.rs` exists specifically to keep from being passed onward. Forwarding correctly means unsealing the gateway's envelope and sending the *backend's* state, which needs the keyring reachable from request state and a retry parameter threaded to the dispatcher. Neither exists, so a retry now fails visibly instead of corrupting a call.
- **`tasks/get`.** It answered every handle with a `not_found` **success** — a status absent from the protocol's task model, reported as though a lookup had happened against a store that does not exist. It now returns method-not-found, which is true. The extension's own specification has since been fetched and the gap inventory below is stated against it.

## Round 8 — the repairs reviewed, and what that found

The fixes above were themselves submitted for review, split in two so neither payload was large
enough to die silently.

| Material | Findings | Verdict |
|---|---|---|
| the protocol modules | 2, both BEFORE-PRODUCTION | **SHIP** |
| the request path and security controls | 6, one gated NOW | SHIP-WITH-FIXES |

**The NOW-gated finding was the pattern this branch keeps producing, turned back on its author.**
`SessionLifecycle` — the registry meant to reclaim per-caller state — had its deadline map carefully
repaired here, and **nothing in production ever calls it**. Verified: nothing constructs it outside
its own module, and `track` and `reap` have no callers. It is pre-existing rather than introduced
(added in `ba268ca9`, already dead on `main` at the base commit), so the wire-or-delete decision
belongs to a human and is filed as **MIK-7291** rather than absorbed into this change.

What *was* closed here is the leak it would have prevented: the anomaly detector's identity map now
carries a ceiling. A stateless caller never disconnects, because it never connected, so there is no
disconnect event to reclaim on even in principle.

Three further repairs to the repairs:

- **The stateless anomaly identity was still the display name.** It is operator-configured, two API keys may share one, and every anonymous caller presents the same one — so scoring on it lets one caller poison another's history. The handler now passes a validated credential key and passes nothing at all for an unauthenticated caller. A `session_owner()` helper one function away already carried this exact reasoning in its own comment.
- **A rule could downgrade the fail-closed refusal.** Refusing an unscoreable call raised a High finding, which an ordinary Allow rule could soften. Refusal is now forced before rule resolution.
- **Session suppression was too narrow**, recognising only an exactly-supported modern version, and a duplicated `MCP-Protocol-Version` header could hide a modern declaration behind a legacy one.

**Two slips of my own, both caught immediately by the compiler**, and worth recording because they
share one cause: a text substitution matched two functions where one was meant. The parameter added
to `check_request` landed on `check_response` too, and a forced-block landed in the wrong function
entirely. Verifying each batch rather than at the end is what turned both into build errors instead
of shipped defects.

### Round 8's own controls, and the two that were not controls

Seven probes against the round-8 repairs. Five failed only their own rows on the first attempt.
The other two are the reason this step exists:

| Control | Probe | Rows that failed |
|---|---|---|
| Unscoreable calls refused | blind no longer forces a block | 1 |
| Identity is real or absent | empty string used as an identity | 2 |
| Modern era declared broadly | only exactly-served versions count | 1 |
| Identity map bounded | ceiling removed | 1 |
| Duplicate header refused | resolved to the first value instead | 1 |

- **The bound probe found a deadlock in the fix it was testing.** The eviction path held a shard guard from the map's iterator and then asked the same shard for a write, so the thread blocked against itself. It could only run once the map reached 100,000 entries, which no ordinary test does — the row written to prove the ceiling existed is the only thing that reached it, and it hung for six minutes rather than failing. Fixed by binding the victim in its own statement so the guard drops first.
- **The duplicate-header row was not a control at all.** It passed whether or not the fix was present, because its body declared itself modern and the request was therefore refused by the duplicate check *inside* the modern block — a different mechanism from the classification the row is named for. Rewritten to use a body with no protocol metadata, which is the only shape where misreading the header actually sends the request down the legacy path. It now fails when reverted.

A hung test also taught something about reading a build: `cargo test` with a live test binary and no
compiler children emits nothing, so a log filtered for `^test result` looks identical to a job that
died. That was misread twice here before anyone looked at the process tree.

## What is honestly NOT finished

Six findings are recorded open: five numbered below, and one test-hygiene item after them. Every
numbered item in that list is open, so the count is read by counting. Findings 1 to 5 are
unreachable by a client while `server.modern_protocol` defaults off. The sixth is unreachable
because it lives in a test, not because of the switch.

1. **The consumed-continuation ledger is process-local.** A second replica would let one continuation be spent once on each. Gated BEFORE-PRODUCTION; needs a shared atomic insert-if-absent store.

2. **The mint counter is process-local.** It bounds envelopes sealed by *this process* since it started, not by the key over its life, so a restart resets it. That is a real ceiling on a single runaway process and not the per-key guarantee the NIST bound describes. Gated BEFORE-PRODUCTION; the module says so in as many words.

3. **The task model is short of the specification, now that the specification has been
   read.** The 404 was a wrong path, not a missing document: tasks moved out of the core
   revision into an extension, and the page lives at
   `https://modelcontextprotocol.io/extensions/tasks/overview` (fetched 2026-08-29). The
   core schema for 2026-07-28 carries no `Task` type at all — only the capability key
   `io.modelcontextprotocol/tasks` under `capabilities.extensions`. Against that source,
   `src/protocol/tasks.rs:21-28` defines three statuses where the specification defines
   five: `input_required` and `cancelled` are absent, and with them the whole mid-flight
   input exchange (`tasks/update`, `inputRequests`) and cooperative cancellation. The
   `Task` struct at `:32-38` carries neither `ttlMs` nor `pollIntervalMs`; the paragraph
   below corrects which of the two the schema actually requires. Nothing verifies that the
   client declared the extension in its per-request capabilities before a task is
   returned, which the specification states as a MUST.

   That paragraph read the overview page, and the overview is not the schema. Against
   `https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks` (fetched
   2026-08-30) the normative `interface Task` requires **`createdAt: string` and
   `lastUpdatedAt: string`** — a reviewer claim this document previously dismissed, wrongly
   — declares **`pollIntervalMs?: number` as optional**, not required, and names a **third
   method, `tasks/cancel`**, alongside a `notifications/tasks` notification. Neither the
   third method nor the notification appears in `ADDED_IN_2026_07_28`, so the constant that
   documents what the revision added is itself short by one.

   MIK-7311's acceptance criteria were derived from the overview and inherit these errors.
   They are corrected against the schema before that ticket is worked, because an
   implementation built to this inventory would have shipped two missing timestamps and a
   wrongly-required poll interval.

4. **The failed-task payload is a string where the specification says a JSON-RPC error.**
   `src/protocol/tasks.rs:37` holds `error: Option<String>`; the specification's terminal
   states put the final `result` on `completed` and the JSON-RPC `error` object on
   `failed`. A client parsing the error would get a message where an object is required.

5. **The per-request `logLevel` is parsed and never read.** `classify_request` lifts
   `io.modelcontextprotocol/logLevel` into `RequestFields::log_level`
   (`src/protocol/meta.rs:196-199`), and no consumer exists: the only other `log_level`
   symbols in the tree are the CLI's own flag and the legacy global `LoggingLevel` behind
   `logging/setLevel` (`src/gateway/meta_mcp/protocol.rs:279`), which is an unrelated
   mechanism and is itself refused on the modern path. Requirement STATELESS.7 is a
   MUST-NOT — do not emit `notifications/message` for a request that declared no level —
   and it holds only because the modern path emits none at all. Nothing positive was built,
   so the requirement is satisfied vacuously and the field is dead on the parse side.

   The key's *presence* is load-bearing and stays: `meta.rs:150` counts it as an era
   declaration, so a request carrying `logLevel` and omitting the required pair is
   malformed rather than quietly legacy. Only the lifted value has no reader.

   The vacuous satisfaction is a standing trap for the next change: the moment anything on
   the modern path emits a `notifications/message`, STATELESS.7 becomes a live MUST-NOT and
   the parsed level has to be read. Whoever wires log delivery closes this finding in the
   same change or breaks the requirement silently.

   Same disposition as `gateway_declares()` below, for the same reason: the repair is to
   consume it, and consuming it means building per-request log delivery, which is a feature
   this release did not set out to add. Recorded rather than repaired. Deleting the field
   was rejected — it is the protocol's own key, and the next release that wires log
   delivery needs the parse it would remove.

One further finding is open and gates nothing: the OAuth metadata tests release an ephemeral port
before rebinding it — once inline at `src/oauth/metadata.rs:322-324` and once in the `free_addr`
helper at `:332-337` — so a concurrent process can take it in between.
Graded LOW / UNLIKELY / LATER. It is test hygiene rather than a shipped defect, recorded because it
was found and never written down.

### Closed during the review — restart detection for `HOME`

This was carried as a sixth numbered finding in an earlier revision of this document. It is
**closed**: the repair is in the tree at `src/config_reload/mod.rs:1340-1344`, where the notice
fires on either run's `HOME` assignment beside a `~` entry or on a changed value. It is kept in
full, out of the open list, because the owner question at the end of it is still open and because
the analysis is the reason the repair is shaped the way it is.

**Restart detection was wrong in both directions.** A reload reported
`restart_required` whenever startup recorded a `~` entry and the overlay assigns `HOME`, changed
or not. `changed_startup_env_keys` filters every other key on whether its resolved value actually
differs from startup, then pushes `HOME` past that filter on presence alone:
`if env.env_paths().has_tilde_entry() && evaluated.overlay.assigns("HOME")`
(`src/config_reload/mod.rs:1311-1312`). The sequential `HOME` + `~/…` layout that branch
exists to serve therefore makes every later reload report a restart it does not need.

It errs in both directions, and the second direction was missed when this finding was first
written down. `HOME` is not in `IMPLICIT_STARTUP_ENV_KEYS` (`:1279-1283`), and it reaches the
value filter only if the config happens to name it as a secret reference. So an overlay that
*removes* a HOME assignment startup had — leaving the recorded `~` entries to resolve
somewhere else on a restart — pushes nothing and is compared against nothing. The common case
over-reports and is merely noisy; the removal case under-reports and is the one that matters.
Gated BEFORE-DEPLOY.

This document does not prescribe the repair, having got it wrong once: comparing the overlay's
final HOME against startup's is not sufficient. `~` resolves at the point each env file is
applied, and `EnvPaths` keeps those paths in application order
(`src/config/env_overlay.rs:45-48`), so moving an unchanged `HOME` assignment across a tilde
entry changes where that entry resolves while every value comparison still reports equal. What
the check has to be sensitive to is the HOME in force *at each tilde-spelled entry*, against what
was in force there at startup — assignment, removal and reordering alike.

**Repaired.** The rule is now a comparison of the HOME actually in force —
`startup.resolve("HOME") != evaluated.overlay.resolve("HOME")`, still conjoined with
`has_tilde_entry()` — in place of the presence check. A re-stated HOME resolves equal and
reports nothing; a removed assignment falls through to the process environment, resolves
different, and reports. The paragraph above overstated what defeats a value comparison: the
reordering case it describes is an edit to the `env_files` list, which the restart-field diff
already reports as `env_files` (`src/config_reload/mod.rs:571-572`, inside
`pending_restart_fields`, not `compute_diff`), so it never needed this rule to
catch it. Nothing resolves `~` a second time, so `RecordingHome`'s one-resolution assertion
(ENVFILE.19e) still holds. New rows ENVFILE.19g (re-stated HOME reports nothing) and
ENVFILE.19h (removed assignment reports HOME) were written first and observed failing on the
presence check — 19g reporting `HOME` with nothing moved, 19h omitting it with everything
moved. `config_reload` is 79/79. **This finding is closed** — see the repair cited at the head of
this section.

**Closure re-check found the layer is wrong (2026-08-30).** Both vendors returned
SHIP-WITH-FIXES on the repair commit and converged on one defect: comparing the *final* HOME
still misses a HOME that changes before a later `~` entry and is restored by a file after it —
the paths move, both finals compare equal, and the `env_files` list is untouched, so nothing
reports. Verified at source: `~` is substituted with the home in force at that point in the
sequence (`src/config/mod.rs:456-466`, `expand_home` at `:475-484`), and the only consumer of
overlay HOME is a later env-file entry — `fallback_config_path` reads `dirs::home_dir()`
directly (`:268`). The same reading condemns the tests, including one that predates this
change: a HOME assignment inside the *sole* `~/x.env` entry moves nothing, because that entry
was expanded from the process home before its own assignments applied. ENVFILE.19h asserts a
restart for exactly that, and so does ENVFILE.19e, whose premise sentence — "a `HOME`
assignment against a `~` entry moves where a restart would read" — is false whenever the
assignment sits in the last, or only, tilde entry. The rule being encoded is not "did HOME
change" at any layer; it is *would a restart open different files than startup did*. That
question is answered by the recorded paths, not by HOME, and it needs an owner decision
because the design deliberately forbids resolving `~` a second time.

**Closed conservatively; the semantics question stays open.** ENVFILE.19i was written first and
observed failing on the value comparison — two entries, the first moving HOME and the file the
second names restoring it, finals equal, `HOME` absent from the report. The rule now fires on
either an assignment or a value change beside a tilde entry
(`src/config_reload/mod.rs:1325-1332`), which is statable in one line: *the notice is never
absent when a restart would read different files, and it does not clear*. This is a deliberate
design event, not a repair: ENVFILE.19g
now asserts the notice it previously asserted away, because nothing available at reload can tell
its harmless case apart from 19i's real one without re-expanding `~`, which the design forbids.
19h keeps its assertion and loses its false premise — its sole entry relocates nothing; it is
the value branch's test, not the relocation case.

Both vendors then found the same remaining silence, independently: checking assignment on the
*reload* overlay alone misses a startup move that the reload DELETES, when the value startup
restored happens to equal the process environment's. ENVFILE.19j reproduces it — observed
silent, `["env_files", "default_routing_profile"]` with no `HOME` — and the predicate now reads
either run's assignment (`startup.assigns("HOME") || evaluated.overlay.assigns("HOME") ||`
values differ). Only startup's own assignment records that the expansion base was ever moved.
The function doc was rewritten with it; it still taught the value-only rule.
`config_reload` is 81/81; lib 3763/3763; clippy and fmt clean.

One reviewer improvement is recorded and not taken: the ENVFILE.19 fixtures seed the running
config with `Config::default()`, so `restart_required` and the `env_files` field in these
outcomes are harness artifacts rather than evidence. The `HOME` assertions are unaffected and
are what these rows test; re-seeding a helper shared by the whole family is a change to other
tests' fixtures and out of this change's scope.

Closure re-check, both vendors, on the repaired head: SHIP (gpt 2026-08-30T16:15:34Z, grok
16:16:32Z, identical material). No further findings, and this was the last round on this
predicate: three examinations each found a new corner rather than damage to a repair, which is
the signal to stop patching and refer the question upward — which the open owner question below
already does.

The conservative rule has a consequence worth stating plainly, because it is what an operator
sees: for a config whose env files assign `HOME` beside a `~` entry, the notice fires on every
reload and a restart does not settle it — the next startup's env files assign `HOME` again, so
it returns immediately. The notice reports that a restart *could* read different files, not
that one is outstanding. It is fail-safe and it is noisy, and the noise is permanent for that
config shape. That is the strongest argument for the *no* branch of the owner question below:
the mechanism cannot both stay silent-free and stay actionable.

What remains for the owner is one question, and it is about behaviour rather than mechanism:
*should setting HOME in an env file be able to move where a later env file is looked for?*
If no, the coupling goes and `~` always means the real home directory — the branch, the
`so_far` parameter on `HomeResolver`, and the ENVFILE.19 family all delete, and the rule
becomes one an operator never has to think about. If yes, the check has to be path-based
("a restart is required when it would open different files than startup did"), which means
relaxing ENVFILE.19e's one-resolution fixture. Either answer is its own change with its own
design review; neither gates 4.0.0, because the conservative rule cannot be silent.

### Disposition of 3 and 4 — the extension ships not implemented

4.0.0 does not advertise the tasks extension, and the code already behaves that way.
`ExtensionSet::gateway_declares()` (`src/protocol/extensions.rs:52-56`) is the only site
that names `Extension::Tasks`, and it has no caller outside its own module, so the
capability key never reaches an advertised capabilities object. `tasks/get` and
`tasks/update` appear only in the documentation constant `src/protocol/meta.rs:240`, which
lists what the revision added; no dispatcher routes either method. No client can negotiate
the extension and none can reach the partial task model.

That is currently true by omission rather than by decision, and this records it as the
decision. It also makes `gateway_declares()` an unwired public symbol, which §2 does not
allow: recorded here rather than repaired, because the repair is to call it, and calling it
is exactly what this disposition declines to do until the implementation is conformant. It
stays in the tree as the entry point that implementation will use.

Chosen over making it conformant before the tag. Conformance is two statuses, the whole
mid-flight input exchange, cooperative cancellation, three required fields, an error payload
change and a per-request capability check — real construction on a branch that had already
converged, and it reopens review rounds on everything it touches. Shipping the subset with
a note was rejected outright: a client reading the extension identifier expects five
states, and an honest release note does not stop that call from breaking.

**This disposition was put to the operator and no answer came back within the window.** It
is the reversible branch — a later release turns the capability on once the implementation
matches the specification, and nothing shipped in 4.0.0 has to be withdrawn to do it. One
line overturns it.

Owner of the conformant implementation: **MIK-7311**, filed before the tag, carrying seven
acceptance criteria and a fail-fast on the capability check. **MIK-7312** owns gaps 1 and 2.

### Closed since: `subscriptions/listen` now streams

The handler returned an acknowledgement that closed, so a client reading it as a
live subscription waited on notifications nothing would send. It now returns the
stream itself: the acknowledgement is its first event, each notification the
client opted into follows on the same body, and every one carries the
subscription id the specification defines as the listen request's own JSON-RPC
id. Falling behind closes the stream rather than delivering a gap, because the
revision removed resumability and a client cannot learn what it missed.

Open streams are bounded by a permit held for the life of the body, so a caller
that opens streams and walks away costs something finite. A count checked before
subscribing would be raced past by concurrent callers; the permit is the
admission.

Four tests drive it over the transport rather than calling the registry
directly. Falsified by changing the published notification's method: exactly the
delivery test failed, 20 of 21 still passed — the control observes the thing it
claims to, and does not stand in for the other three.

### Two fixes have no runtime control, and that is stated rather than hidden

- The **constant-time binding comparison**: reverting it passes every row, verified by running it. A unit test cannot observe timing. The behavioural row beside it proves wrong bindings of any length are refused identically; the timing property is assured by reading the code, which is weaker.
- The **atomic score-and-update**: the probe for it did not compile, so the control is unproven. A race needs a deterministic repro harness, which this does not have.

---

## Rounds 4–7 — and the root cause they expose

Four further module reviews returned **eighteen more findings**, every one gated NOW.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 4 | `meta.rs` + `era.rs` (the era classifier) | 5 — 2 HIGH, 3 MEDIUM | SHIP-WITH-FIXES |
| 5 | `headers.rs` + `mrtr.rs` | 3 — 2 CRITICAL, 1 HIGH | SHIP-WITH-FIXES |
| 6 | `subscriptions.rs` + `tasks.rs` + `extensions.rs` | 7 — 4 HIGH, 2 MEDIUM, 1 LOW | SHIP-WITH-FIXES |
| 7 | the security controls | 3 — all HIGH | SHIP-WITH-FIXES |

### The root cause: three protocol areas were built without their specification

This is the finding that matters, and it was found by checking a reviewer's claim at source
rather than by accepting it.

**The subscription model is wrong in four independent ways, and the specification says so
directly.** Fetching `/specification/2026-07-28/basic/patterns/subscriptions` — a page that was
**never cached during implementation** — confirms all four:

| What the code does | What the specification says |
|---|---|
| parses filters at the `params` root | they nest under `params.notifications` |
| treats `resourceSubscriptions` as a boolean | it is an array of URI strings: `["file:///project/config.json"]` |
| mints a fresh `SubscriptionId` | *"The value is the JSON-RPC ID of the `subscriptions/listen` request"* |
| tags `_meta` at the notification root | the example puts it under `params._meta` |

The scratchpad holds seven cached specification pages. **There is no subscriptions page and no
tasks page**, and `spec-caching.md` is **0 bytes** — a fetch that returned nothing and was never
noticed, because nothing checked. Three protocol areas were implemented from the changelog and the
index rather than from their own pages.

**Why the conformance matrix did not catch this**: it compared the code against the requirements
document, and the requirements document was written from the same incomplete reading. Both agreed,
so the matrix went green. A conformance check that never reaches the specification is checking a
copy of its own assumptions — which is the same defect class as a fixture that reimplements the
production code it is meant to test, recorded earlier in this branch.

### What was checked and found sound

Not everything the reviewers raised survived contact with the source, and saying so is part of the record:

- **`cacheable.rs` is correct.** It defaults to `private`, which is the conservative direction: the specification confirms `public` responses "may be shared between callers even if the Result is coming from an authenticated endpoint". Its doc comment cites the schema, so despite the empty cached page it was not written from nothing. One real gap: the specification requires the same `cacheScope` across all pages of a paginated list, which is not implemented — though a uniform `private` default satisfies it by accident rather than by design.
- **The tasks findings are VERIFIED and the earlier dismissal was wrong.** They were first recorded as unreachable because the index link 404s, then dismissed against the *overview* page. The normative schema lives at `https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks` (fetched 2026-08-30), and against it every disputed claim holds: `interface Task` declares `createdAt: string` and `lastUpdatedAt: string` as required, and all five statuses. Dismissing a correct finding against the wrong page is the same failure this document already records for three other protocol areas — the second occurrence, and the reason the gap inventory below now cites the schema line it rests on.

### Two controls that failed open — both closed, re-verified at head

- **Closed.** `src/security/firewall/mod.rs:355-386` no longer turns an unobservable
  anomaly check into "no finding". `Observation::Unobservable` now sets `anomaly_blind`,
  logs the reason, and pushes a `Severity::High` `SequenceAnomaly` finding, which the
  caller treats as a block (`src/security/firewall/mod.rs:1147`). A detector with no
  identity to key on refuses instead of waving the call through.
- **Closed, with a stated residual.** `src/gateway/session_lifecycle.rs:75-82` records that
  a key re-tracked between reaping's removal and `fire_cleanup` still has its handlers
  fired, and says why: closing it needs an ownership model this module does not have. The
  module is not reached from production at all, tracked as MIK-7291, so the residual is
  bounded by that.

The path in the original finding, `firewall/mod.rs`, does not exist; the file is
`src/security/firewall/mod.rs`.

## The decision, which is the operator's

The 2025 path is unchanged, fully tested and shippable. `server.modern_protocol` defaults **off**,
and that is the isolation for findings 1 to 5 — no client reaches a modern protocol path while the
switch is off. It does not cover the remaining item, the port race, which exists only in tests.
The `HOME` restart-detection finding was in config reload, which any authenticated operator can
trigger regardless of the switch, and so was never covered by the switch either.

That finding has since been repaired rather than accepted, on the operator's instruction that anything
fixable gets fixed and that the rules left standing should be ones any user can state. The rule that
replaced it fires on either run's `HOME` assignment beside a `~` entry, or on a changed value: it is
never silent when a restart would read different files, and for a config that assigns `HOME` beside
a `~` entry it never clears either. With it closed, nothing outstanding is reachable while the
switch is off, and the port race is test-only. Two real options remain:

1. **Ship 4.0.0 as the legacy-safe groundwork**, modern path documented as preview with the findings listed. The default-off switch is what makes this honest.
2. **Hold the tag** until the five numbered open findings above are closed and re-reviewed.

Removing the modern path is *not* a third option worth its cost: the switch already achieves the
isolation removal would buy.

What changed since this recommendation was first written is the size of option 2. It was
"twenty-six findings, several of them systematic". It is now the numbered findings above and the
test-hygiene item after them, and this paragraph does not restate them or claim they are all of
them: three revisions tried, two drifted within a round, and the confirmation pass then found two
that had been omitted since the code rounds. What can be said is what was checked — no construction
remains on the transport itself, the `subscriptions/listen` stream having landed, and nothing on the
list waits on a source that cannot be reached, the tasks schema having been read.

## Rounds 9–17 — the confirmation pass on this document

The last nine rounds reviewed this document rather than the code, both vendors on identical
material, scope declared in the prompt each time. Rounds 15 to 17 reviewed this table.

| Round | Material | Findings | Verdict |
|---|---|---|---|
| 9 | the tasks gap inventory rewritten against the schema | 1 MEDIUM (gpt), 1 improvement (grok), the same one | SHIP-WITH-FIXES |
| 10 | the repair to round 9 | 2 MEDIUM (gpt), 2 improvements (grok), the same passage | SHIP-WITH-FIXES / SHIP |
| 11 | the closing paraphrase deleted | no finding at any gate; 1 improvement (gpt), 2 (grok) | SHIP / SHIP |
| 12 | two omitted findings added to the inventory | 4 (gpt), 1 + 2 improvements (grok); both vendors on the same false claim | SHIP-WITH-FIXES |
| 13 | the repairs to round 12 | 2 + 1 improvement (gpt); grok found none | SHIP-WITH-FIXES / SHIP |
| 14 | the repairs to round 13 | 1 improvement (gpt), 1 (grok) | SHIP / SHIP |
| 15 | this history table itself | 2 LOW bookkeeping errors (gpt); grok found none | SHIP-WITH-FIXES / SHIP |
| 16 | the repairs to round 15 | 1 LOW (grok); gpt found none | SHIP / SHIP-WITH-FIXES |
| 17 | one clause deleted | none | **SHIP** / **SHIP** |

Rounds 12 to 14 are the same pattern one level down. Round 12 asked whether the document's open
inventory matched the reviews that produced it, and it did not: a MEDIUM config-reload finding and a
LOW test-hygiene one had never been written down, while round 11 had shipped a sentence calling the
list complete. Adding them introduced a fresh false claim — that the `HOME` branch errs only in the
safe direction — which both vendors caught, and then a wrong prescribed repair, which one did. The
safe-direction sentence was corrected, because the finding underneath it is real and had to be
stated accurately. The completeness assertion and the prescribed repair were deleted outright.

Rounds 9 and 10 both found their defect in the previous round's repair, in the same paragraph:
a prose summary of the numbered open-findings list, which fell out of date each time the list
was corrected. Round 11 deleted the summary instead of correcting it a third time, and both
vendors returned SHIP. The pattern is the one the repair protocol names — three rounds spent
patching a mechanism that the first round could have removed.
