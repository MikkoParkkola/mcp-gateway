# MCP Gateway 4.0 — reboot handoff (2026-09-08)

User requested a laptop reboot and session restart. New work is paused for this checkpoint. The full release goal remains INCOMPLETE, not blocked or achieved. Resume from actual files and remote state; do not restart or redo completed work.

## Start here

Integration candidate: `/Users/mikko/github/.worktrees/mcp-v4-next-integration`, branch `codex/v4-next-integration`, pushed HEAD `dbc06304b354f405e2dc736af10d2c3993e0f0dd`, draft PR #512. Only generated CLAUDE.md is dirty there; preserve it.

Active unfinished implementation: `/Users/mikko/github/.worktrees/mcp-v4-browser-identity`, branch `codex/v4-browser-identity`, base dbc06304. The four verifier source/design files are saved on the browser-identity checkpoint branch and backed up with a verified SHA256 manifest in CHECKPOINT below. This is unfinished WIP with a known compile failure; do not merge as validated code. Do not reset/stash/remove this worktree.

Artifacts root R: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-task-store-20260907`
CHECKPOINT: `R/reboot-checkpoint-20260908`
Live WBS: `/Users/mikko/github/.worktrees/mcp-v4-delivery/docs/release/v4.0.0-delivery-wbs.md`

## First actions after restart

1. Read local CLAUDE.md/AGENTS.md and this handoff. Check git status in the two worktrees above. The manifest backup is recovery material, not permission to overwrite newer files.
2. Fix verifier compile failure: `src/gateway/browser_identity.rs` imports/references an unavailable standalone `http` crate. Use the existing `axum::http` re-export; do not add a dependency. Initial run executed ZERO tests, failed with 11 unresolved-http errors.
3. Fix contract violations before calling verifier done: exact HTTP 200 only (current `is_success()` accepts all 2xx); session URL must be exactly `/api/v1/auths/` (current validator only requires nonempty path); parse literal loopback hosts consistently instead of the narrow string list; check cookie grammar. Add real regression tests. The redirect test must actually return Location and prove zero target hits, not merely a 302 status without Location.
4. Address independent design review below, reconcile the original account route table, then validate verifier. Keep this branch isolated until real production routes consume the verifier; unused tested helpers are not DoD.
5. Restart the cancelled narrow reap-count review in a NEW artifact directory. If SHIP, fast-forward/cherry-pick the reviewed increment into integration, then rerun all-target check to determine the next actual compile gap. Do not claim full CONTROL.4 from the count method.

## Browser verifier and contract — unfinished

Four files: gateway/mod.rs adds module; gateway/openwebui_adapter.rs widens shared namespaced_issuer to pub(super); new gateway/browser_identity.rs (~tests plus verifier); new docs/design/2026-09-08-openwebui-browser-bridge.md.

Actual Grok implementation r1 hit max turns after declaration only; r2 completed the module. Root formatted and shared namespace helper. Formatting and 569-file secret lint pass. Initial Spark `browser-identity-verifier-check-r1` failed compilation, no tests ran. Source manifest unchanged, no resource failure. Latest GitNexus full index succeeded (33.5s) before checkpoint; source still has the compile failure.

Registered contract review `R/browser-bridge-contract-review-r1` completed SHIP-WITH-FIXES; full review.log is authoritative:
- CRITICAL/NOW: explicitly require validated TLS and the established DNS-pinning/provider-client policy for HTTPS upstream session lookup. Implementation uses default reqwest TLS validation but design and DNS pinning remain to reconcile; do not mechanically disable TLS or trust arbitrary DNS.
- HIGH/BEFORE-DEPLOY: old personal-accounts route table says GET start 303s to provider, new design says GET form. Amend explicitly: GET nonbinding form; POST confirmation re-verifies, binds and 303s to provider; callback consumes/exchanges.
- MEDIUM/BEFORE-PRODUCTION: 64 KiB full OWUI response cap can reject inline avatars. Retain a bound, assess ~1 MiB full UserResponse and test oversized/profile-heavy cases.
- Improvements: exact shared issuer/subject mapping; configured installation binding; host-only gateway cookies not named token; canonical Origin comparison; anti-framing; never insert VerifiedBrowserIdentity into the MCP VerifiedIdentity slot.
These are review findings requiring disposition, not automatically approved new requirements. Review verdict is NOT SHIP.

## Verified delivered work

- PR #512 integration candidate includes reviewed OpenWebUI middleware and shared-header fix (`cc3d2c70`), approved account design/test-plan copies (`3794393a`), redacted account Debug (`aa9d76a3`), source license header (`fdae6da0`), and OAuth correction (`dbc06304`).
- Combined OpenWebUI source passed 5 adapter tests +170 router tests (overlapping groups), formatting and 568-file secret lint; fixture counters/ownership tests are real router tests.
- Earlier combined library suite: 4760 passed, 0 failed, 7 ignored at 5b27f95c. NOT a full latest-head release suite.
- OAuth PR #514 is MERGED into integration. Registered Grok SHIP. Baseline canary failed leaking endpoint twice; fixed 2 refresh tests and all57 executor tests passed on forced-rebuild Spark snapshot. Optional test improvements remain; no blocker from its review.
- PR #515 OPEN/DRAFT, branch codex/v4-reap-count, pushed aae80f8642afa5e2e11fadc5ae0f621b220e7ff1. One-file 3-line fix returns actual removed-key count. Existing2 T3 ACs +6 lifecycle tests pass; fmt/diff/index pass. Review was stopped for reboot WITHOUT VERDICT. Not integrated; full CONTROL.4 still open.

## Actual browser proof — passed, limited scope

`R/openwebui-browser-proof-r1`: receipt.md, browser-evidence.json, final-counters.png, cleanup.json.
Real browser sessions through real OWUI0.9.6 signin: A confirms once; authenticatedB same link, anonymous and replay fail. Final bind_ok1/bind_fail3. Cookies Secure/HttpOnly/SameSite=Lax verified. Ephemeral certificate accepted only by exact SPKI pin; no trust-store change. Python harness, not Rust hosted consent or Google. Canonical Rust identity, actual OWUI UI redirect, encrypted journey, PKCE/provider acceptance remain unproved. Do not close C01-C07/A07 from this proof.
Grok harness r3 fixed duplicate-cookie collapse, redirects, logging and vacuous tests; frozen `R/openwebui-browser-bridge-harness-check-r1` passed26 actual-handler/unit tests. Old r2 first run failed8/9; preserve history.
All temporary browser sessions, container `codex-owui-bridge-20260908-r1`, internal Docker network, owned SSH tunnel/harness processes, synthetic credentials and private key were removed. Verified no named container/network remains. Existing OWUI and other projects untouched.

## Release gap and coordination

Last counted integration ledger:19 blocking rows, plus supplemental account/browser acceptance gaps. CACHE4a/4b, HEADER9a/9b, MRTR7a/7b/8b/10a, SCHEMA1c, CONTROL3b/4, SUB2b/4, CONFIRM1a/2, NFR.COMPAT1/SEC1/SEC3/PERF3. Latest CI is NOT all green. Last confirmed hygiene/format/secret lint green; warnings-as-errors, task SDK, tests and other gates still need current refresh. Do not invent a percentage or treat component counts as all release scope.
External Claude worktree `/Users/mikko/github/.worktrees/mcp-2026-protocol`, branch fix/mrtr2-continuation-handle; actively changes, preserve it. Candidate integration is pinned to older external60b138bb plus our increments; newer external commits need reconciliation, not a blind reset. See checkpoint worktrees.json for latest local external SHA.
Coordination files in external tree: CODEX-TO-CLAUDE-COORDINATION.md and CLAUDE-TO-CODEX-COORDINATION.md. Several outbound exact-SHA handoffs have NO fresh acknowledgement. Do not claim confirmed delivery to Claude beyond writing the mailbox.
External PR473 B1 task-handle-without-dispatch finding is ALREADY repaired in our candidate. x1_dispatch real-router tests assert terminal backend result and exactly1 downstream call, plus caller arguments; passed in latest170 router receipt. Sent evidence to Claude to avoid duplication.
External6c81e0c6 claimed OAuth redaction but omitted actual production changes. Our reviewed dbc06304 supplies them; do not reimplement or integrate the test-only claim as a fix.
External lane remains CONTROL4 handler/cleanup, MRTR/bridge, SUB, CONFIRM and protocol. Root claimed only CONTROL4 T3 count increment; notified mailbox.

## Processes and validation discipline

No Codex-owned implementation or heavy validation process must be resumed by its old PID after reboot. All implementation jobs terminal. Contract review completed; reap review explicitly terminated with descendants for reboot, receipt `R/reap-count-review-r1/cancelled-for-reboot.json`. Do not treat termination as review completion. Other agents/users processes were not stopped.

Use actual Grok/Claude CLIs for most implementation, not Codex subagents (quota conservation). Claude last hit session limit until22:30 Helsinki; recheck availability. Grok works but broad inherited skills cause long exploration. Best bounded worker args: --reasoning-effort low, narrow tools (read_file/write; write-only with supplied context for one-file output), explicit ownership and max turns, simple system override. Inspect terminal receipt, not just a file or PID. Stop/retry only verified terminal jobs or proven loops; never on observation timeout alone.

Root owns serial Spark heavy queue, jobs1, >=20GiB headroom. Other projects may build; do not kill them. Prepare immutable snapshots with `R/prepare-source-validation.py WORKTREE OUTDIR REMOTE COMMANDS_JSON`, new directory each attempt, then execute printed launch.py. Script forces first-phase crate rebuild despite shared target cache. Require nonzero actual tests, source_unchanged=true, no resource_errors; zero tests is no evidence. Relevant run directories named above contain commands/manifests/process receipts. Never reuse the old freshness-broken runs as proof.

GitNexus impact before symbol edits, detect_changes before commit, full `npx gitnexus analyze --force` after commits. Incremental FTS repeatedly failed; use --force rather than repeating incremental failure. Preserve generated CLAUDE.md edits separately from product commits.

## User expectations

Save quota, delegate most implementation to actual Grok/Claude, concise periodic updates with gap and effort when justified, avoid duplicate work and unrelated cleanup. Ask one clear question only for genuine missing decisions. Work remains authorized after reboot. Final evidence must distinguish local WIP, tested source, pushed/merged state and residual risks. Do not mark the release goal complete or blocked because of this user-requested reboot.

## Reboot Git checkpoint supplement

User requested committing and pushing all work needed for restart. Browser verifier WIP and this handoff are being saved on `codex/v4-browser-identity`. The older dirty delivery tree is snapshotted using a temporary Git index onto `codex/v4-reboot-archive-20260908`, preserving its original branch, real index and working files. The archive is recovery material, NOT an integration branch or reviewed implementation. It includes the delivery WBS and uncommitted source/plans. Confirm remote SHA equality in checkpoint `push-verification.json` before relying on push status. Generated CLAUDE.md variations in increment worktrees are backed up locally under checkpoint `generated-instructions`, left untouched. Full release validation was not rerun for this save-only operation; known verifier compile failure and cancelled reap review remain unresolved.

Verified pushes before final evidence copy: browser WIP `a4d0cec6`, legacy archive `d95bccd0f128ff69b561d7e21832b8dac6421a5c`. Sanitized browser proof receipts and reproducible Python harness/tests are also committed under `docs/release/checkpoints/2026-09-08/` on the browser checkpoint branch. Raw worker logs and screenshots remain in local R; they were not uploaded.
