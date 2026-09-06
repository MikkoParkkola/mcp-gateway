# Issue 462: preserve an existing config when loading fails

## Increment delivery checkpoint — 2026-09-07

Isolated branch: `codex/v4-config-preservation-increment`, based on 4.0
integration commit `0d4df3c0bd4e3b3ca5afa3f2d63bdb3261b118cf`.
The five reviewed production/binary-test files are byte-identical to the
integration worktree. Existing dual-vendor SHIP receipts and independent
92/92 public assertions remain supporting evidence. Two later mechanical
changes are explicit: spell zero test permissions `0o0` for current Clippy,
and format the unchanged `discovery_names` expression on the base branch.
Their final delta review is now approved: GPT and Grok both SHIP at HEAD
`35be02836e1b054831b7d1db1063cd7794b42b2d`, material SHA256
`b1fc72b47ac0361834d48b053ee633a731104c48465b66c05ad5e1ad6ef7daff`,
actual exits0 (`gh462-mechanical-code-r1.verified.json`). No new behavioral
claim is introduced.

Fresh isolated validation: `cargo test --all-features --jobs 4 --test
gh462_config_preservation` passes 44/44, including CONFIG.3 real permission
denial and CONFIG.6 literal-reference preservation. `cargo clippy --all-features
--all-targets -- -D warnings`, `cargo fmt --check`, and `git diff --check` pass.
The initial Clippy non-octal-literal failure and initial base formatting failure
are retained in the evidence; both were corrected without suppressing checks.
GitNexus pre-commit inspection reports high aggregate impact across setup/config
flows; the source changes stay within the reviewed mutation and setup paths.

This is a draft increment into the 4.0 integration branch. Exact-commit CI,
integration and final issue/DoD closure remain open.
GH462 is still open. This checkpoint does not claim a release or deployment.


CI follow-through scope (configuration-only): unblock
PR #483 validation by allowing the existing CI workflow to handle pull requests
whose base is exactly `codex/v4-release-delivery`, alongside `main`. Preserve the
existing push branches, tag filters, permissions, jobs and all release workflows.
Only `.github/workflows/ci.yml` and this checkpoint are in scope. This inherits
the GH462 delivery objective; it is not a new release-workflow redesign.

Definition of Ready: the coordinator explicitly selected the exact integration
branch and authorized commit/push to the existing draft PR. Value: replace zero
quality-CI runs with the existing suite on an identified commit. Risks are extra
CI runner use and latent suite failures; no secret permission or runtime surface
changes. Reuse the existing workflow rather than duplicate its jobs. Alternatives:
a broad `codex/**` filter runs unnecessary branches; temporarily retargeting the
PR to `main` tests the wrong integration base. Both are rejected.

| Criterion | Level/type and decisive check | Current evidence |
|---|---|---|
| GH462.CI.1 | Configuration/static: YAML parse and actionlint; exact PR base list contains `main` and `codex/v4-release-delivery`. | PASS: actionlint1.7.12 exits0; parsed list is exactly `main`, `codex/v4-release-delivery`. |
| GH462.CI.2 | Configuration/regression: parsed workflow comparison permits only the PR branch-list addition; push/tag triggers, permissions and jobs remain identical. | PASS: entire parsed workflow equals pre-edit YAML after removing only the added PR base. |
| GH462.CI.3 | Live integration: after authorized push, workflow path `.github/workflows/ci.yml`, name `CI`, event `pull_request`, pushed PR head SHA and expected19 jobs are verified;18 may run and tag-only Docker must remain skipped. | At HEAD35be028, API lists only skipped Dependabot auto-merge run34060257731; no CI run. Post-push result is unknown. |

This observed missing run is the pre-change failure; it is not a failed Rust
test. Mirror unit tests, runtime coverage/mutation and Rust rebuilds are N/A to a
branch selector. No Rust symbol changes, so symbol impact analysis is N/A;
pre-commit diff/graph inspection still applies. Existing GH462 reviews and runtime
results remain valid. GitHub owns actor/run/SHA attribution and durable check
records; no new identity, memory, mission or platform primitive is introduced.
Design/test-plan gate: GPT `gpt-20260906T213650Z-63173` and Grok
`grok-20260906T213650Z-63168` both SHIP, process_status=ok, actual exits0;
identical5780-byte material SHA256
`948f6fa8f1ba74c8a1e83dcc741fdc4117161b185f5b87ac4e94b0af7249ef03`.
The one-line selector change now passes actionlint and parsed whole-workflow
equality after removing only the added PR base. Final config-delta gate is also approved: GPT `gpt-20260906T214607Z-91291`
and Grok `grok-20260906T214607Z-91290` both SHIP, process_status=ok, actual
exits0; identical10567-byte material SHA256
`0f3bf83a3fb1795b11b680746e3cf9f89a05955a82fa59f85fceb35524d3dc6d`.
The reviewer-requested evidence-cell refresh changes no workflow behavior.
Same-SHA CI is the post-push gate; results are recorded in
[PR #483 checks](https://github.com/MikkoParkkola/mcp-gateway/pull/483/checks)
and the delivery evidence `gh462-ci-live-run.json`. The release coordinator
owns removing the temporary allowlist entry when the integration branch is
retired; no broader wildcard is introduced.

Status: design, tests and final code approved by both vendors; compiled RED
followed by all-feature integration 44/44 and reduced-feature 36/36 GREEN;
focused regressions green; critical guard lines 29/29 and source regions 55/55;
mutation 8/9 viable caught; independent public drive 92/92 passes. Increment
validation is complete. Parent release integration, warning/security checks,
tracker receipts and delivery gates remain open; this is not a shipped release.

Issue: <https://github.com/MikkoParkkola/mcp-gateway/issues/462>

## Scope and acceptance

FOR: reject config read-modify-write operations when an existing config cannot
be loaded, preserving the file, live state, and literal secret references.

OUT: new config schemas, parser replacement, cross-process editing locks,
rollback after a successfully persisted candidate fails live reload, changing
whole-config replacement APIs, and unrelated configuration recovery tooling.

The user approved GH462 for 4.0 and subsequently authorized release delivery.
The issue's `MCPGW.CFGDEF.1`–`.3` remain the upstream contract; the following
release IDs make its variants explicit rather than replacing those criteria.

| ID | Given / when / then |
|---|---|
| GH462.CONFIG.1 | Given existing malformed YAML, when an admin mutation is attempted with or without a reload context or CLI `add` runs, return a load error before editing; original bytes and any live config/registry are unchanged. Admin mutation closures never run. |
| GH462.CONFIG.2 | Given syntactically valid but semantically invalid config, those same admin and CLI `add` paths fail with the same preservation guarantees. |
| GH462.CONFIG.3 | Given an unreadable file, inaccessible parent, or existing dangling symlink, admin mutation, CLI `add`, and setup fail without executing the edit, replacing the path, or creating bootstrap/client files. Genuine absence still permits creation. |
| GH462.CONFIG.4 | Given existing invalid config and a discoverable client backend, `setup wizard --yes --configure-client` exits nonzero and preserves gateway bytes, seeded client bytes, and the complete client-file set. Setup also refuses an invalid existing config when discovery is empty. |
| GH462.CONFIG.5 | Given a missing config or valid existing config, admin mutations, CLI `add`, and setup continue creating/extending it successfully, retaining existing settings and setup's local-profile sample capabilities. A mutation's deliberate rejection still writes nothing. |
| GH462.CONFIG.6 | Given valid config containing literal `env:` and `${VAR}` references, successful setup, CLI `add`, and admin edits retain those references and never persist resolved values or unrelated environment overrides. |

`CONFIG.1`/`.2` cover upstream `.1`; `.5` covers `.2`; paired missing/invalid
fixtures across the same entry points cover `.3`. `.3`, `.4`, and `.6` make the
approved preservation scope's I/O, setup, and secret-reference variants explicit.

## Pre-fix evidence and duplicate-work check

On 2026-09-06, `gh issue view 462 --repo MikkoParkkola/mcp-gateway` returned OPEN.
`rg` found no existing GH462 design or tests; `issue-437-config-readability.md`
covers startup diagnostics, a separate failure surface. The delivery worktree's
initial dirty paths do not include the four source areas owned by this increment.
Other agents own the release ledgers and unrelated release implementation.

Production callers, read before designing the change:

- `src/gateway/ui/backends.rs:183,238,346` call `mutate_config_and_reload` for
  add/update/delete; that delegates to `ReloadContext` when available.
- `src/config_reload/mod.rs:1553,1876` load defaults on any load error immediately
  before invoking the mutation closure and persisting its result.
- `src/main.rs:118` dispatches the setup command; `src/commands/setup.rs:77`
  repeats the dangerous load before import. Its empty-discovery route currently
  accepts any existing path without validation.
- `src/main.rs:149` dispatches CLI `add` directly to `run_add_command`; its
  `src/commands/add_remove.rs:71` load has no earlier config validation and
  reaches `write_config` at line 86 after inserting into the default config.
- `src/config_persistence.rs:35` already provides `load_existing_or_default`;
  `src/main.rs:666` uses it for discovery persistence. Its `Path::exists` check
  still conflates absence with metadata errors and dangling symlinks.
- `Config::load_literal` in `src/config/mod.rs:375` preserves references and
  funnels through `finish`/`validate_with_env` at lines 490–533, rejecting
  semantic errors as well as parser failures.

Full defaulting-loader caller classification (`rg -n
'load_config_or_default|load_existing_or_default' src --glob '*.rs'`):

| Caller | Write-back reachability and disposition |
|---|---|
| `ReloadContext::mutate_and_reload_outcome_within` and `mutate_config_and_reload` | Default-on-error can reach closure and writer: migrate both. |
| `run_setup_command` | Default-on-error can import and write: migrate and add preflight. |
| `run_add_command` | Default-on-error can add and write, with no prior load guard: migrate. |
| `run_remove_command` (`add_remove.rs:136`) | Writer exists, but `Config` derives `Default` with an empty backend map (`config/mod.rs:51,69`); `remove_backend` returns an error on that map (`backend_ops.rs:146`). No defaulted config reaches its write. Preserve source and pin invalid-file byte preservation in a behavioral regression. |
| `run_update_backend` (`add_remove.rs:254`) | Same empty-map refusal at `update_backend` (`backend_ops.rs:160`); additionally no production caller, only in-file tests. Preserve source; record as a guarded writer, not a read-only caller or an implemented CLI verb. |
| `run_list_command`, `run_get_command` (`add_remove.rs:156,194`) | Read-only allowlist: neither writes config. Existing default/error display behavior remains. |
| `backend_ops.rs:15` | Re-export, not an executing caller. |
| `setup.rs:418`, `config_persistence.rs:530` | Existing test-only round trips. |
| `write_discovered_to_config` (`main.rs:666`) | Already fallible; shared-helper classification changes apply, so add regression coverage. |

The infallible helper's documentation will state that it is unsuitable for new
write-back code and link this reviewed inventory. Only the two read-only
production callers are the read-only allowlist; existing guarded writers are
explicit exceptions whose empty-map rejection is tested. No brittle source-text
assertion replaces behavior tests. The separate defaulting load in
`resolve_stats_url` (`main.rs:482`) only derives a URL; it never persists config.

GitNexus impact on `mutate_and_reload_outcome_within` was attempted and returned
`Repository "mcp-gateway" not found. Available: hebb`. Graph evidence is
unavailable, not a LOW-risk result. Static caller evidence above supplies the
fallback; risk is moderate because the helper also serves discovery persistence.

## Options and selected design

1. **Reuse the fallible literal loader and distinguish actual absence — selected.**
   Replace the two mutation loads with `load_existing_or_default`, map its error
   into the existing `ConfigWriteError::Failed`, and keep the contextual read
   inside the reload lock. The closure, writer, and reloader run only after a
   successful load. No public signature or HTTP error envelope changes.
   CLI `run_add_command` likewise uses the shared fallible literal loader and
   returns `ExitCode::FAILURE` with a path-specific load diagnostic before adding
   a backend or writing. Missing-file add behavior is unchanged.
2. Keep the infallible loader and add validation separately at each caller.
   Rejected: divergent readers can disagree and repeated checks retain the
   destructive defaulting primitive on mutation paths.
3. Replace config loading with a new read-once parser/transaction abstraction.
   Rejected: it duplicates Figment, env-file, and validation behavior to solve
   a small error-propagation defect, increasing migration and compatibility risk.

The shared fallible helper will use `symlink_metadata`: only `NotFound` permits
defaults; all other metadata errors propagate, and any existing entry delegates
to `Config::load_literal`. This treats a dangling symlink as an existing path
that failed to load. It does not claim to prevent external filesystem races.

Setup will preflight the fallible loader before discovery/bootstrap/client
configuration, then use it again for the actual merge after any first-run local
profile creation. The extra read is confined to the setup command; the second
read preserves current bootstrap behavior and catches edits made during prompts.
This also makes empty discovery fail on invalid existing config. Diagnostics use
the existing error surfaces and name the selected path; no additional config or
credential values are logged. Existing writer validation and atomic replacement
remain authoritative. The infallible helper is not removed in this increment.

Target symbols: `load_existing_or_default`,
`ReloadContext::mutate_and_reload_outcome_within`, `mutate_config_and_reload`,
`run_setup_command`, and `run_add_command`. The infallible loader's doc comment
also changes to describe the allowlist; its implementation and signature do not.
Existing empty-discovery helper tests remain regression coverage; no extraction
or new public API is planned.

## Unknowns and readiness

| Question | Check / recorded result | Consequence |
|---|---|---|
| Is there a reusable literal, validating loader? | Read `load_existing_or_default`, `load_literal`, and `finish`: yes, including semantic validation. | Reuse; do not create a parser. |
| Can an unreadable parent be mistaken for absence here? | Read `Path::exists` usage; a temporary owner-only fixture run as UID 501 returned `stat_errno=13` after removing directory search permission. | Use error-preserving metadata classification and test permission failure. |
| Can setup be driven without touching real client config? | Read `scan_claude_code` and `claude_code_config_path`: it reads `.claude.json` under `dirs::home_dir`; existing subprocess fixtures isolate `HOME`. | Drive the real binary with temporary HOME/current directory and sanitized gateway/discovery environment. |
| Does the current implementation already reject the reproduction? | Resolved by Spark RED run: malformed and semantic fixtures executed the forbidden closure through both context and no-context mutation paths. | Both production mutation loads require repair; implementation still waits for test review. |
| Can OS permission fixtures actually deny access on the validation runner? | Resolved on Spark: real open/metadata permission-denial assertions passed and no case was ignored. | Use this non-root lane; never count a skipped permission case as acceptance evidence. |

DoR applicability (CODE, critical data handling): testable ACs, reuse search,
production wiring, alternatives, fail-fast, risk, security, rollback, and delivery
gates apply. Value is removal of an approved release-blocking data-loss path;
there is no fabricated dollar ROI or benchmark claim. This is reliability work,
not a novel capability or performance project: emerging-language/ML/crypto bets,
numerical precision, moat claims, model evaluation, and new-service SLOs are N/A.
Property-based/formal verification was considered; deterministic failure-class
fixtures are sufficient for this bounded branch contract. No dependencies, API
schema, authorization rules, personal-data destination, or license changes.
Existing CLI/admin authorization remains authoritative (B1); existing file/live
state remains owned by the gateway (B2/B3); existing loader/writer are reused (B4).
Root release delivery owns issue field synchronization, reviews, CI, and merge;
none is claimed complete by this design.

Canonical process and DoD were read from `~/.claude/rules-source/workflows/`.
The process's `_reference/workflows/quality-gates-dor.md` pointer is missing;
the full DoR was read from
`/Users/mikko/github/claude-elite/rules-source/workflows/quality-gates-dor.md`.

## Test plan and release evidence

| AC | Cases, level, type, falsifier | Evidence status |
|---|---|---|
| CONFIG.1 | Component tests invoke both production mutation paths on backend-bearing malformed YAML; assert error, untouched bytes, mutation-call count zero, live config/registry unchanged. Real-binary CLI `add` on the same failure class must exit nonzero, preserve bytes, and report no added backend. Old fallback executes the closure/add and overwrites. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |
| CONFIG.2 | Same admin and CLI `add` matrix with readable YAML containing an invalid backend name or URL; prove fixture rejected by `Config::load_literal` before calling the mutation path. Type: negative validation. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |
| CONFIG.3 | Explicit cross-product: each of unreadable file, denied ancestor, and dangling symlink through each of context and no-context mutation paths (six cases). Assert the failure precondition, path identity/bytes, zero closure calls, and unchanged live config plus registry for all context cases. Binary CLI `add` and setup repeat all three I/O failures; setup covers both plain and `--configure-client` modes and asserts no bootstrap/client writes or new files. Shared-loader unit cases separately pin missing path => default, valid path => literal config, invalid file/permission/dangling entry => error, with path preservation. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |
| CONFIG.4 | Real-binary CLI integration with temporary HOME containing a discoverable `.claude.json`; `setup wizard --yes --configure-client --output ...` must fail, preserve gateway bytes plus every seeded client file's bytes and the complete client-file set, and produce no success/import message. Run with the default `config-export` feature enabled; a positive valid-config control must prove the same fixture permits an actual client write. Repeat the invalid case with an empty client directory and assert failure before the discovery-start message: no discovery outcome, including empty discovery, can bypass the preflight. Type: negative acceptance. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |
| CONFIG.5 | Both mutation paths and CLI `add` pair missing and valid cases with failure cases; valid edits preserve sentinel settings; rejected closure preserves exact bytes. CLI missing/valid setup imports a unique fixture backend and retains local samples/settings. Existing queued-edit/lock-bound tests and CLI remove/update empty-map rejection are regression gates. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |
| CONFIG.6 | Literal reference fixture plus controlled child environment; apply harmless admin edit, CLI `add`, and setup import and inspect persisted YAML for both exact references and absence of a distinctive resolved secret/override. Type: confidentiality and compatibility. | r3 RED followed by all-feature integration GREEN (44/44); tests closure approved. Additional regression/DoD evidence below. |

Tests use `gh462_` names and carry AC IDs in comments. The public reload and
loader APIs expose every needed invariant, so component/loader tests and binary
journeys share `tests/gh462_config_preservation.rs`; no test-only production seam
or edits to the large config-reload test module are needed. This file-layout
choice changes no test level or acceptance requirement.
Focused guarded-writer regressions may be added in `src/commands/add_remove.rs`;
production source changes there are limited to the confirmed `run_add_command` gap.
Add a focused third-consumer regression in `src/main_tests.rs` beside its existing
`write_discovered_to_config` tests: genuinely missing config still imports, while
an invalid or dangling-symlink destination errors without replacing the entry.
This protects the shared helper's existing production caller, without changing
discovery source behavior. Root assigned this increment ownership of new tests in
`src/main_tests.rs`.
Tests must run against pre-fix source and fail at preservation assertions before
implementation. Root coordinates builds and the independent test review.

## Design review receipt

GPT review `gpt-20260906T125419Z-64997` returned SHIP-WITH-FIXES (root confirmed
the completed run). Source verification confirmed `configure_ai_clients` only
runs when `configure_client` is true (`src/commands/setup.rs:90`), so the original
client-byte assertion could not detect an accidental permitted client write.
The CONFIG.4 test plan now enables `--configure-client`, snapshots client bytes
and the complete file set, and requires a positive client-write control. The
CONFIG.3 matrix now explicitly covers all six I/O-failure/mutation-path pairs and
their live-state invariants. The third-consumer regression was also accepted.
These edits strengthen existing criteria without moving FOR or OUT. No source
or test code has been written. This receipt does not claim design approval or a
passing acceptance result.

Grok review `grok-20260906T125419Z-64996` subsequently returned SHIP-WITH-FIXES
(root confirmed the same reviewed payload hash as GPT). Its CLI-add omission
was source-confirmed: `main.rs:149` calls add directly, and `add_remove.rs:71–86`
contains no validating load before fallback and write. This receipt completes
the existing FOR scope's caller inventory and makes add explicit in the AC/test
matrix; it does not narrow any requirement. Remove/update overwrite claims were
source-refuted by their mandatory empty-map refusal, so those implementations
remain unchanged and receive regression checks. Shared-loader classification
tests and the documented defaulting-call allowlist were accepted. Both vendors'
closure rechecks remain pending; no source/test implementation is authorized yet.

Round 2 closure completed with SHIP from both vendors (root verified process
status `ok`): `gpt-20260906T130728Z-98459` and
`grok-20260906T130729Z-98458`. Actual reviewed material SHA-256:
`5de39d7d1ceab1bf1749971626438c2f351ce0660a158233a14cb965c765d1fa`
(49,074 bytes). Root authorized failing tests only after those receipts.
The live CLI declaration at `src/cli/mod.rs:289–295,523` requires `setup wizard`;
tests use that launch spelling rather than the earlier shorthand `setup` and
assert the setup banner plus selected-path error, so a clap failure cannot be
reported as config-preservation evidence. No product contract changed.

The isolated GitNexus index `mcp-gateway-v4-delivery` is now available. Upstream
impact calls returned LOW for the fallible helper, both reload functions, and
setup; MEDIUM for add. The graph's direct-caller counts were respectively
2/2/3/1/8. Static production callers above remain part of the impact review.

### Authored test mapping (compiled; RED observed)

| AC | Test names in `tests/gh462_config_preservation.rs` unless stated otherwise |
|---|---|
| GH462.CONFIG.1 | `gh462_malformed_{without,with}_context`; `cli::gh462_add_malformed`; `tests::gh462_discovery_persistence_preserves_existing_invalid_files` in `src/main_tests.rs`. |
| GH462.CONFIG.2 | `gh462_semantic_{without,with}_context`; `cli::gh462_add_semantic`; same discovery regression. |
| GH462.CONFIG.3 | `unix_io::gh462_{unreadable,denied_parent,dangling}_{without,with}_context`; `unix_io::gh462_loader_{unreadable,denied_parent,dangling}`; `cli::gh462_{add,setup}_{unreadable,denied_parent,dangling}` plus setup `_without_client` variants; `gh462_discovery_persistence_preserves_dangling_symlink` in `src/main_tests.rs`. |
| GH462.CONFIG.4 | `cli::gh462_setup_{malformed,semantic}` and their `_without_client` variants; `cli::gh462_setup_refuses_invalid_config_before_empty_discovery`; `cli::gh462_setup_empty_discovery_without_client`; `cli::gh462_valid_config_control_reaches_empty_discovery`; the valid configure-client control below. |
| GH462.CONFIG.5 | `gh462_{missing,valid}_{without,with}_context`; `gh462_rejected_mutation_leaves_valid_config_exactly_unchanged`; `gh462_shared_loader_distinguishes_missing_valid_and_invalid_files`; `cli::gh462_{add,setup}_{missing,valid}`; `gh462_remove_and_update_preserve_{malformed,semantic_invalid}_config` in `src/commands/add_remove.rs`; existing discovery missing/valid tests. |
| GH462.CONFIG.6 | `gh462_successful_mutations_preserve_literal_secret_references`; `cli::gh462_{add,setup}_references`. |

Negative cases are individually named (test macros only remove repeated fixture
construction): one red assertion cannot prevent the other mutation/CLI path or
failure class from executing. Unix permission fixtures require actual OS denial
and fail rather than silently skipping when the runner is privileged.
`rustfmt --check` on the three changed Rust test files and `git diff --check`
pass; these are syntax/style evidence. Actual RED evidence is recorded below.
Independent tests-as-tests closure subsequently approved this suite in r3 (receipt below).

### Regression-first execution receipt

Spark built the default-feature revision with these test additions before any
GH462 behavior implementation. `cargo test --test gh462_config_preservation --
--nocapture` exited 101: 22 assertion failures, 8 passes, 0 ignored. Failures
demonstrated closure execution on invalid input (CONFIG.1/.2/.3), metadata errors
and dangling entries treated as missing (CONFIG.3), and setup/add reporting
success while rewriting the invalid config and client files (CONFIG.1/.2/.4).
`cargo test --bin mcp-gateway gh462_ -- --nocapture` exited 101: the dangling
discovery destination was replaced, while invalid-file discovery preservation
and guarded remove/update passed (2 passes, 1 failure). Neither result is a
compilation error or a passing release result.

Self-QA found one insufficient original pass: CLI add with a denied parent failed
at its later write, which did not prove early load refusal. The test now rejects
that write-stage diagnostic. A separately compiled exact rerun,
`cargo test --test gh462_config_preservation cli::gh462_add_denied_parent --
--exact --nocapture`, exited 101 at that intended new assertion. This supersedes
that case's original pass; no full-suite rerun is claimed after the strengthening.
The remaining seven original integration controls cover missing/valid configs,
literal references, deliberate rejection, and loader behavior already correct.

Evidence captured by root under the release review directory:
`gh462-red.log`, `gh462-bin-red.log`, and
`gh462-add-denied-parent-red.log`. The deferred reproduction and permission
fixture questions above are resolved by those outputs: both mutation paths
execute the forbidden closure, and real OS permission-denial fixtures executed
without skips. The implementation gate remains closed until tests-as-tests
review approves this frozen test set.

Cheapest checks: `git diff --check`, then targeted `gh462_` tests (library and
binary). After implementation: focused suite green, existing setup/config reload
regressions, formatter and clippy, followed by the release's broader suite and
security gates. An independent driver receives only ACs and launch instructions
and exercises the built revision's setup/admin surfaces. Coverage and mutation
evidence, dual review, CI, and delivery-chain evidence remain required; a local
test pass alone does not close the issue.

Risks: error mapping could falsely report success (assert return status and no
success message); fixtures could hide load failure (assert the precondition and
zero closure calls); filesystem races remain (existing in-process lock retained,
cross-process locking explicitly out). STRIDE: tampering/data-loss mitigated by
early failure; information disclosure mitigated by literal loading and no new
value logging; denial-of-service behavior stays a bounded error on the existing
admin/CLI path. No identity or crypto change.

Rollback is reverting this increment's source changes; no schema/data migration
or service action is required. This restores the old defect, so rollback is not
the operational recovery recommendation: an operator fixes the invalid config
or restores their backup and retries the rejected edit.


### Tests-as-tests review, round 1

Both vendors returned SHIP-WITH-FIXES on identical actual material SHA-256
`73c635487431d5cd34383d8fe7d1517548244ecd2c49e167edce288607c79632`
(140,541 bytes), run ID `mcp-v4-config-tests-20260906-r1`. Authoritative ledger
rows and actual wrapper exits were checked: each reports `process_status=ok`,
exit 0, the same scope/head/digest/byte count. Review artifacts:
`gpt-20260906T134201Z-79974.md` and `grok-20260906T134201Z-79973.md`.
This is a tests gate result, not approval to implement or ship.

Source-confirmed findings and repairs, with no acceptance-scope changes:

- Both vendors: invalid setup only used `--configure-client`; add separately
  named plain-setup malformed, semantic, and all three I/O cases.
- GPT: host process discovery contaminated the purported empty-discovery case.
  `ProcessScanner` invokes `ps`/`wmic` through PATH; tests now give the child an
  isolated PATH without those utilities. Real client scanning remains active.
  A valid existing-config control must print the actual no-servers message and
  preserve the file, proving the empty-discovery branch is exercised. Invalid
  empty-discovery variants cover both client-configuration flag settings.
- GPT: byte equality did not prove the failed operation preserved file identity.
  Snapshot Unix device/inode identities as well as bytes and the complete tree,
  including the discovery and guarded-writer tests. Other platforms retain byte
  and path-set checks; the shared writer's replacement falsifier runs on Unix.
- Improvements adopted: check literal references at their parsed destination
  fields; require the semantic fixture's `ConfigValidation` error class; omit
  no-context live-state assertions; register CLI missing/valid/reference controls
  independently; replace stale planned-only evidence statuses.
- Grok fixture-deduplication suggestion: observation, no action. The two tiny
  malformed/invalid-name literals span independently compiled binary/library
  test contexts; introducing a shared cross-crate fixture module adds coupling
  without improving these concrete failure-class checks.

GitNexus impact attempts for the new test helpers returned UNKNOWN/target not
found because those new files are not indexed; their static consumers are only
this integration test module. No production symbol was modified. Formatter and
`git diff --check` pass on the repaired test files. Root owns the synchronized
rerun; the repaired suite results are recorded below. Both vendors' closure
rechecks remain pending.


### Repaired-suite regression-first execution receipt (r2)

Root synchronized the repaired tests to Spark before runtime behavior changes.
`cargo test --test gh462_config_preservation -- --nocapture` compiled and exited
101: 41 cases, 29 assertion failures, 12 passes, 0 ignored. Failures attribute to
forbidden mutation closure execution (both context paths and every invalid/I/O
class), mistaken absence for dangling or denied-parent entries, successful CLI
add/setup on invalid inputs, later write-stage refusal instead of load refusal,
and discovery reached before setup preflight. Both plain setup and
`--configure-client` variants exposed the intended defect.

The valid-config empty-discovery control passed and printed the actual no-servers
message. Expected missing-`ps` warnings prove child process scanning is isolated;
they are not harness failures. Other passing controls cover missing/valid add and
setup, literal secret references, deliberate mutation rejection, and currently
correct loader behavior. `cargo test --bin mcp-gateway gh462_ -- --nocapture`
compiled and exited 101: one dangling-symlink discovery assertion failure, while
invalid-file discovery and guarded remove/update both passed (3 cases total).
These are meaningful pre-fix RED results; none are compile errors or release PASS.

Evidence: `mcp-gateway-v4-gh462-red-r2.log` and
`mcp-gateway-v4-gh462-bin-red-r2.log` in the release review directory. This full
rerun supersedes the original suite counts and denied-parent-only rerun. Runtime
implementation remains gated on tests-as-tests closure review of these repairs.


### Tests-as-tests closure, round 2

Authoritative receipts agree on run `mcp-v4-config-tests-20260906-r2`, actual
material SHA-256 `1fb2f305f6eea5586045c82ca6f02d274bbaf034bfdac6ebfa5ff31b834e7677`
(162,594 bytes), scope/head and `process_status=ok`; both actual wrapper exits
were 0. GPT `gpt-20260906T141423Z-64073` returned SHIP-WITH-FIXES. Grok
`grok-20260906T141423Z-64068` returned SHIP and closed all original r1 NOW gaps.

GPT's new NOW finding is source-confirmed: the admin reference control did not
supply an unrelated `MCP_GATEWAY_*` override, although CLI controls did. The test
now relaunches itself in an isolated child carrying a distinctive port override,
asserts the resolved control sees it, edits a backend description through both
production mutation paths, and asserts the saved YAML keeps its original port.
A completion marker after both paths prevents a zero-selected-test child from
being mistaken for success. No unsafe shared-process environment mutation.

Small improvements adopted: permission fixtures now contain prevalidated valid
YAML, isolating I/O as their refusal cause; only client-export CLI cases require
`config-export`, retaining add and plain-setup coverage on `webui` builds without
that feature; missing/valid mutation controls and malformed/semantic guarded
writer cases have independent test names; CONFIG.3's table explicitly names both
setup flag variants. GitNexus reported UNKNOWN for these unindexed new test
symbols; static consumers are only their test modules. Runtime behavior remains
unchanged. Formatter and diff checks pass; root's new compiled test run and both
vendors' narrow closure recheck are required before implementation.


### Final test-repair execution receipt (r3)

Spark compiled both suites before any GH462 runtime implementation. Integration
`cargo test --test gh462_config_preservation -- --nocapture` exited 101:
44 tests, 29 intended assertion failures, 15 passes, 0 ignored. All four
independently named missing/valid mutation controls pass. The isolated admin
literal-reference/unrelated-environment-override control passes, including its
required completion marker. The valid-YAML permission fixtures still expose
forbidden closure execution and later write-stage refusal; malformed YAML can
no longer mask those I/O failures. Remaining RED attribution is unchanged from
r2: invalid admin/CLI writes, missing-vs-unreadable misclassification, and setup
reaching discovery before load refusal.

Binary `cargo test --bin mcp-gateway gh462_ -- --nocapture` exited 101:
4 tests, the dangling-discovery replacement assertion failed, and invalid-file
discovery plus independently named guarded malformed/semantic controls passed.
No compilation failures. Raw evidence: `mcp-gateway-v4-gh462-red-r3.log` and
`mcp-gateway-v4-gh462-bin-red-r3.log` in the release review directory. Reduced
feature execution is still unrun; the default-feature results are not presented
as evidence for it. Both vendors' r3 closure remains required to implement.


### Tests-as-tests closure, round 3 — approved

Both authoritative rows returned SHIP: `gpt-20260906T143247Z-9404` and
`grok-20260906T143247Z-9409`, run `mcp-v4-config-tests-20260906-r3`. Both actual
wrapper exits were 0, both rows report `process_status=ok`, and head/scope match.
Actual reviewed material SHA-256:
`9a2be50ae06c94030b1f736c30639f6a5804e5acc6547aadb74bf25996d74495`, 169,866 bytes.
All NOW findings are closed; this opens implementation, not release shipping.

Both reviewers request a `webui`-without-`config-export` execution receipt; it is
queued with root for post-fix validation and remains unclaimed. Grok's remaining
suggestions are recorded observations: independently naming the already passing
2-path deliberate-rejection control improves failure labeling; adding setup CLI
coverage when `webui` is entirely disabled extends the current default/webui
integration verification envelope. Neither is a NOW defect, and no reviewed
assertions were weakened or removed. Root owns the release-wide feature matrix.

### Implementation receipt — initial validation handoff

Applied the approved design only in `src/config_persistence.rs`,
`src/config_reload/mod.rs`, `src/commands/setup.rs`, and
`src/commands/add_remove.rs`. The shared fallible loader defaults only for
`symlink_metadata` NotFound; existing entries retain literal parsing/validation,
and metadata errors identify the selected path. Both admin loaders propagate
load errors before invoking a mutation, keeping the contextual load under its
existing lock. Setup preflights before discovery and loads fallibly after
bootstrap for the actual merge. CLI add refuses a failed load before insertion.
The infallible helper's reviewed allowlist is documented; guarded remove/update
and their behavior remain unchanged. No edits to signing's
`reload_outcome_locked` method or other agents' source.

Pre-edit GitNexus impacts were refreshed against `mcp-gateway-v4-delivery`:
loader, two mutation targets, setup LOW; add MEDIUM, with direct callers reviewed
and no HIGH/CRITICAL result. Source diff inspected. `rustfmt --edition 2024` on
owned source/test files and `git diff --check` pass. Root has the synchronization
request for the 44-case integration and 4-case binary suites, followed by
config-persistence, config-reload (including lock/queued-edit), setup/add-remove,
discovery regressions, and the reduced-feature test command. Green results,
independent functional driving, final review, and release DoD remain pending.


### All-feature integration GREEN

Root ran the implemented candidate on Spark with all features. Raw log
`mcp-gateway-v4-gh462-green.log` reports 44 passed, 0 failed, 0 ignored. Every
CONFIG.1–6 integration case now passes, including all previously red preservation
cases, ordinary/client-configuring setup, and literal-reference/environment
controls. This is executable integration evidence, not the independent D6
functional drive. Binary and regression groups plus webui-only validation were
queued by root and are not claimed here until their results arrive.

Before measuring, the critical coverage denominator and mutation contract were
specified in external `gh462-validation-plan.md`. The AC-only isolated-driver
brief is external `gh462-functional-brief.md`; it contains no implementation or
test diff. Local parser-only cargo-mutants candidate listings are discovery,
not executed mutants or a score. Coverage and mutation execution require root's
Spark slot and preserve the other increments' targets/profiles.


### Adjacent build-matrix repair — Small peer-reviewed increment

FOR: restore compilation of the already supported `webui` build without the
`cost-governance` feature, exposed by this increment's reduced-feature check.
OUT: cost-governance behavior changes, different restart semantics, new fields,
and unrelated warnings. This is a build compatibility repair, not a new product
scope decision or a weakening of CONFIG.1–6.

Source evidence: Config.cost_governance and the corresponding MetaFields member
already share `#[cfg(feature = "cost-governance")]`; tracked_sections alone
references the field unconditionally. The real reduced-feature log contains
E0609 at that entry. This is compiler regression evidence, explicitly NOT an
assertion-level RED or a passing test. Its four existing warnings remain visible.

Selected mechanism: let the existing local sections macro forward optional
per-entry attributes and apply that identical feature guard to the one
cost-governance entry. Alternatives: conditionally building/pushing a second
vector introduces unnecessary separate assembly and an unused-mut concern;
gating the whole classifier would remove unrelated restart reporting. The
selected mechanism keeps the enabled-feature map unchanged and never names an
absent field. No new helper or dependency.

Acceptance GH462.BUILD.1: all-feature and `--no-default-features --features webui`
builds compile, the reviewed preservation matrix passes (44/36 Unix cases), and
the existing `every_tracked_section_is_covered` assertion passes with all
features. Validation uses existing reviewed tests plus the compiler; no mirrored
or brittle text test. DoR: exact failure/target/risk and decisive checks known;
no user-intent unknown, no migration or live deployment. Root peer-reviewed and
approved this Small design/test approach before editing. GitNexus reports LOW
for tracked_sections, with direct consumers pending_restart_fields and the
existing tracked-section regression. Root grants four Spark build jobs in the
main tree; other mutation work is in an independent copied tree.


### Focused regression and BUILD.1 receipts

Raw Spark logs confirm: binary GH462 4/4; config-persistence 13/13;
config-reload 78/78; setup 8/8; add/remove 13/13; discovery-write 2/2. All are
zero-failure, zero-ignored runs. These groups preceded the attribute-only
build-matrix repair. After that repair, `--no-default-features --features webui`
integration passed 36/36 (actual exit 0), all-feature integration passed 44/44
(exit 0), and all-feature `every_tracked_section_is_covered` passed 1/1 (exit 0).
BUILD.1 is met. Logs and actual process receipts use `gh462-reduced-fixed`,
`gh462-all-features-fixed`, and `gh462-tracked-sections-fixed` stems externally.

The reduced-feature build's nine warnings remain in the raw log (five library,
four binary). They concern preexisting feature-dependent unused values/helpers
outside this change; no suppression or clean-clippy claim is made. Root owns
release-wide warning triage. The compiler E0609 is fixed, and its earlier failed
build log remains evidence rather than being relabeled a behavioral RED.

The remaining DoD work runs from a source/target snapshot at
`/home/mikko/codex/mcp-gateway-v4-gh462-dod-20260906`; all six owned source/test
hashes match external `gh462-source-snapshot.json`. The independent driver's
candidate executable SHA-256 is
`5d5220efc6071532d10a57a5125c05e07849b4a84b2c3ee26cfcd4f308c48ddd`.
The driver was spawned with no inherited context and receives only the AC-only
brief. Mutation results, critical coverage, functional observations and both
final code-review verdicts were pending at this snapshot checkpoint. The final
receipts below supersede that historical status; this is not release completion.

### Final code-review receipts and observation dispositions

Both authoritative code-leg rows returned SHIP: `gpt-20260906T151655Z-30426`
and `grok-20260906T151655Z-30427`, run `mcp-v4-config-code-20260906-r1`.
Both wrappers actually exited 0 and both ledger rows report `process_status=ok`.
Head, scope, run ID and actual material match across vendors. Actual material
SHA-256 is `5fd5d856409b4c54b760ab90b1793f98129c5a13c74cb38bd09e0fd8e5a16cdf`,
348,912 bytes. The scope includes the four production files, tests, approved
design, runtime receipts and BUILD.1 repair; it explicitly leaves functional,
coverage/mutation and release delivery as separate evidence legs. Authoritative
rows, process receipts and independently recomputed material validation are
external `gh462-code-review-r1.{gpt,grok}.ledger.json`, corresponding
`.process.json` files and `gh462-code-review-r1.validation.json`.

Neither vendor found a NOW defect. Remaining suggestions are observations:

- Migrating guarded remove/update callers to the fallible helper is future
  consistency work. The complete source inventory above proves their default
  empty backend map cannot reach a writer; the reviewed malformed/semantic
  preservation controls pass. No safety gap is left open by preserving them.
- A cost-governance-specific tracked-section presence assertion would strengthen
  future classifier regression coverage. BUILD.1's narrower compilation contract
  is met by the actual reduced/all-feature builds and existing classifier test;
  the feature-enabled entry and matching Config field gate are source-confirmed.
- The remaining `exists()` calls do not bypass the successful fallible preflight.
  In setup they select first-run bootstrap/empty-discovery messaging; in add the
  flag only controls the existing informational auth-off note. A future edit
  removing the preflight could regress safety, but the reviewed negative matrix
  fails on that regression. Cross-process edits between preflight and write are
  explicitly outside this increment's transaction contract.
- Independently naming both paths of the existing deliberate-rejection control
  would improve failure labeling. It already exercises both and asserts no write;
  no assertion or test was weakened to close the code leg.

### Critical coverage and mutation receipts

The pre-measurement contract is external `gh462-validation-plan.md`. It fixes the
complete shared loader and changed fallible guard blocks, not arbitrary covered
lines. Frozen-source windows: loader 39–48; contextual mutation 1554–1557;
no-context mutation 1880–1881; setup 42–45 and 86–92; add 72–78. The attribute-only
BUILD.1 fix uses its compile matrix, not unrelated classifier mutation counts.

Coverage execution used the isolated source snapshot and its own LLVM target.
The first full instrumented integration attempt exited 101 with 26 pass/18 fail:
CLI fixtures deliberately clear their child environment, so the instrumented
child lost `LLVM_PROFILE_FILE` and created `.profraw` files inside the temporary
HOME. Its complete-file-set assertions correctly detected those extra artifacts.
The raw `gh462-coverage-initial.log` and process receipt remain evidence of this
instrumentation failure; it is neither a product regression nor a passing run.
Frozen production and reviewed tests were not changed to hide the artifacts.

The corrected component-only command passed 20/20, with 24 CLI cases filtered:

```sh
cargo llvm-cov --all-features --test gh462_config_preservation --jobs 4 \
  --json --output-path /home/mikko/codex/gh462-coverage-component.json \
  -- --skip cli::
```

Separate author self-QA `gh462-profiled-cli.py` ran seven passing real CLI cases
with an explicit absolute profiling path outside fixture files. It covers add
and setup invalid/valid/missing paths, plus a real terminal setup selection:
after successful preflight and before import, the selected config was edited;
the second load refused, preserving the edited bytes, inode and client file set.
This supplements coverage; it is not the independent functional leg below.

`cargo llvm-cov report --json` and `--lcov` exported the merged genuine profiles;
both actual exits were 0. The installed tool rejected `report --all-features`
despite listing it in help; that failed invocation is retained, and reports were
rerun without this invalid report-only option using the existing all-feature
instrumented objects. The `show-env --export-prefix` deprecation warning is
retained; actual profiling used the target location generated by the run.

LCOV `DA` records yield **29/29 executable lines (100%)**, with no uncovered
critical line. LLVM JSON yields **55/55 unique source regions (100%)** in the
same windows. Exact source coordinates merge identical Rust generic/async
instantiations; raw instantiated regions are separately reported as 85/208.
This is source guard coverage, not a claim that every generic instance, whole
method, whole file or the whole release has 100% coverage. The fixed denominator,
per-line counters, source hashes and reproducible calculation are external
`gh462-coverage-summary.{py,json}` with raw `gh462-coverage-final.{json,lcov}`.
The critical >=95% and changed-guard target100 thresholds are met.

Cargo-mutants primary and supplemental admin-error runs used copied sources,
disk-backed TMPDIR, one mutation job and four compiler slots. Both baselines
passed. Primary raw exit 2: 9 generated, 6 caught, 1 missed, 2 unviable.
Supplemental raw exit 0: 2 generated and caught. Combined unique total is 11:
**8 caught / 9 viable = 88.89%**, above the critical >=85% threshold; no timeout.
The one survivor deletes `!` from unchanged add line 71, changing the existing
informational creation note. It is not equivalent and remains in the viable
denominator. The actual fallible-load edit begins on line 72. Two generic
`Ok(Default::default())` admin mutants fail E0277 because ConfigMutation lacks
Default; these compiler failures are unviable, never counted as catches.
External `gh462-mutation-summary.json` retains every name, raw log/diff, count and
actual command/process receipt; complete tool output is in `gh462-mutation-r1`
and `gh462-mutation-admin`. Pre-fix RED remains separate falsifier evidence.

### Independent functional acceptance and internal evidence mapping

A fresh driver with no inherited context received only CONFIG.1–6 and public
launch instructions. Its uninstrumented candidate hash matched before and after
driving. It ran real CLI setup/add and authenticated admin HTTP create/update/
delete, verified exact file snapshots and public live configuration/registry
views, and cleaned only its own fixtures. **92/92 public-product assertions
passed**. External `gh462-functional-report.md`, evidence JSONL, action index,
driver and final cleanup receipt preserve the requests, outputs and observations.

The no-reload-context selector and direct mutation-closure execution telemetry
have no public product surface. They are **N/A-to-public-drive**, not internally
driven PASS. Root explicitly accepted this disposition without inventing a new
library driver API. Separate reviewed component evidence supplies those clauses:
`refused_mutation` counts closure calls and checks live config/registry Arc
identity; `gh462_malformed_{with,without}_context` and
`gh462_semantic_{with,without}_context`, plus the paired I/O cases, assert zero
calls and exact preservation. These compiled red before implementation and pass
in the 44-case all-feature suite, 36-case reduced suite and 20-case instrumented
component run. True ConfigValidation semantic failures are explicitly checked
in those fixtures; the independent driver reports its schema-invalid case with
its precise public-surface limits. Neither evidence leg substitutes for the other.

Driver calibration failures, an unavailable PID-namespace operation, and expected
`ps`-unavailable warnings remain in the independent report. Corrected empty-PATH
positive controls prove actual empty-discovery output and successful bootstrap;
seeded-client controls in the same environment prove discovery still works.
No successful host process scan with zero matches is claimed.

### Parent delivery handoff

CONFIG.1–6 and BUILD.1 now have the applicable reviewed component, runtime,
independent public-drive, coverage and mutation evidence. The increment has no
confirmed NOW defect. No commits, pushes, tracker messages, PR operations, live
deployment or restarts were performed by this agent. Root owns integrated final
source validation (including other agents' later hunks), release-wide warnings,
clippy/SCA/security checks, documentation/release notes, issue/PR gate receipts,
CI, review ratification and the complete delivery/deployment chain. Those gates
are open, not waived by these increment receipts.
