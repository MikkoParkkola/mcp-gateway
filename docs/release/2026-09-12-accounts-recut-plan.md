# Re-cutting the branch-only subsystems onto the release line (2026-09-12)

`RELEASE-4.0.0-gap-assessment-2026-09-11.md` step 3 recommends re-cutting
`src/personal_accounts/` onto `main` rather than merging
`codex/v4-next-integration`. This plan measures that recommendation, and the
measurement changes its shape: there are **three** subsystems absent from the
release line, not one plus a graft.

Measured on `fix/v4-integration-ci-green` at `92e46ed6` against `origin/main`
at `bd1adbb4`. Every per-file figure below is `git diff --numstat` between
those two commits, reported as additions and deletions. Commit counts, symbol
match counts and net file lengths are not used as size measurements: they
compress a two-sided diff into one number and hide the side that is a loss.

**Revision note.** A first pass of this plan counted the wiring surface by
grepping for the literal `personal_accounts`. That term misses every file that
reaches the subsystem through `account_strategies`, `AccountStrategyRegistry`,
`AccountCustody`, `install_account_strategies` or the OpenWebUI adapter, and it
misses the task service entirely. The corrected counts below are roughly 2.5×
the first pass. The numbers in the previous revision are withdrawn.

## Why re-cut and not merge

| Route | Size |
|---|---|
| Merge `codex/v4-next-integration` | 415 conflicted paths, 1,963 commits, PR #512 `CONFLICTING/DIRTY` with CodeQL red |
| Re-cut the three subsystems | 78 subsystem files + 31 branch-only wiring files, plus edits at 114 sites in 16 files that exist on `main` |

The merge route is still the worse one, but not because the re-cut is small. It
is because the re-cut's cost is *attributable*: every file it moves belongs to a
subsystem with a release criterion behind it, and nothing else comes with it.

## The three subsystems, none of which exists on `main`

| Subsystem | Files | Lines | Criteria behind it |
|---|---|---|---|
| `src/personal_accounts/` | 44 | 16,880 | `MIK-6744.STORE.1`, and the accounts scope rows generally |
| `src/gateway/task_service/` | 28 | 9,995 | the three `MIK-7311.LIFECYCLE` rows |
| `src/idempotency/` (`admission`) | 6 | 2,812 | task admission and qualification |

`git ls-tree -r origin/main` returns zero entries for each of the three paths.

## Branch-only wiring files (31)

These are not part of the three directories but exist only on this branch, and
have to move with them:

- accounts (15): `src/config/account_bindings.rs`,
  `src/config/account_consumer_config_tests/raw_vault.rs`,
  `src/gateway/server/account_bindings.rs`,
  `src/gateway/server/gateway_bootstrap_tests.rs`,
  `src/gateway/meta_mcp/account_resolver_{fixture,gate,gateway,tests}.rs`,
  `src/gateway/meta_mcp/account_rest_{fixture,tests}.rs`,
  `src/config_reload/account_reload_{tests,guard_tests}.rs`,
  `src/identity_propagation/account_strategies.rs`,
  `src/gateway/openwebui_adapter.rs`,
  `src/gateway/router/tests/openwebui_adapter.rs`.
- task service (14): the `src/gateway/task_service/` support files listed by
  `git ls-tree`, plus `src/gateway/meta_mcp/task_confirmation.rs`.
- admission (2): `src/gateway/meta_mcp/admission.rs` and the
  `#[path]`-declared modules under `src/idempotency/`.

## Edits to files that exist on `main` (16)

Reference sites on this branch, split by which subsystem they reach:

| File | Accounts | Admission |
|---|---|---|
| `src/gateway/server/mod.rs` | 26 | 5 |
| `src/config/mod.rs` | 13 | — |
| `src/gateway/meta_mcp/mod.rs` | 12 | 5 |
| `src/capability/executor/mod.rs` | 10 | — |
| `src/capability/executor/credentials.rs` | 9 | — |
| `src/config_reload/mod.rs` | 8 | — |
| `src/gateway/router/mod.rs` | 4 | — |
| `src/fs_lock.rs` | 4 | — |
| `src/capability/execution_context.rs` | 4 | — |
| `src/identity_propagation/mod.rs` | 3 | — |
| `src/gateway/meta_mcp/invoke.rs` | 2 | — |
| `src/capability/backend.rs` | 2 | — |
| `src/lib.rs` | 2 | — |
| `src/gateway/mod.rs` | 1 | — |
| `src/config/env_overlay.rs` | 1 | — |
| `src/gateway/router/tests.rs` | 1 | 2 |

Each edit is transcribed against **`main`'s** copy of the file. Taking this
branch's copy instead imports unrelated divergence: across those files the
branch carries lines the release line does not, and only a minority of them
reach any of the three subsystems.

## `src/idempotency.rs` must not be overwritten

`git diff --numstat 92e46ed6 bd1adbb4 -- src/idempotency.rs` reports **462
additions and 82 deletions** going from this branch to `main`. The branch copy is
an **older** file with the admission module attached, not a superset: overwriting
`main`'s copy discards 462 lines of release-line work, and the 82 lines it would
bring back are the admission wiring plus divergence, not a superset. The net
figure of 380 lines quoted by an earlier revision understated the loss by
conflating the two sides, and is withdrawn. The graft is additive: add the six files
under `src/idempotency/`, then add the two declaring lines —
`#[path = "idempotency/admission.rs"]` and `pub(crate) mod admission;` — into
`main`'s copy. Neither lineage declares the module any other way.

## Order

1. **`src/idempotency/` admission**, onto `main`. Smallest, and the task service
   depends on it (`store_tests/admission.rs`, `store_tests/qualification.rs`).
2. **`src/gateway/task_service/`**, onto the result. Unblocks re-grading the
   three `MIK-7311.LIFECYCLE` rows. It does **not** by itself carry
   `MIK-7377.SIGNING.1`: that criterion's cited evidence is
   `tests/message_signing_delivery.rs` and `tests/message_signing_config.rs`,
   both branch-only, together with `src/gateway/meta_mcp/signing_delivery_tests.rs`.
   Those three files and the `src/attestation/` and `src/config/features/security.rs`
   edits they exercise move in this step or the row stays ungraded. Admitting the
   subsystem is not the same as integrating its runtime consumers.
3. **`src/personal_accounts/`**, onto the result. Unblocks `MIK-6744.STORE.1`
   and the accounts scope rows.
4. Re-grade the six branch-dependent rows against the release line, conjunct by
   conjunct, not by a passing test count.
5. Dispose of the 13 held `codex/v4-*` drafts **only per draft, and only once
   its unique content has a verified landing on the release line** — the landed
   files present at the cited paths and the criterion re-graded against them.
   A draft with content that no step above carries keeps an explicit retained
   disposition instead; "the re-cut carries it" is a claim to verify per draft,
   not a blanket property of this plan.

## Pre-merge validation, per extracted PR

Each of steps 1–3 runs this before it merges, not after the release-line
re-grading in step 4. A failure here is cheaper than a failure discovered by a
later step's re-grade.

| Check | How |
|---|---|
| Compiles | `cargo build` and `cargo clippy --all-targets -- -D warnings` clean |
| Account wiring | every reference site in the 16-file table resolves; no `mod` declared without its file, no file added without its `mod` |
| Cache isolation | the per-identity cache assertions in the subsystem's own tests pass on the release line's `src/backend/mod.rs`, not the branch's |
| Reload behaviour | `src/config_reload/` tests pass with the step's new modules registered |
| Protocol regressions | the release line's existing `tests/` suite is green, in particular the protocol files where the two trees diverged bidirectionally |
| Ledger | `scripts/release/count-release-criteria.py` and `check_scope_acceptance.py --check` still exit 0 |

Steps 1–3 are ordered by dependency, not by size. Each lands behind the normal
review gate with its own CI run; none of them touches the files the next one
needs, except `src/gateway/meta_mcp/mod.rs` and `src/gateway/server/mod.rs`,
which every step edits and which therefore has to be re-read against `main`'s
then-current copy at each step rather than patched from a saved diff.

## What the re-cut unblocks

Six of the eight grades in `scope-grading-2026-09-12.md` cite code that is not
on the release line. They are statements about this branch until the re-cut
lands, and reading them as release readiness before then repeats the error that
grading against the stale ledger already made.
