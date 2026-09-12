# Re-cutting the accounts subsystem onto the release line (2026-09-12)

`RELEASE-4.0.0-gap-assessment-2026-09-11.md` step 3 recommends re-cutting
`src/personal_accounts/` onto `main` rather than merging
`codex/v4-next-integration`. This plan measures that recommendation and states
what the PR contains.

Measured on `fix/v4-integration-ci-green` against `origin/main`.

## Why re-cut and not merge

Merging is the expensive option and the measurement says so:

| Route | Size |
|---|---|
| Merge `codex/v4-next-integration` | 415 conflicted paths, 1,963 commits, PR #512 `CONFLICTING/DIRTY` with CodeQL red |
| Re-cut the subsystem | 56 files that do not exist on `main`, plus **43 lines** of edits to 6 files that do |

The 43 is the number that settles it. The six shared files carry 1,754 lines the
release line does not have, but only 43 of those lines name an account type at
all. The rest is unrelated divergence in the task service and protocol paths,
imported for free by a merge and excluded by a re-cut.

## What the PR contains

**New files, none of which exist on `main` (56).**

- `src/personal_accounts/` — 44 files, 16,880 lines, the subsystem itself.
- 12 wiring files that are equally branch-only, and belong with it:
  `src/config/account_bindings.rs`, `src/gateway/server/account_bindings.rs`,
  `src/identity_propagation/account_strategies.rs`,
  `src/gateway/openwebui_adapter.rs`,
  `src/gateway/meta_mcp/account_resolver_gate.rs`,
  `src/gateway/meta_mcp/account_resolver_fixture.rs`,
  `src/gateway/meta_mcp/account_resolver_tests.rs`,
  `src/gateway/meta_mcp/account_rest_fixture.rs`,
  `src/gateway/meta_mcp/account_rest_tests.rs`,
  `src/config_reload/account_reload_tests.rs`,
  `src/config_reload/account_reload_guard_tests.rs`,
  `src/gateway/server/gateway_bootstrap_tests.rs`.

**Edits to files that exist on `main` (6).** Reference counts are sites naming
`personal_accounts` on this branch:

| File | Sites |
|---|---|
| `src/gateway/server/mod.rs` | 16 |
| `src/config/mod.rs` | 10 |
| `src/fs_lock.rs` | 4 |
| `src/lib.rs` | 2 |
| `src/config/env_overlay.rs` | 1 |
| `src/capability/executor/credentials.rs` | 1 |

Each edit is transcribed against `main`'s copy of the file, not taken from this
branch's copy. Taking the branch's copy would import the ~1,700 unrelated lines
the re-cut exists to leave behind.

## The `mod admission` graft is separate

It is a second, smaller PR and must not ride along with the accounts re-cut.

`main` carries `src/idempotency.rs` at 1,426 lines; this branch carries it at
1,046. The branch copy is **not** a superset — it is an older file with the
admission module attached. Overwriting `main`'s copy with it loses 380 lines of
release-line work.

The graft is therefore additive:

- add the 6 files under `src/idempotency/` (2,812 lines: `admission.rs` plus its
  five test modules);
- add the two lines that declare them, `#[path = "idempotency/admission.rs"]`
  and `pub(crate) mod admission;`, into **`main`'s** `src/idempotency.rs`.

Neither lineage's `idempotency.rs` declares the module any other way, so the
declaration is the whole wiring surface.

## What the re-cut unblocks

Six of the eight grades recorded in `scope-grading-2026-09-12.md` cite code that
does not exist on `main` — `MIK-6744.STORE.1` cites `src/personal_accounts/`
directly, and the three `MIK-7311.LIFECYCLE` rows and `MIK-7377.SIGNING.1` cite
test files absent from the release line. Those grades are statements about this
branch until the re-cut lands. They are not release readiness before then.

## Order

1. The accounts re-cut, as one reviewable PR against `main`.
2. The `mod admission` graft, as a second PR, after the first is merged — it
   touches `src/idempotency.rs`, which the first PR does not.
3. Re-grade the six branch-dependent rows against the release line, using the
   conjunct-by-conjunct method, not a passing test count.
4. Dispose of the 13 held `codex/v4-*` drafts, whose only unique content the
   re-cut has by then carried across.
