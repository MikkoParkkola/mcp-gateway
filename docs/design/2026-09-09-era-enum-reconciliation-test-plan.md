# Test plan — `Era` enum rename (`PeerEra` / `RequestEra`)

- Date: 2026-09-09
- Anchor commit: `5659af11cb634d43018cf5c694ef46768fa25d79`
- Companion: `docs/design/2026-09-09-era-enum-reconciliation.md`
- Scope: option C of that design — rename `protocol::era::Era` to `PeerEra` and
  `protocol::meta::Era` to `RequestEra`. Variant identifiers unchanged.

## Honest framing

A pure type rename is the case Rust checks best. Most rows below read "the compiler catches
it", and saying so is the point of the fourth column — writing a test for a case the compiler
already rejects buys nothing and costs a file to maintain. **Three rows can actually fail**,
and they are the rows where a variant identifier becomes a string or a serialized value. Those
get real tests.

## The one invariant under test

Variant names `Modern` and `Legacy` are unchanged. `src/protocol/era.rs:36` `as_str` and the
`serde(rename_all = "snake_case")` at `src/protocol/era.rs:24` both derive their output from
the variant identifiers, so a rename that touched a variant would change observability labels
and wire output without any type error. Everything below exists to pin that.

## Rows that can genuinely fail

| # | Case | Check | Can it fail? |
|---|---|---|---|
| 1 | `PeerEra::as_str` still returns the exact labels | Assert `as_str` yields `"modern"` for `Modern` and `"legacy"` for `Legacy` | **Yes.** A variant rename or a hand-edited match arm changes the string with no type error. The doc at `src/protocol/era.rs` says the constant is shared by the operator read and the `era_probe` event "so the two cannot drift" — this test is what makes that true. |
| 2 | `PeerEra` serializes to `"modern"` / `"legacy"` | `serde_json::to_value` on each variant | **Yes.** `rename_all = "snake_case"` maps the variant identifier. A rename to, say, `Modern2026` silently ships a new wire value. Distinct from row 1: `as_str` and the derive are two independent spellings of the same contract, and row 1 passing does not prove row 2. |
| 3 | Recorded `era_probe` and `era_cache` labels unchanged | Existing assertions in `tests/nfr_obs_3_era_observability.rs` and `tests/mik_7217_era_probe_acs.rs` must pass with **no assertion or expected-string edited** | **Yes.** These assert on emitted label strings, which is exactly what a variant rename would break. |

Rows 1 and 2 belong next to the type, in the `src/protocol/era.rs` test module.

Row 3 needs no new code — it is a constraint on the **shape** of the diff, and the earlier
draft of this plan stated it wrongly. Both reviewers caught it: `tests/mik_7217_era_probe_acs.rs`
imports the peer enum, so a correct rename **must** edit that file, and a rule saying
`git diff` may not list it would fail a correct rename. The rule as it actually stands:

> In the row-3 files, the only permitted hunks are mechanical identifier substitutions
> (`Era` becomes `PeerEra` in `use` lines and type positions). No assertion, no expected
> string, and no `"modern"` / `"legacy"` literal may change.

Check it with `git diff -U0` on the two files and read every hunk. If a hunk changes a string
literal or the left or right side of an `assert`, the rename went wrong.

## Rows the compiler covers — asserted, not tested

| # | Case | Why no test |
|---|---|---|
| 4 | Every `protocol::era::Era` reference updated | Unresolved path is a compile error across the ten files named in the design's blast-radius table. |
| 5 | Every `protocol::meta::Era` reference updated | Same. Includes `src/gateway/router/handlers.rs:827` and the field at `src/gateway/meta_mcp/mod.rs:173`. |
| 6 | The two enums still cannot be assigned to each other | Type mismatch today. **But** both reviewers rejected the first draft's claim that pinning this needs `trybuild`: a `compile_fail` doctest on `PeerEra` does it with no new dependency. Promoted out of this table — see row 9. |
| 7 | `tests/mik_7217_acs.rs` compiles with both types in one file | `tests/mik_7217_acs.rs:234` uses the request enum, `tests/mik_7217_acs.rs:487` and `tests/mik_7217_acs.rs:625` the peer enum, in separate `mod` blocks. If a rename crossed the two, this file fails to build. It is the sharpest existing canary; keep it building without editing its assertions. |
| 8 | The two error-code constants keep their module | `UNSUPPORTED_PROTOCOL_VERSION` at `src/gateway/router/handlers.rs:287` and `MISSING_REQUIRED_CLIENT_CAPABILITY` at `src/gateway/router/handlers.rs:992` are constants, untouched by an enum rename. Moving them is option E of the design and out of scope here. |

## Row 9 — the guarantee, pinned

| # | Case | Check | Can it fail? |
|---|---|---|---|
| 9 | A `PeerEra` value cannot be assigned where a `RequestEra` is expected | A `compile_fail` doctest on `PeerEra` in `src/protocol/era.rs` that attempts the cross-assignment | **Yes, later.** It cannot fail on the rename commit — the types are already distinct. It fails the day someone unifies them through a shared alias, a macro, or a well-meant `From` impl. That is the whole reason the design rejects the merge, and it is currently enforced by nothing but the absence of anyone trying. |

`compile_fail` doctests run under plain `cargo test`, need no dependency, and cost about six
lines. This is the single highest-value new test in the plan: rows 1 through 3 protect strings
the codebase already exercises, row 9 protects the design decision itself.

## Regression surfaces to run, unedited

- `tests/mik_7217_acs.rs`, `tests/mik_7217_era_probe_acs.rs` — MIK-7217, both axes.
- `tests/nfr_obs_3_era_observability.rs` — recorded era labels.
- `tests/mik_7212_acs.rs`, `tests/mik_7213_acs.rs`, `tests/nfr_compat1_revisions.rs` — peer-era consumers.
- `tests/stdio_tests.rs`, `src/gateway/router/tests.rs`, `src/gateway/meta_mcp/tests.rs` — request-era consumers.

Plus the project gates: `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
`cargo test --quiet`.

Optional, and worth it because the rename is semver-visible: a `cargo public-api` diff on the
rename commit, to confirm the exported-API delta is exactly the two renames (plus the two
deprecated aliases, under option 3 of the design) and nothing else. Catches an accidentally
dropped re-export at the commit rather than at the 4.0.0 release.

## Execution order

0. Settle the design's open question first. Option 3 (rename plus `#[deprecated]` aliases)
   changes step 2's expected diff and adds the alias check to the gates.
1. Add rows 1 and 2 against the current name `Era` in `src/protocol/era.rs`. They pass before
   the rename — they are a **characterization** of the current wire output, not a red test, and
   claiming otherwise would be false. Their value is that they must still pass after.
2. Rename via `gitnexus_rename` with `dry_run: true` first, per the project instructions in
   `CLAUDE.md`; review the `text_search` edits by hand, since a plain textual `Era` matches both.
   **Named hazard:** `EraObservation` (`src/protocol/era.rs:461`), `EraCache`, `EraSource`,
   `EraEvidence` (`src/protocol/era.rs:402`, `src/protocol/era.rs:435`) and the `era_probe` /
   `era_cache` label strings all contain the substring `Era` or `era`. A naive text pass
   produces `PeerEraObservation` and mangles the label strings. Reject any hunk touching them.
3. Build. Rows 4 through 8 resolve here or not at all.
4. Run the regression surfaces. Confirm `git diff --stat` lists no test file from row 3.

## What this plan does not cover

The rename does not change behaviour, so there is no new failure mode to probe beyond the
label contract. If the operator instead picks option D (document, defer the rename), rows 1
and 2 are still worth landing on their own — the label contract is currently unpinned either
way, and that is a real gap this investigation found.
