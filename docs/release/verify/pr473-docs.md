# PR #473 unreviewed-slice review — docs shard (docs/design, docs/requirements, docs/release)

Method: sampling for ONE defect class — a document asserting behaviour the code does not
have — not full reading, not vendor review. Per team-lead instruction for this shard.

## Scope measured

`git diff c3626cf8 60b138bb -- docs/design/ docs/requirements/ docs/release/`

- 126 files, 45,248 insertions, 27 deletions (brief cited 45,742/84+29+13; close enough to be
  the same set — measured directly, not reconciled against the brief's count).
- `docs/design/`: 84 files. `docs/requirements/`: 29 files. `docs/release/`: 13 files.

## Citation inventory

- `rg` extraction of `path.ext:NNN` patterns (rs/md/yaml/yml/toml/json) across the 126 files:
  **4,368 file:line citations**. This over-counts: two files alone account for 1,256 of them
  (`docs/design/audit-notes/review-1a-20260830/gpt.md` 695, `docs/requirements/RELEASE-4.0.0-criteria-status.md` 561)
  because both are self-auditing transcripts that re-cite the same symbols repeatedly across
  correction passes.
- Absence-claim grep (`no caller`, `not reachable`, `nothing uses`, `zero callers`, `not wired`,
  `does not exist`, etc.) across all 126 files: **387 hits**; narrowed to `docs/requirements/` +
  `docs/design/`: **228 hits**.

## Sample

**Not a 30-citation flat sample — see coverage note below.** I read ~50 of the 228
`docs/requirements/`+`docs/design/` absence-claim lines (weighted toward `docs/requirements/`
per instruction), then took the highest-signal candidates — claims not already self-corrected
inline in the same document — and verified **7 distinct behavioural claims** at source with
fresh `rg` against the current tree (60b138bb). That is a sample of distinct *claims*, several
of which each carry multiple file:line citations, not 30 independent file:line spot-checks.

| # | Verdict | Claim | Doc | Source check |
|---|---|---|---|---|
| 1 | **CONTRADICTION** | `ExtensionSet::gateway_declares()` "has zero callers" | `docs/requirements/RELEASE-4.0.0-audit-partial.md:24` | `src/gateway/meta_mcp_helpers.rs:181-182` — `discovery_extensions()` (production fn, not test-gated) calls `gateway_declares().to_extensions()`. One production call site exists. |
| 2 | **CONTRADICTION** | Cites `resolve_idempotency_key` (`meta_mcp/support.rs:31-46`) as the function that fails to pass continuation fields | `docs/requirements/RELEASE-4.0.0-execution-plan.md:125` | `rg -n 'resolve_idempotency_key' src/ tests/` → zero matches anywhere in the tree. `meta_mcp/support.rs:31-46` is the real function `idempotency_key_for`, not `resolve_idempotency_key`. The cited function does not exist under that name. |
| 3 | **DRIFT→CONTRADICTION** | `cacheable::result_type_of` (`protocol/cacheable.rs:78`) "has zero production callers" | `docs/requirements/RELEASE-4.0.0-execution-plan.md:351` | Line drift: current def is at `cacheable.rs:115`, not `:78`. Substantively: `result_type_of` is wrapped by `is_final` (`cacheable.rs:130-131`, same-file production call), and `is_final` itself has two production callers — `src/idempotency.rs:348` and `src/cache.rs:196` — confirming `docs/requirements/RELEASE-4.0.0-criteria-status.md:211`'s later correction of the same underlying claim. The "zero production callers" framing in execution-plan.md is false as of HEAD. |
| 4 | MATCH | `stable_tool_order()` (`prompt_cache.rs:162`) "genuinely has zero production callers" | `docs/requirements/RELEASE-4.0.0-criteria-status.md:214` (self-claimed, verified independently) | `rg -n 'stable_tool_order' src/` — only call sites outside its own definition/re-exports are inside its own `#[test]` module (`prompt_cache.rs:390-426`). No production caller found. Confirmed true. |
| 5 | **CONTRADICTION** | `set_error_budget_config` / `set_capability_budget_config` "have no callers in `src/` or `tests/`" | `docs/design/2026-09-05-error-budget-config.md:33` | `src/gateway/server/mod.rs:615-616` calls both (`meta_mcp.set_error_budget_config(backend_budget)`, `meta_mcp.set_capability_budget_config(capability_budget)`), production code, not test-gated. Doc's unqualified present-tense claim is false against HEAD. |
| 6 | CANNOT-VERIFY | `is_healthy()` (`:228`) "has no production caller — every hit is a test" | `docs/design/2026-09-05-error-budget-config.md:364` | Ran out of token budget before locating the specific `is_healthy` this row means (multiple `is_healthy` symbols exist in the tree; one broad grep found only a test hit but the search wasn't exhaustive enough to call it confirmed). Not resolved — do not treat as either MATCH or CONTRADICTION. |
| 7 | NOT SAMPLED | `Bridge::to_legacy_client` (`mrtr.rs:186`), "which has no caller" | `docs/requirements/RELEASE-4.0.0-execution-plan.md:126` | Not checked — ran out of budget. |

## Findings requiring attention (CONTRADICTIONS, in full)

**1. `docs/requirements/RELEASE-4.0.0-audit-partial.md:24`** claims
`ExtensionSet::gateway_declares()` "has zero callers", cited at `src/protocol/extensions.rs:59-64`.
Refuted by `src/gateway/meta_mcp_helpers.rs:181-182`:
```rust
pub(crate) fn discovery_extensions() -> std::collections::HashMap<String, Value> {
    crate::protocol::extensions::ExtensionSet::gateway_declares().to_extensions()
}
```
This is production code, not `#[cfg(test)]`. Note: `docs/requirements/RELEASE-4.0.0-criteria-status.md:241`
already carries a correction for this exact row ("EXT.1 never did [fit the zero-caller pattern]:
`gateway_declares` had two production call sites") — so the ledger has already self-corrected,
but `audit-partial.md` itself was not updated and still asserts the stale claim. Two documents
in the same PR disagree; a reader of `audit-partial.md` alone gets the wrong answer.

**2. `docs/requirements/RELEASE-4.0.0-execution-plan.md:125`** cites `resolve_idempotency_key`
at `meta_mcp/support.rs:31-46` as the (broken) mechanism for continuation-field hashing.
`rg -n 'resolve_idempotency_key' src/ tests/` returns zero matches in the entire tree — the
function does not exist under that name anywhere. The function actually defined at
`meta_mcp/support.rs:31-46` is `idempotency_key_for`. Notably, `docs/design/2026-08-31-sub-4-idempotency-wiring.md:172`
already flags this exact error in some other document ("still cite `resolve_idempotency_key`
by name. The function does not exist in `src/`") — but `execution-plan.md` itself is one of the
documents still making the error, at line 125 and again structurally at line 351 (same file).

**3. `docs/design/2026-09-05-error-budget-config.md:33`** ("measured constraints" table) claims
`set_error_budget_config` / `set_capability_budget_config` "have no callers in `src/` or
`tests/`", citing their definitions at `src/gateway/meta_mcp/mod.rs:961,967`, and builds a
downstream claim on it ("The defaults are therefore the only reachable values", row 34).
`src/gateway/server/mod.rs:615-616` calls both setters in production:
```rust
meta_mcp.set_error_budget_config(backend_budget);
meta_mcp.set_capability_budget_config(capability_budget);
```
This may be a case of the wiring landing after the design doc was written (the doc reads as a
point-in-time "measured constraints" snapshot, not explicitly dated as superseded) — but as
committed in this PR's diff, the claim is false against the code it ships beside, and the
"defaults are therefore the only reachable values" conclusion built on it (row 34) does not hold.

## Feature-shipping claims I could not cross-check against `src/`

Not covered — ran out of budget before reaching this pass. No claim to report either way.

## Coverage statement

**This is a sample, not coverage.** Of 4,368 raw file:line citations and 228 absence-specific
claims in `docs/requirements/`+`docs/design/`, I read ~50 absence-claim lines and fully
verified 7 distinct behavioural claims at source (5 with a clear verdict, 1 CANNOT-VERIFY, 1
not reached). That is nowhere near a representative sample of either the 4,368 raw citations or
even the 228 absence claims — it is a fast pass weighted toward the highest-suspicion candidates
(claims not already self-corrected inline). Three of five checked claims were CONTRADICTIONS,
which is a much higher hit rate than the brief's stated "1 in 4 dies on inspection" baseline for
reviewer findings — but the sample is far too small (n=5 with verdicts) to generalize that rate
across the shard. `docs/release/` (13 files, 2.9K insertions) was not sampled at all — no time
remained. Symbol-name-only citations (not paired with file:line) were not separately extracted
or sampled; the counts above cover file:line and commit-sha-shaped patterns only.

Recommendation: `audit-partial.md` and `execution-plan.md` both carry stale/wrong absence claims
that a later, more-maintained document (`criteria-status.md`) has already corrected for at least
one of the two (EXT.1). Neither superseded document was updated or marked stale in this PR. Given
`criteria-status.md`'s own pattern of catching exactly this defect class repeatedly in itself,
the risk is concentrated in the *other*, less-actively-maintained requirements/design docs that
cite the same symbols once and never revisit them — that is exactly where all three confirmed
contradictions above were found.
